/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "executor_impl.h"
#include <hdf_base.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <securec.h>
#include "defines.h"
#include "iam_logger.h"
#include "parameter.h"
#include "sysparam_errno.h"

#define LOG_LABEL OHOS::UserIam::Common::LABEL_PIN_AUTH_IMPL

namespace OHOS {
namespace HDI {
namespace PinAuth {
namespace V1_0 {
namespace {
    constexpr uint32_t EXECUTOR_TYPE = 0;
    constexpr uint32_t ENROLL_PIN = 0;
    constexpr uint32_t AUTH_PIN = 1;
    constexpr uint32_t OPENSSL_SUCCESS = 1;
    constexpr uint32_t SUCCESS = 0;
} // namespace

ExecutorImpl::ExecutorImpl(std::shared_ptr<OHOS::UserIam::PinAuth::PinAuth> pinHdi) : pinHdi_(pinHdi) {}

int32_t ExecutorImpl::GetExecutorInfo(ExecutorInfo &info)
{
    IAM_LOGI("start");
    constexpr unsigned short SENSOR_ID = 1;
    info.sensorId = SENSOR_ID;
    info.executorType = EXECUTOR_TYPE;
    info.executorRole = ExecutorRole::ALL_IN_ONE;
    info.authType = AuthType::PIN;
    if (pinHdi_ == nullptr) {
        IAM_LOGE("pinHdi_ is nullptr");
        return HDF_FAILURE;
    }
    uint32_t eslRet = 0;
    int32_t result = pinHdi_->GetExecutorInfo(info.publicKey, eslRet);
    if (result != SUCCESS) {
        IAM_LOGE("Get ExecutorInfo failed, fail code : %{public}d", result);
        return result;
    }
    info.esl = static_cast<ExecutorSecureLevel>(eslRet);

    return HDF_SUCCESS;
}

int32_t ExecutorImpl::GetTemplateInfo(uint64_t templateId, TemplateInfo &info)
{
    IAM_LOGI("start");
    if (pinHdi_ == nullptr) {
        IAM_LOGE("pinHdi_ is nullptr");
        return HDF_FAILURE;
    }
    OHOS::UserIam::PinAuth::PinCredentialInfo infoRet = {};
    int32_t result = pinHdi_->QueryPinInfo(templateId, infoRet);
    if (result != SUCCESS) {
        IAM_LOGE("Get TemplateInfo failed, fail code : %{public}d", result);
        return result;
    }
    /* subType is stored in extraInfo */
    info.extraInfo.resize(sizeof(infoRet.subType));
    if (memcpy_s(&(info.extraInfo[0]), sizeof(infoRet.subType), &(infoRet.subType), sizeof(infoRet.subType)) != EOK) {
        IAM_LOGE("copy subType to extraInfo fail!");
        return HDF_FAILURE;
    }

    info.executorType = EXECUTOR_TYPE;
    info.remainAttempts = infoRet.remainTimes;
    info.lockoutDuration = infoRet.freezingTime;

    return HDF_SUCCESS;
}

int32_t ExecutorImpl::OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
    const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("start");
    static_cast<void>(frameworkPublicKey);
    static_cast<void>(extraInfo);
    if (pinHdi_ == nullptr) {
        IAM_LOGE("pinHdi_ is nullptr");
        return HDF_FAILURE;
    }
    int32_t result = pinHdi_->VerifyTemplateData(templateIdList);
    if (result != SUCCESS) {
        IAM_LOGE("Verify templateData failed");
        return result;
    }

    return HDF_SUCCESS;
}

void ExecutorImpl::CallError(const sptr<IExecutorCallback> &callbackObj, uint32_t errorCode)
{
    IAM_LOGI("start");
    std::vector<uint8_t> ret(0);
    if (callbackObj->OnResult(errorCode, ret) != SUCCESS) {
        IAM_LOGE("callback failed");
    }
}

int32_t ExecutorImpl::Enroll(uint64_t scheduleId, const std::vector<uint8_t> &extraInfo,
    const sptr<IExecutorCallback> &callbackObj)
{
    IAM_LOGI("start");
    if (callbackObj == nullptr) {
        IAM_LOGE("callbackObj is nullptr");
        return HDF_FAILURE;
    }
    static_cast<void>(extraInfo);
    std::vector<uint8_t> salt;
    if (NewSalt(salt) != HDF_SUCCESS) {
        IAM_LOGE("new salt failed");
        CallError(callbackObj, GENERAL_ERROR);
        return HDF_SUCCESS;
    }
    int32_t result = scheduleMap_.AddScheduleInfo(scheduleId, ENROLL_PIN, callbackObj, 0, salt);
    if (result != HDF_SUCCESS) {
        IAM_LOGE("Add scheduleInfo failed, fail code : %{public}d", result);
        CallError(callbackObj, GENERAL_ERROR);
        return HDF_SUCCESS;
    }
    result = callbackObj->OnGetData(scheduleId, salt, 0);
    if (result != SUCCESS) {
        IAM_LOGE("Enroll Pin failed, fail code : %{public}d", result);
        // If the enroll fails, delete scheduleId of scheduleMap
        if (scheduleMap_.DeleteScheduleId(scheduleId) != HDF_SUCCESS) {
            IAM_LOGI("delete scheduleId failed");
        }
        return result;
    }

    return HDF_SUCCESS;
}

int32_t ExecutorImpl::Authenticate(uint64_t scheduleId, uint64_t templateId, const std::vector<uint8_t> &extraInfo,
    const sptr<IExecutorCallback> &callbackObj)
{
    IAM_LOGI("start");
    if (callbackObj == nullptr) {
        IAM_LOGE("callbackObj is nullptr");
        return HDF_FAILURE;
    }
    if (pinHdi_ == nullptr) {
        IAM_LOGE("pinHdi_ is nullptr");
        CallError(callbackObj, INVALID_PARAMETERS);
        return HDF_SUCCESS;
    }
    static_cast<void>(extraInfo);
    std::vector<uint8_t> salt;
    int32_t result = pinHdi_->GetSalt(templateId, salt);
    if (result  != SUCCESS) {
        IAM_LOGE("get salt failed, fail code : %{public}d", result);
        CallError(callbackObj, GENERAL_ERROR);
        return HDF_SUCCESS;
    }
    result = scheduleMap_.AddScheduleInfo(scheduleId, AUTH_PIN, callbackObj, templateId, salt);
    if (result != HDF_SUCCESS) {
        IAM_LOGE("Add scheduleInfo failed, fail code : %{public}d", result);
        CallError(callbackObj, GENERAL_ERROR);
        return HDF_SUCCESS;
    }
    OHOS::UserIam::PinAuth::PinCredentialInfo infoRet = {};
    result = pinHdi_->QueryPinInfo(templateId, infoRet);
    if (result != SUCCESS) {
        IAM_LOGE("Get TemplateInfo failed, fail code : %{public}d", result);
        CallError(callbackObj, result);
        return HDF_SUCCESS;
    }
    if (infoRet.remainTimes == 0 || infoRet.freezingTime > 0) {
        IAM_LOGE("Pin authentication is now frozen state");
        CallError(callbackObj, LOCKED);
        return HDF_SUCCESS;
    }
    result = callbackObj->OnGetData(scheduleId, salt, 0);
    if (result != SUCCESS) {
        IAM_LOGE("Authenticate Pin failed, fail code : %{public}d", result);
        // If the authentication fails, delete scheduleId of scheduleMap
        if (scheduleMap_.DeleteScheduleId(scheduleId) != HDF_SUCCESS) {
            IAM_LOGI("delete scheduleId failed");
        }
        return result;
    }

    return HDF_SUCCESS;
}

int32_t ExecutorImpl::OnSetData(uint64_t scheduleId, uint64_t authSubType, const std::vector<uint8_t> &data)
{
    IAM_LOGI("start");
    if (pinHdi_ == nullptr) {
        IAM_LOGE("pinHdi_ is nullptr");
        return HDF_FAILURE;
    }
    std::vector<uint8_t> resultTlv;
    int32_t result = SUCCESS;
    constexpr uint32_t INVALID_ID = 2;
    uint32_t commandId = INVALID_ID;
    sptr<IExecutorCallback> callback = nullptr;
    uint64_t templateId = 0;
    std::vector<uint8_t> salt(0, 0);
    if (scheduleMap_.GetScheduleInfo(scheduleId, commandId, callback, templateId, salt) != HDF_SUCCESS) {
        IAM_LOGE("Get ScheduleInfo failed, fail code : %{public}d", result);
        return HDF_FAILURE;
    }
    switch (commandId) {
        case ENROLL_PIN:
            result = pinHdi_->EnrollPin(scheduleId, authSubType, salt, data, resultTlv);
            if (result != SUCCESS) {
                IAM_LOGE("Enroll Pin failed, fail code : %{public}d", result);
            }
            break;
        case AUTH_PIN:
            result = pinHdi_->AuthPin(scheduleId, templateId, data, resultTlv);
            if (result != SUCCESS) {
                IAM_LOGE("Auth Pin failed, fail code : %{public}d", result);
            }
            break;
        default:
            IAM_LOGE("Error commandId");
    }

    if (callback == nullptr || callback->OnResult(result, resultTlv) != SUCCESS) {
        IAM_LOGE("callbackObj Pin failed");
    }
    // Delete scheduleId from the scheduleMap_ when the enroll and authentication are successful
    if (scheduleMap_.DeleteScheduleId(scheduleId) != HDF_SUCCESS) {
        IAM_LOGI("delete scheduleId failed");
    }

    return HDF_SUCCESS;
}

int32_t ExecutorImpl::Delete(uint64_t templateId)
{
    IAM_LOGI("start");
    if (pinHdi_ == nullptr) {
        IAM_LOGE("pinHdi_ is nullptr");
        return HDF_FAILURE;
    }
    int32_t result = pinHdi_->DeleteTemplate(templateId);
    if (result != SUCCESS) {
        IAM_LOGE("Verify templateData failed, fail code : %{public}d", result);
        return result;
    }

    return HDF_SUCCESS;
}

int32_t ExecutorImpl::Cancel(uint64_t scheduleId)
{
    IAM_LOGI("start");
    if (scheduleMap_.DeleteScheduleId(scheduleId) != HDF_SUCCESS) {
        IAM_LOGE("scheduleId is not found");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t ExecutorImpl::SendCommand(int32_t commandId, const std::vector<uint8_t> &extraInfo,
    const sptr<IExecutorCallback> &callbackObj)
{
    IAM_LOGI("Extension interface, temporarily useless");
    static_cast<void>(commandId);
    static_cast<void>(extraInfo);
    static_cast<void>(callbackObj);
    return HDF_SUCCESS;
}

uint32_t ExecutorImpl::NewSalt(std::vector<uint8_t> &salt)
{
    IAM_LOGI("start");
    constexpr uint32_t DEVICE_UUID_LENGTH = 65;
    char localDeviceId[DEVICE_UUID_LENGTH] = {0};
    if (GetDevUdid(localDeviceId, DEVICE_UUID_LENGTH) != EC_SUCCESS) {
        IAM_LOGE("GetDevUdid failed");
        return HDF_FAILURE;
    }
    constexpr int RANDOM_LENGTH = 32;
    unsigned char random[RANDOM_LENGTH] = {0};
    if (RAND_bytes(random, (int)RANDOM_LENGTH) != OPENSSL_SUCCESS) {
        IAM_LOGE("Generate random number failed");
        return HDF_FAILURE;
    }
    std::vector<uint8_t> sum;
    for (uint32_t i = 0; i < DEVICE_UUID_LENGTH; i++) {
        sum.push_back(localDeviceId[i]);
    }
    for (uint32_t i = 0; i < RANDOM_LENGTH; i++) {
        sum.push_back(random[i]);
    }
    const EVP_MD *alg = EVP_sha256();
    if (alg == nullptr) {
        IAM_LOGE("EVP_sha256 failed");
        return HDF_FAILURE;
    }
    IAM_LOGI("EVP_sha256 success");
    constexpr uint32_t SHA256_LENGTH = 32;
    uint8_t result[SHA256_LENGTH] = {0};
    uint32_t size = 0;
    if (EVP_Digest(sum.data(), sum.size(), result, &size, alg, NULL) != OPENSSL_SUCCESS) {
        IAM_LOGE("EVP_Digest failed");
        return HDF_FAILURE;
    }
    for (uint32_t i = 0; i < size; i++) {
        salt.push_back(result[i]);
    }
    IAM_LOGI("result size is : [%{public}u]", size);
    return HDF_SUCCESS;
}

uint32_t ExecutorImpl::ScheduleMap::AddScheduleInfo(const uint64_t scheduleId, const uint32_t commandId,
    const sptr<IExecutorCallback> callback, const uint64_t templateId, const std::vector<uint8_t> salt)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> guard(mutex_);
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return HDF_FAILURE;
    }
    struct ExecutorImpl::ScheduleMap::ScheduleInfo info {
        .commandId = commandId,
        .callback = callback,
        .templateId = templateId,
        .salt = salt
    };
    scheduleInfo_[scheduleId] = info;

    return HDF_SUCCESS;
}

uint32_t ExecutorImpl::ScheduleMap::GetScheduleInfo(const uint64_t scheduleId, uint32_t &commandId,
    sptr<IExecutorCallback> &callback, uint64_t &templateId, std::vector<uint8_t> &salt)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> guard(mutex_);
    if (scheduleInfo_.find(scheduleId) == scheduleInfo_.end()) {
        IAM_LOGE("scheduleId is invalid");
        return HDF_FAILURE;
    }
    commandId = scheduleInfo_[scheduleId].commandId;
    callback = scheduleInfo_[scheduleId].callback;
    templateId = scheduleInfo_[scheduleId].templateId;
    salt = scheduleInfo_[scheduleId].salt;

    return HDF_SUCCESS;
}

uint32_t ExecutorImpl::ScheduleMap::DeleteScheduleId(const uint64_t scheduleId)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> guard(mutex_);
    if (scheduleInfo_.erase(scheduleId) == 1) {
        IAM_LOGI("Delete scheduleId succ");
        return HDF_SUCCESS;
    }
    IAM_LOGE("Delete scheduleId fail");
    return HDF_FAILURE;
}
} // V1_0
} // PinAuth
} // HDI
} // OHOS