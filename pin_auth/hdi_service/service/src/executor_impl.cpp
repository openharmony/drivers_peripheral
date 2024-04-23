/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include <securec.h>
#include "defines.h"
#include "iam_logger.h"

#undef LOG_TAG
#define LOG_TAG "PIN_AUTH_IMPL"

namespace OHOS {
namespace HDI {
namespace PinAuth {
namespace {
    constexpr uint32_t EXECUTOR_TYPE = 0;
    constexpr uint32_t ENROLL_PIN = 0;
    constexpr uint32_t AUTH_PIN = 1;
    constexpr uint32_t GENERAL_ERROR = 2;
    constexpr uint32_t SUCCESS = 0;
} // namespace

ExecutorImpl::ExecutorImpl(std::shared_ptr<OHOS::UserIam::PinAuth::PinAuth> pinHdi)
    : pinHdi_(pinHdi),
      threadPool_("pin_async")
{
    threadPool_.Start(1);
}

ExecutorImpl::~ExecutorImpl()
{
    threadPool_.Stop();
}

int32_t ExecutorImpl::GetExecutorInfo(HdiExecutorInfo &info)
{
    IAM_LOGI("start");
    if (pinHdi_ == nullptr) {
        IAM_LOGE("pinHdi_ is nullptr");
        return HDF_FAILURE;
    }
    constexpr unsigned short SENSOR_ID = 1;
    info.sensorId = SENSOR_ID;
    info.executorMatcher = EXECUTOR_TYPE;
    info.executorRole = HdiExecutorRole::ALL_IN_ONE;
    info.authType = HdiAuthType::PIN;
    uint32_t eslRet = 0;
    int32_t result = pinHdi_->GetExecutorInfo(info.publicKey, eslRet);
    if (result != SUCCESS) {
        IAM_LOGE("Get ExecutorInfo failed, fail code : %{public}d", result);
        return result;
    }
    info.esl = static_cast<HdiExecutorSecureLevel>(eslRet);

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

int32_t ExecutorImpl::SendMessage(uint64_t scheduleId, int32_t srcRole, const std::vector<uint8_t>& msg)
{
    static_cast<void>(scheduleId);
    static_cast<void>(srcRole);
    static_cast<void>(msg);
    return HDF_SUCCESS;
}

void ExecutorImpl::CallError(const sptr<HdiIExecutorCallback> &callbackObj, uint32_t errorCode)
{
    IAM_LOGI("start");
    std::vector<uint8_t> ret(0);
    if (callbackObj->OnResult(errorCode, ret) != SUCCESS) {
        IAM_LOGE("callback failed");
    }
}

int32_t ExecutorImpl::EnrollInner(uint64_t scheduleId, const std::vector<uint8_t> &extraInfo,
    const sptr<HdiIExecutorCallback> &callbackObj, std::vector<uint8_t> &algoParameter, uint32_t &algoVersion)
{
    IAM_LOGI("start");
    static_cast<void>(extraInfo);
    if (pinHdi_->GenerateAlgoParameter(algoParameter, algoVersion) != SUCCESS) {
        IAM_LOGE("Generate algorithm parameter failed");
        CallError(callbackObj, GENERAL_ERROR);
        return GENERAL_ERROR;
    }

    int32_t result = scheduleMap_.AddScheduleInfo(scheduleId, ENROLL_PIN, callbackObj, 0, algoParameter);
    if (result != HDF_SUCCESS) {
        IAM_LOGE("Add scheduleInfo failed, fail code : %{public}d", result);
        CallError(callbackObj, GENERAL_ERROR);
        return GENERAL_ERROR;
    }

    return HDF_SUCCESS;
}

int32_t ExecutorImpl::Enroll(uint64_t scheduleId, const std::vector<uint8_t> &extraInfo,
    const sptr<HdiIExecutorCallback> &callbackObj)
{
    IAM_LOGI("start");
    if (callbackObj == nullptr) {
        IAM_LOGE("callbackObj is nullptr");
        return HDF_ERR_INVALID_PARAM;
    }
    if (pinHdi_ == nullptr) {
        IAM_LOGE("pinHdi_ is nullptr");
        CallError(callbackObj, INVALID_PARAMETERS);
        return HDF_SUCCESS;
    }
    std::vector<uint8_t> algoParameter;
    uint32_t algoVersion = 0;
    int32_t result = EnrollInner(scheduleId, extraInfo, callbackObj, algoParameter, algoVersion);
    if (result != SUCCESS) {
        IAM_LOGE("EnrollInner failed, fail code : %{public}d", result);
        return HDF_SUCCESS;
    }

    std::vector<uint8_t> challenge;
    result = callbackObj->OnGetData(algoParameter, 0, algoVersion, challenge);
    if (result != SUCCESS) {
        IAM_LOGE("Enroll Pin failed, fail code : %{public}d", result);
        CallError(callbackObj, GENERAL_ERROR);
        // If the enroll fails, delete scheduleId of scheduleMap
        if (scheduleMap_.DeleteScheduleId(scheduleId) != HDF_SUCCESS) {
            IAM_LOGI("delete scheduleId failed");
        }
    }

    return HDF_SUCCESS;
}

int32_t ExecutorImpl::AuthenticateInner(uint64_t scheduleId, uint64_t templateId, std::vector<uint8_t> &algoParameter,
    const sptr<HdiIExecutorCallback> &callbackObj)
{
    IAM_LOGI("start");
    OHOS::UserIam::PinAuth::PinCredentialInfo infoRet = {};
    int32_t result = pinHdi_->QueryPinInfo(templateId, infoRet);
    if (result != SUCCESS) {
        IAM_LOGE("Get TemplateInfo failed, fail code : %{public}d", result);
        CallError(callbackObj, result);
        return GENERAL_ERROR;
    }
    if (infoRet.remainTimes == 0 || infoRet.freezingTime > 0) {
        IAM_LOGE("Pin authentication is now frozen state");
        CallError(callbackObj, LOCKED);
        return GENERAL_ERROR;
    }
    result = scheduleMap_.AddScheduleInfo(scheduleId, AUTH_PIN, callbackObj, templateId, algoParameter);
    if (result != HDF_SUCCESS) {
        IAM_LOGE("Add scheduleInfo failed, fail code : %{public}d", result);
        CallError(callbackObj, GENERAL_ERROR);
        return GENERAL_ERROR;
    }

    return SUCCESS;
}

int32_t ExecutorImpl::Authenticate(uint64_t scheduleId, const std::vector<uint64_t>& templateIdList,
    const std::vector<uint8_t> &extraInfo, const sptr<HdiIExecutorCallback> &callbackObj)
{
    IAM_LOGI("start");
    if (callbackObj == nullptr) {
        IAM_LOGE("callbackObj is nullptr");
        return HDF_ERR_INVALID_PARAM;
    }
    if (pinHdi_ == nullptr || templateIdList.size() != 1) {
        IAM_LOGE("pinHdi_ is nullptr or templateIdList size not 1");
        CallError(callbackObj, INVALID_PARAMETERS);
        return HDF_SUCCESS;
    }
    static_cast<void>(extraInfo);
    std::vector<uint8_t> algoParameter;
    uint32_t algoVersion = 0;
    uint64_t templateId = templateIdList[0];
    int32_t result = pinHdi_->GetAlgoParameter(templateId, algoParameter, algoVersion);
    if (result != SUCCESS) {
        IAM_LOGE("Get algorithm parameter failed, fail code : %{public}d", result);
        CallError(callbackObj, result);
        return GENERAL_ERROR;
    }
    result = AuthenticateInner(scheduleId, templateId, algoParameter, callbackObj);
    if (result != SUCCESS) {
        IAM_LOGE("AuthenticateInner failed, fail code : %{public}d", result);
        return HDF_SUCCESS;
    }

    std::vector<uint8_t> challenge;
    result = callbackObj->OnGetData(algoParameter, 0, algoVersion, challenge);
    if (result != SUCCESS) {
        IAM_LOGE("Authenticate Pin failed, fail code : %{public}d", result);
        CallError(callbackObj, GENERAL_ERROR);
        // If the authentication fails, delete scheduleId of scheduleMap
        if (scheduleMap_.DeleteScheduleId(scheduleId) != HDF_SUCCESS) {
            IAM_LOGI("delete scheduleId failed");
        }
    }

    return HDF_SUCCESS;
}

int32_t ExecutorImpl::AuthPin(uint64_t scheduleId, uint64_t templateId,
    const std::vector<uint8_t> &data, std::vector<uint8_t> &resultTlv)
{
    int32_t result = pinHdi_->AuthPin(scheduleId, templateId, data, resultTlv);
    if (result != SUCCESS) {
        IAM_LOGE("Auth Pin failed, fail code : %{public}d", result);
        return result;
    }
    threadPool_.AddTask([hdi = pinHdi_, id = templateId]() {
        if (hdi == nullptr) {
            return;
        }
        hdi->WriteAntiBrute(id);
    });
    IAM_LOGI("Auth Pin success");
    return result;
}

int32_t ExecutorImpl::SetData(uint64_t scheduleId, uint64_t authSubType, const std::vector<uint8_t> &data,
    int32_t resultCode)
{
    IAM_LOGI("start");
    if (pinHdi_ == nullptr) {
        IAM_LOGE("pinHdi_ is nullptr");
        return HDF_FAILURE;
    }
    std::vector<uint8_t> resultTlv;
    int32_t result = GENERAL_ERROR;
    constexpr uint32_t INVALID_ID = 2;
    uint32_t commandId = INVALID_ID;
    sptr<HdiIExecutorCallback> callback = nullptr;
    uint64_t templateId = 0;
    std::vector<uint8_t> algoParameter(0, 0);
    if (scheduleMap_.GetScheduleInfo(scheduleId, commandId, callback, templateId, algoParameter) != HDF_SUCCESS) {
        IAM_LOGE("Get ScheduleInfo failed, fail code : %{public}d", result);
        return HDF_FAILURE;
    }
    if (resultCode != SUCCESS && callback != nullptr) {
        IAM_LOGE("SetData failed, resultCode is %{public}d", resultCode);
        CallError(callback, resultCode);
        return resultCode;
    }
    switch (commandId) {
        case ENROLL_PIN:
            result = pinHdi_->EnrollPin(scheduleId, authSubType, algoParameter, data, resultTlv);
            if (result != SUCCESS) {
                IAM_LOGE("Enroll Pin failed, fail code : %{public}d", result);
            }
            break;
        case AUTH_PIN:
            result = AuthPin(scheduleId, templateId, data, resultTlv);
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

uint32_t ExecutorImpl::ScheduleMap::AddScheduleInfo(const uint64_t scheduleId, const uint32_t commandId,
    const sptr<HdiIExecutorCallback> callback, const uint64_t templateId, const std::vector<uint8_t> algoParameter)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> guard(mutex_);
    if (callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return HDF_ERR_INVALID_PARAM;
    }
    struct ExecutorImpl::ScheduleMap::ScheduleInfo info {
        .commandId = commandId,
        .callback = callback,
        .templateId = templateId,
        .algoParameter = algoParameter
    };
    scheduleInfo_[scheduleId] = info;

    return HDF_SUCCESS;
}

uint32_t ExecutorImpl::ScheduleMap::GetScheduleInfo(const uint64_t scheduleId, uint32_t &commandId,
    sptr<HdiIExecutorCallback> &callback, uint64_t &templateId, std::vector<uint8_t> &algoParameter)
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
    algoParameter = scheduleInfo_[scheduleId].algoParameter;

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

int32_t ExecutorImpl::GetProperty(
    const std::vector<uint64_t> &templateIdList, const std::vector<int32_t> &propertyTypes, HdiProperty &property)
{
    IAM_LOGI("start");
    if (pinHdi_ == nullptr) {
        IAM_LOGE("pinHdi_ is nullptr");
        return HDF_FAILURE;
    }

    if (templateIdList.size() != 1) {
        IAM_LOGE("templateIdList size is not 1");
        return HDF_ERR_INVALID_PARAM;
    }

    uint64_t templateId = templateIdList[0];
    OHOS::UserIam::PinAuth::PinCredentialInfo infoRet = {};
    int32_t result = pinHdi_->QueryPinInfo(templateId, infoRet);
    if (result != SUCCESS) {
        IAM_LOGE("Get TemplateInfo failed, fail code : %{public}d", result);
        return HDF_FAILURE;
    }

    property.authSubType = infoRet.subType;
    property.remainAttempts = infoRet.remainTimes;
    property.lockoutDuration = infoRet.freezingTime;
    return HDF_SUCCESS;
}
} // PinAuth
} // HDI
} // OHOS