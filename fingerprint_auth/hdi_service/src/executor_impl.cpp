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

#include "fingerprint_auth_defines.h"
#include "iam_logger.h"

#define LOG_LABEL OHOS::UserIam::Common::LABEL_FINGERPRINT_AUTH_IMPL

namespace OHOS {
namespace HDI {
namespace FingerprintAuth {
namespace {
constexpr uint16_t SENSOR_ID = 1;
constexpr uint32_t EXECUTOR_TYPE = 123;
constexpr size_t PUBLIC_KEY_LEN = 32;
} // namespace

ExecutorImpl::ExecutorImpl()
{
    executorInfo_ = {
        .sensorId = SENSOR_ID,
        .executorType = EXECUTOR_TYPE,
        .executorRole = ExecutorRole::ALL_IN_ONE,
        .authType = AuthType::FINGERPRINT,
        .esl = ExecutorSecureLevel::ESL0,
        .publicKey = std::vector<uint8_t>(PUBLIC_KEY_LEN, 0),
        .extraInfo = {},
    };
}

int32_t ExecutorImpl::GetExecutorInfo(ExecutorInfo &executorInfo)
{
    IAM_LOGI("interface mock start");
    executorInfo = executorInfo_;
    IAM_LOGI("get executor information success");
    return HDF_SUCCESS;
}

int32_t ExecutorImpl::GetTemplateInfo(uint64_t templateId, TemplateInfo &templateInfo)
{
    IAM_LOGI("interface mock start");
    static_cast<void>(templateId);
    templateInfo = {0};
    IAM_LOGI("get template information success");
    return HDF_SUCCESS;
}

int32_t ExecutorImpl::OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
    const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("interface mock start");
    static_cast<void>(templateIdList);
    static_cast<void>(extraInfo);
    static_cast<void>(frameworkPublicKey);
    IAM_LOGI("register finish");
    return HDF_SUCCESS;
}

int32_t ExecutorImpl::Enroll(
    uint64_t scheduleId, const std::vector<uint8_t> &extraInfo, const sptr<IExecutorCallback> &callbackObj)
{
    IAM_LOGI("interface mock start");
    static_cast<void>(scheduleId);
    static_cast<void>(extraInfo);
    if (callbackObj == nullptr) {
        IAM_LOGE("callbackObj is nullptr");
        return HDF_ERR_INVALID_PARAM;
    }
    IAM_LOGI("enroll, result is %{public}d", ResultCode::OPERATION_NOT_SUPPORT);
    int32_t ret = callbackObj->OnResult(ResultCode::OPERATION_NOT_SUPPORT, {});
    if (ret != HDF_SUCCESS) {
        IAM_LOGE("callback result is %{public}d", ret);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t ExecutorImpl::Authenticate(uint64_t scheduleId, const std::vector<uint64_t> &templateIdList,
    const std::vector<uint8_t> &extraInfo, const sptr<IExecutorCallback> &callbackObj)
{
    IAM_LOGI("interface mock start");
    return AuthenticateV1_1(scheduleId, templateIdList, true, extraInfo, callbackObj);
}

int32_t ExecutorImpl::AuthenticateV1_1(uint64_t scheduleId, const std::vector<uint64_t> &templateIdList,
    bool endAfterFirstFail, const std::vector<uint8_t> &extraInfo, const sptr<IExecutorCallback> &callbackObj)
{
    IAM_LOGI("interface mock start");
    static_cast<void>(scheduleId);
    static_cast<void>(templateIdList);
    static_cast<void>(endAfterFirstFail);
    static_cast<void>(extraInfo);
    if (callbackObj == nullptr) {
        IAM_LOGE("callbackObj is nullptr");
        return HDF_ERR_INVALID_PARAM;
    }
    IAM_LOGI("authenticate, result is %{public}d", ResultCode::NOT_ENROLLED);
    int32_t ret = callbackObj->OnResult(ResultCode::NOT_ENROLLED, {});
    if (ret != HDF_SUCCESS) {
        IAM_LOGE("callback result is %{public}d", ret);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t ExecutorImpl::Identify(
    uint64_t scheduleId, const std::vector<uint8_t> &extraInfo, const sptr<IExecutorCallback> &callbackObj)
{
    IAM_LOGI("interface mock start");
    static_cast<void>(scheduleId);
    static_cast<void>(extraInfo);
    if (callbackObj == nullptr) {
        IAM_LOGE("callbackObj is nullptr");
        return HDF_ERR_INVALID_PARAM;
    }
    IAM_LOGI("identify, result is %{public}d", ResultCode::OPERATION_NOT_SUPPORT);
    int32_t ret = callbackObj->OnResult(ResultCode::OPERATION_NOT_SUPPORT, {});
    if (ret != HDF_SUCCESS) {
        IAM_LOGE("callback result is %{public}d", ret);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t ExecutorImpl::Delete(const std::vector<uint64_t> &templateIdList)
{
    IAM_LOGI("interface mock start");
    static_cast<void>(templateIdList);
    IAM_LOGI("delete success");
    return HDF_SUCCESS;
}

int32_t ExecutorImpl::Cancel(uint64_t scheduleId)
{
    IAM_LOGI("interface mock start");
    static_cast<void>(scheduleId);
    IAM_LOGI("cancel success");
    return HDF_SUCCESS;
}

int32_t ExecutorImpl::SendCommand(
    int32_t commandId, const std::vector<uint8_t> &extraInfo, const sptr<IExecutorCallback> &callbackObj)
{
    IAM_LOGI("interface mock start");
    static_cast<void>(extraInfo);
    if (callbackObj == nullptr) {
        IAM_LOGE("callbackObj is nullptr");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret;
    switch (commandId) {
        case CommandId::LOCK_TEMPLATE:
            IAM_LOGI("lock template, result is %{public}d", ResultCode::SUCCESS);
            ret = callbackObj->OnResult(ResultCode::SUCCESS, {});
            if (ret != HDF_SUCCESS) {
                IAM_LOGE("callback result is %{public}d", ret);
                return HDF_FAILURE;
            }
            break;
        case CommandId::UNLOCK_TEMPLATE:
            IAM_LOGI("unlock template, result is %{public}d", ResultCode::SUCCESS);
            ret = callbackObj->OnResult(ResultCode::SUCCESS, {});
            if (ret != HDF_SUCCESS) {
                IAM_LOGE("callback result is %{public}d", ret);
                return HDF_FAILURE;
            }
            break;
        case CommandId::INIT_ALGORITHM:
            IAM_LOGI("init algorithm, result is %{public}d", ResultCode::SUCCESS);
            ret = callbackObj->OnResult(ResultCode::SUCCESS, {});
            if (ret != HDF_SUCCESS) {
                IAM_LOGE("callback result is %{public}d", ret);
                return HDF_FAILURE;
            }
            break;
        default:
            IAM_LOGD("not support CommandId : %{public}d", commandId);
            ret = callbackObj->OnResult(ResultCode::OPERATION_NOT_SUPPORT, {});
            if (ret != HDF_SUCCESS) {
                IAM_LOGE("callback result is %{public}d", ret);
                return HDF_FAILURE;
            }
    }
    return HDF_SUCCESS;
}

int32_t ExecutorImpl::GetProperty(
    const std::vector<uint64_t> &templateIdList, const std::vector<GetPropertyType> &propertyTypes, Property &property)
{
    IAM_LOGI("interface mock start");
    property = {};
    IAM_LOGI("get property success");
    return HDF_SUCCESS;
}

int32_t ExecutorImpl::SetCachedTemplates(const std::vector<uint64_t> &templateIdList)
{
    IAM_LOGI("interface mock start");
    IAM_LOGI("set cached templates success");
    return HDF_SUCCESS;
}

int32_t ExecutorImpl::RegisterSaCommandCallback(const sptr<ISaCommandCallback> &callbackObj)
{
    IAM_LOGI("interface mock start");
    IAM_LOGI("register sa command callback success");
    return HDF_SUCCESS;
}

} // namespace FingerprintAuth
} // namespace HDI
} // namespace OHOS
