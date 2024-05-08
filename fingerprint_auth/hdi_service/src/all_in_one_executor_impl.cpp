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

#include "all_in_one_executor_impl.h"

#include <hdf_base.h>

#include "fingerprint_auth_defines.h"
#include "iam_logger.h"

#undef LOG_TAG
#define LOG_TAG "FINGERPRINT_AUTH_IMPL"

namespace OHOS {
namespace HDI {
namespace FingerprintAuth {
namespace {
constexpr uint16_t SENSOR_ID = 123;
constexpr uint32_t EXECUTOR_TYPE = 123;
constexpr size_t PUBLIC_KEY_LEN = 32;
constexpr uint32_t FINGERPRINT_CAPABILITY_LEVEL = 3;
} // namespace

AllInOneExecutorImpl::AllInOneExecutorImpl()
{
    executorInfo_ = {
        .sensorId = SENSOR_ID,
        .executorMatcher = EXECUTOR_TYPE,
        .executorRole = ExecutorRole::ALL_IN_ONE,
        .authType = AuthType::FINGERPRINT,
        .publicKey = std::vector<uint8_t>(PUBLIC_KEY_LEN, 0),
        .extraInfo = {},
        // esl and maxTemplateAcl are for example only. Should be implemented in trusted environment.
        .esl = ExecutorSecureLevel::ESL2,
        .maxTemplateAcl = FINGERPRINT_CAPABILITY_LEVEL,
    };
}

int32_t AllInOneExecutorImpl::GetExecutorInfo(ExecutorInfo &executorInfo)
{
    IAM_LOGI("interface mock start");
    executorInfo = executorInfo_;
    IAM_LOGI("get executor information success");
    return HDF_SUCCESS;
}

int32_t AllInOneExecutorImpl::OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
    const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("interface mock start");
    static_cast<void>(templateIdList);
    static_cast<void>(extraInfo);
    static_cast<void>(frameworkPublicKey);
    IAM_LOGI("register finish");
    return HDF_SUCCESS;
}

int32_t AllInOneExecutorImpl::Enroll(
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

int32_t AllInOneExecutorImpl::Authenticate(uint64_t scheduleId, const std::vector<uint64_t> &templateIdList,
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

int32_t AllInOneExecutorImpl::Identify(
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

int32_t AllInOneExecutorImpl::Delete(const std::vector<uint64_t> &templateIdList)
{
    IAM_LOGI("interface mock start");
    static_cast<void>(templateIdList);
    IAM_LOGI("delete success");
    return HDF_SUCCESS;
}

int32_t AllInOneExecutorImpl::Cancel(uint64_t scheduleId)
{
    IAM_LOGI("interface mock start");
    static_cast<void>(scheduleId);
    IAM_LOGI("cancel success");
    return HDF_SUCCESS;
}

int32_t AllInOneExecutorImpl::SendCommand(
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
        case DriverCommandId::LOCK_TEMPLATE:
            IAM_LOGI("lock template, result is %{public}d", ResultCode::SUCCESS);
            ret = callbackObj->OnResult(ResultCode::SUCCESS, {});
            if (ret != HDF_SUCCESS) {
                IAM_LOGE("callback result is %{public}d", ret);
                return HDF_FAILURE;
            }
            break;
        case DriverCommandId::UNLOCK_TEMPLATE:
            IAM_LOGI("unlock template, result is %{public}d", ResultCode::SUCCESS);
            ret = callbackObj->OnResult(ResultCode::SUCCESS, {});
            if (ret != HDF_SUCCESS) {
                IAM_LOGE("callback result is %{public}d", ret);
                return HDF_FAILURE;
            }
            break;
        case DriverCommandId::INIT_ALGORITHM:
            IAM_LOGI("init algorithm, result is %{public}d", ResultCode::SUCCESS);
            ret = callbackObj->OnResult(ResultCode::SUCCESS, {});
            if (ret != HDF_SUCCESS) {
                IAM_LOGE("callback result is %{public}d", ret);
                return HDF_FAILURE;
            }
            break;
        default:
            IAM_LOGD("not support DriverCommandId : %{public}d", commandId);
            ret = callbackObj->OnResult(ResultCode::OPERATION_NOT_SUPPORT, {});
            if (ret != HDF_SUCCESS) {
                IAM_LOGE("callback result is %{public}d", ret);
                return HDF_FAILURE;
            }
    }
    return HDF_SUCCESS;
}

int32_t AllInOneExecutorImpl::GetProperty(
    const std::vector<uint64_t> &templateIdList, const std::vector<int32_t> &propertyTypes, Property &property)
{
    IAM_LOGI("interface mock start");
    property = {};
    IAM_LOGI("get property success");
    return HDF_SUCCESS;
}

int32_t AllInOneExecutorImpl::SetCachedTemplates(const std::vector<uint64_t> &templateIdList)
{
    IAM_LOGI("interface mock start");
    IAM_LOGI("set cached templates success");
    return HDF_SUCCESS;
}

int32_t AllInOneExecutorImpl::RegisterSaCommandCallback(const sptr<ISaCommandCallback> &callbackObj)
{
    IAM_LOGI("interface mock start");
    IAM_LOGI("register sa command callback success");
    return HDF_SUCCESS;
}

int32_t AllInOneExecutorImpl::SendMessage(uint64_t scheduleId, int32_t srcRole, const std::vector<uint8_t> &msg)
{
    IAM_LOGI("interface mock start");
    IAM_LOGI("send message success");
    return HDF_SUCCESS;
}
} // namespace FingerprintAuth
} // namespace HDI
} // namespace OHOS
