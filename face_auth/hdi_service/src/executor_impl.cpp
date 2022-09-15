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

#include "face_auth_defines.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#define LOG_LABEL OHOS::UserIam::Common::LABEL_FACE_AUTH_IMPL

namespace OHOS {
namespace HDI {
namespace FaceAuth {
namespace V1_0 {
namespace {
constexpr uint16_t SENSOR_ID = 123;
constexpr uint32_t EXECUTOR_TYPE = 123;
constexpr size_t PUBLIC_KEY_LEN = 32;
} // namespace

ExecutorImpl::ExecutorImpl()
{
    executorInfo_ = {
        .sensorId = SENSOR_ID,
        .executorType = EXECUTOR_TYPE,
        .executorRole = ExecutorRole::ALL_IN_ONE,
        .authType = AuthType::FACE,
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
    static_cast<void>(scheduleId);
    static_cast<void>(templateIdList);
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
        case LOCK_TEMPLATE:
            IAM_LOGI("lock template, result is %{public}d", ResultCode::SUCCESS);
            ret = callbackObj->OnResult(ResultCode::SUCCESS, {});
            if (ret != HDF_SUCCESS) {
                IAM_LOGE("callback result is %{public}d", ret);
                return HDF_FAILURE;
            }
            break;
        case UNLOCK_TEMPLATE:
            IAM_LOGI("unlock template, result is %{public}d", ResultCode::SUCCESS);
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

int32_t ExecutorImpl::SetBufferProducer(const sptr<BufferProducerSequenceable> &bufferProducer)
{
    IAM_LOGI("interface mock start set buffer producer %{public}s",
        UserIam::Common::GetPointerNullStateString(bufferProducer.GetRefPtr()).c_str());
    return HDF_SUCCESS;
}
} // namespace V1_0
} // namespace FaceAuth
} // namespace HDI
} // namespace OHOS
