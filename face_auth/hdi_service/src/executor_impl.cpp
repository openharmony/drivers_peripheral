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

#define LOG_LABEL OHOS::UserIAM::Common::LABEL_FACE_AUTH_IMPL

namespace OHOS {
namespace HDI {
namespace FaceAuth {
namespace V1_0 {
ExecutorImpl::ExecutorImpl(struct ExecutorInfo executorInfo) : executorInfo_(executorInfo) {}

int32_t ExecutorImpl::GetExecutorInfo(ExecutorInfo &info)
{
    IAM_LOGI("interface mock start");
    info = executorInfo_;
    IAM_LOGI("get executor information success");
    return HDF_SUCCESS;
}

int32_t ExecutorImpl::GetTemplateInfo(uint64_t templateId, TemplateInfo &info)
{
    IAM_LOGI("interface mock start");
    static_cast<void>(templateId);
    info = {0};
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

int32_t ExecutorImpl::Enroll(uint64_t scheduleId, const std::vector<uint8_t> &extraInfo,
    const sptr<IExecutorCallback> &callbackObj)
{
    IAM_LOGI("interface mock start");
    static_cast<void>(scheduleId);
    static_cast<void>(extraInfo);
    IAM_LOGI("enroll, result is %{public}d", ResultCode::OPERATION_NOT_SUPPORT);
    int32_t ret = callbackObj->OnResult(ResultCode::OPERATION_NOT_SUPPORT, {});
    if (ret != ResultCode::SUCCESS) {
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
    IAM_LOGI("authenticate, result is %{public}d", ResultCode::NOT_ENROLLED);
    int32_t ret = callbackObj->OnResult(ResultCode::NOT_ENROLLED, {});
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("callback result is %{public}d", ret);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t ExecutorImpl::Identify(uint64_t scheduleId, const std::vector<uint8_t> &extraInfo,
    const sptr<IExecutorCallback> &callbackObj)
{
    IAM_LOGI("interface mock start");
    static_cast<void>(scheduleId);
    static_cast<void>(extraInfo);
    IAM_LOGI("identify, result is %{public}d", ResultCode::OPERATION_NOT_SUPPORT);
    int32_t ret = callbackObj->OnResult(ResultCode::OPERATION_NOT_SUPPORT, {});
    if (ret != ResultCode::SUCCESS) {
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

int32_t ExecutorImpl::SendCommand(int32_t commandId, const std::vector<uint8_t> &extraInfo,
    const sptr<IExecutorCallback> &callbackObj)
{
    IAM_LOGI("interface mock start");
    static_cast<void>(extraInfo);
    int32_t ret;
    switch (commandId) {
        case LOCK_TEMPLATE:
            IAM_LOGI("unlock template, result is %{public}d", ResultCode::SUCCESS);
            ret = callbackObj->OnResult(ResultCode::SUCCESS, {});
            if (ret != ResultCode::SUCCESS) {
                IAM_LOGE("callback result is %{public}d", ret);
                return HDF_FAILURE;
            }
            break;
        case UNLOCK_TEMPLATE:
            IAM_LOGI("unlock template, result is %{public}d", ResultCode::SUCCESS);
            ret = callbackObj->OnResult(ResultCode::SUCCESS, {});
            if (ret != ResultCode::SUCCESS) {
                IAM_LOGE("callback result is %{public}d", ret);
                return HDF_FAILURE;
            }
            break;
        default:
            IAM_LOGD("not support CommandId : %{public}d", commandId);
            ret = callbackObj->OnResult(ResultCode::OPERATION_NOT_SUPPORT, {});
            if (ret != ResultCode::SUCCESS) {
                IAM_LOGE("callback result is %{public}d", ret);
                return HDF_FAILURE;
            }
    }
    return HDF_SUCCESS;
}
} // V1_0
} // FaceAuth
} // HDI
} // OHOS

