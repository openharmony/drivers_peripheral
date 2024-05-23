/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "verifier_impl.h"
#include <cinttypes>
#include <hdf_base.h>
#include <securec.h>
#include "executor_impl_common.h"
#include "iam_logger.h"

#undef LOG_TAG
#define LOG_TAG "PIN_AUTH_IMPL_V"

namespace OHOS {
namespace HDI {
namespace PinAuth {
VerifierImpl::VerifierImpl(std::shared_ptr<OHOS::UserIam::PinAuth::PinAuth> pinHdi)
    : pinHdi_(pinHdi),
      threadPool_("pin_verifier_async")
{
    threadPool_.Start(1);
}

VerifierImpl::~VerifierImpl()
{
    threadPool_.Stop();
}

int32_t VerifierImpl::GetExecutorInfo(HdiExecutorInfo &executorInfo)
{
    IAM_LOGI("start");
    if (pinHdi_ == nullptr) {
        IAM_LOGE("pinHdi_ is nullptr");
        return HDF_FAILURE;
    }
    executorInfo.sensorId = SENSOR_ID;
    executorInfo.executorMatcher = EXECUTOR_MATCHER;
    executorInfo.executorRole = HdiExecutorRole::VERIFIER;
    executorInfo.authType = HdiAuthType::PIN;
    uint32_t eslRet = 0;
    int32_t result = pinHdi_->GetExecutorInfo(HdiExecutorRole::VERIFIER, executorInfo.publicKey, eslRet,
        executorInfo.maxTemplateAcl);
    if (result != SUCCESS) {
        IAM_LOGE("Get verifier ExecutorInfo failed, fail code:%{public}d", result);
        return HDF_FAILURE;
    }
    executorInfo.esl = static_cast<HdiExecutorSecureLevel>(eslRet);
    return HDF_SUCCESS;
}

int32_t VerifierImpl::OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
    const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("start");
    static_cast<void>(templateIdList);
    static_cast<void>(extraInfo);
    if (pinHdi_ == nullptr) {
        IAM_LOGE("pinHdi_ is nullptr");
        return HDF_FAILURE;
    }
    int32_t result = pinHdi_->SetVerifierFwkParam(frameworkPublicKey);
    if (result != SUCCESS) {
        IAM_LOGE("Hdi SetVerifierFwkParam fail");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

bool VerifierImpl::IsCurrentSchedule(uint64_t scheduleId)
{
    if (!scheduleId_.has_value()) {
        IAM_LOGE("verify schedule not exist");
        return false;
    }
    if (scheduleId_.value() != scheduleId) {
        IAM_LOGE("verify schedule:%{public}x not match current:%{public}x",
            (uint16_t)scheduleId, (uint16_t)scheduleId_.value());
        return false;
    }
    return true;
}

void VerifierImpl::CancelCurrentAuth(int32_t errorCode)
{
    if (!scheduleId_.has_value()) {
        return;
    }
    if (pinHdi_->CancelVerifierAuth() != SUCCESS) {
        IAM_LOGE("Hdi CancelVerify fail");
    }
    CallError(callback_, errorCode);
    scheduleId_ = std::nullopt;
    callback_ = nullptr;
}

int32_t VerifierImpl::Cancel(uint64_t scheduleId)
{
    IAM_LOGI("start %{public}x", (uint16_t)scheduleId);
    if (pinHdi_ == nullptr) {
        IAM_LOGE("pinHdi_ is nullptr");
        return HDF_FAILURE;
    }
    threadPool_.AddTask([this, id = scheduleId]() {
        if (IsCurrentSchedule(id)) {
            CancelCurrentAuth();
        }
    });
    return HDF_SUCCESS;
}

void VerifierImpl::HandleVerifierMsg(uint64_t scheduleId, const std::vector<uint8_t> &msg)
{
    IAM_LOGI("start");
    std::vector<uint8_t> msgOut;
    bool isAuthEnd = false;
    int32_t compareResult = FAIL;
    if (pinHdi_->SendMessageToVerifier(scheduleId, msg, msgOut, isAuthEnd, compareResult) != SUCCESS) {
        IAM_LOGE("Hdi SendMessageToVerifier fail");
        return;
    }
    if (!isAuthEnd) {
        int32_t result = callback_->OnMessage(HdiExecutorRole::COLLECTOR, msgOut);
        if (result != SUCCESS) {
            IAM_LOGE("Send verifier ack msg fail");
            CancelCurrentAuth(result);
            return;
        }
    } else {
        int32_t result = callback_->OnResult(compareResult, msgOut);
        if (result != SUCCESS) {
            IAM_LOGE("call OnResult fail");
            CancelCurrentAuth(result);
            return;
        }
    }
}

int32_t VerifierImpl::SendMessage(uint64_t scheduleId, int32_t srcRole, const std::vector<uint8_t> &msg)
{
    IAM_LOGI("start schedule:%{public}x src:%{public}d", (uint16_t)scheduleId, srcRole);
    if (pinHdi_ == nullptr) {
        IAM_LOGE("pinHdi_ is nullptr");
        return HDF_FAILURE;
    }
    threadPool_.AddTask([this, id = scheduleId, role = srcRole, msgIn = msg]() {
        if (!IsCurrentSchedule(id)) {
            return;
        }
        if (role == HdiExecutorRole::COLLECTOR) {
            return HandleVerifierMsg(id, msgIn);
        }
        IAM_LOGE("message from %{public}d not handled", role);
    });
    return HDF_SUCCESS;
}

int32_t VerifierImpl::Authenticate(uint64_t scheduleId, const std::vector<uint64_t> &templateIdList,
    const std::vector<uint8_t> &extraInfo, const sptr<HdiIExecutorCallback> &callbackObj)
{
    IAM_LOGI("start %{public}x", (uint16_t)scheduleId);
    if (callbackObj == nullptr) {
        IAM_LOGE("callbackObj is nullptr");
        return HDF_FAILURE;
    }
    if ((pinHdi_ == nullptr) || (templateIdList.size() != 1)) {
        IAM_LOGE("pinHdi_ is nullptr or templateIdList size not 1");
        CallError(callbackObj, INVALID_PARAMETERS);
        return HDF_FAILURE;
    }
    threadPool_.AddTask(
        [this, id = scheduleId, templateId = templateIdList, extra = extraInfo, callback = callbackObj]() {
            CancelCurrentAuth();
            std::vector<uint8_t> msg;
            int32_t result = pinHdi_->VerifierAuth(id, templateId[0], extra, msg);
            if (result != SUCCESS) {
                IAM_LOGE("VerifierAuth fail");
                callback->OnResult(result, msg);
                return;
            }
            scheduleId_ = id;
            callback_ = callback;
        });
    return HDF_SUCCESS;
}

int32_t VerifierImpl::NotifyCollectorReady(uint64_t scheduleId)
{
    IAM_LOGI("start %{public}x", (uint16_t)scheduleId);
    static_cast<void>(scheduleId);
    return HDF_SUCCESS;
}

} // PinAuth
} // HDI
} // OHOS