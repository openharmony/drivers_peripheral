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

#include "collector_impl.h"
#include <hdf_base.h>
#include <securec.h>
#include "executor_impl_common.h"
#include "iam_logger.h"

#undef LOG_TAG
#define LOG_TAG "PIN_AUTH_IMPL_C"

namespace OHOS {
namespace HDI {
namespace PinAuth {
CollectorImpl::CollectorImpl(std::shared_ptr<OHOS::UserIam::PinAuth::PinAuth> pinHdi)
    : pinHdi_(pinHdi),
      threadPool_("pin_collector_async")
{
    threadPool_.Start(1);
}

CollectorImpl::~CollectorImpl()
{
    threadPool_.Stop();
}

int32_t CollectorImpl::GetExecutorInfo(HdiExecutorInfo &executorInfo)
{
    IAM_LOGI("start");
    if (pinHdi_ == nullptr) {
        IAM_LOGE("pinHdi_ is nullptr");
        return HDF_FAILURE;
    }
    executorInfo.sensorId = SENSOR_ID;
    executorInfo.executorMatcher = EXECUTOR_MATCHER;
    executorInfo.executorRole = HdiExecutorRole::COLLECTOR;
    executorInfo.authType = HdiAuthType::PIN;
    uint32_t eslRet = 0;
    int32_t result = pinHdi_->GetExecutorInfo(HdiExecutorRole::COLLECTOR, executorInfo.publicKey, eslRet,
        executorInfo.maxTemplateAcl);
    if (result != SUCCESS) {
        IAM_LOGE("Get collector ExecutorInfo failed, fail code:%{public}d", result);
        return HDF_FAILURE;
    }
    executorInfo.esl = static_cast<HdiExecutorSecureLevel>(eslRet);
    return HDF_SUCCESS;
}

int32_t CollectorImpl::OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
    const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("start");
    static_cast<void>(templateIdList);
    static_cast<void>(extraInfo);
    if (pinHdi_ == nullptr) {
        IAM_LOGE("pinHdi_ is nullptr");
        return HDF_FAILURE;
    }
    int32_t result = pinHdi_->SetCollectorFwkParam(frameworkPublicKey);
    if (result != SUCCESS) {
        IAM_LOGE("Hdi SetCollectorFwkParam fail");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

bool CollectorImpl::IsCurrentSchedule(uint64_t scheduleId)
{
    if (!scheduleId_.has_value()) {
        IAM_LOGE("collect schedule not exist");
        return false;
    }
    if (scheduleId_.value() != scheduleId) {
        IAM_LOGE("collect schedule:%{public}x not match current:%{public}x",
            (uint16_t)scheduleId, (uint16_t)scheduleId_.value());
        return false;
    }
    return true;
}

void CollectorImpl::CancelCurrentCollect(int32_t errorCode)
{
    if (!scheduleId_.has_value()) {
        return;
    }
    if (pinHdi_->CancelCollect() != SUCCESS) {
        IAM_LOGE("Hdi CancelCollect fail");
    }
    CallError(callback_, errorCode);
    scheduleId_ = std::nullopt;
    callback_ = nullptr;
}

int32_t CollectorImpl::Cancel(uint64_t scheduleId)
{
    IAM_LOGI("start %{public}x", (uint16_t)scheduleId);
    if (pinHdi_ == nullptr) {
        IAM_LOGE("pinHdi_ is nullptr");
        return HDF_FAILURE;
    }
    threadPool_.AddTask([this, id = scheduleId]() {
        if (IsCurrentSchedule(id)) {
            CancelCurrentCollect();
        }
    });
    return HDF_SUCCESS;
}

int32_t CollectorImpl::SendMessage(uint64_t scheduleId, int32_t srcRole, const std::vector<uint8_t> &msg)
{
    IAM_LOGI("start schedule:%{public}x src:%{public}d", (uint16_t)scheduleId, srcRole);
    if (pinHdi_ == nullptr) {
        IAM_LOGE("pinHdi_ is nullptr");
        return HDF_FAILURE;
    }
    if (srcRole != HdiExecutorRole::VERIFIER) {
        IAM_LOGI("only verifier src handled");
        return HDF_SUCCESS;
    }
    threadPool_.AddTask([this, id = scheduleId, message = msg]() {
        if (!IsCurrentSchedule(id)) {
            return;
        }
        OHOS::UserIam::PinAuth::PinAlgoParam pinAlgoParam = {};
        if (pinHdi_->SendMessageToCollector(id, message, pinAlgoParam) != SUCCESS) {
            IAM_LOGE("Hdi SendMessageToCollector fail");
            return;
        }
        std::vector<uint8_t> pinComplexityReg;
        if (callback_->OnGetData(pinAlgoParam.algoParameter, pinAlgoParam.subType, pinAlgoParam.algoVersion,
            pinAlgoParam.challenge, pinComplexityReg) != SUCCESS) {
            IAM_LOGE("Hdi callback OnGetData fail");
            CancelCurrentCollect();
        }
    });
    return HDF_SUCCESS;
}

void CollectorImpl::ClearPinData(const std::vector<uint8_t> &pinData)
{
    if (pinData.size() != 0) {
        uint8_t *data = const_cast<uint8_t *>(pinData.data());
        (void)memset_s(data, pinData.size(), 0, pinData.size());
    }
}

int32_t CollectorImpl::SetData(
    uint64_t scheduleId, uint64_t authSubType, const std::vector<uint8_t> &data, int32_t resultCode)
{
    IAM_LOGI("start %{public}x", (uint16_t)scheduleId);
    static_cast<void>(authSubType);
    if (pinHdi_ == nullptr) {
        IAM_LOGE("pinHdi_ is nullptr");
        return HDF_FAILURE;
    }
    threadPool_.AddTask([this, id = scheduleId, pinData = data, result = resultCode]() {
        if (!IsCurrentSchedule(id)) {
            ClearPinData(pinData);
            return;
        }
        if (result != SUCCESS) {
            CancelCurrentCollect(result);
            ClearPinData(pinData);
            return;
        }
        std::vector<uint8_t> msg;
        if (pinHdi_->SetDataToCollector(id, pinData, msg) != SUCCESS) {
            IAM_LOGE("Hdi SetDataToCollector fail");
            CancelCurrentCollect();
            ClearPinData(pinData);
            return;
        }
        int32_t ret = callback_->OnMessage(HdiExecutorRole::VERIFIER, msg);
        if (ret != SUCCESS) {
            IAM_LOGE("Send collector ack msg fail");
            CancelCurrentCollect();
            ClearPinData(pinData);
            return;
        }
    });
    ClearPinData(data);
    return HDF_SUCCESS;
}

int32_t CollectorImpl::Collect(uint64_t scheduleId, const std::vector<uint8_t> &extraInfo,
    const sptr<HdiIExecutorCallback> &callbackObj)
{
    IAM_LOGI("start %{public}x", (uint16_t)scheduleId);
    if (callbackObj == nullptr) {
        IAM_LOGE("callbackObj is nullptr");
        return HDF_FAILURE;
    }
    if (pinHdi_ == nullptr) {
        IAM_LOGE("pinHdi_ is nullptr");
        CallError(callbackObj, INVALID_PARAMETERS);
        return HDF_SUCCESS;
    }
    threadPool_.AddTask([this, id = scheduleId, extra = extraInfo, callback = callbackObj]() {
        CancelCurrentCollect();
        std::vector<uint8_t> msg;
        int32_t result = pinHdi_->Collect(id, extra, msg);
        if (result != SUCCESS) {
            IAM_LOGE("Collect fail");
            CallError(callback, result);
            return;
        }
        result = callback->OnMessage(HdiExecutorRole::VERIFIER, msg);
        if (result != SUCCESS) {
            IAM_LOGE("Send collector sync msg fail");
            CallError(callback, result);
            return;
        }
        scheduleId_ = id;
        callback_ = callback;
    });
    return HDF_SUCCESS;
}
} // PinAuth
} // HDI
} // OHOS