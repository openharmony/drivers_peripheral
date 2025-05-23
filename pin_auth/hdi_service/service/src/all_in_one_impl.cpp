/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "all_in_one_impl.h"

#include <chrono>
#include <cinttypes>
#include <hdf_base.h>

#include "defines.h"
#include "executor_impl_common.h"
#include "iam_logger.h"

#undef LOG_TAG
#define LOG_TAG "PIN_AUTH_IMPL_A"

namespace OHOS {
namespace HDI {
namespace PinAuth {
namespace {
constexpr uint32_t ENROLL_PIN = 0;
constexpr uint32_t AUTH_PIN = 1;

constexpr size_t MAX_SCHEDULE_SIZE = 50;
}

AllInOneImpl::AllInOneImpl(std::shared_ptr<OHOS::UserIam::PinAuth::PinAuth> pinHdi)
    : pinHdi_(pinHdi),
      threadPool_("pin_async")
{
    threadPool_.Start(1);
}

AllInOneImpl::~AllInOneImpl()
{
    threadPool_.Stop();
}

int32_t AllInOneImpl::GetExecutorInfo(HdiExecutorInfo &info)
{
    IAM_LOGI("start");
    if (pinHdi_ == nullptr) {
        IAM_LOGE("pinHdi_ is nullptr");
        return HDF_FAILURE;
    }
    info.sensorId = SENSOR_ID;
    info.executorMatcher = EXECUTOR_MATCHER;
    info.executorRole = HdiExecutorRole::ALL_IN_ONE;
    info.authType = HdiAuthType::PIN;
    uint32_t eslRet = 0;
    int32_t result = pinHdi_->GetExecutorInfo(HdiExecutorRole::ALL_IN_ONE, info.publicKey, eslRet,
        info.maxTemplateAcl);
    if (result != SUCCESS) {
        IAM_LOGE("Get all in one ExecutorInfo failed, fail code:%{public}d", result);
        return HDF_FAILURE;
    }
    info.esl = static_cast<HdiExecutorSecureLevel>(eslRet);
    return HDF_SUCCESS;
}

int32_t AllInOneImpl::OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
    const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("start");
    static_cast<void>(extraInfo);
    if (pinHdi_ == nullptr) {
        IAM_LOGE("pinHdi_ is nullptr");
        return HDF_FAILURE;
    }
    int32_t result = pinHdi_->SetAllInOneFwkParam(templateIdList, frameworkPublicKey);
    if (result != SUCCESS) {
        IAM_LOGE("Verify templateData failed");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AllInOneImpl::SendMessage(uint64_t scheduleId, int32_t srcRole, const std::vector<uint8_t> &msg)
{
    static_cast<void>(scheduleId);
    static_cast<void>(srcRole);
    static_cast<void>(msg);
    IAM_LOGI("send message success");
    return HDF_SUCCESS;
}

int32_t AllInOneImpl::EnrollInner(uint64_t scheduleId, const std::vector<uint8_t> &extraInfo,
    const sptr<HdiIExecutorCallback> &callbackObj, std::vector<uint8_t> &algoParameter, uint32_t &algoVersion)
{
    IAM_LOGI("start");
    static_cast<void>(extraInfo);
    if (pinHdi_->GenerateAlgoParameter(algoParameter, algoVersion) != SUCCESS) {
        IAM_LOGE("Generate algorithm parameter failed");
        CallError(callbackObj, GENERAL_ERROR);
        return GENERAL_ERROR;
    }

    ScheduleInfo scheduleInfo = {
        .scheduleId = scheduleId,
        .commandId = ENROLL_PIN,
        .callback = callbackObj,
        .templateId = 0,
        .algoParameter = algoParameter,
    };
    if (!scheduleList_.AddScheduleInfo(scheduleInfo)) {
        IAM_LOGE("Add scheduleInfo failed");
        CallError(callbackObj, GENERAL_ERROR);
        return GENERAL_ERROR;
    }

    return HDF_SUCCESS;
}

int32_t AllInOneImpl::Enroll(uint64_t scheduleId, const std::vector<uint8_t> &extraInfo,
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
    std::string pinComplexityReg = "";
    result = callbackObj->OnGetData(algoParameter, 0, algoVersion, challenge, pinComplexityReg);
    if (result != SUCCESS) {
        IAM_LOGE("Enroll Pin failed, fail code : %{public}d", result);
        CallError(callbackObj, GENERAL_ERROR);
        // If the enroll fails, delete scheduleId of scheduleMap
        scheduleList_.DelScheduleInfo(scheduleId);
    }

    return HDF_SUCCESS;
}

int32_t AllInOneImpl::AuthenticateInner(uint64_t scheduleId, uint64_t templateId, std::vector<uint8_t> &algoParameter,
    const sptr<HdiIExecutorCallback> &callbackObj, const std::vector<uint8_t> &extraInfo)
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
    ScheduleInfo scheduleInfo = {
        .scheduleId = scheduleId,
        .commandId = AUTH_PIN,
        .callback = callbackObj,
        .templateId = templateId,
        .algoParameter = algoParameter,
        .extraInfo = extraInfo,
    };
    if (!scheduleList_.AddScheduleInfo(scheduleInfo)) {
        IAM_LOGE("Add scheduleInfo failed");
        CallError(callbackObj, GENERAL_ERROR);
        return GENERAL_ERROR;
    }

    return SUCCESS;
}

int32_t AllInOneImpl::Authenticate(uint64_t scheduleId, const std::vector<uint64_t>& templateIdList,
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
    OHOS::UserIam::PinAuth::PinAlgoParam pinAlgoParam = {};
    int32_t result = pinHdi_->AllInOneAuth(scheduleId, templateIdList[0], extraInfo, pinAlgoParam);
    if (result != SUCCESS) {
        IAM_LOGE("Get algorithm parameter failed, fail code : %{public}d", result);
        CallError(callbackObj, result);
        return HDF_SUCCESS;
    }
    IAM_LOGI("algorithm parameter len:%{public}zu version:%{public}u",
        pinAlgoParam.algoParameter.size(), pinAlgoParam.algoVersion);
    result = AuthenticateInner(scheduleId, templateIdList[0], pinAlgoParam.algoParameter, callbackObj, extraInfo);
    if (result != SUCCESS) {
        IAM_LOGE("AuthenticateInner failed, fail code : %{public}d", result);
        return HDF_SUCCESS;
    }

    std::string pinComplexityReg = "";
    result = callbackObj->OnGetData(pinAlgoParam.algoParameter, pinAlgoParam.subType, pinAlgoParam.algoVersion,
        pinAlgoParam.challenge, pinComplexityReg);
    if (result != SUCCESS) {
        IAM_LOGE("Authenticate Pin failed, fail code : %{public}d", result);
        CallError(callbackObj, GENERAL_ERROR);
        // If the authentication fails, delete scheduleId of scheduleMap
        scheduleList_.DelScheduleInfo(scheduleId);
    }

    return HDF_SUCCESS;
}

int32_t AllInOneImpl::AuthPin(uint64_t scheduleId, uint64_t templateId, const std::vector<uint8_t> &data,
    const std::vector<uint8_t> &extraInfo, std::vector<uint8_t> &resultTlv)
{
    int32_t result = pinHdi_->AuthPin(scheduleId, templateId, data, extraInfo, resultTlv);
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

int32_t AllInOneImpl::SetData(uint64_t scheduleId, uint64_t authSubType, const std::vector<uint8_t> &data,
    int32_t resultCode)
{
    IAM_LOGI("start");
    if (pinHdi_ == nullptr) {
        IAM_LOGE("pinHdi_ is nullptr");
        return HDF_FAILURE;
    }
    std::vector<uint8_t> resultTlv;
    ScheduleInfo scheduleInfo;
    if (!scheduleList_.GetAndDelScheduleInfo(scheduleId, scheduleInfo)) {
        IAM_LOGE("Get ScheduleInfo failed");
        return HDF_FAILURE;
    }
    if (resultCode != SUCCESS) {
        IAM_LOGE("SetData failed, resultCode is %{public}d", resultCode);
        CallError(scheduleInfo.callback, resultCode);
        return HDF_SUCCESS;
    }
    int32_t result = GENERAL_ERROR;
    switch (scheduleInfo.commandId) {
        case ENROLL_PIN:
            result = pinHdi_->EnrollPin(scheduleId, authSubType, scheduleInfo.algoParameter, data, resultTlv);
            if (result != SUCCESS) {
                IAM_LOGE("Enroll Pin failed, fail code : %{public}d", result);
            }
            break;
        case AUTH_PIN:
            result = AuthPin(scheduleId, scheduleInfo.templateId, data, scheduleInfo.extraInfo, resultTlv);
            if (result != SUCCESS) {
                IAM_LOGE("Auth Pin failed, fail code : %{public}d", result);
            }
            break;
        default:
            IAM_LOGE("Error commandId");
    }

    if (scheduleInfo.callback->OnResult(result, resultTlv) != SUCCESS) {
        IAM_LOGE("callback OnResult failed");
    }
    return HDF_SUCCESS;
}

int32_t AllInOneImpl::Delete(uint64_t templateId)
{
    IAM_LOGI("start");
    if (pinHdi_ == nullptr) {
        IAM_LOGE("pinHdi_ is nullptr");
        return HDF_FAILURE;
    }
    int32_t result = pinHdi_->DeleteTemplate(templateId);
    if (result != SUCCESS) {
        IAM_LOGE("Verify templateData failed, fail code : %{public}d", result);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AllInOneImpl::Cancel(uint64_t scheduleId)
{
    IAM_LOGI("start");
    ScheduleInfo scheduleInfo;
    if (!scheduleList_.GetAndDelScheduleInfo(scheduleId, scheduleInfo)) {
        IAM_LOGE("scheduleId %{public}x is not found", (uint16_t)scheduleId);
        return HDF_FAILURE;
    }
    CallError(scheduleInfo.callback, CANCELED);
    return HDF_SUCCESS;
}

int32_t AllInOneImpl::GetProperty(
    const std::vector<uint64_t> &templateIdList, const std::vector<int32_t> &propertyTypes, HdiProperty &property)
{
    IAM_LOGI("start");
    if (pinHdi_ == nullptr) {
        IAM_LOGE("pinHdi_ is nullptr");
        return HDF_FAILURE;
    }

    if (templateIdList.size() == 0) {
        IAM_LOGE("templateIdList size is 0");
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
    property.nextFailLockoutDuration = infoRet.nextFailLockoutDuration;
    return HDF_SUCCESS;
}

int32_t AllInOneImpl::SendCommand(int32_t commandId, const std::vector<uint8_t> &extraInfo,
    const sptr<HdiIExecutorCallback> &callbackObj)
{
    return HDF_SUCCESS;
}

int32_t AllInOneImpl::Abandon(uint64_t scheduleId, uint64_t templateId, const std::vector<uint8_t> &extraInfo,
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

    std::vector<uint8_t> resultTlv;
    int32_t result = pinHdi_->Abandon(scheduleId, templateId, extraInfo, resultTlv);
    if (result != SUCCESS) {
        IAM_LOGE("Abandon Pin failed, fail code : %{public}d", result);
        CallError(callbackObj, GENERAL_ERROR);
    }

    if (callbackObj->OnResult(result, resultTlv) != SUCCESS) {
        IAM_LOGE("callback OnResult failed");
    }
    return HDF_SUCCESS;
}

bool AllInOneImpl::ScheduleList::AddScheduleInfo(const ScheduleInfo &scheduleInfo)
{
    IAM_LOGI("start");
    if (scheduleInfo.callback == nullptr) {
        IAM_LOGE("callback is nullptr");
        return false;
    }

    std::optional<ScheduleInfo> optScheduleInfo = std::nullopt;
    {
        std::lock_guard<std::mutex> guard(mutex_);
        for (auto iter = scheduleInfoList_.begin(); iter != scheduleInfoList_.end(); ++iter) {
            if ((*iter).scheduleId == scheduleInfo.scheduleId) {
                IAM_LOGE("scheduleId %{public}x already exist", (uint16_t)(scheduleInfo.scheduleId));
                return false;
            }
        }

        if (scheduleInfoList_.size() >= MAX_SCHEDULE_SIZE) {
            optScheduleInfo = scheduleInfoList_.front();
            scheduleInfoList_.pop_front();
        }
        scheduleInfoList_.emplace_back(scheduleInfo);
    }

    if (optScheduleInfo.has_value()) {
        IAM_LOGE("scheduleId %{public}x force stop", (uint16_t)(optScheduleInfo.value().scheduleId));
        CallError(optScheduleInfo.value().callback, GENERAL_ERROR);
    }
    return true;
}

bool AllInOneImpl::ScheduleList::GetAndDelScheduleInfo(uint64_t scheduleId, ScheduleInfo &scheduleInfo)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> guard(mutex_);
    for (auto iter = scheduleInfoList_.begin(); iter != scheduleInfoList_.end(); ++iter) {
        if ((*iter).scheduleId == scheduleId) {
            scheduleInfo = (*iter);
            scheduleInfoList_.erase(iter);
            return true;
        }
    }

    IAM_LOGE("Get scheduleId not exist");
    return false;
}

void AllInOneImpl::ScheduleList::DelScheduleInfo(uint64_t scheduleId)
{
    IAM_LOGI("start");
    std::lock_guard<std::mutex> guard(mutex_);
    for (auto iter = scheduleInfoList_.begin(); iter != scheduleInfoList_.end(); ++iter) {
        if ((*iter).scheduleId == scheduleId) {
            scheduleInfoList_.erase(iter);
            return;
        }
    }
    IAM_LOGE("Delete scheduleId not exist");
}
} // PinAuth
} // HDI
} // OHOS