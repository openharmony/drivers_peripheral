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

#include "ril_interface_impl.h"

#include <hdf_base.h>
#include <hdf_log.h>

namespace OHOS {
namespace HDI {
namespace Ril {
namespace V1_0 {
static std::mutex mutex_;
static sptr<IRilCallback> callback_;
namespace {
sptr<RilInterfaceImpl::RilDeathRecipient> g_deathRecipient = nullptr;
}
extern "C" IRilInterface *RilInterfaceImplGetInstance(void)
{
    using OHOS::HDI::Ril::V1_0::RilInterfaceImpl;
    RilInterfaceImpl *service = new (std::nothrow) RilInterfaceImpl();
    if (service == nullptr) {
        return nullptr;
    }
    if (service->Init() != HDF_SUCCESS) {
        delete service;
        service = nullptr;
        return nullptr;
    }
    return service;
}

// Call
int32_t RilInterfaceImpl::SetEmergencyCallList(
    int32_t slotId, int32_t serialId, const IEmergencyInfoList &emergencyInfoList)
{
    return TaskSchedule(&Telephony::HRilManager::SetEmergencyCallList, slotId, serialId, emergencyInfoList);
}

int32_t RilInterfaceImpl::GetEmergencyCallList(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetEmergencyCallList, slotId, serialId);
}

int32_t RilInterfaceImpl::GetCallList(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetCallList, slotId, serialId);
}

int32_t RilInterfaceImpl::Dial(int32_t slotId, int32_t serialId, const IDialInfo &dialInfo)
{
    return TaskSchedule(&Telephony::HRilManager::Dial, slotId, serialId, dialInfo);
}

int32_t RilInterfaceImpl::Reject(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::Reject, slotId, serialId);
}

int32_t RilInterfaceImpl::Hangup(int32_t slotId, int32_t serialId, int32_t gsmIndex)
{
    return TaskSchedule(&Telephony::HRilManager::Hangup, slotId, serialId, gsmIndex);
}

int32_t RilInterfaceImpl::Answer(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::Answer, slotId, serialId);
}

int32_t RilInterfaceImpl::HoldCall(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::HoldCall, slotId, serialId);
}

int32_t RilInterfaceImpl::UnHoldCall(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::UnHoldCall, slotId, serialId);
}

int32_t RilInterfaceImpl::SwitchCall(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::SwitchCall, slotId, serialId);
}

int32_t RilInterfaceImpl::CombineConference(int32_t slotId, int32_t serialId, int32_t callType)
{
    return TaskSchedule(&Telephony::HRilManager::CombineConference, slotId, serialId, callType);
}

int32_t RilInterfaceImpl::SeparateConference(
    int32_t slotId, int32_t serialId, int32_t callIndex, int32_t callType)
{
    return TaskSchedule(&Telephony::HRilManager::SeparateConference, slotId, serialId, callIndex, callType);
}

int32_t RilInterfaceImpl::GetCallWaiting(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetCallWaiting, slotId, serialId);
}

int32_t RilInterfaceImpl::SetCallWaiting(int32_t slotId, int32_t serialId, int32_t activate)
{
    return TaskSchedule(&Telephony::HRilManager::SetCallWaiting, slotId, serialId, activate);
}

int32_t RilInterfaceImpl::GetCallTransferInfo(int32_t slotId, int32_t serialId, int32_t reason)
{
    return TaskSchedule(&Telephony::HRilManager::GetCallTransferInfo, slotId, serialId, reason);
}

int32_t RilInterfaceImpl::SetCallTransferInfo(
    int32_t slotId, int32_t serialId, const ICallForwardSetInfo &callForwardSetInfo)
{
    return TaskSchedule(&Telephony::HRilManager::SetCallTransferInfo, slotId, serialId, callForwardSetInfo);
}

int32_t RilInterfaceImpl::GetCallRestriction(int32_t slotId, int32_t serialId, const std::string &fac)
{
    return TaskSchedule(&Telephony::HRilManager::GetCallRestriction, slotId, serialId, fac);
}

int32_t RilInterfaceImpl::SetCallRestriction(
    int32_t slotId, int32_t serialId, const ICallRestrictionInfo &callRestrictionInfo)
{
    return TaskSchedule(&Telephony::HRilManager::SetCallRestriction, slotId, serialId, callRestrictionInfo);
}

int32_t RilInterfaceImpl::GetClip(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetClip, slotId, serialId);
}

int32_t RilInterfaceImpl::SetClip(int32_t slotId, int32_t serialId, int32_t action)
{
    return TaskSchedule(&Telephony::HRilManager::SetClip, slotId, serialId, action);
}

int32_t RilInterfaceImpl::GetClir(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetClir, slotId, serialId);
}

int32_t RilInterfaceImpl::SetClir(int32_t slotId, int32_t serialId, int32_t action)
{
    return TaskSchedule(&Telephony::HRilManager::SetClir, slotId, serialId, action);
}

int32_t RilInterfaceImpl::SetCallPreferenceMode(int32_t slotId, int32_t serialId, int32_t mode)
{
    return TaskSchedule(&Telephony::HRilManager::SetCallPreferenceMode, slotId, serialId, mode);
}

int32_t RilInterfaceImpl::GetCallPreferenceMode(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetCallPreferenceMode, slotId, serialId);
}

int32_t RilInterfaceImpl::SetUssd(int32_t slotId, int32_t serialId, const std::string &str)
{
    return TaskSchedule(&Telephony::HRilManager::SetUssd, slotId, serialId, str);
}

int32_t RilInterfaceImpl::GetUssd(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetUssd, slotId, serialId);
}

int32_t RilInterfaceImpl::SetMute(int32_t slotId, int32_t serialId, int32_t mute)
{
    return TaskSchedule(&Telephony::HRilManager::SetMute, slotId, serialId, mute);
}

int32_t RilInterfaceImpl::GetMute(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetMute, slotId, serialId);
}

int32_t RilInterfaceImpl::GetCallFailReason(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetCallFailReason, slotId, serialId);
}

int32_t RilInterfaceImpl::CallSupplement(int32_t slotId, int32_t serialId, int32_t type)
{
    return TaskSchedule(&Telephony::HRilManager::CallSupplement, slotId, serialId, type);
}

int32_t RilInterfaceImpl::SendDtmf(int32_t slotId, int32_t serialId, const IDtmfInfo &dtmfInfo)
{
    return TaskSchedule(&Telephony::HRilManager::SendDtmf, slotId, serialId, dtmfInfo);
}

int32_t RilInterfaceImpl::StartDtmf(int32_t slotId, int32_t serialId, const IDtmfInfo &dtmfInfo)
{
    return TaskSchedule(&Telephony::HRilManager::StartDtmf, slotId, serialId, dtmfInfo);
}

int32_t RilInterfaceImpl::StopDtmf(int32_t slotId, int32_t serialId, const IDtmfInfo &dtmfInfo)
{
    return TaskSchedule(&Telephony::HRilManager::StopDtmf, slotId, serialId, dtmfInfo);
}

int32_t RilInterfaceImpl::SetBarringPassword(
    int32_t slotId, int32_t serialId, const ISetBarringInfo &setBarringInfo)
{
    return TaskSchedule(&Telephony::HRilManager::SetBarringPassword, slotId, serialId, setBarringInfo);
}

// Data
int32_t RilInterfaceImpl::ActivatePdpContext(int32_t slotId, int32_t serialId, const IDataCallInfo &dataCallInfo)
{
    return TaskSchedule(&Telephony::HRilManager::ActivatePdpContext, slotId, serialId, dataCallInfo);
}

int32_t RilInterfaceImpl::DeactivatePdpContext(int32_t slotId, int32_t serialId, const IUniInfo &uniInfo)
{
    return TaskSchedule(&Telephony::HRilManager::DeactivatePdpContext, slotId, serialId, uniInfo);
}

int32_t RilInterfaceImpl::GetPdpContextList(int32_t slotId, int32_t serialId, const IUniInfo &uniInfo)
{
    return TaskSchedule(&Telephony::HRilManager::GetPdpContextList, slotId, serialId, uniInfo);
}

int32_t RilInterfaceImpl::SetInitApnInfo(
    int32_t slotId, int32_t serialId, const IDataProfileDataInfo &dataProfileDataInfo)
{
    return TaskSchedule(&Telephony::HRilManager::SetInitApnInfo, slotId, serialId, dataProfileDataInfo);
}

int32_t RilInterfaceImpl::GetLinkBandwidthInfo(int32_t slotId, int32_t serialId, int32_t cid)
{
    return TaskSchedule(&Telephony::HRilManager::GetLinkBandwidthInfo, slotId, serialId, cid);
}

int32_t RilInterfaceImpl::SetLinkBandwidthReportingRule(
    int32_t slotId, int32_t serialId, const IDataLinkBandwidthReportingRule &dataLinkBandwidthReportingRule)
{
    return TaskSchedule(
        &Telephony::HRilManager::SetLinkBandwidthReportingRule, slotId, serialId, dataLinkBandwidthReportingRule);
}

int32_t RilInterfaceImpl::SetDataPermitted(int32_t slotId, int32_t serialId, int32_t dataPermitted)
{
    return TaskSchedule(&Telephony::HRilManager::SetDataPermitted, slotId, serialId, dataPermitted);
}

int32_t RilInterfaceImpl::SetDataProfileInfo(
    int32_t slotId, int32_t serialId, const IDataProfilesInfo &dataProfilesInfo)
{
    return TaskSchedule(&Telephony::HRilManager::SetDataProfileInfo, slotId, serialId, dataProfilesInfo);
}

// Modem
int32_t RilInterfaceImpl::SetRadioState(int32_t slotId, int32_t serialId, int32_t fun, int32_t rst)
{
    return TaskSchedule(&Telephony::HRilManager::SetRadioState, slotId, serialId, fun, rst);
}

int32_t RilInterfaceImpl::GetRadioState(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetRadioState, slotId, serialId);
}

int32_t RilInterfaceImpl::GetImei(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetImei, slotId, serialId);
}

int32_t RilInterfaceImpl::GetMeid(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetMeid, slotId, serialId);
}

int32_t RilInterfaceImpl::GetVoiceRadioTechnology(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetVoiceRadioTechnology, slotId, serialId);
}

int32_t RilInterfaceImpl::GetBasebandVersion(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetBasebandVersion, slotId, serialId);
}

int32_t RilInterfaceImpl::ShutDown(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::ShutDown, slotId, serialId);
}

int32_t RilInterfaceImpl::SetCallback(const sptr<IRilCallback> &rilCallback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    callback_ = rilCallback;
    if (callback_ == nullptr) {
        UnRegister();
        return HDF_SUCCESS;
    }
    g_deathRecipient = new RilDeathRecipient(this);
    if (g_deathRecipient == nullptr) {
        HDF_LOGE("SetCallback fail g_deathRecipient is null");
        return HDF_FAILURE;
    }
    AddRilDeathRecipient(callback_);
    if (Telephony::HRilManager::manager_ == nullptr) {
        HDF_LOGE("SetCallback fail manager_ is null");
        return HDF_FAILURE;
    }
    Telephony::HRilManager::manager_->SetRilCallback(callback_);
    return HDF_SUCCESS;
}

int32_t RilInterfaceImpl::GetSimIO(int32_t slotId, int32_t serialId, const ISimIoRequestInfo &simIO)
{
    return TaskSchedule(&Telephony::HRilManager::GetSimIO, slotId, serialId, simIO);
}

int32_t RilInterfaceImpl::GetSimStatus(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetSimStatus, slotId, serialId);
}

int32_t RilInterfaceImpl::GetImsi(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetImsi, slotId, serialId);
}

int32_t RilInterfaceImpl::GetSimLockStatus(int32_t slotId, int32_t serialId, const ISimLockInfo &simLockInfo)
{
    return TaskSchedule(&Telephony::HRilManager::GetSimLockStatus, slotId, serialId, simLockInfo);
}

int32_t RilInterfaceImpl::SetSimLock(int32_t slotId, int32_t serialId, const ISimLockInfo &simLockInfo)
{
    return TaskSchedule(&Telephony::HRilManager::SetSimLock, slotId, serialId, simLockInfo);
}

int32_t RilInterfaceImpl::ChangeSimPassword(int32_t slotId, int32_t serialId, const ISimPasswordInfo &simPassword)
{
    return TaskSchedule(&Telephony::HRilManager::ChangeSimPassword, slotId, serialId, simPassword);
}

int32_t RilInterfaceImpl::UnlockPin(int32_t slotId, int32_t serialId, const std::string &pin)
{
    return TaskSchedule(&Telephony::HRilManager::UnlockPin, slotId, serialId, pin);
}

int32_t RilInterfaceImpl::UnlockPuk(int32_t slotId, int32_t serialId, const std::string &puk, const std::string &pin)
{
    return TaskSchedule(&Telephony::HRilManager::UnlockPuk, slotId, serialId, puk, pin);
}

int32_t RilInterfaceImpl::UnlockPin2(int32_t slotId, int32_t serialId, const std::string &pin2)
{
    return TaskSchedule(&Telephony::HRilManager::UnlockPin2, slotId, serialId, pin2);
}

int32_t RilInterfaceImpl::UnlockPuk2(int32_t slotId, int32_t serialId, const std::string &puk2, const std::string &pin2)
{
    return TaskSchedule(&Telephony::HRilManager::UnlockPuk2, slotId, serialId, puk2, pin2);
}

int32_t RilInterfaceImpl::SetActiveSim(int32_t slotId, int32_t serialId, int32_t index, int32_t enable)
{
    return TaskSchedule(&Telephony::HRilManager::SetActiveSim, slotId, serialId, index, enable);
}

int32_t RilInterfaceImpl::SimStkSendTerminalResponse(int32_t slotId, int32_t serialId, const std::string &strCmd)
{
    return TaskSchedule(&Telephony::HRilManager::SimStkSendTerminalResponse, slotId, serialId, strCmd);
}

int32_t RilInterfaceImpl::SimStkSendEnvelope(int32_t slotId, int32_t serialId, const std::string &strCmd)
{
    return TaskSchedule(&Telephony::HRilManager::SimStkSendEnvelope, slotId, serialId, strCmd);
}

int32_t RilInterfaceImpl::SimStkSendCallSetupRequestResult(int32_t slotId, int32_t serialId, int32_t accept)
{
    return TaskSchedule(&Telephony::HRilManager::SimStkSendCallSetupRequestResult, slotId, serialId, accept);
}

int32_t RilInterfaceImpl::SimStkIsReady(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::SimStkIsReady, slotId, serialId);
}

int32_t RilInterfaceImpl::SetRadioProtocol(int32_t slotId, int32_t serialId, const ISimProtocolRequest &protocol)
{
    return TaskSchedule(&Telephony::HRilManager::SetRadioProtocol, slotId, serialId, protocol);
}

int32_t RilInterfaceImpl::SimOpenLogicalChannel(int32_t slotId, int32_t serialId, const std::string &appID, int32_t p2)
{
    return TaskSchedule(&Telephony::HRilManager::SimOpenLogicalChannel, slotId, serialId, appID, p2);
}

int32_t RilInterfaceImpl::SimCloseLogicalChannel(int32_t slotId, int32_t serialId, int32_t channelId)
{
    return TaskSchedule(&Telephony::HRilManager::SimCloseLogicalChannel, slotId, serialId, channelId);
}

int32_t RilInterfaceImpl::SimTransmitApduLogicalChannel(
    int32_t slotId, int32_t serialId, const IApduSimIORequestInfo &apduSimIO)
{
    return TaskSchedule(&Telephony::HRilManager::SimTransmitApduLogicalChannel, slotId, serialId, apduSimIO);
}

int32_t RilInterfaceImpl::SimTransmitApduBasicChannel(
    int32_t slotId, int32_t serialId, const IApduSimIORequestInfo &apduSimIO)
{
    return TaskSchedule(&Telephony::HRilManager::SimTransmitApduBasicChannel, slotId, serialId, apduSimIO);
}

int32_t RilInterfaceImpl::SimAuthentication(
    int32_t slotId, int32_t serialId, const ISimAuthenticationRequestInfo &simAuthInfo)
{
    return TaskSchedule(&Telephony::HRilManager::SimAuthentication, slotId, serialId, simAuthInfo);
}

int32_t RilInterfaceImpl::UnlockSimLock(int32_t slotId, int32_t serialId, int32_t lockType, const std::string &key)
{
    return TaskSchedule(&Telephony::HRilManager::UnlockSimLock, slotId, serialId, lockType, key);
}

int32_t RilInterfaceImpl::AddRilDeathRecipient(const sptr<IRilCallback> &callback)
{
    const sptr<IRemoteObject> &remote = OHOS::HDI::hdi_objcast<IRilCallback>(callback);
    if (!remote->AddDeathRecipient(g_deathRecipient)) {
        HDF_LOGE("AddRilDeathRecipient fail");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t RilInterfaceImpl::RemoveRilDeathRecipient(const sptr<IRilCallback> &callback)
{
    const sptr<IRemoteObject> &remote = OHOS::HDI::hdi_objcast<IRilCallback>(callback);
    if (!remote->RemoveDeathRecipient(g_deathRecipient)) {
        HDF_LOGI("RemoveRilDeathRecipient fail");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

void RilInterfaceImpl::RilDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    if (rilInterfaceImpl_ == nullptr) {
        HDF_LOGE("RilInterfaceImpl::RilDeathRecipient::OnRemoteDied fail rilInterfaceImpl_ is null");
        return;
    }
    rilInterfaceImpl_->UnRegister();
}

int32_t RilInterfaceImpl::UnRegister()
{
    HDF_LOGI("UnRegister");
    RemoveRilDeathRecipient(callback_);
    callback_ = nullptr;
    if (Telephony::HRilManager::manager_ == nullptr) {
        HDF_LOGE("RilInterfaceImpl::UnRegister fail manager_ is null");
        return HDF_FAILURE;
    }
    Telephony::HRilManager::manager_->SetRilCallback(nullptr);
    return HDF_SUCCESS;
}

int32_t RilInterfaceImpl::Init()
{
    if (Telephony::HRilManager::manager_ == nullptr) {
        HDF_LOGE("RilInterfaceImpl::Init is manager_ is null");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
} // namespace V1_0
} // namespace Ril
} // namespace HDI
} // namespace OHOS
