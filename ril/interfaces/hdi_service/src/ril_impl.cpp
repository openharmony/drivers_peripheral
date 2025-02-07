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

#include "ril_impl.h"

#include <hdf_base.h>
#include <hdf_log.h>

namespace OHOS {
namespace HDI {
namespace Ril {
namespace V1_4 {
static std::mutex mutex_;
static sptr<V1_1::IRilCallback> callback1_1_;
static sptr<V1_2::IRilCallback> callback1_2_;
static sptr<V1_3::IRilCallback> callback1_3_;
static sptr<V1_4::IRilCallback> callback_;
namespace {
sptr<RilImpl::RilDeathRecipient> g_deathRecipient = nullptr;
}
extern "C" IRil *RilImplGetInstance(void)
{
    using OHOS::HDI::Ril::V1_4::RilImpl;
    RilImpl *service = new (std::nothrow) RilImpl();
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
int32_t RilImpl::SetEmergencyCallList(
    int32_t slotId, int32_t serialId, const EmergencyInfoList &emergencyInfoList)
{
    return TaskSchedule(&Telephony::HRilManager::SetEmergencyCallList, slotId, serialId, emergencyInfoList);
}

int32_t RilImpl::GetEmergencyCallList(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetEmergencyCallList, slotId, serialId);
}

int32_t RilImpl::GetCallList(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetCallList, slotId, serialId);
}

int32_t RilImpl::Dial(int32_t slotId, int32_t serialId, const DialInfo &dialInfo)
{
    return TaskSchedule(&Telephony::HRilManager::Dial, slotId, serialId, dialInfo);
}

int32_t RilImpl::Reject(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::Reject, slotId, serialId);
}

int32_t RilImpl::Hangup(int32_t slotId, int32_t serialId, int32_t gsmIndex)
{
    return TaskSchedule(&Telephony::HRilManager::Hangup, slotId, serialId, gsmIndex);
}

int32_t RilImpl::Answer(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::Answer, slotId, serialId);
}

int32_t RilImpl::HoldCall(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::HoldCall, slotId, serialId);
}

int32_t RilImpl::UnHoldCall(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::UnHoldCall, slotId, serialId);
}

int32_t RilImpl::SwitchCall(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::SwitchCall, slotId, serialId);
}

int32_t RilImpl::CombineConference(int32_t slotId, int32_t serialId, int32_t callType)
{
    return TaskSchedule(&Telephony::HRilManager::CombineConference, slotId, serialId, callType);
}

int32_t RilImpl::SeparateConference(
    int32_t slotId, int32_t serialId, int32_t callIndex, int32_t callType)
{
    return TaskSchedule(&Telephony::HRilManager::SeparateConference, slotId, serialId, callIndex, callType);
}

int32_t RilImpl::GetCallWaiting(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetCallWaiting, slotId, serialId);
}

int32_t RilImpl::SetCallWaiting(int32_t slotId, int32_t serialId, int32_t activate)
{
    return TaskSchedule(&Telephony::HRilManager::SetCallWaiting, slotId, serialId, activate);
}

int32_t RilImpl::GetCallTransferInfo(int32_t slotId, int32_t serialId, int32_t reason)
{
    return TaskSchedule(&Telephony::HRilManager::GetCallTransferInfo, slotId, serialId, reason);
}

int32_t RilImpl::SetCallTransferInfo(
    int32_t slotId, int32_t serialId, const CallForwardSetInfo &callForwardSetInfo)
{
    return TaskSchedule(&Telephony::HRilManager::SetCallTransferInfo, slotId, serialId, callForwardSetInfo);
}

int32_t RilImpl::GetCallRestriction(int32_t slotId, int32_t serialId, const std::string &fac)
{
    return TaskSchedule(&Telephony::HRilManager::GetCallRestriction, slotId, serialId, fac);
}

int32_t RilImpl::SetCallRestriction(
    int32_t slotId, int32_t serialId, const CallRestrictionInfo &callRestrictionInfo)
{
    return TaskSchedule(&Telephony::HRilManager::SetCallRestriction, slotId, serialId, callRestrictionInfo);
}

int32_t RilImpl::GetClip(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetClip, slotId, serialId);
}

int32_t RilImpl::SetClip(int32_t slotId, int32_t serialId, int32_t action)
{
    return TaskSchedule(&Telephony::HRilManager::SetClip, slotId, serialId, action);
}

int32_t RilImpl::GetClir(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetClir, slotId, serialId);
}

int32_t RilImpl::SetClir(int32_t slotId, int32_t serialId, int32_t action)
{
    return TaskSchedule(&Telephony::HRilManager::SetClir, slotId, serialId, action);
}

int32_t RilImpl::SetCallPreferenceMode(int32_t slotId, int32_t serialId, int32_t mode)
{
    return TaskSchedule(&Telephony::HRilManager::SetCallPreferenceMode, slotId, serialId, mode);
}

int32_t RilImpl::GetCallPreferenceMode(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetCallPreferenceMode, slotId, serialId);
}

int32_t RilImpl::SetUssd(int32_t slotId, int32_t serialId, const std::string &str)
{
    return TaskSchedule(&Telephony::HRilManager::SetUssd, slotId, serialId, str);
}

int32_t RilImpl::CloseUnFinishedUssd(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::CloseUnFinishedUssd, slotId, serialId);
}

int32_t RilImpl::GetUssd(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetUssd, slotId, serialId);
}

int32_t RilImpl::SetMute(int32_t slotId, int32_t serialId, int32_t mute)
{
    return TaskSchedule(&Telephony::HRilManager::SetMute, slotId, serialId, mute);
}

int32_t RilImpl::GetMute(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetMute, slotId, serialId);
}

int32_t RilImpl::GetCallFailReason(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetCallFailReason, slotId, serialId);
}

int32_t RilImpl::CallSupplement(int32_t slotId, int32_t serialId, int32_t type)
{
    return TaskSchedule(&Telephony::HRilManager::CallSupplement, slotId, serialId, type);
}

int32_t RilImpl::SendDtmf(int32_t slotId, int32_t serialId, const DtmfInfo &dtmfInfo)
{
    return TaskSchedule(&Telephony::HRilManager::SendDtmf, slotId, serialId, dtmfInfo);
}

int32_t RilImpl::StartDtmf(int32_t slotId, int32_t serialId, const DtmfInfo &dtmfInfo)
{
    return TaskSchedule(&Telephony::HRilManager::StartDtmf, slotId, serialId, dtmfInfo);
}

int32_t RilImpl::StopDtmf(int32_t slotId, int32_t serialId, const DtmfInfo &dtmfInfo)
{
    return TaskSchedule(&Telephony::HRilManager::StopDtmf, slotId, serialId, dtmfInfo);
}

int32_t RilImpl::SetBarringPassword(
    int32_t slotId, int32_t serialId, const SetBarringInfo &setBarringInfo)
{
    return TaskSchedule(&Telephony::HRilManager::SetBarringPassword, slotId, serialId, setBarringInfo);
}

int32_t RilImpl::SetVonrSwitch(int32_t slotId, int32_t serialId, int32_t status)
{
    return TaskSchedule(&Telephony::HRilManager::SetVonrSwitch, slotId, serialId, status);
}

// Data
int32_t RilImpl::ActivatePdpContext(int32_t slotId, int32_t serialId, const DataCallInfo &dataCallInfo)
{
    return TaskSchedule(&Telephony::HRilManager::ActivatePdpContext, slotId, serialId, dataCallInfo);
}

int32_t RilImpl::ActivatePdpContextWithApnTypes(int32_t slotId, int32_t serialId,
    const DataCallInfoWithApnTypes &dataCallInfo)
{
    return TaskSchedule(&Telephony::HRilManager::ActivatePdpContextWithApnTypes, slotId, serialId, dataCallInfo);
}

int32_t RilImpl::DeactivatePdpContext(int32_t slotId, int32_t serialId, const UniInfo &uniInfo)
{
    return TaskSchedule(&Telephony::HRilManager::DeactivatePdpContext, slotId, serialId, uniInfo);
}

int32_t RilImpl::GetPdpContextList(int32_t slotId, int32_t serialId, const UniInfo &uniInfo)
{
    return TaskSchedule(&Telephony::HRilManager::GetPdpContextList, slotId, serialId, uniInfo);
}

int32_t RilImpl::SetInitApnInfo(
    int32_t slotId, int32_t serialId, const DataProfileDataInfo &dataProfileDataInfo)
{
    return TaskSchedule(&Telephony::HRilManager::SetInitApnInfo, slotId, serialId, dataProfileDataInfo);
}

int32_t RilImpl::GetLinkBandwidthInfo(int32_t slotId, int32_t serialId, int32_t cid)
{
    return TaskSchedule(&Telephony::HRilManager::GetLinkBandwidthInfo, slotId, serialId, cid);
}

int32_t RilImpl::GetLinkCapability(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetLinkCapability, slotId, serialId);
}

int32_t RilImpl::SetLinkBandwidthReportingRule(
    int32_t slotId, int32_t serialId, const DataLinkBandwidthReportingRule &dataLinkBandwidthReportingRule)
{
    return TaskSchedule(
        &Telephony::HRilManager::SetLinkBandwidthReportingRule, slotId, serialId, dataLinkBandwidthReportingRule);
}

int32_t RilImpl::SetDataPermitted(int32_t slotId, int32_t serialId, int32_t dataPermitted)
{
    return TaskSchedule(&Telephony::HRilManager::SetDataPermitted, slotId, serialId, dataPermitted);
}

int32_t RilImpl::SetDataProfileInfo(
    int32_t slotId, int32_t serialId, const DataProfilesInfo &dataProfilesInfo)
{
    return TaskSchedule(&Telephony::HRilManager::SetDataProfileInfo, slotId, serialId, dataProfilesInfo);
}

int32_t RilImpl::SendDataPerformanceMode(
    int32_t slotId, int32_t serialId, const DataPerformanceInfo &dataPerformanceInfo)
{
    return TaskSchedule(&Telephony::HRilManager::SendDataPerformanceMode, slotId, serialId, dataPerformanceInfo);
}

int32_t RilImpl::SendDataSleepMode(
    int32_t slotId, int32_t serialId, const DataSleepInfo &dataSleepInfo)
{
    return TaskSchedule(&Telephony::HRilManager::SendDataSleepMode, slotId, serialId, dataSleepInfo);
}

int32_t RilImpl::CleanAllConnections(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::CleanAllConnections, slotId, serialId);
}

// Modem
int32_t RilImpl::SetRadioState(int32_t slotId, int32_t serialId, int32_t fun, int32_t rst)
{
    return TaskSchedule(&Telephony::HRilManager::SetRadioState, slotId, serialId, fun, rst);
}

int32_t RilImpl::GetRadioState(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetRadioState, slotId, serialId);
}

int32_t RilImpl::GetImei(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetImei, slotId, serialId);
}

int32_t RilImpl::GetImeiSv(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetImeiSv, slotId, serialId);
}

int32_t RilImpl::GetMeid(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetMeid, slotId, serialId);
}

int32_t RilImpl::GetVoiceRadioTechnology(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetVoiceRadioTechnology, slotId, serialId);
}

int32_t RilImpl::GetBasebandVersion(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetBasebandVersion, slotId, serialId);
}

int32_t RilImpl::ShutDown(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::ShutDown, slotId, serialId);
}

// Network
int32_t RilImpl::GetSignalStrength(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetSignalStrength, slotId, serialId);
}

int32_t RilImpl::GetCsRegStatus(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetCsRegStatus, slotId, serialId);
}

int32_t RilImpl::GetPsRegStatus(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetPsRegStatus, slotId, serialId);
}

int32_t RilImpl::GetOperatorInfo(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetOperatorInfo, slotId, serialId);
}

int32_t RilImpl::GetNetworkSearchInformation(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetNetworkSearchInformation, slotId, serialId);
}

int32_t RilImpl::GetNetworkSelectionMode(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetNetworkSelectionMode, slotId, serialId);
}

int32_t RilImpl::SetNetworkSelectionMode(
    int32_t slotId, int32_t serialId, const SetNetworkModeInfo &networkModeInfo)
{
    return TaskSchedule(&Telephony::HRilManager::SetNetworkSelectionMode, slotId, serialId, networkModeInfo);
}

int32_t RilImpl::GetNeighboringCellInfoList(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetNeighboringCellInfoList, slotId, serialId);
}

int32_t RilImpl::GetCurrentCellInfo(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetCurrentCellInfo, slotId, serialId);
}

int32_t RilImpl::SetPreferredNetwork(int32_t slotId, int32_t serialId, int32_t preferredNetworkType)
{
    return TaskSchedule(&Telephony::HRilManager::SetPreferredNetwork, slotId, serialId, preferredNetworkType);
}

int32_t RilImpl::GetPreferredNetwork(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetPreferredNetwork, slotId, serialId);
}

int32_t RilImpl::GetPhysicalChannelConfig(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetPhysicalChannelConfig, slotId, serialId);
}

int32_t RilImpl::SetLocateUpdates(int32_t slotId, int32_t serialId, const RilRegNotifyMode mode)
{
    return TaskSchedule(&Telephony::HRilManager::SetLocateUpdates, slotId, serialId, mode);
}

int32_t RilImpl::SetNotificationFilter(int32_t slotId, int32_t serialId, int32_t newFilter)
{
    return TaskSchedule(&Telephony::HRilManager::SetNotificationFilter, slotId, serialId, newFilter);
}

int32_t RilImpl::SetDeviceState(
    int32_t slotId, int32_t serialId, int32_t deviceStateType, int32_t deviceStateOn)
{
    return TaskSchedule(
        &Telephony::HRilManager::SetDeviceState, slotId, serialId, deviceStateType, deviceStateOn);
}

int32_t RilImpl::SetNrOptionMode(int32_t slotId, int32_t serialId, int32_t mode)
{
    return TaskSchedule(&Telephony::HRilManager::SetNrOptionMode, slotId, serialId, mode);
}

int32_t RilImpl::GetNrOptionMode(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetNrOptionMode, slotId, serialId);
}

int32_t RilImpl::GetRrcConnectionState(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetRrcConnectionState, slotId, serialId);
}

int32_t RilImpl::GetNrSsbId(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetNrSsbId, slotId, serialId);
}

int32_t RilImpl::SetCallback(const sptr<V1_1::IRilCallback> &rilCallback)
{
    return HDF_SUCCESS;
}

int32_t RilImpl::SetCallback1_2(const sptr<V1_2::IRilCallback> &rilCallback)
{
    return HDF_SUCCESS;
}

int32_t RilImpl::SetCallback1_3(const sptr<V1_3::IRilCallback> &rilCallback)
{
    return HDF_SUCCESS;
}

int32_t RilImpl::SetCallback1_4(const sptr<V1_4::IRilCallback> &rilCallback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    callback_ = rilCallback;
    if (callback_ == nullptr) {
        UnRegister();
        return HDF_SUCCESS;
    }
    g_deathRecipient = new RilDeathRecipient(this);
    if (g_deathRecipient == nullptr) {
        HDF_LOGE("SetCallback1_4 fail g_deathRecipient is null");
        return HDF_FAILURE;
    }
    AddRilDeathRecipient(callback_);
    Telephony::HRilManager::GetInstance().SetRilCallback(callback_);
    return HDF_SUCCESS;
}

int32_t RilImpl::GetSimIO(int32_t slotId, int32_t serialId, const SimIoRequestInfo &simIO)
{
    return TaskSchedule(&Telephony::HRilManager::GetSimIO, slotId, serialId, simIO);
}

int32_t RilImpl::GetSimStatus(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetSimStatus, slotId, serialId);
}

int32_t RilImpl::GetImsi(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetImsi, slotId, serialId);
}

int32_t RilImpl::GetSimLockStatus(int32_t slotId, int32_t serialId, const SimLockInfo &simLockInfo)
{
    return TaskSchedule(&Telephony::HRilManager::GetSimLockStatus, slotId, serialId, simLockInfo);
}

int32_t RilImpl::SetSimLock(int32_t slotId, int32_t serialId, const SimLockInfo &simLockInfo)
{
    return TaskSchedule(&Telephony::HRilManager::SetSimLock, slotId, serialId, simLockInfo);
}

int32_t RilImpl::ChangeSimPassword(int32_t slotId, int32_t serialId, const SimPasswordInfo &simPassword)
{
    return TaskSchedule(&Telephony::HRilManager::ChangeSimPassword, slotId, serialId, simPassword);
}

int32_t RilImpl::UnlockPin(int32_t slotId, int32_t serialId, const std::string &pin)
{
    return TaskSchedule(&Telephony::HRilManager::UnlockPin, slotId, serialId, pin);
}

int32_t RilImpl::UnlockPuk(int32_t slotId, int32_t serialId, const std::string &puk, const std::string &pin)
{
    return TaskSchedule(&Telephony::HRilManager::UnlockPuk, slotId, serialId, puk, pin);
}

int32_t RilImpl::UnlockPin2(int32_t slotId, int32_t serialId, const std::string &pin2)
{
    return TaskSchedule(&Telephony::HRilManager::UnlockPin2, slotId, serialId, pin2);
}

int32_t RilImpl::UnlockPuk2(int32_t slotId, int32_t serialId, const std::string &puk2, const std::string &pin2)
{
    return TaskSchedule(&Telephony::HRilManager::UnlockPuk2, slotId, serialId, puk2, pin2);
}

int32_t RilImpl::SetActiveSim(int32_t slotId, int32_t serialId, int32_t index, int32_t enable)
{
    return TaskSchedule(&Telephony::HRilManager::SetActiveSim, slotId, serialId, index, enable);
}

int32_t RilImpl::SimStkSendTerminalResponse(int32_t slotId, int32_t serialId, const std::string &strCmd)
{
    return TaskSchedule(&Telephony::HRilManager::SimStkSendTerminalResponse, slotId, serialId, strCmd);
}

int32_t RilImpl::SimStkSendEnvelope(int32_t slotId, int32_t serialId, const std::string &strCmd)
{
    return TaskSchedule(&Telephony::HRilManager::SimStkSendEnvelope, slotId, serialId, strCmd);
}

int32_t RilImpl::SimStkSendCallSetupRequestResult(int32_t slotId, int32_t serialId, int32_t accept)
{
    return TaskSchedule(&Telephony::HRilManager::SimStkSendCallSetupRequestResult, slotId, serialId, accept);
}

int32_t RilImpl::SimStkIsReady(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::SimStkIsReady, slotId, serialId);
}

int32_t RilImpl::GetRadioProtocol(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetRadioProtocol, slotId, serialId);
}

int32_t RilImpl::SetRadioProtocol(int32_t slotId, int32_t serialId, const RadioProtocol &radioProtocol)
{
    return TaskSchedule(&Telephony::HRilManager::SetRadioProtocol, slotId, serialId, radioProtocol);
}

int32_t RilImpl::SimOpenLogicalChannel(int32_t slotId, int32_t serialId, const std::string &appID, int32_t p2)
{
    return TaskSchedule(&Telephony::HRilManager::SimOpenLogicalChannel, slotId, serialId, appID, p2);
}

int32_t RilImpl::SimCloseLogicalChannel(int32_t slotId, int32_t serialId, int32_t channelId)
{
    return TaskSchedule(&Telephony::HRilManager::SimCloseLogicalChannel, slotId, serialId, channelId);
}

int32_t RilImpl::SimTransmitApduLogicalChannel(int32_t slotId, int32_t serialId, const ApduSimIORequestInfo &apduSimIO)
{
    return TaskSchedule(&Telephony::HRilManager::SimTransmitApduLogicalChannel, slotId, serialId, apduSimIO);
}

int32_t RilImpl::SimTransmitApduBasicChannel(int32_t slotId, int32_t serialId, const ApduSimIORequestInfo &apduSimIO)
{
    return TaskSchedule(&Telephony::HRilManager::SimTransmitApduBasicChannel, slotId, serialId, apduSimIO);
}

int32_t RilImpl::SimAuthentication(int32_t slotId, int32_t serialId, const SimAuthenticationRequestInfo &simAuthInfo)
{
    return TaskSchedule(&Telephony::HRilManager::SimAuthentication, slotId, serialId, simAuthInfo);
}

int32_t RilImpl::UnlockSimLock(int32_t slotId, int32_t serialId, int32_t lockType, const std::string &key)
{
    return TaskSchedule(&Telephony::HRilManager::UnlockSimLock, slotId, serialId, lockType, key);
}

int32_t RilImpl::SendSimMatchedOperatorInfo(int32_t slotId, int32_t serialId, const NcfgOperatorInfo &ncfgOperatorInfo)
{
    return TaskSchedule(&Telephony::HRilManager::SendSimMatchedOperatorInfo, slotId, serialId, ncfgOperatorInfo);
}

// Sms
int32_t RilImpl::SendGsmSms(int32_t slotId, int32_t serialId, const GsmSmsMessageInfo &gsmSmsMessageInfo)
{
    return TaskSchedule(&Telephony::HRilManager::SendGsmSms, slotId, serialId, gsmSmsMessageInfo);
}

int32_t RilImpl::SendCdmaSms(int32_t slotId, int32_t serialId, const SendCdmaSmsMessageInfo &cdmaSmsMessageInfo)
{
    return TaskSchedule(&Telephony::HRilManager::SendCdmaSms, slotId, serialId, cdmaSmsMessageInfo);
}

int32_t RilImpl::AddSimMessage(int32_t slotId, int32_t serialId, const SmsMessageIOInfo &smsMessageIOInfo)
{
    return TaskSchedule(&Telephony::HRilManager::AddSimMessage, slotId, serialId, smsMessageIOInfo);
}

int32_t RilImpl::DelSimMessage(int32_t slotId, int32_t serialId, int32_t index)
{
    return TaskSchedule(&Telephony::HRilManager::DelSimMessage, slotId, serialId, index);
}

int32_t RilImpl::UpdateSimMessage(int32_t slotId, int32_t serialId, const SmsMessageIOInfo &smsMessageIOInfo)
{
    return TaskSchedule(&Telephony::HRilManager::UpdateSimMessage, slotId, serialId, smsMessageIOInfo);
}

int32_t RilImpl::AddCdmaSimMessage(int32_t slotId, int32_t serialId, const SmsMessageIOInfo &smsMessageIOInfo)
{
    return TaskSchedule(&Telephony::HRilManager::AddCdmaSimMessage, slotId, serialId, smsMessageIOInfo);
}

int32_t RilImpl::DelCdmaSimMessage(int32_t slotId, int32_t serialId, int32_t index)
{
    return TaskSchedule(&Telephony::HRilManager::DelCdmaSimMessage, slotId, serialId, index);
}

int32_t RilImpl::UpdateCdmaSimMessage(int32_t slotId, int32_t serialId, const SmsMessageIOInfo &smsMessageIOInfo)
{
    return TaskSchedule(&Telephony::HRilManager::UpdateCdmaSimMessage, slotId, serialId, smsMessageIOInfo);
}

int32_t RilImpl::SetSmscAddr(int32_t slotId, int32_t serialId, const ServiceCenterAddress &serviceCenterAddress)
{
    return TaskSchedule(&Telephony::HRilManager::SetSmscAddr, slotId, serialId, serviceCenterAddress);
}

int32_t RilImpl::GetSmscAddr(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetSmscAddr, slotId, serialId);
}

int32_t RilImpl::SetCBConfig(int32_t slotId, int32_t serialId, const CBConfigInfo &cellBroadcastInfo)
{
    return TaskSchedule(&Telephony::HRilManager::SetCBConfig, slotId, serialId, cellBroadcastInfo);
}

int32_t RilImpl::GetCBConfig(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetCBConfig, slotId, serialId);
}

int32_t RilImpl::SetCdmaCBConfig(int32_t slotId, int32_t serialId, const CdmaCBConfigInfoList &cdmaCBConfigInfoList)
{
    return TaskSchedule(&Telephony::HRilManager::SetCdmaCBConfig, slotId, serialId, cdmaCBConfigInfoList);
}

int32_t RilImpl::GetCdmaCBConfig(int32_t slotId, int32_t serialId)
{
    return TaskSchedule(&Telephony::HRilManager::GetCdmaCBConfig, slotId, serialId);
}

int32_t RilImpl::SendSmsMoreMode(int32_t slotId, int32_t serialId, const GsmSmsMessageInfo &gsmSmsMessageInfo)
{
    return TaskSchedule(&Telephony::HRilManager::SendSmsMoreMode, slotId, serialId, gsmSmsMessageInfo);
}

int32_t RilImpl::SendSmsAck(int32_t slotId, int32_t serialId, const ModeData &modeData)
{
    return TaskSchedule(&Telephony::HRilManager::SendSmsAck, slotId, serialId, modeData);
}

int32_t RilImpl::SendRilAck()
{
    return Telephony::HRilManager::GetInstance().SendRilAck();
}

int32_t RilImpl::AddRilDeathRecipient(const sptr<IRilCallback> &callback)
{
    const sptr<IRemoteObject> &remote = OHOS::HDI::hdi_objcast<IRilCallback>(callback);
    if (!remote->AddDeathRecipient(g_deathRecipient)) {
        HDF_LOGE("AddRilDeathRecipient fail");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t RilImpl::RemoveRilDeathRecipient(const sptr<IRilCallback> &callback)
{
    if (callback == nullptr) {
        return HDF_FAILURE;
    }
    const sptr<IRemoteObject> &remote = OHOS::HDI::hdi_objcast<IRilCallback>(callback);
    if (!remote->RemoveDeathRecipient(g_deathRecipient)) {
        HDF_LOGI("RemoveRilDeathRecipient fail");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

void RilImpl::RilDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    if (rilInterfaceImpl_ == nullptr) {
        HDF_LOGE("RilImpl::RilDeathRecipient::OnRemoteDied fail rilInterfaceImpl_ is null");
        return;
    }
    rilInterfaceImpl_->UnRegister();
}

int32_t RilImpl::UnRegister()
{
    HDF_LOGI("UnRegister");
    RemoveRilDeathRecipient(callback_);
    callback_ = nullptr;
    Telephony::HRilManager::GetInstance().SetRilCallback(nullptr);
    return HDF_SUCCESS;
}

int32_t RilImpl::Init()
{
    return HDF_SUCCESS;
}
} // namespace V1_4
} // namespace Ril
} // namespace HDI
} // namespace OHOS
