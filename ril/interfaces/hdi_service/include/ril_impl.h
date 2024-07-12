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

#ifndef OHOS_HDI_RIL_V1_0_RIL_INTERFACE_IMPL_H
#define OHOS_HDI_RIL_V1_0_RIL_INTERFACE_IMPL_H

#include "hril_manager.h"

#include <hdf_log.h>
#include <iproxy_broker.h>
#include <iremote_object.h>

#include "v1_3/iril.h"
#include "vector"

namespace OHOS {
namespace HDI {
namespace Ril {
namespace V1_3 {
class RilImpl : public IRil {
public:
    RilImpl() = default;
    virtual ~RilImpl() = default;

    // Call
    int32_t SetEmergencyCallList(int32_t slotId, int32_t serialId, const EmergencyInfoList &emergencyInfoList) override;
    int32_t GetEmergencyCallList(int32_t slotId, int32_t serialId) override;
    int32_t GetCallList(int32_t slotId, int32_t serialId) override;
    int32_t Dial(int32_t slotId, int32_t serialId, const DialInfo &dialInfo) override;
    int32_t Reject(int32_t slotId, int32_t serialId) override;
    int32_t Hangup(int32_t slotId, int32_t serialId, int32_t gsmIndex) override;
    int32_t Answer(int32_t slotId, int32_t serialId) override;
    int32_t HoldCall(int32_t slotId, int32_t serialId) override;
    int32_t UnHoldCall(int32_t slotId, int32_t serialId) override;
    int32_t SwitchCall(int32_t slotId, int32_t serialId) override;
    int32_t CombineConference(int32_t slotId, int32_t serialId, int32_t callType) override;
    int32_t SeparateConference(int32_t slotId, int32_t serialId, int32_t callIndex, int32_t callType) override;
    int32_t GetCallWaiting(int32_t slotId, int32_t serialId) override;
    int32_t SetCallWaiting(int32_t slotId, int32_t serialId, int32_t activate) override;
    int32_t GetCallTransferInfo(int32_t slotId, int32_t serialId, int32_t reason) override;
    int32_t SetCallTransferInfo(
        int32_t slotId, int32_t serialId, const CallForwardSetInfo &callForwardSetInfo) override;
    int32_t GetCallRestriction(int32_t slotId, int32_t serialId, const std::string &fac) override;
    int32_t SetCallRestriction(
        int32_t slotId, int32_t serialId, const CallRestrictionInfo &callRestrictionInfo) override;
    int32_t GetClip(int32_t slotId, int32_t serialId) override;
    int32_t SetClip(int32_t slotId, int32_t serialId, int32_t action) override;
    int32_t GetClir(int32_t slotId, int32_t serialId) override;
    int32_t SetClir(int32_t slotId, int32_t serialId, int32_t action) override;
    int32_t SetCallPreferenceMode(int32_t slotId, int32_t serialId, int32_t mode) override;
    int32_t GetCallPreferenceMode(int32_t slotId, int32_t serialId) override;
    int32_t SetUssd(int32_t slotId, int32_t serialId, const std::string &str) override;
    int32_t CloseUnFinishedUssd(int32_t slotId, int32_t serialId) override;
    int32_t GetUssd(int32_t slotId, int32_t serialId) override;
    int32_t SetMute(int32_t slotId, int32_t serialId, int32_t mute) override;
    int32_t GetMute(int32_t slotId, int32_t serialId) override;
    int32_t GetCallFailReason(int32_t slotId, int32_t serialId) override;
    int32_t CallSupplement(int32_t slotId, int32_t serialId, int32_t type) override;
    int32_t SendDtmf(int32_t slotId, int32_t serialId, const DtmfInfo &dtmfInfo) override;
    int32_t StartDtmf(int32_t slotId, int32_t serialId, const DtmfInfo &dtmfInfo) override;
    int32_t StopDtmf(int32_t slotId, int32_t serialId, const DtmfInfo &dtmfInfo) override;
    int32_t SetBarringPassword(int32_t slotId, int32_t serialId, const SetBarringInfo &setBarringInfo) override;
    int32_t SetVonrSwitch(int32_t slotId, int32_t serialId, int32_t status) override;

    // Data
    int32_t ActivatePdpContext(int32_t slotId, int32_t serialId, const DataCallInfo &dataCallInfo) override;
    int32_t ActivatePdpContextWithApnTypes(int32_t slotId, int32_t serialId,
        const DataCallInfoWithApnTypes &dataCallInfo) override;
    int32_t DeactivatePdpContext(int32_t slotId, int32_t serialId, const UniInfo &uniInfo) override;
    int32_t GetPdpContextList(int32_t slotId, int32_t serialId, const UniInfo &uniInfo) override;
    int32_t SetInitApnInfo(int32_t slotId, int32_t serialId, const DataProfileDataInfo &dataProfileDataInfo) override;
    int32_t GetLinkBandwidthInfo(int32_t slotId, int32_t serialId, int32_t cid) override;
    int32_t GetLinkCapability(int32_t slotId, int32_t serialId) override;
    int32_t SetLinkBandwidthReportingRule(int32_t slotId, int32_t serialId,
        const DataLinkBandwidthReportingRule &dataLinkBandwidthReportingRule) override;
    int32_t SetDataPermitted(int32_t slotId, int32_t serialId, int32_t dataPermitted) override;
    int32_t SetDataProfileInfo(int32_t slotId, int32_t serialId, const DataProfilesInfo &dataProfilesInfo) override;
    int32_t SendDataPerformanceMode(int32_t slotId, int32_t serialId,
        const DataPerformanceInfo &dataPerformanceInfo) override;
    int32_t SendDataSleepMode(int32_t slotId, int32_t serialId, const DataSleepInfo &dataSleepInfo) override;
    int32_t CleanAllConnections(int32_t slotId, int32_t serialId) override;

    int32_t SetRadioState(int32_t slotId, int32_t serialId, int32_t fun, int32_t rst) override;
    int32_t GetRadioState(int32_t slotId, int32_t serialId) override;
    int32_t GetImei(int32_t slotId, int32_t serialId) override;
    int32_t GetImeiSv(int32_t slotId, int32_t serialId) override;
    int32_t GetMeid(int32_t slotId, int32_t serialId) override;
    int32_t GetVoiceRadioTechnology(int32_t slotId, int32_t serialId) override;
    int32_t GetBasebandVersion(int32_t slotId, int32_t serialId) override;
    int32_t ShutDown(int32_t slotId, int32_t serialId) override;

    int32_t GetSimIO(int32_t slotId, int32_t serialId, const SimIoRequestInfo &simIO) override;
    int32_t GetSimStatus(int32_t slotId, int32_t serialId) override;
    int32_t GetImsi(int32_t slotId, int32_t serialId) override;
    int32_t GetSimLockStatus(int32_t slotId, int32_t serialId, const SimLockInfo &simLockInfo) override;
    int32_t SetSimLock(int32_t slotId, int32_t serialId, const SimLockInfo &simLockInfo) override;
    int32_t ChangeSimPassword(int32_t slotId, int32_t serialId, const SimPasswordInfo &simPassword) override;
    int32_t UnlockPin(int32_t slotId, int32_t serialId, const std::string &pin) override;
    int32_t UnlockPuk(int32_t slotId, int32_t serialId, const std::string &puk, const std::string &pin) override;
    int32_t UnlockPin2(int32_t slotId, int32_t serialId, const std::string &pin2) override;
    int32_t UnlockPuk2(int32_t slotId, int32_t serialId, const std::string &puk2, const std::string &pin2) override;
    int32_t SetActiveSim(int32_t slotId, int32_t serialId, int32_t index, int32_t enable) override;
    int32_t SimStkSendTerminalResponse(int32_t slotId, int32_t serialId, const std::string &strCmd) override;
    int32_t SimStkSendEnvelope(int32_t slotId, int32_t serialId, const std::string &strCmd) override;
    int32_t SimStkSendCallSetupRequestResult(int32_t slotId, int32_t serialId, int32_t accept) override;
    int32_t SimStkIsReady(int32_t slotId, int32_t serialId) override;
    int32_t GetRadioProtocol(int32_t slotId, int32_t serialId) override;
    int32_t SetRadioProtocol(int32_t slotId, int32_t serialId, const RadioProtocol &radioProtocol) override;
    int32_t SimOpenLogicalChannel(int32_t slotId, int32_t serialId, const std::string &appID, int32_t p2) override;
    int32_t SimCloseLogicalChannel(int32_t slotId, int32_t serialId, int32_t channelId) override;
    int32_t SimTransmitApduLogicalChannel(
        int32_t slotId, int32_t serialId, const ApduSimIORequestInfo &apduSimIO) override;
    int32_t SimTransmitApduBasicChannel(
        int32_t slotId, int32_t serialId, const ApduSimIORequestInfo &apduSimIO) override;
    int32_t SimAuthentication(
        int32_t slotId, int32_t serialId, const SimAuthenticationRequestInfo &simAuthInfo) override;
    int32_t UnlockSimLock(int32_t slotId, int32_t serialId, int32_t lockType, const std::string &key) override;
    int32_t SendSimMatchedOperatorInfo(
        int32_t slotId, int32_t serialId, const NcfgOperatorInfo &ncfgOperatorInfo) override;

    // Network
    int32_t GetSignalStrength(int32_t slotId, int32_t serialId) override;
    int32_t GetCsRegStatus(int32_t slotId, int32_t serialId) override;
    int32_t GetPsRegStatus(int32_t slotId, int32_t serialId) override;
    int32_t GetOperatorInfo(int32_t slotId, int32_t serialId) override;
    int32_t GetNetworkSearchInformation(int32_t slotId, int32_t serialId) override;
    int32_t GetNetworkSelectionMode(int32_t slotId, int32_t serialId) override;
    int32_t SetNetworkSelectionMode(
        int32_t slotId, int32_t serialId, const SetNetworkModeInfo &networkModeInfo) override;
    int32_t GetNeighboringCellInfoList(int32_t slotId, int32_t serialId) override;
    int32_t GetCurrentCellInfo(int32_t slotId, int32_t serialId) override;
    int32_t SetPreferredNetwork(int32_t slotId, int32_t serialId, int32_t preferredNetworkType) override;
    int32_t GetPreferredNetwork(int32_t slotId, int32_t serialId) override;
    int32_t GetPhysicalChannelConfig(int32_t slotId, int32_t serialId) override;
    int32_t SetLocateUpdates(int32_t slotId, int32_t serialId, const RilRegNotifyMode mode) override;
    int32_t SetNotificationFilter(int32_t slotId, int32_t serialId, int32_t newFilter) override;
    int32_t SetDeviceState(int32_t slotId, int32_t serialId, int32_t deviceStateType, int32_t deviceStateOn) override;
    int32_t SetNrOptionMode(int32_t slotId, int32_t serialId, int32_t mode) override;
    int32_t GetNrOptionMode(int32_t slotId, int32_t serialId) override;
    int32_t GetRrcConnectionState(int32_t slotId, int32_t serialId) override;
    int32_t GetNrSsbId(int32_t slotId, int32_t serialId) override;

    // Sms
    int32_t SendGsmSms(int32_t slotId, int32_t serialId, const GsmSmsMessageInfo &gsmSmsMessageInfo) override;
    int32_t SendCdmaSms(int32_t slotId, int32_t serialId, const SendCdmaSmsMessageInfo &cdmaSmsMessageInfo) override;
    int32_t AddSimMessage(int32_t slotId, int32_t serialId, const SmsMessageIOInfo &smsMessageIOInfo) override;
    int32_t DelSimMessage(int32_t slotId, int32_t serialId, int32_t index) override;
    int32_t UpdateSimMessage(int32_t slotId, int32_t serialId, const SmsMessageIOInfo &smsMessageIOInfo) override;
    int32_t AddCdmaSimMessage(int32_t slotId, int32_t serialId, const SmsMessageIOInfo &smsMessageIOInfo) override;
    int32_t DelCdmaSimMessage(int32_t slotId, int32_t serialId, int32_t index) override;
    int32_t UpdateCdmaSimMessage(int32_t slotId, int32_t serialId, const SmsMessageIOInfo &smsMessageIOInfo) override;
    int32_t SetSmscAddr(int32_t slotId, int32_t serialId, const ServiceCenterAddress &serviceCenterAddress) override;
    int32_t GetSmscAddr(int32_t slotId, int32_t serialId) override;
    int32_t SetCBConfig(int32_t slotId, int32_t serialId, const CBConfigInfo &cellBroadcastInfo) override;
    int32_t GetCBConfig(int32_t slotId, int32_t serialId) override;
    int32_t SetCdmaCBConfig(
        int32_t slotId, int32_t serialId, const CdmaCBConfigInfoList &cdmaCBConfigInfoList) override;
    int32_t GetCdmaCBConfig(int32_t slotId, int32_t serialId) override;
    int32_t SendSmsMoreMode(int32_t slotId, int32_t serialId, const GsmSmsMessageInfo &gsmSmsMessageInfo) override;
    int32_t SendSmsAck(int32_t slotId, int32_t serialId, const ModeData &modeData) override;

    int32_t SendRilAck() override;

    int32_t SetCallback(const sptr<V1_1::IRilCallback> &rilCallback) override;
    int32_t SetCallback1_2(const sptr<V1_2::IRilCallback> &rilCallback) override;
    int32_t SetCallback1_3(const sptr<V1_3::IRilCallback> &rilCallback) override;
    int32_t Init();
    class RilDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit RilDeathRecipient(const wptr<RilImpl> &rilInterfaceImpl) : rilInterfaceImpl_(rilInterfaceImpl) {}
        virtual ~RilDeathRecipient() = default;
        virtual void OnRemoteDied(const wptr<IRemoteObject> &object) override;

    private:
        wptr<RilImpl> rilInterfaceImpl_;
    };

    template<typename FuncType, typename... ParamTypes>
    inline int32_t TaskSchedule(FuncType &&_func, int32_t slotId, ParamTypes &&... _args) const
    {
        if (_func == nullptr || Telephony::HRilManager::manager_ == nullptr) {
            HDF_LOGE("manager or func is null pointer");
            return RIL_ERR_NULL_POINT;
        }
        if (slotId >= Telephony::HRilManager::manager_->GetMaxSimSlotCount()) {
            HDF_LOGE("slotId is inValid");
            return RIL_ERR_INVALID_PARAMETER;
        }
        auto ret = (Telephony::HRilManager::manager_.get()->*(_func))(slotId, std::forward<ParamTypes>(_args)...);
        return ret;
    }

private:
    int32_t UnRegister();
    int32_t AddRilDeathRecipient(const sptr<IRilCallback> &callback);
    int32_t RemoveRilDeathRecipient(const sptr<IRilCallback> &callback);
};
} // namespace V1_3
} // namespace Ril
} // namespace HDI
} // namespace OHOS
#endif // OHOS_HDI_RIL_V1_0_RILIMPL_H
