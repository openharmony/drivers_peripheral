/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef WLAN_HAL_PROXY_H
#define WLAN_HAL_PROXY_H

#include <hdf_remote_service.h>
#include "wlan_hdi_service_stub.h"
#include "Iwifi_hal.h"
#include <iremote_proxy.h>
#include <hdf_log.h>
#include <iservmgr_hdi.h>
#include <ipc_object_stub.h>

namespace OHOS {
namespace HDI {
namespace WLAN {
namespace V1_0 {

class WlanInterfaceProxy : public IRemoteProxy<IWlan> {
public:
    explicit WlanInterfaceProxy(const sptr<IRemoteObject>& impl) : IRemoteProxy<IWlan>(impl) {}
    virtual ~WlanInterfaceProxy() override {}
    virtual int32_t WifiConstruct() override;
    virtual int32_t WifiDestruct() override;
    virtual int32_t Start() override;
    virtual int32_t Stop() override;
    virtual int32_t GetSupportFeature(std::vector<uint8_t>& supType) override;
    virtual int32_t GetSupportCombo(std::vector<uint64_t>& combo) override;
    virtual int32_t CreateFeature(int32_t type, std::shared_ptr<WifiFeatureInfo>& ifeature) override;
    virtual int32_t GetFeatureByIfName(std::string& ifName, std::shared_ptr<WifiFeatureInfo>& ifeature) override;
    virtual int32_t RegisterEventCallback(std::function<int32_t(int32_t event, struct HdfSBuf *sbuf)> cb) override;
    virtual int32_t UnregisterEventCallback() override;
    virtual int32_t DestroyFeature(std::shared_ptr<WifiFeatureInfo> ifeature) override;
    virtual int32_t ResetDriver(const uint8_t chipId) override;
    virtual int32_t GetAsscociatedStas(std::shared_ptr<WifiFeatureInfo> ifeature, std::shared_ptr<StaInfo> staInfo,
        uint32_t count, std::vector<uint32_t>& num) override;
    virtual int32_t SetCountryCode(std::shared_ptr<WifiFeatureInfo> ifeature, std::string& code, uint32_t len) override;
    virtual int32_t GetNetworkIfaceName(std::shared_ptr<WifiFeatureInfo> ifeature) override;
    virtual int32_t GetFeatureType(std::shared_ptr<WifiFeatureInfo> ifeature) override;
    virtual int32_t SetMacAddress(std::shared_ptr<WifiFeatureInfo> ifeature, std::vector<uint8_t>& mac) override;
    virtual int32_t GetDeviceMacAddress(std::shared_ptr<WifiFeatureInfo> ifeature, std::vector<uint8_t>& mac,
        uint8_t len) override;
    virtual int32_t GetFreqsWithBand(std::shared_ptr<WifiFeatureInfo> ifeature, int32_t band, std::vector<int32_t> freq,
        uint32_t count, uint32_t& num) override;
    virtual int32_t SetTxPower(std::shared_ptr<WifiFeatureInfo> ifeature, int32_t power) override;
    virtual int32_t GetChipId(std::shared_ptr<WifiFeatureInfo> ifeature, uint8_t& chipId) override;
    virtual int32_t GetIfNamesByChipId(const uint8_t chipId, std::string& ifNames, uint32_t& num) override;
    virtual int32_t SetScanningMacAddress(std::shared_ptr<WifiFeatureInfo> ifeature, std::vector<uint8_t>& scanMac,
        uint8_t len) override;
    static int32_t CallbackWlanProxy(int32_t event, struct HdfSBuf *reqData);
    static std::function<int32_t(int32_t event, struct HdfSBuf *sbuf)> callback_;
private:
    static inline BrokerDelegator<WlanInterfaceProxy> delegator_;
};

class IPCObjectStubWlan: public OHOS::IPCObjectStub {
public:
    explicit IPCObjectStubWlan() : OHOS::IPCObjectStub(u"") {};
    virtual ~IPCObjectStubWlan() = default;
    int OnRemoteRequest(uint32_t code, OHOS::MessageParcel &data,
        OHOS::MessageParcel &reply, OHOS::MessageOption &option) override;
};
}
}
}
}

#endif