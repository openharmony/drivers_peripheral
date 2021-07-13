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

#ifndef HDI_SAMPLE_CLIENT_CPP_INF_H
#define HDI_SAMPLE_CLIENT_CPP_INF_H

#include <list>
#include <map>
#include <vector>
#include <hdf_log.h>
#include <iservmgr_hdi.h>

namespace OHOS {
namespace HDI {
namespace WLAN {
namespace V1_0 {

struct WifiFeatureInfo {
    char *ifName;
    int32_t type;
};

class IWlan : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"HDI.WLAN.V1_0");
    virtual ~IWlan(){}
    static sptr<IWlan> Get(const std::string& serviceName);
    virtual int32_t WifiConstruct() = 0;
    virtual int32_t WifiDestruct() = 0;
    virtual int32_t Start() = 0;
    virtual int32_t Stop() = 0;
    virtual int32_t GetSupportFeature(std::vector<uint8_t>& supType) = 0;
    virtual int32_t GetSupportCombo(std::vector<uint64_t>& combo) = 0;
    virtual int32_t CreateFeature(int32_t type, std::shared_ptr<WifiFeatureInfo>& ifeature) = 0;
    virtual int32_t GetFeatureByIfName(std::string& ifName, std::shared_ptr<WifiFeatureInfo>& ifeature) = 0;
    virtual int32_t RegisterEventCallback(std::function<int32_t(int32_t event, struct HdfSBuf *sbuf)> cb) = 0;
    virtual int32_t UnregisterEventCallback() = 0;
    virtual int32_t DestroyFeature(std::shared_ptr<WifiFeatureInfo> ifeature) = 0;
    virtual int32_t ResetDriver(const uint8_t chipId) = 0;
    virtual int32_t GetAsscociatedStas(std::shared_ptr<WifiFeatureInfo> ifeature, std::shared_ptr<StaInfo> staInfo,
        uint32_t count, std::vector<uint32_t>& num) = 0;
    virtual int32_t SetCountryCode(std::shared_ptr<WifiFeatureInfo> ifeature, std::string& code, uint32_t len) = 0;
    virtual int32_t GetNetworkIfaceName(std::shared_ptr<WifiFeatureInfo> ifeature) = 0;
    virtual int32_t GetFeatureType(std::shared_ptr<WifiFeatureInfo> ifeature) = 0;
    virtual int32_t SetMacAddress(std::shared_ptr<WifiFeatureInfo> ifeature, std::vector<uint8_t>& mac) = 0;
    virtual int32_t GetDeviceMacAddress(std::shared_ptr<WifiFeatureInfo> ifeature, std::vector<uint8_t>& mac,
        uint8_t len) = 0;
    virtual int32_t GetFreqsWithBand(std::shared_ptr<WifiFeatureInfo> ifeature, int32_t band, std::vector<int32_t> freq,
        uint32_t count, uint32_t& num) = 0;
    virtual int32_t SetTxPower(std::shared_ptr<WifiFeatureInfo> ifeature, int32_t power) = 0;
    virtual int32_t GetChipId(std::shared_ptr<WifiFeatureInfo> ifeature, uint8_t& chipId) = 0;
    virtual int32_t GetIfNamesByChipId(const uint8_t chipId, std::string& ifNames, uint32_t& num) = 0;
    virtual int32_t SetScanningMacAddress(std::shared_ptr<WifiFeatureInfo> ifeature, std::vector<uint8_t>& scanMac,
        uint8_t len) = 0;
};
}
}
}
}

#endif