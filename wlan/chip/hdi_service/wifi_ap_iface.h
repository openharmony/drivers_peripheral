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

#ifndef WIFI_AP_IFACE_H
#define WIFI_AP_IFACE_H

#include "v2_0/ichip_iface.h"
#include "v2_0/chip_types.h"
#include "wifi_vendor_hal.h"
#include "v2_0/ichip_iface_callback.h"
#include "iface_util.h"

namespace OHOS {
namespace HDI {
namespace Wlan {
namespace Chip {
namespace V2_0 {

class WifiApIface : public IChipIface {
public:
    WifiApIface(const std::string& ifname, const std::vector<std::string>& instances,
        const std::weak_ptr<WifiVendorHal> vendorHal, const std::weak_ptr<IfaceUtil> ifaceUtil);
    void Invalidate();
    bool IsValid();
    std::string GetName();
    void RemoveInstance(std::string instance);

    int32_t GetIfaceName(std::string& name) override;
    int32_t GetIfaceType(IfaceType& type) override;
    int32_t GetSupportFreqs(int band, std::vector<uint32_t>& frequencies) override;
    int32_t GetIfaceCap(uint32_t& capabilities) override;
    int32_t SetMacAddress(const std::string& mac) override;
    int32_t SetCountryCode(const std::string& code) override;
    int32_t GetPowerMode(int32_t& powerMode) override;
    int32_t SetPowerMode(int32_t powerMode) override;
    int32_t RegisterChipIfaceCallBack(const sptr<IChipIfaceCallback>& chipIfaceCallback) override;
    int32_t UnRegisterChipIfaceCallBack(const sptr<IChipIfaceCallback>& chipIfaceCallback) override;
    int32_t StartScan(const ScanParams& scanParam) override;
    int32_t GetScanInfos(std::vector<ScanResultsInfo>& scanResultsInfo) override;
    int32_t StartPnoScan(const PnoScanParams& pnoParams) override;
    int32_t StopPnoScan() override;
    int32_t GetSignalPollInfo(SignalPollResult& signalPollResult) override;
    int32_t EnablePowerMode(int32_t mode) override;
    int32_t SetDpiMarkRule(int32_t uid, int32_t protocol, int32_t enable) override;
    int32_t SetTxPower(int32_t power) override;
    int32_t SetIfaceState(bool state) override;
    int32_t SendCmdToDriver(const std::string& ifName, int32_t cmdId,
        const std::vector<int8_t>& paramBuf, std::vector<int8_t>& result) override;
    int32_t SendActionFrame(const std::string& ifName, uint32_t freq, const std::vector<uint8_t>& frameData) override;
    int32_t RegisterActionFrameReceiver(const std::string& ifName, const std::vector<uint8_t>& match) override;
    int32_t GetCoexictenceChannelList(const std::string& ifName, std::vector<uint8_t>& paramBuf) override;
    int32_t SetProjectionScreenParam(const std::string& ifName, const ProjectionScreenCmdParam& param) override;

private:
    std::string ifname_;
    std::vector<std::string> instances_;
    std::weak_ptr<WifiVendorHal> vendorHal_;
    std::weak_ptr<IfaceUtil> ifaceUtil_;
    bool isValid_;
};

}
}
}
}
}
#endif