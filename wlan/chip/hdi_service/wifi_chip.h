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

#ifndef WIFI_CHIP_H
#define WIFI_CHIP_H

#include <list>
#include <map>
#include <mutex>
#include "v1_0/iconcrete_chip.h"
#include "v1_0/chip_types.h"
#include "iface_tool.h"
#include "wifi_vendor_hal_list.h"
#include "wifi_chip_modes.h"
#include "callback_handler.h"
#include "v1_0/ichip_iface.h"
#include "wifi_ap_iface.h"
#include "wifi_sta_iface.h"
#include "wifi_p2p_iface.h"
#include "iface_util.h"

namespace OHOS {
namespace HDI {
namespace Wlan {
namespace Chip {
namespace V1_0 {
class WifiChip : public IConcreteChip {
public:
    WifiChip(int32_t chipId, bool isPrimary,
             const std::weak_ptr<WifiVendorHal> vendorHal,
             const std::shared_ptr<IfaceUtil> ifaceUtil,
             const std::function<void(const std::string&)> &subsystemCallbackHandler);
    ~WifiChip();
    void Invalidate();
    bool IsValid();
    int32_t GetChipId(int32_t& id) override;
    int32_t RegisterChipEventCallback(const sptr<IConcreteChipCallback>& chipEventcallback) override;
    int32_t GetChipCaps(uint32_t& capabilities) override;
    int32_t GetChipModes(std::vector<UsableMode>& modes) override;
    int32_t GetCurrentMode(uint32_t& modeId) override;
    int32_t SetChipMode(uint32_t modeId) override;
    int32_t CreateApService(sptr<IChipIface>& iface) override;
    int32_t GetApServiceIfNames(std::vector<std::string>& ifnames) override;
    int32_t GetApService(const std::string& ifname, sptr<IChipIface>& iface) override;
    int32_t RemoveApService(const std::string& ifname) override;
    int32_t CreateP2pService(sptr<IChipIface>& iface) override;
    int32_t GetP2pServiceIfNames(std::vector<std::string>& ifnames) override;
    int32_t GetP2pService(const std::string& ifname, sptr<IChipIface>& iface) override;
    int32_t RemoveP2pService(const std::string& ifname) override;
    int32_t CreateStaService(sptr<IChipIface>& iface) override;
    int32_t GetStaServiceIfNames(std::vector<std::string>& ifnames) override;
    int32_t GetStaService(const std::string& ifname, sptr<IChipIface>& iface) override;
    int32_t RemoveStaService(const std::string& ifname) override;

private:
    std::string GetIfaceName(IfaceType type, unsigned idx);
    std::string GetUsedIfaceName();
    bool CanSupportIfaceType(IfaceType type);
    bool CanExpandedIfaceSupportIfaceType(
        const std::map<IfaceType, size_t>& expandedCombo, IfaceType type);
    std::vector<ComboIface> GetCurrentCombinations();
    std::map<IfaceType, size_t> GetCurrentIfaceCombo();
    std::vector<std::map<IfaceType, size_t>> ExpandIfaceCombinations(
        const ComboIface& combination);
    bool IsValidModeId(uint32_t modeId);
    std::string AllocIfaceName(IfaceType type, uint32_t startIdx);
    bool CanExpandedIfaceComboSupportIfaceCombo(
        const std::map<IfaceType, size_t>& expandedCombo,
        const std::map<IfaceType, size_t>& reqCombo);
    bool CanCurrentModeSupportIfaceCombo(
        const std::map<IfaceType, size_t>& reqCombo);
    bool IsDualStaSupportInCurrentMode();
    bool IsStaApCoexInCurrentMode();
    uint32_t IdxOfApIface();
    std::string AllocateApIfaceName();
    sptr<WifiApIface> NewApIface(std::string& ifname);
    void SetUsedIfaceNameProperty(const std::string& ifname);
    int32_t CreateVirtualApInterface(const std::string& apVirtIf);
    std::string GetDefaultP2pIfaceName();
    std::string AllocateStaIfaceName();
    int32_t HandleChipConfiguration(int32_t modeId);
    int32_t chipId_;
    std::weak_ptr<WifiVendorHal> vendorHal_;
    std::vector<sptr<WifiApIface>> apIfaces_;
    std::vector<sptr<WifiP2pIface>> p2pIfaces_;
    std::vector<sptr<WifiStaIface>> staIfaces_;
    bool isValid_;
    uint32_t currentModeId_;
    std::shared_ptr<IfaceUtil> ifaceUtil_;
    CallbackHandler<IConcreteChipCallback> cbHandler_;
    const std::function<void(const std::string&)> subsystemCallbackHandler_;
};
}
}
}
}
}
#endif