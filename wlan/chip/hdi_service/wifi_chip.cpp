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

#include <fcntl.h>
#include <net/if.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <cstring>
#include "wifi_chip.h"
#include "parameter.h"
#include "wifi_hal.h"
#include <hdf_log.h>

namespace OHOS {
namespace HDI {
namespace Wlan {
namespace Chip {
namespace V1_0 {
constexpr int IFACE_TYPE_STA = 2;
constexpr char K_ACTIVE_WLAN_IFACE_NAME_PROPERTY[] = "wifi.active.interface";
constexpr char K_NO_ACTIVE_WLAN_IFACE_NAME_PROPERTY_VALUE[] = "";
constexpr unsigned K_MAX_WLAN_IFACES = 5;
const std::string AP_CODEX_DEFAULT_IFACENAME = "wlan1";

void InvalidateAndClearApIface(std::vector<sptr<WifiApIface>>& ifaces)
{
    for (const auto& iface : ifaces) {
        iface->Invalidate();
    }
    ifaces.clear();
}

void InvalidateAndClearStaIface(std::vector<sptr<WifiStaIface>>& ifaces)
{
    for (const auto& iface : ifaces) {
        iface->Invalidate();
    }
    ifaces.clear();
}

void InvalidateAndClearP2pIface(std::vector<sptr<WifiP2pIface>>& ifaces)
{
    for (const auto& iface : ifaces) {
        iface->Invalidate();
    }
    ifaces.clear();
}

WifiChip::WifiChip(
    int32_t chipId, bool isPrimary,
    const std::weak_ptr<WifiVendorHal> vendorHal,
    const std::shared_ptr<IfaceUtil> ifaceUtil,
    const std::function<void(const std::string&)>& handler)
    : chipId_(chipId),
    vendorHal_(vendorHal),
    isValid_(true),
    currentModeId_(chip_mode_ids::K_INVALID),
    ifaceUtil_(ifaceUtil),
    subsystemCallbackHandler_(handler)
{}

WifiChip::~WifiChip()
{}

void WifiChip::Invalidate()
{
    InvalidateAndClearApIface(apIfaces_);
    InvalidateAndClearP2pIface(p2pIfaces_);
    InvalidateAndClearStaIface(staIfaces_);
    SetParameter(K_ACTIVE_WLAN_IFACE_NAME_PROPERTY, K_NO_ACTIVE_WLAN_IFACE_NAME_PROPERTY_VALUE);
    vendorHal_.reset();
    cbHandler_.Invalidate();
    isValid_ = false;
}

int32_t WifiChip::GetChipId(int32_t& id)
{
    id = chipId_;
    return HDF_SUCCESS;
}

int32_t WifiChip::RegisterChipEventCallback(const sptr<IConcreteChipCallback>& chipEventcallback)
{
    if (!cbHandler_.AddCallback(chipEventcallback)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

std::string GetWlanIfaceName(unsigned idx)
{
    if (idx >= K_MAX_WLAN_IFACES) {
        HDF_LOGI("Requested interface beyond wlan%{public}d", K_MAX_WLAN_IFACES);
        return "";
    }
    return "wlan" + std::to_string(idx);
}

std::string WifiChip::GetIfaceName(IfaceType type, unsigned idx)
{
    return GetWlanIfaceName(idx);
}

std::string WifiChip::GetUsedIfaceName()
{
    if (staIfaces_.size() > 0) return staIfaces_[0]->GetName();
    if (apIfaces_.size() > 0) {
        return apIfaces_[0]->GetName();
    }
    HDF_LOGI("No active wlan interfaces in use! Using default");
    return GetIfaceName(IfaceType::STA, 0);
}

int32_t WifiChip::GetChipCaps(uint32_t& capabilities)
{
    WifiError status;

    const auto ifname = GetUsedIfaceName();
    status = vendorHal_.lock()->GetChipCaps(ifname, capabilities);
    if (status != HAL_SUCCESS) {
        return HDF_FAILURE;
    } else {
        return HDF_SUCCESS;
    }
}

int32_t WifiChip::GetChipModes(std::vector<UsableMode>& modes)
{
    auto chipModes = std::make_shared<WifiChipModes>(vendorHal_);
    modes = chipModes->GetChipModes(true);
    return HDF_SUCCESS;
}

bool WifiChip::IsValidModeId(uint32_t modeId)
{
    std::vector<UsableMode> modes;
    auto chipModes = std::make_shared<WifiChipModes>(vendorHal_);
    modes = chipModes->GetChipModes(true);
    for (const auto& mode : modes) {
        if (mode.modeId == modeId) {
            return true;
        }
    }
    return false;
}

int32_t WifiChip::GetCurrentMode(uint32_t& modeId)
{
    if (!IsValidModeId(currentModeId_)) {
        return HDF_ERR_INVALID_PARAM;
    }
    modeId = currentModeId_;
    return HDF_SUCCESS;
}

int32_t WifiChip::SetChipMode(uint32_t modeId)
{
    if (!IsValidModeId(modeId)) {
        return HDF_FAILURE;
    }
    if (modeId == currentModeId_) {
        HDF_LOGI("Already in the specified mode, modeId: %{public}d", modeId);
        return HDF_SUCCESS;
    }
    int32_t status = HandleChipConfiguration(modeId);
    if (status != ErrorCode::SUCCESS) {
        return HDF_FAILURE;
    }
    currentModeId_ = modeId;
    HDF_LOGI("Configured chip in mode, modeId: %{public}d", modeId);
    SetUsedIfaceNameProperty(GetUsedIfaceName());
    vendorHal_.lock()->RegisterRestartCallback(subsystemCallbackHandler_);
    return HDF_SUCCESS;
}

int32_t WifiChip::HandleChipConfiguration(int32_t modeId)
{
    std::unique_lock<std::recursive_mutex> lock = AcquireGlobalLock();
    if (IsValidModeId(currentModeId_)) {
        HDF_LOGI("Reconfiguring chip from mode %{public}d to mode %{public}d", currentModeId_, modeId);
        InvalidateAndClearApIface(apIfaces_);
        InvalidateAndClearP2pIface(p2pIfaces_);
        InvalidateAndClearStaIface(staIfaces_);
        WifiError status = vendorHal_.lock()->Stop(&lock, []() {});
        if (status != HAL_SUCCESS) {
            HDF_LOGE("Failed to stop vendor HAL: %{public}d", status);
            return HDF_FAILURE;
        }
    }
    WifiError status = vendorHal_.lock()->Start();
    if (status != HAL_SUCCESS) {
        HDF_LOGE("Failed to start vendor HAL: %{public}d", status);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

std::vector<std::map<IfaceType, size_t>> WifiChip::ExpandIfaceCombinations(
    const ComboIface& combination)
{
    uint32_t numExpandedCombos = 1;
    for (const auto& limit : combination.limits) {
        for (uint32_t i = 0; i < limit.ifaceNum; i++) {
            numExpandedCombos *= limit.types.size();
        }
    }

    std::vector<std::map<IfaceType, size_t>> expandedCombos;
    expandedCombos.resize(numExpandedCombos);
    for (auto& expandedCombo : expandedCombos) {
        for (const auto type : {
            IfaceType::AP, IfaceType::P2P, IfaceType::STA
        }) {
            expandedCombo[type] = 0;
        }
    }
    uint32_t span = numExpandedCombos;
    for (const auto& limit : combination.limits) {
        for (uint32_t i = 0; i < limit.ifaceNum; i++) {
            span /= limit.types.size();
            for (uint32_t k = 0; k < numExpandedCombos; ++k) {
                const auto ifaceType =
                    limit.types[(k / span) % limit.types.size()];
                expandedCombos[k][ifaceType]++;
            }
        }
    }
    return expandedCombos;
}

std::map<IfaceType, size_t> WifiChip::GetCurrentIfaceCombo()
{
    std::map<IfaceType, size_t> iface_counts;
    iface_counts[IfaceType::AP] = apIfaces_.size();
    iface_counts[IfaceType::P2P] = p2pIfaces_.size();
    iface_counts[IfaceType::STA] = staIfaces_.size();
    return iface_counts;
}

std::vector<ComboIface> WifiChip::GetCurrentCombinations()
{
    if (!IsValidModeId(currentModeId_)) {
        HDF_LOGE("Chip not configured in a mode yet");
        return {};
    }
    std::vector<UsableMode> modes;
    auto chipModes = std::make_shared<WifiChipModes>(vendorHal_);
    modes = chipModes->GetChipModes(true);
    for (const auto& mode : modes) {
        if (mode.modeId == currentModeId_) {
            return mode.usableCombo;
        }
    }
    HDF_LOGE("not find iface combinations for current mode!");
    return {};
}


bool WifiChip::CanExpandedIfaceSupportIfaceType(
    const std::map<IfaceType, size_t>& expandedCombo, IfaceType type)
{
    const auto currentCombo = GetCurrentIfaceCombo();
    for (const auto ifaceType : {IfaceType::AP, IfaceType::P2P, IfaceType::STA}) {
        size_t numIfacesNeeded = currentCombo.at(ifaceType);
        if (ifaceType == type) {
            numIfacesNeeded++;
        }
        size_t numIfacesAllowed = expandedCombo.at(ifaceType);
        if (numIfacesNeeded > numIfacesAllowed) {
            return false;
        }
    }
    return true;
}

bool WifiChip::CanSupportIfaceType(IfaceType type)
{
    if (!IsValidModeId(currentModeId_)) {
        HDF_LOGE("Chip not configured in a mode yet");
        return false;
    }
    const auto combinations = GetCurrentCombinations();
    for (const auto& combination : combinations) {
        const auto expandedCombos = ExpandIfaceCombinations(combination);
        for (const auto& expandedCombo : expandedCombos) {
            if (CanExpandedIfaceSupportIfaceType(expandedCombo, type)) {
                return true;
            }
        }
    }
    return false;
}

std::vector<std::string> GetApNames(std::vector<sptr<WifiApIface>>& ifaces)
{
    std::vector<std::string> names;
    for (const auto& iface : ifaces) {
        names.emplace_back(iface->GetName());
    }
    return names;
}

sptr<WifiApIface> FindApUsingName(std::vector<sptr<WifiApIface>>& ifaces, const std::string& name)
{
    std::vector<std::string> names;
    for (const auto& iface : ifaces) {
        if (name == iface->GetName()) {
            return iface;
        }
    }
    return nullptr;
}

std::vector<std::string> GetP2pNames(std::vector<sptr<WifiP2pIface>>& ifaces)
{
    std::vector<std::string> names;
    for (const auto& iface : ifaces) {
        names.emplace_back(iface->GetName());
    }
    return names;
}

sptr<WifiP2pIface> FindP2pUsingName(std::vector<sptr<WifiP2pIface>>& ifaces, const std::string& name)
{
    std::vector<std::string> names;
    for (const auto& iface : ifaces) {
        if (name == iface->GetName()) {
            return iface;
        }
    }
    return nullptr;
}

std::vector<std::string> GetStaNames(std::vector<sptr<WifiStaIface>>& ifaces)
{
    std::vector<std::string> names;
    for (const auto& iface : ifaces) {
        names.emplace_back(iface->GetName());
    }
    return names;
}

sptr<WifiStaIface> FindStaUsingName(std::vector<sptr<WifiStaIface>>& ifaces, const std::string& name)
{
    std::vector<std::string> names;
    for (const auto& iface : ifaces) {
        if (name == iface->GetName()) {
            return iface;
        }
    }
    return nullptr;
}

std::string WifiChip::AllocIfaceName(IfaceType type, uint32_t startIdx)
{
    HDF_LOGI("%{public}s: enter AllocIfaceName", __FUNCTION__);
    for (unsigned idx = startIdx; idx < K_MAX_WLAN_IFACES; idx++) {
        const auto ifname = GetIfaceName(type, idx);
        if (FindApUsingName(apIfaces_, ifname)) {
            continue;
        }
        if (FindStaUsingName(staIfaces_, ifname)) {
            continue;
        }
        return ifname;
    }
    HDF_LOGE("All wlan interfaces in use already!");
    return {};
}

bool WifiChip::CanExpandedIfaceComboSupportIfaceCombo(
    const std::map<IfaceType, size_t>& expandedCombo,
    const std::map<IfaceType, size_t>& reqCombo)
{
    for (const auto type : {
        IfaceType::AP, IfaceType::P2P, IfaceType::STA
    }) {
        if (reqCombo.count(type) == 0) {
            continue;
        }
        size_t numIfacesNeeded = reqCombo.at(type);
        size_t numIfacesAllowed = expandedCombo.at(type);
        if (numIfacesNeeded > numIfacesAllowed) {
            return false;
        }
    }
    return true;
}

bool WifiChip::CanCurrentModeSupportIfaceCombo(
    const std::map<IfaceType, size_t>& reqCombo)
{
    if (!IsValidModeId(currentModeId_)) {
        HDF_LOGE("Chip not configured in a mode yet");
        return false;
    }
    const auto combinations = GetCurrentCombinations();
    for (const auto& combination : combinations) {
        const auto expandedCombos = ExpandIfaceCombinations(combination);
        for (const auto& expandedCombo : expandedCombos) {
            if (CanExpandedIfaceComboSupportIfaceCombo(expandedCombo, reqCombo)) {
                return true;
            }
        }
    }
    return false;
}

bool WifiChip::IsDualStaSupportInCurrentMode()
{
    std::map<IfaceType, size_t> reqIfaceCombo;
    reqIfaceCombo[IfaceType::STA] = IFACE_TYPE_STA;
    return CanCurrentModeSupportIfaceCombo(reqIfaceCombo);
}

bool WifiChip::IsStaApCoexInCurrentMode()
{
    std::map<IfaceType, size_t> reqIfaceCombo;
    reqIfaceCombo[IfaceType::AP] = 1;
    reqIfaceCombo[IfaceType::STA] = 1;
    return CanCurrentModeSupportIfaceCombo(reqIfaceCombo);
}

uint32_t WifiChip::IdxOfApIface()
{
    if (IsDualStaSupportInCurrentMode()) {
        return IFACE_TYPE_STA;
    } else if (IsStaApCoexInCurrentMode()) {
        return 1;
    }
    return 0;
}

std::string WifiChip::AllocateApIfaceName()
{
    bool isCoex;
    vendorHal_.lock()->IsSupportCoex(isCoex);
    if (isCoex) {
        return AP_CODEX_DEFAULT_IFACENAME;
    }
    return AllocIfaceName(IfaceType::AP, IdxOfApIface());
}

void WifiChip::SetUsedIfaceNameProperty(const std::string& ifname)
{
    int res = SetParameter(K_ACTIVE_WLAN_IFACE_NAME_PROPERTY, ifname.c_str());
    if (res != 0) {
        HDF_LOGE("Failed to set active wlan iface name property");
    }
}

sptr<WifiApIface> WifiChip::NewApIface(std::string& ifname)
{
    std::vector<std::string> ap_instances;
    sptr<WifiApIface> iface =
        new WifiApIface(ifname, ap_instances, vendorHal_, ifaceUtil_);
    apIfaces_.push_back(iface);
    SetUsedIfaceNameProperty(GetUsedIfaceName());
    return iface;
}

int32_t WifiChip::CreateVirtualApInterface(const std::string& apVirtIf)
{
    WifiError status = vendorHal_.lock()->CreateVirtualInterface(
        apVirtIf, HalIfaceType::HAL_TYPE_AP);
    if (status != WifiError::HAL_SUCCESS) {
        HDF_LOGE("Failed to add interface: %{public}s, error: %{public}d", apVirtIf.c_str(), status);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t WifiChip::CreateApService(sptr<OHOS::HDI::Wlan::Chip::V1_0::IChipIface>& iface)
{
    if (!CanSupportIfaceType(IfaceType::AP)) {
        return HDF_FAILURE;
    }
    std::string ifname = AllocateApIfaceName();
    int32_t status = CreateVirtualApInterface(ifname);
    if (status != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    iface = NewApIface(ifname);
    return HDF_SUCCESS;
}

int32_t WifiChip::GetApServiceIfNames(std::vector<std::string>& ifnames)
{
    if (apIfaces_.empty()) {
        return HDF_FAILURE;
    }
    ifnames = GetApNames(apIfaces_);
    return HDF_SUCCESS;
}

int32_t WifiChip::GetApService(const std::string& ifname, sptr<IChipIface>& iface)
{
    iface = FindApUsingName(apIfaces_, ifname);
    if (iface == nullptr) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t WifiChip::RemoveApService(const std::string& ifname)
{
    const auto iface = FindApUsingName(apIfaces_, ifname);
    if (iface == nullptr) {
        return HDF_FAILURE;
    }
    InvalidateAndClearApIface(apIfaces_);
    SetUsedIfaceNameProperty(GetUsedIfaceName());
    return HDF_SUCCESS;
}

int32_t WifiChip::CreateP2pService(sptr<IChipIface>& iface)
{
    if (!CanSupportIfaceType(IfaceType::P2P)) {
        return HDF_FAILURE;
    }
    std::string ifname = GetDefaultP2pIfaceName();
    sptr<WifiP2pIface> ifa = new WifiP2pIface(ifname, vendorHal_, ifaceUtil_);
    p2pIfaces_.push_back(ifa);
    iface = ifa;
    return HDF_SUCCESS;
}

std::string WifiChip::GetDefaultP2pIfaceName()
{
    return "p2p0";
}

int32_t WifiChip::GetP2pServiceIfNames(std::vector<std::string>& ifnames)
{
    if (p2pIfaces_.empty()) {
        return HDF_FAILURE;
    }
    ifnames = GetP2pNames(p2pIfaces_);
    return HDF_SUCCESS;
}

int32_t WifiChip::GetP2pService(const std::string& ifname, sptr<IChipIface>& iface)
{
    iface = FindP2pUsingName(p2pIfaces_, ifname);
    if (iface == nullptr) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t WifiChip::RemoveP2pService(const std::string& ifname)
{
    const auto iface = FindP2pUsingName(p2pIfaces_, ifname);
    if (iface == nullptr) {
        return HDF_FAILURE;
    }
    InvalidateAndClearP2pIface(p2pIfaces_);
    return HDF_SUCCESS;
}

int32_t WifiChip::CreateStaService(sptr<IChipIface>& iface)
{
    HDF_LOGI("enter CreateStaService");
    if (!CanSupportIfaceType(IfaceType::STA)) {
        HDF_LOGE("%{public}s: Current Mode Not Support Iface Of Type With Current Ifaces", __FUNCTION__);
        return HDF_FAILURE;
    }
    WifiError status;
    std::string ifname = AllocateStaIfaceName();
    status = vendorHal_.lock()->CreateVirtualInterface(ifname,
        HalIfaceType::HAL_TYPE_STA);
    if (status != WifiError::HAL_SUCCESS) {
        HDF_LOGE("Failed to add interface: %{public}s, error: %{public}d", ifname.c_str(), status);
        return HDF_FAILURE;
    }
    sptr<WifiStaIface> ifa = new WifiStaIface(ifname, vendorHal_, ifaceUtil_);
    staIfaces_.push_back(ifa);
    iface = ifa;
    SetUsedIfaceNameProperty(GetUsedIfaceName());
    return HDF_SUCCESS;
}

std::string WifiChip::AllocateStaIfaceName()
{
    return AllocIfaceName(IfaceType::STA, 0);
}

int32_t WifiChip::GetStaServiceIfNames(std::vector<std::string>& ifnames)
{
    if (staIfaces_.empty()) {
        return HDF_FAILURE;
    }
    ifnames = GetStaNames(staIfaces_);
    return HDF_SUCCESS;
}

int32_t WifiChip::GetStaService(const std::string& ifname, sptr<IChipIface>& iface)
{
    iface = FindStaUsingName(staIfaces_, ifname);
    if (iface == nullptr) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t WifiChip::RemoveStaService(const std::string& ifname)
{
    const auto iface = FindStaUsingName(staIfaces_, ifname);
    if (iface == nullptr) {
        return HDF_FAILURE;
    }
    WifiError status =
        vendorHal_.lock()->DeleteVirtualInterface(ifname);
    if (status != WifiError::HAL_SUCCESS) {
        HDF_LOGE("Failed to remove interface: %{public}s, error: %{public}d", ifname.c_str(), status);
    }
    HDF_LOGI("RemoveStaService Invalidate and erase iface:%{public}s", ifname.c_str());
    iface->Invalidate();
    staIfaces_.erase(std::remove(staIfaces_.begin(), staIfaces_.end(), iface), staIfaces_.end());
    SetUsedIfaceNameProperty(GetUsedIfaceName());
    return HDF_SUCCESS;
}

}
}
}
}
}