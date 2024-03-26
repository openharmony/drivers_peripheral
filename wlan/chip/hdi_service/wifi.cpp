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

#include "wifi.h"
#include <hdf_base.h>
#include <hdf_log.h>
#include "wifi_hal.h"
#include "hdi_sync_util.h"
#include "iproxy_broker.h"

namespace OHOS {
namespace HDI {
namespace Wlan {
namespace Chip {
namespace V1_0 {
#ifdef FEATURE_ANCO_WIFI
const int CHIP_ID_STA = 1;
const int CHIP_ID_P2P = 2;
const int CHIP_ID_AP = 3;
#endif

static constexpr int32_t K_PRIMARY_CHIP_ID = 0;

extern "C" IChipController *WifiImplGetInstance(void)
{
    return new (std::nothrow) Wifi();
}

Wifi::Wifi()
    :ifaceTool_(std::make_shared<IfaceTool>()),
    vendorHalList_(std::make_shared<WifiVendorHalList>(ifaceTool_)),
    chipModes_(std::make_shared<WifiChipModes>()),
    runState_(RunState::STOPPED) {
    remoteDeathRecipient_ =
        new RemoteDeathRecipient(std::bind(&Wifi::OnRemoteDied, this, std::placeholders::_1));
}

Wifi::~Wifi()
{
    for (const auto& callback : cbHandler_.GetCallbacks()) {
        if (callback != nullptr) {
            RemoveWifiDeathRecipient(callback);
        }
    }
    cbHandler_.Invalidate();
}

int32_t Wifi::RegisterWifiEventCallback(const sptr<IChipControllerCallback>& eventCallback)
{
    if (AddWifiDeathRecipient(eventCallback) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }

    if (!cbHandler_.AddCallback(eventCallback)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t Wifi::IsInit(bool& inited)
{
    inited = runState_ != RunState::STOPPED;
    return HDF_SUCCESS;
}

int32_t Wifi::Init()
{
    HDF_LOGI("Wifi HAL start enter");
    if (runState_ == RunState::STARTED) {
        return HDF_SUCCESS;
    } else if (runState_ == RunState::STOPPING) {
        return HDF_SUCCESS;
    }
    WifiStatus wifi_status = InitializVendorHal();
    if (wifi_status.code == WifiStatusCode::SUCCESS) {
        const auto& onSubsystemRestartCallback =
            [this](const std::string& error) {
            WifiStatus wifi_status;
            wifi_status.code = WifiStatusCode::ERROR_UNKNOWN;
            wifi_status.description = error;
            for (const auto& callback : cbHandler_.GetCallbacks()) {
                callback->OnSubsystemRestart(wifi_status);
            }
        };

        int32_t chipId = K_PRIMARY_CHIP_ID;
        for (auto& hal : vendorHals_) {
            chips_.push_back(new WifiChip(
                chipId, chipId == K_PRIMARY_CHIP_ID, hal,
                chipModes_, onSubsystemRestartCallback));
            chipId++;
        }
        runState_ = RunState::STARTED;
        HDF_LOGI("Wifi HAL started");
        return HDF_SUCCESS;
    } else {
        HDF_LOGE("Wifi HAL start failed");
        return HDF_FAILURE;
    }
}

int32_t Wifi::Release()
{
    if (runState_ == RunState::STOPPED) {
        return HDF_SUCCESS;
    } else if (runState_ == RunState::STOPPING) {
        return HDF_SUCCESS;
    }
    for (auto& chip : chips_) {
        if (chip) {
            chip->Invalidate();
        }
    }
    chips_.clear();
    auto lock = AcquireGlobalLock();
    WifiStatus wifi_status = StopVendorHal(&lock);
    if (wifi_status.code == WifiStatusCode::SUCCESS) {
        return HDF_SUCCESS;
        HDF_LOGI("Wifi HAL stopped");
    } else {
        return HDF_FAILURE;
        HDF_LOGE("Wifi HAL stop failed");
    }
}

int32_t Wifi::GetAvailableChips(std::vector<uint32_t>& chipIds)
{
    for (auto& chip : chips_) {
        int32_t chipId = GetChipIdFromWifiChip(chip);
        if (chipId != UINT32_MAX) chipIds.emplace_back(chipId);
    }
#ifdef FEATURE_ANCO_WIFI
    if (chipIds.empty()) {
        chipIds.emplace_back(CHIP_ID_STA);
        chipIds.emplace_back(CHIP_ID_P2P);
        chipIds.emplace_back(CHIP_ID_AP);
    }
#endif
    return HDF_SUCCESS;
}

int32_t Wifi::GetChipService(uint32_t chipId, sptr<IConcreteChip>& chip)
{
    for (auto& ch : chips_) {
        uint32_t cand_id = GetChipIdFromWifiChip(ch);
        if ((cand_id != UINT32_MAX) && (cand_id == chipId)) {
            chip = ch;
            return HDF_SUCCESS;
        }
    }
    chip = nullptr;
    return HDF_FAILURE;
}

WifiStatus Wifi::StopVendorHal(std::unique_lock<std::recursive_mutex>* lock)
{
    WifiError legacyStatus = WIFI_SUCCESS;
    int index = 0;
    WifiStatus wifi_status;

    runState_ = RunState::STOPPING;
    for (auto& hal : vendorHals_) {
        WifiError tmp = hal->Stop(lock, [&]() {});
        if (tmp != WIFI_SUCCESS) {
            HDF_LOGE("Failed to stop vendor hal index: %{public}d, error %{public}d", index, tmp);
            legacyStatus = tmp;
        }
        index++;
    }
    runState_ = RunState::STOPPED;

    if (legacyStatus != WIFI_SUCCESS) {
        HDF_LOGE("One or more vendor hals failed to stop error is %{public}d", legacyStatus);
        wifi_status.code = WifiStatusCode::ERROR_UNKNOWN;
        return wifi_status;
    }
    wifi_status.code = WifiStatusCode::SUCCESS;
    return wifi_status;
}

WifiStatus Wifi::InitializVendorHal()
{
    WifiStatus wifi_status;

    vendorHals_ = vendorHalList_->GetHals();
    if (vendorHals_.empty()) {
        wifi_status.code = WifiStatusCode::ERROR_UNKNOWN;
        return wifi_status;
    }
    int index = 0;
    for (auto& hal : vendorHals_) {
        WifiError legacyStatus = hal->Initialize();
        if (legacyStatus != WIFI_SUCCESS) {
            wifi_status.code = WifiStatusCode::ERROR_UNKNOWN;
            return wifi_status;
        }
        index++;
    }

    wifi_status.code = WifiStatusCode::SUCCESS;
    return wifi_status;
}

int32_t Wifi::GetChipIdFromWifiChip(sptr <WifiChip>& chip)
{
    int chipId = UINT32_MAX;
    int32_t id;

    if (chip) {
        chip->GetChipId(id);
        chipId = id;
    }
    return chipId;
}

void Wifi::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    for (auto& chip : chips_) {
        if (chip) {
            chip->Invalidate();
        }
    }
    chips_.clear();
    auto lock = AcquireGlobalLock();
    StopVendorHal(&lock);
}

int32_t Wifi::AddWifiDeathRecipient(const sptr<IChipControllerCallback>& eventCallback)
{
    HDF_LOGI("AddWifiDeathRecipient");
    const sptr<IRemoteObject>& remote = OHOS::HDI::hdi_objcast<IChipControllerCallback>(eventCallback);
    bool result = remote->AddDeathRecipient(remoteDeathRecipient_);
    if (!result) {
        HDF_LOGE("Wifi AddDeathRecipient fail");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t Wifi::RemoveWifiDeathRecipient(const sptr<IChipControllerCallback>& eventCallback)
{
    HDF_LOGI("RemoveWifiDeathRecipient");
    const sptr<IRemoteObject>& remote = OHOS::HDI::hdi_objcast<IChipControllerCallback>(eventCallback);
    bool result = remote->RemoveDeathRecipient(remoteDeathRecipient_);
    if (!result) {
        HDF_LOGE("Wifi RemoveDeathRecipient fail");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
    
} // namespace V1_0
} // namespace Chip
} // namespace Wlan
} // namespace HDI
} // namespace OHOS