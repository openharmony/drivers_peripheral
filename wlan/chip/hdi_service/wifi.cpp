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

extern "C" IChipController *ChipControllerImplGetInstance(void)
{
    return new (std::nothrow) Wifi();
}

Wifi::Wifi()
    :ifaceTool_(std::make_shared<IfaceTool>()),
    vendorHalList_(std::make_shared<WifiVendorHalList>(ifaceTool_)),
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
        return HDF_FAILURE;
    }
    ErrorCode res = InitializVendorHal();
    if (res == ErrorCode::SUCCESS) {
        const auto& onVendorHalRestartCallback =
            [this](const std::string& error) {
            ErrorCode res = ErrorCode::UNKNOWN;
            for (const auto& callback : cbHandler_.GetCallbacks()) {
                callback->OnVendorHalRestart(res);
            }
        };

        int32_t chipId = K_PRIMARY_CHIP_ID;
        for (auto& hal : vendorHals_) {
            chipModes_ = std::make_shared<WifiChipModes>(hal);
            chips_.push_back(new WifiChip(
                chipId, chipId == K_PRIMARY_CHIP_ID, hal,
                std::make_shared<IfaceUtil>(ifaceTool_),
                chipModes_, onVendorHalRestartCallback));
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
    ErrorCode res = StopVendorHal(&lock);
    if (res == ErrorCode::SUCCESS) {
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
        uint32_t chipId = GetChipIdFromWifiChip(chip);
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

ErrorCode Wifi::StopVendorHal(std::unique_lock<std::recursive_mutex>* lock)
{
    WifiError legacyStatus = HAL_SUCCESS;
    int index = 0;
    ErrorCode res;

    runState_ = RunState::STOPPING;
    for (auto& hal : vendorHals_) {
        WifiError tmp = hal->Stop(lock, [&]() {});
        if (tmp != HAL_SUCCESS) {
            HDF_LOGE("Failed to stop vendor hal index: %{public}d, error %{public}d", index, tmp);
            legacyStatus = tmp;
        }
        index++;
    }
    runState_ = RunState::STOPPED;

    if (legacyStatus != HAL_SUCCESS) {
        HDF_LOGE("One or more vendor hals failed to stop error is %{public}d", legacyStatus);
        res = ErrorCode::UNKNOWN;
        return res;
    }
    res = ErrorCode::SUCCESS;
    return res;
}

ErrorCode Wifi::InitializVendorHal()
{
    ErrorCode res;

    vendorHals_ = vendorHalList_->GetHals();
    if (vendorHals_.empty()) {
        res = ErrorCode::UNKNOWN;
        return res;
    }
    int index = 0;
    for (auto& hal : vendorHals_) {
        WifiError legacyStatus = hal->Initialize();
        if (legacyStatus != HAL_SUCCESS) {
            res = ErrorCode::UNKNOWN;
            return res;
        }
        index++;
    }

    res = ErrorCode::SUCCESS;
    return res;
}

uint32_t Wifi::GetChipIdFromWifiChip(sptr <WifiChip>& chip)
{
    uint32_t chipId = UINT32_MAX;
    int32_t id;

    if (chip) {
        chip->GetChipId(id);
        chipId = static_cast<uint32_t>(id);
    }
    return chipId;
}

void Wifi::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    HDF_LOGI("chip service OnRemoteDied");
    runState_ = RunState::STOPPING;
    for (auto& chip : chips_) {
        if (chip) {
            chip->Invalidate();
        }
    }
    chips_.clear();
    auto lock = AcquireGlobalLock();
    StopVendorHal(&lock);
    runState_ = RunState::STOPPED;
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