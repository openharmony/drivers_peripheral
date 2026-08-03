/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "usb_driver_manager.h"

#include <algorithm>
#include <cstdint>
#include <set>
#include <sstream>
#include <vector>

#include "hdf_log.h"
#include "ipc_skeleton.h"
#include "usbd_wrapper.h"

#define HDF_LOG_TAG usb_driver_manager

namespace OHOS {
namespace HDI {
namespace Usb {
namespace Ddk {
namespace V1_2 {
UsbDriverManager& UsbDriverManager::GetInstance(void)
{
    static UsbDriverManager instance;
    return instance;
}

static bool ConvertDriverUid2TokenId(const std::string &driverUid, uint32_t &tokenId)
{
    std::stringstream ss(driverUid);
    std::string part;

    if (std::getline(ss, part, '-')) {
        if (!(ss >> tokenId)) {
            HDF_LOGE("%{public}s: Failed to extract a valid uint32_t after the delimiter", __func__);
            return false;
        }
    } else {
        HDF_LOGE("%{public}s: Delimiter '-' not found in the string.", __func__);
        return false;
    }
    return true;
}

bool UsbDriverManager::UpdateDriverInfo(const V1_1::DriverAbilityInfo &driverInfo)
{
    uint32_t tokenId;
    if (!ConvertDriverUid2TokenId(driverInfo.driverUid, tokenId)) {
        HDF_LOGE("%{public}s: convert failed, driverUid:%{public}s", __func__, driverInfo.driverUid.c_str());
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    auto it = driverMap_.find(tokenId);
    if (it == driverMap_.end() || it->second.empty()) {
        auto vec = std::vector<std::unique_ptr<V1_1::DriverAbilityInfo>>();
        vec.push_back(std::make_unique<V1_1::DriverAbilityInfo>(driverInfo));
        driverMap_[tokenId] = std::move(vec);
        HDF_LOGI("%{public}s: new driver registered, driverUid: %{public}s", __func__, driverInfo.driverUid.c_str());
        return true;
    }

    constexpr size_t MAX_DRIVER_ENTRIES_PER_TOKEN = 255;
    if (it->second.size() >= MAX_DRIVER_ENTRIES_PER_TOKEN) {
        HDF_LOGE("%{public}s: entries for tokenId: %{private}u exceed limit %{public}zu, driverUid: %{public}s",
            __func__, tokenId, MAX_DRIVER_ENTRIES_PER_TOKEN, driverInfo.driverUid.c_str());
        return false;
    }

    driverMap_[tokenId].push_back(std::make_unique<V1_1::DriverAbilityInfo>(driverInfo));

    HDF_LOGI("%{public}s: driver merged, driverUid: %{public}s, entryCount:%{public}zu",
        __func__, driverInfo.driverUid.c_str(), driverMap_[tokenId].size());
    return true;
}

bool UsbDriverManager::RemoveDriverInfo(const std::string &driverUid)
{
    uint32_t tokenId;
    if (!ConvertDriverUid2TokenId(driverUid, tokenId)) {
        HDF_LOGE("%{public}s: convert failed, driverUid:%{public}s", __func__, driverUid.c_str());
        return false;
    }

    HDF_LOGI("%{public}s: start remove, driverUid: %{public}s", __func__, driverUid.c_str());

    std::lock_guard<std::mutex> lock(mutex_);
    auto it = driverMap_.find(tokenId);
    if (it == driverMap_.end()) {
        HDF_LOGW("%{public}s: tokenId not found, skip remove, driverUid:%{public}s", __func__, driverUid.c_str());
        return true;
    }

    auto &vec = it->second;
    size_t oldSize = vec.size();
    auto target = std::remove_if(vec.begin(), vec.end(),
        [&driverUid](const std::unique_ptr<V1_1::DriverAbilityInfo> &entry) {
            return entry != nullptr && entry->driverUid == driverUid;
        });
    size_t removeCount = std::distance(target, vec.end());
    vec.erase(target, vec.end());

    HDF_LOGI("%{public}s, removed %{public}zu/%{public}zu entries, remaining %{public}zu, driverUid:%{public}s",
        __func__, removeCount, oldSize, vec.size(), driverUid.c_str());

    if (vec.empty()) {
        driverMap_.erase(it);
    }
    return true;
}

bool UsbDriverManager::QueryDriverInfo(uint32_t tokenId, std::vector<uint16_t> &vendorIds)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = driverMap_.find(tokenId);
    if (it == driverMap_.end() || it->second.empty()) {
        vendorIds.clear();
        HDF_LOGW("%{public}s: tokenId=%{private}u not found or driver list empty", __func__, tokenId);
        return false;
    }

    std::set<uint16_t> vidSet;
    for (const auto &driverPtr : it->second) {
        if (driverPtr == nullptr) {
            continue;
        }
        for (auto vid : driverPtr->vids) {
            vidSet.insert(vid);
        }
    }
    HDF_LOGI("%{public}s: tokenId=%{private}u, vidCount=%{public}zu", __func__, tokenId, vidSet.size());

    if (vidSet.empty()) {
        HDF_LOGI("%{public}s: tokenId has entries but all nullptr", __func__);
        return true;
    }

    vendorIds.assign(vidSet.begin(), vidSet.end());
    HDF_LOGI("%{public}s: tokenId=%{private}u found %{public}zu vendorIds", __func__, tokenId, vendorIds.size());
    return true;
}
} // namespace V1_2
} // namespace Ddk
} // namespace Usb
} // namespace HDI
} // namespace OHOS