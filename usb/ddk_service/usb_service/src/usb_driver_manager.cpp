/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <cstdint>
#include <sstream>
#include "hdf_log.h"
#include "ipc_skeleton.h"
#include "usbd_wrapper.h"

#define HDF_LOG_TAG usb_driver_manager

namespace OHOS {
namespace HDI {
namespace Usb {
namespace Ddk {
namespace V1_1 {
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

bool UsbDriverManager::UpdateDriverInfo(const DriverAbilityInfo &driverInfo)
{
    uint32_t tokenId;
    if (!ConvertDriverUid2TokenId(driverInfo.driverUid, tokenId)) {
        HDF_LOGE("%{public}s: convert failed, driverUid:%{public}s", __func__, driverInfo.driverUid.c_str());
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    driverMap_[tokenId] = std::make_unique<DriverAbilityInfo>(driverInfo);
    return true;
}

bool UsbDriverManager::RemoveDriverInfo(const std::string &driverUid)
{
    uint32_t tokenId;
    if (!ConvertDriverUid2TokenId(driverUid, tokenId)) {
        HDF_LOGE("%{public}s: convert failed, driverUid:%{public}s", __func__, driverUid.c_str());
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    auto it = driverMap_.find(tokenId);
    if (it != driverMap_.end()) {
        driverMap_.erase(tokenId);
    }
    return true;
}

bool UsbDriverManager::QueryDriverInfo(uint32_t tokenId, DriverAbilityInfo &driverInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = driverMap_.find(tokenId);
    if (it != driverMap_.end() && it->second != nullptr) {
        driverInfo = *(it->second);
        return true;
    }
    return false;
}
} // namespace V1_1
} // namespace Ddk
} // namespace Usb
} // namespace HDI
} // namespace OHOS