/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved
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

#include "wifi_sta_iface.h"
#include <hdf_log.h>
#include "hdi_struct_util.h"

namespace OHOS {
namespace HDI {
namespace Wlan {
namespace Chip {
namespace V1_0 {

WifiStaIface::WifiStaIface(
    const std::string& ifname,
    const std::weak_ptr<WifiVendorHal> vendorHal)
    : ifname_(ifname),
      vendorHal_(vendorHal),
      isValid_(true)
{
    WifiError legacyStatus = vendorHal_.lock()->SetDfsFlag(ifname_, true);
    if (legacyStatus != WifiError::WIFI_SUCCESS) {
        HDF_LOGE("Failed to set DFS flag, DFS channels may be unavailable.");
    }
}

void WifiStaIface::Invalidate()
{
    vendorHal_.reset();
    isValid_ = false;
}

bool WifiStaIface::IsValid()
{
    return isValid_;
}

std::string WifiStaIface::GetName()
{
    return ifname_;
}

int32_t WifiStaIface::GetIfaceType(IfaceType& type)
{
    type = IfaceType::STA;
    return HDF_SUCCESS;
}

int32_t WifiStaIface::GetIfaceName(std::string& name)
{
    name = ifname_;
    return HDF_SUCCESS;
}

int32_t WifiStaIface::GetSupportFreqs(WifiBand band, std::vector<uint32_t>& frequencies)
{
    static_assert(sizeof(WifiChannelInMhz) == sizeof(uint32_t), "Size mismatch");
    WifiError legacyStatus;
    std::vector<uint32_t> validFrequencies;
    std::tie(legacyStatus, validFrequencies) = vendorHal_.lock()->GetValidFrequenciesForBand(
        ifname_, band);
    frequencies = validFrequencies;
    if (legacyStatus == WIFI_SUCCESS) {
        return HDF_SUCCESS;        
    }
    return HDF_FAILURE;
}

int32_t WifiStaIface::GetIfaceCap(uint32_t& capabilities)
{
    WifiError legacyStatus;
    uint64_t legacyFeatureSet;
    std::tie(legacyStatus, legacyFeatureSet) = vendorHal_.lock()->GetSupportedFeatureSet(ifname_);
    if (legacyStatus != WifiError::WIFI_SUCCESS) {
        return HDF_FAILURE;
    }
    uint32_t legacyLoggerFeatureSet = 0;
    uint32_t hidlCaps;
    if (!ConvertVendorFeaturesToStaCaps(legacyFeatureSet, legacyLoggerFeatureSet, &hidlCaps)) {
        return HDF_FAILURE;
    }
    capabilities = hidlCaps;
    return HDF_SUCCESS;
}
}
}
}
}
}