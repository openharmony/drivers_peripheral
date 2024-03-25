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

#include "wifi_ap_iface.h"
#include "hdi_struct_util.h"

namespace OHOS {
namespace HDI {
namespace Wlan {
namespace Chip {
namespace V1_0 {
WifiApIface::WifiApIface(
    const std::string& ifname, const std::vector<std::string>& instances,
    const std::weak_ptr<WifiVendorHal> vendorHal)
    : ifname_(ifname),
      instances_(instances),
      vendorHal_(vendorHal),
      isValid_(true) {}

void WifiApIface::Invalidate()
{
    vendorHal_.reset();
    isValid_ = false;
}

bool WifiApIface::IsValid()
{
    return isValid_;
}

std::string WifiApIface::GetName()
{
    return ifname_;
}

void WifiApIface::RemoveInstance(std::string instance)
{
    instances_.erase(std::remove(instances_.begin(), instances_.end(), instance), instances_.end());
}

int32_t WifiApIface::GetIfaceType(IfaceType& type)
{
    type = IfaceType::AP;
    return HDF_SUCCESS;
}

int32_t WifiApIface::GetIfaceName(std::string& name)
{
    name = ifname_;
    return HDF_SUCCESS;
}

int32_t WifiApIface::GetSupportFreqs(WifiBand band, std::vector<uint32_t>& frequencies)
{
    static_assert(sizeof(WifiChannelInMhz) == sizeof(uint32_t), "Size mismatch");
    WifiError legacyStatus;
    std::vector<uint32_t> validFrequencies;
    std::tie(legacyStatus, validFrequencies) = vendorHal_.lock()->GetValidFrequenciesForBand(
        instances_.size() > 0 ? instances_[0] : ifname_, band);
    frequencies = validFrequencies;
    if (legacyStatus == WIFI_SUCCESS) {
        return HDF_SUCCESS;
    }
    return HDF_FAILURE;
}

int32_t WifiApIface::GetIfaceCap(uint32_t& capabilities)
{
    return HDF_SUCCESS;
}
}
}
}
}
}