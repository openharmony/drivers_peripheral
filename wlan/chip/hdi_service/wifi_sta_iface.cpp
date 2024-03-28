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

#include "wifi_sta_iface.h"
#include <hdf_log.h>

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
{}

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

int32_t WifiStaIface::GetSupportFreqs(BandType band, std::vector<uint32_t>& frequencies)
{
    WifiError status;
    std::vector<uint32_t> validFrequencies;
    std::tie(status, validFrequencies) = vendorHal_.lock()->GetValidFrequenciesForBand(
        ifname_, band);
    frequencies = validFrequencies;
    if (status == HAL_SUCCESS) {
        return HDF_SUCCESS;
    }
    return HDF_FAILURE;
}

}
}
}
}
}