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

#include "wifi_p2p_iface.h"

namespace OHOS {
namespace HDI {
namespace Wlan {
namespace Chip {
namespace V1_0 {
WifiP2pIface::WifiP2pIface(
    const std::string& ifname, const std::weak_ptr<WifiVendorHal> vendorHal)
    : ifname_(ifname),
      vendorHal_(vendorHal),
      isValid_(true) {}

void WifiP2pIface::Invalidate()
{
    vendorHal_.reset();
    isValid_ = false;
}

bool WifiP2pIface::IsValid()
{
    return isValid_;
}

std::string WifiP2pIface::GetName()
{
    return ifname_;
}

int32_t WifiP2pIface::GetIfaceType(IfaceType& type)
{
    type = IfaceType::P2P;
    return HDF_SUCCESS;
}

int32_t WifiP2pIface::GetIfaceName(std::string& name)
{
    name = ifname_;
    return HDF_SUCCESS;
}

int32_t WifiP2pIface::GetSupportFreqs(WifiBand band, std::vector<uint32_t>& frequencies)
{
    return HDF_SUCCESS;
}

int32_t WifiP2pIface::GetIfaceCap(uint32_t& capabilities)
{
    return HDF_SUCCESS;
}
}
}
}
}
}