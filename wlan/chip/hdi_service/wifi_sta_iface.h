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

#ifndef WIFI_STA_IFACE_H
#define WIFI_STA_IFACE_H

#include "v1_0/ichip_iface.h"
#include "v1_0/chip_types.h"
#include "wifi_vendor_hal.h"
#include "callback_handler.h"

namespace OHOS {
namespace HDI {
namespace Wlan {
namespace Chip {
namespace V1_0 {

class WifiStaIface : public IChipIface {
public:
    WifiStaIface(const std::string& ifname,
                const std::weak_ptr<WifiVendorHal> vendorHal);
    void Invalidate();
    bool IsValid();
    std::string GetName();
    int32_t GetIfaceName(std::string& name) override;
    int32_t GetIfaceType(IfaceType& type) override;
    int32_t GetSupportFreqs(WifiBand band,
        std::vector<uint32_t>& frequencies) override;
    int32_t GetIfaceCap(uint32_t& capabilities) override;

private:
    std::string ifname_;
    std::vector<std::string> instances_;
    std::weak_ptr<WifiVendorHal> vendorHal_;
    bool isValid_;
};
}
}
}
}
}
#endif