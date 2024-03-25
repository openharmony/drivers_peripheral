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

#ifndef WIFI_LEGACY_HAL_FACTORY_H
#define WIFI_LEGACY_HAL_FACTORY_H

#include "interface_tool.h"
#include "wifi_vendor_hal.h"
#include "wifi_hal.h"
#include <hdf_log.h>

namespace OHOS {
namespace HDI {
namespace Wlan {
namespace Chip {
namespace V1_0 {

class WifiVendorHalList {
public:
    explicit WifiVendorHalList(
        const std::weak_ptr<IfaceTool> ifaceTool);
    virtual ~WifiVendorHalList() = default;

    std::vector<std::shared_ptr<WifiVendorHal>> GetHals();

private:
    typedef struct {
        WifiHalFn fn;
        bool primary;
        void* handle;
    } wifi_hal_lib_desc;
    
    void InitVendorHalsDescriptorList();
    bool LoadVendorHalLib(const std::string& path, wifi_hal_lib_desc& desc);

    std::weak_ptr<IfaceTool> ifaceTool_;
    std::vector<wifi_hal_lib_desc> descs_;
    std::vector<std::shared_ptr<WifiVendorHal>> vendorHals_;
};
    
} // namespace v1_0
} // namespace Chip
} // namespace Wlan
} // namespace HDI
} // namespace OHOS
#endif