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

#ifndef HDI_STRUCT_UTIL_H
#define HDI_STRUCT_UTIL_H

#include <vector>
#include "v1_0/ichip_controller.h"
#include "v1_0/iconcrete_chip.h"
#include "v1_0/chip_types.h"
#include "wifi_vendor_hal.h"

namespace OHOS {
namespace HDI {
namespace Wlan {
namespace Chip {
namespace V1_0 {

uint32_t ConvertLoggerFeatureToCapability(uint32_t feature);
uint32_t ConvertVendorFeatureToCapability(uint64_t feature);
bool ConvertVendorFeaturesToChipCaps(
    uint64_t legacyFeatureSet, uint32_t legacyLoggerFeatureSet,
    uint32_t* hidlCaps);
bool ConvertVendorFeaturesToStaCaps(
    uint64_t legacyFeatureSet, uint32_t legacyLoggerFeatureSet,
    uint32_t* hidlCaps);
uint32_t ConvertLoggerFeatureToStaIfaceCap(uint32_t feature);
uint32_t ConvertVendorFeatureTStaIfaceCap(uint64_t feature);
}
}
}
}
}
#endif