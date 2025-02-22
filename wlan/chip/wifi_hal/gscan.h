/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
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

#ifndef WIFI_HAL_GSCAN_H
#define WIFI_HAL_GSCAN_H

#include "wifi_hal.h"

#define LOW_LITMIT_FREQ_2_4G      2400
#define HIGH_LIMIT_FREQ_2_4G      2500
#define LOW_LIMIT_FREQ_5G         5100
#define HIGH_LIMIT_FREQ_5G        5900

WifiError VendorHalGetChannelsInBand(wifiInterfaceHandle handle,
    int band, std::vector<uint32_t>& freqs);
#endif