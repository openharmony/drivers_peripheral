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

#ifndef WIFI_SCAN
#define WIFI_SCAN
#include "wifi_hal.h"

#define SCAN_QUAL_INVALID      1U << 0
#define SCAN_NOISE_INVALID     1U << 1
#define SCAN_LEVEL_INVALID     1U << 2
#define SCAN_LEVEL_DBM         1U << 3
#define SCAN_ASSOCIATED        1U << 5

#define BITNUMS_OF_ONE_BYTE 8
#define SLOW_SCAN_INTERVAL_MULTIPLIER 3
#define FAST_SCAN_ITERATIONS 3
#define BITNUMS_OF_ONE_BYTE 8
#define SCHED_SCAN_PLANS_ATTR_INDEX1 1
#define SCHED_SCAN_PLANS_ATTR_INDEX2 2
#define MS_PER_SECOND 1000
#define SIGNAL_LEVEL_CONFFICIENT 100


typedef struct {
    uint8_t maxNumScanSsids;
    uint8_t maxNumSchedScanSsids;
    uint8_t maxMatchSets;
    uint32_t maxNumScanPlans;
    uint32_t maxScanPlanInterval;
    uint32_t maxScanPlanIterations;
} ScanCapabilities;

typedef struct {
    bool supportsRandomMacSchedScan;
    bool supportsLowPowerOneshotScan;
    bool supportsExtSchedScanRelativeRssi;
} WiphyFeatures;

typedef struct {
    ScanCapabilities scanCapabilities;
    WiphyFeatures wiphyFeatures;
} WiphyInfo;

WifiError WifiStartScan(wifiInterfaceHandle handle,
    const OHOS::HDI::Wlan::Chip::V1_0::ScanParams& scanParam);
WifiError WifiGetScanInfo(wifiInterfaceHandle handle,
    std::vector<OHOS::HDI::Wlan::Chip::V1_0::ScanResultsInfo>& mscanResults);
WifiError WifiStartPnoScan(wifiInterfaceHandle handle,
    const OHOS::HDI::Wlan::Chip::V1_0::PnoScanParams& scanParam);
WifiError WifiStopPnoScan(wifiInterfaceHandle handle);

#endif
