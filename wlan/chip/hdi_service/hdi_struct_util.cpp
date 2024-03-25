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

#include "hdi_struct_util.h"
#include <hdf_log.h>

namespace OHOS {
namespace HDI {
namespace Wlan {
namespace Chip {
namespace V1_0 {

uint32_t ConvertLoggerFeatureToCapability(uint32_t feature)
{
    using HidlChipCaps = ChipCapabilityMask;
    switch (feature) {
        case WIFI_LOGGER_MEMORY_DUMP_SUPPORTED:
            return HidlChipCaps::DEBUG_MEMORY_FIRMWARE_DUMP;
        case WIFI_LOGGER_DRIVER_DUMP_SUPPORTED:
            return HidlChipCaps::DEBUG_MEMORY_DRIVER_DUMP;
        case WIFI_LOGGER_CONNECT_EVENT_SUPPORTED:
            return HidlChipCaps::DEBUG_RING_BUFFER_CONNECT_EVENT;
        case WIFI_LOGGER_POWER_EVENT_SUPPORTED:
            return HidlChipCaps::DEBUG_RING_BUFFER_POWER_EVENT;
        case WIFI_LOGGER_WAKE_LOCK_SUPPORTED:
            return HidlChipCaps::DEBUG_RING_BUFFER_WAKELOCK_EVENT;
        default:
            HDF_LOGI("Unknown legacy feature: %{public}d", feature);
    };
    return 0;
}

uint32_t ConvertVendorFeatureToCapability(uint64_t feature)
{
    using HidlChipCaps = ChipCapabilityMask;
    switch (feature) {
        case WIFI_FEATURE_SET_TX_POWER_LIMIT:
            return HidlChipCaps::SET_TX_POWER_LIMIT;
        case WIFI_FEATURE_USE_BODY_HEAD_SAR:
            return HidlChipCaps::USE_BODY_HEAD_SAR;
        case WIFI_FEATURE_D2D_RTT:
            return HidlChipCaps::D2D_RTT;
        case WIFI_FEATURE_D2AP_RTT:
            return HidlChipCaps::D2AP_RTT;
        case WIFI_FEATURE_INFRA_60G:
            return HidlChipCaps::WIGIG;
        case WIFI_FEATURE_SET_LATENCY_MODE:
            return HidlChipCaps::SET_LATENCY_MODE;
        case WIFI_FEATURE_P2P_RAND_MAC:
            return HidlChipCaps::P2P_RAND_MAC;
        default:
            HDF_LOGI("Unknown feature: %{public}lu", feature);
    };
    return 0;
}

bool ConvertVendorFeaturesToChipCaps(
    uint64_t legacyFeatureSet, uint32_t legacyLoggerFeatureSet, uint32_t* hidlCaps)
{
    if (!hidlCaps) {
        return false;
    }
    *hidlCaps = {};
    using HidlChipCaps = ChipCapabilityMask;
    for (const auto feature : {WIFI_LOGGER_MEMORY_DUMP_SUPPORTED,
                               WIFI_LOGGER_DRIVER_DUMP_SUPPORTED,
                               WIFI_LOGGER_CONNECT_EVENT_SUPPORTED,
                               WIFI_LOGGER_POWER_EVENT_SUPPORTED,
                               WIFI_LOGGER_WAKE_LOCK_SUPPORTED}) {
        if (feature & legacyLoggerFeatureSet) {
            *hidlCaps |=
               ConvertLoggerFeatureToCapability(feature);
        }
    }
    std::vector<uint64_t> features = {WIFI_FEATURE_SET_TX_POWER_LIMIT,
                                      WIFI_FEATURE_USE_BODY_HEAD_SAR,
                                      WIFI_FEATURE_D2D_RTT,
                                      WIFI_FEATURE_D2AP_RTT,
                                      WIFI_FEATURE_INFRA_60G,
                                      WIFI_FEATURE_SET_LATENCY_MODE,
                                      WIFI_FEATURE_P2P_RAND_MAC};
    for (const auto feature : features) {
        if (feature & legacyFeatureSet) {
            *hidlCaps |= ConvertVendorFeatureToCapability(feature);
        }
    }
    *hidlCaps |= HidlChipCaps::DEBUG_RING_BUFFER_VENDOR_DATA;
    *hidlCaps |= HidlChipCaps::DEBUG_HOST_WAKE_REASON_STATS;
    *hidlCaps |= HidlChipCaps::DEBUG_ERROR_ALERTS;
    return true;
}

bool ConvertVendorFeaturesToStaCaps(
    uint64_t legacyFeatureSet, uint32_t legacyLoggerFeatureSet,
    uint32_t* hidlCaps)
{
    if (!hidlCaps) {
        return false;
    }
    *hidlCaps = {};
    using HidlStaIfaceCaps = StaIfaceCapabilityMask;
    for (const auto feature : {WIFI_LOGGER_PACKET_FATE_SUPPORTED}) {
        if (feature & legacyLoggerFeatureSet) {
            *hidlCaps |=
                ConvertLoggerFeatureToStaIfaceCap(feature);
        }
    }
    for (const auto feature : {
        WIFI_FEATURE_GSCAN, WIFI_FEATURE_LINK_LAYER_STATS,
        WIFI_FEATURE_RSSI_MONITOR, WIFI_FEATURE_CONTROL_ROAMING,
        WIFI_FEATURE_IE_WHITELIST, WIFI_FEATURE_SCAN_RAND,
        WIFI_FEATURE_INFRA_5G, WIFI_FEATURE_HOTSPOT, WIFI_FEATURE_PNO,
        WIFI_FEATURE_TDLS, WIFI_FEATURE_TDLS_OFFCHANNEL,
        WIFI_FEATURE_CONFIG_NDO, WIFI_FEATURE_MKEEP_ALIVE}) {
        if (feature & legacyFeatureSet) {
            *hidlCaps |= ConvertVendorFeatureTStaIfaceCap(feature);
        }
    }
    *hidlCaps |= HidlStaIfaceCaps::APF;
    return true;
}

uint32_t ConvertLoggerFeatureToStaIfaceCap(uint32_t feature)
{
    using HidlStaIfaceCaps = StaIfaceCapabilityMask;
    switch (feature) {
        case WIFI_LOGGER_PACKET_FATE_SUPPORTED:
            return HidlStaIfaceCaps::DEBUG_PACKET_FATE;
        default:
            HDF_LOGI("Unknown feature: %{public}d", feature);
    };
    return 0;
}

uint32_t ConvertVendorFeatureTStaIfaceCap(uint64_t feature)
{
    using HidlStaIfaceCaps = StaIfaceCapabilityMask;
    switch (feature) {
        case WIFI_FEATURE_GSCAN:
            return HidlStaIfaceCaps::BACKGROUND_SCAN;
        case WIFI_FEATURE_LINK_LAYER_STATS:
            return HidlStaIfaceCaps::LINK_LAYER_STATS;
        case WIFI_FEATURE_RSSI_MONITOR:
            return HidlStaIfaceCaps::RSSI_MONITOR;
        case WIFI_FEATURE_CONTROL_ROAMING:
            return HidlStaIfaceCaps::CONTROL_ROAMING;
        case WIFI_FEATURE_IE_WHITELIST:
            return HidlStaIfaceCaps::PROBE_IE_WHITELIST;
        case WIFI_FEATURE_SCAN_RAND:
            return HidlStaIfaceCaps::SCAN_RAND;
        case WIFI_FEATURE_INFRA_5G:
            return HidlStaIfaceCaps::STA_5G;
        case WIFI_FEATURE_HOTSPOT:
            return HidlStaIfaceCaps::HOTSPOT;
        case WIFI_FEATURE_PNO:
            return HidlStaIfaceCaps::PNO;
        case WIFI_FEATURE_TDLS:
            return HidlStaIfaceCaps::TDLS;
        case WIFI_FEATURE_TDLS_OFFCHANNEL:
            return HidlStaIfaceCaps::TDLS_OFFCHANNEL;
        case WIFI_FEATURE_CONFIG_NDO:
            return HidlStaIfaceCaps::ND_OFFLOAD;
        case WIFI_FEATURE_MKEEP_ALIVE:
            return HidlStaIfaceCaps::KEEP_ALIVE;
        default:
            HDF_LOGI("Unknown feature: %{public}lu", feature);
    };
    return 0;
}
}
}
}
}
}
