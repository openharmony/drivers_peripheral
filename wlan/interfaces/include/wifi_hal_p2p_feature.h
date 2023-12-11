/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

/**
 * @addtogroup WLAN
 * @{
 *
 * @brief Provides cross-OS migration, component adaptation, and modular assembly and compilation.
 *
 * Based on the unified APIs provided by the WLAN module, developers of the Hardware Driver Interface
 * (HDI) are capable of creating, disabling, scanning for, and connecting to WLAN hotspots, managing WLAN chips,
 * network devices, and power, and applying for, releasing, and moving network data buffers.
 *
 * @since 4.1
 * @version 1.2
 */

/**
 * @file wifi_hal_p2p_feature.h
 *
 * @brief Declares P2P features.
 *
 * @since 4.1
 * @version 1.2
 */

#ifndef WIFI_HAL_P2P_FEATURE_H
#define WIFI_HAL_P2P_FEATURE_H

#include "wifi_hal_base_feature.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/**
 * @brief Inherits the basic features of {@link IWiFiBaseFeature} and additionally provides the feature of setting
 * scanning for a single MAC address.
 *
 * @since 4.1
 * @version 1.2
 */
struct IWiFiP2p {
    struct IWiFiBaseFeature baseFeature;  /**< Basic features of {@link IWiFiBaseFeature} */
};

/**
 * @brief Initializes a specified P2P feature. This function is called during P2P {@link FeatureType} creation.
 *
 * @param fe Indicates the double pointer to the P2P feature.
 *
 * @return Returns <b>0</b> if the operation is successful; returns a negative value representing {@link HDF_STATUS}
 * if the operation fails.
 *
 * @since 4.1
 * @version 1.2
 */
int32_t InitP2pFeature(struct IWiFiP2p **fe);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif
/** @} */
