/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef WLAN_HDI_TYPES_H
#define WLAN_HDI_TYPES_H

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef enum {
    PROTOCOL_80211_IFTYPE_UNSPECIFIED,                         /**< Unspecified type */
    PROTOCOL_80211_IFTYPE_ADHOC,                               /**< Ad hoc network */
    PROTOCOL_80211_IFTYPE_STATION,                             /**< Station */
    PROTOCOL_80211_IFTYPE_AP,                                  /**< Access point (AP) */
    PROTOCOL_80211_IFTYPE_AP_VLAN,                             /**< Virtual AP */
    PROTOCOL_80211_IFTYPE_WDS,                                 /**< Wireless distributed system */
    PROTOCOL_80211_IFTYPE_MONITOR,                             /**< Listening */
    PROTOCOL_80211_IFTYPE_MESH_POINT,                          /**< Mesh network */
    PROTOCOL_80211_IFTYPE_P2P_CLIENT,                          /**< P2P client */
    PROTOCOL_80211_IFTYPE_P2P_GO,                              /**< P2P group owner */
    PROTOCOL_80211_IFTYPE_P2P_DEVICE,                          /**< P2P device */
    PROTOCOL_80211_IFTYPE_NUM,                                 /**< Number of network ports */
} FeatureType;

enum Ieee80211Band {
    IEEE80211_BAND_2GHZ,  /**< 2.4 GHz */
    IEEE80211_BAND_5GHZ,  /**< 5 GHz */
    IEEE80211_NUM_BANDS   /**< Reserved */
};

typedef enum {
    CMD_CLOSE_GO_CAC,
    CMD_SET_GO_CSA_CHANNEL,
    CMD_SET_GO_RADAR_DETECT,
    CMD_ID_MCC_STA_P2P_QUOTA_TIME,
    CMD_ID_CTRL_ROAM_CHANNEL
} ProjectionScreenCmd;

typedef enum {
    CMD_HID2D_MODULE_INIT,
    CMD_SET_BATTERY_LEVEL,
    CMD_SET_SUPP_COEX_CHAN_LIST,
    CMD_SET_CHAN_ADJUST
} Hid2dCmdType;

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif
#define ETH_ADDR_LEN 6
#define WIFI_POWER_MODE_SLEEPING 0
#define WIFI_POWER_MODE_GENERAL 1
#define WIFI_POWER_MODE_THROUGH_WALL 2
#define WIFI_POWER_MODE_NUM 3

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of wlan_hdi_types.h */