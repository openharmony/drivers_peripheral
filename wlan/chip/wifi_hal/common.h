/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2024. All rights reserved.
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

#ifndef __WIFI_HAL_COMMON_H__
#define __WIFI_HAL_COMMON_H__

#include "wifi_hal.h"
#include <linux/nl80211.h>
#include "sync.h"
#include <hdf_log.h>
#include <map>
#include <mutex>
#include <shared_mutex>

#define SOCKET_BUFFER_SIZE      (32768U)
constexpr int32_t DEFAULT_EVENT_CB_SIZE = 64;
constexpr int32_t DEFAULT_CMD_SIZE = 64;

const uint32_t HAL_OUI = 0x001A11;
const uint32_t BRCM_OUI =  0x001018;
const uint32_t OUI_QCA = 0x001374;

typedef int (*nl_recvmsg_msg_cb_t)(struct nl_msg *msg, void *arg);
typedef enum {
    /* don't use 0 as a valid subcommand */
    VENDOR_NL80211_SUBCMD_UNSPECIFIED,
    VENDOR_NL80211_SUBCMD_RANGE_START = 0x0001,
    VENDOR_NL80211_SUBCMD_RANGE_END   = 0x0FFF,
    NL80211_SUBCMD_GSCAN_RANGE_START = 0x1000,
    NL80211_SUBCMD_GSCAN_RANGE_END   = 0x10FF,
    NL80211_SUBCMD_NBD_RANGE_START = 0x1100,
    NL80211_SUBCMD_NBD_RANGE_END   = 0x11FF,
    NL80211_SUBCMD_RTT_RANGE_START = 0x1100,
    NL80211_SUBCMD_RTT_RANGE_END   = 0x11FF,
    NL80211_SUBCMD_LSTATS_RANGE_START = 0x1200,
    NL80211_SUBCMD_LSTATS_RANGE_END   = 0x12FF,
    NL80211_SUBCMD_DEBUG_RANGE_START = 0x1400,
    NL80211_SUBCMD_DEBUG_RANGE_END   = 0x14FF,
    NL80211_SUBCMD_WIFI_OFFLOAD_RANGE_START = 0x1600,
    NL80211_SUBCMD_WIFI_OFFLOAD_RANGE_END   = 0x16FF,
    NL80211_SUBCMD_NAN_RANGE_START = 0x1700,
    NL80211_SUBCMD_NAN_RANGE_END   = 0x17FF,
    NL80211_SUBCMD_PKT_FILTER_RANGE_START = 0x1800,
    NL80211_SUBCMD_PKT_FILTER_RANGE_END   = 0x18FF,
    NL80211_SUBCMD_TX_POWER_RANGE_START = 0x1900,
    NL80211_SUBCMD_TX_POWER_RANGE_END    = 0x1910,
    NL80211_SUBCMD_MITIGATION_RANGE_START = 0x1920,
    NL80211_SUBCMD_MITIGATION_RANGE_END   = 0x192F,
    NL80211_SUBCMD_DSCP_RANGE_START =   0x2000,
    NL80211_SUBCMD_DSCP_RANGE_END   =   0x20FF,
    NL80211_SUBCMD_CHAVOID_RANGE_START =    0x2100,
    NL80211_SUBCMD_CHAVOID_RANGE_END   =    0x211F,
    NL80211_SUBCMD_OTA_DOWNLOAD_START   = 0x2120,
    NL80211_SUBCMD_OTA_DOWNLOAD_END = 0x212F,
    NL80211_SUBCMD_VIOP_MODE_START = 0x2130,
    NL80211_SUBCMD_VIOP_MODE_END = 0x213F,
    NL80211_SUBCMD_TWT_START = 0x2140,
    NL80211_SUBCMD_TWT_END = 0x214F,
    NL80211_SUBCMD_USABLE_CHANNEL_START = 0x2150,
    NL80211_SUBCMD_USABLE_CHANNEL_END = 0x215F,
    NL80211_SUBCMD_INIT_DEINIT_RANGE_START = 0x2160,
    NL80211_SUBCMD_INIT_DEINIT_RANGE_END   = 0x216F,
}VENDOR_SUB_COMMAND;

typedef enum {
    GSCAN_SUBCMD_GET_CAPABILITIES = NL80211_SUBCMD_GSCAN_RANGE_START,
    GSCAN_SUBCMD_SET_CONFIG,
    GSCAN_SUBCMD_SET_SCAN_CONFIG,
    GSCAN_SUBCMD_ENABLE_GSCAN,
    GSCAN_SUBCMD_GET_SCAN_RESULTS,
    GSCAN_SUBCMD_SCAN_RESULTS,
    GSCAN_SUBCMD_SET_HOTLIST,
    GSCAN_SUBCMD_SET_SIGNIFICANT_CHANGE_CONFIG,
    GSCAN_SUBCMD_ENABLE_FULL_SCAN_RESULTS,
    GSCAN_SUBCMD_GET_CHANNEL_LIST,
    WIFI_SUBCMD_GET_FEATURE_SET,
    WIFI_SUBCMD_GET_FEATURE_SET_MATRIX,
    WIFI_SUBCMD_SET_PNO_RANDOM_MAC_OUI,
    WIFI_SUBCMD_NODFS_SET,
    WIFI_SUBCMD_SET_COUNTRY_CODE,
    GSCAN_SUBCMD_SET_EPNO_SSID,
    WIFI_SUBCMD_SET_SSID_WHITE_LIST,
    WIFI_SUBCMD_SET_ROAM_PARAMS,
    WIFI_SUBCMD_ENABLE_LAZY_ROAM,
    WIFI_SUBCMD_SET_BSSID_PREF,
    WIFI_SUBCMD_SET_BSSID_AVOID,
    GSCAN_SUBCMD_ANQPO_CONFIG,
    WIFI_SUBCMD_SET_RSSI_MONITOR,
    WIFI_SUBCMD_CONFIG_ND_OFFLOAD,
    WIFI_SUBCMD_CONFIG_TCPACK_SUP,
    WIFI_SUBCMD_FW_ROAM_POLICY,
    WIFI_SUBCMD_ROAM_CAPABILITY,
    WIFI_SUBCMD_SET_LATENCY_MODE,
    WIFI_SUBCMD_SET_MULTISTA_PRIMARY_CONNECTION,
    WIFI_SUBCMD_SET_MULTISTA_USE_CASE,
    WIFI_SUBCMD_SET_DTIM_CONFIG,
    GSCAN_SUBCMD_MAX,
    NAN_SUBCMD_ENABLE = NL80211_SUBCMD_NAN_RANGE_START,
    NAN_SUBCMD_DISABLE,
    NAN_SUBCMD_PUBLISH,
    NAN_SUBCMD_SUBSCRIBE,
    NAN_SUBCMD_PUBLISH_CANCEL,
    NAN_SUBCMD_SUBSCRIBE_CANCEL,
    NAN_SUBCMD_TRANSMIT_FOLLOWUP,
    NAN_SUBCMD_CONFIG,
    NAN_SUBCMD_TCA,
    NAN_SUBCMD_STATS,
    NAN_SUBCMD_GET_CAPABILITIES,
    NAN_SUBCMD_DATA_PATH_IFACE_CREATE,
    NAN_SUBCMD_DATA_PATH_IFACE_DELETE,
    NAN_SUBCMD_DATA_PATH_REQUEST,
    NAN_SUBCMD_DATA_PATH_RESPONSE,
    NAN_SUBCMD_DATA_PATH_END,
    NAN_SUBCMD_DATA_PATH_SEC_INFO,
    NAN_SUBCMD_VERSION_INFO,
    NAN_SUBCMD_ENABLE_MERGE,
    APF_SUBCMD_GET_CAPABILITIES = NL80211_SUBCMD_PKT_FILTER_RANGE_START,
    APF_SUBCMD_SET_FILTER,
    APF_SUBCMD_READ_FILTER,
    WIFI_SUBCMD_TX_POWER_SCENARIO = NL80211_SUBCMD_TX_POWER_RANGE_START,
    WIFI_SUBCMD_THERMAL_MITIGATION = NL80211_SUBCMD_MITIGATION_RANGE_START,
    DSCP_SUBCMD_SET_TABLE = NL80211_SUBCMD_DSCP_RANGE_START,
    DSCP_SUBCMD_RESET_TABLE,
    CHAVOID_SUBCMD_SET_CONFIG = NL80211_SUBCMD_CHAVOID_RANGE_START,
    TWT_SUBCMD_GETCAPABILITY    = NL80211_SUBCMD_TWT_START,
    TWT_SUBCMD_SETUP_REQUEST,
    TWT_SUBCMD_TEAR_DOWN_REQUEST,
    TWT_SUBCMD_INFO_FRAME_REQUEST,
    TWT_SUBCMD_GETSTATS,
    TWT_SUBCMD_CLR_STATS,
    WIFI_SUBCMD_CONFIG_VOIP_MODE = NL80211_SUBCMD_VIOP_MODE_START,
    WIFI_SUBCMD_GET_OTA_CURRUNT_INFO = NL80211_SUBCMD_OTA_DOWNLOAD_START,
    WIFI_SUBCMD_OTA_UPDATE,
    WIFI_SUBCMD_USABLE_CHANNEL = NL80211_SUBCMD_USABLE_CHANNEL_START,
    WIFI_SUBCMD_TRIGGER_SSR = NL80211_SUBCMD_INIT_DEINIT_RANGE_START,
} WIFI_SUB_COMMAND;

typedef enum {
    BRCM_RESERVED1              = 0,
    BRCM_RESERVED2              = 1,
    GSCAN_EVENT_SIGNIFICANT_CHANGE_RESULTS = 2,
    GSCAN_EVENT_HOTLIST_RESULTS_FOUND      = 3,
    GSCAN_EVENT_SCAN_RESULTS_AVAILABLE     = 4,
    GSCAN_EVENT_FULL_SCAN_RESULTS       = 5,
    RTT_EVENT_COMPLETE              = 6,
    GSCAN_EVENT_COMPLETE_SCAN           = 7,
    GSCAN_EVENT_HOTLIST_RESULTS_LOST        = 8,
    GSCAN_EVENT_EPNO_EVENT          = 9,
    GSCAN_DEBUG_RING_EVENT          = 10,
    GSCAN_DEBUG_MEM_DUMP_EVENT          = 11,
    GSCAN_EVENT_ANQPO_HOTSPOT_MATCH     = 12,
    GSCAN_RSSI_MONITOR_EVENT            = 13,
    GSCAN_MKEEP_ALIVE               = 14,
    NAN_EVENT_ENABLED               = 15,
    NAN_EVENT_DISABLED              = 16,
    NAN_EVENT_SUBSCRIBE_MATCH           = 17,
    NAN_EVENT_PUBLISH_REPLIED_IND       = 18,
    NAN_EVENT_PUBLISH_TERMINATED        = 19,
    NAN_EVENT_SUBSCRIBE_TERMINATED      = 20,
    NAN_EVENT_DE_EVENT              = 21,
    NAN_EVENT_FOLLOWUP              = 22,
    NAN_EVENT_TRANSMIT_FOLLOWUP_IND     = 23,
    NAN_EVENT_DATA_REQUEST          = 24,
    NAN_EVENT_DATA_CONFIRMATION         = 25,
    NAN_EVENT_DATA_END              = 26,
    NAN_EVENT_BEACON                = 27,
    NAN_EVENT_SDF               = 28,
    NAN_EVENT_TCA               = 29,
    NAN_EVENT_SUBSCRIBE_UNMATCH         = 30,
    NAN_EVENT_UNKNOWN               = 31,
    NAN_EVENT_RESPONSE              = 32,
    BRCM_VENDOR_EVENT_HANGED            = 33,
    ROAM_EVENT_START,
    GSCAN_FILE_DUMP_EVENT           = 37,
    NAN_ASYNC_RESPONSE_DISABLED         = 40,
    BRCM_IDSUP_STATUS           = 42,
    BRCM_VENDOR_EVENT_TWT           = 43,
    BRCM_TPUT_DUMP_EVENT            = 44,
    NAN_EVENT_MATCH_EXPIRY          = 45
} WIFI_EVENT;

typedef void (*WifiInternalEventHandler) (wifiHandle handle, int events);

class WifiCommand;

typedef struct {
    int nlCmd;
    uint32_t vendorId;
    int vendorSubcmd;
    nl_recvmsg_msg_cb_t cbFunc;
    void *cbArg;
} CbInfo;

typedef struct {
    int id;
    WifiCommand *cmd;
} CmdInfo;

typedef struct {
    wifiHandle handle;
    char name[IFNAMSIZ + 1];
    int  id;
    bool isVirtual;
} InterfaceInfo;

typedef struct {
    struct nl_sock *cmdSock;
    struct nl_sock *eventSock;
    int nl80211FamilyId;
    int cleanupSocks[2];
    bool inEventLoop;
    bool cleanUp;
    WifiInternalEventHandler eventHandler;
    VendorHalExitHandler CleanedUpHandler;
    CbInfo *eventCb;
    int numEventCb;
    int allocEventCb;
    pthread_mutex_t cbLock;
    CmdInfo *cmd;
    int numCmd;
    int allocCmd;
    InterfaceInfo **interfaces;
    int numInterfaces;
    int maxNumInterfaces;
    VendorHalRestartHandler restartHandler;
    WifiCallbackHandler ifaceCallBack;
} HalInfo;

WifiError WifiRegisterHandler(wifiHandle handle, int cmd, nl_recvmsg_msg_cb_t func, void *arg);
WifiError WifiRegisterVendorHandler(wifiHandle handle,
    uint32_t id, int subcmd, nl_recvmsg_msg_cb_t func, void *arg);
void WifiUnregisterHandler(wifiHandle handle, int cmd);
void WifiUnregisterVendorHandlerWithoutLock(wifiHandle handle, uint32_t id, int subcmd);
void WifiUnregisterVendorHandler(wifiHandle handle, uint32_t id, int subcmd);
WifiError WifiRegisterCmd(wifiHandle handle, int id, WifiCommand *cmd);
WifiCommand *WifiUnregisterCmd(wifiHandle handle, int id);
void WifiUnregisterCmd(wifiHandle handle, WifiCommand *cmd);
InterfaceInfo *GetIfaceInfo(wifiInterfaceHandle);
wifiHandle GetWifiHandle(wifiInterfaceHandle handle);
HalInfo *GetHalInfo(wifiHandle handle);
HalInfo *GetHalInfo(wifiInterfaceHandle handle);
wifiHandle GetWifiHandle(HalInfo *info);
wifiInterfaceHandle GetIfaceHandle(InterfaceInfo *info);
wifiInterfaceHandle WifiGetWlanInterface(wifiHandle info,
    wifiInterfaceHandle *ifaceHandles, int numIfaceHandles);
void SetHautilMode(bool halutilMode);
bool GetGHalutilMode();
WifiError TriggerVendorHalRestart(wifiHandle handle);
std::shared_lock<std::shared_mutex> ReadLockData();
std::unique_lock<std::shared_mutex> WriteLock();

#define MIN(x, y)       ((x) < (y) ? (x) : (y))
#define MAX(x, y)       ((x) > (y) ? (x) : (y))

#define NULL_CHECK_RETURN(ptr, str, ret) \
    do { \
        if (!(ptr)) { \
            HDF_LOGE("%s(): null pointer - #ptr (%s)\n", __FUNCTION__, str); \
            return ret; \
        } \
    } while (0)

#endif
