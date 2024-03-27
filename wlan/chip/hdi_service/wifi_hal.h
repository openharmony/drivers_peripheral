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

#ifndef WIFI_HAL_H
#define WIFI_HAL_H

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C"
{
#endif

#define IFNAMSIZ_WIFI 16

typedef unsigned char byte;
typedef unsigned char u8;
typedef signed char s8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef int32_t s32;
typedef uint64_t u64;
typedef int64_t s64;
typedef int wifi_request_id;
typedef int wifi_channel;
typedef int wifi_rssi;
typedef int wifi_radio;
typedef byte mac_addr[6];
typedef byte oui[3];
typedef int64_t wifi_timestamp;
typedef int64_t wifi_timespan;
typedef uint64_t feature_set;
typedef uint32_t WifiChannelInMhz;

struct WifiInfo;
struct WifiInterfaceInfo;
typedef struct WifiInfo *wifiHandle;
typedef struct WifiInterfaceInfo *wifiInterfaceHandle;

typedef enum {
    WIFI_CHAN_WIDTH_20    = 0,
    WIFI_CHAN_WIDTH_40    = 1,
    WIFI_CHAN_WIDTH_80    = 2,
    WIFI_CHAN_WIDTH_160   = 3,
    WIFI_CHAN_WIDTH_80P80 = 4,
    WIFI_CHAN_WIDTH_5     = 5,
    WIFI_CHAN_WIDTH_10    = 6,
    WIFI_CHAN_WIDTH_INVALID = -1
} WifiChannelWidth;

typedef enum {
    WIFI_INTERFACE_TYPE_STA = 0,
    WIFI_INTERFACE_TYPE_AP  = 1,
    WIFI_INTERFACE_TYPE_P2P = 2,
    WIFI_INTERFACE_TYPE_NAN = 3
} WifiInterfaceType;

typedef enum {
    WLAN_MAC_2_4_BAND = 1 << 0,
    WLAN_MAC_5_0_BAND = 1 << 1,
    WLAN_MAC_6_0_BAND = 1 << 2,
    WLAN_MAC_60_0_BAND = 1 << 3
}WlanMacBand;

typedef enum {
    WIFI_SUCCESS = 0,
    WIFI_ERROR_NONE = 0,
    WIFI_ERROR_UNKNOWN = -1,
    WIFI_ERROR_UNINITIALIZED = -2,
    WIFI_ERROR_NOT_SUPPORTED = -3,
    WIFI_ERROR_NOT_AVAILABLE = -4,
    WIFI_ERROR_INVALID_ARGS = -5,
    WIFI_ERROR_INVALID_REQUEST_ID = -6,
    WIFI_ERROR_TIMED_OUT = -7,
    WIFI_ERROR_TOO_MANY_REQUESTS = -8,
    WIFI_ERROR_OUT_OF_MEMORY = -9,
    WIFI_ERROR_BUSY = -10
} WifiError;

WifiError WifiInitialize(wifiHandle *handle);
WifiError WifiWaitForDriverReady(void);

typedef void (*WifiCleanedUpHandler) (wifiHandle handle);
void WifiCleanup(wifiHandle handle, WifiCleanedUpHandler handler);
void WifiEventLoop(wifiHandle handle);

#define WIFI_FEATURE_INFRA            static_cast<uint64_t>(0x1)
#define WIFI_FEATURE_INFRA_5G         static_cast<uint64_t>(0x2)
#define WIFI_FEATURE_HOTSPOT          static_cast<uint64_t>(0x4)
#define WIFI_FEATURE_P2P              static_cast<uint64_t>(0x8)
#define WIFI_FEATURE_SOFT_AP          static_cast<uint64_t>(0x10)
#define WIFI_FEATURE_GSCAN            static_cast<uint64_t>(0x20)
#define WIFI_FEATURE_NAN              static_cast<uint64_t>(0x40)
#define WIFI_FEATURE_D2D_RTT          static_cast<uint64_t>(0x80)
#define WIFI_FEATURE_D2AP_RTT         static_cast<uint64_t>(0x100)
#define WIFI_FEATURE_BATCH_SCAN       static_cast<uint64_t>(0x200)
#define WIFI_FEATURE_PNO              static_cast<uint64_t>(0x400)
#define WIFI_FEATURE_ADDITIONAL_STA   static_cast<uint64_t>(0x800)
#define WIFI_FEATURE_TDLS             static_cast<uint64_t>(0x1000)
#define WIFI_FEATURE_TDLS_OFFCHANNEL  static_cast<uint64_t>(0x2000)
#define WIFI_FEATURE_EPR              static_cast<uint64_t>(0x4000)
#define WIFI_FEATURE_AP_STA           static_cast<uint64_t>(0x8000)
#define WIFI_FEATURE_LINK_LAYER_STATS static_cast<uint64_t>(0x10000)
#define WIFI_FEATURE_LOGGER           static_cast<uint64_t>(0x20000)
#define WIFI_FEATURE_HAL_EPNO         static_cast<uint64_t>(0x40000)
#define WIFI_FEATURE_RSSI_MONITOR     static_cast<uint64_t>(0x80000)
#define WIFI_FEATURE_MKEEP_ALIVE      static_cast<uint64_t>(0x100000)
#define WIFI_FEATURE_CONFIG_NDO       static_cast<uint64_t>(0x200000)
#define WIFI_FEATURE_TX_TRANSMIT_POWER static_cast<uint64_t>(0x400000)
#define WIFI_FEATURE_CONTROL_ROAMING  static_cast<uint64_t>(0x800000)
#define WIFI_FEATURE_IE_WHITELIST     static_cast<uint64_t>(0x1000000)
#define WIFI_FEATURE_SCAN_RAND        static_cast<uint64_t>(0x2000000)
#define WIFI_FEATURE_SET_TX_POWER_LIMIT static_cast<uint64_t>(0x4000000)
#define WIFI_FEATURE_USE_BODY_HEAD_SAR  static_cast<uint64_t>(0x8000000)
#define WIFI_FEATURE_SET_LATENCY_MODE   static_cast<uint64_t>(0x40000000)
#define WIFI_FEATURE_P2P_RAND_MAC       static_cast<uint64_t>(0x80000000)
#define WIFI_FEATURE_INFRA_60G          static_cast<uint64_t>(0x100000000)

#define IS_MASK_SET(mask, flags)        (((flags) & (mask)) == (mask))

#define IS_SUPPORTED_FEATURE(feature, featureSet)   IS_MASK_SET(feature, featureSet)

WifiError WifiGetIfaces(wifiHandle handle, int *numIfaces, wifiInterfaceHandle **ifaces);
WifiError WifiGetIfaceName(wifiInterfaceHandle iface, char *name, size_t size);

typedef struct {
    char ifaceName[IFNAMSIZ_WIFI + 1];
    wifi_channel channel;
} WifiIfaceInfo;

typedef struct {
    void (*onSubsystemRestart)(const char* error);
} WifiSubsystemRestartHandler;

WifiError WifiSetNodfsFlag(wifiInterfaceHandle handle, u32 nodfs);

WifiError WifiSetSubsystemRestartHandler(wifiHandle handle,
    WifiSubsystemRestartHandler handler);

#define WIFI_COEX_NO_POWER_CAP (int32_t)0x7FFFFFF

typedef struct {
    WlanMacBand band;
    u32 channel;
    s32 powerCapDbm;
} WifiCoexUnsafeChannel;

typedef struct {
    WifiError (*wifiInitialize)(wifiHandle *);
    WifiError (*wifiWaitForDriverReady)(void);
    void (*wifiCleanup)(wifiHandle, WifiCleanedUpHandler);
    void (*wifiEventLoop)(wifiHandle);
    WifiError (*wifiGetIfaces)(wifiHandle, int *, wifiInterfaceHandle **);
    WifiError (*wifiGetIfaceName)(wifiInterfaceHandle, char *name, size_t);
    WifiError (*wifiGetValidChannels)(wifiInterfaceHandle, int, int, wifi_channel *, int *);
    WifiError (*wifiSetNodfsFlag)(wifiInterfaceHandle, u32);
    WifiError (*wifiGetLoggerSupportedFeatureSet)(wifiInterfaceHandle iface,
        unsigned int *support);
    WifiError (*wifiVirtualInterfaceCreate)(wifiHandle handle, const char* ifname,
                                                WifiInterfaceType ifaceType);
    WifiError (*wifiVirtualInterfaceDelete)(wifiHandle handle, const char* ifname);
    WifiError (*wifiSetSubsystemRestartHandler)(wifiHandle handle,
                                                    WifiSubsystemRestartHandler handler);
    WifiError (*wifiGetSupportedIfaceName)(wifiHandle handle, u32 ifaceType,
                                                char *name, size_t len);
    WifiError (*wifiEarlyInitialize)(void);
    WifiError (*wifiGetChipFeatureSet)(wifiHandle handle, feature_set *set);
    WifiError (*wifiTriggerSubsystemRestart)(wifiHandle handle);
} WifiHalFn;

WifiError InitWifiVendorHalFuncTable(WifiHalFn *fn);
typedef WifiError (*InitWifiVendorHalFuncTableT)(WifiHalFn *fn);

#ifdef __cplusplus
}
#endif

#endif