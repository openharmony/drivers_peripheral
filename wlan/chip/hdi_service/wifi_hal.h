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
#include "v1_0/ichip_iface_callback.h"
#include "v1_0/chip_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define IFNAMSIZ_WIFI 16
#define ETH_ADDR_LEN 6
#define BSS_STATUS_ASSOCIATED 1

typedef unsigned char macAddr[6];

struct WifiInfo;
struct WifiInterfaceInfo;
typedef struct WifiInfo *wifiHandle;
typedef struct WifiInterfaceInfo *wifiInterfaceHandle;

typedef enum {
    HAL_TYPE_STA = 0,
    HAL_TYPE_AP  = 1,
    HAL_TYPE_P2P = 2,
    HAL_TYPE_NAN = 3
} HalIfaceType;

typedef enum {
    HAL_SUCCESS = 0,
    HAL_NONE = 0,
    HAL_UNKNOWN = -1,
    HAL_UNINITIALIZED = -2,
    HAL_NOT_SUPPORTED = -3,
    HAL_NOT_AVAILABLE = -4,
    HAL_INVALID_ARGS = -5,
    HAL_INVALID_REQUEST_ID = -6,
    HAL_TIMED_OUT = -7,
    HAL_TOO_MANY_REQUESTS = -8,
    HAL_OUT_OF_MEMORY = -9,
    HAL_BUSY = -10
} WifiError;

enum Ieee80211Band {
    IEEE80211_BAND_2GHZ,
    IEEE80211_BAND_5GHZ,
    IEEE80211_NUM_BANDS
};

typedef struct {
    uint8_t associatedBssid[ETH_ADDR_LEN];
    uint32_t associatedFreq;
} AssociatedInfo;

WifiError VendorHalInit(wifiHandle *handle);
WifiError WaitDriverStart(void);

typedef void (*VendorHalExitHandler) (wifiHandle handle);
void VendorHalExit(wifiHandle handle, VendorHalExitHandler handler);
void StartHalLoop(wifiHandle handle);

WifiError VendorHalGetIfaces(wifiHandle handle, int *numIfaces, wifiInterfaceHandle **ifaces);
WifiError VendorHalGetIfName(wifiInterfaceHandle iface, char *name, size_t size);

typedef struct {
    void (*onVendorHalRestart)(const char* error);
} VendorHalRestartHandler;

WifiError VendorHalSetRestartHandler(wifiHandle handle,
    VendorHalRestartHandler handler);

typedef struct {
    void (*onScanEvent) (int event);
    void (*OnRssiReport) (int index, int c0Rssi, int c1Rssi);
} WifiCallbackHandler;

typedef struct {
    WifiError (*vendorHalInit)(wifiHandle *);
    WifiError (*waitDriverStart)(void);
    void (*vendorHalExit)(wifiHandle, VendorHalExitHandler);
    void (*startHalLoop)(wifiHandle);
    uint32_t (*wifiGetSupportedFeatureSet)(const char *);
    WifiError (*wifiGetChipFeatureSet)(wifiHandle handle, uint64_t *set);
    WifiError (*vendorHalGetIfaces)(wifiHandle, int *, wifiInterfaceHandle **);
    WifiError (*vendorHalGetIfName)(wifiInterfaceHandle, char *name, size_t size);
    WifiError (*vendorHalGetChannelsInBand)(wifiInterfaceHandle, int, std::vector<uint32_t>&);
    WifiError (*vendorHalCreateIface)(wifiHandle handle, const char* ifname, HalIfaceType ifaceType);
    WifiError (*vendorHalDeleteIface)(wifiHandle handle, const char* ifname);
    WifiError (*vendorHalSetRestartHandler)(wifiHandle handle, VendorHalRestartHandler handler);
    uint32_t (*getChipCaps)(const char *);
    WifiError (*vendorHalPreInit)(void);
    WifiError (*triggerVendorHalRestart)(wifiHandle handle);
    WifiError (*wifiSetCountryCode)(wifiInterfaceHandle handle, const char *);
    WifiError (*getPowerMode)(const char *, int *);
    WifiError (*setPowerMode)(const char *, int);
    WifiError (*wifiStartScan)(wifiInterfaceHandle handle,
        const OHOS::HDI::Wlan::Chip::V1_0::ScanParams& scanParam);
    WifiError (*wifiStartPnoScan)(wifiInterfaceHandle handle,
        const OHOS::HDI::Wlan::Chip::V1_0::PnoScanParams& pnoScanParam);
    WifiError (*wifiStopPnoScan)(wifiInterfaceHandle handle);
    WifiError (*getScanResults)(wifiInterfaceHandle handle,
        std::vector<OHOS::HDI::Wlan::Chip::V1_0::ScanResultsInfo>& mscanResults);
    WifiError (*enablePowerMode)(const char *, int);
    WifiError (*getSignalPollInfo)(wifiInterfaceHandle handle,
        OHOS::HDI::Wlan::Chip::V1_0::SignalPollResult& signalPollResult);
    WifiError (*setDpiMarkRule)(int32_t, int32_t, int32_t);
    WifiError (*registerIfaceCallBack)(const char *, WifiCallbackHandler);
    WifiError (*setTxPower)(const char *, int);
} WifiHalFn;

WifiError InitWifiVendorHalFuncTable(WifiHalFn *fn);
typedef WifiError (*InitWifiVendorHalFuncTableT)(WifiHalFn *fn);

#ifdef __cplusplus
}
#endif

#endif