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
    WifiError (*vendorHalInit)(wifiHandle *);
    WifiError (*waitDriverStart)(void);
    void (*vendorHalExit)(wifiHandle, VendorHalExitHandler);
    void (*startHalLoop)(wifiHandle);
    WifiError (*vendorHalGetIfaces)(wifiHandle, int *, wifiInterfaceHandle **);
    WifiError (*vendorHalGetIfName)(wifiInterfaceHandle, char *name, size_t size);
    WifiError (*vendorHalGetChannelsInBand)(wifiInterfaceHandle, int, int, int *, int *);
    WifiError (*vendorHalCreateIface)(wifiHandle handle, const char* ifname, HalIfaceType ifaceType);
    WifiError (*vendorHalDeleteIface)(wifiHandle handle, const char* ifname);
    WifiError (*vendorHalSetRestartHandler)(wifiHandle handle, VendorHalRestartHandler handler);
    WifiError (*vendorHalPreInit)(void);
    WifiError (*triggerVendorHalRestart)(wifiHandle handle);
} WifiHalFn;

WifiError InitWifiVendorHalFuncTable(WifiHalFn *fn);
typedef WifiError (*InitWifiVendorHalFuncTableT)(WifiHalFn *fn);

#ifdef __cplusplus
}
#endif

#endif