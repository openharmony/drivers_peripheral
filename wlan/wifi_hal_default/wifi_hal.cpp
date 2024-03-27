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

#include "wifi_hal.h"
#include "gscan.h"

WifiError WifiVirtualInterfaceCreate(wifiHandle handle, const char* ifname,
    WifiInterfaceType ifaceType)
{
    return WIFI_SUCCESS;
}

WifiError WifiVirtualInterfaceDelete(wifiHandle handle, const char* ifname)
{
    return WIFI_SUCCESS;
}

WifiError WifiTriggerSubsystemRestart(wifiHandle handle)
{
    return WIFI_SUCCESS;
}

WifiError InitWifiVendorHalFuncTable(WifiHalFn *fn)
{
    if (fn == nullptr) {
        return WIFI_ERROR_UNKNOWN;
    }
    fn->wifiInitialize = WifiInitialize;
    fn->wifiWaitForDriverReady = WifiWaitForDriverReady;
    fn->wifiCleanup = WifiCleanup;
    fn->wifiEventLoop = WifiEventLoop;
    fn->wifiGetSupportedFeatureSet = WifiGetSupportedFeatureSet;
    fn->wifiGetIfaces = WifiGetIfaces;
    fn->wifiGetIfaceName = WifiGetIfaceName;
    fn->wifiGetValidChannels = WifiGetValidChannels;
    fn->wifiSetNodfsFlag = WifiSetNodfsFlag;
    fn->wifiSetSubsystemRestartHandler = WifiSetSubsystemRestartHandler;
    fn->wifiVirtualInterfaceCreate = WifiVirtualInterfaceCreate;
    fn->wifiVirtualInterfaceDelete = WifiVirtualInterfaceDelete;
    fn->wifiTriggerSubsystemRestart = WifiTriggerSubsystemRestart;

    return WIFI_SUCCESS;
}

WifiError WifiInitialize(wifiHandle *handle)
{
    return WIFI_SUCCESS;
}

WifiError WifiWaitForDriverReady(void)
{
    return WIFI_SUCCESS;
}

void WifiCleanup(wifiHandle handle, WifiCleanedUpHandler handler)
{
    return;
}

void WifiEventLoop(wifiHandle handle)
{
    return;
}

WifiError WifiGetSupportedFeatureSet(wifiInterfaceHandle handle, feature_set *set)
{
    return WIFI_SUCCESS;
}

WifiError WifiGetIfaces(wifiHandle handle, int *num, wifiInterfaceHandle **interfaces)
{
    return WIFI_SUCCESS;
}

WifiError WifiGetIfaceName(wifiInterfaceHandle handle, char *name, size_t size)
{
    return WIFI_SUCCESS;
}

WifiError WifiSetNodfsFlag(wifiInterfaceHandle handle, u32 nodfs)
{
    return WIFI_SUCCESS;
}

WifiError WifiGetValidChannels(wifiInterfaceHandle handle,
    int band, int maxChannels, wifi_channel *channels, int *numChannels)
{
    return WIFI_SUCCESS;
}

WifiError WifiSetSubsystemRestartHandler(wifiHandle handle,
    WifiSubsystemRestartHandler handler)
{
    return WIFI_SUCCESS;
}
