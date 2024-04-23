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

WifiError VendorHalCreateIface(wifiHandle handle, const char* ifname,
    HalIfaceType ifaceType)
{
    return HAL_SUCCESS;
}

WifiError VendorHalDeleteIface(wifiHandle handle, const char* ifname)
{
    return HAL_SUCCESS;
}

WifiError TriggerVendorHalRestart(wifiHandle handle)
{
    return HAL_SUCCESS;
}

WifiError VendorHalGetChannelsInBand(wifiInterfaceHandle handle,
    int band, int maxChannels, int *channels, int *numChannels)
{
    return HAL_SUCCESS;
}

WifiError InitWifiVendorHalFuncTable(WifiHalFn *fn)
{
    if (fn == nullptr) {
        return HAL_UNKNOWN;
    }
    fn->vendorHalInit = VendorHalInit;
    fn->waitDriverStart = WaitDriverStart;
    fn->vendorHalExit = VendorHalExit;
    fn->startHalLoop = StartHalLoop;
    fn->vendorHalGetIfaces = VendorHalGetIfaces;
    fn->vendorHalGetIfName = VendorHalGetIfName;
    fn->vendorHalGetChannelsInBand = VendorHalGetChannelsInBand;
    fn->vendorHalSetRestartHandler = VendorHalSetRestartHandler;
    fn->vendorHalCreateIface = VendorHalCreateIface;
    fn->vendorHalDeleteIface = VendorHalDeleteIface;
    fn->triggerVendorHalRestart = TriggerVendorHalRestart;

    return HAL_SUCCESS;
}

WifiError VendorHalInit(wifiHandle *handle)
{
    return HAL_SUCCESS;
}

WifiError WaitDriverStart(void)
{
    return HAL_SUCCESS;
}

void VendorHalExit(wifiHandle handle, VendorHalExitHandler handler)
{
    return;
}

void StartHalLoop(wifiHandle handle)
{
    return;
}

WifiError VendorHalGetIfaces(wifiHandle handle, int *num, wifiInterfaceHandle **interfaces)
{
    return HAL_SUCCESS;
}

WifiError VendorHalGetIfName(wifiInterfaceHandle handle, char *name, size_t size)
{
    return HAL_SUCCESS;
}

WifiError VendorHalSetRestartHandler(wifiHandle handle,
    VendorHalRestartHandler handler)
{
    return HAL_SUCCESS;
}
