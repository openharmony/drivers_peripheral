/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "wifi_hal_fn.h"

const std::string VAILD_IFNAME = "wlan0";
const std::string INVAILD_IFNAME = "wlan2";
const int NAME_LEN = 5;

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
    HDF_LOGI("VendorHalExit enter");
}

void StartHalLoop(wifiHandle handle)
{
    HDF_LOGI("StartHalLoop enter");
}

WifiError VendorHalGetIfaces(wifiHandle handle, int *num, wifiInterfaceHandle **interfaces)
{
    return HAL_SUCCESS;
}

WifiError VendorHalGetIfName(wifiInterfaceHandle handle, char *name, size_t size)
{
    return HAL_SUCCESS;
}

WifiError VendorHalGetChannelsInBand(wifiInterfaceHandle handle, int band,
    std::vector<uint32_t>& freqs)
{
    if (band == 0) {
        return HAL_SUCCESS;
    }
    return HAL_UNKNOWN;
}

WifiError VendorHalSetRestartHandler(wifiHandle handle, VendorHalRestartHandler handler)
{
    return HAL_SUCCESS;
}

WifiError VendorHalCreateIface(wifiHandle handle, const char* ifname, HalIfaceType ifaceType)
{
    return HAL_SUCCESS;
}

WifiError VendorHalDeleteIface(wifiHandle handle, const char* ifname)
{
    if (strncmp(ifname, VAILD_IFNAME.c_str(), NAME_LEN) == 0) {
        return HAL_SUCCESS;
    }
    return HAL_NOT_SUPPORTED;
}

WifiError TriggerVendorHalRestart(wifiHandle handle)
{
    return HAL_SUCCESS;
}

static WifiError WifiSetCountryCode(wifiInterfaceHandle handle, const char *countryCode)
{
    return HAL_SUCCESS;
}

WifiError GetPowerMode(const char *ifName, int *mode)
{
    return HAL_SUCCESS;
}

WifiError SetPowerMode(const char *ifName, int mode)
{
    return HAL_SUCCESS;
}

WifiError EnablePowerMode(const char *ifName, int mode)
{
    return HAL_SUCCESS;
}

static WifiError WifiGetSignalInfo(wifiInterfaceHandle handle,
    OHOS::HDI::Wlan::Chip::V1_0::SignalPollResult& signalPollresult)
{
    return HAL_SUCCESS;
}

WifiError WifiSetDpiMarkRule(int32_t uid, int32_t protocol, int32_t enable)
{
    if (uid == 0) {
        return HAL_SUCCESS;
    }
    return HAL_INVALID_ARGS;
}

WifiError WifiStartScan(wifiInterfaceHandle handle,
    const OHOS::HDI::Wlan::Chip::V1_0::ScanParams& scanParam)
{
    if (scanParam.fastConnectFlag == 0) {
        return HAL_SUCCESS;
    }
    return HAL_INVALID_ARGS;
}

static WifiError RegisterIfaceCallBack(const char *ifaceName, WifiCallbackHandler onCallbackEvent)
{
    if (ifaceName == nullptr) {
        HDF_LOGE("ifaceName is null");
        return HAL_NONE;
    }
    return HAL_SUCCESS;
}

WifiError WifiGetScanInfo(wifiInterfaceHandle handle,
    std::vector<OHOS::HDI::Wlan::Chip::V1_0::ScanResultsInfo>& res)
{
    return HAL_SUCCESS;
}

WifiError WifiStartPnoScan(wifiInterfaceHandle handle,
    const OHOS::HDI::Wlan::Chip::V1_0::PnoScanParams& pnoScanParam)
{
    if (pnoScanParam.min2gRssi == 0) {
        return HAL_SUCCESS;
    }
    return HAL_INVALID_ARGS;
}

WifiError WifiStopPnoScan(wifiInterfaceHandle handle)
{
    return HAL_SUCCESS;
}

uint32_t WifiGetSupportedFeatureSet(const char *ifName)
{
    if (ifName == nullptr) {
        return 0;
    }
    if (strncmp(ifName, VAILD_IFNAME.c_str(), NAME_LEN) == 0) {
        return 1;
    }
    return 0;
}

uint32_t GetChipCaps(const char *ifName)
{
    if (ifName == nullptr) {
        return 0;
    }
    if (strncmp(ifName, VAILD_IFNAME.c_str(), NAME_LEN) == 0) {
        return 1;
    }
    return 0;
}

WifiError SetTxPower(const char *ifName, int mode)
{
    if (mode == 0) {
        return HAL_SUCCESS;
    }
    return HAL_INVALID_ARGS;
}

WifiError InitWifiHalFuncTable(WifiHalFn *fn)
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
    fn->wifiSetCountryCode = WifiSetCountryCode;
    fn->getPowerMode = GetPowerMode;
    fn->setPowerMode = SetPowerMode;
    fn->enablePowerMode = EnablePowerMode;
    fn->getSignalPollInfo = WifiGetSignalInfo;
    fn->setDpiMarkRule = WifiSetDpiMarkRule;
    fn->wifiStartScan = WifiStartScan;
    fn->registerIfaceCallBack = RegisterIfaceCallBack;
    fn->getScanResults = WifiGetScanInfo;
    fn->wifiStartPnoScan = WifiStartPnoScan;
    fn->wifiStopPnoScan = WifiStopPnoScan;
    fn->wifiGetSupportedFeatureSet = WifiGetSupportedFeatureSet;
    fn->getChipCaps = GetChipCaps;
    fn->setTxPower = SetTxPower;
    return HAL_SUCCESS;
}