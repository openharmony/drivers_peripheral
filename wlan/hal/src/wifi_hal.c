/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include <stdbool.h>
#include "securec.h"
#include "unistd.h"
#include "hdf_log.h"
#include "wifi_hal_cmd.h"
#include "wifi_hal_common.h"
#include "wifi_hal_util.h"
#include "wifi_driver_client.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

static bool g_wifiIsStarted = false;

static int32_t StartInner(const struct IWiFi *iwifi)
{
    int32_t ret;

    if (iwifi == NULL) {
        HDF_LOGE("%s: input parameter invalid, line: %d", __FUNCTION__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_wifiIsStarted) {
        HDF_LOGE("%s: wifi has started already, line: %d", __FUNCTION__, __LINE__);
        return HDF_FAILURE;
    }
    ret = WifiDriverClientInit();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: WifiDriverClientInit failed, line: %d, error no: %d", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    ret = HalCmdGetAvailableNetwork();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: HalCmdGetAvailableNetwork failed, line: %d, error no: %d", __FUNCTION__, __LINE__, ret);
        WifiDriverClientDeinit();
        return ret;
    }
    g_wifiIsStarted = true;
    return ret;
}

static int32_t StopInner(const struct IWiFi *iwifi)
{
    if (iwifi == NULL) {
        HDF_LOGE("%s: input parameter invalid, line: %d", __FUNCTION__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!g_wifiIsStarted) {
        HDF_LOGE("%s: wifi has stopped already, line: %d", __FUNCTION__, __LINE__);
        return HDF_FAILURE;
    }
    WifiDriverClientDeinit();
    ClearIWiFiList();
    g_wifiIsStarted = false;
    return HDF_SUCCESS;
}

static int32_t GetSupportFeatureInner(uint8_t *supType, uint32_t size)
{
    if (supType == NULL || size <= PROTOCOL_80211_IFTYPE_NUM) {
        HDF_LOGE("%s: input parameter invalid, line: %d", __FUNCTION__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    return HalCmdGetSupportType(supType);
}

static int32_t GetSupportComboInner(uint64_t *combo, uint32_t size)
{
    if (combo == NULL) {
        HDF_LOGE("%s: input parameter invalid, line: %d", __FUNCTION__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    return HalCmdGetSupportCombo(combo, size);
}

static int32_t InitFeatureByType(int32_t type, struct IWiFiBaseFeature **ifeature)
{
    int32_t ret;

    switch (type) {
        case PROTOCOL_80211_IFTYPE_AP:
            *ifeature = (struct IWiFiBaseFeature *)malloc(sizeof(struct IWiFiAp));
            if (*ifeature == NULL) {
                HDF_LOGE("%s: malloc failed, line: %d", __FUNCTION__, __LINE__);
                return HDF_FAILURE;
            }
            (void)memset_s(*ifeature, sizeof(struct IWiFiAp), 0, sizeof(struct IWiFiAp));
            ret = InitApFeature((struct IWiFiAp **)ifeature);
            break;
        case PROTOCOL_80211_IFTYPE_STATION:
            *ifeature = (struct IWiFiBaseFeature *)malloc(sizeof(struct IWiFiSta));
            if (*ifeature == NULL) {
                HDF_LOGE("%s: malloc failed, line: %d", __FUNCTION__, __LINE__);
                return HDF_FAILURE;
            }
            (void)memset_s(*ifeature, sizeof(struct IWiFiSta), 0, sizeof(struct IWiFiSta));
            ret = InitStaFeature((struct IWiFiSta **)ifeature);
            break;
        default:
            HDF_LOGE("%s: type not support, line: %d", __FUNCTION__, __LINE__);
            return HDF_FAILURE;
    }
    if (ret != HDF_SUCCESS) {
        free(*ifeature);
        *ifeature = NULL;
    }
    return ret;
}

static int32_t FindValidNetwork(int32_t type, struct IWiFiBaseFeature **feature)
{
    struct DListHead *networkHead = GetNetworkHead();
    struct IWiFiList *networkNode = NULL;

    DLIST_FOR_EACH_ENTRY(networkNode, networkHead, struct IWiFiList, entry) {
        if (networkNode->ifeature == NULL && networkNode->supportMode[type] == 1) {
            if (memcpy_s((*feature)->ifName, IFNAME_MAX_LEN, networkNode->ifName, strlen(networkNode->ifName)) != EOK) {
                HDF_LOGE("%s: memcpy_s failed, line: %d", __FUNCTION__, __LINE__);
                return HDF_FAILURE;
            }
            (*feature)->type = type;
            networkNode->ifeature = *feature;
            return HDF_SUCCESS;
        }
    }
    HDF_LOGE("%s: cannot find available network, line: %d", __FUNCTION__, __LINE__);
    return HDF_FAILURE;
}

static int32_t CreateFeatureInner(int32_t type, struct IWiFiBaseFeature **ifeature)
{
    int32_t ret;

    if (ifeature == NULL) {
        HDF_LOGE("%s: ifeature is null, line: %d", __FUNCTION__, __LINE__);
        return HDF_FAILURE;
    }
    ret = InitFeatureByType(type, ifeature);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: init feature failed, line: %d, error no: %d", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    ret = FindValidNetwork(type, ifeature);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: create feature failed, line: %d, error no: %d", __FUNCTION__, __LINE__, ret);
        if (*ifeature != NULL) {
            free(*ifeature);
            *ifeature = NULL;
        }
        return ret;
    }
    return HDF_SUCCESS;
}

static int32_t GetFeatureByIfNameInner(const char *ifName, struct IWiFiBaseFeature **ifeature)
{
    struct DListHead *networkHead = GetNetworkHead();
    struct IWiFiList *networkNode = NULL;

    if (ifName == NULL) {
        HDF_LOGE("%s: input parameter invalid, line: %d", __FUNCTION__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    DLIST_FOR_EACH_ENTRY(networkNode, networkHead, struct IWiFiList, entry) {
        if (strcmp(networkNode->ifName, ifName) == HDF_SUCCESS) {
            *ifeature = networkNode->ifeature;
            return HDF_SUCCESS;
        }
    }
    HDF_LOGE("%s: cannot find feature by ifName, line: %d", __FUNCTION__, __LINE__);
    return HDF_FAILURE;
}

static int32_t DestroyFeatureInner(struct IWiFiBaseFeature *ifeature)
{
    struct DListHead *networkHead = GetNetworkHead();
    struct IWiFiList *networkNode = NULL;

    if (ifeature == NULL) {
        HDF_LOGE("%s: input parameter invalid, line: %d", __FUNCTION__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    DLIST_FOR_EACH_ENTRY(networkNode, networkHead, struct IWiFiList, entry) {
        if (strcmp(networkNode->ifName, ifeature->ifName) == HDF_SUCCESS) {
            free(ifeature);
            networkNode->ifeature = NULL;
            return HDF_SUCCESS;
        }
    }
    HDF_LOGE("%s: cannot find feature to destroy, line: %d", __FUNCTION__, __LINE__);
    return HDF_FAILURE;
}

static int32_t RegisterEventCallbackInner(OnReceiveFunc onRecFunc, const char *ifName)
{
    if (onRecFunc == NULL || ifName == NULL) {
        HDF_LOGE("%s: input parameter invalid, line: %d", __FUNCTION__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (WifiRegisterEventCallback(onRecFunc, WIFI_KERNEL_TO_HAL_CLIENT, ifName) != HDF_SUCCESS) {
        HDF_LOGE("%s: callback function has been registered, line: %d", __FUNCTION__, __LINE__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t UnregisterEventCallbackInner(OnReceiveFunc onRecFunc, const char *ifName)
{
    if (onRecFunc == NULL || ifName == NULL) {
        HDF_LOGE("%s: input parameter invalid, line: %d", __FUNCTION__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    WifiUnregisterEventCallback(onRecFunc, WIFI_KERNEL_TO_HAL_CLIENT, ifName);
    return HDF_SUCCESS;
}

static int32_t RegisterHid2dCallbackInner(Hid2dCallback func, const char *ifName)
{
    int32_t ret;
    if (func == NULL || ifName == NULL) {
        HDF_LOGE("%s: input parameter invalid, line: %d", __FUNCTION__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = WifiRegisterHid2dCallback(func, ifName);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: register hid2d callback fail!", __FUNCTION__);
    }
    return ret;
}

static int32_t UnregisterHid2dCallbackInner(Hid2dCallback func, const char *ifName)
{
    if (func == NULL || ifName == NULL) {
        HDF_LOGE("%s: input parameter invalid, line: %d", __FUNCTION__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    WifiUnregisterHid2dCallback(func, ifName);
    return HDF_SUCCESS;
}

static int32_t ResetDriverInner(uint8_t chipId, const char *ifName)
{
    if (ifName == NULL || chipId >= MAX_WLAN_DEVICE) {
        HDF_LOGE("%s: input parameter invalid, line: %d, chipId = %d", __FUNCTION__, __LINE__, chipId);
        return HDF_ERR_INVALID_PARAM;
    }
    return HalCmdSetResetDriver(chipId, ifName);
}

static int32_t GetNetDevInfoInner(struct NetDeviceInfoResult *netDeviceInfoResult)
{
    if (netDeviceInfoResult == NULL) {
        HDF_LOGE("%s: input parameter invalid, line: %d", __FUNCTION__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    return GetNetDeviceInfo(netDeviceInfoResult);
}

static int32_t GetPowerModeInner(const char *ifName, uint8_t *mode)
{
    if (ifName == NULL || mode == NULL) {
        HDF_LOGE("%s: input parameter invalid, line: %d", __FUNCTION__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }

    return GetCurrentPowerMode(ifName, mode);
}

static int32_t SetPowerModeInner(const char *ifName, uint8_t mode)
{
    if (ifName == NULL || mode >= WIFI_POWER_MODE_NUM) {
        HDF_LOGE("%s: input parameter invalid, line: %d", __FUNCTION__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    return SetPowerMode(ifName, mode);
}

static int32_t StartChannelMeasInner(const char *ifName, const struct MeasParam *measParam)
{
    if (ifName == NULL || measParam == NULL) {
        HDF_LOGE("%s: input parameter invalid, line: %d", __FUNCTION__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    return StartChannelMeas(ifName, measParam);
}

static int32_t GetChannelMeasResultInner(const char *ifName, struct MeasResult *measResult)
{
    if (ifName == NULL || measResult == NULL) {
        HDF_LOGE("%s: input parameter invalid, line: %d", __FUNCTION__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    return HDF_ERR_NOT_SUPPORT;
}

static int32_t SetProjectionScreenParamInner(const char *ifName, const ProjScrnCmdParam *param)
{
    if (ifName == NULL || param == NULL) {
        HDF_LOGE("%s: input parameter invalid, line: %d", __FUNCTION__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    return SetProjectionScreenParam(ifName, param);
}

static int32_t SendCmdIoctlInner(const char *ifName, int32_t cmdId, const int8_t *paramBuf, uint32_t paramBufLen)
{
    if (ifName == NULL || paramBuf == NULL) {
        HDF_LOGE("%s: input parameter invalid, line: %d", __FUNCTION__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    return SendCmdIoctl(ifName, cmdId, paramBuf, paramBufLen);
}

static int32_t GetStationInfoInner(const char *ifName, StationInfo *info, const uint8_t *mac, uint32_t macLen)
{
    if (ifName == NULL || info == NULL || mac == NULL || macLen < ETH_ADDR_LEN) {
        HDF_LOGE("%s: input parameter invalid, line: %d", __FUNCTION__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    return GetStationInfo(ifName, info, mac, macLen);
}

static int32_t Start(struct IWiFi *iwifi)
{
    HalMutexLock();
    int32_t ret = StartInner(iwifi);
    HalMutexUnlock();
    return ret;
}

static int32_t Stop(struct IWiFi *iwifi)
{
    HalMutexLock();
    int32_t ret = StopInner(iwifi);
    HalMutexUnlock();
    return ret;
}

static int32_t GetSupportFeature(uint8_t *supType, uint32_t size)
{
    HalMutexLock();
    int32_t ret = GetSupportFeatureInner(supType, size);
    HalMutexUnlock();
    return ret;
}

static int32_t GetSupportCombo(uint64_t *combo, uint32_t size)
{
    HalMutexLock();
    int32_t ret = GetSupportComboInner(combo, size);
    HalMutexUnlock();
    return ret;
}

static int32_t CreateFeature(int32_t type, struct IWiFiBaseFeature **ifeature)
{
    HalMutexLock();
    int32_t ret = CreateFeatureInner(type, ifeature);
    HalMutexUnlock();
    return ret;
}

static int32_t GetFeatureByIfName(const char *ifName, struct IWiFiBaseFeature **ifeature)
{
    HalMutexLock();
    int32_t ret = GetFeatureByIfNameInner(ifName, ifeature);
    HalMutexUnlock();
    return ret;
}

static int32_t DestroyFeature(struct IWiFiBaseFeature *ifeature)
{
    HalMutexLock();
    int32_t ret = DestroyFeatureInner(ifeature);
    HalMutexUnlock();
    return ret;
}

static int32_t HalRegisterEventCallback(OnReceiveFunc onRecFunc, const char *ifName)
{
    HalMutexLock();
    int32_t ret = RegisterEventCallbackInner(onRecFunc, ifName);
    HalMutexUnlock();
    return ret;
}

static int32_t HalUnregisterEventCallback(OnReceiveFunc onRecFunc, const char *ifName)
{
    HalMutexLock();
    int32_t ret = UnregisterEventCallbackInner(onRecFunc, ifName);
    HalMutexUnlock();
    return ret;
}

static int32_t HalRegisterHid2dCallback(Hid2dCallback func, const char *ifName)
{
    HalMutexLock();
    int32_t ret = RegisterHid2dCallbackInner(func, ifName);
    HalMutexUnlock();
    return ret;
}

static int32_t HalUnregisterHid2dCallback(Hid2dCallback func, const char *ifName)
{
    HalMutexLock();
    int32_t ret = UnregisterHid2dCallbackInner(func, ifName);
    HalMutexUnlock();
    return ret;
}

static int32_t ResetDriver(const uint8_t chipId, const char *ifName)
{
    HalMutexLock();
    int32_t ret = ResetDriverInner(chipId, ifName);
    HalMutexUnlock();
    return ret;
}

static int32_t GetNetDevInfo(struct NetDeviceInfoResult *netDeviceInfoResult)
{
    HalMutexLock();
    int32_t ret = GetNetDevInfoInner(netDeviceInfoResult);
    HalMutexUnlock();
    return ret;
}

static int32_t WifiGetPowerMode(const char *ifName, uint8_t *mode)
{
    HalMutexLock();
    int32_t ret = GetPowerModeInner(ifName, mode);
    HalMutexUnlock();
    return ret;
}

static int32_t WifiSetPowerMode(const char *ifName, uint8_t mode)
{
    HalMutexLock();
    int32_t ret = SetPowerModeInner(ifName, mode);
    HalMutexUnlock();
    return ret;
}

static int32_t WifiStartChannelMeas(const char *ifName, const struct MeasParam *measParam)
{
    HalMutexLock();
    int32_t ret = StartChannelMeasInner(ifName, measParam);
    HalMutexUnlock();
    return ret;
}

static int32_t WifiGetChannelMeasResult(const char *ifName, struct MeasResult *measResult)
{
    HalMutexLock();
    int32_t ret = GetChannelMeasResultInner(ifName, measResult);
    HalMutexUnlock();
    return ret;
}

static int32_t WifiSetProjectionScreenParam(const char *ifName, const ProjScrnCmdParam *param)
{
    HalMutexLock();
    int32_t ret = SetProjectionScreenParamInner(ifName, param);
    HalMutexUnlock();
    return ret;
}

static int32_t WifiSendCmdIoctl(const char *ifName, int32_t cmdId, const int8_t *paramBuf, uint32_t paramBufLen)
{
    HalMutexLock();
    int32_t ret = SendCmdIoctlInner(ifName, cmdId, paramBuf, paramBufLen);
    HalMutexUnlock();
    return ret;
}

static int32_t WifiGetStationInfo(const char *ifName, StationInfo *info, const uint8_t *mac, uint32_t macLen)
{
    HalMutexLock();
    int32_t ret = GetStationInfoInner(ifName, info, mac, macLen);
    HalMutexUnlock();
    return ret;
}

int32_t WifiConstruct(struct IWiFi **wifiInstance)
{
    static bool isInited = false;
    static struct IWiFi singleWifiInstance;

    if (!isInited) {
        if (HalMutexInit() != HDF_SUCCESS) {
            HDF_LOGE("%s: HalMutexInit failed, line: %d", __FUNCTION__, __LINE__);
            return HDF_FAILURE;
        }

        singleWifiInstance.start = Start;
        singleWifiInstance.stop = Stop;
        singleWifiInstance.getSupportFeature = GetSupportFeature;
        singleWifiInstance.getSupportCombo = GetSupportCombo;
        singleWifiInstance.createFeature = CreateFeature;
        singleWifiInstance.getFeatureByIfName = GetFeatureByIfName;
        singleWifiInstance.destroyFeature = DestroyFeature;
        singleWifiInstance.registerEventCallback = HalRegisterEventCallback;
        singleWifiInstance.unregisterEventCallback = HalUnregisterEventCallback;
        singleWifiInstance.resetDriver = ResetDriver;
        singleWifiInstance.getNetDevInfo = GetNetDevInfo;
        singleWifiInstance.getPowerMode = WifiGetPowerMode;
        singleWifiInstance.setPowerMode = WifiSetPowerMode;
        singleWifiInstance.startChannelMeas = WifiStartChannelMeas;
        singleWifiInstance.getChannelMeasResult = WifiGetChannelMeasResult;
        singleWifiInstance.setProjectionScreenParam = WifiSetProjectionScreenParam;
        singleWifiInstance.sendCmdIoctl = WifiSendCmdIoctl;
        singleWifiInstance.registerHid2dCallback = HalRegisterHid2dCallback;
        singleWifiInstance.unregisterHid2dCallback = HalUnregisterHid2dCallback;
        singleWifiInstance.getStationInfo = WifiGetStationInfo;
        InitIWiFiList();
        isInited = true;
    }
    (*wifiInstance) = &singleWifiInstance;
    return HDF_SUCCESS;
}

int32_t WifiDestruct(struct IWiFi **wifiInstance)
{
    if (wifiInstance == NULL) {
        HDF_LOGE("%s: input parameter invalid, line: %d", __FUNCTION__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    *wifiInstance = NULL;
    if (HalMutexDestroy() != HDF_SUCCESS) {
        HDF_LOGE("%s: HalMutexDestroy failed, line: %d", __FUNCTION__, __LINE__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
