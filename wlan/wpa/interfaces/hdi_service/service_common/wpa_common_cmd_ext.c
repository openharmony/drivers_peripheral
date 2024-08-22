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
#include "wpa_common_cmd.h"
#include "wpa_p2p_cmd.h"
#include "hdi_wpa_hal.h"
#include <securec.h>
#include <hdf_base.h>
#include <hdf_log.h>
#include <osal_time.h>
#include <osal_mem.h>
#include <arpa/inet.h>
#include "utils/common.h"
#include "wpa_supplicant_i.h"
#include "ctrl_iface.h"
#include "main.h"
#include "wps_supplicant.h"
#include "bssid_ignore.h"
#include "wpa_supplicant/config.h"
#include "common/defs.h"
#include "v1_1/iwpa_callback.h"
#include "v1_1/iwpa_interface.h"
#include "wpa_client.h"
#include <unistd.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include "hdi_wpa_common.h"

extern pthread_mutex_t g_interfaceLock;

pthread_mutex_t *GetInterfaceLock()
{
    return &g_interfaceLock;
}

int32_t FillData(uint8_t **dst, uint32_t *dstLen, uint8_t *src, uint32_t srcLen)
{
    if (src == NULL || dst == NULL || dstLen == NULL) {
        HDF_LOGE("%{public}s: Invalid parameter!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGD("%{public}s: srcLen =%{public}d ", __func__, srcLen);
    if (srcLen > 0) {
        *dst = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * srcLen);
        if (*dst == NULL) {
            HDF_LOGE("%{public}s: OsalMemCalloc fail!", __func__);
            return HDF_FAILURE;
        }
        if (memcpy_s(*dst, srcLen, src, srcLen) != EOK) {
            HDF_LOGE("%{public}s: memcpy_s fail!", __func__);
            return HDF_FAILURE;
        }
    }
    *dstLen = srcLen;
    return HDF_SUCCESS;
}

struct HdfWpaStubData *HdfWpaStubDriver(void)
{
    static struct HdfWpaStubData registerManager;
    return &registerManager;
}

int32_t WpaInterfaceScan(struct IWpaInterface *self, const char *ifName)
{
    (void)self;
    HDF_LOGI("enter %{public}s", __func__);
    pthread_mutex_lock(&g_interfaceLock);
    if (ifName == NULL) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    ScanSettings settings = {0};
    settings.scanStyle = SCAN_TYPE_LOW_SPAN;
    int ret = pStaIfc->wpaCliCmdScan(pStaIfc, &settings);
    if (ret < 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: StartScan fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    if (ret == WIFI_HAL_SCAN_BUSY) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: StartScan return scan busy", __func__);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: StartScan successfully!", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceScanResult(struct IWpaInterface *self, const char *ifName, unsigned char *resultBuf,
     uint32_t *resultBufLen)
{
    HDF_LOGI("enter %{public}s", __func__);
    (void)self;
    if (ifName == NULL || resultBuf == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(&g_interfaceLock);
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdScanInfo(pStaIfc, resultBuf, resultBufLen);
    if (ret < 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: WpaCliCmdScanInfo2 fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: Get scan result successfully!", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceAddNetwork(struct IWpaInterface *self, const char *ifName, int32_t *networkId)
{
    (void)self;
    HDF_LOGI("enter %{public}s", __func__);
    if (ifName == NULL || networkId == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(&g_interfaceLock);
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdAddNetworks(pStaIfc);
    if (ret < 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: WpaInterfaceAddNetwork fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    *networkId = ret;
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: add network success networkId = %{public}d", __func__, *networkId);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceRemoveNetwork(struct IWpaInterface *self, const char *ifName, int32_t networkId)
{
    (void)self;
    HDF_LOGI("enter %{public}s networkId = %{public}d", __func__, networkId);
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(&g_interfaceLock);
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdRemoveNetwork(pStaIfc, networkId);
    if (ret < 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: WpaInterfaceRemoveNetwork fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: remove network success ret = %{public}d", __func__, ret);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceDisableNetwork(struct IWpaInterface *self, const char *ifName, const int32_t networkId)
{
    (void)self;
    HDF_LOGI("enter %{public}s networkId = %{public}d", __func__, networkId);
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(&g_interfaceLock);
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdDisableNetwork(pStaIfc, networkId);
    if (ret < 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: WpaInterfaceDisableNetwork fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: WpaInterfaceDisableNetwork success ret = %{public}d", __func__, ret);
    return HDF_SUCCESS;
}

int32_t WpaFillWpaListNetworkParam(struct WifiNetworkInfo  *wifiWpaNetworkInfo,
    struct HdiWifiWpaNetworkInfo *hdiWifiWpaNetworkInfo)
{
    int32_t ret = HDF_SUCCESS;

    if (wifiWpaNetworkInfo == NULL || hdiWifiWpaNetworkInfo == NULL) {
        HDF_LOGE("%{public}s: wifiWpaNetworkInfo or hdiWifiWpaNetworkInfo is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    do {
        uint8_t tmpBssid[ETH_ADDR_LEN] = {0};
        hwaddr_aton(wifiWpaNetworkInfo->bssid, tmpBssid);
        if (FillData(&hdiWifiWpaNetworkInfo->bssid, &hdiWifiWpaNetworkInfo->bssidLen,
            tmpBssid, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiWifiWpaNetworkInfo->ssid, &hdiWifiWpaNetworkInfo->ssidLen,
            (uint8_t *)wifiWpaNetworkInfo->ssid, strlen(wifiWpaNetworkInfo->ssid)) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill ssid fail!", __func__);
            ret = HDF_FAILURE;
        }
        if (FillData(&hdiWifiWpaNetworkInfo->flags, &hdiWifiWpaNetworkInfo->flagsLen,
            (uint8_t *)wifiWpaNetworkInfo->flags, strlen(wifiWpaNetworkInfo->flags)) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill flags fail!", __func__);
            ret = HDF_FAILURE;
        }
    } while (0);
    if (ret != HDF_SUCCESS) {
        if (hdiWifiWpaNetworkInfo->bssid != NULL) {
            OsalMemFree(hdiWifiWpaNetworkInfo->bssid);
            hdiWifiWpaNetworkInfo->bssid = NULL;
        }
        if (hdiWifiWpaNetworkInfo->ssid != NULL) {
            OsalMemFree(hdiWifiWpaNetworkInfo->ssid);
            hdiWifiWpaNetworkInfo->ssid = NULL;
        }
        if (hdiWifiWpaNetworkInfo->flags != NULL) {
            OsalMemFree(hdiWifiWpaNetworkInfo->flags);
            hdiWifiWpaNetworkInfo->flags = NULL;
        }
    }
    return ret;
}