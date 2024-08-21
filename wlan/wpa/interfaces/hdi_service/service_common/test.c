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

#define BUF_SIZE 512

pthread_t g_tid;
const int QUOTATION_MARKS_FLAG_YES = 0;
const int QUOTATION_MARKS_FLAG_NO = 1;
const int MAX_NETWORKS_NUM = 100;
pthread_mutex_t g_interfaceLock = PTHREAD_MUTEX_INITIALIZER;

static WpaSsidField g_wpaSsidFields[] = {
    {DEVICE_CONFIG_SSID, "ssid", QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_PSK, "psk", QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_KEYMGMT, "key_mgmt", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_PRIORITY, "priority", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_SCAN_SSID, "scan_ssid", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_EAP, "eap", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_IDENTITY, "identity", QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_PASSWORD, "password", QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_BSSID, "bssid", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_AUTH_ALGORITHMS, "auth_alg", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_WEP_KEY_IDX, "wep_tx_keyidx", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_WEP_KEY_0, "wep_key0", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_WEP_KEY_1, "wep_key1", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_WEP_KEY_2, "wep_key2", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_WEP_KEY_3, "wep_key3", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_EAP_CLIENT_CERT, "client_cert", QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_EAP_PRIVATE_KEY, "private_key", QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_EAP_PHASE2METHOD, "phase2", QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_IEEE80211W, "ieee80211w", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_ALLOW_PROTOCOLS, "proto", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_GROUP_CIPHERS, "group", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_PAIRWISE_CIPHERS, "pairwise", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_SAE_PASSWD, "sae_password", QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_WAPI_CA_CERT, "wapi_ca_cert", QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_WAPI_USER_CERT, "wapi_user_sel_cert", QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_WAPI_PSK_KEY_TYPE, "psk_key_type", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_WAPI_PSK, "wapi_psk", QUOTATION_MARKS_FLAG_YES},
};

int CalcQuotationMarksFlag(int pos, const char value[WIFI_NETWORK_CONFIG_VALUE_LENGTH])
{
    int flag = g_wpaSsidFields[pos].flag;
    const int hexPskMaxLen = 64;
    int len = strlen(value);
    /* if the psk length is 64, it's hex format and don't need quotation marks */
    if (pos == DEVICE_CONFIG_PSK && len >= hexPskMaxLen) {
        flag = QUOTATION_MARKS_FLAG_NO;
    }
    if (pos == DEVICE_CONFIG_WEP_KEY_0 ||
        pos == DEVICE_CONFIG_WEP_KEY_1 ||
        pos == DEVICE_CONFIG_WEP_KEY_2 ||
        pos == DEVICE_CONFIG_WEP_KEY_3) {
        const int wepKeyLen1 = 5;
        const int wepKeyLen2 = 13;
        const int wepKeyLen3 = 16;
        /* For wep key, ASCII format need quotation marks, hex format is not required */
        if (len == wepKeyLen1 || len == wepKeyLen2 || len == wepKeyLen3) {
            flag = QUOTATION_MARKS_FLAG_YES;
        }
    }
    return flag;
}

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

int32_t WpaInterfaceSetNetwork(struct IWpaInterface *self, const char *ifName,
    const int32_t networkId, const char *name, const char *value)
{
    (void)self;
    if (ifName == NULL || name == NULL || value == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGI("enter %{public}s networkId = %{public}d name = %{private}s value = %{private}s", __func__, networkId,
        name, value);
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    struct WpaSetNetworkArgv conf = {0};
    conf.id = networkId;
    int pos = -1;
    for (int i = 0; i < (int)(sizeof(g_wpaSsidFields) / sizeof(g_wpaSsidFields[0])); ++i) {
        if (strcmp(g_wpaSsidFields[i].fieldName, name) == 0) {
            pos = i;
            conf.param = g_wpaSsidFields[i].field;
            break;
        }
    }
    if (pos < 0) {
        HDF_LOGE("%{public}s SetNetwork: unsupported name  %{public}s", __func__, name);
        return HDF_FAILURE;
    }
    if (strncpy_s(conf.value, sizeof(conf.value), value, strlen(value)) != 0) {
        HDF_LOGE("%{public}s strncpy_s conf.value fail", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdSetNetwork(pStaIfc, &conf);
    if (ret < 0) {
        HDF_LOGE("%{public}s: wpaCliCmdSetNetwork fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s: wpaCliCmdSetNetwork sucess ret = %{public}d", __func__, ret);
    return HDF_SUCCESS;
}

static int32_t WpaFillWpaListNetworkParam(struct WifiNetworkInfo  *wifiWpaNetworkInfo,
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

//need to check
int32_t WpaInterfaceListNetworks(struct IWpaInterface *self, const char *ifName,
    struct HdiWifiWpaNetworkInfo *networkInfo, uint32_t *networkInfoLen)
{
    (void)self;
    HDF_LOGI("enter %{public}s ", __func__);
    if (ifName == NULL || networkInfo == NULL || networkInfoLen == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(&g_interfaceLock);
    int size = MAX_NETWORKS_NUM;
    WifiNetworkInfo *infos = (WifiNetworkInfo *)calloc(size, sizeof(WifiNetworkInfo));
    if (infos == NULL) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: info = NULL", __func__);
        return HDF_FAILURE;
    }
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        free(infos);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdListNetworks(pStaIfc, infos, &size);
    if (ret < 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: wpaCliCmdListNetworks fail! ret = %{public}d", __func__, ret);
        free(infos);
        return HDF_FAILURE;
    }
    WifiNetworkInfo *infosTmp = infos;
    HDF_LOGI("%{public}s: wpaCliCmdListNetworks success size = %{public}d", __func__, size);
    for (int i = 0; i < ((size > MAX_NETWORKS_NUM) ? MAX_NETWORKS_NUM : size); i++) {
        WpaFillWpaListNetworkParam(infos, networkInfo);
        infos++;
        networkInfo++;
    }
    *networkInfoLen = size;
    free(infosTmp);
    pthread_mutex_unlock(&g_interfaceLock);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceSelectNetwork(struct IWpaInterface *self, const char *ifName,
    const int32_t networkId)
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
    int ret = pStaIfc->wpaCliCmdSelectNetwork(pStaIfc, networkId);
    if (ret < 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: wpaCliCmdSelectNetwork fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: wpaCliCmdSelectNetwork success ret = %{public}d", __func__, ret);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceEnableNetwork(struct IWpaInterface *self, const char *ifName, const int32_t networkId)
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
    int ret = pStaIfc->wpaCliCmdEnableNetwork(pStaIfc, networkId);
    if (ret < 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: wpaCliCmdEnableNetwork fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: wpaCliCmdEnableNetwork success ret = %{public}d", __func__, ret);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceReconnect(struct IWpaInterface *self, const char *ifName)
{
    (void)self;
    HDF_LOGI("enter %{public}s ", __func__);
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
    int ret = pStaIfc->wpaCliCmdReconnect(pStaIfc);
    if (ret < 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: wpaCliCmdReconnect fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: wpaCliCmdReconnect success ret = %{public}d", __func__, ret);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceDisconnect(struct IWpaInterface *self, const char *ifName)
{
    (void)self;
    HDF_LOGI("enter %{public}s ", __func__);
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
    int ret = pStaIfc->wpaCliCmdDisconnect(pStaIfc);
    if (ret < 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: wpaCliCmdDisconnect fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: wpaCliCmdDisconnect success ret = %{public}d", __func__, ret);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceSetPowerSave(struct IWpaInterface *self, const char *ifName, const int32_t enable)
{
    (void)self;
    HDF_LOGI("enter %{public}s enable = %{public}d", __func__, enable);
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
    int ret = pStaIfc->wpaCliCmdPowerSave(pStaIfc, enable);
    if (ret < 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: wpaCliCmdPowerSave fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: wpaCliCmdPowerSave success ret = %{public}d", __func__, ret);
    return HDF_SUCCESS;
}

int32_t  WpaInterfaceAutoConnect(struct IWpaInterface *self, const char *ifName, const int32_t enable)
{
    (void)self;
    HDF_LOGI("enter %{public}s enable = %{public}d", __func__, enable);
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
    int ret = pStaIfc->wpaCliCmdSetAutoConnect(pStaIfc, enable);
    if (ret < 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: wpaCliCmdSetAutoConnect fail! ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: wpaCliCmdSetAutoConnect success ret = %{public}d", __func__, ret);
    return HDF_SUCCESS;
}

static void WpaProcessWifiStatus(struct WpaHalCmdStatus *halStatus, struct HdiWpaCmdStatus *status)
{
    if (halStatus == NULL) {
        HDF_LOGE("%{public}s halStatus is NULL", __func__);
        return;
    }
    status->id = halStatus->id;
    status->freq = halStatus->freq;
    if (strcmp(halStatus->keyMgmt, "") != 0) {
        HDF_LOGI("%{public}s key include key_mgmt value=%{private}s", __func__, halStatus->keyMgmt);
        status->keyMgmt = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (strlen(halStatus->keyMgmt) + 1));
        if (status->keyMgmt == NULL) {
            HDF_LOGE("%{public}s status->keyMgmt is NULL", __func__);
            status->keyMgmtLen = 0;
            return;
        }
        status->keyMgmtLen = strlen(halStatus->keyMgmt);
        if (strcpy_s((char *)status->keyMgmt, strlen(halStatus->keyMgmt) + 1, halStatus->keyMgmt) != EOK) {
            HDF_LOGE("%{public}s strcpy failed", __func__);
        }
    }
    if (strcmp(halStatus->ssid, "") != 0) {
        HDF_LOGI("%{public}s key include ssid value=%{private}s", __func__, halStatus->ssid);
        status->ssid = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (strlen(halStatus->ssid) + 1));
        if (status->ssid == NULL) {
            HDF_LOGE("%{public}s status->ssid is NULL", __func__);
            status->ssidLen = 0;
            return;
        }
        status->ssidLen = strlen(halStatus->ssid);
        if (strcpy_s((char *)status->ssid, strlen(halStatus->ssid) + 1, halStatus->ssid) != EOK) {
            HDF_LOGE("%{public}s strcpy failed", __func__);
        }
    }
    if (strcmp(halStatus->address, "") != 0) {
        HDF_LOGI("%{public}s key include address value=%{private}s", __func__, halStatus->address);
        uint8_t tmpAddress[ETH_ADDR_LEN + 1] = {0};
        hwaddr_aton(halStatus->address, tmpAddress);
        status->address = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (ETH_ADDR_LEN + 1));
        if (status->address == NULL) {
            HDF_LOGE("%{public}s status->address is NULL", __func__);
            status->addressLen = 0;
            return;
        }
        status->addressLen = ETH_ADDR_LEN + 1 ;
        if (memcpy_s((char *)status->address, ETH_ADDR_LEN + 1, (char*)tmpAddress, ETH_ADDR_LEN + 1) != EOK) {
            HDF_LOGE("%{public}s strcpy memcpy", __func__);
        }
    }
    if (strcmp(halStatus->bssid, "") != 0) {
        HDF_LOGI("%{public}s key include bssid value=%{private}s", __func__, halStatus->bssid);
        uint8_t tmpBssid[ETH_ADDR_LEN + 1] = {0};
        hwaddr_aton(halStatus->bssid, tmpBssid);
        status->bssid = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (ETH_ADDR_LEN + 1));
        if (status->bssid == NULL) {
            HDF_LOGE("%{public}s status->bssid is NULL", __func__);
            status->bssidLen = 0;
            return;
        }
        status->bssidLen = ETH_ADDR_LEN + 1 ;
        if (strcpy_s((char *)status->bssid, ETH_ADDR_LEN + 1, (char*)tmpBssid) != EOK) {
            HDF_LOGE("%{public}s strcpy failed", __func__);
        }
    }
}

int32_t WpaInterfaceWifiStatus(struct IWpaInterface *self, const char *ifName, struct HdiWpaCmdStatus *status)
{
    HDF_LOGI("enter %{public}s", __func__);
    if (ifName == NULL || status == NULL) {
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
    struct WpaHalCmdStatus halStatus;
    if (memset_s(&halStatus, sizeof(halStatus), 0, sizeof(halStatus)) != EOK) {
        pthread_mutex_unlock(&g_interfaceLock);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdStatus(pStaIfc, ifName, &halStatus);
    if (ret < 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: wpaCliCmdStatus fail! ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    status->bssidLen = 0;
    status->ssidLen = 0;
    status->keyMgmtLen = 0;
    status->addressLen = 0;
    WpaProcessWifiStatus(&halStatus, status);
    if (status->addressLen == 0) {
        HDF_LOGE("%{public}s key not include address", __func__);
    }
    if (status->bssidLen == 0) {
        HDF_LOGE("%{public}s key not include bssid", __func__);
    }
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: WpaInterfaceWifiStatus success ", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceSaveConfig(struct IWpaInterface *self, const char *ifName)
{
    (void)self;
    HDF_LOGI("enter %{public}s ", __func__);
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
    int ret = pStaIfc->wpaCliCmdSaveConfig(pStaIfc);
    if (ret < 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: wpaCliCmdSaveConfig fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: wpaCliCmdSaveConfig success ret = %{public}d", __func__, ret);
    return HDF_SUCCESS;
}

const char *macToStr(const u8 *addr)
{
    const int macAddrIndexOne = 0;
    const int macAddrIndexTwo = 1;
    const int macAddrIndexThree = 2;
    const int macAddrIndexFour = 3;
    const int macAddrIndexFive = 4;
    const int macAddrIndexSix = 5;
    static char macToStr[WIFI_BSSID_LENGTH];
    if (snprintf_s(macToStr, sizeof(macToStr), sizeof(macToStr)-1, "%02x:%02x:%02x:%02x:%02x:%02x",
        addr[macAddrIndexOne], addr[macAddrIndexTwo], addr[macAddrIndexThree], addr[macAddrIndexFour],
        addr[macAddrIndexFive], addr[macAddrIndexSix]) < 0) {
        return NULL;
    }
    return macToStr;
}

int32_t WpaInterfaceWpsPbcMode(struct IWpaInterface *self, const char *ifName, const struct HdiWifiWpsParam *wpaParam)
{
    HDF_LOGI("enter %{public}s ", __func__);
    (void)self;
    if (ifName == NULL || wpaParam == NULL || wpaParam->bssid == NULL) {
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
    int ret;
    if (wpaParam->anyFlag < 0 && wpaParam->multiAp <= 0 && wpaParam->bssidLen == 0) {
        ret = pStaIfc->wpaCliCmdWpsPbc(pStaIfc, NULL);
    } else {
        struct WpaWpsPbcArgv config = {0};
        config.anyFlag = wpaParam->anyFlag;
        config.multiAp = wpaParam->multiAp;
        if (wpaParam->bssidLen > 0) {
            if (strncpy_s(config.bssid, sizeof(config.bssid), (const char *)wpaParam->bssid,
                wpaParam->bssidLen) != 0) {
                pthread_mutex_unlock(&g_interfaceLock);
                HDF_LOGE("%{public}s: strncpy_s bssid fail", __func__);
                return HDF_FAILURE;
            }
        }
        ret = pStaIfc->wpaCliCmdWpsPbc(pStaIfc, &config);
    }
    if (ret < 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: wpaCliCmdWpsPbc fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    } else if (ret == WIFI_HAL_PBC_OVERLAP) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: wpaCliCmdWpsPbc fail PBC_OVERLAP ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: wpaCliCmdWpsPbc success ret = %{public}d", __func__, ret);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceWpsPinMode(struct IWpaInterface *self, const char *ifName,
    const struct HdiWifiWpsParam *wpaParam, int *pinCode)
{
    HDF_LOGI("enter %{public}s ", __func__);
    (void)self;
    if (ifName == NULL || wpaParam == NULL || wpaParam->bssid == NULL
        || wpaParam->pinCode == NULL || pinCode == NULL) {
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
    struct WpaWpsPinArgv config = {{0}, {0}};
    if (strncpy_s(config.bssid, sizeof(config.bssid), macToStr(wpaParam->bssid),
        strlen(macToStr(wpaParam->bssid))) != 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: strncpy_s bssid fail", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdWpsPin(pStaIfc, &config, pinCode);
    if (ret < 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: wpaCliCmdWpsPin fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: wpaCliCmdWpsPin success ret = %{public}d", __func__, ret);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceWpsCancel(struct IWpaInterface *self, const char *ifName)
{
    HDF_LOGI("enter %{public}s ", __func__);
    (void)self;
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

    int ret = pStaIfc->wpaCliCmdWpsCancel(pStaIfc);
    if (ret < 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: wpaCliCmdWpsCancel fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: wpaCliCmdWpsCancel success ret = %{public}d", __func__, ret);
    return HDF_SUCCESS;
}

//need to deal countryCodeLen
int32_t WpaInterfaceGetCountryCode(struct IWpaInterface *self, const char *ifName,
    char *countryCode, uint32_t countryCodeLen)
{
    HDF_LOGI("enter %{public}s: ", __func__);
    (void)self;
    if (ifName == NULL || countryCode == NULL) {
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
    int ret = pStaIfc->wpaCliCmdGetCountryCode(pStaIfc, countryCode, countryCodeLen);
    if (ret < 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: wpaCliCmdGetCountryCode fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: wpaCliCmdGetCountryCode success ret = %{public}d", __func__, ret);
    return HDF_SUCCESS;
}

//need to deal valueLen
int32_t WpaInterfaceGetNetwork(struct IWpaInterface *self, const char *ifName,
    const int32_t networkId, const char *param, char *value, uint32_t valueLen)
{
    HDF_LOGI("enter %{public}s ", __func__);
    (void)self;
    if (ifName == NULL || param == NULL || value == NULL || valueLen == 0) {
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
    struct WpaGetNetworkArgv getNetwork = {0};
    getNetwork.id = networkId;
    if (strncpy_s(getNetwork.param, sizeof(getNetwork.param), param, strlen(param)) != 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: strncpy_s param fail", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdGetNetwork(pStaIfc, &getNetwork, value, valueLen);
    if (ret < 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: wpaCliCmdGetNetwork fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: wpaCliCmdGetNetwork success ret = %{public}d", __func__, ret);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceBlocklistClear(struct IWpaInterface *self, const char *ifName)
{
    HDF_LOGI("enter %{public}s ", __func__);
    (void)self;
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
    int ret = pStaIfc->wpaCliCmdWpaBlockListClear(pStaIfc);
    if (ret < 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: wpaCliCmdWpaBlockListClear fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: wpaCliCmdWpaBlockListClear success ret = %{public}d", __func__, ret);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceSetSuspendMode(struct IWpaInterface *self, const char *ifName, const int32_t mode)
{
    HDF_LOGI("enter %{public}s: mode = %{public}d", __func__, mode);
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(&g_interfaceLock);
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdWpaSetSuspendMode(pStaIfc, mode);
    if (ret != 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: wpaCliCmdWpaSetSuspendMode failed!, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: wpaCliCmdWpaSetSuspendMode success, ret = %{public}d", __func__, ret);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceGetConnectionCapabilities(struct IWpaInterface *self, const char *ifName,
    struct ConnectionCapabilities *connectionCap)
{
    HDF_LOGI("enter %{public}s: ", __func__);
    (void)self;
    if (ifName == NULL || connectionCap == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(&g_interfaceLock);
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdGetConnectionCapabilities(pStaIfc, connectionCap);
    if (ret != 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: wpaCliCmdGetConnectionCapabilities failed!, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: wpaCliCmdGetConnectionCapabilities success, ret = %{public}d", __func__, ret);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceGetScanSsid(struct IWpaInterface *self, const char *ifName, int32_t *enable)
{
    HDF_LOGI("enter %{public}s ", __func__);
    (void)self;
    if (ifName == NULL || enable == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(&g_interfaceLock);
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int scanSsid = 0;
    int ret = pStaIfc->wpaCliCmdGetScanSsid(pStaIfc, &scanSsid);
    if (ret != 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: wpaCliCmdGetScanSsid failed!, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    *enable = (scanSsid == 1);
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: wpaCliCmdGetScanSsid success, scanSsid = %{public}d ", __func__, scanSsid);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceGetPskPassphrase(struct IWpaInterface *self, const char *ifName,
    char *psk, uint32_t pskLen)
{
    HDF_LOGI("enter %{public}s ", __func__);
    (void)self;
    if (ifName == NULL || psk == NULL || pskLen == 0) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(&g_interfaceLock);
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdGetPskPassphrase(pStaIfc, psk, pskLen);
    if (ret < 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: wpaCliCmdGetPskPassphrase failed!,ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: wpaCliCmdGetPskPassphrase success!,ret = %{public}d", __func__, ret);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceGetPsk(struct IWpaInterface *self, const char *ifName, uint8_t *psk, uint32_t *pskLen)
{
    HDF_LOGI("enter %{public}s ", __func__);
    (void)self;
    if (ifName == NULL || psk == NULL || pskLen == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(&g_interfaceLock);
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdGetPsk(pStaIfc, psk, pskLen);
    if (ret < 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: wpaCliCmdGetPsk failed!,ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: wpaCliCmdGetPsk success!,ret = %{public}d", __func__, ret);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceGetWepKey(struct IWpaInterface *self, const char *ifName, int keyIdx,
    uint8_t *wepKey, uint32_t *wepKeyLen)
{
    HDF_LOGI("enter %{public}s keyIdx = %{public}d", __func__, keyIdx);
    (void)self;
    if (ifName == NULL || wepKey == NULL || wepKeyLen == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(&g_interfaceLock);
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdWepKey(pStaIfc, keyIdx, wepKey, wepKeyLen);
    if (ret < 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: wpaCliCmdWepKey failed!,ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: wpaCliCmdWepKey success!,ret = %{public}d", __func__, ret);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceGetWepTxKeyIdx(struct IWpaInterface *self, const char *ifName, int *keyIdx)
{
    HDF_LOGI("enter %{public}s ", __func__);
    (void)self;
    if (ifName == NULL || keyIdx == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(&g_interfaceLock);
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdWepKeyTxKeyIdx(pStaIfc, keyIdx);
    if (ret < 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: wpaCliCmdWepKeyTxKeyIdx failed!,ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: wpaCliCmdWepKeyTxKeyIdx success!,*keyIdx = %{public}d", __func__, *keyIdx);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceGetRequirePmf(struct IWpaInterface *self, const char *ifName, int *enable)
{
    HDF_LOGI("enter %{public}s ", __func__);
    (void)self;
    if (ifName == NULL || enable == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(&g_interfaceLock);
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdGetRequirePmf(pStaIfc, enable);
    if (ret != 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: wpaCliCmdGetRequirePmf failed!, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: wpaCliCmdGetRequirePmf success, ret=%{public}d  enable=%{public}d ", __func__, ret, *enable);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceSetCountryCode(struct IWpaInterface *self, const char *ifName, const char *countryCode)
{
    HDF_LOGI("enter %{public}s ", __func__);
    (void)self;
    if (ifName == NULL || countryCode == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(&g_interfaceLock);
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdSetCountryCode(pStaIfc, countryCode);
    if (ret < 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: wpaCliCmdSetCountryCode failed!, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: wpaCliCmdSetCountryCode success, ret = %{public}d", __func__, ret);
    return HDF_SUCCESS;
}

static void OnRemoteServiceDied(struct HdfDeathRecipient *deathRecipient, struct HdfRemoteService *remote)
{
    HDF_LOGI("enter %{public}s ", __func__);
    WifiWpaInterface *pWpaInterface = GetWifiWpaGlobalInterface();
    if (pWpaInterface == NULL) {
        HDF_LOGE("%{public}s: Get wpa global interface failed!", __func__);
        return;
    }
    int ret = pWpaInterface->wpaCliTerminate();
    if (ret != 0) {
        HDF_LOGE("%{public}s: wpaCliTerminate failed!", __func__);
    } else {
        HDF_LOGI("%{public}s: wpaCliTerminate suc!", __func__);
    }
    ReleaseWpaGlobalInterface();
    HDF_LOGI("%{public}s: call ReleaseWpaGlobalInterface finish", __func__);
}

static struct RemoteServiceDeathRecipient g_deathRecipient = {
    .recipient = {
        .OnRemoteDied = OnRemoteServiceDied,
    }
};

static void AddDeathRecipientForService(struct IWpaCallback *cbFunc)
{
    HDF_LOGI("enter %{public}s ", __func__);
    if (cbFunc == NULL) {
        HDF_LOGE("invalid parameter");
        return;
    }
    struct HdfRemoteService *remote = cbFunc->AsObject(cbFunc);
    if (remote == NULL) {
        HDF_LOGE("remote is NULL");
        return;
    }
    HdfRemoteServiceAddDeathRecipient(remote, &g_deathRecipient.recipient);
}

static int32_t HdfWpaAddRemoteObj(struct IWpaCallback *self, const char *ifName)
{
    struct HdfWpaRemoteNode *pos = NULL;
    struct DListHead *head = &HdfWpaStubDriver()->remoteListHead;

    if (self == NULL) {
        HDF_LOGE("%{public}s:self == NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!DListIsEmpty(head)) {
        DLIST_FOR_EACH_ENTRY(pos, head, struct HdfWpaRemoteNode, node) {
            if (pos->service == self->AsObject(self)) {
                HDF_LOGE("%{public}s: pos->service == self", __func__);
                return HDF_FAILURE;
            }
        }
    }
    struct HdfWpaRemoteNode *newRemoteNode = (struct HdfWpaRemoteNode *)OsalMemCalloc(sizeof(struct HdfWpaRemoteNode));
    if (newRemoteNode == NULL) {
        HDF_LOGE("%{public}s:newRemoteNode is NULL", __func__);
        return HDF_FAILURE;
    }
    newRemoteNode->callbackObj = self;
    newRemoteNode->service = self->AsObject(self);
    DListInsertTail(&newRemoteNode->node, head);
    if (strncmp(ifName, "wlan", strlen("wlan")) == 0) {
        AddDeathRecipientForService(self);
    }
    return HDF_SUCCESS;
}