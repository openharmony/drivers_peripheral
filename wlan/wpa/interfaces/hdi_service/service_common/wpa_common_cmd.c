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

#define BUF_SIZE 512

pthread_t g_tid;
const int QUOTATION_MARKS_FLAG_YES = 0;
const int QUOTATION_MARKS_FLAG_NO = 1;
const int MAX_NETWORKS_NUM = 100;

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
            OsalMemFree(*dst);
            *dst = NULL;
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
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    ScanSettings settings = {0};
    settings.scanStyle = SCAN_TYPE_LOW_SPAN;
    int ret = pStaIfc->wpaCliCmdScan(pStaIfc, &settings);
    if (ret < 0) {
        HDF_LOGE("%{public}s: StartScan fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    if (ret == WIFI_HAL_SCAN_BUSY) {
        HDF_LOGE("%{public}s: StartScan return scan busy", __func__);
        return HDF_FAILURE;
    }
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
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdScanInfo(pStaIfc, resultBuf, resultBufLen);
    if (ret < 0) {
        HDF_LOGE("%{public}s: WpaCliCmdScanInfo2 fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
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
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdAddNetworks(pStaIfc);
    if (ret < 0) {
        HDF_LOGE("%{public}s: WpaInterfaceAddNetwork fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    *networkId = ret;
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

    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdRemoveNetwork(pStaIfc, networkId);
    if (ret < 0) {
        HDF_LOGE("%{public}s: WpaInterfaceRemoveNetwork fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
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
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdDisableNetwork(pStaIfc, networkId);
    if (ret < 0) {
        HDF_LOGE("%{public}s: WpaInterfaceDisableNetwork fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
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
    HDF_LOGI("enter %{public}s networkId = %{public}d", __func__, networkId);
    if (name != NULL) {
        HDF_LOGI("%{public}s name = %{private}s", __func__, name);
    }
    if (value != NULL) {
        HDF_LOGI("%{public}s value = %{private}s", __func__, value);
    }
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    struct WpaSetNetworkArgv conf;
    if (memset_s(&conf, sizeof(conf), 0, sizeof(conf)) != 0) {
        HDF_LOGE("%{public}s: memset_s conf fail", __func__);
        return HDF_FAILURE;
    }
    conf.id = networkId;
    int pos = -1;
    for (unsigned int i = 0; i < sizeof(g_wpaSsidFields) / sizeof(g_wpaSsidFields[0]); ++i) {
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
    int size = MAX_NETWORKS_NUM;
    WifiNetworkInfo *infos = (WifiNetworkInfo *)calloc(size, sizeof(WifiNetworkInfo));
    if (infos == NULL) {
        HDF_LOGE("%{public}s: info = NULL", __func__);
        return HDF_FAILURE;
    }
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        free(infos);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdListNetworks(pStaIfc, infos, &size);
    if (ret < 0) {
        HDF_LOGE("%{public}s: wpaCliCmdListNetworks fail! ret = %{public}d", __func__, ret);
        free(infos);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s: wpaCliCmdListNetworks success size = %{public}d", __func__, size);
    for (int i = 0; i < ((size > MAX_NETWORKS_NUM) ? MAX_NETWORKS_NUM : size); i++) {
        WpaFillWpaListNetworkParam(infos, networkInfo);
        infos++;
        networkInfo++;
    }
    *networkInfoLen = size;
    free(infos);
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

    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdSelectNetwork(pStaIfc, networkId);
    if (ret < 0) {
        HDF_LOGE("%{public}s: wpaCliCmdSelectNetwork fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
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

    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdEnableNetwork(pStaIfc, networkId);
    if (ret < 0) {
        HDF_LOGE("%{public}s: wpaCliCmdEnableNetwork fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
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
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdReconnect(pStaIfc);
    if (ret < 0) {
        HDF_LOGE("%{public}s: wpaCliCmdReconnect fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
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

    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdDisconnect(pStaIfc);
    if (ret < 0) {
        HDF_LOGE("%{public}s: wpaCliCmdDisconnect fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
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

    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdPowerSave(pStaIfc, enable);
    if (ret < 0) {
        HDF_LOGE("%{public}s: wpaCliCmdPowerSave fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
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

    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdSetAutoConnect(pStaIfc, enable);
    if (ret < 0) {
        HDF_LOGE("%{public}s: wpaCliCmdSetAutoConnect fail! ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
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
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    struct WpaHalCmdStatus halStatus;
    if (memset_s(&halStatus, sizeof(halStatus), 0, sizeof(halStatus)) != EOK) {
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdStatus(pStaIfc, ifName, &halStatus);
    if (ret < 0) {
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
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdSaveConfig(pStaIfc);
    if (ret < 0) {
        HDF_LOGE("%{public}s: wpaCliCmdSaveConfig fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
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
    if (os_snprintf(macToStr, sizeof(macToStr), "%02x:%02x:%02x:%02x:%02x:%02x", addr[macAddrIndexOne],
        addr[macAddrIndexTwo], addr[macAddrIndexThree], addr[macAddrIndexFour],
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
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
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
            if (strncpy_s(config.bssid, sizeof(config.bssid),(const char *)wpaParam->bssid,
                wpaParam->bssidLen) != 0) {
                HDF_LOGE("%{public}s: strncpy_s bssid fail", __func__);
                return HDF_FAILURE;
            }
        }
        ret = pStaIfc->wpaCliCmdWpsPbc(pStaIfc, &config);
    }
    if (ret < 0) {
        HDF_LOGE("%{public}s: wpaCliCmdWpsPbc fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    } else if (ret == WIFI_HAL_PBC_OVERLAP) {
        HDF_LOGE("%{public}s: wpaCliCmdWpsPbc fail PBC_OVERLAP ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
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
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    struct WpaWpsPinArgv config = {{0}, {0}};
    if (strncpy_s(config.bssid, sizeof(config.bssid), macToStr(wpaParam->bssid),
        strlen(macToStr(wpaParam->bssid))) != 0) {
        HDF_LOGE("%{public}s: strncpy_s bssid fail", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdWpsPin(pStaIfc, &config, pinCode);
    if (ret < 0) {
        HDF_LOGE("%{public}s: wpaCliCmdWpsPin fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
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

    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }

    int ret = pStaIfc->wpaCliCmdWpsCancel(pStaIfc);
    if (ret < 0) {
        HDF_LOGE("%{public}s: wpaCliCmdWpsCancel fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
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
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdGetCountryCode(pStaIfc, countryCode, countryCodeLen);
    if (ret < 0) {
        HDF_LOGE("%{public}s: wpaCliCmdGetCountryCode fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
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
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    struct WpaGetNetworkArgv getNetwork = {0};
    getNetwork.id = networkId;
    if (strncpy_s(getNetwork.param, sizeof(getNetwork.param), param, strlen(param)) != 0) {
        HDF_LOGE("%{public}s: strncpy_s param fail", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdGetNetwork(pStaIfc, &getNetwork, value, valueLen);
    if (ret < 0) {
        HDF_LOGE("%{public}s: wpaCliCmdGetNetwork fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
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
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdWpaBlockListClear(pStaIfc);
    if (ret < 0) {
        HDF_LOGE("%{public}s: wpaCliCmdWpaBlockListClear fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
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
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdWpaSetSuspendMode(pStaIfc, mode);
    if (ret != 0) {
        HDF_LOGE("%{public}s: wpaCliCmdWpaSetSuspendMode failed!, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
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

    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdGetConnectionCapabilities(pStaIfc, connectionCap);
    if (ret != 0) {
        HDF_LOGE("%{public}s: wpaCliCmdGetConnectionCapabilities failed!, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
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

    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int scanSsid = 0;
    int ret = pStaIfc->wpaCliCmdGetScanSsid(pStaIfc, &scanSsid);
    if (ret != 0) {
        HDF_LOGE("%{public}s: wpaCliCmdGetScanSsid failed!, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    *enable = (scanSsid == 1);
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

    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdGetPskPassphrase(pStaIfc, psk, pskLen);
    if (ret < 0) {
        HDF_LOGE("%{public}s: wpaCliCmdGetPskPassphrase failed!,ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
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
	
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdGetPsk(pStaIfc, psk, pskLen);
    if (ret < 0) {
        HDF_LOGE("%{public}s: wpaCliCmdGetPsk failed!,ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
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
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdWepKey(pStaIfc, keyIdx, wepKey, wepKeyLen);
    if (ret < 0) {
        HDF_LOGE("%{public}s: wpaCliCmdWepKey failed!,ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
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

    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdWepKeyTxKeyIdx(pStaIfc, keyIdx);
    if (ret < 0) {
        HDF_LOGE("%{public}s: wpaCliCmdWepKeyTxKeyIdx failed!,ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
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
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdGetRequirePmf(pStaIfc, enable);
    if (ret != 0) {
        HDF_LOGE("%{public}s: wpaCliCmdGetRequirePmf failed!, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
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
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdSetCountryCode(pStaIfc, countryCode);
    if (ret < 0) {
        HDF_LOGE("%{public}s: wpaCliCmdSetCountryCode failed!, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s: wpaCliCmdSetCountryCode success, ret = %{public}d", __func__, ret);
    return HDF_SUCCESS;
}

static int32_t HdfWpaAddRemoteObj(struct IWpaCallback *self)
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
    return HDF_SUCCESS;
}

static void HdfWpaDelRemoteObj(struct IWpaCallback *self)
{
    struct HdfWpaRemoteNode *pos = NULL;
    struct HdfWpaRemoteNode *tmp = NULL;
    struct DListHead *head = &HdfWpaStubDriver()->remoteListHead;

    DLIST_FOR_EACH_ENTRY_SAFE(pos, tmp, head, struct HdfWpaRemoteNode, node) {
        if (pos->service->index == self->AsObject(self)->index) {
            DListRemove(&(pos->node));
            IWpaCallbackRelease(pos->callbackObj);
            OsalMemFree(pos);
            pos = NULL;
            break;
        }
    }
    IWpaCallbackRelease(self);
}

static int32_t WpaFillWpaDisconnectParam(struct WpaDisconnectParam *disconnectParam,
    struct HdiWpaDisconnectParam *hdiWpaDisconnectParam)
{
    int32_t ret = HDF_SUCCESS;

    if (disconnectParam == NULL || hdiWpaDisconnectParam == NULL) {
        HDF_LOGE("%{public}s: disconnectParam or hdiWpaDisconnectParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiWpaDisconnectParam->locallyGenerated = disconnectParam->locallyGenerated;
    hdiWpaDisconnectParam->reasonCode = disconnectParam->reasonCode;
    if (FillData(&hdiWpaDisconnectParam->bssid, &hdiWpaDisconnectParam->bssidLen,
        disconnectParam->bssid, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
    }
    if (ret != HDF_SUCCESS) {
        if (hdiWpaDisconnectParam->bssid != NULL) {
            OsalMemFree(hdiWpaDisconnectParam->bssid);
            hdiWpaDisconnectParam->bssid = NULL;
        }
    }
    return ret;
}

static int32_t WpaFillWpaConnectParam(struct WpaConnectParam *connectParam,
    struct HdiWpaConnectParam *hdiWpaConnectParam)
{
    int32_t ret = HDF_SUCCESS;

    if (connectParam == NULL || hdiWpaConnectParam == NULL) {
        HDF_LOGE("%{public}s: connectParam or hdiWpaConnectParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiWpaConnectParam->networkId = connectParam->networkId;
    if (FillData(&hdiWpaConnectParam->bssid, &hdiWpaConnectParam->bssidLen,
        connectParam->bssid, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
    }
    if (ret != HDF_SUCCESS) {
        if (hdiWpaConnectParam->bssid != NULL) {
            OsalMemFree(hdiWpaConnectParam->bssid);
            hdiWpaConnectParam->bssid = NULL;
        }
    }
    return ret;
}

static int32_t WpaFillWpaBssidChangedParam(struct WpaBssidChangedParam *bssidChangedParam,
    struct HdiWpaBssidChangedParam *hdiWpaBssidChangedParam)
{
    int32_t ret = HDF_SUCCESS;

    if (bssidChangedParam == NULL || hdiWpaBssidChangedParam == NULL) {
        HDF_LOGE("%{public}s: bssidChangedParam or hdiWpaBssidChangedParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    do {
        if (FillData(&hdiWpaBssidChangedParam->bssid, &hdiWpaBssidChangedParam->bssidLen,
            bssidChangedParam->bssid, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiWpaBssidChangedParam->reason, &hdiWpaBssidChangedParam->reasonLen,
            bssidChangedParam->reason, strlen((char*) bssidChangedParam->reason)) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill reason fail!", __func__);
            ret = HDF_FAILURE;
        }
    } while (0);
    if (ret != HDF_SUCCESS) {
        if (hdiWpaBssidChangedParam->bssid != NULL) {
            OsalMemFree(hdiWpaBssidChangedParam->bssid);
            hdiWpaBssidChangedParam->bssid = NULL;
        }
        if (hdiWpaBssidChangedParam->reason != NULL) {
            OsalMemFree(hdiWpaBssidChangedParam->reason);
            hdiWpaBssidChangedParam->reason = NULL;
        }
    }
    return ret;
}

static int32_t WpaFillWpaStateChangedParam(struct WpaStateChangedParam *stateChangedParam,
    struct HdiWpaStateChangedParam *hdiWpaStateChangedParam)
{
    int32_t ret = HDF_SUCCESS;

    if (stateChangedParam == NULL || hdiWpaStateChangedParam == NULL) {
        HDF_LOGE("%{public}s: stateChangedParam or hdiWpaStateChangedParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiWpaStateChangedParam->networkId = stateChangedParam->networkId;
    HDF_LOGD("%{public}s: hdiWpaStateChangedParam->networkId =%d", __func__, hdiWpaStateChangedParam->networkId);
    hdiWpaStateChangedParam->status = stateChangedParam->status;
    HDF_LOGD("%{public}s: hdiWpaStateChangedParam->status =%d", __func__, hdiWpaStateChangedParam->status);
    do {
        HDF_LOGD("%{public}s: stateChangedParam->bssid[0] = %x", __func__, stateChangedParam->bssid[0]);
        HDF_LOGD("%{public}s: stateChangedParam->bssid[5] = %x", __func__,
            stateChangedParam->bssid[WIFI_BSSID_LEN - 1]);
        if (FillData(&hdiWpaStateChangedParam->bssid, &hdiWpaStateChangedParam->bssidLen,
            stateChangedParam->bssid, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        HDF_LOGD("%{public}s: stateChangedParam->ssid[0] = %x", __func__, stateChangedParam->ssid[0]);
        HDF_LOGD("%{public}s: stateChangedParam->ssid[WIFI_SSID_LENGTH-1] = %x", __func__,
            stateChangedParam->ssid[WIFI_SSID_LENGTH - 1]);
        if (memcmp(stateChangedParam->ssid, "\0", 1) == 0) {
            hdiWpaStateChangedParam->ssidLen = 0;
            HDF_LOGE("%{public}s: hdiWpaStateChangedParam->ssidLen =%d", __func__, hdiWpaStateChangedParam->ssidLen);
        } else {
            if (FillData(&hdiWpaStateChangedParam->ssid, &hdiWpaStateChangedParam->ssidLen,
            stateChangedParam->ssid, strlen((char*)stateChangedParam->ssid)) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill ssid fail!", __func__);
            ret = HDF_FAILURE;
            }
        }
    } while (0);
    if (ret != HDF_SUCCESS) {
        if (hdiWpaStateChangedParam->bssid != NULL) {
            OsalMemFree(hdiWpaStateChangedParam->bssid);
            hdiWpaStateChangedParam->bssid = NULL;
        }
        if (hdiWpaStateChangedParam->ssid != NULL) {
            OsalMemFree(hdiWpaStateChangedParam->ssid);
            hdiWpaStateChangedParam->ssid = NULL;
        }
    }
    return ret;
}

static int32_t WpaFillWpaTempDisabledParam(struct WpaTempDisabledParam *tempDisabledParam,
    struct HdiWpaTempDisabledParam *hdiWpaTempDisabledParam)
{
    int32_t ret = HDF_SUCCESS;

    if (tempDisabledParam == NULL || hdiWpaTempDisabledParam == NULL) {
        HDF_LOGE("%{public}s: tempDisabledParam or hdiWpaTempDisabledParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiWpaTempDisabledParam->networkId = tempDisabledParam->networkId;
    hdiWpaTempDisabledParam->authFailures = tempDisabledParam->authFailures;
    hdiWpaTempDisabledParam->duration = tempDisabledParam->duration;
    do {
        if (FillData(&hdiWpaTempDisabledParam->reason, &hdiWpaTempDisabledParam->reasonLen,
            tempDisabledParam->reason, strlen((char*)tempDisabledParam->reason)) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiWpaTempDisabledParam->ssid, &hdiWpaTempDisabledParam->ssidLen,
            tempDisabledParam->ssid, strlen((char*)tempDisabledParam->ssid)) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill ssid fail!", __func__);
            ret = HDF_FAILURE;
        }
    } while (0);
    if (ret != HDF_SUCCESS) {
        if (hdiWpaTempDisabledParam->reason != NULL) {
            OsalMemFree(hdiWpaTempDisabledParam->reason);
            hdiWpaTempDisabledParam->reason = NULL;
        }
        if (hdiWpaTempDisabledParam->ssid != NULL) {
            OsalMemFree(hdiWpaTempDisabledParam->ssid);
            hdiWpaTempDisabledParam->ssid = NULL;
        }
    }
    return ret;
}

static int32_t WpaFillWpaAssociateRejectParam(struct WpaAssociateRejectParam *associateRejectParam,
    struct HdiWpaAssociateRejectParam *hdiWpaAssociateRejectParam)
{
    int32_t ret = HDF_SUCCESS;

    if (associateRejectParam == NULL || hdiWpaAssociateRejectParam == NULL) {
        HDF_LOGE("%{public}s: associateRejectParam or hdiWpaAssociateRejectParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiWpaAssociateRejectParam->statusCode = associateRejectParam->statusCode;
    hdiWpaAssociateRejectParam->timeOut = associateRejectParam->timeOut;
    if (FillData(&hdiWpaAssociateRejectParam->bssid, &hdiWpaAssociateRejectParam->bssidLen,
        associateRejectParam->bssid, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
    }
    if (ret != HDF_SUCCESS) {
        if (hdiWpaAssociateRejectParam->bssid != NULL) {
            OsalMemFree(hdiWpaAssociateRejectParam->bssid);
            hdiWpaAssociateRejectParam->bssid = NULL;
        }
    }
    return ret;
}

static int32_t WpaFillWpaRecvScanResultParam(struct WpaRecvScanResultParam *recvScanResultParam,
    struct HdiWpaRecvScanResultParam *hdiWpaRecvScanResultParam)
{
    int32_t ret = HDF_SUCCESS;

    if (recvScanResultParam == NULL || hdiWpaRecvScanResultParam == NULL) {
        HDF_LOGE("%{public}s: recvScanResultParam or hdiWpaRecvScanResultParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiWpaRecvScanResultParam->scanId = recvScanResultParam->scanId;
    return ret;
}

static int32_t WpaFillWpaAuthRejectParam(struct WpaAuthRejectParam *authRejectParam,
    struct HdiWpaAuthRejectParam *hdiWpaAuthRejectParam)
{
    int32_t ret = HDF_SUCCESS;

    if (authRejectParam == NULL || hdiWpaAuthRejectParam == NULL) {
        HDF_LOGE("%{public}s: authRejectParam or hdiWpaAuthRejectParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiWpaAuthRejectParam->statusCode = authRejectParam->statusCode;
    hdiWpaAuthRejectParam->authType = authRejectParam->authType;
    hdiWpaAuthRejectParam->authTransaction = authRejectParam->authTransaction;
    if (FillData(&hdiWpaAuthRejectParam->bssid, &hdiWpaAuthRejectParam->bssidLen,
        authRejectParam->bssid, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
    }
    if (ret != HDF_SUCCESS) {
        if (hdiWpaAuthRejectParam->bssid != NULL) {
            OsalMemFree(hdiWpaAuthRejectParam->bssid);
            hdiWpaAuthRejectParam->bssid = NULL;
        }
    }
    return ret;
}

static int32_t ProcessEventWpaDisconnect(struct HdfWpaRemoteNode *node,
    struct WpaDisconnectParam *disconnectParam, const char *ifName)
{
    struct HdiWpaDisconnectParam *hdiWpaDisconnectParam = NULL;
    int32_t ret = HDF_FAILURE;

    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventDisconnected == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiWpaDisconnectParam = (struct HdiWpaDisconnectParam *)OsalMemCalloc(sizeof(struct HdiWpaDisconnectParam));
    if ((hdiWpaDisconnectParam == NULL) || (WpaFillWpaDisconnectParam(disconnectParam,
        hdiWpaDisconnectParam) != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: hdiWpaDisconnectParam is NULL or disconnectParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventDisconnected(node->callbackObj, hdiWpaDisconnectParam, ifName);
    }
    HdiWpaDisconnectParamFree(hdiWpaDisconnectParam, true);
    return ret;
}

static int32_t ProcessEventWpaConnect(struct HdfWpaRemoteNode *node,
    struct WpaConnectParam *connectParam, const char *ifName)
{
    struct HdiWpaConnectParam *hdiWpaConnectParam = NULL;
    int32_t ret = HDF_FAILURE;

    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventConnected == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiWpaConnectParam = (struct HdiWpaConnectParam *)OsalMemCalloc(sizeof(struct HdiWpaConnectParam));
    if ((hdiWpaConnectParam == NULL) || (WpaFillWpaConnectParam(connectParam, hdiWpaConnectParam) != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: HdiWpaConnectParam is NULL or connectParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventConnected(node->callbackObj, hdiWpaConnectParam, ifName);
    }
    HdiWpaConnectParamFree(hdiWpaConnectParam, true);
    return ret;
}

static int32_t ProcessEventWpaBssidChange(struct HdfWpaRemoteNode *node,
    struct WpaBssidChangedParam *bssidChangeParam, const char *ifName)
{
    struct HdiWpaBssidChangedParam *hdiWpaBssidChangedParam = NULL;
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventBssidChanged == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiWpaBssidChangedParam = (struct HdiWpaBssidChangedParam *)OsalMemCalloc(sizeof(struct HdiWpaBssidChangedParam));
    if ((hdiWpaBssidChangedParam == NULL) || (WpaFillWpaBssidChangedParam(bssidChangeParam,
        hdiWpaBssidChangedParam) != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: hdiWpaBssidChangedParam is NULL or bssidChangeParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventBssidChanged(node->callbackObj, hdiWpaBssidChangedParam, ifName);
    }
    HdiWpaBssidChangedParamFree(hdiWpaBssidChangedParam, true);
    return ret;
}

static int32_t ProcessEventWpaStateChange(struct HdfWpaRemoteNode *node,
    struct WpaStateChangedParam *stateChangeParam, const char *ifName)
{
    struct HdiWpaStateChangedParam *hdiWpaStateChangedParam = NULL;
    int32_t ret = HDF_FAILURE;

    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventStateChanged == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiWpaStateChangedParam = (struct HdiWpaStateChangedParam *)OsalMemCalloc(sizeof(struct HdiWpaStateChangedParam));
    if ((hdiWpaStateChangedParam == NULL) || (WpaFillWpaStateChangedParam(stateChangeParam,
        hdiWpaStateChangedParam) != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: hdiWpaStateChangedParam is NULL or stateChangeParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventStateChanged(node->callbackObj, hdiWpaStateChangedParam, ifName);
    }
    HdiWpaStateChangedParamFree(hdiWpaStateChangedParam, true);
    return ret;
}

static int32_t ProcessEventWpaTempDisable(struct HdfWpaRemoteNode *node,
    struct WpaTempDisabledParam *tempDisabledParam, const char *ifName)
{
    struct HdiWpaTempDisabledParam *hdiWpaTempDisabledParam = NULL;
    int32_t ret = HDF_FAILURE;

    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventTempDisabled == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiWpaTempDisabledParam = (struct HdiWpaTempDisabledParam *)OsalMemCalloc(sizeof(struct HdiWpaTempDisabledParam));
    if ((hdiWpaTempDisabledParam == NULL) || (WpaFillWpaTempDisabledParam(tempDisabledParam,
        hdiWpaTempDisabledParam) != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: hdiWpaTempDisabledParam is NULL or tempDisabledParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventTempDisabled(node->callbackObj, hdiWpaTempDisabledParam, ifName);
    }
    HdiWpaTempDisabledParamFree(hdiWpaTempDisabledParam, true);
    return ret;
}

static int32_t ProcessEventWpaAssociateReject(struct HdfWpaRemoteNode *node,
    struct WpaAssociateRejectParam *associateRejectParam, const char *ifName)
{
    struct HdiWpaAssociateRejectParam *hdiWpaAssociateRejectParam = NULL;
    int32_t ret = HDF_FAILURE;

    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventAssociateReject == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiWpaAssociateRejectParam = (struct HdiWpaAssociateRejectParam *)
        OsalMemCalloc(sizeof(struct HdiWpaAssociateRejectParam));
    if ((hdiWpaAssociateRejectParam == NULL) || (WpaFillWpaAssociateRejectParam(associateRejectParam,
        hdiWpaAssociateRejectParam) != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: hdiWpaAssociateRejectParam is NULL or associateRejectParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventAssociateReject(node->callbackObj, hdiWpaAssociateRejectParam, ifName);
    }
    HdiWpaAssociateRejectParamFree(hdiWpaAssociateRejectParam, true);
    return ret;
}

static int32_t ProcessEventWpaWpsOverlap(struct HdfWpaRemoteNode *node,
     const char *ifName)
{
    int32_t ret = HDF_FAILURE;

    if (node == NULL || node->callbackObj == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = node->callbackObj->OnEventWpsOverlap(node->callbackObj, ifName);
    return ret;
}

static int32_t ProcessEventWpaWpsTimeout(struct HdfWpaRemoteNode *node,
     const char *ifName)
{
    int32_t ret = HDF_FAILURE;

    if (node == NULL || node->callbackObj == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = node->callbackObj->OnEventWpsTimeout(node->callbackObj, ifName);
    return ret;
}

static int32_t ProcessEventWpaRecvScanResult(struct HdfWpaRemoteNode *node,
    struct WpaRecvScanResultParam *recvScanResultParam, const char *ifName)
{
    struct HdiWpaRecvScanResultParam *hdiRecvScanResultParam = NULL;
    int32_t ret = HDF_FAILURE;

    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventScanResult == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiRecvScanResultParam  = (struct HdiWpaRecvScanResultParam *)
        OsalMemCalloc(sizeof(struct HdiWpaRecvScanResultParam));
    if ((hdiRecvScanResultParam == NULL) || (WpaFillWpaRecvScanResultParam(recvScanResultParam,
        hdiRecvScanResultParam) != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: hdiWpaAssociateRejectParam is NULL or associateRejectParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventScanResult(node->callbackObj, hdiRecvScanResultParam, ifName);
    }
    HdiWpaRecvScanResultParamFree(hdiRecvScanResultParam, true);
    return ret;
}

static int32_t ProcessEventWpaAuthReject(
    struct HdfWpaRemoteNode *node, struct WpaAuthRejectParam *authRejectParam, const char *ifName)
{
    struct HdiWpaAuthRejectParam *hdiWpaAuthRejectParam = NULL;
    int32_t ret = HDF_FAILURE;

    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventAuthReject == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiWpaAuthRejectParam =
        (struct HdiWpaAuthRejectParam *)OsalMemCalloc(sizeof(struct HdiWpaAuthRejectParam));
    if ((hdiWpaAuthRejectParam == NULL) ||
        (WpaFillWpaAuthRejectParam(authRejectParam, hdiWpaAuthRejectParam) != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: hdiWpaAuthRejectParam is NULL or authRejectParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventAuthReject(node->callbackObj, hdiWpaAuthRejectParam, ifName);
    }
    HdiWpaAuthRejectParamFree(hdiWpaAuthRejectParam, true);
    return ret;
}

int32_t ProcessEventStaNotify(struct HdfWpaRemoteNode *node, char *notifyParam, const char *ifName)
{
    int32_t ret = HDF_FAILURE;
    if (notifyParam == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_FAILURE;
    }
    char *notifyStr = (char*)malloc(BUF_SIZE);
    if (notifyStr == NULL) {
        HDF_LOGE("%{public}s notifyStr malloc failed", __func__);
        return HDF_FAILURE;
    }
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventStaNotify == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        free(notifyStr);
        return HDF_ERR_INVALID_PARAM;
    }
    if (memset_s(notifyStr, BUF_SIZE, 0, BUF_SIZE) != EOK) {
        HDF_LOGE("%{public}s memset failed", __func__);
        free(notifyStr);
        return HDF_FAILURE;
    }
    if (strcpy_s(notifyStr, BUF_SIZE, notifyParam) != EOK) {
        HDF_LOGE("%{public}s strcpy failed", __func__);
        free(notifyStr);
        return HDF_FAILURE;
    }
    ret = node->callbackObj->OnEventStaNotify(node->callbackObj, notifyStr, ifName);
    free(notifyStr);
    return ret;
}

static int32_t WpaFillWpaVendorExtInfo(struct WpaVendorExtInfo *wpaVendorExtInfo,
                                       struct WpaVendorInfo *wpaVendorInfo)
{
    if (wpaVendorExtInfo == NULL || wpaVendorInfo == NULL) {
        HDF_LOGE("%{public}s: wpaVendorExtInfo or wpaVendorInfo is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaVendorInfo->data = NULL;
    wpaVendorInfo->type = wpaVendorExtInfo->type;
    wpaVendorInfo->freq = wpaVendorExtInfo->freq;
    wpaVendorInfo->width = wpaVendorExtInfo->width;
    wpaVendorInfo->id = wpaVendorExtInfo->id;
    wpaVendorInfo->status = wpaVendorExtInfo->status;
    wpaVendorInfo->reason = wpaVendorExtInfo->reason;
    if (FillData(&wpaVendorInfo->ssid, &wpaVendorInfo->ssidLen,
                 wpaVendorExtInfo->ssid, strlen((char *)wpaVendorExtInfo->ssid)) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s ssid fail !", __func__);
        return HDF_FAILURE;
    }

    if (FillData(&wpaVendorInfo->psk, &wpaVendorInfo->pskLen,
                 wpaVendorExtInfo->psk, strlen((char *)wpaVendorExtInfo->psk)) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s psk fail !", __func__);
        return HDF_FAILURE;
    }

    if (FillData(&wpaVendorInfo->devAddr, &wpaVendorInfo->devAddrLen,
                 wpaVendorExtInfo->devAddr, ETH_ADDR_LEN) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s devAddr fail !", __func__);
        return HDF_FAILURE;
    }

    if (FillData(&wpaVendorInfo->data, &wpaVendorInfo->dataLen,
                 wpaVendorExtInfo->data, strlen((char *)wpaVendorExtInfo->data)) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s data fail !", __func__);
        return HDF_FAILURE;
    }

    HDF_LOGI("wpaVendorInfo type %{public}d, freq %{public}d, reason %{public}d, "
             "id %{public}d status %{public}d!",
             wpaVendorInfo->type, wpaVendorInfo->freq, wpaVendorInfo->reason,
             wpaVendorInfo->id, wpaVendorInfo->status);
    return HDF_SUCCESS;
}

static int32_t ProcessEventWpaVendorExt(struct HdfWpaRemoteNode *node,
    struct WpaVendorExtInfo *wpaVendorExtInfo, const char *ifName)
{
    HDF_LOGI("%{public}s: ifName => %{public}s ; ", __func__, ifName);
    struct WpaVendorInfo wpaVendorInfo;
    int32_t ret = HDF_FAILURE;
    if (wpaVendorExtInfo == NULL) {
        HDF_LOGE("%{public}s: wpaVendorExtInfo is NULL !", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventVendorCb == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (WpaFillWpaVendorExtInfo(wpaVendorExtInfo, &wpaVendorInfo) != HDF_SUCCESS) {
        ret = HDF_FAILURE;
        HDF_LOGE("%{public}s: wpaVendorInfo is NULL or associateRejectParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventVendorCb(node->callbackObj, &wpaVendorInfo, ifName);
    }
    HDF_LOGI("%{public}s: res %{public}d!", __func__, ret);
    return ret;
}
static int32_t HdfStaDealEvent(uint32_t event, struct HdfWpaRemoteNode *pos, void *data, const char *ifName)
{
    int32_t ret = HDF_FAILURE;
    switch (event) {
        case WPA_EVENT_DISCONNECT:
            ret = ProcessEventWpaDisconnect(pos, (struct WpaDisconnectParam *)data, ifName);
            break;
        case WPA_EVENT_CONNECT:
            ret = ProcessEventWpaConnect(pos, (struct WpaConnectParam *)data, ifName);
            break;
        case WPA_EVENT_BSSID_CHANGE:
            ret = ProcessEventWpaBssidChange(pos, (struct WpaBssidChangedParam *)data, ifName);
            break;
        case WPA_EVENT_STATE_CHANGED:
            ret = ProcessEventWpaStateChange(pos, (struct WpaStateChangedParam *)data, ifName);
            break;
        case WPA_EVENT_TEMP_DISABLE:
            ret = ProcessEventWpaTempDisable(pos, (struct WpaTempDisabledParam *)data, ifName);
            break;
        case WPA_EVENT_ASSOCIATE_REJECT:
            ret = ProcessEventWpaAssociateReject(pos, (struct WpaAssociateRejectParam *)data, ifName);
            break;
        case WPA_EVENT_WPS_OVERLAP:
            ret = ProcessEventWpaWpsOverlap(pos, ifName);
            break;
        case WPA_EVENT_WPS_TIMEMOUT:
            ret = ProcessEventWpaWpsTimeout(pos, ifName);
            break;
        case WPA_EVENT_RECV_SCAN_RESULT:
            ret = ProcessEventWpaRecvScanResult(pos, (struct WpaRecvScanResultParam *)data, ifName);
            break;
        case WPA_EVENT_STA_AUTH_REJECT:
            ret = ProcessEventWpaAuthReject(pos, (struct WpaAuthRejectParam *)data, ifName);
            break;
        case WPA_EVENT_STA_NOTIFY:
            ret = ProcessEventStaNotify(pos, (char *)data, ifName);
            break;
        default:
            HDF_LOGE("%{public}s: unknown eventId:%{public}d", __func__, event);
            break;
    }
    return ret;
}

static int32_t HdfP2pDealEvent(uint32_t event, struct HdfWpaRemoteNode *pos, void *data, const char *ifName)
{
    int32_t ret = HDF_FAILURE;
    switch (event) {
        case WPA_EVENT_DEVICE_FOUND:
            ret = ProcessEventP2pDeviceFound(pos, (struct P2pDeviceInfoParam *)data, ifName);
            break;
        case WPA_EVENT_DEVICE_LOST:
            ret = ProcessEventP2pDeviceLost(pos, (struct P2pDeviceLostParam *)data, ifName);
            break;
        case WPA_EVENT_GO_NEGOTIATION_REQUEST:
            ret = ProcessEventP2pGoNegotiationRequest(pos, (struct P2pGoNegotiationRequestParam *)data, ifName);
            break;
        case WPA_EVENT_GO_NEGOTIATION_COMPLETED:
            ret = ProcessEventP2pGoNegotiationCompleted(pos, (struct P2pGoNegotiationCompletedParam *)data, ifName);
            break;
        case WPA_EVENT_INVITATION_RECEIVED:
            ret = ProcessEventP2pInvitationReceived(pos, (struct P2pInvitationReceivedParam *)data, ifName);
            break;
        case WPA_EVENT_INVITATION_RESULT:
            ret = ProcessEventP2pInvitationResult(pos, (struct P2pInvitationResultParam *)data, ifName);
            break;
        case WPA_EVENT_GROUP_FORMATION_SUCCESS:
            ret = ProcessEventP2pGroupFormationSuccess(pos, ifName);
            break;
        case WPA_EVENT_GROUP_FORMATION_FAILURE:
            ret = ProcessEventP2pGroupFormationFailure(pos, (char *)data, ifName);
            break;
        case WPA_EVENT_GROUP_START:
            ret = ProcessEventP2pGroupStarted(pos, (struct P2pGroupStartedParam *)data, ifName);
            break;
        case WPA_EVENT_GROUP_REMOVED:
            ret = ProcessEventP2pGroupRemoved(pos, (struct P2pGroupRemovedParam *)data, ifName);
            break;
        case WPA_EVENT_PROVISION_DISCOVERY_COMPLETED:
            ret = ProcessEventP2pProvisionDiscoveryCompleted(pos, (struct P2pProvisionDiscoveryCompletedParam *)data,
                ifName);
            break;
        case WPA_EVENT_FIND_STOPPED:
            ret = ProcessEventP2pFindStopped(pos, ifName);
            break;
        case WPA_EVENT_SERV_DISC_REQ:
            ret = ProcessEventP2pServDiscReq(pos, (struct P2pServDiscReqInfoParam *)data, ifName);
            break;
        case WPA_EVENT_SERV_DISC_RESP:
            ret = ProcessEventP2pServDiscResp(pos, (struct P2pServDiscRespParam *)data, ifName);
            break;
        case WPA_EVENT_STA_CONNECT_STATE:
            ret = ProcessEventP2pStaConnectState(pos, (struct P2pStaConnectStateParam *)data, ifName);
            break;
        case WPA_EVENT_IFACE_CREATED:
            ret = ProcessEventP2pIfaceCreated(pos, (struct P2pIfaceCreatedParam *)data, ifName);
            break;
        default:
            HDF_LOGE("%{public}s: unknown eventId:%{public}d", __func__, event);
            break;
    }
    return ret;
}

static int32_t HdfVendorExtDealEvent(uint32_t event, struct HdfWpaRemoteNode *pos, void *data, const char *ifName)
{
    int32_t ret = HDF_FAILURE;
    switch (event) {
        case WPA_EVENT_VENDOR_EXT:
            ret = ProcessEventWpaVendorExt(pos, (struct WpaVendorExtInfo *)data, ifName);
            break;
        default:
            HDF_LOGE("%{public}s: unknown eventId:%{public}d", __func__, event);
            break;
    }
    return ret;
}


static int32_t HdfWpaCallbackFun(uint32_t event, void *data, const char *ifName)
{
    struct HdfWpaRemoteNode *pos = NULL;
    struct DListHead *head = NULL;
    int32_t ret = HDF_FAILURE;

    (void)OsalMutexLock(&HdfWpaStubDriver()->mutex);
    head = &HdfWpaStubDriver()->remoteListHead;
    HDF_LOGD("%s: enter HdfWpaCallbackFun event =%u", __FUNCTION__, event);
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: data or ifName is NULL!", __func__);
        (void)OsalMutexUnlock(&HdfWpaStubDriver()->mutex);
        return HDF_ERR_INVALID_PARAM;
    }
    DLIST_FOR_EACH_ENTRY(pos, head, struct HdfWpaRemoteNode, node) {
        if (pos == NULL) {
            HDF_LOGE("%{public}s: pos is NULL", __func__);
            break;
        }
        if (pos->service == NULL || pos->callbackObj == NULL) {
            HDF_LOGW("%{public}s: pos->service or pos->callbackObj NULL", __func__);
            continue;
        }
        if (strncmp(ifName, "wlan", strlen("wlan")) == 0 || strncmp(ifName, "common", strlen("common")) == 0) {
            ret = HdfStaDealEvent(event, pos, data, ifName);
        } else if (strncmp(ifName, "chba", strlen("chba")) == 0 ||
            strncmp(ifName, "p2p-chba", strlen("p2p-chba")) == 0) {
            ret = HdfVendorExtDealEvent(event, pos, data, ifName);
        } else if (strncmp(ifName, "p2p", strlen("p2p")) == 0) {
            ret = HdfP2pDealEvent(event, pos, data, ifName);
        } else {
            HDF_LOGE("%{public}s: ifName is error %{public}s", __func__, ifName);
        }
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: dispatch code fialed, error code: %{public}d", __func__, ret);
        }
    }
    (void)OsalMutexUnlock(&HdfWpaStubDriver()->mutex);
    return ret;
}

int32_t WpaInterfaceRegisterEventCallback(struct IWpaInterface *self, struct IWpaCallback *cbFunc,
    const char *ifName)
{
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (cbFunc == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    (void)OsalMutexLock(&HdfWpaStubDriver()->mutex);
    do {
        HDF_LOGE("%{public}s: call HdfWpaAddRemoteObj", __func__);
        ret = HdfWpaAddRemoteObj(cbFunc);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: HdfSensorAddRemoteObj false", __func__);
            break;
        }
        ret = WpaRegisterEventCallback(HdfWpaCallbackFun, WIFI_WPA_TO_HAL_CLIENT, ifName);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: Register failed!, error code: %{public}d", __func__, ret);
            HdfWpaDelRemoteObj(cbFunc);
            break;
        }
    } while (0);
    (void)OsalMutexUnlock(&HdfWpaStubDriver()->mutex);
    return ret;
}

int32_t WpaInterfaceUnregisterEventCallback(struct IWpaInterface *self, struct IWpaCallback *cbFunc,
    const char *ifName)
{
    (void)self;
    if (cbFunc == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    (void)OsalMutexLock(&HdfWpaStubDriver()->mutex);
    HdfWpaDelRemoteObj(cbFunc);
    if (DListIsEmpty(&HdfWpaStubDriver()->remoteListHead)) {
        int32_t ret = WpaUnregisterEventCallback(HdfWpaCallbackFun, WIFI_WPA_TO_HAL_CLIENT, ifName);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: Unregister failed!, error code: %{public}d", __func__, ret);
        }
    }
    (void)OsalMutexUnlock(&HdfWpaStubDriver()->mutex);
    return HDF_SUCCESS;
}

static void SplitCmdString(const char *startCmd, struct StWpaMainParam *pParam)
{
    if (pParam == NULL) {
        return;
    }
    if (startCmd == NULL) {
        pParam->argc = 0;
        return;
    }
    const char *p = startCmd;
    int i = 0;
    int j = 0;
    while (*p != '\0') {
        if (*p == ' ') {
            if (j <= MAX_WPA_MAIN_ARGV_LEN - 1) {
                pParam->argv[i][j] = '\0';
            } else {
                pParam->argv[i][MAX_WPA_MAIN_ARGV_LEN - 1] = '\0';
            }
            ++i;
            j = 0;
            if (i >= MAX_WPA_MAIN_ARGC_NUM) {
                break;
            }
        } else {
            if (j < MAX_WPA_MAIN_ARGV_LEN - 1) {
                pParam->argv[i][j] = *p;
                ++j;
            }
        }
        ++p;
    }
    if (i >= MAX_WPA_MAIN_ARGC_NUM) {
        pParam->argc = MAX_WPA_MAIN_ARGC_NUM;
    } else {
        pParam->argc = i + 1;
    }
    return;
}


static void *WpaThreadMain(void *p)
{
    const char *startCmd;
    struct StWpaMainParam param = {0};
    char *tmpArgv[MAX_WPA_MAIN_ARGC_NUM] = {0};

    if (p == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return NULL;
    }
    startCmd = (const char *)p;
    SplitCmdString(startCmd, &param);
    for (int i = 0; i < param.argc; i++) {
        tmpArgv[i] = param.argv[i];
    }
    int ret = wpa_main(param.argc, tmpArgv);
    HDF_LOGI("%{public}s: run wpa_main ret:%{public}d.", __func__, ret);
    return NULL;
}

static int32_t StartWpaSupplicant(const char *moduleName, const char *startCmd)
{
    int32_t ret;

    if (moduleName == NULL || startCmd == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM ;
    }
    ret = pthread_create(&g_tid, NULL, WpaThreadMain, (void *)startCmd);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Create wpa thread failed, error code: %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_setname_np(g_tid, "WpaMainThread");
    HDF_LOGI("%{public}s: pthread_create successfully.", __func__);
    usleep(WPA_SLEEP_TIME);
    return HDF_SUCCESS;
}
int32_t WpaInterfaceAddWpaIface(struct IWpaInterface *self, const char *ifName, const char *confName)
{
    (void)self;
    if (ifName == NULL || confName == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM ;
    }
    HDF_LOGI("enter %{public}s Ready to add iface, ifName: %{public}s, confName: %{public}s",
        __func__, ifName, confName);
    WifiWpaInterface *pWpaInterface = GetWifiWpaGlobalInterface();
    if (pWpaInterface == NULL) {
        HDF_LOGE("Get wpa interface failed!");
        return HDF_FAILURE;
    }
    if (pWpaInterface->wpaCliConnect(pWpaInterface) < 0) {
        HDF_LOGE("Failed to connect to wpa!");
        return HDF_FAILURE;
    }
    AddInterfaceArgv addInterface = {0};
    if (strncmp(ifName, "wlan", strlen("wlan")) == 0) {
        if (strcpy_s(addInterface.name, sizeof(addInterface.name) - 1, ifName) != EOK ||
            strcpy_s(addInterface.confName, sizeof(addInterface.confName) - 1,
            CONFIG_ROOR_DIR"/wpa_supplicant/wpa_supplicant.conf") != EOK) {
            return HDF_FAILURE;
        }
    } else if (strncmp(ifName, "p2p", strlen("p2p")) == 0) {
        if (strcpy_s(addInterface.name, sizeof(addInterface.name) - 1, ifName) != EOK ||
            strcpy_s(addInterface.confName, sizeof(addInterface.confName) - 1,
            CONFIG_ROOR_DIR"/wpa_supplicant/p2p_supplicant.conf") != EOK) {
            return HDF_FAILURE;
        }
    } else if (strncmp(ifName, "chba0", strlen("chba0")) == 0) {
        if (strcpy_s(addInterface.name, sizeof(addInterface.name) - 1, ifName) != EOK ||
            strcpy_s(addInterface.confName, sizeof(addInterface.confName) - 1,
            CONFIG_ROOR_DIR"/wpa_supplicant/p2p_supplicant.conf") != EOK) {
            return HDF_FAILURE;
        }
    } else {
        HDF_LOGE("%{public}s Wrong ifname!", __func__);
        return HDF_FAILURE;
    }
    if (pWpaInterface->wpaCliAddIface(pWpaInterface, &addInterface, true) < 0) {
        HDF_LOGE("%{public}s Failed to add wpa iface!", __func__);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s Add interface finish", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceRemoveWpaIface(struct IWpaInterface *self, const char *ifName)
{
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM ;
    }
    HDF_LOGI("enter %{public}s Ready to Remove iface, ifName: %{public}s", __func__, ifName);
    int ret = -1;
    WifiWpaInterface *pWpaInterface = GetWifiWpaGlobalInterface();
    if (pWpaInterface == NULL) {
        HDF_LOGE("Get wpa interface failed!");
        return HDF_FAILURE;
    }
    ret = pWpaInterface->wpaCliRemoveIface(pWpaInterface, ifName);
    HDF_LOGI("%{public}s Remove wpa iface finish, ifName: %{public}s ret = %{public}d", __func__, ifName, ret);
    return (ret == 0 ? HDF_SUCCESS : HDF_FAILURE);
}

static int32_t StopWpaSupplicant(void)
{
    /*Do nothing here,waiting for IWpaInterfaceReleaseInstance to destroy the wpa service. */
    WifiWpaInterface *pWpaInterface = GetWifiWpaGlobalInterface();
    if (pWpaInterface == NULL) {
        HDF_LOGE("%{public}s: Get wpa global interface failed!", __func__);
        return HDF_FAILURE;
    }
    int ret = pWpaInterface->wpaCliTerminate();
    if (ret != 0) {
        HDF_LOGE("%{public}s: wpaCliTerminate failed!", __func__);
    } else {
        HDF_LOGI("%{public}s: wpaCliTerminate suc!", __func__);
    }
    ReleaseWpaGlobalInterface();
    HDF_LOGI("%{public}s: call ReleaseWpaGlobalInterface finish", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceStart(struct IWpaInterface *self)
{
    int32_t ret;

    (void)self;
    HDF_LOGI("enter %{public}s: wpa_supplicant begin to start", __func__);
    ret = StartWpaSupplicant(WPA_SUPPLICANT_NAME, START_CMD);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: StartWpaSupplicant failed, error code: %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s: wpa_supplicant start successfully!", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceStop(struct IWpaInterface *self)
{
    int32_t ret;

    (void)self;
    HDF_LOGI("enter %{public}s: wpa_supplicant begin to stop", __func__);
    ret = StopWpaSupplicant();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Wifi stop failed, error code: %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    ReleaseWifiStaInterface(0);
    HDF_LOGI("%{public}s: wpa_supplicant stop successfully!", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceReassociate(struct IWpaInterface *self, const char *ifName)
{
    (void)self;
    HDF_LOGI("enter %{public}s ", __func__);
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdReassociate(pStaIfc);
    if (ret < 0) {
        HDF_LOGE("%{public}s: wpaCliCmdReassociate fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s: wpaCliCmdReassociate success ret = %{public}d", __func__, ret);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceStaShellCmd(struct IWpaInterface *self, const char *ifName, const char *cmd)
{
    (void)self;
    HDF_LOGI("enter %{public}s", __func__);
    if (ifName == NULL || cmd == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdStaShellCmd(pStaIfc, cmd);
    if (ret < 0) {
        HDF_LOGE("%{public}s: fail ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s: success", __func__);
    return HDF_SUCCESS;
}
