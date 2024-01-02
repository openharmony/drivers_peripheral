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
#include "v1_0/iwpa_callback.h"
#include "v1_0/iwpa_interface.h"
#include "wpa_client.h"
#include <unistd.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>

pthread_t g_tid;
const int QUOTATION_MARKS_FLAG_YES = 0;
const int QUOTATION_MARKS_FLAG_NO = 1;

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

void StrSafeCopy(char *dst, unsigned len, const char *src)
{
    if (dst == NULL) {
        return;
    }
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }
    unsigned i = 0;
    while (i + 1 < len && src[i] != '\0') {
        dst[i] = src[i];
        ++i;
    }
    dst[i] = '\0';
    return;
}

static int Hex2num(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + HDI_POS_TEN;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + HDI_POS_TEN;
    }
    return HDF_FAILURE;
}

int Hex2byte(const char *hex)
{
    int a, b;
    a = Hex2num(*hex++);
    if (a < 0) {
        return HDF_FAILURE;
    }
    b = Hex2num(*hex++);
    if (b < 0) {
        return HDF_FAILURE;
    }
    return (a << HDI_POS_FOURTH) | b;
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
    struct wpa_supplicant *wpaSupp;
    char reply[REPLY_SIZE] = {0};
    int32_t replyLen = 0;
    int32_t ret = HDF_FAILURE;

    (void)self;
    HDF_LOGD("%{public}s scan!", __func__);
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaWlan();
    if (wpaSupp == NULL) {
        HDF_LOGE("%{public}s wpaSupp == NULL", __func__);
        return HDF_FAILURE;
    }
    wpas_ctrl_scan(wpaSupp, NULL, reply, REPLY_SIZE, &replyLen);
    if (replyLen == -1) {
        HDF_LOGE("%{public}s scan network fail!", __func__);
        ret = HDF_FAILURE;
    } else {
        HDF_LOGE("%{public}s scan network reply = %s", __func__, reply);
        ret = HDF_SUCCESS;
    }
    return ret;
}

int32_t WpaInterfaceScanResult(struct IWpaInterface *self, const char *ifName, unsigned char *resultBuf,
     uint32_t *resultBufLen)
{
    struct wpa_supplicant *wpaSupp;
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (ifName == NULL || resultBuf == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaWlan();
    if (wpaSupp == NULL) {
        HDF_LOGE("%{public}s wpaSupp == NULL", __func__);
        return HDF_FAILURE;
    }
    *resultBufLen = (uint32_t)wpa_supplicant_ctrl_iface_scan_results(wpaSupp, (char *)resultBuf,
        REPLY_SIZE * REPLY_SIZE_FACTOR_FIRST * REPLY_SIZE_FACTOR_SECOND);
    HDF_LOGE("%{public}s ScanResult resultBufLen = %d", __func__, *resultBufLen);
    ret = HDF_SUCCESS;
    return ret;
}

int32_t WpaInterfaceAddNetwork(struct IWpaInterface *self, const char *ifName, int32_t *networkId)
{
    struct wpa_supplicant *wpaSupp;
    char reply[REPLY_SIZE] = {0};
    int32_t ret = HDF_FAILURE;

    (void)self;
    HDF_LOGE("%{public}s add network", __func__);
    if (ifName == NULL || networkId == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaWlan();
    if (wpaSupp == NULL) {
        HDF_LOGE("%{public}s wpaSupp == NULL", __func__);
        return HDF_FAILURE;
    }
    ret = wpa_supplicant_ctrl_iface_add_network(wpaSupp, reply, REPLY_SIZE);
    if (ret != HDF_FAILURE) {
        HDF_LOGE("%{public}s add network reply= %{public}s", __func__, reply);
        *networkId = atoi(reply);
        ret = HDF_SUCCESS;
        HDF_LOGE("%{public}s add network success! *networkId = %{public}d", __func__, *networkId);
    } else {
        HDF_LOGE("%{public}s add network fail!", __func__);
    }
    return ret;
}

int32_t WpaInterfaceRemoveNetwork(struct IWpaInterface *self, const char *ifName, int32_t networkId)
{
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE] = {0};
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaWlan();
    if (wpaSupp == NULL) {
        HDF_LOGE("%{public}s wpaSupp == NULL", __func__);
        return HDF_FAILURE;
    }
    if (networkId == -1) {
        strcpy_s(cmd, CMD_SIZE, "all");
    } else {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%d", networkId);
    }
    ret = wpa_supplicant_ctrl_iface_remove_network(wpaSupp, cmd);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s remove network fail!", __func__);
    }
    return ret;
}

int32_t WpaInterfaceDisableNetwork(struct IWpaInterface *self, const char *ifName, const int32_t networkId)
{
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE] = {0};
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaWlan();
    if (wpaSupp == NULL) {
        HDF_LOGE("%{public}s wpaSupp == NULL", __func__);
        return HDF_FAILURE;
    }
    if (networkId == -1) {
        strcpy_s(cmd, CMD_SIZE, "all");
    } else {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%d", networkId);
    }
    ret = wpa_supplicant_ctrl_iface_disable_network(wpaSupp, cmd);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s disable network fail!", __func__);
    }
    return ret;
}

int32_t WpaInterfaceSetNetwork(struct IWpaInterface *self, const char *ifName,
    const int32_t networkId, const char *name, const char *value)
{
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE] = {0};
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (ifName == NULL || name == NULL || value == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaWlan();
    if (wpaSupp == NULL) {
        HDF_LOGE("%{public}s wpaSupp == NULL", __func__);
        return HDF_FAILURE;
    }
    HDF_LOGE("%{public}s networkId =%{public}d", __func__, networkId);
    if (name != NULL) {
        HDF_LOGE("%{public}s name =%{public}s", __func__, name);
    }
    if (value != NULL) {
        HDF_LOGE("%{public}s value =%{public}s", __func__, value);
    }
    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%d %s %s",
        networkId, name, value);
    ret = wpa_supplicant_ctrl_iface_set_network(wpaSupp, cmd);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s set network fail!", __func__);
    }
    return ret;
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
        }
        if (hdiWifiWpaNetworkInfo->ssid != NULL) {
            OsalMemFree(hdiWifiWpaNetworkInfo->ssid);
        }
        if (hdiWifiWpaNetworkInfo->flags != NULL) {
            OsalMemFree(hdiWifiWpaNetworkInfo->flags);
        }
    }
    return ret;
}

static void HdiListNetworkProcess(struct HdiWifiWpaNetworkInfo *pcmd, char *tmpBuf, int bufLeng)
{
    int start = 0; /* start pos */
    int end = 0;   /* end pos */
    int i = 0;

    WifiNetworkInfo wifiNetworkInfo;
    memset_s(&wifiNetworkInfo, sizeof(struct WifiNetworkInfo), 0, sizeof(struct WifiNetworkInfo));
    while (end < bufLeng) {
        if (tmpBuf[end] != '\t') {
            ++end;
            continue;
        }
        tmpBuf[end] = '\0';
        if (i == COLUMN_INDEX_ZERO) {
            pcmd->id = atoi(tmpBuf);
        } else if (i == COLUMN_INDEX_ONE) {
            if (strcpy_s(wifiNetworkInfo.ssid, sizeof(wifiNetworkInfo.ssid), tmpBuf + start) != EOK) {
                break;
            }
            printf_decode((u8 *)wifiNetworkInfo.ssid, sizeof(wifiNetworkInfo.ssid), wifiNetworkInfo.ssid);
        } else if (i == COLUMN_INDEX_TWO) {
            if (strcpy_s(wifiNetworkInfo.bssid, sizeof(wifiNetworkInfo.bssid), tmpBuf + start) != EOK) {
                break;
            }
            start = end + 1;
            if (strcpy_s(wifiNetworkInfo.flags, sizeof(wifiNetworkInfo.flags), tmpBuf + start) != EOK) {
                break;
            }
            break;
        }
        WpaFillWpaListNetworkParam(&wifiNetworkInfo, pcmd);
        ++i;
        end++;
        start = end;
    }
    return;
}

//need to check
int32_t WpaInterfaceListNetworks(struct IWpaInterface *self, const char *ifName,
    struct HdiWifiWpaNetworkInfo *networkInfo, uint32_t *networkInfoLen)
{
    struct wpa_supplicant *wpaSupp;
    char reply[REPLY_SIZE] = {0};
    char cmd[CMD_SIZE] = {0};
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (ifName == NULL || networkInfo == NULL || networkInfoLen == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaWlan();
    if (wpaSupp == NULL) {
        HDF_LOGE("%{public}s wpaSupp == NULL", __func__);
        return HDF_FAILURE;
    }
    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "LIST_NETWORKS");
    if (ret < 0) {
        HDF_LOGE("%{public}s set network fail!", __func__);
        return HDF_FAILURE;
    }
    wpa_supplicant_ctrl_iface_list_networks(wpaSupp, cmd, reply, REPLY_SIZE);

    char *savedPtr = NULL;
    strtok_r(reply, "\n", &savedPtr); /* skip first line */
    char *token = strtok_r(NULL, "\n", &savedPtr);
    int32_t j = 0;
    while (token != NULL) {
        if (j >= *networkInfoLen) {
            *networkInfoLen = j;
            HDF_LOGI("%{public}s list_networks full!", __func__);
            return HDF_SUCCESS;
        }
        int length = strlen(token);
        if (length <= 0) {
            break;
        }
        HdiListNetworkProcess(networkInfo + j, token, length);
        token = strtok_r(NULL, "\n", &savedPtr);
        j++;
    }
    *networkInfoLen  = j;
    if (*networkInfoLen  <= 0) {
        HDF_LOGI("%{public}s list_networks empty!", __func__);
    }
    return HDF_SUCCESS;
}

int32_t WpaInterfaceSelectNetwork(struct IWpaInterface *self, const char *ifName,
    const int32_t networkId)
{
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaWlan();
    if (wpaSupp == NULL) {
        HDF_LOGE("%{public}s wpaSupp == NULL", __func__);
        return HDF_FAILURE;
    }
    HDF_LOGE("%{public}s networkId =%{public}d", __func__, networkId);
    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%d", networkId);
    ret = wpa_supplicant_ctrl_iface_select_network(wpaSupp, cmd);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s select network fail!", __func__);
    }
    return ret;
}

int32_t WpaInterfaceEnableNetwork(struct IWpaInterface *self, const char *ifName, const int32_t networkId)
{
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaWlan();
    if (wpaSupp == NULL) {
        HDF_LOGE("%{public}s wpaSupp == NULL", __func__);
        return HDF_FAILURE;
    }
    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%d", networkId);
    ret = wpa_supplicant_ctrl_iface_enable_network(wpaSupp, cmd);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s enable network fail!", __func__);
    }
    return ret;
}

int32_t WpaInterfaceReconnect(struct IWpaInterface *self, const char *ifName)
{
    struct wpa_supplicant *wpaSupp;

    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaWlan();
    if (wpaSupp == NULL) {
        HDF_LOGE("%{public}s wpaSupp == NULL", __func__);
        return HDF_FAILURE;
    }
    wpas_request_connection(wpaSupp);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceDisconnect(struct IWpaInterface *self, const char *ifName)
{
    struct wpa_supplicant *wpaSupp;

    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaWlan();
    if (wpaSupp == NULL) {
        HDF_LOGE("%{public}s wpaSupp == NULL", __func__);
        return HDF_FAILURE;
    }
    wpas_request_disconnection(wpaSupp);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceSetPowerSave(struct IWpaInterface *self, const char *ifName, const int32_t enable)
{
    struct wpa_supplicant *wpaSupp;
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaWlan();
    if (wpaSupp == NULL) {
        HDF_LOGE("%{public}s wpaSupp == NULL", __func__);
        return HDF_FAILURE;
    }
    if (!wpaSupp->driver->set_p2p_powersave) {
        return HDF_FAILURE;
    }
    ret = wpaSupp->driver->set_p2p_powersave(wpaSupp->drv_priv, enable, -1, -1);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s set powersave fail!", __func__);
    }
    return ret;
}

int32_t  WpaInterfaceAutoConnect(struct IWpaInterface *self, const char *ifName, const int32_t enable)
{
    struct wpa_supplicant *wpaSupp;

    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaWlan();
    if (wpaSupp == NULL) {
        HDF_LOGE("%{public}s wpaSupp == NULL", __func__);
        return HDF_FAILURE;
    }
    wpaSupp->auto_reconnect_disabled = enable == 0;
    return HDF_SUCCESS;
}

static void WapDealWifiStatus(char *reply, struct HdiWpaCmdStatus *status)
{
    char *savedPtr = NULL;
    char *key = strtok_r(reply, "=", &savedPtr);
    while (key != NULL) {
        char *value = strtok_r(NULL, "\n", &savedPtr);
        if (strcmp(key, "bssid") == 0) {
            uint8_t tmpBssid[ETH_ADDR_LEN + 1] = {0};
            HDF_LOGI("%{public}s key include bssid value=%{public}s", __func__, value);
            hwaddr_aton(value, tmpBssid);
            status->bssid = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (ETH_ADDR_LEN + 1));
            status->bssidLen = ETH_ADDR_LEN + 1;
            StrSafeCopy((char *)status->bssid, ETH_ADDR_LEN + 1, (char *)tmpBssid);
        } else if (strcmp(key, "freq") == 0) {
            status->freq = atoi(value);
            HDF_LOGI("%{public}s status->freq= %{public}d", __func__, status->freq);
        } else if (strcmp(key, "ssid") == 0) {
            HDF_LOGI("%{public}s key include ssid value=%{public}s", __func__, value);
            status->ssid = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * strlen(value));
            status->ssidLen = strlen(value);
            StrSafeCopy((char *)status->ssid, strlen(value), value);
            printf_decode((u8 *)status->ssid, strlen(value), (char *)status->ssid);
        } else if (strcmp(key, "id") == 0) {
            status->id = atoi(value);
            HDF_LOGI("%{public}s status->id= %{public}d", __func__, status->id);
        } else if (strcmp(key, "key_mgmt") == 0) {
            HDF_LOGI("%{public}s key include key_mgmt value=%{public}s", __func__, value);
            status->keyMgmt = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * strlen(value));
            status->keyMgmtLen = strlen(value);
            StrSafeCopy((char *)status->keyMgmt, strlen(value), value);
        } else if (strcmp(key, "address") == 0) {
            uint8_t tmpAddress[ETH_ADDR_LEN +1] = {0};
            HDF_LOGD("%{public}s key include address value=%{public}s", __func__, value);
            hwaddr_aton(value, tmpAddress);
            HDF_LOGD("%{public}s key include tmpAddress=%{public}s", __func__, (char *)tmpAddress);
            status->address = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (ETH_ADDR_LEN + 1));
            status->addressLen = ETH_ADDR_LEN + 1;
            StrSafeCopy((char *)status->address, ETH_ADDR_LEN + 1, (char *)tmpAddress);
        }
        key = strtok_r(NULL, "=", &savedPtr);
    }
}

int32_t WpaInterfaceWifiStatus(struct IWpaInterface *self, const char *ifName, struct HdiWpaCmdStatus *status)
{
    char cmd[CMD_SIZE] = {0};
    char reply[REPLY_SIZE] = {0};
    int replyLen;
    struct wpa_supplicant *wpaSupp;
    HDF_LOGI("%{public}s enter WpaInterfaceWifiStatus!", __func__);
    if (ifName == NULL || status == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%s", "STATUS") < 0) {
        return HDF_FAILURE;
    }
    wpaSupp = getWpaWlan();
    if (wpaSupp != NULL) {
        HDF_LOGI("%{public}s call wpa_supplicant_ctrl_iface_status!", __func__);
        replyLen = wpa_supplicant_ctrl_iface_status(wpaSupp, cmd + CMD_LEN, reply, REPLY_SIZE);
    } else {
        HDF_LOGE("%{public}s wpaSupp is NULL", __func__);
    }
    status->bssidLen = 0;
    status->ssidLen = 0;
    status->keyMgmtLen = 0;
    status->addressLen = 0;
    WapDealWifiStatus(reply, status);
    if (status->addressLen == 0) {
        HDF_LOGE("%{public}s key not include address", __func__);
    }
    if (status->bssidLen == 0) {
        HDF_LOGE("%{public}s key not include bssid", __func__);
    }
    HDF_LOGI("%{public}s WpaInterfaceWifiStatus success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceSaveConfig(struct IWpaInterface *self, const char *ifName)
{
    struct wpa_supplicant *wpaSupp;
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaWlan();
    if (wpaSupp == NULL) {
        HDF_LOGE("%{public}s wpaSupp == NULL", __func__);
        return HDF_FAILURE;
    }
    ret = wpa_supplicant_ctrl_iface_save_config(wpaSupp);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s set config fail!", __func__);
    }
    return ret;
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
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];
    int32_t ret = HDF_FAILURE;
    int res = 0;
    int pos = 0;

    (void)self;
    if (ifName == NULL || wpaParam == NULL || wpaParam->bssid == NULL || wpaParam->pinCode == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaWlan();
    if (wpaSupp == NULL) {
        HDF_LOGE("%{public}s wpaSupp == NULL", __func__);
        return HDF_FAILURE;
    }
    if (wpaParam->anyFlag == 1) {
        res = snprintf_s(cmd + pos, sizeof(cmd) - pos, sizeof(cmd) - pos - 1, "%s", "any");
    } else if (wpaParam->bssidLen > 0) {
        res = snprintf_s(cmd + pos, sizeof(cmd) - pos, sizeof(cmd) - pos - 1, "%s", macToStr(wpaParam->bssid));
    }
    if (res < 0) {
        HDF_LOGE("%{public}s snprintf err", __func__);
        return HDF_FAILURE;
    }
    pos += res;
    if (wpaParam->multiAp > 0) { /* The value of ap needs to be determined. The value is greater than 0. */
        res = snprintf_s(
            cmd + pos, sizeof(cmd) - pos, sizeof(cmd) - pos - 1, " multi_ap=%d", wpaParam->multiAp);
        if (res < 0) {
            HDF_LOGE("%{public}s snprintf err2", __func__);
            return HDF_FAILURE;
        }
    }
    ret = wpa_supplicant_ctrl_iface_wps_pbc(wpaSupp, cmd);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s set wps pbcfail!", __func__);
    }
    return ret;
}

int32_t WpaInterfaceWpsPinMode(struct IWpaInterface *self, const char *ifName,
    const struct HdiWifiWpsParam *wpaParam, int *pinCode)
{
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];
    char reply[REPLY_SIZE];
    int32_t ret = HDF_FAILURE;
    int res = 0;
    int pos = 0;

    (void)self;
    if (ifName == NULL || wpaParam == NULL || wpaParam->bssid == NULL
        || wpaParam->pinCode == NULL || pinCode == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaWlan();
    if (wpaParam->bssidLen > 0) {
        res = snprintf_s(cmd + pos, sizeof(cmd) - pos, sizeof(cmd) - pos - 1, "%s", macToStr(wpaParam->bssid));
    } else {
        res = snprintf_s(cmd + pos, sizeof(cmd) - pos, sizeof(cmd) - pos - 1, "any");
    }
    if (res < 0) {
        HDF_LOGE("%{public}s snprintf err", __func__);
        return HDF_FAILURE;
    }
    pos += res;
    if (wpaParam->pinCodeLen > 0) {
        res = snprintf_s(cmd + pos, sizeof(cmd) - pos, sizeof(cmd) - pos - 1, "%s", wpaParam->pinCode);
        if (res < 0) {
            HDF_LOGE("%{public}s snprintf err2", __func__);
            return HDF_FAILURE;
        }
    }
    ret = wpa_supplicant_ctrl_iface_wps_pin(wpaSupp, cmd, reply, REPLY_SIZE);
    if (ret > 0) {
        *pinCode = atoi(reply);
    } else {
        HDF_LOGE("%{public}s wps pin fail!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t WpaInterfaceWpsCancel(struct IWpaInterface *self, const char *ifName)
{
    struct wpa_supplicant *wpaSupp;
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaWlan();
    if (wpaSupp == NULL) {
        HDF_LOGE("%{public}s wpaSupp == NULL", __func__);
        return HDF_FAILURE;
    }
    ret = wpas_wps_cancel(wpaSupp);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s set wps pbc cancel fail!", __func__);
    }
    return ret;
}

//need to deal countryCodeLen
int32_t WpaInterfaceGetCountryCode(struct IWpaInterface *self, const char *ifName,
    char *countryCode, uint32_t countryCodeLen)
{
    struct wpa_supplicant *wpaSupp;
    int32_t ret = HDF_FAILURE;

    (void)self;
    HDF_LOGI("enter %{public}s: ", __func__);
    if (ifName == NULL || countryCode == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaWlan();
    if (wpaSupp == NULL) {
        HDF_LOGE("%{public}s wpaSupp == NULL", __func__);
        return HDF_FAILURE;
    }
    if (wpaSupp->conf->country[0] && wpaSupp->conf->country[1]) {
        char tmpCountryCode[WIFI_COUNTRY_CODE_MAXLEN + 1] = {0};
        ret = os_snprintf(tmpCountryCode, WIFI_COUNTRY_CODE_MAXLEN + 1, "%c%c",
            wpaSupp->conf->country[0], wpaSupp->conf->country[1]);
        HDF_LOGI("%{public}s: tmpCountryCode = %s", __func__, tmpCountryCode);
        if (strcpy_s(countryCode, countryCodeLen, tmpCountryCode) != EOK) {
            HDF_LOGE("%{public}s: copy countryCode failed!", __func__);
            return HDF_FAILURE;
        }
    }
    return HDF_SUCCESS;
}

//need to deal valueLen
int32_t WpaInterfaceGetNetwork(struct IWpaInterface *self, const char *ifName,
    const int32_t networkId, const char *param, char *value, uint32_t valueLen)
{
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];
    char reply[REPLY_SIZE] = {0};
    int replyLen;
    int32_t ret = HDF_FAILURE;
 
    (void)self;
    if (ifName == NULL || param == NULL || value == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaWlan();
    if (wpaSupp == NULL) {
        HDF_LOGE("%{public}s wpaSupp == NULL", __func__);
        return HDF_FAILURE;
    }
    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%d %s", networkId, param);
    if (ret < 0) {
        HDF_LOGE("%{public}s get network fail!", __func__);
        return HDF_FAILURE;
    }
    replyLen = wpa_supplicant_ctrl_iface_get_network(wpaSupp, cmd, reply, REPLY_SIZE);
    if (strncpy_s(value, valueLen, reply, strlen(reply)) != EOK) {
        HDF_LOGE("%{public}s copy get_network result failed!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t WpaInterfaceBlocklistClear(struct IWpaInterface *self, const char *ifName)
{
    struct wpa_supplicant *wpaSupp;

    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaWlan();
    if (wpaSupp == NULL) {
        HDF_LOGE("%{public}s wpaSupp == NULL", __func__);
        return HDF_FAILURE;
    }
    wpa_bssid_ignore_clear(wpaSupp);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceSetSuspendMode(struct IWpaInterface *self, const char *ifName, const int32_t mode)
{
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaWlan();
    if (wpaSupp == NULL) {
        HDF_LOGE("%{public}s wpaSupp == NULL", __func__);
        return HDF_FAILURE;
    }
    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, " %s %d ", "SETSUSPENDMODE", mode);
    if (ret < 0) {
        HDF_LOGE("%{public}s set suspend mode fail!", __func__);
        return HDF_FAILURE;
    }
    #if defined(CONFIG_DRIVER_NL80211_HISI)
    char reply[REPLY_SIZE] = {0};
    ret = wpa_supplicant_driver_cmd(wpaSupp, cmd, reply, REPLY_SIZE);
    #else
    ret = HDF_FAILURE ;
    #endif
    return ret;
}

static void WpaGetConnectionCapabilities(struct wpa_supplicant *wpaSupp,
    struct ConnectionCapabilities *connectionCap)
{
    if (wpaSupp->connection_set) {
        connectionCap->legacyMode = UNKNOWN_MODE;
        if (wpaSupp->connection_he) {
            connectionCap->technology = HE;
        } else if (wpaSupp->connection_vht) {
            connectionCap->technology = VHT;
        } else if (wpaSupp->connection_ht) {
            connectionCap->technology = HT;
        } else {
            connectionCap->technology = LEGACY;
            if (wpas_freq_to_band(wpaSupp->assoc_freq) == BAND_2_4_GHZ) {
                connectionCap->legacyMode = (wpaSupp->connection_11b_only) ? B_MODE
                        : G_MODE;
            } else {
                connectionCap->legacyMode = A_MODE;
            }
        }
    switch (wpaSupp->connection_channel_bandwidth) {
        case CHAN_WIDTH_20:
            connectionCap->channelBandwidth = WIDTH_20;
            break;
        case CHAN_WIDTH_40:
            connectionCap->channelBandwidth = WIDTH_40;
            break;
        case CHAN_WIDTH_80:
            connectionCap->channelBandwidth = WIDTH_80;
            break;
        case CHAN_WIDTH_160:
            connectionCap->channelBandwidth = WIDTH_160;
            break;
        case CHAN_WIDTH_80P80:
            connectionCap->channelBandwidth = WIDTH_80P80;
            break;
        default:
            connectionCap->channelBandwidth = WIDTH_20;
            break;
        }
        connectionCap->maxNumberRxSpatialStreams = wpaSupp->connection_max_nss_rx;
        connectionCap->maxNumberTxSpatialStreams = wpaSupp->connection_max_nss_tx;
    } else {
        connectionCap->technology = UNKNOWN_TECHNOLOGY;
        connectionCap->channelBandwidth = WIDTH_20;
        connectionCap->maxNumberTxSpatialStreams = 1;
        connectionCap->maxNumberRxSpatialStreams = 1;
        connectionCap->legacyMode = UNKNOWN_MODE;
    }
}

int32_t WpaInterfaceGetConnectionCapabilities(struct IWpaInterface *self, const char *ifName,
    struct ConnectionCapabilities *connectionCap)
{
    struct wpa_supplicant *wpaSupp;

    (void)self;
    if (ifName == NULL || connectionCap == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaWlan();
    if (wpaSupp == NULL) {
        HDF_LOGE("%{public}s wpaSupp == NULL", __func__);
        return HDF_FAILURE;
    }
    WpaGetConnectionCapabilities(wpaSupp, connectionCap);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceGetScanSsid(struct IWpaInterface *self, const char *ifName, int32_t *enable)
{
    struct wpa_supplicant *wpaSupp;
    int scanSsid = 0;
    int32_t ret = HDF_FAILURE;
   
    (void)self;
    HDF_LOGI("%{public}s GetScanSsid !", __func__);
    if (ifName == NULL || enable == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaWlan();
    if ((wpaSupp != NULL) && (wpaSupp->current_ssid != NULL)) {
        scanSsid = wpaSupp->current_ssid->scan_ssid;
        *enable = (scanSsid == 1);
        HDF_LOGI("%{public}s GetScanSsid *enable = %{public}d", __func__, *enable);
        ret = HDF_SUCCESS ;
    } else {
        HDF_LOGE("%{public}s GetScanSsid fail", __func__);
    }
    return ret;
}

int32_t WpaInterfaceGetPskPassphrase(struct IWpaInterface *self, const char *ifName,
    char *psk, uint32_t pskLen)
{
    struct wpa_supplicant *wpaSupp;
    int32_t ret = HDF_FAILURE;

    (void)self;
    HDF_LOGI("%{public}s GetPskPassphrase !", __func__);
    if (ifName == NULL || psk == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaWlan();
    if ((wpaSupp != NULL) && (wpaSupp->current_ssid != NULL) &&
        (wpaSupp->current_ssid->passphrase != NULL)) {
        if (strncpy_s(psk, pskLen, wpaSupp->current_ssid->passphrase,
            strlen(wpaSupp->current_ssid->passphrase)) != EOK) {
            HDF_LOGE("%{public}s copy passphrase failed!", __func__);
            return HDF_FAILURE;
        }
        HDF_LOGI("%{public}s GetPskPassphrase psk = %{public}s", __func__, psk);
        ret = HDF_SUCCESS ;
    } else {
        HDF_LOGE("%{public}s GetPskPassphrase fail", __func__);
    }
    return ret;
}
int32_t WpaInterfaceGetPsk(struct IWpaInterface *self, const char *ifName, uint8_t *psk, uint32_t *pskLen)
{
    struct wpa_supplicant *wpaSupp;
    int32_t ret = HDF_FAILURE;

    (void)self;
    HDF_LOGI("%{public}s WpaInterfaceGetPsk !", __func__);
    if (ifName == NULL || psk == NULL || pskLen == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaWlan();
    if ((wpaSupp != NULL) && (wpaSupp->current_ssid != NULL)) {
        *pskLen = sizeof(wpaSupp->current_ssid->psk);
        os_memcpy(psk, wpaSupp->current_ssid->psk, *pskLen);
        HDF_LOGI("%{public}s GetPsk  psk[0] = %{public}d", __func__, psk[0]);
        HDF_LOGI("%{public}s GetPsk  psk[1] = %{public}d", __func__, psk[1]);
        ret = HDF_SUCCESS ;
    } else {
        HDF_LOGE("%{public}s GetPsk fail", __func__);
    }
    return ret;
}

int32_t WpaInterfaceGetWepKey(struct IWpaInterface *self, const char *ifName, int keyIdx,
    uint8_t *wepKey, uint32_t *wepKeyLen)
{
    struct wpa_supplicant *wpaSupp;
    int32_t ret = HDF_FAILURE;

    (void)self;
    HDF_LOGI("%{public}s WpaInterfaceGetWepKey !", __func__);
    if (ifName == NULL || wepKey == NULL || wepKeyLen == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaWlan();
    if ((wpaSupp != NULL) && (wpaSupp->current_ssid != NULL)) {
        *wepKeyLen = wpaSupp->current_ssid->wep_key_len[keyIdx];
        os_memcpy(wepKey, wpaSupp->current_ssid->wep_key[keyIdx], *wepKeyLen);
        HDF_LOGI("%{public}s GetWepKey  wepKey[0] = %{public}d", __func__, wepKey[0]);
        HDF_LOGI("%{public}s GetWepKey  wepKey[1] = %{public}d", __func__, wepKey[1]);
        ret = HDF_SUCCESS ;
    } else {
        HDF_LOGE("%{public}s GetWepKey fail", __func__);
    }
    return ret;
}

int32_t WpaInterfaceGetWepTxKeyIdx(struct IWpaInterface *self, const char *ifName, int *keyIdx)
{
    struct wpa_supplicant *wpaSupp;
    int32_t ret = HDF_FAILURE;

    (void)self;
    HDF_LOGI("%{public}s WpaInterfaceGetWepTxKeyIdx !", __func__);
    if (ifName == NULL || keyIdx == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaWlan();
    if ((wpaSupp != NULL) && (wpaSupp->current_ssid != NULL)) {
        *keyIdx = wpaSupp->current_ssid->wep_tx_keyidx;
        HDF_LOGI("%{public}s GetWepTxKeyIdx  *keyIdx = %{public}d", __func__, *keyIdx);
        ret = HDF_SUCCESS ;
    } else {
        HDF_LOGE("%{public}s GetWepTxKeyIdx fail", __func__);
    }
    return ret;
}

int32_t WpaInterfaceGetRequirePmf(struct IWpaInterface *self, const char *ifName, int *enable)
{
    struct wpa_supplicant *wpaSupp;
    int32_t ret = HDF_FAILURE;

    (void)self;
    HDF_LOGI("%{public}s WpaInterfaceGetWepTxKeyIdx !", __func__);
    if (ifName == NULL || enable == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaWlan();
    if ((wpaSupp != NULL) && (wpaSupp->current_ssid != NULL)) {
        *enable = (wpaSupp->current_ssid->ieee80211w == MGMT_FRAME_PROTECTION_REQUIRED);
        HDF_LOGI("%{public}s GetRequirePmf  *enable = %{public}d", __func__, *enable);
        ret = HDF_SUCCESS ;
    } else {
        HDF_LOGE("%{public}s GetRequirePmf fail", __func__);
    }
    return ret;
}

int32_t WpaInterfaceSetCountryCode(struct IWpaInterface *self, const char *ifName, const char *countryCode)
{
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE] = {0};
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (ifName == NULL || countryCode == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaWlan();
    if (wpaSupp == NULL) {
        HDF_LOGE("%{public}s wpaSupp == NULL", __func__);
        return HDF_FAILURE;
    }
    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "COUNTRY %s", countryCode);
    if (ret < 0) {
        HDF_LOGE("%{public}s set country code fail!", __func__);
        return HDF_FAILURE;
    }
    #if defined(CONFIG_DRIVER_NL80211_HISI)
    char reply[REPLY_SIZE] = {0};
    ret = wpa_supplicant_driver_cmd(wpaSupp, cmd, reply, REPLY_SIZE);
    HDF_LOGI("%{public}s SetCountryCode  ret = %{public}d", __func__, ret);
    #else
    ret = HDF_FAILURE;
    HDF_LOGE("%{public}s SetCountryCode fail", __func__);
    #endif
    return ret;
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
        }
        if (hdiWpaBssidChangedParam->reason != NULL) {
            OsalMemFree(hdiWpaBssidChangedParam->reason);
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
        }
        if (hdiWpaStateChangedParam->ssid != NULL) {
            OsalMemFree(hdiWpaStateChangedParam->ssid);
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
        }
        if (hdiWpaTempDisabledParam->ssid != NULL) {
            OsalMemFree(hdiWpaTempDisabledParam->ssid);
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

static int32_t HdfWpaDealEvent(uint32_t event, struct HdfWpaRemoteNode *pos, void *data, const char *ifName)
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

static int32_t HdfWpaCallbackFun(uint32_t event, void *data, const char *ifName)
{
    struct HdfWpaRemoteNode *pos = NULL;
    struct DListHead *head = NULL;
    int32_t ret = HDF_FAILURE;

    (void)OsalMutexLock(&HdfWpaStubDriver()->mutex);
    head = &HdfWpaStubDriver()->remoteListHead;
    HDF_LOGD("%s: enter HdfWpaCallbackFun event =%d", __FUNCTION__, event);
    if (data == NULL || ifName == NULL) {
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
        ret = HdfWpaDealEvent(event, pos, data, ifName);
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
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (cbFunc == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    (void)OsalMutexLock(&HdfWpaStubDriver()->mutex);
    HdfWpaDelRemoteObj(cbFunc);
    if (DListIsEmpty(&HdfWpaStubDriver()->remoteListHead)) {
        ret = WpaUnregisterEventCallback(HdfWpaCallbackFun, WIFI_WPA_TO_HAL_CLIENT, ifName);
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
    HDF_LOGI("%{public}s: pthread_create ID: %{public}p.", __func__, (void*)g_tid);
    usleep(WPA_SLEEP_TIME);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceAddWpaIface(struct IWpaInterface *self, const char *ifName, const char *confName)
{
    HDF_LOGI("%{public}s Ready to add iface, ifName: %{public}s, confName: %{public}s", __func__, ifName, confName);
    struct wpa_global *wpa_g;
    int32_t ret;
    int32_t result;
    char cmd[WPA_CMD_BUF_LEN] = {0};
    
    (void)self;
    if (ifName == NULL || confName == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM ;
    }
    wpa_g = getWpaGlobal();
    if (wpa_g == NULL) {
        HDF_LOGE("%{public}s: wpa_g is null.", __func__);
        return HDF_FAILURE;
    }
    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%s\t%s", ifName, confName);
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }
    result =  wpa_supplicant_global_iface_add(wpa_g, cmd);
    if (result != HDF_SUCCESS) {
        HDF_LOGE("%{public}s add interface failed, cmd: %{public}s, result: %{public}d", __func__, cmd, result);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s Add interface finish, cmd: %{public}s", __func__, cmd);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceRemoveWpaIface(struct IWpaInterface *self, const char *ifName)
{
    struct wpa_global *wpa_g;
    char *name;

    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM ;
    }
    wpa_g = getWpaGlobal();
    if (wpa_g == NULL) {
        HDF_LOGE("%{public}s: wpa_g is null.", __func__);
        return HDF_FAILURE;
    }
    name = strdup(ifName);
    if (wpa_supplicant_global_iface_remove(wpa_g, name) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Failed to remove wpa iface!", __func__);
        free(name);
        return HDF_FAILURE;
    }
    free(name);
    HDF_LOGI("%{public}s remove wpa interface finish, ifName: %{public}s", __func__, ifName);
    return HDF_SUCCESS;
}

static int32_t StopWpaSupplicant(void)
{
    /*Do nothing here,waiting for IWpaInterfaceReleaseInstance to destroy the wpa service. */
    HDF_LOGI("%{public}s: wpa_supplicant stop successfully!", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceStart(struct IWpaInterface *self)
{
    int32_t ret;

    (void)self;
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
    ret = StopWpaSupplicant();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Wifi stop failed, error code: %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s: wpa_supplicant stop successfully!", __func__);
    return HDF_SUCCESS;
}
