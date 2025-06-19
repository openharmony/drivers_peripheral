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
#include "hdi_wpa_common.h"
#include <securec.h>
#include <hdf_base.h>
#include <hdf_log.h>
#include <osal_time.h>
#include <osal_mem.h>
#include <arpa/inet.h>
#include "utils/common.h"
#include "wpa_supplicant_i.h"
#include "main.h"
#include "wps_supplicant.h"
#include "p2p_supplicant.h"
#include "ctrl_iface.h"
#include "wpa_magiclink.h"
#include "wifi_display.h"
#include "bssid_ignore.h"
#include "config.h"
#include "v2_0/iwpa_callback.h"
#include "v2_0/iwpa_interface.h"
#include "wpa_p2p_hal.h"

#define HEX_TO_DEC_MOVING 4
#define DEC_MAX_SCOPE 10
#define MIN_MAC_LEN 6
#define LIST_BUF_LEN 200
#define LIST_BUF_TYPE 5
#define LIST_ID_OFFSET 0
#define LIST_SSID_OFFSET 1
#define LIST_BSSID_OFFSET 2
#define LIST_FLAG_OFFSET 3
#define LIST_CLIENLIST_OFFSET 4

struct HdiWpaKeyValue {
    char key[CMD_SIZE];
    char value[CMD_SIZE];
};

void GetStrKeyVal(char *src, const char *split, struct HdiWpaKeyValue *out)
{
    if (src == NULL || split == NULL || out == NULL) {
        return;
    }
    char *p = strstr(src, split);
    if (p == NULL) {
        if (strcpy_s(out->key, sizeof(out->key), src) != EOK) {
            HDF_LOGE("%{public}s strcpy failed", __func__);
        }
        return;
    }
    *p = '\0';
    if (strcpy_s(out->key, sizeof(out->key), src) != EOK) {
        HDF_LOGE("%{public}s strcpy failed", __func__);
    }
    p += strlen(split);
    if (strcpy_s(out->value, sizeof(out->value), p) != EOK) {
        HDF_LOGE("%{public}s strcpy failed", __func__);
    }
    return;
}

static void GetSsidInfo(char *res, struct HdiP2pNetworkInfo *info)
{
    if (strcpy_s((char *)info->ssid, WIFI_SSID_LENGTH, res) != EOK) {
        HDF_LOGE("%{public}s strcpy failed", __func__);
        return;
    }
    printf_decode((u8 *)info->ssid, WIFI_SSID_LENGTH, (char *)info->ssid);
}

static void GetBssidInfo(char *res, struct HdiP2pNetworkInfo *info)
{
    uint8_t tmpBssid[ETH_ADDR_LEN] = {0};
    hwaddr_aton(res, tmpBssid);
    if (memcpy_s((char *)info->bssid, ETH_ADDR_LEN, (char *)tmpBssid, ETH_ADDR_LEN) != EOK) {
        HDF_LOGE("%{public}s memcpy_s failed", __func__);
        return;
    }
    info->bssid[ETH_ADDR_LEN] = '\0';
}

static void GetFlagInfo(char *res, struct HdiP2pNetworkInfo *info)
{
    int falgLen = strlen(res);
    info->flags = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (falgLen + 1));
    if (info->flags == NULL) {
        HDF_LOGE("malloc flags failed!");
        return;
    }
    info->flagsLen = falgLen + 1;
    if (strcpy_s((char *)info->flags, falgLen + 1, res) != EOK) {
        HDF_LOGE("GetFlagInfo strcpy_s failed!");
    }
}

static void GetClientListInfo(char *res, struct HdiP2pNetworkInfo *info)
{
    int clientLen = strlen(res);
    info->clientList = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (clientLen + 1));
    if (info->clientList == NULL) {
        HDF_LOGE("malloc client list failed!");
        return;
    }
    info->clientListLen = clientLen + 1;
    if (strcpy_s((char *)info->clientList, clientLen + 1, res) != EOK) {
        HDF_LOGE("GetClientListInfo strcpy_s failed!");
    }
}

void GetHalNetworkInfos(char *buf, struct HdiP2pNetworkInfo *info)
{
    /* The buf format is as follows:
     * id'\t'ssid'\t'bssid'\t'flag'\t'clientlist
     * In the format, clientlist exists when the device is go
     */
    if (buf == NULL || info == NULL) {
        return;
    }
    char *tmp = buf;
    int i = 0;
    char res[LIST_BUF_TYPE][LIST_BUF_LEN] = {0};
    char *pos = strstr(buf, "\t");
    if (pos == NULL) {
        HDF_LOGE("invaild str, return");
        return;
    }
    while (pos != NULL) {
        if (i >= LIST_BUF_TYPE) {
            break;
        }
        if (memcpy_s(res[i], LIST_BUF_LEN, tmp, pos - tmp) != EOK) {
            HDF_LOGE("%{public}s memcpy_s failed %{public}d", __func__, i);
            return;
        }
        if (pos - tmp + 1 >= LIST_BUF_LEN) {
            HDF_LOGE("%{public}s tmp len is max, i is %{public}d", __func__, i);
            return;
        } else {
            res[i][pos - tmp + 1] = '\0';
        }
        pos += 1;
        tmp = pos;
        pos = strstr(pos, "\t");
        i++;
    }
    if (memcpy_s(res[i], LIST_BUF_LEN, tmp, strlen(tmp)) != EOK) {
        HDF_LOGE("%{public}s memcpy_s failed %{public}d", __func__, i);
        return;
    }
    if (strlen(tmp) >= LIST_BUF_LEN) {
        HDF_LOGE("%{public}s tmp len is max, i is %{public}d", __func__, i);
        return;
    } else {
        res[i][strlen(tmp)] = '\0';
    }
    info->id = atoi(res[LIST_ID_OFFSET]);
    GetSsidInfo(res[LIST_SSID_OFFSET], info);
    GetBssidInfo(res[LIST_BSSID_OFFSET], info);
    /* The memory alloced for the info structure will be released by wifi_manager_service. */
    GetFlagInfo(res[LIST_FLAG_OFFSET], info);
    if (i == LIST_CLIENLIST_OFFSET) {
        GetClientListInfo(res[LIST_CLIENLIST_OFFSET], info);
    }
    return;
}

int32_t WpaInterfaceP2pSetSsidPostfixName(struct IWpaInterface *self, const char *ifName, const char *name)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL || name == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdSetSsidPostfixName(pMainIfc, name);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSetWpsDeviceType(struct IWpaInterface *self, const char *ifName, const char *type)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL || type == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdSetWpsDeviceType(pMainIfc, type);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSetWpsConfigMethods(struct IWpaInterface *self, const char *ifName, const char *methods)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL || methods == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdSetWpsConfigMethods(pMainIfc, methods);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSetGroupMaxIdle(struct IWpaInterface *self, const char *ifName, int32_t time)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    WifiWpaP2pGroupInterface *pGroupIfc = GetWifiWpaP2pGroupInterface(ifName);
    if (pGroupIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pGroupIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pGroupIfc->wpaP2pCliCmdSetGroupIdle(pGroupIfc, time);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSetWfdEnable(struct IWpaInterface *self, const char *ifName, int32_t enable)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    (void)ifName;
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdSetWfdEnable(pMainIfc, enable);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSetPersistentReconnect(struct IWpaInterface *self, const char *ifName, int32_t status)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    (void)ifName;
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdSetPersistentReconnect(pMainIfc, status);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSetWpsSecondaryDeviceType(struct IWpaInterface *self, const char *ifName, const char *type)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL || type == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdSetWpsSecDeviceType(pMainIfc, type);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSetupWpsPbc(struct IWpaInterface *self, const char *ifName, const char *address)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL || address == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    WifiWpaP2pGroupInterface *pGroupIfc = GetWifiWpaP2pGroupInterface(ifName);
    if (pGroupIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pGroupIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pGroupIfc->wpaP2pCliCmdWpsPbc(pGroupIfc, address);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSetupWpsPin(struct IWpaInterface *self, const char *ifName, const char *address,
    const char *pin, char *result, uint32_t resultLen)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL || address == NULL || pin == NULL || result == NULL || resultLen == 0) {
        HDF_LOGE("%{public}s groupIfc, address, pin and result have NULL", __func__);
        return HDF_FAILURE;
    }

    P2pWpsPinDisplayArgv p2pWpsPinDisplay = {0};
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    WifiWpaP2pGroupInterface *pGroupIfc = GetWifiWpaP2pGroupInterface(ifName);
    if (pMainIfc == NULL || pGroupIfc == NULL) {
        HDF_LOGE("%{public}s: pMainIfc or pGroupIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pGroupIfc->wpaP2pCliCmdWpsPin(pGroupIfc, &p2pWpsPinDisplay);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        HDF_LOGE("WpaP2pCliCmdWpsPin fail, ret = %{public}d", ret);
        return HDF_FAILURE;
    }
    if (strlen(pin) > 0) {
        p2pWpsPinDisplay.mode = P2P_PIN_KEYPAD;
        if (strncpy_s(p2pWpsPinDisplay.pinCode, sizeof(p2pWpsPinDisplay.pinCode), pin, strlen(pin)) != EOK) {
            HDF_LOGE("%{public}s: Failed to init pin code, the input pin code may be invalid!", __func__);
            return HDF_FAILURE;
        }
    } else {
        p2pWpsPinDisplay.mode = P2P_PIN_DISPLAY;
        if ((strncpy_s(p2pWpsPinDisplay.bssid, sizeof(p2pWpsPinDisplay.bssid), address, strlen(address)) != EOK) ||
            (strncpy_s(result, resultLen, p2pWpsPinDisplay.pinCode, strlen(p2pWpsPinDisplay.pinCode)) != EOK)) {
            HDF_LOGE("%{public}s: Failed to init request message, the input message may be invalid!", __func__);
            return HDF_FAILURE;
        }
    }
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSetPowerSave(struct IWpaInterface *self, const char *ifName, int32_t enable)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("P2pSetPowerSave, groupIfc is NULL");
        return HDF_FAILURE;
    }
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    WifiWpaP2pGroupInterface *pGroupIfc = GetWifiWpaP2pGroupInterface(ifName);
    if (pGroupIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pGroupIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pGroupIfc->wpaP2pCliCmdSetPowerSave(pGroupIfc, enable);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSetDeviceName(struct IWpaInterface *self, const char *ifName, const char *name)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL || name == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdSetWpsName(pMainIfc, name);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSetWfdDeviceConfig(struct IWpaInterface *self, const char *ifName, const char *config)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL || config == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdSetWfdDeviceInfo(pMainIfc, config);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSetRandomMac(struct IWpaInterface *self, const char *ifName, int32_t networkId)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    (void)ifName;
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdSetRandomMac(pMainIfc, networkId);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pStartFind(struct IWpaInterface *self, const char *ifName, int32_t timeout)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    (void)ifName;
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdP2pFound(pMainIfc, timeout);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSetExtListen(struct IWpaInterface *self, const char *ifName, int32_t enable,
    int32_t period, int32_t interval)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    (void)ifName;
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdExtListen(pMainIfc, enable, period, interval);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSetListenChannel(struct IWpaInterface *self, const char *ifName,
    int32_t channel, int32_t regClass)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    (void)ifName;
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdSetListenChannel(pMainIfc, channel, regClass);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pProvisionDiscovery(struct IWpaInterface *self, const char *ifName,
    const char *peerBssid, int32_t mode)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL || peerBssid == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(GetInterfaceLock());
    P2pProvisionDiscoveryArgv p2pProvision;
    if (memset_s(&p2pProvision, sizeof(p2pProvision), 0, sizeof(p2pProvision)) != EOK ||
        strncpy_s(p2pProvision.peerbssid, sizeof(p2pProvision.peerbssid), peerBssid, strlen(peerBssid)) != EOK) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("Failed to init request message, the input message may be invalid!");
        return HDF_FAILURE;
    }
    p2pProvision.mode = mode;
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdProvisionDiscovery(pMainIfc, &p2pProvision);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pAddGroup(struct IWpaInterface *self, const char *ifName, int32_t isPersistent,
    int32_t networkId, int32_t freq)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    (void)ifName;
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdGroupAdd(pMainIfc, isPersistent, networkId, freq);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pAddService(struct IWpaInterface *self, const char *ifName,
    const struct HdiP2pServiceInfo *info)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL || info == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdServiceAdd(pMainIfc, info);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pRemoveService(struct IWpaInterface *self, const char *ifName,
    const struct HdiP2pServiceInfo *info)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL || info == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdServiceDel(pMainIfc, info);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pStopFind(struct IWpaInterface *self, const char *ifName)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    (void)ifName;
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdP2pStopFind(pMainIfc);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pFlush(struct IWpaInterface *self, const char *ifName)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    (void)ifName;
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdFlush(pMainIfc);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pFlushService(struct IWpaInterface *self, const char *ifName)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    (void)ifName;
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdFlushService(pMainIfc);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pRemoveNetwork(struct IWpaInterface *self, const char *ifName, int32_t networkId)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    (void)ifName;
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdRemoveNetwork(pMainIfc, networkId);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSetGroupConfig(struct IWpaInterface *self, const char *ifName, const int32_t networkId,
    const char *name, const char *value)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    char cmd[CMD_SIZE] = {0};
    char buf[CMD_SIZE] = {0};
    int32_t ret = 0;
    (void)self;
    if (ifName == NULL || name == NULL || value == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(GetInterfaceLock());
    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s SET_NETWORK %d %s %s",
        ifName, networkId, name, value);
    if (ret < 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{private}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }
    if (WpaCliCmd(cmd, buf, sizeof(buf)) != 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s command failed!", __func__);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pInvite(struct IWpaInterface *self, const char *ifName,
    const char *peerBssid, const char *goBssid)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    if (peerBssid == NULL || goBssid == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: peerBssid, goBssid and ifname have NULL", __func__);
        return HDF_FAILURE;
    }
    pthread_mutex_lock(GetInterfaceLock());
    P2pHalInviteArgv p2pHalInvite;
    if (memset_s(&p2pHalInvite, sizeof(p2pHalInvite), 0, sizeof(p2pHalInvite)) != EOK ||
        strncpy_s(p2pHalInvite.peerbssid, sizeof(p2pHalInvite.peerbssid), peerBssid, strlen(peerBssid)) != EOK ||
        strncpy_s(p2pHalInvite.gobssid, sizeof(p2pHalInvite.gobssid), goBssid, strlen(goBssid)) != EOK ||
        strncpy_s(p2pHalInvite.ifname, sizeof(p2pHalInvite.ifname), ifName, strlen(ifName)) != EOK) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("Failed to init request message, the input message may be invalid!");
        return HDF_FAILURE;
    }
    p2pHalInvite.persistent = 0;
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdInvite(pMainIfc, &p2pHalInvite);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pReinvoke(struct IWpaInterface *self, const char *ifName, const int32_t networkId,
    const char *bssid)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL || bssid == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(GetInterfaceLock());
    P2pHalReInviteArgv p2pHalReInvite;
    if (memset_s(&p2pHalReInvite, sizeof(p2pHalReInvite), 0, sizeof(p2pHalReInvite)) != EOK ||
        strncpy_s(p2pHalReInvite.peerbssid, sizeof(p2pHalReInvite.peerbssid), bssid, strlen(bssid)) != EOK) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("Failed to init request message, the input message may be invalid!");
        return HDF_FAILURE;
    }
    p2pHalReInvite.networkId = networkId;
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdReInvite(pMainIfc, &p2pHalReInvite);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pGetDeviceAddress(struct IWpaInterface *self, const char *ifName, char *deviceAddress,
    uint32_t deviceAddressLen)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    if (ifName == NULL || deviceAddress == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    (void)self;
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdGetDeviceAddress(pMainIfc, deviceAddress, deviceAddressLen);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pReqServiceDiscovery(struct IWpaInterface *self, const char *ifName,
    const struct HdiP2pReqService *reqService, char *replyDisc, uint32_t replyDiscLen)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    if (ifName == NULL || reqService == NULL || replyDisc == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    (void)self;
    char seq[WIFI_P2P_SERVER_DISCOVERY_SEQUENCE_LENGTH] = {0};
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdServDiscReq(pMainIfc, (char *)reqService->bssid,
        (char *)reqService->msg, seq, sizeof(seq));
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    if (strncpy_s(replyDisc, replyDiscLen, seq, strlen(seq)) != EOK) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: fail", __func__);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pCancelServiceDiscovery(struct IWpaInterface *self, const char *ifName, const char *id)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL || id == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdServDiscCancelReq(pMainIfc, id);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pRespServerDiscovery(struct IWpaInterface *self, const char *ifName,
    const struct HdiP2pServDiscReqInfo *info)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    if (ifName == NULL || info == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    (void)self;
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdRespServerDiscovery(pMainIfc, info);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("WpaP2pCliCmdRespServerDiscovery fail, ret = %{public}d", ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pConnect(struct IWpaInterface *self, const char *ifName, const struct HdiP2pConnectInfo *info,
    char *replyPin, uint32_t replyPinLen)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    if (ifName == NULL || info == NULL || replyPin == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(GetInterfaceLock());
    char *reply;
    const int replySize = REPLY_SIZE;
    char cmd[CMD_SIZE] = {0};
    char join[CMD_SIZE] = {0};
    char mode[CMD_SIZE] = {0};
    char pin[CMD_SIZE] = {0};
    char peerDevAddr[CMD_SIZE] = {0};
    if (memcpy_s(pin, CMD_SIZE, info->pin, info->pinLen) != EOK) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s strcpy failed", __func__);
        return HDF_FAILURE;
    }

    if (memcpy_s(peerDevAddr, CMD_SIZE, info->peerDevAddr, info->peerDevAddrLen) != EOK) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s strcpy failed", __func__);
        return HDF_FAILURE;
    }

    reply = (char *)malloc(replySize);
    if (reply == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s reply is NULL!", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = 0;
    (void)self;

    if (info->mode != 0) {
        if (strcpy_s(join, sizeof(join), " join") != EOK) {
            HDF_LOGE("%{public}s strcpy failed", __func__);
        }
    } else {
        if (snprintf_s(join, sizeof(join), sizeof(join) - 1, " go_intent=%d", info->goIntent) < 0) {
            pthread_mutex_unlock(GetInterfaceLock());
            HDF_LOGE("%{public}s input parameter invalid!", __func__);
            free(reply);
            return HDF_ERR_INVALID_PARAM;
        }
    }

    if (info->provdisc == P2P_WPS_METHOD_DISPLAY) {
        if (strcpy_s(mode, sizeof(mode), " display") != EOK) {
            HDF_LOGE("%{public}s strcpy failed", __func__);
        }
    } else if (info->provdisc == P2P_WPS_METHOD_KEYPAD) {
        if (strcpy_s(mode, sizeof(mode), " keypad") != EOK) {
            HDF_LOGE("%{public}s strcpy failed", __func__);
        }
    } else if (info->provdisc == P2P_WPS_METHOD_PBC && info->pin != NULL && strlen((char *)info->pin) == 0) {
        if (strcpy_s(pin, CMD_SIZE, "pbc") != EOK) {
            HDF_LOGE("%{public}s strcpy failed", __func__);
        }
    } else {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s Mode value is invalid %{public}d!", __func__, info->provdisc);
        free(reply);
        return HDF_ERR_INVALID_PARAM;
    }

    if (info->peerDevAddr) {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s P2P_CONNECT %s %s%s persistent=%d %s", ifName,
            MacToStr(info->peerDevAddr), pin, mode, info->persistent, join);
    }
    if (ret < 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{private}s, count = %{public}d", __func__, cmd, ret);
        free(reply);
        return HDF_FAILURE;
    }

    if (WpaCliCmd(cmd, reply, REPLY_SIZE) != 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("P2P_CONNECT command failed!");
        free(reply);
        return HDF_FAILURE;
    }

    if (strncmp(reply, "FAIL", strlen("FAIL")) == 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s P2p connect return %{public}s", __func__, reply);
        free(reply);
        return HDF_FAILURE;
    }
    if (info->provdisc == P2P_WPS_METHOD_DISPLAY && strcmp((char *)info->pin, "pin") == 0) {
        if (strncpy_s(replyPin, replyPinLen, reply, strlen(reply)) != 0) {
            pthread_mutex_unlock(GetInterfaceLock());
            HDF_LOGE("%{public}s Failed to copy response pin code info!", __func__);
            free(reply);
            return HDF_FAILURE;
        }
    }
    pthread_mutex_unlock(GetInterfaceLock());
    free(reply);
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pHid2dConnect(struct IWpaInterface *self, const char *ifName,
    const struct HdiHid2dConnectInfo *info)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    if (ifName == NULL || info == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(GetInterfaceLock());
    char cmd[CMD_SIZE];
    char buf[CMD_SIZE];
    (void)self;
    int freq = (info->frequency >> 16);
    int isLegacyGo = (info->frequency & 0xffff);
    if (freq < 0) {
        HDF_LOGE("hid2dconnect freq is failed, freq=%{public}d", freq);
        freq = 0;
    }
    HDF_LOGI("hid2dconnect freq=%{public}d, isLegacyGo=%{public}d", freq, isLegacyGo);
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s MAGICLINK \"%s\"\n%s\n\"%s\"\n%d\n%d", ifName,
            (char *)info->ssid, MacToStr(info->bssid), (char *)info->passphrase, freq, isLegacyGo) < 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{private}s.", __func__, cmd);
        return HDF_FAILURE;
    }
    if (WpaCliCmd(cmd, buf, sizeof(buf)) != 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("hid2d_connect command failed!");
        return HDF_FAILURE;
    }
    if (strncmp(buf, "FAIL", strlen("FAIL")) == 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: return %{public}s", __func__, buf);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSetServDiscExternal(struct IWpaInterface *self, const char *ifName, int32_t mode)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    (void)ifName;
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdSetServDiscExternal(pMainIfc, mode);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("WpaP2pCliCmdSetServDiscExternal fail, ret = %{public}d", ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pRemoveGroup(struct IWpaInterface *self, const char *ifName, const char *groupName)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL || groupName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdP2pRemoveGroup(pMainIfc, groupName);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pCancelConnect(struct IWpaInterface *self, const char *ifName)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    (void)ifName;
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdCancelConnect(pMainIfc);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pGetGroupConfig(struct IWpaInterface *self, const char *ifName, const int32_t networkId,
    const char *param, char *value, uint32_t valueLen)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    char cmd[CMD_SIZE];

    int32_t ret = 0;
    (void)self;
    if (ifName == NULL || param == NULL || value == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(GetInterfaceLock());
    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s GET_NETWORK %d %s", ifName, networkId, param);
    if (ret < 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{private}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }
    if (WpaCliCmd(cmd, value, valueLen) != 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("GET_NETWORK command failed!");
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pAddNetwork(struct IWpaInterface *self, const char *ifName, int32_t *networkId)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    if (ifName == NULL || networkId == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    (void)self;
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdAddNetwork(pMainIfc, networkId);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("WpaP2pCliCmdAddNetwork fail, ret = %{public}d", ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pGetPeer(struct IWpaInterface *self, const char *ifName, const char *bssid,
    struct HdiP2pDeviceInfo *info)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    if (ifName == NULL || info == NULL || bssid == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(GetInterfaceLock());
    char *reply;
    const int replySize = REPLY_SIZE;
    char cmd[CMD_SIZE];

    reply = (char *)malloc(replySize);
    if (reply == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s reply is NULL!", __func__);
        return HDF_FAILURE;
    }
    
    int32_t ret = 0;
    (void)self;

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s P2P_PEER %s", ifName, bssid);
    if (ret < 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{private}s, count = %{public}d", __func__, cmd, ret);
        free(reply);
        return HDF_FAILURE;
    }

    if (WpaCliCmd(cmd, reply, REPLY_SIZE) != 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("P2P_PEER command failed!");
        free(reply);
        return HDF_FAILURE;
    }

    if (strstr(reply, "\n") == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s reply is error", __func__);
        free(reply);
        return HDF_FAILURE;
    }
    char *savedPtr = NULL;
    char *token = strtok_r(reply, "\n", &savedPtr);
    info->srcAddress = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (ETH_ADDR_LEN + 1));
    if (info->srcAddress == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("malloc srcAddress failed!");
        free(reply);
        HdiP2pDeviceInfoFree(info, false);
        return HDF_FAILURE;
    }
    info->p2pDeviceAddress = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (ETH_ADDR_LEN + 1));
    if (info->p2pDeviceAddress == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("malloc p2pDeviceAddress failed!");
        free(reply);
        HdiP2pDeviceInfoFree(info, false);
        return HDF_FAILURE;
    }
    info->primaryDeviceType = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * WIFI_P2P_DEVICE_TYPE_LENGTH);
    if (info->primaryDeviceType == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("malloc primaryDeviceType failed!");
        free(reply);
        HdiP2pDeviceInfoFree(info, false);
        return HDF_FAILURE;
    }
    info->deviceName = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * WIFI_P2P_DEVICE_NAME_LENGTH);
    if (info->deviceName == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("malloc deviceName failed!");
        free(reply);
        HdiP2pDeviceInfoFree(info, false);
        return HDF_FAILURE;
    }
    info->wfdDeviceInfo = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * WIFI_P2P_WFD_DEVICE_INFO_LENGTH);
    if (info->wfdDeviceInfo == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("malloc wfdDeviceInfo failed!");
        free(reply);
        HdiP2pDeviceInfoFree(info, false);
        return HDF_FAILURE;
    }
    info->operSsid = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * WIFI_P2P_DEVICE_NAME_LENGTH);
    if (info->operSsid == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("malloc operSsid failed!");
        free(reply);
        HdiP2pDeviceInfoFree(info, false);
        return HDF_FAILURE;
    }
    info->srcAddressLen = ETH_ADDR_LEN + 1;
    info->p2pDeviceAddressLen = ETH_ADDR_LEN + 1;
    info->primaryDeviceTypeLen = WIFI_P2P_DEVICE_TYPE_LENGTH;
    info->deviceNameLen = WIFI_P2P_DEVICE_NAME_LENGTH;
    info->wfdDeviceInfoLen = WIFI_P2P_WFD_DEVICE_INFO_LENGTH;
    info->operSsidLen = WIFI_P2P_DEVICE_NAME_LENGTH;
    uint8_t tmpBssid[ETH_ADDR_LEN] = {0};
    hwaddr_aton(token, tmpBssid);
    if (memcpy_s((char *)info->p2pDeviceAddress, ETH_ADDR_LEN, (char *)tmpBssid, ETH_ADDR_LEN) != EOK) {
        HDF_LOGE("%{public}s memcpy failed", __func__);
    }
    while (token != NULL) {
        struct HdiWpaKeyValue retMsg = {{0}, {0}};
        GetStrKeyVal(token, "=", &retMsg);
        if (strncmp(retMsg.key, "pri_dev_type", strlen("pri_dev_type")) == 0) {
            if (strcpy_s((char *)info->primaryDeviceType, WIFI_P2P_DEVICE_TYPE_LENGTH + 1, retMsg.value) != EOK) {
                HDF_LOGE("%{public}s strcpy failed", __func__);
            }
        } else if (strncmp(retMsg.key, "device_name", strlen("device_name")) == 0) {
            if (strcpy_s((char *)info->deviceName, WIFI_P2P_DEVICE_NAME_LENGTH + 1, retMsg.value) != EOK) {
                HDF_LOGE("%{public}s strcpy failed", __func__);
            }
        } else if (strncmp(retMsg.key, "config_methods", strlen("config_methods")) == 0) {
            info->configMethods = Hex2Dec(retMsg.value);
        } else if (strncmp(retMsg.key, "dev_capab", strlen("dev_capab")) == 0) {
            info->deviceCapabilities = Hex2Dec(retMsg.value);
        } else if (strncmp(retMsg.key, "group_capab", strlen("group_capab")) == 0) {
            info->groupCapabilities = Hex2Dec(retMsg.value);
        } else if (strncmp(retMsg.key, "oper_ssid", strlen("oper_ssid")) == 0) {
            if (strcpy_s((char *)info->operSsid, WIFI_P2P_DEVICE_NAME_LENGTH + 1, retMsg.value) != EOK) {
                HDF_LOGE("%{public}s strcpy failed", __func__);
            }
            printf_decode((u8 *)info->operSsid, WIFI_P2P_DEVICE_NAME_LENGTH + 1, (char *)info->operSsid);
        }
        token = strtok_r(NULL, "\n", &savedPtr);
    }
    pthread_mutex_unlock(GetInterfaceLock());
    free(reply);
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pGetGroupCapability(struct IWpaInterface *self, const char *ifName,
    const char *bssid, int32_t *cap)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    if (ifName == NULL || bssid == NULL || cap == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(GetInterfaceLock());
    char *reply;
    const int replySize = REPLY_SIZE;
    char cmd[CMD_SIZE];

    reply = (char *)malloc(replySize);
    if (reply == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s reply is NULL!", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = 0;
    (void)self;

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s P2P_PEER %s", ifName, bssid);
    if (ret < 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{private}s, count = %{public}d", __func__, cmd, ret);
        free(reply);
        return HDF_FAILURE;
    }

    if (WpaCliCmd(cmd, reply, REPLY_SIZE) != 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("P2P_PEER command failed!");
        free(reply);
        return HDF_FAILURE;
    }

    if (strstr(reply, "\n") == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s reply is error", __func__);
        free(reply);
        return HDF_FAILURE;
    }
    char *savedPtr = NULL;
    char *token = strtok_r(reply, "\n", &savedPtr);

    while (token != NULL) {
        struct HdiWpaKeyValue retMsg = {{0}, {0}};
        GetStrKeyVal(token, "=", &retMsg);
        if (strncmp(retMsg.key, "group_capab", strlen("group_capab")) == 0) {
            *cap = Hex2Dec(retMsg.value);
        }
        token = strtok_r(NULL, "\n", &savedPtr);
    }
    pthread_mutex_unlock(GetInterfaceLock());
    free(reply);
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pListNetworks(struct IWpaInterface *self, const char *ifName,
    struct HdiP2pNetworkList *infoList)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    if (ifName == NULL || infoList == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(GetInterfaceLock());
    char *reply;
    const int replySize = P2P_LIST_REPLY_SIZE;
    char cmd[CMD_SIZE];
    reply = (char *)malloc(replySize);
    if (reply == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s reply is NULL!", __func__);
        return HDF_FAILURE;
    }

    (void)self;
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s LIST_NETWORKS", ifName) < 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("snprintf err");
        free(reply);
        return HDF_FAILURE;
    }
    if (WpaCliCmd(cmd, reply, P2P_LIST_REPLY_SIZE) != 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("LIST_NETWORKS command failed!");
        free(reply);
        return HDF_FAILURE;
    }

    char *token = strstr(reply, "\n");
    if (token == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s token is NULL!", __func__);
        free(reply);
        return HDF_FAILURE;
    }
    char *tmpPos = token + 1;
    while ((tmpPos = strstr(tmpPos, "\n")) != NULL) {
        infoList->infoNum += 1;
        ++tmpPos;
    }
    if (infoList->infoNum <= 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s infoList->infoNum <= 0", __func__);
        free(reply);
        return HDF_FAILURE;
    }
    infoList->infos = (struct HdiP2pNetworkInfo *)OsalMemCalloc(sizeof(struct HdiP2pNetworkInfo) * infoList->infoNum);
    if (infoList->infos == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("malloc infos failed!");
        free(reply);
        return HDF_FAILURE;
    }
    infoList->infosLen = (uint32_t)infoList->infoNum;
    char *tmpBuf = token + 1;
    char *savedPtr = NULL;
    token = strtok_r(tmpBuf, "\n", &savedPtr);
    int index = 0;
    while (token != NULL) {
        if (index >= infoList->infoNum) {
            break;
        }
        infoList->infos[index].ssid = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * WIFI_SSID_LENGTH);
        if (infoList->infos[index].ssid == NULL) {
            HDF_LOGE("malloc ssid failed!");
            HdiP2pNetworkInfoFree(&(infoList->infos[index]), true);
            break;
        }
        infoList->infos[index].ssidLen = WIFI_SSID_LENGTH;
        infoList->infos[index].bssid = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (ETH_ADDR_LEN + 1));
        if (infoList->infos[index].bssid == NULL) {
            HDF_LOGE("malloc bssid failed!");
            HdiP2pNetworkInfoFree(&(infoList->infos[index]), true);
            break;
        }
        infoList->infos[index].bssidLen = ETH_ADDR_LEN + 1;
        GetHalNetworkInfos(token, &(infoList->infos[index]));
        index++;
        token = strtok_r(NULL, "\n", &savedPtr);
    }
    pthread_mutex_unlock(GetInterfaceLock());
    free(reply);
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSaveConfig(struct IWpaInterface *self, const char *ifName)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    (void)ifName;
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdStoreConfig(pMainIfc);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

static int32_t GetCmdWithCarryDate(char *cmd, const char *ifName,
    int32_t cmdType, int32_t dataType, const char *carryData)
{
    int ret = 0;
    switch (cmdType) {
        case P2P_REJECT: {
            ret = snprintf_s(cmd, MAX_CMD_SIZE, MAX_CMD_SIZE - 1,
                "IFNAME=%s P2P_REJECT %s", ifName, carryData);
            break;
        }
        case P2P_REMOVE_GROUP_CLIENT: {
            ret = snprintf_s(cmd, MAX_CMD_SIZE, MAX_CMD_SIZE - 1,
                "IFNAME=%s P2P_REMOVE_CLIENT %s", ifName, carryData);
            break;
        }
        case P2P_SET_MIRACAST_SINK_CONFIG: {
            ret = snprintf_s(cmd, MAX_CMD_SIZE, MAX_CMD_SIZE - 1,
                "IFNAME=%s SINK_CONFIG_SET %s", ifName, carryData);
            break;
        }
        case P2P_CREATE_TEMP_GROUP: {
            ret = snprintf_s(cmd, MAX_CMD_SIZE, MAX_CMD_SIZE - 1,
                "IFNAME=%s CREATE_TEMP_GROUP %s", ifName, carryData);
            break;
        }
        default: {
            ret = snprintf_s(cmd, MAX_CMD_SIZE, MAX_CMD_SIZE - 1,
                "IFNAME=%s P2P_DELIVER_DATA cmdType=%d dataType=%d carryData=%s",
                ifName, cmdType, dataType, carryData);
            break;
        }
    }
    return ret;
}

int32_t WpaInterfaceDeliverP2pData(struct IWpaInterface *self, const char *ifName,
    int32_t cmdType, int32_t dataType, const char *carryData)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    (void)ifName;
    char cmd[MAX_CMD_SIZE] = {0};
    char buf[CMD_SIZE] = {0};

    int32_t ret = 0;
    if (ifName == NULL || carryData == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(GetInterfaceLock());
    ret = GetCmdWithCarryDate(cmd, ifName, cmdType, dataType, carryData);
    if (ret < 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{private}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }
    if (WpaCliCmd(cmd, buf, sizeof(buf)) != 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s command failed!", __func__);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceVendorExtProcessCmd(struct IWpaInterface *self, const char *ifName, const char *cmd)
{
#define NEW_CMD_MAX_LEN 400
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    int32_t ret = 0;
    (void)self;
    if (cmd == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM ;
    }
    pthread_mutex_lock(GetInterfaceLock());
    char *reply;
    const int replySize = REPLY_SIZE;
    reply = (char *)malloc(replySize);
    if (reply == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s reply is NULL!", __func__);
        return HDF_FAILURE;
    }

    char newCmd[NEW_CMD_MAX_LEN] = {0};
    if (snprintf_s(newCmd, sizeof(newCmd), sizeof(newCmd) - 1, "IFNAME=%s %s", ifName, cmd) < 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: snprintf_s is failed, error code: %{public}d", __func__, ret);
        free(reply);
        return HDF_FAILURE;
    }
 
    if (WpaCliCmd(newCmd, reply, replySize) < 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s WpaCliCmd failed!", __func__);
        free(reply);
        return HDF_FAILURE;
    }

    HDF_LOGI("%{public}s reply %{public}s !", __func__, reply);
    pthread_mutex_unlock(GetInterfaceLock());
    ret = atoi(reply);
    free(reply);
    return ret;
}

static int32_t WpaFillP2pDeviceFoundParam(struct P2pDeviceInfoParam *deviceInfoParam,
    struct HdiP2pDeviceInfoParam *hdiP2pDeviceInfoParam)
{
    int32_t ret = 0;
    if (deviceInfoParam == NULL || hdiP2pDeviceInfoParam == NULL) {
        HDF_LOGE("%{public}s: deviceInfoParam or hdiP2pDeviceInfo is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pDeviceInfoParam->configMethods = deviceInfoParam->configMethods;
    hdiP2pDeviceInfoParam->deviceCapabilities = deviceInfoParam->deviceCapabilities;
    hdiP2pDeviceInfoParam->groupCapabilities = deviceInfoParam->groupCapabilities;
    hdiP2pDeviceInfoParam->wfdLength = deviceInfoParam->wfdLength;

    do {
        if (FillData(&hdiP2pDeviceInfoParam->srcAddress, &hdiP2pDeviceInfoParam->srcAddressLen,
            deviceInfoParam->srcAddress, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pDeviceInfoParam->p2pDeviceAddress, &hdiP2pDeviceInfoParam->p2pDeviceAddressLen,
            deviceInfoParam->p2pDeviceAddress, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pDeviceInfoParam->primaryDeviceType, &hdiP2pDeviceInfoParam->primaryDeviceTypeLen,
            deviceInfoParam->primaryDeviceType, WIFI_P2P_DEVICE_TYPE_LENGTH) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pDeviceInfoParam->deviceName, &hdiP2pDeviceInfoParam->deviceNameLen,
            deviceInfoParam->deviceName, WIFI_P2P_DEVICE_NAME_LENGTH) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (deviceInfoParam->wfdLength != 0 &&
            FillData(&hdiP2pDeviceInfoParam->wfdDeviceInfo, &hdiP2pDeviceInfoParam->wfdDeviceInfoLen,
            deviceInfoParam->wfdDeviceInfo, deviceInfoParam->wfdLength) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pDeviceInfoParam->operSsid, &hdiP2pDeviceInfoParam->operSsidLen,
            deviceInfoParam->operSsid, WIFI_P2P_DEVICE_NAME_LENGTH) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill reason fail!", __func__);
            ret = HDF_FAILURE;
        }
    } while (0);

    if (ret != HDF_SUCCESS) {
        if (hdiP2pDeviceInfoParam->srcAddress != NULL) {
            OsalMemFree(hdiP2pDeviceInfoParam->srcAddress);
            hdiP2pDeviceInfoParam->srcAddress = NULL;
        }
        if (hdiP2pDeviceInfoParam->p2pDeviceAddress != NULL) {
            OsalMemFree(hdiP2pDeviceInfoParam->p2pDeviceAddress);
            hdiP2pDeviceInfoParam->p2pDeviceAddress = NULL;
        }
        if (hdiP2pDeviceInfoParam->primaryDeviceType != NULL) {
            OsalMemFree(hdiP2pDeviceInfoParam->primaryDeviceType);
            hdiP2pDeviceInfoParam->primaryDeviceType = NULL;
        }
        if (hdiP2pDeviceInfoParam->deviceName != NULL) {
            OsalMemFree(hdiP2pDeviceInfoParam->deviceName);
            hdiP2pDeviceInfoParam->deviceName = NULL;
        }
        if (hdiP2pDeviceInfoParam->wfdDeviceInfo != NULL) {
            OsalMemFree(hdiP2pDeviceInfoParam->wfdDeviceInfo);
            hdiP2pDeviceInfoParam->wfdDeviceInfo = NULL;
        }
        if (hdiP2pDeviceInfoParam->operSsid != NULL) {
            OsalMemFree(hdiP2pDeviceInfoParam->operSsid);
            hdiP2pDeviceInfoParam->operSsid = NULL;
        }
    }
    return ret;
}

static int32_t WpaFillP2pDeviceLostParam(struct P2pDeviceLostParam  *deviceLostParam,
    struct HdiP2pDeviceLostParam *hdiP2pDeviceLostParam)
{
    int32_t ret = 0;
    if (deviceLostParam == NULL || hdiP2pDeviceLostParam == NULL) {
        HDF_LOGE("%{public}s: deviceLostParam or hdiP2pDeviceLostParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pDeviceLostParam->networkId = deviceLostParam->networkId;

    if (FillData(&hdiP2pDeviceLostParam->p2pDeviceAddress, &hdiP2pDeviceLostParam->p2pDeviceAddressLen,
        deviceLostParam->p2pDeviceAddress, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
    }
    if (ret != HDF_SUCCESS) {
        if (hdiP2pDeviceLostParam->p2pDeviceAddress != NULL) {
            OsalMemFree(hdiP2pDeviceLostParam->p2pDeviceAddress);
            hdiP2pDeviceLostParam->p2pDeviceAddress = NULL;
        }
    }
    return ret;
}

static int32_t WpaFillP2pGoNegotiationRequestParam(struct P2pGoNegotiationRequestParam *goNegotiationRequestParam,
    struct HdiP2pGoNegotiationRequestParam *hdiP2pGoNegotiationRequestParam)
{
    int32_t ret = 0;
    if (goNegotiationRequestParam == NULL || hdiP2pGoNegotiationRequestParam == NULL) {
        HDF_LOGE("%{public}s: goNegotiationRequestParam or hdiP2pGoNegotiationRequestParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pGoNegotiationRequestParam->passwordId = goNegotiationRequestParam->passwordId;

    if (FillData(&hdiP2pGoNegotiationRequestParam->srcAddress, &hdiP2pGoNegotiationRequestParam->srcAddressLen,
        goNegotiationRequestParam->srcAddress, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
    }
    if (ret != HDF_SUCCESS) {
        if (hdiP2pGoNegotiationRequestParam->srcAddress != NULL) {
            OsalMemFree(hdiP2pGoNegotiationRequestParam->srcAddress);
            hdiP2pGoNegotiationRequestParam->srcAddress = NULL;
        }
    }
    return ret;
}

static int32_t WpaFillP2pGoNegotiationCompletedParam(struct P2pGoNegotiationCompletedParam
    *goNegotiationCompletedParam, struct HdiP2pGoNegotiationCompletedParam *hdiP2pGoNegotiationCompletedParam)
{
    int32_t ret = 0;
    if (goNegotiationCompletedParam == NULL || hdiP2pGoNegotiationCompletedParam == NULL) {
        HDF_LOGE("%{public}s: goNegotiationCompletedParam or hdiP2pGoNegotiationCompletedParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pGoNegotiationCompletedParam->status = goNegotiationCompletedParam->status;
    return ret;
}

static int32_t WpaFillP2pInvitationReceivedParam(struct P2pInvitationReceivedParam *invitationReceivedParam,
    struct HdiP2pInvitationReceivedParam *hdiP2pInvitationReceivedParam)
{
    int32_t ret = HDF_SUCCESS;
    if (invitationReceivedParam == NULL || hdiP2pInvitationReceivedParam == NULL) {
        HDF_LOGE("%{public}s: invitationReceivedParam or hdiP2pInvitationReceivedParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pInvitationReceivedParam->type = invitationReceivedParam->type;
    hdiP2pInvitationReceivedParam->persistentNetworkId = invitationReceivedParam->persistentNetworkId;
    hdiP2pInvitationReceivedParam->operatingFrequency = invitationReceivedParam->operatingFrequency;

    do {
        if (FillData(&hdiP2pInvitationReceivedParam->srcAddress, &hdiP2pInvitationReceivedParam->srcAddressLen,
            invitationReceivedParam->srcAddress, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pInvitationReceivedParam->goDeviceAddress,
            &hdiP2pInvitationReceivedParam->goDeviceAddressLen,
            invitationReceivedParam->goDeviceAddress, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pInvitationReceivedParam->bssid, &hdiP2pInvitationReceivedParam->bssidLen,
            invitationReceivedParam->bssid, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill ssid fail!", __func__);
            ret = HDF_FAILURE;
        }
    } while (0);

    if (ret != HDF_SUCCESS) {
        if (hdiP2pInvitationReceivedParam->srcAddress != NULL) {
            OsalMemFree(hdiP2pInvitationReceivedParam->srcAddress);
            hdiP2pInvitationReceivedParam->srcAddress = NULL;
        }
        if (hdiP2pInvitationReceivedParam->goDeviceAddress != NULL) {
            OsalMemFree(hdiP2pInvitationReceivedParam->goDeviceAddress);
            hdiP2pInvitationReceivedParam->goDeviceAddress = NULL;
        }
        if (hdiP2pInvitationReceivedParam->bssid != NULL) {
            OsalMemFree(hdiP2pInvitationReceivedParam->bssid);
            hdiP2pInvitationReceivedParam->bssid = NULL;
        }
    }
    return ret;
}

static int32_t WpaFillP2pInvitationResultParam(struct P2pInvitationResultParam *invitationResultParam,
    struct HdiP2pInvitationResultParam *hdiP2pInvitationResultParam)
{
    int32_t ret = HDF_SUCCESS;
    if (invitationResultParam == NULL || hdiP2pInvitationResultParam == NULL) {
        HDF_LOGE("%{public}s: invitationResultParam or hdiP2pInvitationResultParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pInvitationResultParam->status = invitationResultParam->status;

    if (FillData(&hdiP2pInvitationResultParam->bssid, &hdiP2pInvitationResultParam->bssidLen,
        invitationResultParam->bssid, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
    }
    if (ret != HDF_SUCCESS) {
        if (hdiP2pInvitationResultParam->bssid != NULL) {
            OsalMemFree(hdiP2pInvitationResultParam->bssid);
            hdiP2pInvitationResultParam->bssid = NULL;
        }
    }
    return ret;
}

static int32_t FillHdiP2pGroupInfoStartedParam(struct P2pGroupStartedParam *groupStartedParam,
    struct HdiP2pGroupInfoStartedParam *hdiP2pGroupStartedParam)
{
    int32_t ret = HDF_SUCCESS;
    if (groupStartedParam == NULL || hdiP2pGroupStartedParam == NULL) {
        HDF_LOGE("%{public}s: groupStartedParam or hdiP2pGroupStartedParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    do {
        if (FillData(&hdiP2pGroupStartedParam->groupIfName, &hdiP2pGroupStartedParam->groupIfNameLen,
            groupStartedParam->groupIfName, WIFI_P2P_GROUP_IFNAME_LENGTH) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill groupIfName fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pGroupStartedParam->ssid, &hdiP2pGroupStartedParam->ssidLen,
            groupStartedParam->ssid, WIFI_SSID_LENGTH) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill ssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pGroupStartedParam->psk, &hdiP2pGroupStartedParam->pskLen,
            groupStartedParam->psk, WIFI_P2P_PASSWORD_SIZE) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill psk fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pGroupStartedParam->passphrase, &hdiP2pGroupStartedParam->passphraseLen,
            groupStartedParam->passphrase, WIFI_P2P_PASSWORD_SIZE) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill passphrase fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pGroupStartedParam->goDeviceAddress, &hdiP2pGroupStartedParam->goDeviceAddressLen,
            groupStartedParam->goDeviceAddress, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill goDeviceAddress fail!", __func__);
            ret = HDF_FAILURE;
        }
        if (FillData(&hdiP2pGroupStartedParam->goRandomDeviceAddress,
            &hdiP2pGroupStartedParam->goRandomDeviceAddressLen,
            groupStartedParam->goRandomDeviceAddress, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill goRandomDeviceAddress fail!", __func__);
            ret = HDF_FAILURE;
        }
    } while (0);
    return ret;
}

static int32_t WpaFillP2pGroupInfoStartedParam(struct P2pGroupStartedParam *groupStartedParam,
    struct HdiP2pGroupInfoStartedParam *hdiP2pGroupStartedParam)
{
    int32_t ret = HDF_SUCCESS;
    if (groupStartedParam == NULL || hdiP2pGroupStartedParam == NULL) {
        HDF_LOGE("%{public}s: groupStartedParam or hdiP2pGroupStartedParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pGroupStartedParam->isGo = groupStartedParam->isGo;
    hdiP2pGroupStartedParam->isPersistent = groupStartedParam->isPersistent;
    hdiP2pGroupStartedParam->frequency = groupStartedParam->frequency;
    ret = FillHdiP2pGroupInfoStartedParam(groupStartedParam, hdiP2pGroupStartedParam);
    if (ret != HDF_SUCCESS) {
        if (hdiP2pGroupStartedParam->groupIfName != NULL) {
            OsalMemFree(hdiP2pGroupStartedParam->groupIfName);
            hdiP2pGroupStartedParam->groupIfName = NULL;
        }
        if (hdiP2pGroupStartedParam->ssid != NULL) {
            OsalMemFree(hdiP2pGroupStartedParam->ssid);
            hdiP2pGroupStartedParam->ssid = NULL;
        }
        if (hdiP2pGroupStartedParam->psk != NULL) {
            OsalMemFree(hdiP2pGroupStartedParam->psk);
            hdiP2pGroupStartedParam->psk = NULL;
        }
        if (hdiP2pGroupStartedParam->passphrase != NULL) {
            OsalMemFree(hdiP2pGroupStartedParam->passphrase);
            hdiP2pGroupStartedParam->passphrase = NULL;
        }
        if (hdiP2pGroupStartedParam->goDeviceAddress != NULL) {
            OsalMemFree(hdiP2pGroupStartedParam->goDeviceAddress);
            hdiP2pGroupStartedParam->goDeviceAddress = NULL;
        }
        if (hdiP2pGroupStartedParam->goRandomDeviceAddress != NULL) {
            OsalMemFree(hdiP2pGroupStartedParam->goRandomDeviceAddress);
            hdiP2pGroupStartedParam->goRandomDeviceAddress = NULL;
        }
    }
    return ret;
}

static int32_t WpaFillP2pGroupRemovedParam(struct P2pGroupRemovedParam *groupRemovedParam,
    struct HdiP2pGroupRemovedParam *hdiP2pGroupRemovedParam)
{
    int32_t ret = HDF_SUCCESS;
    if (groupRemovedParam == NULL || hdiP2pGroupRemovedParam == NULL) {
        HDF_LOGE("%{public}s: groupStartedParam or hdiP2pGroupRemovedParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pGroupRemovedParam->isGo = groupRemovedParam->isGo;

    if (FillData(&hdiP2pGroupRemovedParam->groupIfName, &hdiP2pGroupRemovedParam->groupIfNameLen,
        groupRemovedParam->groupIfName, WIFI_P2P_GROUP_IFNAME_LENGTH) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
    }
    if (ret != HDF_SUCCESS) {
        if (hdiP2pGroupRemovedParam->groupIfName != NULL) {
            OsalMemFree(hdiP2pGroupRemovedParam->groupIfName);
            hdiP2pGroupRemovedParam->groupIfName = NULL;
        }
    }
    return ret;
}

static int32_t WpaFillP2pProvisionDiscoveryCompletedParam(struct P2pProvisionDiscoveryCompletedParam
    *provisionDiscoveryCompletedParam,
    struct HdiP2pProvisionDiscoveryCompletedParam *hdiP2pProvisionDiscoveryCompletedParam)
{
    int32_t ret = HDF_SUCCESS;
    if (provisionDiscoveryCompletedParam == NULL || hdiP2pProvisionDiscoveryCompletedParam == NULL) {
        HDF_LOGE("%{public}s: provisionDiscoveryCompletedParam or hdiP2pProvisionDiscoveryCompletedParam is NULL!",
            __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pProvisionDiscoveryCompletedParam->isRequest = provisionDiscoveryCompletedParam->isRequest;
    hdiP2pProvisionDiscoveryCompletedParam->provDiscStatusCode = provisionDiscoveryCompletedParam->provDiscStatusCode;
    hdiP2pProvisionDiscoveryCompletedParam->configMethods = provisionDiscoveryCompletedParam->configMethods;

    do {
        if (FillData(&hdiP2pProvisionDiscoveryCompletedParam->p2pDeviceAddress,
            &hdiP2pProvisionDiscoveryCompletedParam->p2pDeviceAddressLen,
            provisionDiscoveryCompletedParam->p2pDeviceAddress, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pProvisionDiscoveryCompletedParam->generatedPin,
            &hdiP2pProvisionDiscoveryCompletedParam->generatedPinLen,
            provisionDiscoveryCompletedParam->generatedPin, WIFI_PIN_CODE_LENGTH) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill ssid fail!", __func__);
            ret = HDF_FAILURE;
        }
    } while (0);

    if (ret != HDF_SUCCESS) {
        if (hdiP2pProvisionDiscoveryCompletedParam->p2pDeviceAddress != NULL) {
            OsalMemFree(hdiP2pProvisionDiscoveryCompletedParam->p2pDeviceAddress);
            hdiP2pProvisionDiscoveryCompletedParam->p2pDeviceAddress = NULL;
        }
        if (hdiP2pProvisionDiscoveryCompletedParam->generatedPin != NULL) {
            OsalMemFree(hdiP2pProvisionDiscoveryCompletedParam->generatedPin);
            hdiP2pProvisionDiscoveryCompletedParam->generatedPin = NULL;
        }
    }
    return ret;
}

static int32_t WpaFillP2pServDiscReqParam(struct P2pServDiscReqInfoParam *servDiscReqInfo,
    struct HdiP2pServDiscReqInfoParam *hdiP2pServDiscReqInfo)
{
    int32_t ret = HDF_SUCCESS;
    if (servDiscReqInfo == NULL || hdiP2pServDiscReqInfo == NULL) {
        HDF_LOGE("%{public}s: servDiscReqInfo or hdiP2pServDiscReqInfo is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pServDiscReqInfo->freq = servDiscReqInfo->freq;
    hdiP2pServDiscReqInfo->dialogToken = servDiscReqInfo->dialogToken;
    hdiP2pServDiscReqInfo->updateIndic = servDiscReqInfo->updateIndic;

    do {
        if (FillData(&hdiP2pServDiscReqInfo->mac, &hdiP2pServDiscReqInfo->macLen,
            servDiscReqInfo->mac, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pServDiscReqInfo->tlvs, &hdiP2pServDiscReqInfo->tlvsLen,
            servDiscReqInfo->tlvs, WIFI_P2P_TLVS_LENGTH) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill ssid fail!", __func__);
            ret = HDF_FAILURE;
        }
    } while (0);

    if (ret != HDF_SUCCESS) {
        if (hdiP2pServDiscReqInfo->mac != NULL) {
            OsalMemFree(hdiP2pServDiscReqInfo->mac);
            hdiP2pServDiscReqInfo->mac = NULL;
        }
        if (hdiP2pServDiscReqInfo->tlvs != NULL) {
            OsalMemFree(hdiP2pServDiscReqInfo->tlvs);
            hdiP2pServDiscReqInfo->tlvs = NULL;
        }
    }
    return ret;
}

static int32_t WpaFillP2pServDiscRespParam(struct P2pServDiscRespParam *servDiscRespParam,
    struct HdiP2pServDiscRespParam *hdiP2pServDiscRespParam)
{
    int32_t ret = HDF_SUCCESS;
    if (servDiscRespParam == NULL || hdiP2pServDiscRespParam == NULL) {
        HDF_LOGE("%{public}s: servDiscRespParam or hdiP2pServDiscRespParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pServDiscRespParam->updateIndicator = servDiscRespParam->updateIndicator;

    do {
        if (FillData(&hdiP2pServDiscRespParam->srcAddress, &hdiP2pServDiscRespParam->srcAddressLen,
            servDiscRespParam->srcAddress, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pServDiscRespParam->tlvs, &hdiP2pServDiscRespParam->tlvsLen,
            servDiscRespParam->tlvs, WIFI_P2P_TLVS_LENGTH) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill ssid fail!", __func__);
            ret = HDF_FAILURE;
        }
    } while (0);

    if (ret != HDF_SUCCESS) {
        if (hdiP2pServDiscRespParam->srcAddress != NULL) {
            OsalMemFree(hdiP2pServDiscRespParam->srcAddress);
            hdiP2pServDiscRespParam->srcAddress = NULL;
        }
        if (hdiP2pServDiscRespParam->tlvs != NULL) {
            OsalMemFree(hdiP2pServDiscRespParam->tlvs);
            hdiP2pServDiscRespParam->tlvs = NULL;
        }
    }
    return ret;
}

static int32_t WpaFillP2pStaConnectStateParam(struct P2pStaConnectStateParam *staConnectStateParam,
    struct HdiP2pStaConnectStateParam *hdiP2pStaConnectStateParam)
{
    int32_t ret = HDF_SUCCESS;
    if (staConnectStateParam == NULL || hdiP2pStaConnectStateParam == NULL) {
        HDF_LOGE("%{public}s: staConnectStateParam or hdiP2pStaConnectStateParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pStaConnectStateParam->state = staConnectStateParam->state;
    do {
        if (FillData(&hdiP2pStaConnectStateParam->srcAddress, &hdiP2pStaConnectStateParam->srcAddressLen,
            staConnectStateParam->srcAddress, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pStaConnectStateParam->p2pDeviceAddress, &hdiP2pStaConnectStateParam->p2pDeviceAddressLen,
            staConnectStateParam->p2pDeviceAddress, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill ssid fail!", __func__);
            ret = HDF_FAILURE;
        }
    } while (0);

    if (ret != HDF_SUCCESS) {
        if (hdiP2pStaConnectStateParam->srcAddress != NULL) {
            OsalMemFree(hdiP2pStaConnectStateParam->srcAddress);
            hdiP2pStaConnectStateParam->srcAddress = NULL;
        }
        if (hdiP2pStaConnectStateParam->p2pDeviceAddress != NULL) {
            OsalMemFree(hdiP2pStaConnectStateParam->p2pDeviceAddress);
            hdiP2pStaConnectStateParam->p2pDeviceAddress = NULL;
        }
    }
    return ret;
}

static int32_t WpaFillP2pIfaceCreatedParam(struct P2pIfaceCreatedParam *ifaceCreatedParam,
    struct HdiP2pIfaceCreatedParam *hdiP2pIfaceCreatedParam)
{
    int32_t ret = HDF_SUCCESS;
    if (ifaceCreatedParam == NULL || hdiP2pIfaceCreatedParam == NULL) {
        HDF_LOGE("%{public}s: ifaceCreatedParam or hdiP2pIfaceCreatedParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pIfaceCreatedParam->isGo = ifaceCreatedParam->isGo;
    return ret;
}

int32_t ProcessEventP2pDeviceFound(struct HdfWpaRemoteNode *node,
    struct P2pDeviceInfoParam *deviceInfoParam, const char *ifName)
{
    struct HdiP2pDeviceInfoParam hdiP2pDeviceInfo = {0};
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventDeviceFound == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (WpaFillP2pDeviceFoundParam(deviceInfoParam, &hdiP2pDeviceInfo) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: hdiP2pDeviceInfo is NULL or deviceInfoParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventDeviceFound(node->callbackObj, &hdiP2pDeviceInfo, ifName);
    }
    HdiP2pDeviceInfoParamFree(&hdiP2pDeviceInfo, false);
    return ret;
}

int32_t ProcessEventP2pDeviceLost(struct HdfWpaRemoteNode *node,
    struct P2pDeviceLostParam *deviceLostParam, const char *ifName)
{
    struct HdiP2pDeviceLostParam hdiP2pDeviceLostParam = {0};
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventDeviceLost == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (WpaFillP2pDeviceLostParam(deviceLostParam, &hdiP2pDeviceLostParam) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: hdiP2pDeviceLostParam is NULL or deviceLostParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventDeviceLost(node->callbackObj, &hdiP2pDeviceLostParam, ifName);
    }
    HdiP2pDeviceLostParamFree(&hdiP2pDeviceLostParam, false);
    return ret;
}

int32_t ProcessEventP2pGoNegotiationRequest(struct HdfWpaRemoteNode *node,
    struct P2pGoNegotiationRequestParam *goNegotiationRequestParam, const char *ifName)
{
    struct HdiP2pGoNegotiationRequestParam hdiP2pGoNegotiationRequestParam = {0};
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventGoNegotiationRequest == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (WpaFillP2pGoNegotiationRequestParam(goNegotiationRequestParam,
        &hdiP2pGoNegotiationRequestParam) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: hdiP2pGoNegotiationRequestParam is NULL or goNegotiationRequestParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventGoNegotiationRequest(node->callbackObj,
            &hdiP2pGoNegotiationRequestParam, ifName);
    }
    HdiP2pGoNegotiationRequestParamFree(&hdiP2pGoNegotiationRequestParam, false);
    return ret;
}

int32_t ProcessEventP2pGoNegotiationCompleted(struct HdfWpaRemoteNode *node, struct P2pGoNegotiationCompletedParam
    *goNegotiationCompletedParam, const char *ifName)
{
    struct HdiP2pGoNegotiationCompletedParam hdiP2pGoNegotiationCompletedParam = {0};
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventGoNegotiationCompleted == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (WpaFillP2pGoNegotiationCompletedParam(goNegotiationCompletedParam,
        &hdiP2pGoNegotiationCompletedParam) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: hdiP2pGoNegotiationCompletedParam is NULL or goNegotiationCompletedParam fialed!",
            __func__);
    } else {
        ret = node->callbackObj->OnEventGoNegotiationCompleted(node->callbackObj,
            &hdiP2pGoNegotiationCompletedParam, ifName);
    }
    HdiP2pGoNegotiationCompletedParamFree(&hdiP2pGoNegotiationCompletedParam, false);
    return ret;
}

int32_t ProcessEventP2pInvitationReceived(struct HdfWpaRemoteNode *node,
    struct P2pInvitationReceivedParam *invitationReceivedParam, const char *ifName)
{
    struct HdiP2pInvitationReceivedParam hdiP2pInvitationReceivedParam = {0};
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventInvitationReceived == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (WpaFillP2pInvitationReceivedParam(invitationReceivedParam, &hdiP2pInvitationReceivedParam) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: hdiP2pInvitationReceivedParam is NULL or invitationReceivedParam fialed!", __func__);
        return ret;
    } else {
        ret = node->callbackObj->OnEventInvitationReceived(node->callbackObj, &hdiP2pInvitationReceivedParam, ifName);
    }
    HdiP2pInvitationReceivedParamFree(&hdiP2pInvitationReceivedParam, false);
    return ret;
}

int32_t ProcessEventP2pInvitationResult(struct HdfWpaRemoteNode *node,
    struct P2pInvitationResultParam *invitationResultParam, const char *ifName)
{
    struct HdiP2pInvitationResultParam hdiP2pInvitationResultParam = {0};
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventInvitationResult == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (WpaFillP2pInvitationResultParam(invitationResultParam, &hdiP2pInvitationResultParam) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: hdiP2pInvitationResultParam is NULL or invitationResultParam fialed!", __func__);
        return ret;
    } else {
        ret = node->callbackObj->OnEventInvitationResult(node->callbackObj, &hdiP2pInvitationResultParam, ifName);
    }
    HdiP2pInvitationResultParamFree(&hdiP2pInvitationResultParam, false);
    return ret;
}

int32_t ProcessEventP2pGroupFormationSuccess(struct HdfWpaRemoteNode *node,
    const char *ifName)
{
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = node->callbackObj->OnEventGroupFormationSuccess(node->callbackObj, ifName);
    return ret;
}

int32_t ProcessEventP2pGroupFormationFailure(struct HdfWpaRemoteNode *node, char *reason,
    const char *ifName)
{
    char *hdiReason = NULL;
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventGroupFormationFailure == NULL ||
        reason == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiReason = (char *)OsalMemCalloc(WIFI_REASON_LENGTH);
    if ((hdiReason == NULL) || (strncpy_s(hdiReason, WIFI_REASON_LENGTH, reason, strlen(reason)) != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: hdiReason is NULL or reason fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventGroupFormationFailure(node->callbackObj, hdiReason, ifName);
    }
    if (hdiReason) {
        OsalMemFree(hdiReason);
        hdiReason = NULL;
    }
    return ret;
}

int32_t ProcessEventP2pGroupStarted(struct HdfWpaRemoteNode *node,
    struct P2pGroupStartedParam *groupStartedParam, const char *ifName)
{
    struct HdiP2pGroupInfoStartedParam hdiP2pGroupInfoStartedParam = {0};
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventGroupInfoStarted == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (WpaFillP2pGroupInfoStartedParam(groupStartedParam, &hdiP2pGroupInfoStartedParam) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: hdiP2pGroupStartedParam is NULL or groupStartedParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventGroupInfoStarted(node->callbackObj, &hdiP2pGroupInfoStartedParam, ifName);
    }
    HdiP2pGroupInfoStartedParamFree(&hdiP2pGroupInfoStartedParam, false);
    return ret;
}

int32_t ProcessEventP2pGroupRemoved(struct HdfWpaRemoteNode *node,
    struct P2pGroupRemovedParam *groupRemovedParam, const char *ifName)
{
    struct HdiP2pGroupRemovedParam hdiP2pGroupRemovedParam = {0};
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventGroupRemoved == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (WpaFillP2pGroupRemovedParam(groupRemovedParam, &hdiP2pGroupRemovedParam) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: hdiP2pGroupRemovedParam is NULL or groupRemovedParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventGroupRemoved(node->callbackObj, &hdiP2pGroupRemovedParam, ifName);
    }
    HdiP2pGroupRemovedParamFree(&hdiP2pGroupRemovedParam, false);
    return ret;
}

int32_t ProcessEventP2pProvisionDiscoveryCompleted(struct HdfWpaRemoteNode *node,
    struct P2pProvisionDiscoveryCompletedParam *provisionDiscoveryCompletedParam, const char *ifName)
{
    struct HdiP2pProvisionDiscoveryCompletedParam hdiP2pProvisionDiscoveryCompletedParam = {0};
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventProvisionDiscoveryCompleted == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (WpaFillP2pProvisionDiscoveryCompletedParam(provisionDiscoveryCompletedParam,
        &hdiP2pProvisionDiscoveryCompletedParam) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Param is NULL or provisionDiscoveryCompletedParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventProvisionDiscoveryCompleted(node->callbackObj,
            &hdiP2pProvisionDiscoveryCompletedParam, ifName);
    }
    HdiP2pProvisionDiscoveryCompletedParamFree(&hdiP2pProvisionDiscoveryCompletedParam, false);
    return ret;
}

int32_t ProcessEventP2pFindStopped(struct HdfWpaRemoteNode *node,
     const char *ifName)
{
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = node->callbackObj->OnEventFindStopped(node->callbackObj, ifName);
    return ret;
}

int32_t ProcessEventP2pServDiscReq(struct HdfWpaRemoteNode *node,
    struct P2pServDiscReqInfoParam *servDiscReqInfo, const char *ifName)
{
    struct HdiP2pServDiscReqInfoParam hdiP2pServDiscReqInfo = {0};
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventServDiscReq == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (WpaFillP2pServDiscReqParam(servDiscReqInfo, &hdiP2pServDiscReqInfo) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: hdiP2pServDiscReqInfo is NULL or servDiscReqInfo fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventServDiscReq(node->callbackObj, &hdiP2pServDiscReqInfo, ifName);
    }
    HdiP2pServDiscReqInfoParamFree(&hdiP2pServDiscReqInfo, false);
    return ret;
}

int32_t ProcessEventP2pServDiscResp(struct HdfWpaRemoteNode *node,
    struct P2pServDiscRespParam *servDiscRespParam, const char *ifName)
{
    struct HdiP2pServDiscRespParam hdiP2pServDiscRespParam = {0};
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventServDiscResp == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (WpaFillP2pServDiscRespParam(servDiscRespParam, &hdiP2pServDiscRespParam) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: hdiP2pServDiscRespParam is NULL or servDiscRespParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventServDiscResp(node->callbackObj, &hdiP2pServDiscRespParam, ifName);
    }
    HdiP2pServDiscRespParamFree(&hdiP2pServDiscRespParam, false);
    return ret;
}

int32_t ProcessEventP2pStaConnectState(struct HdfWpaRemoteNode *node,
    struct P2pStaConnectStateParam *staConnectStateParam, const char *ifName)
{
    struct HdiP2pStaConnectStateParam hdiP2pStaConnectStateParam = {0};
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventStaConnectState == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (WpaFillP2pStaConnectStateParam(staConnectStateParam, &hdiP2pStaConnectStateParam) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: hdiP2pStaConnectStateParam is NULL or staConnectStateParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventStaConnectState(node->callbackObj, &hdiP2pStaConnectStateParam, ifName);
    }
    HdiP2pStaConnectStateParamFree(&hdiP2pStaConnectStateParam, false);
    return ret;
}

int32_t ProcessEventP2pIfaceCreated(struct HdfWpaRemoteNode *node, struct P2pIfaceCreatedParam *ifaceCreatedParam,
    const char *ifName)
{
    struct HdiP2pIfaceCreatedParam hdiP2pIfaceCreatedParam = {0};
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventIfaceCreated == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (WpaFillP2pIfaceCreatedParam(ifaceCreatedParam, &hdiP2pIfaceCreatedParam) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: hdiP2pIfaceCreatedParam is NULL or ifaceCreatedParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventIfaceCreated(node->callbackObj, &hdiP2pIfaceCreatedParam, ifName);
    }
    HdiP2pIfaceCreatedParamFree(&hdiP2pIfaceCreatedParam, false);
    return ret;
}
