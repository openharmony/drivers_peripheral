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
#include "v1_1/iwpa_callback.h"
#include "v1_1/iwpa_interface.h"
#include "wpa_p2p_hal.h"

#define HEX_TO_DEC_MOVING 4
#define DEC_MAX_SCOPE 10
#define MIN_MAC_LEN 6

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

void GetHalNetworkInfos(char *buf, struct HdiP2pNetworkInfo *info)
{
    if (buf == NULL || info == NULL) {
        return;
    }
    int len = strlen(buf);
    int start = 0;
    int end = 0;
    int i = 0;
    const int count = 2;
    while (end < len) {
        if (buf[end] != '\t') {
            ++end;
            continue;
        }
        buf[end] = '\0';
        if (i == 0) {
            info->id = atoi(buf);
        } else if (i == 1) {
            if (strcpy_s((char *)info->ssid, WIFI_SSID_LENGTH + 1, buf + start) != EOK) {
                break;
            }
            printf_decode((u8 *)info->ssid, WIFI_SSID_LENGTH + 1, (char *)info->ssid);
        } else if (i == count) {
            uint8_t tmpBssid[ETH_ADDR_LEN] = {0};
            hwaddr_aton(buf + start, tmpBssid);
            if (strcpy_s((char *)info->bssid, ETH_ADDR_LEN + 1, (char *)tmpBssid) != EOK) {
                break;
            }
            start = end + 1;
            if (strcpy_s((char *)info->flags, WIFI_NETWORK_FLAGS_LENGTH + 1, buf + start) != EOK) {
                break;
            }
            break;
        }
        ++i;
        end++;
        start = end;
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
    if (memcpy_s(pin, CMD_SIZE, info->pin, CMD_SIZE) != EOK) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s strcpy failed", __func__);
        return HDF_FAILURE;
    }

    if (memcpy_s(peerDevAddr, CMD_SIZE, info->peerDevAddr, CMD_SIZE) != EOK) {
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

    char persistent[CMD_SIZE] = {0};
    if (info->peerDevAddr && strlen(peerDevAddr) >= MIN_MAC_LEN) {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s P2P_CONNECT %s %s%s%s%s", ifName,
            macToStr(info->peerDevAddr), pin, mode, persistent, join);
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
            (char *)info->ssid, macToStr(info->bssid), (char *)info->passphrase, freq, isLegacyGo) < 0) {
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