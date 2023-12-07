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
#include "main.h"
#include "wps_supplicant.h"
#include "p2p_supplicant.h"
#include "ctrl_iface.h"
#include "wpa_magiclink.h"
#include "wifi_display.h"
#include "bssid_ignore.h"
#include "config.h"

#include "v1_0/iwpa_callback.h"
#include "v1_0/iwpa_interface.h"

#define HEX_TO_DEC_MOVING 4
#define DEC_MAX_SCOPE 10

struct HdiWpaKeyValue {
    char key[CMD_SIZE];
    char value[CMD_SIZE];
};

int Hex2Dec(const char *str)
{
    if (str == NULL || strncasecmp(str, "0x", strlen("0x")) != 0) {
        return 0;
    }
    int result = 0;
    const char *tmp = str + strlen("0x");
    while (*tmp != '\0') {
        result <<= HEX_TO_DEC_MOVING;
        if (*tmp >= '0' && *tmp <= '9') {
            result += *tmp - '0';
        } else if (*tmp >= 'A' && *tmp <= 'F') {
            result += *tmp - 'A' + DEC_MAX_SCOPE;
        } else if (*tmp >= 'a' && *tmp <= 'f') {
            result += *tmp - 'a' + DEC_MAX_SCOPE;
        } else {
            result = 0;
            break;
        }
        ++tmp;
    }
    return result;
}

void GetStrKeyVal(char *src, const char *split, struct HdiWpaKeyValue *out)
{
    if (src == NULL || split == NULL || out == NULL) {
        return;
    }
    char *p = strstr(src, split);
    if (p == NULL) {
        StrSafeCopy(out->key, sizeof(out->key), src);
        return;
    }
    *p = '\0';
    StrSafeCopy(out->key, sizeof(out->key), src);
    p += strlen(split);
    StrSafeCopy(out->value, sizeof(out->value), p);
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
            if (strcpy_s((char *)info->ssid, sizeof(info->ssid), buf + start) != EOK) {
                break;
            }
            printf_decode((u8 *)info->ssid, sizeof(info->ssid), (char *)info->ssid);
        } else if (i == count) {
            uint8_t tmpBssid[ETH_ADDR_LEN] = {0};
            hwaddr_aton(buf + start, tmpBssid);
            if (strcpy_s((char *)info->bssid, ETH_ADDR_LEN + 1, (char *)tmpBssid) != EOK) {
                break;
            }
            start = end + 1;
            if (strcpy_s((char *)info->flags, sizeof(info->flags), buf + start) != EOK) {
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
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];

    int32_t ret = 0;
    (void)self;
    if (ifName == NULL || name == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "ssid_postfix %s", name);
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }

    ret = p2p_ctrl_set(wpaSupp, cmd);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pSetSsidPostfixName fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSetWpsDeviceType(struct IWpaInterface *self, const char *ifName, const char *type)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];

    int32_t ret = 0;
    (void)self;
    if (ifName == NULL || type == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "device_type %s", type);
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }

    ret = wpa_supplicant_ctrl_iface_set(wpaSupp, cmd);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pSetWpsDeviceType fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSetWpsConfigMethods(struct IWpaInterface *self, const char *ifName, const char *methods)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];

    int32_t ret = 0;
    (void)self;
    if (ifName == NULL || methods == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "config_methods %s", methods);
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }

    ret = wpa_supplicant_ctrl_iface_set(wpaSupp, cmd);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pSetWpsConfigMethods fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSetGroupMaxIdle(struct IWpaInterface *self, const char *ifName, int32_t time)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];

    int32_t ret = 0;
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "p2p_group_idle %d", time);
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }

    ret = wpa_supplicant_ctrl_iface_set(wpaSupp, cmd);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pSetGroupMaxIdle fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSetWfdEnable(struct IWpaInterface *self, const char *ifName, int32_t enable)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];

    int32_t ret = 0;
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "wifi_display %d", enable);
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }

    ret = wpa_supplicant_ctrl_iface_set(wpaSupp, cmd);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pSetWfdEnable fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSetPersistentReconnect(struct IWpaInterface *self, const char *ifName, int32_t status)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];

    int32_t ret = 0;
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "persistent_reconnect %d", status);
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }

    ret = wpa_supplicant_ctrl_iface_set(wpaSupp, cmd);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pSetPersistentReconnect fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}


int32_t WpaInterfaceP2pSetWpsSecondaryDeviceType(struct IWpaInterface *self, const char *ifName, const char *type)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];

    int32_t ret = 0;
    (void)self;
    if (ifName == NULL || type == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "sec_device_type %s", type);

    ret = wpa_supplicant_ctrl_iface_set(wpaSupp, cmd);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pSetWpsSecondaryDeviceType fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSetupWpsPbc(struct IWpaInterface *self, const char *ifName, const char *address)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];

    int32_t ret = 0;
    (void)self;
    if (ifName == NULL || address == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%s", address);
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }

    ret = wpa_supplicant_ctrl_iface_wps_pbc(wpaSupp, cmd);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pSetupWpsPbc fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSetupWpsPin(struct IWpaInterface *self, const char *ifName, const char *address,
    const char *pin, char *result, uint32_t resultLen)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];

    int32_t ret = 0;
    (void)self;
    if (ifName == NULL || result == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    if (strlen(pin) > 0) {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "any %s", pin);
    } else if (strlen(address) == 0) {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "any");
    } else {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%s", address);
    }

    ret = wpa_supplicant_ctrl_iface_wps_pin(wpaSupp, cmd, result, resultLen);
    strcpy_s(result, resultLen, "test result");
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pSetupWpsPin fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSetPowerSave(struct IWpaInterface *self, const char *ifName, int32_t enable)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];

    int32_t ret = 0;
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "ps %d", enable);
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }

    ret = p2p_ctrl_set(wpaSupp, cmd);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pSetPowerSave fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}


int32_t WpaInterfaceP2pSetDeviceName(struct IWpaInterface *self, const char *ifName, const char *name)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];

    int32_t ret = 0;
    (void)self;
    if (ifName == NULL || name == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "device_name %s", name);
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }

    ret = wpa_supplicant_ctrl_iface_set(wpaSupp, cmd);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pSetDeviceName fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSetWfdDeviceConfig(struct IWpaInterface *self, const char *ifName, const char *config)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];

    int32_t ret = 0;
    (void)self;
    if (ifName == NULL || config == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%s", config);
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }
    ret = p2p_wifi_display_subelem_set(wpaSupp->global, cmd);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pSetWfdDeviceConfig fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}


int32_t WpaInterfaceP2pSetRandomMac(struct IWpaInterface *self, const char *ifName, int32_t networkId)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];

    int32_t ret = 0;
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "p2p_device_random_mac_addr %d", networkId);
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }

    ret = wpa_supplicant_ctrl_iface_set(wpaSupp, cmd);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pSetRandomMac fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pStartFind(struct IWpaInterface *self, const char *ifName, int32_t timeout)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];

    int32_t ret = 0;
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    if (timeout >= 0) {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%d", timeout);
    } else {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "");
    }
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }

    HDF_LOGE("%{public}s P2pStartFind timeout=%d", __func__, timeout);
    ret = p2p_ctrl_find(wpaSupp, cmd);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pStartFind fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSetExtListen(struct IWpaInterface *self, const char *ifName, int32_t enable,
    int32_t period, int32_t interval)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];

    int32_t ret = 0;
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    if (enable == 0) {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "");
    } else {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%d %d", period, interval);
    }
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }

    ret = p2p_ctrl_ext_listen(wpaSupp, cmd);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pSetExtListen fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSetListenChannel(struct IWpaInterface *self, const char *ifName,
    int32_t channel, int32_t regClass)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];

    int32_t ret = 0;
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    if (regClass > 0) {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "listen_channel %d %d", channel, regClass);
    } else {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "listen_channel %d", channel);
    }
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }

    ret = p2p_ctrl_set(wpaSupp, cmd);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pSetListenChannel fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pProvisionDiscovery(struct IWpaInterface *self, const char *ifName,
    const char *peerBssid, int32_t mode)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];

    int32_t ret = 0;
    (void)self;
    if (ifName == NULL || peerBssid == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    if (mode == P2P_WPS_METHOD_PBC) {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%s pbc", peerBssid);
    } else if (mode == P2P_WPS_METHOD_DISPLAY) {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%s display", peerBssid);
    } else if (mode == P2P_WPS_METHOD_KEYPAD) {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%s keypad", peerBssid);
    } else {
        HDF_LOGE("%{public}s mode is error", __func__);
        return HDF_FAILURE;
    }
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }

    ret = p2p_ctrl_prov_disc(wpaSupp, cmd);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pProvisionDiscovery fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pAddGroup(struct IWpaInterface *self, const char *ifName, int32_t isPersistent,
    int32_t networkId, int32_t freq)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];

    int32_t ret = 0;
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    if (isPersistent) {
        if (networkId < 0) {
            ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "persistent freq=%d", freq);
        } else {
            ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "persistent=%d freq=%d", networkId, freq);
        }
    } else {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "freq=%d", freq);
    }
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }

    ret = p2p_ctrl_group_add(wpaSupp, cmd);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pAddGroup fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pAddService(struct IWpaInterface *self, const char *ifName,
    const struct HdiP2pServiceInfo *info)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];

    int32_t ret = 0;
    (void)self;
    if (ifName == NULL || info == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    if (info->mode == 0) {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "upnp %d %s", info->version, info->name);
    } else {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "bonjour %s %s", info->query, info->resp);
    }
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }

    ret = p2p_ctrl_service_add(wpaSupp, cmd);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pAddService fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pRemoveService(struct IWpaInterface *self, const char *ifName,
    const struct HdiP2pServiceInfo *info)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];

    int32_t ret = 0;
    (void)self;
    if (ifName == NULL || info == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    if (info->mode == 0) {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "upnp %d %s", info->version, info->name);
    } else {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "bonjour %s", info->query);
    }
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }

    ret = p2p_ctrl_service_del(wpaSupp, cmd);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pRemoveService fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pStopFind(struct IWpaInterface *self, const char *ifName)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;

    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    wpas_p2p_stop_find(wpaSupp);
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}


int32_t WpaInterfaceP2pFlush(struct IWpaInterface *self, const char *ifName)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    p2p_ctrl_flush(wpaSupp);
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pFlushService(struct IWpaInterface *self, const char *ifName)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    wpas_p2p_service_flush(wpaSupp);
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pRemoveNetwork(struct IWpaInterface *self, const char *ifName, int32_t networkId)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];

    int32_t ret = 0;
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    if (networkId == -1) {
        strcpy_s(cmd, sizeof(cmd), "all");
    } else {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%d", networkId);
    }
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }

    ret = wpa_supplicant_ctrl_iface_remove_network(wpaSupp, cmd);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pRemoveNetwork fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSetGroupConfig(struct IWpaInterface *self, const char *ifName, const int32_t networkId,
    const char *name, const char *value)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];

    int32_t ret = 0;
    (void)self;
    if (ifName == NULL || name == NULL || value == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%d %s %s",
            networkId, name, value);
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }

    ret = wpa_supplicant_ctrl_iface_set_network(wpaSupp, cmd);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pSetGroupConfig fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pInvite(struct IWpaInterface *self, const char *ifName,
    const char *peerBssid, const char *goBssid)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];
    
    int32_t ret = 0;
    (void)self;
    if (ifName == NULL || peerBssid == NULL || goBssid == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "group=%s peer=%s go_dev_addr=%s", ifName, peerBssid, goBssid);
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }

    ret = p2p_ctrl_invite(wpaSupp, cmd);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pInvite fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pReinvoke(struct IWpaInterface *self, const char *ifName, const int32_t networkId,
    const char *bssid)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];
    
    int32_t ret = 0;
    (void)self;
    if (ifName == NULL || bssid == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "persistent=%d peer=%s", networkId, bssid);
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }

    ret = p2p_ctrl_invite(wpaSupp, cmd);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pReinvoke fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pGetDeviceAddress(struct IWpaInterface *self, const char *ifName, char *deviceAddress,
    uint32_t deviceAddressLen)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    char cmd[CMD_SIZE] = {0};
    const int replySize = REPLY_SIZE;
    char *reply = (char *)malloc(replySize);
    struct wpa_supplicant *wpaSupp;
    if (ifName == NULL || deviceAddress == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (reply == NULL) {
        HDF_LOGE("%{public}s reply is NULL!", __func__);
        return HDF_FAILURE;
    }
    int32_t ret = 0;
    (void)self;
    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        free(reply);
        return HDF_FAILURE;
    }
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%s", "STATUS") < 0) {
        HDF_LOGE("%{public}s snprintf_s failed", __func__);
        free(reply);
        return HDF_FAILURE;
    }
    ret = wpa_supplicant_ctrl_iface_status(wpaSupp, cmd + CMD_LEN, reply, replySize);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pGetDeviceAddress fail! ret=%d", __func__, ret);
        free(reply);
        return HDF_FAILURE;
    }
    char *p = strstr(reply, "p2p_device_address=");
    if (p == NULL) {
        HDF_LOGE("%{public}s Not find device address!", __func__);
        free(reply);
        return HDF_FAILURE;
    }
    p += strlen("p2p_device_address=");
    char *q = p;
    while (*q != '\0' && *q != '\n') {
        ++q;
    }
    if (strncpy_s(deviceAddress, deviceAddressLen, p, q - p) != EOK) {
        HDF_LOGE("%{public}s Failed to copy device address!", __func__);
        free(reply);
        return HDF_FAILURE;
    }
    free(reply);
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
    char *reply;
    const int replySize = REPLY_SIZE;
    struct wpa_supplicant *wpaSupp;
    reply = (char *)malloc(replySize);
    if (reply == NULL) {
        HDF_LOGE("%{public}s reply is NULL!", __func__);
        return HDF_FAILURE;
    }
    char cmd[CMD_SIZE];
    int32_t ret = 0;
    (void)self;

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        free(reply);
        return HDF_FAILURE;
    }
    if (reqService->bssid) {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%s %s", macToStr(reqService->bssid), reqService->msg);
    }
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        free(reply);
        return HDF_FAILURE;
    }

    ret = p2p_ctrl_serv_disc_req(wpaSupp, cmd, reply, replySize);
    if (strncpy_s(replyDisc, replyDiscLen, reply, replySize) != 0) {
        HDF_LOGE("%{public}s Failed to copy response about service discovery sequence!", __func__);
        free(reply);
        return HDF_FAILURE;
    }

    if (ret < 0) {
        HDF_LOGE("%{public}s P2pReqServiceDiscovery fail! ret=%d", __func__, ret);
        free(reply);
        return HDF_FAILURE;
    }

    free(reply);
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pCancelServiceDiscovery(struct IWpaInterface *self, const char *ifName, const char *id)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];

    int32_t ret = 0;
    (void)self;
    if (ifName == NULL || id == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%s", id);
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }

    ret = p2p_ctrl_serv_disc_cancel_req(wpaSupp, cmd);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pCancelServiceDiscovery fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }
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

    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];
    
    int32_t ret = 0;
    (void)self;

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }
    if (info->mac) {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%d %s %d %s", info->freq, macToStr(info->mac),
        info->dialogToken, info->tlvs);
    }

    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }

    ret = p2p_ctrl_serv_disc_resp(wpaSupp, cmd);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pRespServerDiscovery fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }
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
    char *reply;
    const int replySize = REPLY_SIZE;
    char cmd[CMD_SIZE] = {0};
    char join[CMD_SIZE] = {0};
    char mode[CMD_SIZE] = {0};
    char persistent[CMD_SIZE] = {0};

    struct wpa_supplicant *wpaSupp;
    reply = (char *)malloc(replySize);
    if (reply == NULL) {
        HDF_LOGE("%{public}s reply is NULL!", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = 0;
    (void)self;

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        free(reply);
        return HDF_FAILURE;
    }

    if (info->mode != 0) {
        StrSafeCopy(join, sizeof(join), " join");
    } else {
        if (snprintf_s(join, sizeof(join), sizeof(join) - 1, " go_intent=%d", info->goIntent) < 0) {
            HDF_LOGE("%{public}s input parameter invalid!", __func__);
            free(reply);
            return HDF_ERR_INVALID_PARAM;
        }
    }

    if (info->provdisc == P2P_WPS_METHOD_DISPLAY) {
        StrSafeCopy(mode, sizeof(mode), " display");
    } else if (info->provdisc == P2P_WPS_METHOD_KEYPAD) {
        StrSafeCopy(mode, sizeof(mode), " keypad");
    } else if (info->provdisc == P2P_WPS_METHOD_PBC && info->pin != NULL && strlen((char *)info->pin) == 0) {
        StrSafeCopy((char *)info->pin, sizeof(info->pin), "pbc");
    } else {
        HDF_LOGE("%{public}s Mode value is invalid %{public}d!", __func__, info->provdisc);
        free(reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (info->peerDevAddr) {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%s %s%s%s%s", macToStr(info->peerDevAddr), info->pin, mode,
        persistent, join);
    }
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        free(reply);
        return HDF_FAILURE;
    }

    ret = p2p_ctrl_connect(wpaSupp, cmd, reply, replySize);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pConnect fail! ret=%d", __func__, ret);
        free(reply);
        return HDF_FAILURE;
    }

    if (strncmp(reply, "FAIL", strlen("FAIL")) == 0) {
        HDF_LOGE("%{public}s P2p connect return %{public}s", __func__, reply);
        free(reply);
        return HDF_FAILURE;
    }
    if (info->provdisc == P2P_WPS_METHOD_DISPLAY && strcmp((char *)info->pin, "pin") == 0) {
        if (strncpy_s(replyPin, replyPinLen, reply, strlen(reply)) != 0) {
            HDF_LOGE("%{public}s Failed to copy response pin code info!", __func__);
            free(reply);
            return HDF_FAILURE;
        }
    }

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
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];

    int32_t ret = 0;
    (void)self;

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }
    if (info->bssid) {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "\"%s\"\n%s\n\"%s\"\n%d", info->ssid,
            macToStr(info->bssid), info->passphrase, info->frequency);
    }

    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }
    ret = magiclink_p2p_ctrl_connect(wpaSupp, cmd);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pHid2dConnect fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSetServDiscExternal(struct IWpaInterface *self, const char *ifName, int32_t mode)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];
    
    int32_t ret = 0;
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%d", mode);
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }

    ret = p2p_ctrl_serv_disc_external(wpaSupp, cmd);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pSetServDiscExternal fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pRemoveGroup(struct IWpaInterface *self, const char *ifName, const char *groupName)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    int32_t ret = 0;
    (void)self;
    if (ifName == NULL || groupName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    ret = wpas_p2p_group_remove(wpaSupp, groupName);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pRemoveGroup fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }

    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pCancelConnect(struct IWpaInterface *self, const char *ifName)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    int32_t ret = 0;
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    ret = wpas_p2p_cancel(wpaSupp);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pCancelConnect fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pGetGroupConfig(struct IWpaInterface *self, const char *ifName, const int32_t networkId,
    const char *param, char *value, uint32_t valueLen)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;
    char cmd[CMD_SIZE];

    int32_t ret = 0;
    (void)self;
    if (ifName == NULL || param == NULL || value == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%d %s", networkId, param);
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }

    ret = wpa_supplicant_ctrl_iface_get_network(wpaSupp, cmd, value, valueLen);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pGetGroupConfig fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }
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
    char *reply;
    const int replySize = REPLY_SIZE;
    struct wpa_supplicant *wpaSupp;
    reply = (char *)malloc(replySize);
    if (reply == NULL) {
        HDF_LOGE("%{public}s reply is NULL!", __func__);
        return HDF_FAILURE;
    }
    
    int32_t ret = 0;
    (void)self;

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        free(reply);
        return HDF_FAILURE;
    }

    ret = wpa_supplicant_ctrl_iface_add_network(wpaSupp, reply, replySize);
    *networkId = atoi(reply);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pAddNetwork fail! ret=%d", __func__, ret);
        return HDF_FAILURE;
    }

    free(reply);
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
    char *reply;
    const int replySize = REPLY_SIZE;
    char cmd[CMD_SIZE];
    struct wpa_supplicant *wpaSupp;
    reply = (char *)malloc(replySize);
    if (reply == NULL) {
        HDF_LOGE("%{public}s reply is NULL!", __func__);
        return HDF_FAILURE;
    }
    
    int32_t ret = 0;
    (void)self;

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        free(reply);
        return HDF_FAILURE;
    }

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%s", bssid);
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        free(reply);
        return HDF_FAILURE;
    }

    ret = p2p_ctrl_peer(wpaSupp, cmd, reply, replySize);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pGetPeer fail! ret=%d", __func__, ret);
        free(reply);
        return HDF_FAILURE;
    }

    if (strstr(reply, "\n") == NULL) {
        HDF_LOGE("%{public}s reply is error", __func__);
        free(reply);
        return HDF_FAILURE;
    }
    char *savedPtr = NULL;
    char *token = strtok_r(reply, "\n", &savedPtr);
    info->srcAddress = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (ETH_ADDR_LEN + 1));
    info->p2pDeviceAddress = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (ETH_ADDR_LEN + 1));
    info->primaryDeviceType = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * WIFI_P2P_DEVICE_TYPE_LENGTH);
    info->deviceName = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * WIFI_P2P_DEVICE_NAME_LENGTH);
    info->wfdDeviceInfo = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * WIFI_P2P_WFD_DEVICE_INFO_LENGTH);
    info->operSsid = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * WIFI_P2P_DEVICE_NAME_LENGTH);
    info->srcAddressLen = ETH_ADDR_LEN + 1;
    info->p2pDeviceAddressLen = ETH_ADDR_LEN + 1;
    info->primaryDeviceTypeLen = WIFI_P2P_DEVICE_TYPE_LENGTH;
    info->deviceNameLen = WIFI_P2P_DEVICE_NAME_LENGTH;
    info->wfdDeviceInfoLen = WIFI_P2P_WFD_DEVICE_INFO_LENGTH;
    info->operSsidLen = WIFI_P2P_DEVICE_NAME_LENGTH;
    uint8_t tmpBssid[ETH_ADDR_LEN] = {0};
    hwaddr_aton(token, tmpBssid);
    StrSafeCopy((char *)info->p2pDeviceAddress, ETH_ADDR_LEN + 1, (char *)tmpBssid); /* copy first line */
    while (token != NULL) {
        struct HdiWpaKeyValue retMsg = {{0}, {0}};
        GetStrKeyVal(token, "=", &retMsg);
        if (strncmp(retMsg.key, "pri_dev_type", strlen("pri_dev_type")) == 0) {
            StrSafeCopy((char *)info->primaryDeviceType, sizeof(info->primaryDeviceType), retMsg.value);
        } else if (strncmp(retMsg.key, "device_name", strlen("device_name")) == 0) {
            StrSafeCopy((char *)info->deviceName, sizeof(info->deviceName), retMsg.value);
        } else if (strncmp(retMsg.key, "config_methods", strlen("config_methods")) == 0) {
            info->configMethods = Hex2Dec(retMsg.value);
        } else if (strncmp(retMsg.key, "dev_capab", strlen("dev_capab")) == 0) {
            info->deviceCapabilities = Hex2Dec(retMsg.value);
        } else if (strncmp(retMsg.key, "group_capab", strlen("group_capab")) == 0) {
            info->groupCapabilities = Hex2Dec(retMsg.value);
        } else if (strncmp(retMsg.key, "oper_ssid", strlen("oper_ssid")) == 0) {
            StrSafeCopy((char *)info->operSsid, sizeof(info->operSsid), retMsg.value);
        }
        token = strtok_r(NULL, "\n", &savedPtr);
    }
    free(reply);
    HDF_LOGI("%{public}s P2pGetPeer success", __func__);
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
    char *reply;
    const int replySize = REPLY_SIZE;
    char cmd[CMD_SIZE];
    struct wpa_supplicant *wpaSupp;
    struct HdiP2pDeviceInfo *info = {0};
    reply = (char *)malloc(replySize);
    if (reply == NULL) {
        HDF_LOGE("%{public}s reply is NULL!", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = 0;
    (void)self;

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        free(reply);
        return HDF_FAILURE;
    }

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%s", bssid);
    if (ret < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, count = %{public}d", __func__, cmd, ret);
        free(reply);
        return HDF_FAILURE;
    }

    ret = p2p_ctrl_peer(wpaSupp, cmd, reply, replySize);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pGetGroupCapability fail! ret=%d", __func__, ret);
        free(reply);
        return HDF_FAILURE;
    }
    if (strstr(reply, "\n") == NULL) {
        HDF_LOGE("%{public}s reply is error", __func__);
        free(reply);
        return HDF_FAILURE;
    }
    char *savedPtr = NULL;
    char *token = strtok_r(reply, "\n", &savedPtr);
    StrSafeCopy((char *)info->p2pDeviceAddress, sizeof(info->p2pDeviceAddress), token); /* copy first line */
    while (token != NULL) {
        struct HdiWpaKeyValue retMsg = {{0}, {0}};
        GetStrKeyVal(token, "=", &retMsg);
        if (strncmp(retMsg.key, "group_capab", strlen("group_capab")) == 0) {
            info->groupCapabilities = Hex2Dec(retMsg.value);
        }
        token = strtok_r(NULL, "\n", &savedPtr);
    }
    *cap = info->groupCapabilities;
    free(reply);
    HDF_LOGI("%{public}s P2pGetGroupCapability success", __func__);
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
    char *reply;
    const int replySize = REPLY_SIZE;
    struct wpa_supplicant *wpaSupp;
    reply = (char *)malloc(replySize);
    if (reply == NULL) {
        HDF_LOGE("%{public}s reply is NULL!", __func__);
        return HDF_FAILURE;
    }
    int32_t ret = 0;
    (void)self;
    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        free(reply);
        return HDF_FAILURE;
    }
    ret = wpa_supplicant_ctrl_iface_list_networks(wpaSupp, NULL, reply, replySize);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pListNetworks fail! ret=%d", __func__, ret);
        free(reply);
        return HDF_FAILURE;
    }
    char *token = strstr(reply, "\n");
    if (token == NULL) {
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
        HDF_LOGE("%{public}s infoList->infoNum <= 0", __func__);
        free(reply);
        return HDF_FAILURE;
    }
    infoList->infos = (struct HdiP2pNetworkInfo *)OsalMemCalloc(sizeof(struct HdiP2pNetworkInfo) * infoList->infoNum);
    infoList->infosLen = infoList->infoNum;
    char *tmpBuf = token + 1;
    char *savedPtr = NULL;
    token = strtok_r(tmpBuf, "\n", &savedPtr);
    int index = 0;
    while (token != NULL) {
        if (index >= infoList->infoNum) {
            break;
        }
        infoList->infos[index].ssid = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * WIFI_SSID_LENGTH);
        infoList->infos[index].ssidLen = WIFI_SSID_LENGTH;
        infoList->infos[index].bssid = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (ETH_ADDR_LEN + 1));
        infoList->infos[index].bssidLen = ETH_ADDR_LEN + 1;
        infoList->infos[index].flags = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * WIFI_NETWORK_FLAGS_LENGTH);
        infoList->infos[index].flagsLen = WIFI_NETWORK_FLAGS_LENGTH;
        GetHalNetworkInfos(token, &(infoList->infos[index]));
        index++;
        token = strtok_r(NULL, "\n", &savedPtr);
    }
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pListNetworks fail!", __func__);
    }
    free(reply);
    HDF_LOGI("%{public}s P2pListNetworks success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSaveConfig(struct IWpaInterface *self, const char *ifName)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    struct wpa_supplicant *wpaSupp;

    int32_t ret = 0;
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaSupp = getWpaP2p();
    if (!wpaSupp) {
        HDF_LOGE("%{public}s wpaSupp is NULL!", __func__);
        return HDF_FAILURE;
    }

    ret = wpa_supplicant_ctrl_iface_save_config(wpaSupp);
    if (ret < 0) {
        HDF_LOGE("%{public}s P2pSaveConfig fail! ret=%d", __func__, ret);
    }
    HDF_LOGI("%{public}s P2pSaveConfig success", __func__);
    return HDF_SUCCESS;
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
        if (FillData(&hdiP2pDeviceInfoParam->wfdDeviceInfo, &hdiP2pDeviceInfoParam->wfdDeviceInfoLen,
            deviceInfoParam->wfdDeviceInfo, WIFI_P2P_WFD_DEVICE_INFO_LENGTH) != HDF_SUCCESS) {
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
        }
        if (hdiP2pDeviceInfoParam->p2pDeviceAddress != NULL) {
            OsalMemFree(hdiP2pDeviceInfoParam->p2pDeviceAddress);
        }
        if (hdiP2pDeviceInfoParam->primaryDeviceType != NULL) {
            OsalMemFree(hdiP2pDeviceInfoParam->primaryDeviceType);
        }
        if (hdiP2pDeviceInfoParam->deviceName != NULL) {
            OsalMemFree(hdiP2pDeviceInfoParam->deviceName);
        }
        if (hdiP2pDeviceInfoParam->wfdDeviceInfo != NULL) {
            OsalMemFree(hdiP2pDeviceInfoParam->wfdDeviceInfo);
        }
        if (hdiP2pDeviceInfoParam->operSsid != NULL) {
            OsalMemFree(hdiP2pDeviceInfoParam->operSsid);
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
        }
        if (hdiP2pInvitationReceivedParam->goDeviceAddress != NULL) {
            OsalMemFree(hdiP2pInvitationReceivedParam->goDeviceAddress);
        }
        if (hdiP2pInvitationReceivedParam->bssid != NULL) {
            OsalMemFree(hdiP2pInvitationReceivedParam->bssid);
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
        }
    }
    return ret;
}

static int32_t WpaFillP2pGroupStartedParam(struct P2pGroupStartedParam *groupStartedParam,
    struct HdiP2pGroupStartedParam *hdiP2pGroupStartedParam)
{
    int32_t ret = HDF_SUCCESS;
    if (groupStartedParam == NULL || hdiP2pGroupStartedParam == NULL) {
        HDF_LOGE("%{public}s: groupStartedParam or hdiP2pGroupStartedParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pGroupStartedParam->isGo = groupStartedParam->isGo;
    hdiP2pGroupStartedParam->isPersistent = groupStartedParam->isPersistent;
    hdiP2pGroupStartedParam->frequency = groupStartedParam->frequency;

    do {
        if (FillData(&hdiP2pGroupStartedParam->groupIfName, &hdiP2pGroupStartedParam->groupIfNameLen,
            groupStartedParam->groupIfName, WIFI_P2P_GROUP_IFNAME_LENGTH) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pGroupStartedParam->ssid, &hdiP2pGroupStartedParam->ssidLen,
            groupStartedParam->ssid, WIFI_SSID_LENGTH) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pGroupStartedParam->psk, &hdiP2pGroupStartedParam->pskLen,
            groupStartedParam->psk, WIFI_P2P_PASSWORD_SIZE) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill ssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pGroupStartedParam->passphrase, &hdiP2pGroupStartedParam->passphraseLen,
            groupStartedParam->passphrase, WIFI_P2P_PASSWORD_SIZE) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill ssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pGroupStartedParam->goDeviceAddress, &hdiP2pGroupStartedParam->goDeviceAddressLen,
            groupStartedParam->goDeviceAddress, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill ssid fail!", __func__);
            ret = HDF_FAILURE;
        }
    } while (0);

    if (ret != HDF_SUCCESS) {
        if (hdiP2pGroupStartedParam->groupIfName != NULL) {
            OsalMemFree(hdiP2pGroupStartedParam->groupIfName);
        }
        if (hdiP2pGroupStartedParam->ssid != NULL) {
            OsalMemFree(hdiP2pGroupStartedParam->ssid);
        }
        if (hdiP2pGroupStartedParam->psk != NULL) {
            OsalMemFree(hdiP2pGroupStartedParam->psk);
        }
        if (hdiP2pGroupStartedParam->passphrase != NULL) {
            OsalMemFree(hdiP2pGroupStartedParam->passphrase);
        }
        if (hdiP2pGroupStartedParam->goDeviceAddress != NULL) {
            OsalMemFree(hdiP2pGroupStartedParam->goDeviceAddress);
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
        }
        if (hdiP2pProvisionDiscoveryCompletedParam->generatedPin != NULL) {
            OsalMemFree(hdiP2pProvisionDiscoveryCompletedParam->generatedPin);
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
        }
        if (hdiP2pServDiscReqInfo->tlvs != NULL) {
            OsalMemFree(hdiP2pServDiscReqInfo->tlvs);
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
        }
        if (hdiP2pServDiscRespParam->tlvs != NULL) {
            OsalMemFree(hdiP2pServDiscRespParam->tlvs);
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
        }
        if (hdiP2pStaConnectStateParam->p2pDeviceAddress != NULL) {
            OsalMemFree(hdiP2pStaConnectStateParam->p2pDeviceAddress);
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
    struct HdiP2pDeviceInfoParam *hdiP2pDeviceInfo = NULL;
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventDeviceFound == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pDeviceInfo = (struct HdiP2pDeviceInfoParam *)OsalMemCalloc(sizeof(struct P2pDeviceInfoParam));
    if ((hdiP2pDeviceInfo == NULL) || (WpaFillP2pDeviceFoundParam(deviceInfoParam, hdiP2pDeviceInfo) != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: hdiP2pDeviceInfo is NULL or deviceInfoParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventDeviceFound(node->callbackObj, hdiP2pDeviceInfo, ifName);
    }
    HdiP2pDeviceInfoParamFree(hdiP2pDeviceInfo, true);
    return ret;
}

int32_t ProcessEventP2pDeviceLost(struct HdfWpaRemoteNode *node,
    struct P2pDeviceLostParam *deviceLostParam, const char *ifName)
{
    struct HdiP2pDeviceLostParam *hdiP2pDeviceLostParam = NULL;
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventDeviceLost == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pDeviceLostParam = (struct HdiP2pDeviceLostParam *)OsalMemCalloc(sizeof(struct P2pDeviceLostParam));
    if ((hdiP2pDeviceLostParam == NULL) || (WpaFillP2pDeviceLostParam(deviceLostParam, hdiP2pDeviceLostParam)
        != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: hdiP2pDeviceLostParam is NULL or deviceLostParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventDeviceLost(node->callbackObj, hdiP2pDeviceLostParam, ifName);
    }
    HdiP2pDeviceLostParamFree(hdiP2pDeviceLostParam, true);
    return ret;
}

int32_t ProcessEventP2pGoNegotiationRequest(struct HdfWpaRemoteNode *node,
    struct P2pGoNegotiationRequestParam *goNegotiationRequestParam, const char *ifName)
{
    struct HdiP2pGoNegotiationRequestParam *hdiP2pGoNegotiationRequestParam = NULL;
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventGoNegotiationRequest == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pGoNegotiationRequestParam = (struct HdiP2pGoNegotiationRequestParam *)OsalMemCalloc(
        sizeof(struct P2pGoNegotiationRequestParam));
    if ((hdiP2pGoNegotiationRequestParam == NULL) || (WpaFillP2pGoNegotiationRequestParam(goNegotiationRequestParam,
        hdiP2pGoNegotiationRequestParam) != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: hdiP2pGoNegotiationRequestParam is NULL or goNegotiationRequestParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventGoNegotiationRequest(node->callbackObj,
            hdiP2pGoNegotiationRequestParam, ifName);
    }
    HdiP2pGoNegotiationRequestParamFree(hdiP2pGoNegotiationRequestParam, true);
    return ret;
}

int32_t ProcessEventP2pGoNegotiationCompleted(struct HdfWpaRemoteNode *node, struct P2pGoNegotiationCompletedParam
    *goNegotiationCompletedParam, const char *ifName)
{
    struct HdiP2pGoNegotiationCompletedParam *hdiP2pGoNegotiationCompletedParam = NULL;
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventGoNegotiationCompleted == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pGoNegotiationCompletedParam->status = goNegotiationCompletedParam->status;
    if ((hdiP2pGoNegotiationCompletedParam == NULL) || (WpaFillP2pGoNegotiationCompletedParam(
        goNegotiationCompletedParam, hdiP2pGoNegotiationCompletedParam) != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: hdiP2pGoNegotiationCompletedParam is NULL or goNegotiationCompletedParam fialed!",
            __func__);
    } else {
        ret = node->callbackObj->OnEventGoNegotiationCompleted(node->callbackObj,
            hdiP2pGoNegotiationCompletedParam, ifName);
    }
    HdiP2pGoNegotiationCompletedParamFree(hdiP2pGoNegotiationCompletedParam, true);
    return ret;
}

int32_t ProcessEventP2pInvitationReceived(struct HdfWpaRemoteNode *node,
    struct P2pInvitationReceivedParam *invitationReceivedParam, const char *ifName)
{
    struct HdiP2pInvitationReceivedParam *hdiP2pInvitationReceivedParam = NULL;
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventInvitationReceived == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pInvitationReceivedParam = (struct HdiP2pInvitationReceivedParam *)OsalMemCalloc(
        sizeof(struct P2pInvitationReceivedParam));
    if ((hdiP2pInvitationReceivedParam == NULL) || (WpaFillP2pInvitationReceivedParam(
        invitationReceivedParam, hdiP2pInvitationReceivedParam) != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: hdiP2pInvitationReceivedParam is NULL or invitationReceivedParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventInvitationReceived(node->callbackObj, hdiP2pInvitationReceivedParam, ifName);
    }
    HdiP2pInvitationReceivedParamFree(hdiP2pInvitationReceivedParam, true);
    return ret;
}

int32_t ProcessEventP2pInvitationResult(struct HdfWpaRemoteNode *node,
    struct P2pInvitationResultParam *invitationResultParam, const char *ifName)
{
    struct HdiP2pInvitationResultParam *hdiP2pInvitationResultParam = NULL;
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventInvitationResult == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pInvitationResultParam = (struct HdiP2pInvitationResultParam *)OsalMemCalloc(
        sizeof(struct P2pInvitationResultParam));
    if ((hdiP2pInvitationResultParam == NULL) || (WpaFillP2pInvitationResultParam(
        invitationResultParam, hdiP2pInvitationResultParam) != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: hdiP2pInvitationResultParam is NULL or invitationResultParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventInvitationResult(node->callbackObj, hdiP2pInvitationResultParam, ifName);
    }
    HdiP2pInvitationResultParamFree(hdiP2pInvitationResultParam, true);
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
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventGroupFormationFailure == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiReason = (char *)OsalMemCalloc(WIFI_REASON_LENGTH);
    if ((hdiReason == NULL) || (strncpy_s(hdiReason, WIFI_REASON_LENGTH, reason, WIFI_REASON_LENGTH) != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: hdiReason is NULL or reason fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventGroupFormationFailure(node->callbackObj, hdiReason, ifName);
    }
    OsalMemFree(hdiReason);
    return ret;
}

int32_t ProcessEventP2pGroupStarted(struct HdfWpaRemoteNode *node,
    struct P2pGroupStartedParam *groupStartedParam, const char *ifName)
{
    struct HdiP2pGroupStartedParam *hdiP2pGroupStartedParam = NULL;
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventGroupStarted == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pGroupStartedParam = (struct HdiP2pGroupStartedParam *)OsalMemCalloc(sizeof(struct P2pGroupStartedParam));
    if ((hdiP2pGroupStartedParam == NULL) || (WpaFillP2pGroupStartedParam(groupStartedParam, hdiP2pGroupStartedParam)
        != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: hdiP2pGroupStartedParam is NULL or groupStartedParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventGroupStarted(node->callbackObj, hdiP2pGroupStartedParam, ifName);
    }
    HdiP2pGroupStartedParamFree(hdiP2pGroupStartedParam, true);
    return ret;
}

int32_t ProcessEventP2pGroupRemoved(struct HdfWpaRemoteNode *node,
    struct P2pGroupRemovedParam *groupRemovedParam, const char *ifName)
{
    struct HdiP2pGroupRemovedParam *hdiP2pGroupRemovedParam = NULL;
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventGroupRemoved == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pGroupRemovedParam = (struct HdiP2pGroupRemovedParam *)OsalMemCalloc(sizeof(struct P2pGroupRemovedParam));
    if ((hdiP2pGroupRemovedParam == NULL) || (WpaFillP2pGroupRemovedParam(groupRemovedParam, hdiP2pGroupRemovedParam)
        != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: hdiP2pGroupRemovedParam is NULL or groupRemovedParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventGroupRemoved(node->callbackObj, hdiP2pGroupRemovedParam, ifName);
    }
    HdiP2pGroupRemovedParamFree(hdiP2pGroupRemovedParam, true);
    return ret;
}

int32_t ProcessEventP2pProvisionDiscoveryCompleted(struct HdfWpaRemoteNode *node,
    struct P2pProvisionDiscoveryCompletedParam *provisionDiscoveryCompletedParam, const char *ifName)
{
    struct HdiP2pProvisionDiscoveryCompletedParam *hdiP2pProvisionDiscoveryCompletedParam = NULL;
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventProvisionDiscoveryCompleted == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pProvisionDiscoveryCompletedParam = (struct HdiP2pProvisionDiscoveryCompletedParam *)OsalMemCalloc(
        sizeof(struct P2pProvisionDiscoveryCompletedParam));
    if ((hdiP2pProvisionDiscoveryCompletedParam == NULL) || (WpaFillP2pProvisionDiscoveryCompletedParam(
        provisionDiscoveryCompletedParam, hdiP2pProvisionDiscoveryCompletedParam) != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: Param is NULL or provisionDiscoveryCompletedParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventProvisionDiscoveryCompleted(node->callbackObj,
            hdiP2pProvisionDiscoveryCompletedParam, ifName);
    }
    HdiP2pProvisionDiscoveryCompletedParamFree(hdiP2pProvisionDiscoveryCompletedParam, true);
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
    struct HdiP2pServDiscReqInfoParam *hdiP2pServDiscReqInfo = NULL;
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventServDiscReq == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pServDiscReqInfo = (struct HdiP2pServDiscReqInfoParam *)OsalMemCalloc(
        sizeof(struct P2pServDiscReqInfoParam));
    if ((hdiP2pServDiscReqInfo == NULL) || (WpaFillP2pServDiscReqParam(servDiscReqInfo, hdiP2pServDiscReqInfo)
        != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: hdiP2pServDiscReqInfo is NULL or servDiscReqInfo fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventServDiscReq(node->callbackObj, hdiP2pServDiscReqInfo, ifName);
    }
    HdiP2pServDiscReqInfoParamFree(hdiP2pServDiscReqInfo, true);
    return ret;
}

int32_t ProcessEventP2pServDiscResp(struct HdfWpaRemoteNode *node,
    struct P2pServDiscRespParam *servDiscRespParam, const char *ifName)
{
    struct HdiP2pServDiscRespParam *hdiP2pServDiscRespParam = NULL;
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventServDiscResp == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pServDiscRespParam = (struct HdiP2pServDiscRespParam *)OsalMemCalloc(sizeof(struct P2pServDiscRespParam));
    if ((hdiP2pServDiscRespParam == NULL) || (WpaFillP2pServDiscRespParam(servDiscRespParam, hdiP2pServDiscRespParam)
        != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: hdiP2pServDiscRespParam is NULL or servDiscRespParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventServDiscResp(node->callbackObj, hdiP2pServDiscRespParam, ifName);
    }
    HdiP2pServDiscRespParamFree(hdiP2pServDiscRespParam, true);
    return ret;
}

int32_t ProcessEventP2pStaConnectState(struct HdfWpaRemoteNode *node,
    struct P2pStaConnectStateParam *staConnectStateParam, const char *ifName)
{
    struct HdiP2pStaConnectStateParam *hdiP2pStaConnectStateParam = NULL;
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventStaConnectState == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pStaConnectStateParam = (struct HdiP2pStaConnectStateParam *)OsalMemCalloc(
        sizeof(struct P2pStaConnectStateParam));
    if ((hdiP2pStaConnectStateParam == NULL) || (WpaFillP2pStaConnectStateParam(
        staConnectStateParam, hdiP2pStaConnectStateParam) != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: hdiP2pStaConnectStateParam is NULL or staConnectStateParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventStaConnectState(node->callbackObj, hdiP2pStaConnectStateParam, ifName);
    }
    HdiP2pStaConnectStateParamFree(hdiP2pStaConnectStateParam, true);
    return ret;
}

int32_t ProcessEventP2pIfaceCreated(struct HdfWpaRemoteNode *node, struct P2pIfaceCreatedParam *ifaceCreatedParam,
    const char *ifName)
{
    struct HdiP2pIfaceCreatedParam *hdiP2pIfaceCreatedParam = NULL;
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventIfaceCreated == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pIfaceCreatedParam = (struct HdiP2pIfaceCreatedParam *)OsalMemCalloc(sizeof(struct P2pIfaceCreatedParam));
    if ((hdiP2pIfaceCreatedParam == NULL) || (WpaFillP2pIfaceCreatedParam(ifaceCreatedParam, hdiP2pIfaceCreatedParam)
        != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: hdiP2pIfaceCreatedParam is NULL or ifaceCreatedParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventIfaceCreated(node->callbackObj, hdiP2pIfaceCreatedParam, ifName);
    }
    HdiP2pIfaceCreatedParamFree(hdiP2pIfaceCreatedParam, true);
    return ret;
}
