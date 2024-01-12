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
#include "hostapd_common_cmd.h"
#include <securec.h>
#include <hdf_base.h>
#include <errno.h>
#include <hdf_log.h>
#include <osal_time.h>
#include <osal_mem.h>
#include "v1_0/ihostapd_callback.h"
#include "v1_0/ihostapd_interface.h"
#include "ap/ap_config.h"
#include "ap/hostapd.h"
#include "ap_ctrl_iface.h"
#include "ap/ctrl_iface_ap.h"
#include "ap_ctrl_iface.h"
#include "ap_main.h"
#include "hostapd_client.h"
#include <unistd.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>

pthread_t g_tid;

struct HdfHostapdStubData *HdfHostapdStubDriver(void)
{
    static struct HdfHostapdStubData registerManager;
    return &registerManager;
}

static void SplitCmdString(const char *startCmd, struct StApMainParam *pParam)
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

static void *ApThreadMain(void *p)
{
    const char *startCmd;
    struct StApMainParam param = {0};
    char *tmpArgv[MAX_WPA_MAIN_ARGC_NUM] = {0};

    if (p == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return NULL;
    }
    startCmd = (const char *)p;
    HDF_LOGE("%{public}s: startCmd: %{public}s", __func__, startCmd);
    SplitCmdString(startCmd, &param);
    for (int i = 0; i < param.argc; i++) {
        tmpArgv[i] = param.argv[i];
        HDF_LOGE("%{public}s: tmpArgv[%{public}d]: %{public}s", __func__, i, tmpArgv[i]);
    }
    int ret = ap_main(param.argc, tmpArgv);
    HDF_LOGI("%{public}s: run ap_main ret:%{public}d.", __func__, ret);
    return NULL;
}

static int32_t StartApMain(const char *moduleName, const char *startCmd)
{
    int32_t ret;

    if (moduleName == NULL || startCmd == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM ;
    }
    ret = pthread_create(&g_tid, NULL, ApThreadMain, (void *)startCmd);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Create Ap thread failed, error code: %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_setname_np(g_tid, "ApMainThread");
    HDF_LOGE("%{public}s: pthread_create ID: %{public}p.", __func__, (void*)g_tid);
    usleep(WPA_SLEEP_TIME);
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceEnableAp(struct IHostapdInterface *self, const char *ifName,
    int32_t id)
{
    struct hostapd_data *hostApd;
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: Input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hostApd = getHostapd();
    if (hostApd == NULL) {
        HDF_LOGE("%{public}s hostApd is null.", __func__);
        return HDF_FAILURE;
    }
    ret = hostapd_ctrl_iface_enable(hostApd->iface);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Enable Ap failed!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceDisableAp(struct IHostapdInterface *self, const char *ifName,
    int32_t id)
{
    struct hostapd_data *hostApd;
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: Input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hostApd = getHostapd();
    if (hostApd == NULL) {
        HDF_LOGE("%{public}s hostApd is null.", __func__);
        return HDF_FAILURE;
    }
    ret = hostapd_ctrl_iface_disable(hostApd->iface);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Disable Ap failed!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceStartAp(struct IHostapdInterface *self)
{
    int32_t ret;

    (void)self;
    ret = StartApMain(WPA_HOSTAPD_NAME, START_CMD);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: StartHostapd failed, error code: %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGE("%{public}s: hostapd start successfully!", __func__);
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceStopAp(struct IHostapdInterface *self)
{
    (void)self;
    /* Need IHostapdInterfaceReleaseInstance to stop hostapd service. */
    HDF_LOGI("%{public}s: hostapd stop successfully!", __func__);
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceSetApPasswd(struct IHostapdInterface *self, const char *ifName,
    const char *pass, int32_t id)
{
    struct hostapd_data *hostApd;
    char cmd[CMD_SIZE] = {0};
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (ifName == NULL || pass == NULL) {
        HDF_LOGE("%{public}s: Input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hostApd = getHostapd();
    if (hostApd == NULL) {
        HDF_LOGE("%{public}s hostApd is null.", __func__);
        return HDF_FAILURE;
    }
    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "wpa_passphrase %s", pass);
    if (ret < EOK) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, ret = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }
    ret = hostapd_ctrl_iface_set(hostApd, cmd);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Hostapd failed to set password!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceSetApName(struct IHostapdInterface *self, const char *ifName,
    const char *name, int32_t id)
{
    struct hostapd_data *hostApd;
    char cmd[CMD_SIZE] = {0};
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (ifName == NULL || name == NULL) {
        HDF_LOGE("%{public}s: Input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hostApd = getHostapd();
    if (hostApd == NULL) {
        HDF_LOGE("%{public}s hostApd is null.", __func__);
        return HDF_FAILURE;
    }
    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "ssid %s", name);
    if (ret < EOK) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, ret = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }
    ret = hostapd_ctrl_iface_set(hostApd, cmd);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Hostapd failed to set name!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceSetApWpaValue(struct IHostapdInterface *self, const char *ifName,
    int32_t securityType, int32_t id)
{
    struct hostapd_data *hostApd;
    char cmd[CMD_SIZE] = {0};
    int32_t ret = HDF_FAILURE;

    (void)self;
    hostApd = getHostapd();
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: Input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    switch (securityType) {
        case NONE:
            // The authentication mode is NONE.
            ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "wpa 0");
            break;
        case WPA_PSK:
            // The authentication mode is WPA-PSK.
            ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "wpa 1");
            break;
        case WPA2_PSK:
            // The authentication mode is WPA2-PSK.
            ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "wpa 2");
            break;
        default:
            HDF_LOGE("Unknown encryption type!");
            return ret;
    }
    if (ret < EOK) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, Type = %{public}d", __func__, cmd, securityType);
        return HDF_FAILURE;
    }
    ret = hostapd_ctrl_iface_set(hostApd, cmd);
    if (ret == 0 && securityType != NONE) {
        /*
         * If the value of wpa is switched between 0, 1, and 2, the wpa_key_mgmt,
         * wpa_pairwise, and rsn_pairwise attributes must be set. Otherwise, the
         * enable or STA cannot be connected.
         */
        strcpy_s(cmd, sizeof(cmd), "wpa_key_mgmt WPA-PSK");
        ret = hostapd_ctrl_iface_set(hostApd, cmd);
    }
    if (ret == 0 && securityType == WPA_PSK) {
        strcpy_s(cmd, sizeof(cmd), "wpa_pairwise CCMP");
        ret = hostapd_ctrl_iface_set(hostApd, cmd);
    }
    if (ret == 0 && securityType == WPA2_PSK) {
        strcpy_s(cmd, sizeof(cmd), "rsn_pairwise CCMP");
        ret = hostapd_ctrl_iface_set(hostApd, cmd);
    }
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Hostapd failed to set securityType!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceSetApBand(struct IHostapdInterface *self, const char *ifName,
    int32_t band, int32_t id)
{
    struct hostapd_data *hostApd;
    char cmd[CMD_SIZE] = {0};
    const char *hwMode = NULL;
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: Input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hostApd = getHostapd();
    if (hostApd == NULL) {
        HDF_LOGE("%{public}s hostApd is null.", __func__);
        return HDF_FAILURE;
    }
    switch (band) {
        case AP_NONE_BAND:
            /* Unknown frequency band. */
            hwMode = "any";
            break;
        case AP_2GHZ_BAND:
            /* BAND_2_4_GHZ. */
            hwMode = "g";
            break;
        case AP_5GHZ_BAND:
            /* BAND_5_GHZ. */
            hwMode = "a";
            break;
        default:
            HDF_LOGE("Invalid band!");
            return HDF_FAILURE;
        }
    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "hw_mode %s", hwMode);
    if (ret < EOK) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, ret = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }
    ret = hostapd_ctrl_iface_set(hostApd, cmd);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Hostapd failed to set AP bandwith!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceSetAp80211n(struct IHostapdInterface *self, const char *ifName,
    int32_t value, int32_t id)
{
    struct hostapd_data *hostApd;
    char cmd[CMD_SIZE] = {0};
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: Input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hostApd = getHostapd();
    if (hostApd == NULL) {
        HDF_LOGE("%{public}s hostApd is null.", __func__);
        return HDF_FAILURE;
    }
    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "ieee80211n %d", value);
    if (ret < EOK) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, ret = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }
    ret = hostapd_ctrl_iface_set(hostApd, cmd);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Hostapd failed to set Ap80211n!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceSetApWmm(struct IHostapdInterface *self, const char *ifName,
    int32_t value, int32_t id)
{
    struct hostapd_data *hostApd;
    char cmd[CMD_SIZE] = {0};
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: Input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hostApd = getHostapd();
    if (hostApd == NULL) {
        HDF_LOGE("%{public}s hostApd is null.", __func__);
        return HDF_FAILURE;
    }
    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "wmm_enabled %d", value);
    if (ret < EOK) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, ret = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }
    ret = hostapd_ctrl_iface_set(hostApd, cmd);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Hostapd failed to set ApWmm!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceSetApChannel(struct IHostapdInterface *self, const char *ifName,
    int32_t channel, int32_t id)
{
    struct hostapd_data *hostApd;
    char cmd[CMD_SIZE] = {0};
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: Input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hostApd = getHostapd();
    if (hostApd == NULL) {
        HDF_LOGE("%{public}s hostApd is null.", __func__);
        return HDF_FAILURE;
    }
    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "channel %d", channel);
    if (ret < EOK) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, ret = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }
    ret = hostapd_ctrl_iface_set(hostApd, cmd);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Hostapd failed to set ApWmm!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceSetApMaxConn(struct IHostapdInterface *self, const char *ifName,
    int32_t maxConn, int32_t id)
{
    struct hostapd_data *hostApd;
    char cmd[CMD_SIZE] = {0};
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: Input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hostApd = getHostapd();
    if (hostApd == NULL) {
        HDF_LOGE("%{public}s hostApd is null.", __func__);
        return HDF_FAILURE;
    }
    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "max_num_sta %d", maxConn);
    if (ret < EOK) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{public}s, ret = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }
    ret = hostapd_ctrl_iface_set(hostApd, cmd);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Hostapd failed to set ApWmm!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceSetMacFilter(struct IHostapdInterface *self, const char *ifName,
    const char *mac, int32_t id)
{
    struct hostapd_data *hostApd;

    (void)self;
    if (ifName == NULL || mac == NULL) {
        HDF_LOGE("%{public}s: SetMacFilter or ifName is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hostApd = getHostapd();
    if (hostApd == NULL) {
        HDF_LOGE("%{public}s hostApd is null.", __func__);
        return HDF_FAILURE;
    }
    if (!hostapd_ctrl_iface_acl_add_mac(
        &hostApd->conf->deny_mac, &hostApd->conf->num_deny_mac, mac)) {
        hostapd_disassoc_deny_mac(hostApd);
        HDF_LOGE("%{public}s: Hostapd add mac success!", __func__);
    } else {
        HDF_LOGE("%{public}s: Hostapd failed to add mac!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceDelMacFilter(struct IHostapdInterface *self, const char *ifName,
    const char *mac, int32_t id)
{
    struct hostapd_data *hostApd;

    (void)self;
    if (ifName == NULL || mac == NULL) {
        HDF_LOGE("%{public}s: Input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hostApd = getHostapd();
    if (hostApd == NULL) {
        HDF_LOGE("%{public}s hostApd is null.", __func__);
        return HDF_FAILURE;
    }
    if (hostapd_ctrl_iface_acl_del_mac(
        &hostApd->conf->deny_mac, &hostApd->conf->num_deny_mac, mac)) {
        HDF_LOGE("%{public}s: Hostapd failed to delete the mac!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceGetStaInfos(struct IHostapdInterface *self, const char *ifName,
    char *buf, uint32_t bufLen, int32_t size, int32_t id)
{
    struct hostapd_data *hostApd;
    char cmd[CMD_SIZE] = {0};
    int32_t ret = HDF_FAILURE;
    char *reqBuf = (char *)calloc(BUFFSIZE_REQUEST, sizeof(char));

    (void)self;
    if (ifName == NULL || buf == NULL || reqBuf == NULL) {
        HDF_LOGE("%{public}s: Input parameter invalid or calloc failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hostApd = getHostapd();
    if (hostApd == NULL) {
        HDF_LOGE("%{public}s hostapd is null.", __func__);
        free(reqBuf);
        return HDF_FAILURE;
    }
    ret = hostapd_ctrl_iface_sta_first(hostApd, reqBuf, BUFFSIZE_REQUEST);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Hostapd failed to get first sta!", __func__);
        free(reqBuf);
        return HDF_FAILURE;
    }
    do {
        char *pos = reqBuf;
        while (*pos != '\0' && *pos != '\n') {
            /* return station info, first line is mac address */
            pos++;
        }
        *pos = '\0';
        if (strcmp(reqBuf, "") != 0) {
            int bufLen = strlen(buf);
            int staLen = strlen(reqBuf);
            if (bufLen + staLen + 1 >= size) {
                free(reqBuf);
                reqBuf = NULL;
                return HDF_SUCCESS;
            }
            buf[bufLen++] = ',';
            for (int i = 0; i < staLen; ++i) {
                buf[bufLen + i] = reqBuf[i];
            }
            buf[bufLen + staLen] = '\0';
        }
        if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "%s", reqBuf) < 0) {
            HDF_LOGE("%{public}s: Hostapd failed to get sta infos!", __func__);
            free(reqBuf);
            return HDF_FAILURE;
        }
    } while (hostapd_ctrl_iface_sta_next(hostApd, cmd, reqBuf, BUFFSIZE_REQUEST));
    free(reqBuf);
    reqBuf = NULL;
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceDisassociateSta(struct IHostapdInterface *self, const char *ifName,
    const char *mac, int32_t id)
{
    struct hostapd_data *hostApd;
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (ifName == NULL || mac == NULL) {
        HDF_LOGE("%{public}s: Input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hostApd = getHostapd();
    if (hostApd == NULL) {
        HDF_LOGE("%{public}s hostApd is null.", __func__);
        return HDF_FAILURE;
    }
    ret = hostapd_ctrl_iface_disassociate(hostApd, mac);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Hostapd failed to disassociate with sta!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t ProcessEventStaJoin(struct HdfHostapdRemoteNode *node,
    struct HostapdApCbParm *apCbParm, const char *ifName)
{
    struct HdiApCbParm *hdiApCbParm = NULL;
    int32_t ret = HDF_FAILURE;

    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventStaJoin == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiApCbParm = (struct HdiApCbParm *)OsalMemCalloc(sizeof(struct HdiApCbParm));
    if (hdiApCbParm == NULL) {
        HDF_LOGE("%{public}s: hdiApCbParm is NULL!", __func__);
        return HDF_FAILURE;
    } else {
        hdiApCbParm->content = OsalMemCalloc(WIFI_HOSTAPD_CB_CONTENT_LENGTH);
        if (hdiApCbParm->content == NULL) {
            HDF_LOGE("%{public}s: hdiApCbParm->content is NULL!", __func__);
        } else {
            os_memcpy(hdiApCbParm->content, apCbParm->content, WIFI_HOSTAPD_CB_CONTENT_LENGTH);
            hdiApCbParm->id = apCbParm->id;
            ret = node->callbackObj->OnEventStaJoin(node->callbackObj, hdiApCbParm, ifName);
        }
    }
    HdiApCbParmFree(hdiApCbParm, true);
    return ret;
}

static int32_t ProcessEventApState(struct HdfHostapdRemoteNode *node,
    struct HostapdApCbParm *apCbParm, const char *ifName)
{
    struct HdiApCbParm *hdiApCbParm  = NULL;
    int32_t ret = HDF_FAILURE;
    
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventApState == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiApCbParm = (struct HdiApCbParm *)OsalMemCalloc(sizeof(struct HdiApCbParm));
    if (hdiApCbParm == NULL) {
        HDF_LOGE("%{public}s: hdiApCbParm is NULL!", __func__);
        return HDF_FAILURE;
    } else {
        hdiApCbParm->content = OsalMemCalloc(WIFI_HOSTAPD_CB_CONTENT_LENGTH);
        if (hdiApCbParm->content == NULL) {
            HDF_LOGE("%{public}s: hdiApCbParm is NULL!", __func__);
        } else {
            os_memcpy(hdiApCbParm->content, apCbParm->content, WIFI_HOSTAPD_CB_CONTENT_LENGTH);
            hdiApCbParm->id = apCbParm->id;
            ret = node->callbackObj->OnEventApState(node->callbackObj, hdiApCbParm, ifName);
        }
    }
    HdiApCbParmFree(hdiApCbParm, true);
    return ret;
}

int32_t ProcessEventHostapdNotify(struct HdfHostapdRemoteNode *node, char *notifyParam, const char *ifName)
{
    int32_t ret = HDF_FAILURE;

    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventHostApdNotify == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (strlen(notifyParam) == 0) {
        ret = HDF_FAILURE;
    }
    return ret;
}

static int32_t HdfHostapdCallbackFun(uint32_t event, void *data, const char *ifName)
{
    struct HdfHostapdRemoteNode *pos = NULL;
    struct DListHead *head = NULL;
    int32_t ret = HDF_FAILURE;

    (void)OsalMutexLock(&HdfHostapdStubDriver()->mutex);
    head = &HdfHostapdStubDriver()->remoteListHead;
    HDF_LOGD("%s: enter HdfHostapdCallbackFun event =%d ", __FUNCTION__, event);
    if (data == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: data or ifName is NULL!", __func__);
        (void)OsalMutexUnlock(&HdfHostapdStubDriver()->mutex);
        return HDF_ERR_INVALID_PARAM;
    }
    DLIST_FOR_EACH_ENTRY(pos, head, struct HdfHostapdRemoteNode, node) {
        if (pos == NULL) {
            HDF_LOGE("%{public}s: pos is NULL", __func__);
            break;
        }
        if (pos->service == NULL || pos->callbackObj == NULL) {
            HDF_LOGW("%{public}s: pos->service or pos->callbackObj NULL", __func__);
            continue;
        }
        switch (event) {
            case HOSTAPD_EVENT_STA_JOIN:
                ret = ProcessEventStaJoin(pos, (struct HostapdApCbParm *)data, ifName);
                break;
            case HOSTAPD_EVENT_AP_STATE:
                ret = ProcessEventApState(pos, (struct HostapdApCbParm *)data, ifName);
                break;
            case HOSTAPD_EVENT_HOSTAPD_NOTIFY:
                ret = ProcessEventHostapdNotify(pos, (char *)data, ifName);
                break;
            default:
                HDF_LOGE("%{public}s: unknown eventId:%{public}d", __func__, event);
                break;
        }
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: dispatch code fialed, error code: %{public}d", __func__, ret);
        }
    }
    (void)OsalMutexUnlock(&HdfHostapdStubDriver()->mutex);
    return ret;
}

static int32_t HdfHostapdAddRemoteObj(struct IHostapdCallback *self)
{
    struct HdfHostapdRemoteNode *pos = NULL;
    struct DListHead *head = &HdfHostapdStubDriver()->remoteListHead;

    if (self == NULL) {
        HDF_LOGE("%{public}s:self is null.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!DListIsEmpty(head)) {
            DLIST_FOR_EACH_ENTRY(pos, head, struct HdfHostapdRemoteNode, node) {
            if (pos->service == self->AsObject(self)) {
                HDF_LOGE("%{public}s: pos->service == self", __func__);
                return HDF_FAILURE;
            }
        }
    }
    struct HdfHostapdRemoteNode *newRemoteNode =
        (struct HdfHostapdRemoteNode *)OsalMemCalloc(sizeof(struct HdfHostapdRemoteNode));
    if (newRemoteNode == NULL) {
        HDF_LOGE("%{public}s:newRemoteNode is NULL", __func__);
        return HDF_FAILURE;
    }
    newRemoteNode->callbackObj = self;
    newRemoteNode->service = self->AsObject(self);
    DListInsertTail(&newRemoteNode->node, head);
    return HDF_SUCCESS;
}

static void HdfHostapdDelRemoteObj(struct IHostapdCallback *self)
{
    struct HdfHostapdRemoteNode *pos = NULL;
    struct HdfHostapdRemoteNode *tmp = NULL;
    struct DListHead *head = &HdfHostapdStubDriver()->remoteListHead;

    DLIST_FOR_EACH_ENTRY_SAFE(pos, tmp, head, struct HdfHostapdRemoteNode, node) {
        if (pos->service->index == self->AsObject(self)->index) {
            DListRemove(&(pos->node));
            IHostapdCallbackRelease(pos->callbackObj);
            OsalMemFree(pos);
            break;
        }
    }
    IHostapdCallbackRelease(self);
}

int32_t HostapdInterfaceRegisterEventCallback(struct IHostapdInterface *self,
    struct IHostapdCallback *cbFunc, const char *ifName)
{
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (cbFunc == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    (void)OsalMutexLock(&HdfHostapdStubDriver()->mutex);
    do {
        ret = HdfHostapdAddRemoteObj(cbFunc);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: HdfSensorAddRemoteObj false", __func__);
            break;
        }
        ret = HostapdRegisterEventCallback(HdfHostapdCallbackFun, WIFI_HOSTAPD_TO_HAL_CLIENT, ifName);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: Register failed!, error code: %{public}d", __func__, ret);
            HdfHostapdDelRemoteObj(cbFunc);
            break;
        }
    } while (0);
    (void)OsalMutexUnlock(&HdfHostapdStubDriver()->mutex);
    return ret;
}

int32_t HostapdInterfaceUnregisterEventCallback(struct IHostapdInterface *self,
    struct IHostapdCallback *cbFunc, const char *ifName)
{
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (cbFunc == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    (void)OsalMutexLock(&HdfHostapdStubDriver()->mutex);
    HdfHostapdDelRemoteObj(cbFunc);
    if (DListIsEmpty(&HdfHostapdStubDriver()->remoteListHead)) {
        ret = HostapdUnregisterEventCallback(HdfHostapdCallbackFun, WIFI_HOSTAPD_TO_HAL_CLIENT, ifName);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: Unregister failed!, error code: %{public}d", __func__, ret);
        }
    }
    (void)OsalMutexUnlock(&HdfHostapdStubDriver()->mutex);
    return HDF_SUCCESS;
}

int32_t HostApdInterfaceShellCmd(struct IHostapdInterface *self, const char *ifName, const char *cmd)
{
    struct hostapd_data *hostApd;

    (void)self;
    if (ifName == NULL || cmd == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hostApd = getHostapd();
    if (hostApd == NULL) {
        HDF_LOGE("%{public}s wpaSupp == NULL", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}