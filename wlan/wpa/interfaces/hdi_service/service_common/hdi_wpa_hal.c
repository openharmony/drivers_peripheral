/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include <poll.h>
#include <unistd.h>
#include <hdf_log.h>
#include <pthread.h>
#include "securec.h"
#include "hdi_wpa_hal.h"
#include "hdi_wpa_common.h"
#include "wpa_common_cmd.h"
#ifndef OHOS_EUPDATER
#include "wpa_client.h"
#endif

#undef LOG_TAG
#define LOG_TAG "HdiWpaHal"

#define WPA_TRY_CONNECT_TIMES 20
#define WPA_TRY_CONNECT_SLEEP_TIME (100 * 1000) /* 100ms */
#define WPA_CMD_BUF_LEN 256
#define WPA_CMD_REPLY_BUF_SMALL_LEN 64
#define P2P_SERVICE_INFO_FIRST_SECTION 1
#define P2P_SERVICE_INFO_SECOND_SECTION 2
#define P2P_SERVICE_INFO_THIRD_SECTION 3
#define P2P_SERVICE_DISC_REQ_ONE 1
#define P2P_SERVICE_DISC_REQ_TWO 2
#define P2P_SERVICE_DISC_REQ_THREE 3
#define P2P_SERVICE_DISC_REQ_FOUR 4
#define P2P_SERVICE_DISC_REQ_FIVE 5
#define WPA_CB_CONNECTED 1
#define WPA_CB_DISCONNECTED 2
#define WPA_CB_ASSOCIATING 3
#define WPA_CB_ASSOCIATED 4
#define WPS_EVENT_PBC_OVERLAP "WPS-OVERLAP-DETECTED PBC session overlap"
#define WPA_EVENT_BSSID_CHANGED "WPA-EVENT-BSSID-CHANGED "
#define WPA_EVENT_ASSOCIATING "Request association with "
#define WPA_EVENT_ASSOCIATED "Associated with "
#define REPLY_BUF_LENGTH 4096
#define CONNECTION_PWD_WRONG_STATUS 1
#define CONNECTION_FULL_STATUS 17
#define CONNECTION_REJECT_STATUS 37
#define WLAN_STATUS_AUTH_TIMEOUT 16
#define MAC_AUTH_RSP2_TIMEOUT 5201
#define MAC_AUTH_RSP4_TIMEOUT 5202
#define MAC_ASSOC_RSP_TIMEOUT 5203
#define SSID_EMPTY_LENGTH 1
static const int MAX_IFACE_LEN = 6;

#define WPA_CTRL_OPEN_IFNAME "@abstract:"CONFIG_ROOR_DIR"/sockets/wpa/wlan0"

static WifiWpaInterface *g_wpaInterface = NULL;

static int WpaCliConnect(WifiWpaInterface *p)
{
    HDF_LOGI("Wpa connect start.");
    if (p == NULL) {
        HDF_LOGE("Wpa connect parameter error.");
        return -1;
    }
    if (p->staCtrl.pSend != NULL && p->p2pCtrl.pSend != NULL && p->chbaCtrl.pSend != NULL &&
        p->commonCtrl.pSend != NULL) {
        HDF_LOGE("Wpa is already connected.");
        return 0;
    }
    int count = WPA_TRY_CONNECT_TIMES;
    while (count-- > 0) {
        if (!InitWpaCtrl(&p->staCtrl, WPA_CTRL_OPEN_IFNAME) && !InitWpaCtrl(&p->p2pCtrl, WPA_CTRL_OPEN_IFNAME) &&
            !InitWpaCtrl(&p->chbaCtrl, WPA_CTRL_OPEN_IFNAME) && !InitWpaCtrl(&p->commonCtrl, WPA_CTRL_OPEN_IFNAME)) {
            HDF_LOGI("Global wpa interface connect successfully!");
            break;
        } else {
            HDF_LOGE("Init wpaCtrl failed.");
        }
        usleep(WPA_TRY_CONNECT_SLEEP_TIME);
    }
    if (count <= 0) {
        return -1;
    }
    p->threadRunFlag = 1;
    HDF_LOGI("Wpa connect finish.");
    return 0;
}

static void WpaCliClose(WifiWpaInterface *p)
{
    HDF_LOGI("Wpa connect close.");
    if (p->tid != 0) {
        p->threadRunFlag = 0;
        pthread_join(p->tid, NULL);
        p->tid = 0;
    }
    ReleaseWpaCtrl(&p->staCtrl);
    ReleaseWpaCtrl(&p->p2pCtrl);
    ReleaseWpaCtrl(&p->chbaCtrl);
    ReleaseWpaCtrl(&p->commonCtrl);
    return;
}

static int WpaCliAddIface(WifiWpaInterface *p, const AddInterfaceArgv *argv, bool isWpaAdd)
{
    HDF_LOGI("enter WpaCliAddIface");
    if (p == NULL || argv == NULL) {
        return -1;
    }
    WpaIfaceInfo *info = p->ifaces;
    while (info != NULL) {
        if (strncmp(info->name, argv->name, MAX_IFACE_LEN) == 0) {
            return 0;
        }
        info = info->next;
    }
    info = (WpaIfaceInfo *)calloc(1, sizeof(WpaIfaceInfo));
    if (info == NULL) {
        return -1;
    }
    if (strcpy_s(info->name, sizeof(info->name), argv->name) != 0) {
        HDF_LOGI("WpaCliAddIface strcpy_s fail");
        free(info);
        info = NULL;
        return -1;
    }
    char cmd[WPA_CMD_BUF_LEN] = {0};
    char buf[WPA_CMD_REPLY_BUF_SMALL_LEN] = {0};
    HDF_LOGI("Add interface start.");
    if (isWpaAdd && (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "INTERFACE_ADD %s\t%s",
        argv->name, argv->confName) < 0 || WpaCliCmd(cmd, buf, sizeof(buf)) != 0)) {
        free(info);
        info = NULL;
        HDF_LOGI("WpaCliAddIface failed, cmd: %{public}s, buf: %{public}s", cmd, buf);
        return -1;
    }
    HDF_LOGI("Add interface finish, cmd: %{public}s, buf: %{public}s", cmd, buf);
    info->next = p->ifaces;
    p->ifaces = info;
    return 0;
}

static int WpaCliRemoveIface(WifiWpaInterface *p, const char *name)
{
    HDF_LOGI("enter WpaCliRemoveIface.");
    if (p == NULL || name == NULL) {
        return -1;
    }
    WpaIfaceInfo *prev = NULL;
    WpaIfaceInfo *info = p->ifaces;
    while (info != NULL) {
        if (strncmp(info->name, name, MAX_IFACE_LEN) == 0) {
            break;
        }
        prev = info;
        info = info->next;
    }
    if (info == NULL) {
        HDF_LOGI("the WpaInterface info is null");
        return 0;
    }
    char cmd[WPA_CMD_BUF_LEN] = {0};
    char buf[WPA_CMD_REPLY_BUF_SMALL_LEN] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "INTERFACE_REMOVE %s", name) < 0 ||
        WpaCliCmd(cmd, buf, sizeof(buf)) != 0) {
        return -1;
    }
    if (prev == NULL) {
        p->ifaces = info->next;
    } else {
        prev->next = info->next;
    }
    HDF_LOGI("Remove interface finish, cmd: %{public}s, buf: %{public}s", cmd, buf);
    free(info);
    info = NULL;
    return 0;
}

static int WpaCliWpaTerminate(void)
{
    HDF_LOGI("enter WpaCliWpaTerminate.");
    char cmd[WPA_CMD_BUF_LEN] = {0};
    char buf[WPA_CMD_REPLY_BUF_SMALL_LEN] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "TERMINATE") < 0) {
        HDF_LOGE("WpaCliWpaTerminate, snprintf err");
        return -1;
    }
    return WpaCliCmd(cmd, buf, sizeof(buf));
}

void InitWifiWpaGlobalInterface(void)
{
    HDF_LOGI("enter InitWifiWpaGlobalInterface.");
    if (g_wpaInterface != NULL) {
        return;
    }
    g_wpaInterface = (WifiWpaInterface *)calloc(1, sizeof(WifiWpaInterface));
    if (g_wpaInterface == NULL) {
        HDF_LOGE("Failed to create wpa interface!");
        return;
    }
    g_wpaInterface->wpaCliConnect = WpaCliConnect;
    g_wpaInterface->wpaCliClose = WpaCliClose;
    g_wpaInterface->wpaCliAddIface = WpaCliAddIface;
    g_wpaInterface->wpaCliRemoveIface = WpaCliRemoveIface;
    g_wpaInterface->wpaCliTerminate = WpaCliWpaTerminate;
    g_wpaInterface->ifaces = NULL;
}
 
WifiWpaInterface *GetWifiWpaGlobalInterface(void)
{
    HDF_LOGI("enter GetWifiWpaGlobalInterface.");
    return g_wpaInterface;
}

void ReleaseWpaGlobalInterface(void)
{
    HDF_LOGI("enter ReleaseWpaGlobalInterface.");
    if (g_wpaInterface == NULL) {
        return;
    }
    WpaIfaceInfo *p = g_wpaInterface->ifaces;
    while (p != NULL) {
        WpaIfaceInfo *q = p->next;
        free(p);
        p = q;
    }
    WpaCliClose(g_wpaInterface);
    free(g_wpaInterface);
    g_wpaInterface = NULL;
}

WpaCtrl *GetStaCtrl(void)
{
    HDF_LOGI("enter GetStaCtrl");
    if (g_wpaInterface == NULL) {
        HDF_LOGE("GetStaCtrl g_wpaInterface = NULL!");
        return NULL;
    }
    return &g_wpaInterface->staCtrl;
}

WpaCtrl *GetP2pCtrl(void)
{
    HDF_LOGI("enter GetP2pCtrl");
    if (g_wpaInterface == NULL) {
        HDF_LOGE("GetP2pCtrl g_wpaInterface = NULL!");
        return NULL;
    }
    return &g_wpaInterface->p2pCtrl;
}

WpaCtrl *GetChbaCtrl(void)
{
    HDF_LOGI("enter GetChbaCtrl");
    if (g_wpaInterface == NULL) {
        HDF_LOGE("GetChbaCtrl g_wpaInterface = NULL!");
        return NULL;
    }
    return &g_wpaInterface->chbaCtrl;
}

WpaCtrl *GetCommonCtrl(void)
{
    HDF_LOGI("enter GetCommonCtrl");
    if (g_wpaInterface == NULL) {
        HDF_LOGE("GetCommonCtrl g_wpaInterface = NULL!");
        return NULL;
    }
    return &g_wpaInterface->commonCtrl;
}

void ReleaseIfaceCtrl(char *ifName, int len)
{
    if (g_wpaInterface == NULL) {
        return;
    }
    if (len < IFNAME_LEN_MIN || len > IFNAME_LEN_MAX) {
        HDF_LOGE("ifname is invalid");
        return;
    }
    if (strncmp(ifName, "wlan0", strlen("wlan0")) == 0) {
        ReleaseWpaCtrl(&(g_wpaInterface->staCtrl));
        ReleaseWpaCtrl(&(g_wpaInterface->p2pCtrl));
        ReleaseWpaCtrl(&(g_wpaInterface->chbaCtrl));
#ifndef OHOS_EUPDATER
        ReleaseEventCallback();
#endif
    }
}
