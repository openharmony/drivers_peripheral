/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
 
#include "hdi_wpa_hal.h"
 
#include <poll.h>
#include <unistd.h>
#include <hdf_log.h>
#include <pthread.h>
 
#include "wpa_common_cmd.h"
#include "ethernet_eap_client.h"
#include "common/wpa_ctrl.h"
#include "securec.h"
 
#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "EthHdiWpaHal"
#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif
#define LOG_DOMAIN 0xD0015b0
 
#define WPA_TRY_CONNECT_TIMES 20
#define WPA_TRY_CONNECT_SLEEP_TIME (100 * 1000) /* 100ms */
#define WPA_CMD_BUF_LEN 256
#define WPA_CMD_REPLY_BUF_LEN 64
#define CMD_BUFFER_SIZE 2148
#define MAX_NAME_LEN 12
#define REPLY_BUF_LENGTH (4096 * 10)
#define REPLY_BUF_SMALL_LENGTH 64
#define REPLY_BUF_STA_INFO_LENGTH 2048
#define CMD_BUFFER_MIN_SIZE 15
 
static EthWpaInstance *g_wpaInstance = NULL;
 
static WpaCtrl *GetEthWpaInsCtrl(void)
{
    if (g_wpaInstance == NULL) {
        HDF_LOGE("GetEthWpaInsCtrl g_wpaInstance = NULL!");
        return NULL;
    }
    return &g_wpaInstance->staCtrl;
}
 
int InitWpaCtrl(WpaCtrl *pCtrl, const char *ctrlPath)
{
    if (pCtrl == NULL || ctrlPath == NULL) {
        return -1;
    }
    pCtrl->pSend = wpa_ctrl_open(ctrlPath);
    if (pCtrl->pSend == NULL) {
        HDF_LOGE("open wpa control send interface failed!");
        ReleaseWpaCtrl(pCtrl);
        return -1;
    }
    return 0;
}
 
void ReleaseWpaCtrl(WpaCtrl *pCtrl)
{
    if (pCtrl == NULL) {
        return;
    }
    if (pCtrl->pSend != NULL) {
        wpa_ctrl_close(pCtrl->pSend);
        pCtrl->pSend = NULL;
    }
    if (pCtrl->pRecv != NULL) {
        wpa_ctrl_close(pCtrl->pRecv);
        pCtrl->pRecv = NULL;
    }
}
 
static int StaCliCmd(WpaCtrl *ctrl, const char *cmd, char *buf, size_t bufLen)
{
    HDF_LOGI("enter StaCliCmd");
    if (ctrl == NULL || ctrl->pSend == NULL || cmd == NULL || buf == NULL || bufLen == 0) {
        HDF_LOGE("StaCliCmd, invalid param");
        return -1;
    }
    size_t len = bufLen - 1;
    HDF_LOGI("wpa_ctrl_request -> cmd: %{public}s", cmd);
    int ret = wpa_ctrl_request(ctrl->pSend, cmd, strlen(cmd), buf, &len, NULL);
    if (ret < 0) {
        HDF_LOGE("[%{public}s] command failed.", cmd);
        return -1;
    }
    buf[len] = '\0';
    HDF_LOGI("wpa_ctrl_request -> buf: %{public}s", buf);
    if (strncmp(buf, "FAIL\n", strlen("FAIL\n")) == 0 ||
        strncmp(buf, "UNKNOWN COMMAND\n", strlen("UNKNOWN COMMAND\n")) == 0) {
        HDF_LOGE("%{public}s request success, but response %{public}s", cmd, buf);
        return -1;
    }
    return 0;
}
 
int WpaCliCmd(const char *cmd, char *buf, size_t bufLen)
{
    int ret = -1;
    HDF_LOGI("enter WpaCliCmd");
    if (cmd == NULL || buf == NULL || bufLen == 0) {
        HDF_LOGE("WpaCliCmd, invalid parameters!");
        return ret;
    }
    ret = StaCliCmd(GetEthWpaInsCtrl(), cmd, buf, bufLen);
    return ret;
}
 
static int WpaCliConnect(EthWpaInstance *p)
{
    HDF_LOGI("Wpa connect start.");
    if (p == NULL) {
        HDF_LOGE("Wpa connect parameter error.");
        return -1;
    }
    if (p->staCtrl.pSend != NULL) {
        HDF_LOGE("Wpa is already connected.");
        return 0;
    }
    int count = WPA_TRY_CONNECT_TIMES;
    char *ctrlPath = WPA_CTRL_OPEN_IFNAME;
    while (count-- > 0) {
        if (!InitWpaCtrl(&p->staCtrl, ctrlPath)) {
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
    HDF_LOGI("Wpa connect finish.");
    return 0;
}
 
static void WpaCliClose(EthWpaInstance *p)
{
    HDF_LOGI("Wpa connect close.");
    if (p->tid != 0) {
        pthread_join(p->tid, NULL);
        p->tid = 0;
    }
    ReleaseWpaCtrl(&p->staCtrl);
    return;
}
 
static int WpaCliTerminate(void)
{
    HDF_LOGI("enter WpaCliTerminate.");
    char cmd[WPA_CMD_BUF_LEN] = {0};
    char buf[WPA_CMD_REPLY_BUF_LEN] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "TERMINATE") < 0) {
        HDF_LOGE("WpaCliTerminate, snprintf err");
        return -1;
    }
    return WpaCliCmd(cmd, buf, sizeof(buf));
}
 
static int WpaCliCmdSetNetwork(EthWpaInstance *p, const char *ifName, const char *name, const char *value)
{
    char cmd[CMD_BUFFER_SIZE] = {0};
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    int res = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s SET_NETWORK %d %s %s", ifName,
        0, name, value);
    HDF_LOGI("%{public}s cmd= %{private}s", __func__, cmd);
    if (res < 0) {
        HDF_LOGE("%{public}s Internal error, set request message failed!", __func__);
        return -1;
    }
    return WpaCliCmd(cmd, buf, sizeof(buf));
}
 
static int WpaCliCmdStaShellCmd(EthWpaInstance *p, const char *ifName, const char *params)
{
    if (params == NULL) {
        return -1;
    }
    char cmd[CMD_BUFFER_SIZE] = {0};
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s STA_SHELL %s", ifName, params) < 0) {
        HDF_LOGE("WpaCliCmdStaShellCmd, snprintf_s err");
        return -1;
    }
    return WpaCliCmd(cmd, buf, sizeof(buf));
}
 
void InitEthWpaGlobalInstance(void)
{
    HDF_LOGI("enter InitEthWpaGlobalInstance.");
    if (g_wpaInstance != NULL) {
        return;
    }
    g_wpaInstance = (EthWpaInstance *)calloc(1, sizeof(EthWpaInstance));
    if (g_wpaInstance == NULL) {
        HDF_LOGE("Failed to create wpa interface!");
        return;
    }
    g_wpaInstance->wpaCliConnect = WpaCliConnect;
    g_wpaInstance->wpaCliClose = WpaCliClose;
    g_wpaInstance->wpaCliTerminate = WpaCliTerminate;
    g_wpaInstance->wpaCliCmdSetNetwork = WpaCliCmdSetNetwork;
    g_wpaInstance->wpaCliCmdStaShellCmd = WpaCliCmdStaShellCmd;
}
 
EthWpaInstance *GetEthWpaGlobalInstance(void)
{
    return g_wpaInstance;
}
 
void ReleaseEthWpaGlobalInstance(void)
{
    HDF_LOGI("enter ReleaseEthWpaGlobalInstance.");
    if (g_wpaInstance == NULL) {
        return;
    }
    WpaCliClose(g_wpaInstance);
    free(g_wpaInstance);
    g_wpaInstance = NULL;
}
