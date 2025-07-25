/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
 
#include <hdf_log.h>
#include <string.h>
#include <securec.h>
#include <hdf_base.h>
#include <osal_time.h>
#include <osal_mem.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>
 
#include "hdi_wpa_hal.h"
#include "utils/common.h"
#include "wpa_supplicant_i.h"
#include "ctrl_iface.h"
#include "main.h"
#include "wps_supplicant.h"
#include "config.h"
#include "common/defs.h"
#include "common/wpa_ctrl.h"
#include "ethernet_eap_client.h"
#include "securec.h"
#include "wpa_hdi_util.h"
 
#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "EthWpaCmd"
#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif
#define LOG_DOMAIN 0xD0015b0
 
#define BUF_SIZE 2048
#define START_CMD_BUF_SIZE 512
#define WPA_CMD_RETURN_TIMEOUT (-2)
#define WPA_SLEEP_TIME (100 * 1000) /* 100ms */
#define MAX_WPA_WAIT_TIMES 30
#define CTRL_LEN 128
 
pthread_t g_tid;
pthread_mutex_t g_wpaLock = PTHREAD_MUTEX_INITIALIZER;
 
static void SplitCmdString(const char *startCmd, struct WpaMainParam *pParam)
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
}
 
static void *WpaThreadMain(void *p)
{
    const char *startCmd;
    struct WpaMainParam param = {0};
    char *tmpArgv[MAX_WPA_MAIN_ARGC_NUM] = {0};
    if (p == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return NULL;
    }
    startCmd = (const char *)p;
    HDF_LOGI("%{public}s: run wpa_main -> %{public}s.", __func__, startCmd);
    SplitCmdString(startCmd, &param);
    for (int i = 0; i < param.argc; i++) {
        tmpArgv[i] = param.argv[i];
    }
    int ret = wpa_main(param.argc, tmpArgv);
    HDF_LOGI("%{public}s: run wpa_main ret:%{public}d.", __func__, ret);
    g_tid = 0;
    return NULL;
}
 
static int32_t StartWpaSupplicant(const char *startCmd)
{
    int32_t ret;
    int32_t times = 0;
    if (startCmd == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM ;
    }
    while (g_tid != 0) {
        HDF_LOGI("%{public}s: wpa_supplicant is already running!", __func__);
        usleep(WPA_SLEEP_TIME);
        times++;
        if (times > MAX_WPA_WAIT_TIMES) {
            HDF_LOGE("%{public}s: wait supplicant time out!", __func__);
            return HDF_FAILURE;
        }
    }
    ret = pthread_create(&g_tid, NULL, WpaThreadMain, (void *)startCmd);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Create wpa thread failed, error code: %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_setname_np(g_tid, "WpaMainThread");
    HDF_LOGI("%{public}s: pthread_create successfully.", __func__);
    usleep(WPA_SLEEP_TIME);
    EthWpaInstance *pWpaInstance = GetEthWpaGlobalInstance();
    if (pWpaInstance == NULL) {
        HDF_LOGE("Get wpa interface failed!");
        return HDF_FAILURE;
    }
    if (pWpaInstance->wpaCliConnect(pWpaInstance) < 0) {
        HDF_LOGE("Failed to connect to wpa!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
 
static void RemoveLostCtrl(void)
{
    DIR *dir = NULL;
    char path[CTRL_LEN];
    struct dirent *entry;
    dir = opendir(CONFIG_ROOR_DIR);
    if (dir == NULL) {
        HDF_LOGE("can not open dir");
        return;
    }
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "wpa_ctrl_", strlen("wpa_ctrl_")) != 0) {
            continue;
        }
        int ret = sprintf_s(path, sizeof(path), "%s/%s", CONFIG_ROOR_DIR, entry->d_name);
        if (ret == -1) {
            HDF_LOGE("sprintf_s dir name fail");
            break;
        }
        if (entry->d_type != DT_DIR) {
            remove(path);
        }
    }
    closedir(dir);
}
 
int32_t EthStartEap(struct IEthernet *self, const char *ifName)
{
    int32_t ret;
    (void)self;
    HDF_LOGI("enter %{public}s", __func__);
    InitEthWpaGlobalInstance();
    EthWpaInstance *pWpaInstance = GetEthWpaGlobalInstance();
    if (pWpaInstance == NULL) {
        HDF_LOGI("fail get global interface");
        return HDF_FAILURE;
    }
    pthread_mutex_lock(&g_wpaLock);
    RemoveLostCtrl();
    char startCmd[START_CMD_BUF_SIZE];
    ret = sprintf_s(startCmd, sizeof(startCmd), "%s -i%s", START_CMD, ifName);
    if (ret == -1) {
        pthread_mutex_unlock(&g_wpaLock);
        HDF_LOGE("%{public}s: sprintf_s start cmd fail", __func__);
        return HDF_FAILURE;
    }
    ret = StartWpaSupplicant(startCmd);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: StartWpaSupplicant failed, error code: %{public}d", __func__, ret);
        pthread_mutex_unlock(&g_wpaLock);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_wpaLock);
    HDF_LOGI("%{public}s: wpa_supplicant start successfully!", __func__);
    return HDF_SUCCESS;
}
 
static int32_t StopWpaSupplicant(void)
{
    EthWpaInstance *pWpaInstance = GetEthWpaGlobalInstance();
    if (pWpaInstance == NULL) {
        HDF_LOGE("%{public}s: Get wpa global interface failed!", __func__);
        return HDF_FAILURE;
    }
    int ret = pWpaInstance->wpaCliTerminate();
    HDF_LOGI("%{public}s: wpaCliTerminate ret = %{public}d", __func__, ret);
    return HDF_SUCCESS;
}
 
int32_t EthStopEap(struct IEthernet *self, const char *ifName)
{
    int32_t ret;
    int32_t times = 0;
    (void)self;
    pthread_mutex_lock(&g_wpaLock);
    HDF_LOGI("enter %{public}s", __func__);
    ret = StopWpaSupplicant();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: stop failed, error code: %{public}d", __func__, ret);
        pthread_mutex_unlock(&g_wpaLock);
        return HDF_FAILURE;
    }
    while (g_tid != 0) {
        HDF_LOGI("%{public}s: wpa_supplicant is not stop!", __func__);
        usleep(WPA_SLEEP_TIME);
        times++;
        if (times > MAX_WPA_WAIT_TIMES) {
            HDF_LOGE("%{public}s: wait supplicant stop time out!", __func__);
            break;
        }
    }
    ReleaseEthWpaGlobalInstance();
    pthread_mutex_unlock(&g_wpaLock);
    HDF_LOGI("%{public}s: wpa_supplicant stop successfully!", __func__);
    return HDF_SUCCESS;
}
 
int32_t EthEapShellCmd(struct IEthernet *self, const char *ifName, const char *cmd)
{
    (void)self;
    HDF_LOGI("enter %{public}s", __func__);
    pthread_mutex_lock(&g_wpaLock);
    if (ifName == NULL || cmd == NULL) {
        pthread_mutex_unlock(&g_wpaLock);
        HDF_LOGE("%{public}s: input param invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    EthWpaInstance *pWpaInstance = GetEthWpaGlobalInstance();
    if (pWpaInstance == NULL) {
        pthread_mutex_unlock(&g_wpaLock);
        HDF_LOGE("%{public}s: pWpaInstance = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pWpaInstance->wpaCliCmdStaShellCmd(pWpaInstance, ifName, cmd);
    if (ret < 0) {
        pthread_mutex_unlock(&g_wpaLock);
        HDF_LOGE("%{public}s: fail ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_wpaLock);
    HDF_LOGI("%{public}s: success", __func__);
    return HDF_SUCCESS;
}
 
int32_t EthRegisterEapEventCallback(struct IEthernet *self, struct IEthernetCallback *cbFunc,
    const char *ifName)
{
    int32_t ret = HDF_FAILURE;
    (void)self;
    pthread_mutex_lock(&g_wpaLock);
    if (cbFunc == NULL || ifName == NULL) {
        pthread_mutex_unlock(&g_wpaLock);
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = EthEapClientRegisterCallback(cbFunc, ifName);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Register failed!, error code: %{public}d", __func__, ret);
    } else {
        HDF_LOGI("%{public}s: Register success", __func__);
    }
    pthread_mutex_unlock(&g_wpaLock);
    return ret;
}
 
int32_t EthUnregisterEapEventCallback(struct IEthernet *self, struct IEthernetCallback *cbFunc,
    const char *ifName)
{
    (void)self;
    pthread_mutex_lock(&g_wpaLock);
    if (cbFunc == NULL || ifName == NULL) {
        pthread_mutex_unlock(&g_wpaLock);
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret = EthEapClientUnregisterCallback(cbFunc, ifName);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Unregister failed!, error code: %{public}d", __func__, ret);
    } else {
        HDF_LOGI("%{public}s: Register success", __func__);
    }
    pthread_mutex_unlock(&g_wpaLock);
    return HDF_SUCCESS;
}
