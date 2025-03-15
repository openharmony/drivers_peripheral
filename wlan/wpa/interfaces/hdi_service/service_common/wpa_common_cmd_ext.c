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
#include "config.h"
#include "common/defs.h"
#include "v2_0/iwpa_callback.h"
#include "v2_0/iwpa_interface.h"

#include <unistd.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include "hdi_wpa_common.h"

pthread_t g_tid;
#define MAX_WPA_WAIT_TIMES 30

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
    g_tid = 0;
    return NULL;
}

const char *MacToStr(const u8 *addr)
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

void HdfWpaDelRemoteObj(struct IWpaCallback *self)
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

static int32_t StartWpaSupplicant(const char *moduleName, const char *startCmd)
{
    int32_t ret;
    int32_t times = 0;

    if (moduleName == NULL || startCmd == NULL) {
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
    WifiWpaInterface *pWpaInterface = GetWifiWpaGlobalInterface();
    if (pWpaInterface == NULL) {
        HDF_LOGE("Get wpa interface failed!");
        return HDF_FAILURE;
    }
    if (pWpaInterface->wpaCliConnect(pWpaInterface) < 0) {
        HDF_LOGE("Failed to connect to wpa!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t WpaInterfaceStart(struct IWpaInterface *self)
{
    int32_t ret;

    (void)self;
    HDF_LOGI("enter %{public}s: wpa_supplicant begin to start", __func__);
    InitWifiWpaGlobalInterface();
    WifiWpaInterface *pWpaInterface = GetWifiWpaGlobalInterface();
    if (pWpaInterface == NULL) {
        HDF_LOGI("fail get global interface");
        return HDF_FAILURE;
    }
    pthread_mutex_lock(GetInterfaceLock());
    ret = StartWpaSupplicant(WPA_SUPPLICANT_NAME, START_CMD);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: StartWpaSupplicant failed, error code: %{public}d", __func__, ret);
        pthread_mutex_unlock(GetInterfaceLock());
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s: wpa_supplicant start successfully!", __func__);
    return HDF_SUCCESS;
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
    return HDF_SUCCESS;
}

int32_t WpaInterfaceStop(struct IWpaInterface *self)
{
    int32_t ret;
    int32_t times = 0;

    (void)self;
    pthread_mutex_lock(GetInterfaceLock());
    HDF_LOGI("enter %{public}s: wpa_supplicant begin to stop", __func__);
    ret = StopWpaSupplicant();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Wifi stop failed, error code: %{public}d", __func__, ret);
        pthread_mutex_unlock(GetInterfaceLock());
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
    ReleaseWifiStaInterface(0);
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s: wpa_supplicant stop successfully!", __func__);
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
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaInterface *pWpaInterface = GetWifiWpaGlobalInterface();
    if (pWpaInterface == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        return HDF_FAILURE;
    }
    AddInterfaceArgv addInterface = {0};
    if (strncmp(ifName, "wlan", strlen("wlan")) == 0) {
        if (strcpy_s(addInterface.name, sizeof(addInterface.name) - 1, ifName) != EOK ||
            strcpy_s(addInterface.confName, sizeof(addInterface.confName) - 1,
            CONFIG_ROOR_DIR"/wpa_supplicant/wpa_supplicant.conf") != EOK) {
            pthread_mutex_unlock(GetInterfaceLock());
            return HDF_FAILURE;
        }
    } else if (strncmp(ifName, "p2p", strlen("p2p")) == 0) {
        if (strcpy_s(addInterface.name, sizeof(addInterface.name) - 1, ifName) != EOK ||
            strcpy_s(addInterface.confName, sizeof(addInterface.confName) - 1,
            CONFIG_ROOR_DIR"/wpa_supplicant/p2p_supplicant.conf") != EOK) {
            pthread_mutex_unlock(GetInterfaceLock());
            return HDF_FAILURE;
        }
    }  else if (strncmp(ifName, "chba0", strlen("chba0")) == 0) {
        if (strcpy_s(addInterface.name, sizeof(addInterface.name) - 1, ifName) != EOK ||
            strcpy_s(addInterface.confName, sizeof(addInterface.confName) - 1,
                     CONFIG_ROOR_DIR"/wpa_supplicant/p2p_supplicant.conf") != EOK) {
            pthread_mutex_unlock(GetInterfaceLock());
            return HDF_FAILURE;
        }
    } else {
        pthread_mutex_unlock(GetInterfaceLock());
        return HDF_FAILURE;
    }
    if (pWpaInterface->wpaCliAddIface(pWpaInterface, &addInterface, true) < 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s Add interface finish", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceRemoveWpaIface(struct IWpaInterface *self, const char *ifName)
{
    (void)self;
    HDF_LOGI("enter %{public}s", __func__);
    if (ifName == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM ;
    }
    HDF_LOGI("enter %{public}s Ready to Remove iface, ifName: %{public}s", __func__, ifName);
    int ret = -1;
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaInterface *pWpaInterface = GetWifiWpaGlobalInterface();
    if (pWpaInterface == NULL) {
        HDF_LOGE("Get wpa interface failed!");
        pthread_mutex_unlock(GetInterfaceLock());
        return HDF_FAILURE;
    }
    ret = pWpaInterface->wpaCliRemoveIface(pWpaInterface, ifName);
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s Remove wpa iface finish, ifName: %{public}s ret = %{public}d", __func__, ifName, ret);
    return (ret == 0 ? HDF_SUCCESS : HDF_FAILURE);
}

int32_t WpaInterfaceScan(struct IWpaInterface *self, const char *ifName)
{
    (void)self;
    HDF_LOGI("enter %{public}s", __func__);
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    ScanSettings settings = {0};
    settings.scanStyle = SCAN_TYPE_LOW_SPAN;
    int ret = pStaIfc->wpaCliCmdScan(pStaIfc, &settings);
    if (ret < 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: StartScan fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    if (ret == WIFI_HAL_SCAN_BUSY) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: StartScan return scan busy", __func__);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
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
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdScanInfo(pStaIfc, resultBuf, resultBufLen);
    if (ret < 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: WpaCliCmdScanInfo2 fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s: Get scan result successfully!", __func__);
    return HDF_SUCCESS;
}