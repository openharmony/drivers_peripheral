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
#include <dlfcn.h>
#include <errno.h>
#include <hdf_base.h>
#include <hdf_log.h>
#include <osal_time.h>
#include <osal_mem.h>
#include <securec.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ap/ap_config.h"
#include "ap/hostapd.h"
#include "ap_ctrl_iface.h"
#include "ap/ctrl_iface_ap.h"
#include "ap_main.h"
#include "hostapd_client.h"
#include "v1_0/ihostapd_callback.h"
#include "v1_0/ihostapd_interface.h"

pthread_t g_tid;
int32_t g_channel;

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
        HDF_LOGE("%{public}s: input parameter invalid", __func__);
        return NULL;
    }
    startCmd = (const char *)p;
    HDF_LOGI("%{public}s: startCmd: %{public}s", __func__, startCmd);
    SplitCmdString(startCmd, &param);
    for (int i = 0; i < param.argc; i++) {
        tmpArgv[i] = param.argv[i];
        HDF_LOGE("%{public}s: tmpArgv[%{public}d]: %{public}s", __func__, i, tmpArgv[i]);
    }
    int ret = ap_main(param.argc, tmpArgv);
    HDF_LOGI("%{public}s: run ap_main ret:%{public}d", __func__, ret);
    return NULL;
}

static int32_t StartApMain(const char *moduleName, const char *startCmd)
{
    int32_t ret;

    if (moduleName == NULL || startCmd == NULL) {
        HDF_LOGE("%{public}s input parameter invalid", __func__);
        return HDF_ERR_INVALID_PARAM ;
    }
    ret = pthread_create(&g_tid, NULL, ApThreadMain, (void *)startCmd);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Create Ap thread failed, error code: %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_setname_np(g_tid, "ApMainThread");
    HDF_LOGE("%{public}s: pthread_create successfully.", __func__);
    usleep(WPA_SLEEP_TIME);
    return HDF_SUCCESS;
}

static int32_t StartHostapdHal(int id)
{
    HDF_LOGI("Ready to init HostapdHal");
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev(id);
    if (hostapdHalDevice == NULL) {
        HDF_LOGE("hostapdHalDevice is NULL");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t StartHostapd(void)
{
    char startCmd[WIFI_MULTI_CMD_MAX_LEN] = {0};
    char *p = startCmd;
    int onceMove = 0;
    int sumMove = 0;
    onceMove = snprintf_s(p, WIFI_MULTI_CMD_MAX_LEN - sumMove,
        WIFI_MULTI_CMD_MAX_LEN - sumMove - 1, "%s", WPA_HOSTAPD_NAME);
    if (onceMove < 0) {
        HDF_LOGE("%{public}s:snprintf_s WPA_HOSTAPD_NAME fail", __func__);
        return HDF_FAILURE;
    }
    p = p + onceMove;
    sumMove = sumMove + onceMove;
    int num;
    const WifiHostapdHalDeviceInfo *cfg = GetWifiCfg(&num);
    if (cfg == NULL) {
        HDF_LOGE("%{public}s:cfg is NULL", __func__);
        return HDF_FAILURE;
    }
    for (int i = 0; i < num; i++) {
        onceMove = snprintf_s(p, WIFI_MULTI_CMD_MAX_LEN - sumMove,
            WIFI_MULTI_CMD_MAX_LEN - sumMove - 1, " %s", cfg[i].config);
        if (onceMove < 0) {
            HDF_LOGE("%{public}s:snprintf_s config fail", __func__);
            return HDF_FAILURE;
        }
        p = p + onceMove;
        sumMove = sumMove + onceMove;
    }
    HDF_LOGI("Cmd is %{public}s", startCmd);
    int32_t ret = StartApMain(WPA_HOSTAPD_NAME, startCmd);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:StartApMain error", __func__);
        return ret;
    }
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceEnableAp(struct IHostapdInterface *self, const char *ifName,
    int32_t id)
{
    HDF_LOGI("Enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s input parameter invalid", __func__);
        return HDF_ERR_INVALID_PARAM ;
    }
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev(id);
    if (hostapdHalDevice == NULL) {
        HDF_LOGE("hostapdHalDevice is NULL");
        return HDF_FAILURE;
    }
    if (hostapdHalDevice->enableAp(id) != 0) {
        HDF_LOGE("enableAp failed");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceDisableAp(struct IHostapdInterface *self, const char *ifName,
    int32_t id)
{
    HDF_LOGI("Enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s input parameter invalid", __func__);
        return HDF_ERR_INVALID_PARAM ;
    }
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev(id);
    if (hostapdHalDevice == NULL) {
        HDF_LOGE("hostapdHalDevice is NULL");
        return HDF_FAILURE;
    }
    if (hostapdHalDevice->disableAp(id) != 0) {
        HDF_LOGE("disableAp failed");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceStartAp(struct IHostapdInterface *self)
{
    HDF_LOGI("Enter hdi %{public}s, this interface is discarded", __func__);
    /*This interface has been discarded. Please use the new interface HostapdInterfaceStartApWithCmd*/
    return HDF_FAILURE;
}

int32_t HostapdInterfaceStartApWithCmd(struct IHostapdInterface *self, const char *ifName, int id)
{
    HDF_LOGI("Enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s input parameter invalid", __func__);
        return HDF_ERR_INVALID_PARAM ;
    }
    int32_t ret;
    ret = InitCfg(ifName);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: InitCfg failed", __func__);
        return HDF_FAILURE;
    }

    ret = StartHostapd();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: StartHostapd failed, error code: %{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    if (StartHostapdHal(id) != HDF_SUCCESS) {
        HDF_LOGE("StartHostapdHal failed");
        return HDF_FAILURE;
    }

    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev(id);
    if (hostapdHalDevice == NULL) {
        HDF_LOGE("hostapdHalDevice is NULL");
        return HDF_FAILURE;
    }

    if (GetIfaceState(ifName) == 0) {
        ret = hostapdHalDevice->enableAp(id);
        if (ret != 0) {
            HDF_LOGE("enableAp failed, ret = %{public}d", ret);
            return HDF_FAILURE;
        }
    }
    HDF_LOGI("%{public}s: hostapd start successfully", __func__);
    return HDF_SUCCESS;
}

static int32_t StopHostapdHal(int id)
{
    ReleaseHostapdDev(id);
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceStopAp(struct IHostapdInterface *self)
{
    HDF_LOGI("Enter hdi %{public}s", __func__);
    (void)self;
    int id = 0;
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev(id);
    if (hostapdHalDevice == NULL) {
        HDF_LOGE("hostapdHalDevice is NULL");
        return HDF_FAILURE;
    }

    if (hostapdHalDevice->stopAp(id) != 0) {
        HDF_LOGE("stopAp failed");
        return HDF_FAILURE;
    }

    if (StopHostapdHal(id) != HDF_SUCCESS) {
        HDF_LOGE("StopHostapdHal failed");
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s: hostapd stop successfully", __func__);
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceReloadApConfigInfo(struct IHostapdInterface *self, const char *ifName,
    int32_t id)
{
    HDF_LOGI("Enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s input parameter invalid", __func__);
        return HDF_ERR_INVALID_PARAM ;
    }
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev(id);
    if (hostapdHalDevice == NULL) {
        HDF_LOGE("hostapdHalDevice is NULL");
        return HDF_FAILURE;
    }

    if (hostapdHalDevice->reloadApConfigInfo(id) != 0) {
        HDF_LOGE("reloadApConfigInfo failed");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceSetApPasswd(struct IHostapdInterface *self, const char *ifName,
    const char *pass, int32_t id)
{
    HDF_LOGI("Enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL || pass == NULL) {
        HDF_LOGE("%{public}s input parameter invalid", __func__);
        return HDF_ERR_INVALID_PARAM ;
    }
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev(id);
    if (hostapdHalDevice == NULL) {
        HDF_LOGE("hostapdHalDevice is NULL");
        return HDF_FAILURE;
    }

    if (hostapdHalDevice->setApPasswd(pass, id) != 0) {
        HDF_LOGE("setApPasswd failed");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceSetApName(struct IHostapdInterface *self, const char *ifName,
    const char *name, int32_t id)
{
    HDF_LOGI("Enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL || name == NULL) {
        HDF_LOGE("%{public}s input parameter invalid", __func__);
        return HDF_ERR_INVALID_PARAM ;
    }
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev(id);
    if (hostapdHalDevice == NULL) {
        HDF_LOGE("hostapdHalDevice is NULL");
        return HDF_FAILURE;
    }

    if (hostapdHalDevice->setApName(name, id) != 0) {
        HDF_LOGE("setApName failed");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceSetApWpaValue(struct IHostapdInterface *self, const char *ifName,
    int32_t securityType, int32_t id)
{
    HDF_LOGI("Enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s input parameter invalid", __func__);
        return HDF_ERR_INVALID_PARAM ;
    }
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev(id);
    if (hostapdHalDevice == NULL) {
        HDF_LOGE("hostapdHalDevice is NULL");
        return HDF_FAILURE;
    }

    if (hostapdHalDevice->setApWpaValue(securityType, id) != 0) {
        HDF_LOGE("setApWpaValue failed");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceSetApBand(struct IHostapdInterface *self, const char *ifName,
    int32_t band, int32_t id)
{
    HDF_LOGI("Enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s input parameter invalid", __func__);
        return HDF_ERR_INVALID_PARAM ;
    }
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev(id);
    if (hostapdHalDevice == NULL) {
        HDF_LOGE("hostapdHalDevice is NULL");
        return HDF_FAILURE;
    }

    if (hostapdHalDevice->setApBand(band, id) != 0) {
        HDF_LOGE("setApBand failed");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceSetAp80211n(struct IHostapdInterface *self, const char *ifName,
    int32_t value, int32_t id)
{
    HDF_LOGI("Enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s input parameter invalid", __func__);
        return HDF_ERR_INVALID_PARAM ;
    }
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev(id);
    if (hostapdHalDevice == NULL) {
        HDF_LOGE("hostapdHalDevice is NULL");
        return HDF_FAILURE;
    }

    if (hostapdHalDevice->setAp80211n(value, id) != 0) {
        HDF_LOGE("setAp80211n failed");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceSetApWmm(struct IHostapdInterface *self, const char *ifName,
    int32_t value, int32_t id)
{
    HDF_LOGI("Enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s input parameter invalid", __func__);
        return HDF_ERR_INVALID_PARAM ;
    }
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev(id);
    if (hostapdHalDevice == NULL) {
        HDF_LOGE("hostapdHalDevice is NULL");
        return HDF_FAILURE;
    }

    if (hostapdHalDevice->setApWmm(value, id) != 0) {
        HDF_LOGE("setApWmm failed");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceSetApChannel(struct IHostapdInterface *self, const char *ifName,
    int32_t channel, int32_t id)
{
    HDF_LOGI("Enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s input parameter invalid", __func__);
        return HDF_ERR_INVALID_PARAM ;
    }
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev(id);
    if (hostapdHalDevice == NULL) {
        HDF_LOGE("hostapdHalDevice is NULL");
        return HDF_FAILURE;
    }

    if (hostapdHalDevice->setApChannel(channel, id) != 0) {
        HDF_LOGE("setApChannel failed");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceSetApMaxConn(struct IHostapdInterface *self, const char *ifName,
    int32_t maxConn, int32_t id)
{
    HDF_LOGI("Enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s input parameter invalid", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev(id);
    if (hostapdHalDevice == NULL) {
        HDF_LOGE("hostapdHalDevice is NULL");
        return HDF_FAILURE;
    }

    if (hostapdHalDevice->setApMaxConn(maxConn, id) != 0) {
        HDF_LOGE("setApMaxConn failed");
        return HDF_FAILURE;
    }
    if (hostapdHalDevice->setApMaxConnHw(maxConn, g_channel) != 0) {
        HDF_LOGE("setApMaxConnHw failed");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceSetMacFilter(struct IHostapdInterface *self, const char *ifName,
    const char *mac, int32_t id)
{
    HDF_LOGI("Enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL || mac == NULL) {
        HDF_LOGE("%{public}s input parameter invalid", __func__);
        return HDF_ERR_INVALID_PARAM ;
    }
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev(id);
    if (hostapdHalDevice == NULL) {
        HDF_LOGE("hostapdHalDevice is NULL");
        return HDF_FAILURE;
    }

    if (hostapdHalDevice->addBlocklist(mac, id) != 0) {
        HDF_LOGE("addBlocklist failed");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceDelMacFilter(struct IHostapdInterface *self, const char *ifName,
    const char *mac, int32_t id)
{
    HDF_LOGI("Enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL || mac == NULL) {
        HDF_LOGE("%{public}s input parameter invalid", __func__);
        return HDF_ERR_INVALID_PARAM ;
    }
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev(id);
    if (hostapdHalDevice == NULL) {
        HDF_LOGE("hostapdHalDevice is NULL");
        return HDF_FAILURE;
    }

    if (hostapdHalDevice->delBlocklist(mac, id) != 0) {
        HDF_LOGE("delBlocklist failed");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceGetStaInfos(struct IHostapdInterface *self, const char *ifName,
    char *buf, uint32_t bufLen, int32_t size, int32_t id)
{
    HDF_LOGI("Enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL || buf == NULL) {
        HDF_LOGE("%{public}s input parameter invalid", __func__);
        return HDF_ERR_INVALID_PARAM ;
    }
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev(id);
    if (hostapdHalDevice == NULL) {
        HDF_LOGE("hostapdHalDevice is NULL");
        return HDF_FAILURE;
    }

    if (hostapdHalDevice->showConnectedDevList(buf, size, id) != 0) {
        HDF_LOGE("showConnectedDevList failed");
        return HDF_FAILURE;
    }
    bufLen = strlen(buf);
    HDF_LOGD("bufLen is %{public}u", bufLen);
    return HDF_SUCCESS;
}

int32_t HostapdInterfaceDisassociateSta(struct IHostapdInterface *self, const char *ifName,
    const char *mac, int32_t id)
{
    HDF_LOGI("Enter hdi %{public}s", __func__);
    (void)self;
    if (ifName == NULL || mac == NULL) {
        HDF_LOGE("%{public}s input parameter invalid", __func__);
        return HDF_ERR_INVALID_PARAM ;
    }
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev(id);
    if (hostapdHalDevice == NULL) {
        HDF_LOGE("hostapdHalDevice is NULL");
        return HDF_FAILURE;
    }

    if (hostapdHalDevice->disConnectedDev(mac, id) != 0) {
        HDF_LOGE("disConnectedDev failed");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t ProcessEventStaJoin(struct HdfHostapdRemoteNode *node,
    struct HostapdApCbParm *apCbParm, const char *ifName)
{
    struct HdiApCbParm *hdiApCbParm = NULL;
    int32_t ret = HDF_FAILURE;

    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventStaJoin == NULL || apCbParm == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiApCbParm = (struct HdiApCbParm *)OsalMemCalloc(sizeof(struct HdiApCbParm));
    if (hdiApCbParm == NULL) {
        HDF_LOGE("%{public}s: hdiApCbParm OsalMemCalloc fail", __func__);
        return HDF_FAILURE;
    } else {
        hdiApCbParm->content = OsalMemCalloc(WIFI_HOSTAPD_CB_CONTENT_LENGTH);
        if (hdiApCbParm->content == NULL) {
            HDF_LOGE("%{public}s: hdiApCbParm->content OsalMemCalloc fail", __func__);
            HdiApCbParmFree(hdiApCbParm, true);
            return HDF_FAILURE;
        } else {
            if (memcpy_s(hdiApCbParm->content, WIFI_HOSTAPD_CB_CONTENT_LENGTH,
                apCbParm->content, WIFI_HOSTAPD_CB_CONTENT_LENGTH) != 0) {
                HDF_LOGE("%{public}s: memcpy_s fail", __func__);
                HdiApCbParmFree(hdiApCbParm, true);
                return HDF_FAILURE;
            }
            hdiApCbParm->id = apCbParm->id;
            ret = node->callbackObj->OnEventStaJoin(node->callbackObj, hdiApCbParm, ifName);
            HDF_LOGI("%{public}s: OnEventStaJoin send success, content is %{private}s", __func__,
                hdiApCbParm->content);
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
    
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventApState == NULL || apCbParm == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiApCbParm = (struct HdiApCbParm *)OsalMemCalloc(sizeof(struct HdiApCbParm));
    if (hdiApCbParm == NULL) {
        HDF_LOGE("%{public}s: hdiApCbParm OsalMemCalloc fail", __func__);
        return HDF_FAILURE;
    } else {
        hdiApCbParm->content = OsalMemCalloc(WIFI_HOSTAPD_CB_CONTENT_LENGTH);
        if (hdiApCbParm->content == NULL) {
            HDF_LOGE("%{public}s: hdiApCbParm->content OsalMemCalloc fail", __func__);
            HdiApCbParmFree(hdiApCbParm, true);
            return HDF_FAILURE;
        } else {
            if (memcpy_s(hdiApCbParm->content, WIFI_HOSTAPD_CB_CONTENT_LENGTH,
                apCbParm->content, WIFI_HOSTAPD_CB_CONTENT_LENGTH) != 0) {
                HDF_LOGE("%{public}s: memcpy_s fail", __func__);
                HdiApCbParmFree(hdiApCbParm, true);
                return HDF_FAILURE;
            }
            hdiApCbParm->id = apCbParm->id;
            ret = node->callbackObj->OnEventApState(node->callbackObj, hdiApCbParm, ifName);
            HDF_LOGI("%{public}s: OnEventApState send success, content is %{private}s", __func__,
                hdiApCbParm->content);
        }
    }
    HdiApCbParmFree(hdiApCbParm, true);
    return ret;
}

int32_t ProcessEventHostapdNotify(struct HdfHostapdRemoteNode *node, char *notifyParam, const char *ifName)
{
    int32_t ret = HDF_FAILURE;

    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventHostApdNotify == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (notifyParam == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid", __func__);
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
    HDF_LOGD("%s: enter HdfHostapdCallbackFun event =%u ", __FUNCTION__, event);
    if (data == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: data or ifName is NULL", __func__);
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

static void OnRemoteServiceDied(struct HdfDeathRecipient *deathRecipient, struct HdfRemoteService *remote)
{
    HDF_LOGI("enter %{public}s ", __func__);
    int id = 0;
    WifiHostapdHalDevice *hostapdHalDevice = GetWifiHostapdDev(id);
    if (hostapdHalDevice == NULL) {
        HDF_LOGE("hostapdHalDevice is NULL");
        return;
    }

    if (hostapdHalDevice->stopAp(id) != 0) {
        HDF_LOGE("stopAp failed");
    }

    if (StopHostapdHal(id) != HDF_SUCCESS) {
        HDF_LOGE("StopHostapdHal failed");
    }
    HDF_LOGI("%{public}s: hostapd stop successfully", __func__);
}

static struct RemoteServiceDeathRecipient g_deathRecipient = {
    .recipient = {
        .OnRemoteDied = OnRemoteServiceDied,
    }
};

static void AddDeathRecipientForService(struct IHostapdCallback *cbFunc)
{
    HDF_LOGI("enter %{public}s ", __func__);
    if (cbFunc == NULL) {
        HDF_LOGE("invalid parameter");
        return;
    }
    struct HdfRemoteService *remote = cbFunc->AsObject(cbFunc);
    if (remote == NULL) {
        HDF_LOGE("remote is NULL");
        return;
    }
    HdfRemoteServiceAddDeathRecipient(remote, &g_deathRecipient.recipient);
}
static int32_t HdfHostapdAddRemoteObj(struct IHostapdCallback *self)
{
    struct HdfHostapdRemoteNode *pos = NULL;
    struct DListHead *head = &HdfHostapdStubDriver()->remoteListHead;

    if (self == NULL) {
        HDF_LOGE("%{public}s:self is null", __func__);
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
    AddDeathRecipientForService(self);
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
            pos = NULL;
            break;
        }
    }
    IHostapdCallbackRelease(self);
}

int32_t HostapdInterfaceRegisterEventCallback(struct IHostapdInterface *self,
    struct IHostapdCallback *cbFunc, const char *ifName)
{
    HDF_LOGI("Enter hdi %{public}s", __func__);
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (cbFunc == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid", __func__);
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
    HDF_LOGI("Enter hdi %{public}s", __func__);

    (void)self;
    if (cbFunc == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    (void)OsalMutexLock(&HdfHostapdStubDriver()->mutex);
    HdfHostapdDelRemoteObj(cbFunc);
    if (DListIsEmpty(&HdfHostapdStubDriver()->remoteListHead)) {
        int32_t ret = HostapdUnregisterEventCallback(HdfHostapdCallbackFun, WIFI_HOSTAPD_TO_HAL_CLIENT, ifName);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: Unregister failed!, error code: %{public}d", __func__, ret);
        }
    }
    (void)OsalMutexUnlock(&HdfHostapdStubDriver()->mutex);
    return HDF_SUCCESS;
}

int32_t HostApdInterfaceShellCmd(struct IHostapdInterface *self, const char *ifName, const char *cmd)
{
    HDF_LOGI("Enter hdi %{public}s", __func__);
    struct hostapd_data *hostApd;

    (void)self;
    if (ifName == NULL || cmd == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hostApd = getHostapd();
    if (hostApd == NULL) {
        HDF_LOGE("%{public}s hostApd is NULL", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
