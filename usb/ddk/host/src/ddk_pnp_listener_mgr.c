/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "ddk_pnp_listener_mgr.h"

#include <ctype.h>
#include <dirent.h>

#include "ddk_device_manager.h"
#include "hdf_base.h"
#include "hdf_dlist.h"
#include "hdf_log.h"
#include "hdf_usb_pnp_manage.h"
#include "osal_mem.h"
#include "osal_mutex.h"
#include "securec.h"
#include "usbd_wrapper.h"

#define HDF_LOG_TAG usb_ddk_listener_mgr

struct UsbDdkListenerList {
    bool isInit;
    struct OsalMutex listMutex;
    struct DListHead listenerList;
};

struct UsbDdkDeviceHanldePriv {
    struct HdfDevEventlistener *listener;
    enum UsbPnpNotifyServiceCmd cmd;
};

static struct UsbDdkListenerList g_ddkListenerList = {.isInit = false};
static bool g_hasCacheAccessory = false;
static struct OsalMutex g_cacheAccMutex;

static bool DdkListenerMgrIsExists(const struct HdfDevEventlistener *listener)
{
    OsalMutexLock(&g_ddkListenerList.listMutex);
    if (DListIsEmpty(&g_ddkListenerList.listenerList)) {
        HDF_LOGI("%{public}s: the listenerList is empty.", __func__);
        OsalMutexUnlock(&g_ddkListenerList.listMutex);
        return false;
    }

    struct HdfDevEventlistener *pos = NULL;
    struct HdfDevEventlistener *tmp = NULL;
    bool findFlag = false;
    DLIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_ddkListenerList.listenerList, struct HdfDevEventlistener, listNode) {
        if (pos == listener) {
            findFlag = true;
            break;
        }
    }

    OsalMutexUnlock(&g_ddkListenerList.listMutex);
    return findFlag;
}

static int32_t DdkListenerMgrNotifyOne(const struct UsbPnpNotifyMatchInfoTable *device, void *priv)
{
    struct UsbDdkDeviceHanldePriv *handlePriv = priv;
    const struct HdfDevEventlistener *listener = handlePriv->listener;
    // pack device
    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC);
    if (data == NULL) {
        HDF_LOGE("%{public}s: get buf failed", __func__);
        return HDF_DEV_ERR_NO_MEMORY;
    }

    int32_t ret = HDF_SUCCESS;
    do {
        struct HdfSBuf *dataTmp = NULL;
        if (device != NULL) {
            if (!HdfSbufWriteBuffer(data, device, sizeof(struct UsbPnpNotifyMatchInfoTable))) {
                HDF_LOGE("%{public}s: write buf failed", __func__);
                ret = HDF_FAILURE;
                break;
            }
            dataTmp = data;
        }

        if (listener->callBack(listener->priv, handlePriv->cmd, dataTmp) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s:callback failed, cmd is %{public}u", __func__, handlePriv->cmd);
            ret = HDF_FAILURE;
        }
    } while (0);

    HdfSbufRecycle(data);
    return ret;
}

static int32_t DdkListenerMgrNotifyGadgetOne(void *priv)
{
    struct UsbDdkDeviceHanldePriv *handlePriv = (struct UsbDdkDeviceHanldePriv *)priv;
    const struct HdfDevEventlistener *listener = handlePriv->listener;
    if (listener->callBack(listener->priv, handlePriv->cmd, NULL) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:callback failed", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

void DdkListenerMgrNotifyAll(const struct UsbPnpNotifyMatchInfoTable *device, enum UsbPnpNotifyServiceCmd cmd)
{
    HDF_LOGI("%{public}s: notify cmd:%{public}d, start.", __func__, cmd);
    OsalMutexLock(&g_cacheAccMutex);
    g_hasCacheAccessory = (cmd == USB_ACCESSORY_SEND);
    OsalMutexUnLock(&g_cacheAccMutex);

    OsalMutexLock(&g_ddkListenerList.listMutex);
    if (DListIsEmpty(&g_ddkListenerList.listenerList)) {
        HDF_LOGI("%{public}s: the listenerList is empty.", __func__);
        OsalMutexUnlock(&g_ddkListenerList.listMutex);
        return;
    }

    struct HdfDevEventlistener *pos = NULL;
    struct HdfDevEventlistener *tmp = NULL;
    struct UsbDdkDeviceHanldePriv handlePriv = {.cmd = cmd};
    DLIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_ddkListenerList.listenerList, struct HdfDevEventlistener, listNode) {
        handlePriv.listener = pos;
        if (DdkListenerMgrNotifyOne(device, &handlePriv) != HDF_SUCCESS) {
            HDF_LOGW("%{public}s: notify failed cmd:%{public}d", __func__, cmd);
        }
    }

    OsalMutexUnlock(&g_ddkListenerList.listMutex);
    HDF_LOGI("%{public}s: notify cmd:%{public}d, end.", __func__, cmd);
}

int32_t DdkListenerMgrAdd(struct HdfDevEventlistener *listener)
{
    if (listener == NULL) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    // notify all device to listener
    struct UsbDdkDeviceHanldePriv handlePriv = {.listener = listener, .cmd = USB_PNP_NOTIFY_ADD_DEVICE};
    struct UsbDdkDeviceHanldePriv handlePriv1 = {.listener = listener, .cmd = USB_PNP_DRIVER_GADGET_ADD};
    if (DdkListenerMgrIsExists(listener)) {
        HDF_LOGW("%{public}s: add listener repeatedly", __func__);
    } else {
        OsalMutexLock(&g_ddkListenerList.listMutex);
        DListInsertTail(&listener->listNode, &g_ddkListenerList.listenerList);
        OsalMutexUnlock(&g_ddkListenerList.listMutex);
    }
    int32_t ret = DdkDevMgrForEachDeviceSafe(DdkListenerMgrNotifyOne, (void *)&handlePriv);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:DdkDevMgrForEachDeviceSafe failed", __func__);
        return ret;
    }
    ret = DdkDevMgrGetGadgetLinkStatusSafe(DdkListenerMgrNotifyGadgetOne, (void *)&handlePriv1);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:DdkDevMgrGetGadgetLinkStatusSafe failed", __func__);
        return ret;
    }

    OsalMutexLock(&g_cacheAccMutex);
    if (g_hasCacheAccessory) {
        struct UsbDdkDeviceHanldePriv accessoryPriv = {.listener = listener, .cmd = USB_ACCESSORY_SEND};
        HDF_LOGI("%{public}s:DdkDevMgrGetGadgetLinkStatusSafe notify cache accessory send", __func__);
        (void)DdkDevMgrGetGadgetLinkStatusSafe(DdkListenerMgrNotifyGadgetOne, (void *)&accessoryPriv);
    }
    OsalMutexUnLock(&g_cacheAccMutex);
    return ret;
}

int32_t DdkListenerMgrRemove(struct HdfDevEventlistener *listener)
{
    if (!DdkListenerMgrIsExists(listener)) {
        HDF_LOGE("%{public}s: no listener", __func__);
        return HDF_DEV_ERR_NO_DEVICE;
    }

    OsalMutexLock(&g_ddkListenerList.listMutex);
    if (listener->listNode.prev != NULL && listener->listNode.next != NULL) {
        DListRemove(&listener->listNode);
    } else {
        HDF_LOGE("%{public}s: The node prev or next is NULL", __func__);
    }
    OsalMutexUnlock(&g_ddkListenerList.listMutex);
    return HDF_SUCCESS;
}

int32_t DdkListenerMgrInit(void)
{
    if (g_ddkListenerList.isInit) {
        return HDF_SUCCESS;
    }

    int32_t ret = OsalMutexInit(&g_ddkListenerList.listMutex);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: init mutex failed", __func__);
        return HDF_FAILURE;
    }

    ret = OsalMutexInit(&g_cacheAccMutex);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: init cache accessory mutex failed", __func__);
        return HDF_FAILURE;
    }
    DListHeadInit(&g_ddkListenerList.listenerList);
    g_ddkListenerList.isInit = true;
    return HDF_SUCCESS;
}
