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

bool DdkListenerMgrIsExists(const struct HdfDevEventlistener *listener)
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

int32_t DdkListenerMgrNotifyOne(const struct UsbPnpNotifyMatchInfoTable *device, void *priv)
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
        if (!HdfSbufWriteBuffer(data, device, sizeof(struct UsbPnpNotifyMatchInfoTable))) {
            HDF_LOGE("%{public}s: write buf failed", __func__);
            ret = HDF_FAILURE;
            break;
        }

        if (listener->callBack(listener->priv, handlePriv->cmd, data) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s:callback failed", __func__);
            ret = HDF_FAILURE;
        }
    } while (0);

    HdfSbufRecycle(data);
    return ret;
}

void DdkListenerMgrNotifyAll(const struct UsbPnpNotifyMatchInfoTable *device, enum UsbPnpNotifyServiceCmd cmd)
{
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
            HDF_LOGW("%{public}s: notify failed busNum:%{public}d, devNum:%{public}d.", __func__, device->busNum,
                device->devNum);
        }
    }

    OsalMutexUnlock(&g_ddkListenerList.listMutex);
}

int32_t DdkListenerMgrAdd(struct HdfDevEventlistener *listener)
{
    if (listener == NULL) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (DdkListenerMgrIsExists(listener)) {
        HDF_LOGW("%{public}s: add listener repeatedly", __func__);
        return HDF_SUCCESS;
    }

    OsalMutexLock(&g_ddkListenerList.listMutex);
    DListInsertTail(&listener->listNode, &g_ddkListenerList.listenerList);
    OsalMutexUnlock(&g_ddkListenerList.listMutex);
    // notify all device to listener
    struct UsbDdkDeviceHanldePriv handlePriv = {.listener = listener, .cmd = USB_PNP_NOTIFY_ADD_DEVICE};
    return DdkDevMgrForEachDeviceSafe(DdkListenerMgrNotifyOne, (void *)&handlePriv);
}

int32_t DdkListenerMgrRemove(struct HdfDevEventlistener *listener)
{
    if (!DdkListenerMgrIsExists(listener)) {
        HDF_LOGE("%{public}s: no listener", __func__);
        return HDF_DEV_ERR_NO_DEVICE;
    }

    OsalMutexLock(&g_ddkListenerList.listMutex);
    DListRemove(&listener->listNode);
    OsalMutexUnlock(&g_ddkListenerList.listMutex);
    return HDF_SUCCESS;
}

int32_t DdkListenerMgrInit()
{
    if (g_ddkListenerList.isInit) {
        return HDF_SUCCESS;
    }

    int32_t ret = OsalMutexInit(&g_ddkListenerList.listMutex);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: init mutex failed", __func__);
        return HDF_FAILURE;
    }

    DListHeadInit(&g_ddkListenerList.listenerList);
    g_ddkListenerList.isInit = true;
    return HDF_SUCCESS;
}