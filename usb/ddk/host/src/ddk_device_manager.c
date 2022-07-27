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

#include "ddk_device_manager.h"

#include <ctype.h>
#include <dirent.h>

#include "ddk_sysfs_device.h"
#include "hdf_base.h"
#include "hdf_dlist.h"
#include "hdf_log.h"
#include "osal_mem.h"
#include "osal_mutex.h"
#include "securec.h"

#define HDF_LOG_TAG usb_ddk_dev_mgr

struct UsbDdkDeviceInfo {
    struct OsalMutex deviceMutex;
    struct DListHead list;
    struct UsbPnpNotifyMatchInfoTable info;
};

struct UsbDdkDeviceList {
    bool isInit;
    struct OsalMutex listMutex;
    struct DListHead devList;
};

static struct UsbDdkDeviceList g_ddkDevList = {.isInit = false};

struct UsbDdkDeviceInfo *DdkDevMgrIsDevExists(uint64_t devAddr)
{
    OsalMutexLock(&g_ddkDevList.listMutex);
    if (DListIsEmpty(&g_ddkDevList.devList)) {
        HDF_LOGI("%{public}s: the devList is empty.", __func__);
        OsalMutexUnlock(&g_ddkDevList.listMutex);
        return NULL;
    }

    struct UsbDdkDeviceInfo *res = NULL;
    struct UsbDdkDeviceInfo *infoPos = NULL;
    struct UsbDdkDeviceInfo *infoTemp = NULL;
    DLIST_FOR_EACH_ENTRY_SAFE(infoPos, infoTemp, &g_ddkDevList.devList, struct UsbDdkDeviceInfo, list) {
        if (infoPos->info.usbDevAddr == devAddr) {
            res = infoPos;
            break;
        }
    }
    OsalMutexUnlock(&g_ddkDevList.listMutex);
    return res;
}

int32_t DdkDevMgrAddDevice(struct UsbDdkDeviceInfo *device)
{
    if (device == NULL) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (DdkDevMgrIsDevExists(DdkSysfsMakeDevAddr(device->info.busNum, device->info.devNum)) != NULL) {
        HDF_LOGW("%{public}s: add device repeatedly busNum:%{public}d, devNum:%{public}d", __func__,
            device->info.busNum, device->info.devNum);
        return HDF_SUCCESS;
    }

    OsalMutexLock(&g_ddkDevList.listMutex);
    DListInsertTail(&device->list, &g_ddkDevList.devList);
    OsalMutexUnlock(&g_ddkDevList.listMutex);
    return HDF_SUCCESS;
}

int32_t DdkDevMgrRemoveDevice(int32_t busNum, int32_t devNum, struct UsbPnpNotifyMatchInfoTable *info)
{
    uint64_t devAddr = DdkSysfsMakeDevAddr(busNum, devNum);
    struct UsbDdkDeviceInfo *dev = DdkDevMgrIsDevExists(devAddr);
    if (dev == NULL) {
        HDF_LOGE("%{public}s: no device busNum:%{public}d, devNum:%{public}d", __func__, busNum, devNum);
        return HDF_DEV_ERR_NO_DEVICE;
    }

    int32_t ret = memcpy_s(
        info, sizeof(struct UsbPnpNotifyMatchInfoTable), &dev->info, sizeof(struct UsbPnpNotifyMatchInfoTable));
    if (ret != EOK) {
        HDF_LOGE("%{public}s: memcpy_s failed", __func__);
        return HDF_FAILURE;
    }

    OsalMutexLock(&g_ddkDevList.listMutex);
    DListRemove(&dev->list);
    OsalMemFree(dev);
    dev = NULL;
    OsalMutexUnlock(&g_ddkDevList.listMutex);
    return HDF_SUCCESS;
}

int32_t DdkDevMgrInitDevice(struct UsbDdkDeviceInfo *deviceInfo)
{
    (void)memset_s(deviceInfo, sizeof(struct UsbDdkDeviceInfo), 0, sizeof(struct UsbDdkDeviceInfo));
    int32_t ret = OsalMutexInit(&deviceInfo->deviceMutex);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: init mutex failed", __func__);
        return HDF_FAILURE;
    }
    DListHeadInit(&deviceInfo->list);

    return HDF_SUCCESS;
}

const struct UsbPnpNotifyMatchInfoTable *DdkDevMgrCreateDevice(const char *deviceDir)
{
    struct UsbDdkDeviceInfo *device = (struct UsbDdkDeviceInfo *)OsalMemCalloc(sizeof(struct UsbDdkDeviceInfo));
    if (device == NULL) {
        HDF_LOGE("%{public}s: init device failed", __func__);
        return NULL;
    }

    int32_t status = HDF_SUCCESS;
    do {
        // init device
        status = DdkDevMgrInitDevice(device);
        if (status != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: init device failed:%{public}d", __func__, status);
            break;
        }

        // get device from sysfs
        status = DdkSysfsGetDevice(deviceDir, &device->info);
        if (status != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: sysfs get device failed:%{public}d", __func__, status);
            break;
        }

        // insert device to list
        status = DdkDevMgrAddDevice(device);
        if (status != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: add device failed:%{public}d", __func__, status);
            break;
        }
        return &device->info;
    } while (0);

    OsalMemFree(device);
    return status == HDF_SUCCESS ? &device->info : NULL;
}

int32_t DdkDevMgrScanSysfs(const char *sysfsDevDir)
{
    if (sysfsDevDir == NULL) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    DIR *dir = opendir(sysfsDevDir);
    if (dir == NULL) {
        HDF_LOGE("%{public}s: opendir failed sysfsDevDir:%{public}s", __func__, sysfsDevDir);
        return HDF_ERR_BAD_FD;
    }

    struct dirent *devHandle;
    while ((devHandle = readdir(dir))) {
        // only read dir like 3-1
        if ((!isdigit(devHandle->d_name[0])) || strchr(devHandle->d_name, ':')) {
            continue;
        }

        if (DdkDevMgrCreateDevice(devHandle->d_name) == NULL) {
            HDF_LOGW("%{public}s: create device failed d_name:%{public}s", __func__, devHandle->d_name);
        }
    }
    closedir(dir);
    return HDF_SUCCESS;
}

int32_t DdkDevMgrInit(void)
{
    if (g_ddkDevList.isInit) {
        return HDF_SUCCESS;
    }

    int32_t ret = OsalMutexInit(&g_ddkDevList.listMutex);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: init mutex failed", __func__);
        return HDF_FAILURE;
    }

    DListHeadInit(&g_ddkDevList.devList);
    ret = DdkDevMgrScanSysfs(SYSFS_DEVICES_DIR);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Scan sysfs failed ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    g_ddkDevList.isInit = true;
    return HDF_SUCCESS;
}

int32_t DdkDevMgrForEachDeviceSafe(DdkDevMgrHandleDev handle, void *priv)
{
    OsalMutexLock(&g_ddkDevList.listMutex);
    if (DListIsEmpty(&g_ddkDevList.devList)) {
        HDF_LOGI("%{public}s:the devList is empty", __func__);
        OsalMutexUnlock(&g_ddkDevList.listMutex);
        return HDF_SUCCESS;
    }

    struct UsbDdkDeviceInfo *pos = NULL;
    struct UsbDdkDeviceInfo *tmp = NULL;
    DLIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_ddkDevList.devList, struct UsbDdkDeviceInfo, list) {
        if (handle(&pos->info, priv) != HDF_SUCCESS) {
            HDF_LOGW("%{public}s: handle failed", __func__);
        }
    }

    OsalMutexUnlock(&g_ddkDevList.listMutex);
    return HDF_SUCCESS;
}