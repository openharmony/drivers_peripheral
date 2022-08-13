/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include <fcntl.h>
#include <hdf_base.h>
#include <hdf_device_desc.h>
#include <hdf_device_object.h>
#include <hdf_log.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <osal_mem.h>
#include "v1_0/wlan_interface_service.h"
#include "wlan_impl.h"

struct HdfWlanInterfaceHost {
    struct IDeviceIoService ioservice;
    struct WlanInterfaceService *service;
};

static int32_t WlanInterfaceDriverDispatch(
    struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    struct HdfWlanInterfaceHost *wlaninterfaceHost =
        CONTAINER_OF(client->device->service, struct HdfWlanInterfaceHost, ioservice);
    if (wlaninterfaceHost->service == NULL || wlaninterfaceHost->service->stub.OnRemoteRequest == NULL) {
        HDF_LOGE("%{public}s: invalid service obj", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    if (!HdfDeviceObjectCheckInterfaceDesc(client->device, data)) {
        HDF_LOGE("%{public}s: check interface desc failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return wlaninterfaceHost->service->stub.OnRemoteRequest(
        &wlaninterfaceHost->service->stub.interface, cmdId, data, reply);
}

static int HdfWlanInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    int32_t ret;
    HDF_LOGI("HdfWlanInterfaceDriverInit enter.");
    struct HdfWlanStubData *stubData = HdfStubDriver();
    DListHeadInit(&stubData->remoteListHead);
    ret = OsalMutexInit(&stubData->mutex);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Mutex init failed, error code: %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    if (WlanInterfaceServiceInit() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: wlan interface service init failed!", __func__);
        OsalMutexDestroy(&stubData->mutex);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int HdfWlanInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfWlanInterfaceDriverBind enter.");

    int32_t ret = HdfDeviceObjectSetInterfaceDesc(deviceObject, IWLANINTERFACE_INTERFACE_DESC);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("failed to set interface descriptor of device object");
        return ret;
    }

    struct HdfWlanInterfaceHost *wlaninterfaceHost =
        (struct HdfWlanInterfaceHost *)OsalMemAlloc(sizeof(struct HdfWlanInterfaceHost));
    if (wlaninterfaceHost == NULL) {
        HDF_LOGE("HdfWlanInterfaceDriverBind OsalMemAlloc HdfWlanInterfaceHost failed!");
        return HDF_FAILURE;
    }

    wlaninterfaceHost->ioservice.Dispatch = WlanInterfaceDriverDispatch;
    wlaninterfaceHost->ioservice.Open = NULL;
    wlaninterfaceHost->ioservice.Release = NULL;
    wlaninterfaceHost->service = WlanInterfaceServiceGet();
    if (wlaninterfaceHost->service == NULL) {
        OsalMemFree(wlaninterfaceHost);
        return HDF_FAILURE;
    }

    deviceObject->service = &wlaninterfaceHost->ioservice;
    return HDF_SUCCESS;
}

static void HdfWlanInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfWlanInterfaceDriverRelease enter.");
    struct HdfWlanRemoteNode *pos = NULL;
    struct HdfWlanRemoteNode *tmp = NULL;
    struct HdfWlanStubData *stubData = HdfStubDriver();
    if (stubData == NULL) {
        HDF_LOGE("%{public}s: stubData is NUll!", __func__);
        return;
    }

    DLIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &stubData->remoteListHead, struct HdfWlanRemoteNode, node) {
        DListRemove(&(pos->node));
        OsalMemFree(pos);
    }
    OsalMutexDestroy(&stubData->mutex);
    struct HdfWlanInterfaceHost *wlaninterfaceHost =
        CONTAINER_OF(deviceObject->service, struct HdfWlanInterfaceHost, ioservice);
    WlanInterfaceServiceRelease(wlaninterfaceHost->service);
    OsalMemFree(wlaninterfaceHost);
}

struct HdfDriverEntry g_wlaninterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "wlan_service",
    .Bind = HdfWlanInterfaceDriverBind,
    .Init = HdfWlanInterfaceDriverInit,
    .Release = HdfWlanInterfaceDriverRelease,
};

HDF_INIT(g_wlaninterfaceDriverEntry);