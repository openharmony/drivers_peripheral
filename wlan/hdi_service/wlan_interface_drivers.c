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
#include <stub_collector.h>
#include "v1_0/iwlan_interface.h"
#include "wlan_impl.h"

struct HdfWlanInterfaceHost {
    struct IDeviceIoService ioService;
    struct IWlanInterface *service;
    struct HdfRemoteService **stubObject;
};

static int32_t WlanInterfaceDriverDispatch(
    struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    struct HdfWlanInterfaceHost *wlaninterfaceHost = CONTAINER_OF(
        client->device->service, struct HdfWlanInterfaceHost, ioService);
    if (wlaninterfaceHost->service == NULL || wlaninterfaceHost->stubObject == NULL) {
        HDF_LOGE("%{public}s: invalid service obj", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    struct HdfRemoteService *stubObj = *wlaninterfaceHost->stubObject;
    if (stubObj == NULL || stubObj->dispatcher == NULL || stubObj->dispatcher->Dispatch == NULL) {
        return HDF_ERR_INVALID_OBJECT;
    }

    return stubObj->dispatcher->Dispatch((struct HdfRemoteService *)stubObj->target, cmdId, data, reply);
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

    struct IWlanInterface *serviceImpl = IWlanInterfaceGet(true);
    struct HdfRemoteService **stubObj = StubCollectorGetOrNewObject(IWLANINTERFACE_INTERFACE_DESC, serviceImpl);
    if (stubObj == NULL) {
        OsalMemFree(wlaninterfaceHost);
        IWlanInterfaceRelease(serviceImpl, true);
        return HDF_FAILURE;
    }

    wlaninterfaceHost->ioService.Dispatch = WlanInterfaceDriverDispatch;
    wlaninterfaceHost->ioService.Open = NULL;
    wlaninterfaceHost->ioService.Release = NULL;
    wlaninterfaceHost->service = serviceImpl;
    wlaninterfaceHost->stubObject = stubObj;
    deviceObject->service = &wlaninterfaceHost->ioService;
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
    struct HdfWlanInterfaceHost *wlaninterfaceHost = CONTAINER_OF(
        deviceObject->service, struct HdfWlanInterfaceHost, ioService);
    StubCollectorRemoveObject(IWLANINTERFACE_INTERFACE_DESC, wlaninterfaceHost->service);
    IWlanInterfaceRelease(wlaninterfaceHost->service, true);
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