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

#include <fcntl.h>
#include <hdf_base.h>
#include <hdf_device_desc.h>
#include <hdf_device_object.h>
#include <hdf_log.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <osal_mem.h>
#include <stub_collector.h>
#include "v1_0/ihostapd_interface.h"
#include "hostapd_impl.h"

struct HdfHostapdInterfaceHost {
    struct IDeviceIoService ioService;
    struct IHostapdInterface *service;
    struct HdfRemoteService **stubObject;
};

static pthread_rwlock_t g_rwLock = PTHREAD_RWLOCK_INITIALIZER;
static int g_stop = 0;

static int32_t HostapdInterfaceDriverDispatch(
    struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    HDF_LOGI("HostapdInterfaceDriverDispatch enter.");
    pthread_rwlock_rdlock(&g_rwLock);
    struct HdfHostapdInterfaceHost *hostapdinterfaceHost = CONTAINER_OF(
        client->device->service, struct HdfHostapdInterfaceHost, ioService);
    if (g_stop == 1 || hostapdinterfaceHost->service == NULL || hostapdinterfaceHost->stubObject == NULL) {
        HDF_LOGE("%{public}s: invalid service obj", __func__);
        pthread_rwlock_unlock(&g_rwLock);
        return HDF_ERR_INVALID_OBJECT;
    }

    struct HdfRemoteService *stubObj = *hostapdinterfaceHost->stubObject;
    if (stubObj == NULL || stubObj->dispatcher == NULL || stubObj->dispatcher->Dispatch == NULL) {
        pthread_rwlock_unlock(&g_rwLock);
        return HDF_ERR_INVALID_OBJECT;
    }
    int ret = stubObj->dispatcher->Dispatch((struct HdfRemoteService *)stubObj->target, cmdId, data, reply);
    pthread_rwlock_unlock(&g_rwLock);
    return ret;
}

static int HdfHostapdInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    int32_t ret;
    HDF_LOGI("HdfHostapdInterfaceDriverInit enter.");
    struct HdfHostapdStubData *stubData = HdfHostapdStubDriver();
    DListHeadInit(&stubData->remoteListHead);
    ret = OsalMutexInit(&stubData->mutex);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Mutex init failed, error code: %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int HdfHostapdInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfHostapdInterfaceDriverBind enter.");

    int32_t ret = HdfDeviceObjectSetInterfaceDesc(deviceObject, IHOSTAPDINTERFACE_INTERFACE_DESC);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("Failed to set interface descriptor of device object");
        return ret;
    }

    struct HdfHostapdInterfaceHost *hostapdinterfaceHost =
        (struct HdfHostapdInterfaceHost *)OsalMemAlloc(sizeof(struct HdfHostapdInterfaceHost));
    if (hostapdinterfaceHost == NULL) {
        HDF_LOGE("HdfHostapdInterfaceDriverBind OsalMemAlloc HdfHostapdInterfaceHost failed!");
        return HDF_FAILURE;
    }

    struct IHostapdInterface *serviceImpl = IHostapdInterfaceGet(true);
    struct HdfRemoteService **stubObj = StubCollectorGetOrNewObject(IHOSTAPDINTERFACE_INTERFACE_DESC, serviceImpl);
    if (stubObj == NULL) {
        OsalMemFree(hostapdinterfaceHost);
        hostapdinterfaceHost = NULL;
        IHostapdInterfaceRelease(serviceImpl, true);
        return HDF_FAILURE;
    }

    hostapdinterfaceHost->ioService.Dispatch = HostapdInterfaceDriverDispatch;
    hostapdinterfaceHost->ioService.Open = NULL;
    hostapdinterfaceHost->ioService.Release = NULL;
    hostapdinterfaceHost->service = serviceImpl;
    hostapdinterfaceHost->stubObject = stubObj;
    deviceObject->service = &hostapdinterfaceHost->ioService;
    return HDF_SUCCESS;
}

static void HdfHostapdInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfHostapdInterfaceDriverRelease enter.");
    struct HdfHostapdRemoteNode *pos = NULL;
    struct HdfHostapdRemoteNode *tmp = NULL;
    pthread_rwlock_wrlock(&g_rwLock);
    g_stop = 1;
    struct HdfHostapdStubData *stubData = HdfHostapdStubDriver();
    if (stubData == NULL) {
        HDF_LOGE("%{public}s: stubData is NUll!", __func__);
        pthread_rwlock_unlock(&g_rwLock);
        return;
    }

    DLIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &stubData->remoteListHead, struct HdfHostapdRemoteNode, node) {
        DListRemove(&(pos->node));
        OsalMemFree(pos);
        pos = NULL;
    }

    OsalMutexDestroy(&stubData->mutex);
    struct HdfHostapdInterfaceHost *hostapdinterfaceHost = CONTAINER_OF(
        deviceObject->service, struct HdfHostapdInterfaceHost, ioService);
    StubCollectorRemoveObject(IHOSTAPDINTERFACE_INTERFACE_DESC, hostapdinterfaceHost->service);
    IHostapdInterfaceRelease(hostapdinterfaceHost->service, true);
    OsalMemFree(hostapdinterfaceHost);
    hostapdinterfaceHost = NULL;
    pthread_rwlock_unlock(&g_rwLock);
}

struct HdfDriverEntry g_hostapdinterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "hostapd_service",
    .Bind = HdfHostapdInterfaceDriverBind,
    .Init = HdfHostapdInterfaceDriverInit,
    .Release = HdfHostapdInterfaceDriverRelease,
};

HDF_INIT(g_hostapdinterfaceDriverEntry);
