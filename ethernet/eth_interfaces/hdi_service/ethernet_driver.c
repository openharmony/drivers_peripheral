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
#include <fcntl.h>
#include <hdf_base.h>
#include <hdf_device_desc.h>
#include <hdf_device_object.h>
#include <hdf_log.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <signal.h>
#include <osal_mem.h>
#include <stub_collector.h>
 
#include "v1_0/iethernet.h"
#include "ethernet_impl.h"
 
#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "EthernetDriver"
#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif
#define LOG_DOMAIN 0xD0015b0
 
struct HdfEthernetInterfaceHost {
    struct IDeviceIoService ioService;
    struct IEthernet *service;
    struct HdfRemoteService **stubObject;
};
 
static pthread_rwlock_t g_rwLock = PTHREAD_RWLOCK_INITIALIZER;
static int g_stop = 0;
 
struct HdfEthernetStubData *HdfEthernetStubDriver(void)
{
    static struct HdfEthernetStubData registerManager;
    return &registerManager;
}
 
static int32_t EthernetDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    HDF_LOGI("EthernetDriverDispatch enter.");
    pthread_rwlock_rdlock(&g_rwLock);
    if (g_stop == 1 || client == NULL || client->device == NULL ||
        client->device->service == NULL) {
        pthread_rwlock_unlock(&g_rwLock);
        HDF_LOGE("%{public}s: client or client.device or service is nullptr", __func__);
        return HDF_FAILURE;
    }
    struct HdfEthernetInterfaceHost *ethernetHost = CONTAINER_OF(
        client->device->service, struct HdfEthernetInterfaceHost, ioService);
    if (ethernetHost == NULL || ethernetHost->service == NULL || ethernetHost->stubObject == NULL) {
        HDF_LOGE("%{public}s: invalid service obj", __func__);
        pthread_rwlock_unlock(&g_rwLock);
        return HDF_ERR_INVALID_OBJECT;
    }
 
    struct HdfRemoteService *stubObj = *ethernetHost->stubObject;
    if (stubObj == NULL || stubObj->dispatcher == NULL || stubObj->dispatcher->Dispatch == NULL) {
        pthread_rwlock_unlock(&g_rwLock);
        return HDF_ERR_INVALID_OBJECT;
    }
    int ret = stubObj->dispatcher->Dispatch((struct HdfRemoteService *)stubObj->target, cmdId, data, reply);
    pthread_rwlock_unlock(&g_rwLock);
    return ret;
}
 
static int HdfEthernetDriverInit(struct HdfDeviceObject *deviceObject)
{
    int32_t ret;
    HDF_LOGI("HdfEthernetDriverInit enter.");
    struct HdfEthernetStubData *stubData = HdfEthernetStubDriver();
    DListHeadInit(&stubData->remoteListHead);
    ret = OsalMutexInit(&stubData->mutex);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Mutex init failed, error code: %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
 
static int HdfEthernetDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfEthernetDriverBind enter.");
    int32_t ret = HdfDeviceObjectSetInterfaceDesc(deviceObject, IETHERNET_INTERFACE_DESC);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("failed to set interface descriptor of device object");
        return ret;
    }
    struct HdfEthernetInterfaceHost *ethernetHost =
        (struct HdfEthernetInterfaceHost *)OsalMemAlloc(sizeof(struct HdfEthernetInterfaceHost));
    if (ethernetHost == NULL) {
        HDF_LOGE("HdfEthernetDriverBind OsalMemAlloc Host failed!");
        return HDF_FAILURE;
    }
 
    struct IEthernet *serviceImpl = IEthernetGet(true);
    struct HdfRemoteService **stubObj = StubCollectorGetOrNewObject(IETHERNET_INTERFACE_DESC, serviceImpl);
    if (stubObj == NULL) {
        OsalMemFree(ethernetHost);
        ethernetHost = NULL;
        IEthernetRelease(serviceImpl, true);
        return HDF_FAILURE;
    }
 
    ethernetHost->ioService.Dispatch = EthernetDriverDispatch;
    ethernetHost->ioService.Open = NULL;
    ethernetHost->ioService.Release = NULL;
    ethernetHost->service = serviceImpl;
    ethernetHost->stubObject = stubObj;
    deviceObject->service = &ethernetHost->ioService;
    return HDF_SUCCESS;
}
 
static void HdfEthernetDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfEthernetDriverRelease enter.");
    struct HdfEthernetRemoteNode *pos = NULL;
    struct HdfEthernetRemoteNode *tmp = NULL;
    pthread_rwlock_wrlock(&g_rwLock);
    if (deviceObject == NULL) {
        HDF_LOGI("deviceObject is NULL.");
        pthread_rwlock_unlock(&g_rwLock);
        return;
    }
    g_stop = 1;
    struct HdfEthernetStubData *stubData = HdfEthernetStubDriver();
    if (stubData == NULL) {
        HDF_LOGE("%{public}s: stubData is NUll!", __func__);
        pthread_rwlock_unlock(&g_rwLock);
        return;
    }
 
    DLIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &stubData->remoteListHead, struct HdfEthernetRemoteNode, node) {
        DListRemove(&(pos->node));
        OsalMemFree(pos);
        pos = NULL;
    }
    OsalMutexDestroy(&stubData->mutex);
    struct HdfEthernetInterfaceHost *ethernetHost = CONTAINER_OF(
        deviceObject->service, struct HdfEthernetInterfaceHost, ioService);
    StubCollectorRemoveObject(IETHERNET_INTERFACE_DESC, ethernetHost->service);
    ethernetHost->stubObject = NULL;
    IEthernetRelease(ethernetHost->service, true);
    OsalMemFree(ethernetHost);
    ethernetHost = NULL;
    if (deviceObject->service != NULL) {
        deviceObject->service = NULL;
    }
    pthread_rwlock_unlock(&g_rwLock);
}
 
struct HdfDriverEntry g_ethernetDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "ethernet_service",
    .Bind = HdfEthernetDriverBind,
    .Init = HdfEthernetDriverInit,
    .Release = HdfEthernetDriverRelease,
};
 
HDF_INIT(g_ethernetDriverEntry);
