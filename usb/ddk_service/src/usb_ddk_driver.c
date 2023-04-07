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

#include <hdf_base.h>
#include <hdf_device_desc.h>
#include <hdf_device_object.h>
#include <hdf_log.h>
#include <hdf_remote_service.h>
#include <osal_mem.h>
#include <stub_collector.h>
#include "iusb_ddk.h"

#define HDF_LOG_TAG usb_ddk_driver

struct HdfUsbDdkHost {
    struct IDeviceIoService ioService;
    struct IUsbDdk *service;
    struct HdfRemoteService **stubObject;
};

static int32_t UsbDdkDriverDispatch(
    struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    struct HdfUsbDdkHost *host = CONTAINER_OF(client->device->service, struct HdfUsbDdkHost, ioService);
    if (host->service == NULL || host->stubObject == NULL) {
        HDF_LOGE("%{public}s: invalid service obj", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    struct HdfRemoteService *stubObj = *host->stubObject;
    if (stubObj == NULL || stubObj->dispatcher == NULL || stubObj->dispatcher->Dispatch == NULL) {
        return HDF_ERR_INVALID_OBJECT;
    }

    return stubObj->dispatcher->Dispatch((struct HdfRemoteService *)stubObj->target, cmdId, data, reply);
}

static int HdfUsbDdkDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver init start", __func__);
    return HDF_SUCCESS;
}

static int HdfUsbDdkDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver bind start", __func__);
    int32_t ret = HdfDeviceObjectSetInterfaceDesc(deviceObject, IUSBDDK_INTERFACE_DESC);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: failed to set interface descriptor of device object", __func__);
        return ret;
    }

    struct HdfUsbDdkHost *host = (struct HdfUsbDdkHost *)OsalMemCalloc(sizeof(struct HdfUsbDdkHost));
    if (host == NULL) {
        HDF_LOGE("%{public}s: create HdfUsbDdkHost object failed!", __func__);
        return HDF_FAILURE;
    }

    struct IUsbDdk *serviceImpl = IUsbDdkGet(true);
    if (serviceImpl == NULL) {
        HDF_LOGE("%{public}s: create serviceImpl failed!", __func__);
        OsalMemFree(host);
        return HDF_FAILURE;
    }

    struct HdfRemoteService **stubObj = StubCollectorGetOrNewObject(IUSBDDK_INTERFACE_DESC, serviceImpl);
    if (stubObj == NULL) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        OsalMemFree(host);
        IUsbDdkRelease(serviceImpl, true);
        return HDF_FAILURE;
    }

    host->ioService.Dispatch = UsbDdkDriverDispatch;
    host->ioService.Open = NULL;
    host->ioService.Release = NULL;
    host->service = serviceImpl;
    host->stubObject = stubObj;
    deviceObject->service = &host->ioService;
    return HDF_SUCCESS;
}

static void HdfUsbDdkDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver release start", __func__);
    if (deviceObject->service == NULL) {
        return;
    }

    struct HdfUsbDdkHost *host = CONTAINER_OF(deviceObject->service, struct HdfUsbDdkHost, ioService);
    if (host != NULL) {
        StubCollectorRemoveObject(IUSBDDK_INTERFACE_DESC, host->service);
        IUsbDdkRelease(host->service, true);
        OsalMemFree(host);
    }
}

struct HdfDriverEntry g_usbddkDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "usb_ddk",
    .Bind = HdfUsbDdkDriverBind,
    .Init = HdfUsbDdkDriverInit,
    .Release = HdfUsbDdkDriverRelease,
};

HDF_INIT(g_usbddkDriverEntry);
