/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "usbd.h"
#include <unistd.h>
#include "devmgr_service_if.h"
#include "hdf_base.h"
#include "hdf_io_service_if.h"
#include "hdf_log.h"
#include "hdf_syscall_adapter.h"
#include "hdf_usb_pnp_manage.h"
#include "osal_mem.h"
#include "osal_time.h"
#include "securec.h"
#include "usb_ddk_pnp_loader.h"
#include "usbd_dispatcher.h"
#include "usbd_function.h"
#include "usbd_publisher.h"

#define HEX_NUM_09 0x09

const int32_t DEFAULT_PORT_ID = 1;
const int32_t DEFAULT_POWER_ROLE = 2;
const int32_t DEFAULT_DATA_ROLE = 2;

int32_t HdfDeviceRegisterEventListener(struct HdfIoService *target, struct HdfDevEventlistener *listener);

static int32_t UsbdDriverBind(struct HdfDeviceObject *device);
static int32_t UsbdDriverInit(struct HdfDeviceObject *device);
static void UsbdDriverRelease(struct HdfDeviceObject *device);
int32_t UsbdRealseDevices(struct UsbdService *service);
int32_t HostDeviceCreate(struct HostDevice **port);

static int UsbdEventHandle(const struct UsbdService *inst);

int SetPortInit(int portId, int powerRole, int dataRole);

/* HdfDriverEntry implementations */
static int32_t UsbdDriverBind(struct HdfDeviceObject *device)
{
    struct UsbdService *dev = NULL;
    struct UsbPnpNotifyServiceInfo *info = NULL;
    int32_t ret;
    HDF_LOGI("%{public}s:%{public}d  entry", __func__, __LINE__);
    if (device == NULL) {
        HDF_LOGE("%{public}s:%{public}d device is null", __func__, __LINE__);
        return HDF_ERR_INVALID_OBJECT;
    }
    dev = (struct UsbdService *)OsalMemCalloc(sizeof(struct UsbdService));
    if (dev == NULL) {
        HDF_LOGE("%{public}s: Alloc dev device failed", __func__);
        return HDF_FAILURE;
    }
    memset_s(dev, sizeof(struct UsbdService), 0, sizeof(struct UsbdService));
    if (OsalMutexInit(&dev->lock) != HDF_SUCCESS) {
        HDF_LOGE(" init lock fail!");
        return HDF_FAILURE;
    }
    info = (struct UsbPnpNotifyServiceInfo *)device->priv;
    if (info) {
        struct HostDevice *port = NULL;
        ret = HostDeviceCreate(&port);
        if (ret == HDF_SUCCESS) {
            port->busNum = info->busNum;
            port->devAddr = info->devNum;
            port->service = dev;
            OsalMutexLock(&dev->lock);
            HdfSListAdd(&dev->devList, &port->node);
            OsalMutexUnlock(&dev->lock);
        }
    }
    HDF_LOGI("%{public}s:  exit", __func__);
    device->service = &(dev->service);
    device->service->Dispatch = UsbdServiceDispatch;
    dev->device = device;
    ret = UsbdEventHandle(dev);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d UsbdEventHandle ret=%{public}d", __func__, __LINE__, ret);
        return ret;
    }
    return HDF_SUCCESS;
}

static int32_t UsbdDriverInit(struct HdfDeviceObject *device)
{
    int32_t ret = HDF_SUCCESS;
    HDF_LOGI("%{public}s:%{public}d  exit", __func__, __LINE__);
    if (device == NULL) {
        HDF_LOGE("%{public}s:%{public}d device is null", __func__, __LINE__);
        return HDF_ERR_INVALID_OBJECT;
    }
    ret = SetPortInit(DEFAULT_PORT_ID, DEFAULT_POWER_ROLE, DEFAULT_DATA_ROLE);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d SetPortInit Error!", __func__, __LINE__);
        return ret;
    }
    HDF_LOGI("%{public}s:%{public}d init ok!", __func__, __LINE__);
    return ret;
}

static void UsbdDriverRelease(struct HdfDeviceObject *device)
{
    struct UsbdService *dev = NULL;
    HDF_LOGI("%{public}s:%{public}d exit", __func__, __LINE__);
    if (device == NULL) {
        HDF_LOGE("%{public}s: device is NULL", __func__);
        return;
    }
    dev = (struct UsbdService *)device->service;
    UsbdRealseDevices(dev);
    HDF_LOGI("%{public}s:%{public}d exit", __func__, __LINE__);
}

struct HdfDriverEntry g_usbdDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "usbd",
    .Bind = UsbdDriverBind,
    .Init = UsbdDriverInit,
    .Release = UsbdDriverRelease,
};
HDF_INIT(g_usbdDriverEntry);

static int UsbdAddDevicesOnStart(struct UsbdService *service);

int32_t BindUsbSubscriber(struct UsbdService *service, struct UsbdSubscriber *subscriber)
{
    HDF_LOGI("%{public}s:  entry", __func__);
    HDF_LOGI("%{public}s:%{public}d entry service:%{public}p subscriber:%{public}p", __func__, __LINE__, service,
             subscriber);
    if (service == NULL) {
        HDF_LOGE("%{public}s  service is NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    service->subscriber = subscriber;
    int32_t ret = UsbdAddDevicesOnStart(service);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d UsbdAddDevicesOnStart ret=%{public}d", __func__, __LINE__, ret);
        return ret;
    }
    return HDF_SUCCESS;
}

int32_t UnbindUsbSubscriber(struct UsbdService *service)
{
    HDF_LOGI("%{public}s:%{public}d entry", __func__, __LINE__);
    if (service == NULL) {
        HDF_LOGE("%{public}s service is NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (service->subscriber != NULL) {
        HDF_LOGI("%{public}s:%{public}d entry", __func__, __LINE__);
        OsalMemFree(service->subscriber);
        service->subscriber = NULL;
    }
    return HDF_SUCCESS;
}

static int UsbdPnpLoaderEventReceived(void *priv, uint32_t id, struct HdfSBuf *data)
{
    struct UsbPnpNotifyMatchInfoTable *infoTable = NULL;
    struct UsbdService *super = (struct UsbdService *)priv;
    HDF_LOGI("%{public}s:%{public}d id:%{public}d service:%{public}s subscriber:%{public}s ", __func__, __LINE__, id,
             super ? "OK" : "NULL", super ? (super->subscriber ? "OK" : "NULL") : "NULL");
    if (!super) {
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGI("%{public}s:%{public}d id:%{public}d service:%{public}p subscriber:%{public}p ", __func__, __LINE__, id,
             super, super->subscriber);
    if (USB_PNP_DRIVER_GADGET_ADD == id) {
        NotifySubscriberDevice(super->subscriber, ACT_UPDEVICE, 0, 0);
        return HDF_SUCCESS;
    } else if (USB_PNP_DRIVER_GADGET_REMOVE == id) {
        NotifySubscriberDevice(super->subscriber, ACT_DOWNDEVICE, 0, 0);
        return HDF_SUCCESS;
    }
    uint32_t infoSize;
    bool flag = HdfSbufReadBuffer(data, (const void **)(&infoTable), &infoSize);
    int ret = HDF_SUCCESS;
    if ((flag == false) || (infoTable == NULL)) {
        ret = HDF_ERR_INVALID_PARAM;
        HDF_LOGE("%{public}s: fail to read infoTable in event data, flag=%{public}d, infoTable=%{public}p", __func__,
                 flag, infoTable);
        return ret;
    }
    if (infoTable->deviceInfo.deviceClass == HEX_NUM_09) {
        HDF_LOGE("%{public}s:%{public}d hub device ret:%{public}d", __func__, __LINE__, ret);
        return ret;
    }
    if (id == USB_PNP_NOTIFY_ADD_DEVICE) {
        ret = HDF_SUCCESS;
        if (infoTable->deviceInfo.deviceClass != HEX_NUM_09)
            NotifySubscriberDevice(super->subscriber, ACT_DEVUP, infoTable->busNum, infoTable->devNum);
    } else if (id == USB_PNP_NOTIFY_REMOVE_DEVICE) {
        ret = HDF_SUCCESS;
        if (infoTable->deviceInfo.deviceClass != HEX_NUM_09)
            NotifySubscriberDevice(super->subscriber, ACT_DEVDOWN, infoTable->busNum, infoTable->devNum);
    } else {
        ret = HDF_SUCCESS;
    }

    HDF_LOGI("%{public}s:%{public}d ret=%{public}d DONE", __func__, __LINE__, ret);

    return ret;
}

static int UsbdEventHandle(const struct UsbdService *inst)
{
    struct HdfIoService *usbPnpServ = HdfIoServiceBind(USB_PNP_NOTIFY_SERVICE_NAME);
    static struct HdfDevEventlistener usbPnpListener = {
        .callBack = UsbdPnpLoaderEventReceived,
    };
    usbPnpListener.priv = (void *)(inst);

    if (usbPnpServ == NULL) {
        HDF_LOGE("%{public}s: HdfIoServiceBind faile.", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    int status;
    status = HdfDeviceRegisterEventListener(usbPnpServ, &usbPnpListener);
    if (status != HDF_SUCCESS) {
        HDF_LOGE("HdfDeviceRegisterEventListener faile status=%{public}d", status);
        return status;
    }

    return HDF_SUCCESS;
}

static int32_t HdfReadDevice(struct UsbdService *service, int32_t *count, int32_t *size, struct HdfSBuf *reply)
{
    int32_t busNum;
    int32_t devNum;
    uint8_t devClass;
    uint8_t subClass;
    uint8_t protocol;
    uint8_t status;
    if (!HdfSbufReadInt32(reply, &busNum)) {
        HDF_LOGE("%{public}s: fail to get service call reply", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadInt32(reply, &devNum)) {
        HDF_LOGE("%{public}s: fail to get service call reply", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint8(reply, &devClass)) {
        HDF_LOGE("%{public}s:%{public}d fail to get service call reply", __func__, __LINE__);
        return HDF_ERR_INVALID_OBJECT;
    }
    if (!HdfSbufReadUint8(reply, &subClass)) {
        HDF_LOGE("%{public}s:%{public}d fail to get service call reply", __func__, __LINE__);
        return HDF_ERR_INVALID_OBJECT;
    }
    if (!HdfSbufReadUint8(reply, &protocol)) {
        HDF_LOGE("%{public}s:%{public}d fail to get service call reply", __func__, __LINE__);
        return HDF_ERR_INVALID_OBJECT;
    }
    if (!HdfSbufReadUint8(reply, &status)) {
        HDF_LOGE("%{public}s:%{public}d fail to get service call reply", __func__, __LINE__);
        return HDF_ERR_INVALID_OBJECT;
    }
    HDF_LOGI(
        "%{public}s:%{public}d OnStart get device[%{public}d]:%{public}d:%{public}d status:%{pubic}d "
        "class:%{public}d subClass:%{public}d protocol:%{pubic}d",
        __func__, __LINE__, *count, busNum, devNum, status, devClass, subClass, protocol);
    if (devClass != HEX_NUM_09) {
        NotifySubscriberDevice(service->subscriber, ACT_DEVUP, busNum, devNum);
        ++(*size);
    }
    ++(*count);
    return HDF_SUCCESS;
}

static int ReturnOnStartOut(int ret, struct HdfSBuf *data, struct HdfSBuf *reply, struct HdfIoService *usbPnpServ)
{
    HdfSBufRecycle(data);
    HdfSBufRecycle(reply);
    HdfIoServiceRecycle(usbPnpServ);
    return ret;
}

static int UsbdAddDevicesOnStart(struct UsbdService *service)
{
    struct HdfIoService *usbPnpServ = HdfIoServiceBind(USB_PNP_NOTIFY_SERVICE_NAME);
    if (service == NULL || usbPnpServ == NULL) {
        HDF_LOGE("%{public}s:%{public}d service is NULL or HdfIoServiceBind.faile serv:%{public}s.", __func__, __LINE__,
                 USB_PNP_NOTIFY_SERVICE_NAME);
        return HDF_ERR_INVALID_OBJECT;
    }
    int32_t ret;
    struct HdfSBuf *data = HdfSBufObtainDefaultSize();
    if (data == NULL) {
        HDF_LOGE("%{public}s: fail to obtain sbuf data", __func__);
        ret = HDF_DEV_ERR_NO_MEMORY;
        return ret;
    }
    struct HdfSBuf *reply = HdfSBufObtainDefaultSize();
    if (reply == NULL) {
        HDF_LOGE("%{public}s: fail to obtain sbuf reply", __func__);
        ret = HDF_DEV_ERR_NO_MEMORY;
        return ReturnOnStartOut(ret, data, reply, usbPnpServ);
    }
    ret = usbPnpServ->dispatcher->Dispatch(&usbPnpServ->object, USB_PNP_DRIVER_GETDEVICES, data, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: fail to send serivice call, ret=%{public}d", __func__, ret);
        return ReturnOnStartOut(ret, data, reply, usbPnpServ);
    }
    int32_t count = 0;
    int32_t size = 0;
    while (1) {
        int statue = HdfReadDevice(service, &count, &size, reply);
        if (statue == HDF_ERR_INVALID_PARAM) {
            break;
        } else if (statue == HDF_ERR_INVALID_OBJECT) {
            ret = statue;
            break;
        }
    }
    HDF_LOGI("%{public}s:%{public}d onStart add devices:%{public}d size:%{public}d success", __func__, __LINE__, count,
             size);

    HdfSBufRecycle(data);
    HdfSBufRecycle(reply);
    HdfIoServiceRecycle(usbPnpServ);
    return ret;
}
