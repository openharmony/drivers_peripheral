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

#include <hdf_base.h>
#include <hdf_core_log.h>
#include <hdf_device_desc.h>
#include <hdf_sbuf_ipc.h>
#include "usb_device_impl.h"
#include "v2_0/usb_device_interface_stub.h"

#define HDF_LOG_TAG    usb_device_interface_driver

using namespace OHOS::HDI::Usb::V2_0;

struct HdfUsbDeviceInterfaceHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t UsbDeviceInterfaceDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    if (client == nullptr || client->device == nullptr || client->device->service == nullptr) {
        HDF_LOGE("%{public}s:invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    OHOS::MessageParcel *dataParcel = nullptr;
    OHOS::MessageParcel *replyParcel = nullptr;
    OHOS::MessageOption option;

    if (SbufToParcel(data, &dataParcel) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: invalid data sbuf object to dispatch", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (SbufToParcel(reply, &replyParcel) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: invalid reply sbuf object to dispatch", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    auto *hdfUsbDevInterfaceHost = CONTAINER_OF(client->device->service, struct HdfUsbDeviceInterfaceHost, ioService);
    if (hdfUsbDevInterfaceHost == nullptr || hdfUsbDevInterfaceHost->stub == nullptr) {
        HDF_LOGE("%{public}s:host or stub are nullptr", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return hdfUsbDevInterfaceHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfUsbDeviceInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver init start", __func__);
    if (deviceObject == nullptr) {
        HDF_LOGE("%{public}s:deviceObject is nullptr", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }
    return HDF_SUCCESS;
}

static int HdfUsbDeviceInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver bind start", __func__);
    if (deviceObject == nullptr) {
        HDF_LOGE("%{public}s:deviceObject is nullptr", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }
    auto *hdfUsbDeviceInterfaceHost = new (std::nothrow) HdfUsbDeviceInterfaceHost;
    if (hdfUsbDeviceInterfaceHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create create HdfUsbDeviceInterfaceHost object", __func__);
        return HDF_FAILURE;
    }

    hdfUsbDeviceInterfaceHost->ioService.Dispatch = UsbDeviceInterfaceDriverDispatch;
    hdfUsbDeviceInterfaceHost->ioService.Open = nullptr;
    hdfUsbDeviceInterfaceHost->ioService.Release = nullptr;

    auto serviceImpl = OHOS::HDI::Usb::V2_0::IUsbDeviceInterface::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfUsbDeviceInterfaceHost;
        hdfUsbDeviceInterfaceHost =nullptr;
        return HDF_FAILURE;
    }

    hdfUsbDeviceInterfaceHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        OHOS::HDI::Usb::V2_0::IUsbDeviceInterface::GetDescriptor());
    if (hdfUsbDeviceInterfaceHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfUsbDeviceInterfaceHost;
        hdfUsbDeviceInterfaceHost = nullptr;
        return HDF_FAILURE;
    }

    int32_t ret = UsbDeviceImpl::UsbdEventHandle();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: UsbdEventHandle failed", __func__);
        hdfUsbDeviceInterfaceHost->stub = nullptr;
        delete hdfUsbDeviceInterfaceHost;
        hdfUsbDeviceInterfaceHost = nullptr;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfUsbDeviceInterfaceHost->ioService;
    return HDF_SUCCESS;
}

static void HdfUsbDeviceInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver release start", __func__);
    int32_t ret = UsbDeviceImpl::UsbdEventHandleRelease();
    if (ret != HDF_SUCCESS) {
        HDF_LOGW("%{public}s:UsbdEventHandleRelease ret=%{public}d", __func__, ret);
    }
    if (deviceObject == nullptr || deviceObject->service == nullptr) {
        HDF_LOGE("HdfUsbInterfaceDriverRelease not initted");
        return;
    }

    auto *hdfUsbDeviceInterfaceHost = CONTAINER_OF(deviceObject->service, struct HdfUsbDeviceInterfaceHost, ioService);
    if (hdfUsbDeviceInterfaceHost == nullptr) {
        HDF_LOGE("%{public}s:invalid param", __func__);
        return;
    }
    delete hdfUsbDeviceInterfaceHost;
    hdfUsbDeviceInterfaceHost = nullptr;
    deviceObject->service = nullptr;
    return;
}

static struct HdfDriverEntry g_usbdeviceinterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "",
    .Bind = HdfUsbDeviceInterfaceDriverBind,
    .Init = HdfUsbDeviceInterfaceDriverInit,
    .Release = HdfUsbDeviceInterfaceDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_usbdeviceinterfaceDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
