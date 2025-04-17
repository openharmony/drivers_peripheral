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
#include "usb_port_impl.h"
#include "v2_0/usb_port_interface_stub.h"

#define HDF_LOG_TAG    usb_port_interface_driver

using namespace OHOS::HDI::Usb::V2_0;

struct HdfUsbPortInterfaceHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t UsbPortInterfaceDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
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

    auto *hdfUsbPortInterfaceHost = CONTAINER_OF(client->device->service, struct HdfUsbPortInterfaceHost, ioService);
    if (hdfUsbPortInterfaceHost == nullptr || hdfUsbPortInterfaceHost->stub == nullptr) {
        HDF_LOGE("%{public}s:host or stub are nullptr", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return hdfUsbPortInterfaceHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfUsbPortInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver init start", __func__);
    if (deviceObject == nullptr) {
        HDF_LOGE("%{public}s:deviceObject is nullptr", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }
    return HDF_SUCCESS;
}

static int HdfUsbPortInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver bind start", __func__);
    if (deviceObject == nullptr) {
        HDF_LOGE("%{public}s:deviceObject is nullptr", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }
    auto *hdfUsbPortInterfaceHost = new (std::nothrow) HdfUsbPortInterfaceHost;
    if (hdfUsbPortInterfaceHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create HdfUsbPortInterfaceHost object", __func__);
        return HDF_FAILURE;
    }

    hdfUsbPortInterfaceHost->ioService.Dispatch = UsbPortInterfaceDriverDispatch;
    hdfUsbPortInterfaceHost->ioService.Open = nullptr;
    hdfUsbPortInterfaceHost->ioService.Release = nullptr;

    auto serviceImpl = OHOS::HDI::Usb::V2_0::IUsbPortInterface::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfUsbPortInterfaceHost;
        hdfUsbPortInterfaceHost = nullptr;
        return HDF_FAILURE;
    }

    hdfUsbPortInterfaceHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        OHOS::HDI::Usb::V2_0::IUsbPortInterface::GetDescriptor());
    if (hdfUsbPortInterfaceHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfUsbPortInterfaceHost;
        hdfUsbPortInterfaceHost = nullptr;
        return HDF_FAILURE;
    }

    sptr<UsbPortImpl> impl = static_cast<UsbPortImpl *>(serviceImpl.GetRefPtr());
    impl->device_ = deviceObject;
    int32_t ret = UsbPortImpl::UsbdEventHandle(impl);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: UsbdEventHandle failed", __func__);
        hdfUsbPortInterfaceHost->stub = nullptr;
        delete hdfUsbPortInterfaceHost;
        hdfUsbPortInterfaceHost = nullptr;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfUsbPortInterfaceHost->ioService;
    return HDF_SUCCESS;
}

static void HdfUsbPortInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver release start", __func__);
    if (deviceObject == nullptr || deviceObject->service == nullptr) {
        HDF_LOGE("HdfUsbInterfaceDriverRelease not initted");
        return;
    }

    auto *hdfUsbPortInterfaceHost = CONTAINER_OF(deviceObject->service, struct HdfUsbPortInterfaceHost, ioService);
    if (hdfUsbPortInterfaceHost == nullptr) {
        HDF_LOGE("%{public}s:invalid param", __func__);
        return;
    }
    delete hdfUsbPortInterfaceHost;
    hdfUsbPortInterfaceHost = nullptr;
    deviceObject->service = nullptr;
    return;
}

static struct HdfDriverEntry g_usbportinterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "",
    .Bind = HdfUsbPortInterfaceDriverBind,
    .Init = HdfUsbPortInterfaceDriverInit,
    .Release = HdfUsbPortInterfaceDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_usbportinterfaceDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
