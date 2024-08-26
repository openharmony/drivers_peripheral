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

#include <hdf_base.h>
#include <hdf_device_desc.h>
#include <hdf_log.h>
#include <hdf_sbuf_ipc.h>

#include "hdf_usb_pnp_manage.h"
#include "usb_impl.h"
#include "usbd_dispatcher.h"
#include "v1_1/usb_interface_stub.h"
#include "usbd_wrapper.h"

#define HDF_LOG_TAG Usbd

using namespace OHOS::HDI::Usb::V1_1;

struct HdfUsbInterfaceHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t UsbInterfaceDriverDispatch(
    struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == nullptr || client->device == nullptr || client->device->service == nullptr) {
        HDF_LOGE("%{public}s:invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    OHOS::MessageParcel *dataParcel = nullptr;
    OHOS::MessageParcel *replyParcel = nullptr;
    OHOS::MessageOption option;

    if (SbufToParcel(data, &dataParcel) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:invalid data sbuf object to dispatch", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (SbufToParcel(reply, &replyParcel) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:invalid reply sbuf object to dispatch", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    auto *hdfUsbInterfaceHost = CONTAINER_OF(client->device->service, struct HdfUsbInterfaceHost, ioService);
    if (hdfUsbInterfaceHost == nullptr || hdfUsbInterfaceHost->stub == nullptr) {
        HDF_LOGE("%{public}s:host or stub are nullptr", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return hdfUsbInterfaceHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfUsbInterfaceDriverInit(struct HdfDeviceObject * const deviceObject)
{
    if (deviceObject == nullptr) {
        HDF_LOGE("%{public}s:deviceObject is nullptr", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }
    return HDF_SUCCESS;
}

static int HdfUsbInterfaceDriverBind(struct HdfDeviceObject * const deviceObject)
{
    if (deviceObject == nullptr) {
        HDF_LOGE("%{public}s:deviceObject is nullptr", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }
    auto *hdfUsbInterfaceHost = new (std::nothrow) HdfUsbInterfaceHost;
    if (hdfUsbInterfaceHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create HdfUsbInterfaceHost object", __func__);
        return HDF_FAILURE;
    }

    hdfUsbInterfaceHost->ioService.Dispatch = UsbInterfaceDriverDispatch;
    hdfUsbInterfaceHost->ioService.Open = nullptr;
    hdfUsbInterfaceHost->ioService.Release = nullptr;

    auto serviceImpl = OHOS::HDI::Usb::V1_1::IUsbInterface::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfUsbInterfaceHost;
        hdfUsbInterfaceHost = nullptr;
        return HDF_FAILURE;
    }

    hdfUsbInterfaceHost->stub =
        OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
            OHOS::HDI::Usb::V1_1::IUsbInterface::GetDescriptor());
    if (hdfUsbInterfaceHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfUsbInterfaceHost;
        hdfUsbInterfaceHost = nullptr;
        return HDF_FAILURE;
    }

    sptr<UsbImpl> impl = static_cast<UsbImpl *>(serviceImpl.GetRefPtr());
    impl->device_ = deviceObject;
    int32_t ret = UsbImpl::UsbdEventHandle(impl);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: UsbdEventHandle failed", __func__);
        hdfUsbInterfaceHost->stub = nullptr;
        delete hdfUsbInterfaceHost;
        hdfUsbInterfaceHost = nullptr;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfUsbInterfaceHost->ioService;
    return HDF_SUCCESS;
}

static void HdfUsbInterfaceDriverRelease(struct HdfDeviceObject *const deviceObject)
{
    int32_t ret = UsbImpl::UsbdEventHandleRelease();
    if (ret != HDF_SUCCESS) {
        HDF_LOGW("%{public}s:UsbdEventHandleRelease ret=%{public}d", __func__, ret);
    }

    if (deviceObject == nullptr || deviceObject->service == nullptr) {
        HDF_LOGE("HdfUsbInterfaceDriverRelease not initted");
        return;
    }

    auto *hdfUsbInterfaceHost = CONTAINER_OF(deviceObject->service, struct HdfUsbInterfaceHost, ioService);
    if (hdfUsbInterfaceHost == nullptr) {
        HDF_LOGE("%{public}s:invalid param", __func__);
        return;
    }
    delete hdfUsbInterfaceHost;
    hdfUsbInterfaceHost = nullptr;
    deviceObject->service = nullptr;
    return;
}

static struct HdfDriverEntry g_usbInterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "usbd",
    .Bind = HdfUsbInterfaceDriverBind,
    .Init = HdfUsbInterfaceDriverInit,
    .Release = HdfUsbInterfaceDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_usbInterfaceDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
