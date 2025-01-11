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
#include <hdf_device_desc.h>
#include <hdf_log.h>
#include <hdf_sbuf_ipc.h>
#include "usbd_wrapper.h"
#include "v1_0/usb_serial_ddk_stub.h"

#define HDF_LOG_TAG usb_serial_ddk_driver

using namespace OHOS::HDI::Usb::UsbSerialDdk::V1_0;

struct HdfUsbSerialDdkHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t UsbSerialDdkDriverDispatch(
    struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    auto *hdfUsbSerialDdkHost = CONTAINER_OF(client->device->service, struct HdfUsbSerialDdkHost, ioService);
    if (hdfUsbSerialDdkHost == nullptr) {
        HDF_LOGE("%{public}s: hdfUsbSerialDdkHost = nullptr", __func__);
        return HDF_FAILURE;
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

    return hdfUsbSerialDdkHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfUsbSerialDdkDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver init start", __func__);
    return HDF_SUCCESS;
}

static int HdfUsbSerialDdkDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver bind start", __func__);
    auto *hdfUsbSerialDdkHost = new (std::nothrow) HdfUsbSerialDdkHost;
    if (hdfUsbSerialDdkHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create create hdfUsbSerialDdkHost object", __func__);
        return HDF_FAILURE;
    }

    hdfUsbSerialDdkHost->ioService.Dispatch = UsbSerialDdkDriverDispatch;
    hdfUsbSerialDdkHost->ioService.Open = NULL;
    hdfUsbSerialDdkHost->ioService.Release = NULL;

    auto serviceImpl = OHOS::HDI::Usb::UsbSerialDdk::V1_0::IUsbSerialDdk::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfUsbSerialDdkHost;
        return HDF_FAILURE;
    }

    hdfUsbSerialDdkHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(
        serviceImpl, OHOS::HDI::Usb::UsbSerialDdk::V1_0::IUsbSerialDdk::GetDescriptor());
    if (hdfUsbSerialDdkHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfUsbSerialDdkHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfUsbSerialDdkHost->ioService;
    return HDF_SUCCESS;
}

static void HdfUsbSerialDdkDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver release start", __func__);
    if (deviceObject->service == nullptr) {
        return;
    }

    auto *hdfUsbSerialDdkHost = CONTAINER_OF(deviceObject->service, struct HdfUsbSerialDdkHost, ioService);
    if (hdfUsbSerialDdkHost != nullptr) {
        delete hdfUsbSerialDdkHost;
    }
}

static struct HdfDriverEntry g_usbSeruakddkDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "",
    .Bind = HdfUsbSerialDdkDriverBind,
    .Init = HdfUsbSerialDdkDriverInit,
    .Release = HdfUsbSerialDdkDriverRelease,
};
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_usbSeruakddkDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
