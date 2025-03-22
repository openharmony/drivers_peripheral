/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "v1_1/usb_ddk_stub.h"
#include <hdf_base.h>
#include <hdf_device_desc.h>
#include <hdf_log.h>
#include <hdf_sbuf_ipc.h>
#include "usbd_wrapper.h"

#define HDF_LOG_TAG usb_ddk_driver

using namespace OHOS::HDI::Usb::Ddk;

struct HdfUsbDdkHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t UsbDdkDriverDispatch(
    struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    auto *hdfUsbDdkHost = CONTAINER_OF(client->device->service, struct HdfUsbDdkHost, ioService);

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

    return hdfUsbDdkHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfUsbDdkDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver init start", __func__);
    return HDF_SUCCESS;
}

static int HdfUsbDdkDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver bind start", __func__);
    auto *hdfUsbDdkHost = new (std::nothrow) HdfUsbDdkHost;
    if (hdfUsbDdkHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create create HdfUsbDdkHost object", __func__);
        return HDF_FAILURE;
    }

    hdfUsbDdkHost->ioService.Dispatch = UsbDdkDriverDispatch;
    hdfUsbDdkHost->ioService.Open = NULL;
    hdfUsbDdkHost->ioService.Release = NULL;

    auto serviceImpl = V1_1::IUsbDdk::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfUsbDdkHost;
        return HDF_FAILURE;
    }

    hdfUsbDdkHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(
        serviceImpl, V1_1::IUsbDdk::GetDescriptor());
    if (hdfUsbDdkHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfUsbDdkHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfUsbDdkHost->ioService;
    return HDF_SUCCESS;
}

static void HdfUsbDdkDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver release start", __func__);
    if (deviceObject->service == nullptr) {
        return;
    }

    auto *hdfUsbDdkHost = CONTAINER_OF(deviceObject->service, struct HdfUsbDdkHost, ioService);
    if (hdfUsbDdkHost != nullptr) {
        delete hdfUsbDdkHost;
    }
}

static struct HdfDriverEntry g_usbddkDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "",
    .Bind = HdfUsbDdkDriverBind,
    .Init = HdfUsbDdkDriverInit,
    .Release = HdfUsbDdkDriverRelease,
};
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_usbddkDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
