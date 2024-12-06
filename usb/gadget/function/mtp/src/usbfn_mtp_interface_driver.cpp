/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include <pthread.h>

#include "usbfn_mtp_impl.h"
#include "v1_0/usbfn_mtp_interface_stub.h"

#define HDF_LOG_TAG usbfn_mtp_interface_driver

using namespace OHOS::HDI::Usb::Gadget::Mtp::V1_0;

struct HdfUsbfnMtpInterfaceHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static pthread_rwlock_t g_rwLock = PTHREAD_RWLOCK_INITIALIZER;
static bool g_stop = true;

static int32_t UsbfnMtpInterfaceDriverDispatch(
    struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data, struct HdfSBuf *reply)
{
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

    pthread_rwlock_rdlock(&g_rwLock);
    auto *hdfUsbfnMtpInterfaceHost = CONTAINER_OF(client->device->service, struct HdfUsbfnMtpInterfaceHost, ioService);
    if (hdfUsbfnMtpInterfaceHost == nullptr || g_stop) {
        HDF_LOGE("%{public}s: hdfUsbfnMtpInterfaceHost is nullptr, %{public}d", __func__, g_stop);
        pthread_rwlock_unlock(&g_rwLock);
        return HDF_FAILURE;
    }

    int ret = hdfUsbfnMtpInterfaceHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
    pthread_rwlock_unlock(&g_rwLock);
    return ret;
}

static int HdfUsbfnMtpInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver init start", __func__);
    if (deviceObject == nullptr) {
        HDF_LOGE("%{public}s:deviceObject is nullptr", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }
    return HDF_SUCCESS;
}

static int HdfUsbfnMtpInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver bind start", __func__);
    if (deviceObject == nullptr) {
        HDF_LOGE("%{public}s:deviceObject is nullptr", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }
    auto *hdfUsbfnMtpInterfaceHost = new (std::nothrow) HdfUsbfnMtpInterfaceHost;
    if (hdfUsbfnMtpInterfaceHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create HdfUsbfnMtpInterfaceHost object", __func__);
        return HDF_FAILURE;
    }

    hdfUsbfnMtpInterfaceHost->ioService.Dispatch = UsbfnMtpInterfaceDriverDispatch;
    hdfUsbfnMtpInterfaceHost->ioService.Open = nullptr;
    hdfUsbfnMtpInterfaceHost->ioService.Release = nullptr;

    auto serviceImpl = IUsbfnMtpInterface::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfUsbfnMtpInterfaceHost;
        return HDF_FAILURE;
    }

    hdfUsbfnMtpInterfaceHost->stub =
        OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl, IUsbfnMtpInterface::GetDescriptor());
    if (hdfUsbfnMtpInterfaceHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfUsbfnMtpInterfaceHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfUsbfnMtpInterfaceHost->ioService;

    sptr<UsbfnMtpImpl> impl = static_cast<UsbfnMtpImpl *>(serviceImpl.GetRefPtr());
    impl->deviceObject_ = deviceObject;
    g_stop = false;
    return HDF_SUCCESS;
}

static void HdfUsbfnMtpInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver release start", __func__);
    if (deviceObject->service == nullptr) {
        HDF_LOGE("HdfUsbfnMtpInterfaceDriverRelease not initted");
        return;
    }

    pthread_rwlock_wrlock(&g_rwLock);
    g_stop = true;
    auto *hdfUsbfnMtpInterfaceHost = CONTAINER_OF(deviceObject->service, struct HdfUsbfnMtpInterfaceHost, ioService);
    if (hdfUsbfnMtpInterfaceHost != nullptr) {
        delete hdfUsbfnMtpInterfaceHost;
    }
    pthread_rwlock_unlock(&g_rwLock);
}

static struct HdfDriverEntry g_usbfnmtpinterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "usbfn_mtp",
    .Bind = HdfUsbfnMtpInterfaceDriverBind,
    .Init = HdfUsbfnMtpInterfaceDriverInit,
    .Release = HdfUsbfnMtpInterfaceDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_usbfnmtpinterfaceDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
