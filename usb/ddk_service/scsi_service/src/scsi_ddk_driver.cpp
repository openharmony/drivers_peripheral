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

#include "v1_0/scsi_peripheral_ddk_stub.h"
#include <hdf_base.h>
#include <hdf_device_desc.h>
#include <hdf_sbuf_ipc.h>
#include "scsi_ddk_uhdf_log.h"

#define HDF_LOG_TAG scsi_ddk_driver

using namespace OHOS::HDI::Usb::ScsiDdk::V1_0;

struct HdfScsiDdkHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t ScsiDdkDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    auto *hdfScsiDdkHost = CONTAINER_OF(client->device->service, struct HdfScsiDdkHost, ioService);

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

    return hdfScsiDdkHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfScsiDdkDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver init start", __func__);
    return HDF_SUCCESS;
}

static int HdfScsiDdkDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver bind start", __func__);
    auto *hdfScsiDdkHost = new (std::nothrow) HdfScsiDdkHost;
    if (hdfScsiDdkHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create HdfScsiDdkHost object", __func__);
        return HDF_FAILURE;
    }

    hdfScsiDdkHost->ioService.Dispatch = ScsiDdkDriverDispatch;
    hdfScsiDdkHost->ioService.Open = NULL;
    hdfScsiDdkHost->ioService.Release = NULL;

    auto serviceImpl = OHOS::HDI::Usb::ScsiDdk::V1_0::IScsiPeripheralDdk::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get implement service", __func__);
        delete hdfScsiDdkHost;
        return HDF_FAILURE;
    }

    hdfScsiDdkHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        OHOS::HDI::Usb::ScsiDdk::V1_0::IScsiPeripheralDdk::GetDescriptor());
    if (hdfScsiDdkHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfScsiDdkHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfScsiDdkHost->ioService;
    return HDF_SUCCESS;
}

static void HdfScsiDdkDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver release start", __func__);

    if (deviceObject->service == nullptr) {
        return;
    }

    auto *hdfScsiDdkHost = CONTAINER_OF(deviceObject->service, struct HdfScsiDdkHost, ioService);
    if (hdfScsiDdkHost != nullptr) {
        delete hdfScsiDdkHost;
    }
}

static struct HdfDriverEntry g_scsiddkDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "",
    .Bind = HdfScsiDdkDriverBind,
    .Init = HdfScsiDdkDriverInit,
    .Release = HdfScsiDdkDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_scsiddkDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
