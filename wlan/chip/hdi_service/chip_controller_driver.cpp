/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "v2_0/chip_controller_stub.h"

#define HDF_LOG_TAG    chip_controller_driver

using namespace OHOS::HDI::Wlan::Chip::V2_0;

struct HdfChipControllerHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t ChipControllerDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    auto *hdfChipControllerHost = CONTAINER_OF(client->device->service, struct HdfChipControllerHost, ioService);

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

    return hdfChipControllerHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfChipControllerDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver init start", __func__);
    return HDF_SUCCESS;
}

static int HdfChipControllerDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver bind start", __func__);
    auto *hdfChipControllerHost = new (std::nothrow) HdfChipControllerHost;
    if (hdfChipControllerHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create create HdfChipControllerHost object", __func__);
        return HDF_FAILURE;
    }

    hdfChipControllerHost->ioService.Dispatch = ChipControllerDriverDispatch;
    hdfChipControllerHost->ioService.Open = NULL;
    hdfChipControllerHost->ioService.Release = NULL;

    auto serviceImpl = OHOS::HDI::Wlan::Chip::V2_0::IChipController::Get("chip_interface_service", true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfChipControllerHost;
        return HDF_FAILURE;
    }

    hdfChipControllerHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        OHOS::HDI::Wlan::Chip::V2_0::IChipController::GetDescriptor());
    if (hdfChipControllerHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfChipControllerHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfChipControllerHost->ioService;
    return HDF_SUCCESS;
}

static void HdfChipControllerDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver release start", __func__);
    if (deviceObject->service == nullptr) {
        return;
    }

    auto *hdfChipControllerHost = CONTAINER_OF(deviceObject->service, struct HdfChipControllerHost, ioService);
    if (hdfChipControllerHost != nullptr) {
        delete hdfChipControllerHost;
    }
}

struct HdfDriverEntry g_chipcontrollerDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "chip",
    .Bind = HdfChipControllerDriverBind,
    .Init = HdfChipControllerDriverInit,
    .Release = HdfChipControllerDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif
HDF_INIT(g_chipcontrollerDriverEntry);
#ifdef  __cplusplus
}
#endif