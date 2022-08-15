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
#include "v1_0/partition_slot_stub.h"

using namespace OHOS::HDI::Partitionslot::V1_0;

struct HdfPartitionSlotHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t PartitionSlotDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    auto *hdfPartitionSlotHost = CONTAINER_OF(client->device->service, struct HdfPartitionSlotHost, ioService);

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

    return hdfPartitionSlotHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfPartitionSlotDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfPartitionSlotDriverInit enter");
    return HDF_SUCCESS;
}

static int HdfPartitionSlotDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfPartitionSlotDriverBind enter");

    auto *hdfPartitionSlotHost = new (std::nothrow) HdfPartitionSlotHost;
    if (hdfPartitionSlotHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create create HdfPartitionSlotHost object", __func__);
        return HDF_FAILURE;
    }

    hdfPartitionSlotHost->ioService.Dispatch = PartitionSlotDriverDispatch;
    hdfPartitionSlotHost->ioService.Open = NULL;
    hdfPartitionSlotHost->ioService.Release = NULL;

    auto serviceImpl = IPartitionSlot::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfPartitionSlotHost;
        return HDF_FAILURE;
    }

    hdfPartitionSlotHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        IPartitionSlot::GetDescriptor());
    if (hdfPartitionSlotHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfPartitionSlotHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfPartitionSlotHost->ioService;
    return HDF_SUCCESS;
}

static void HdfPartitionSlotDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfPartitionSlotDriverRelease enter");
    if (deviceObject->service == nullptr) {
        HDF_LOGE("HdfPartitionSlotDriverRelease not initted");
        return;
    }

    auto *hdfPartitionSlotHost = CONTAINER_OF(deviceObject->service, struct HdfPartitionSlotHost, ioService);
    delete hdfPartitionSlotHost;
}

static struct HdfDriverEntry g_partitionslotDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "partitionslot_interface_service",
    .Bind = HdfPartitionSlotDriverBind,
    .Init = HdfPartitionSlotDriverInit,
    .Release = HdfPartitionSlotDriverRelease,
};

#ifndef __cplusplus
extern "C" {
#endif
HDF_INIT(g_partitionslotDriverEntry);
#ifndef __cplusplus
}
#endif
