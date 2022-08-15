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

#include "v1_0/memory_tracker_interface_stub.h"

using namespace OHOS::HDI::Memorytracker::V1_0;

struct HdfMemoryTrackerInterfaceHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t MemoryTrackerInterfaceDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    auto *hdfMemoryTrackerInterfaceHost = CONTAINER_OF(client->device->service, struct HdfMemoryTrackerInterfaceHost,
        ioService);

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

    return hdfMemoryTrackerInterfaceHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfMemoryTrackerInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfMemoryTrackerInterfaceDriverInit enter");
    return HDF_SUCCESS;
}

static int HdfMemoryTrackerInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfMemoryTrackerInterfaceDriverBind enter");

    auto *hdfMemoryTrackerInterfaceHost = new (std::nothrow) HdfMemoryTrackerInterfaceHost;
    if (hdfMemoryTrackerInterfaceHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create create HdfMemoryTrackerInterfaceHost object", __func__);
        return HDF_FAILURE;
    }

    hdfMemoryTrackerInterfaceHost->ioService.Dispatch = MemoryTrackerInterfaceDriverDispatch;
    hdfMemoryTrackerInterfaceHost->ioService.Open = NULL;
    hdfMemoryTrackerInterfaceHost->ioService.Release = NULL;

    auto serviceImpl = IMemoryTrackerInterface::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfMemoryTrackerInterfaceHost;
        return HDF_FAILURE;
    }

    hdfMemoryTrackerInterfaceHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        IMemoryTrackerInterface::GetDescriptor());
    if (hdfMemoryTrackerInterfaceHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfMemoryTrackerInterfaceHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfMemoryTrackerInterfaceHost->ioService;
    return HDF_SUCCESS;
}

static void HdfMemoryTrackerInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfMemoryTrackerInterfaceDriverRelease enter");
    auto *hdfMemoryTrackerInterfaceHost = CONTAINER_OF(deviceObject->service, struct HdfMemoryTrackerInterfaceHost,
        ioService);
    delete hdfMemoryTrackerInterfaceHost;
}

static struct HdfDriverEntry g_memorytrackerinterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "memory_tracker_interface_service",
    .Bind = HdfMemoryTrackerInterfaceDriverBind,
    .Init = HdfMemoryTrackerInterfaceDriverInit,
    .Release = HdfMemoryTrackerInterfaceDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_memorytrackerinterfaceDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
