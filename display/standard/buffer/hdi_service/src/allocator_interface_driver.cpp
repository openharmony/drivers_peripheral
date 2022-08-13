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
#include "v1_0/allocator_interface_stub.h"

using namespace OHOS::HDI::Display::Buffer::V1_0;

struct HdfAllocatorInterfaceHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t AllocatorInterfaceDriverDispatch(
    struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    auto *hdfAllocatorInterfaceHost =
        CONTAINER_OF(client->device->service, struct HdfAllocatorInterfaceHost, ioService);

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

    return hdfAllocatorInterfaceHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfAllocatorInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    (void)deviceObject;
    HDF_LOGI("HdfAllocatorInterfaceDriverInit enter");
    return HDF_SUCCESS;
}

static int HdfAllocatorInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfAllocatorInterfaceDriverBind enter");

    auto *hdfAllocatorInterfaceHost = new (std::nothrow) HdfAllocatorInterfaceHost;
    if (hdfAllocatorInterfaceHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create create HdfAllocatorInterfaceHost object", __func__);
        return HDF_FAILURE;
    }

    hdfAllocatorInterfaceHost->ioService.Dispatch = AllocatorInterfaceDriverDispatch;
    hdfAllocatorInterfaceHost->ioService.Open = NULL;
    hdfAllocatorInterfaceHost->ioService.Release = NULL;

    auto serviceImpl = IAllocatorInterface::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfAllocatorInterfaceHost;
        return HDF_FAILURE;
    }

    hdfAllocatorInterfaceHost->stub =
        OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl, IAllocatorInterface::GetDescriptor());
    if (hdfAllocatorInterfaceHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfAllocatorInterfaceHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfAllocatorInterfaceHost->ioService;
    return HDF_SUCCESS;
}

static void HdfAllocatorInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfAllocatorInterfaceDriverRelease enter");
    if (deviceObject->service == nullptr) {
        HDF_LOGE("HdfAllocatorInterfaceDriverRelease not initted");
        return;
    }

    auto *hdfAllocatorInterfaceHost = CONTAINER_OF(deviceObject->service, struct HdfAllocatorInterfaceHost, ioService);
    delete hdfAllocatorInterfaceHost;
}

static struct HdfDriverEntry g_allocatorinterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "display_buffer",
    .Bind = HdfAllocatorInterfaceDriverBind,
    .Init = HdfAllocatorInterfaceDriverInit,
    .Release = HdfAllocatorInterfaceDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif
HDF_INIT(g_allocatorinterfaceDriverEntry);
#ifdef __cplusplus
}
#endif