/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "v1_0/allocator_stub.h"

#undef LOG_TAG
#define LOG_TAG "ALLOC_DRV"
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002515

using namespace OHOS::HDI::Display::Buffer::V1_0;

struct HdfAllocatorHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t AllocatorDriverDispatch(
    struct HdfDeviceIoClient* client, int cmdId, struct HdfSBuf* data, struct HdfSBuf* reply)
{
    if ((client == nullptr) || (client->device == nullptr)) {
        HDF_LOGE("%{public}s: param is nullptr", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    auto* hdfAllocatorHost =
        CONTAINER_OF(client->device->service, struct HdfAllocatorHost, ioService);

    OHOS::MessageParcel* dataParcel = nullptr;
    OHOS::MessageParcel* replyParcel = nullptr;
    OHOS::MessageOption option;

    if (SbufToParcel(data, &dataParcel) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: invalid data sbuf object to dispatch", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (SbufToParcel(reply, &replyParcel) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: invalid reply sbuf object to dispatch", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return hdfAllocatorHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfAllocatorDriverInit(struct HdfDeviceObject* deviceObject)
{
    HDF_LOGI("%{public}s: enter", __func__);
    return HDF_SUCCESS;
}

static int HdfAllocatorDriverBind(struct HdfDeviceObject* deviceObject)
{
    HDF_LOGI("%{public}s: enter", __func__);
    auto* hdfAllocatorHost = new (std::nothrow) HdfAllocatorHost;
    if (hdfAllocatorHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create HdfAllocatorHost object", __func__);
        return HDF_FAILURE;
    }

    hdfAllocatorHost->ioService.Dispatch = AllocatorDriverDispatch;
    hdfAllocatorHost->ioService.Open = NULL;

    hdfAllocatorHost->ioService.Release = NULL;

    auto serviceImpl = IAllocator::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get the implement of service", __func__);
        delete hdfAllocatorHost;
        return HDF_FAILURE;
    }

    hdfAllocatorHost->stub =
        OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl, IAllocator::GetDescriptor());
    if (hdfAllocatorHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfAllocatorHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfAllocatorHost->ioService;
    return HDF_SUCCESS;
}

static void HdfAllocatorDriverRelease(struct HdfDeviceObject* deviceObject)
{
    HDF_LOGI("%{public}s: enter", __func__);
    if (deviceObject->service == nullptr) {
        HDF_LOGE("%{public}s: service is nullptr", __func__);
        return;
    }

    auto* hdfAllocatorHost = CONTAINER_OF(deviceObject->service, struct HdfAllocatorHost, ioService);
    delete hdfAllocatorHost;
}

static struct HdfDriverEntry g_allocatorDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "display_buffer",
    .Bind = HdfAllocatorDriverBind,
    .Init = HdfAllocatorDriverInit,
    .Release = HdfAllocatorDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif
HDF_INIT(g_allocatorDriverEntry);
#ifdef __cplusplus
}
#endif
