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
#include "v1_0/mapper_stub.h"

using namespace OHOS::HDI::Display::Buffer::V1_0;

struct HdfMapperHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t MapperDriverDispatch(
    struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    auto *hdfMapperHost = CONTAINER_OF(client->device->service, struct HdfMapperHost, ioService);

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

    return hdfMapperHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfMapperDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfMapperDriverInit enter");
    return HDF_SUCCESS;
}

static int HdfMapperDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfMapperDriverBind enter");

    auto *hdfMapperHost = new (std::nothrow) HdfMapperHost;
    if (hdfMapperHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create create HdfMapperHost object", __func__);
        return HDF_FAILURE;
    }

    hdfMapperHost->ioService.Dispatch = MapperDriverDispatch;
    hdfMapperHost->ioService.Open = NULL;
    hdfMapperHost->ioService.Release = NULL;

    auto serviceImpl = IMapper::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfMapperHost;
        return HDF_FAILURE;
    }

    hdfMapperHost->stub =
        OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl, IMapper::GetDescriptor());
    if (hdfMapperHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfMapperHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfMapperHost->ioService;
    return HDF_SUCCESS;
}

static void HdfMapperDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfMapperDriverRelease enter");
    if (deviceObject->service == nullptr) {
        HDF_LOGE("HdfMapperDriverRelease not initted");
        return;
    }

    auto *hdfMapperHost = CONTAINER_OF(deviceObject->service, struct HdfMapperHost, ioService);
    delete hdfMapperHost;
}

static struct HdfDriverEntry g_mapperDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "display_buffer",
    .Bind = HdfMapperDriverBind,
    .Init = HdfMapperDriverInit,
    .Release = HdfMapperDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif
HDF_INIT(g_mapperDriverEntry);
#ifdef __cplusplus
}
#endif
