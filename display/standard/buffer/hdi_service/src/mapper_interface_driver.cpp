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
#include "v1_0/mapper_interface_stub.h"

using namespace OHOS::HDI::Display::Buffer::V1_0;

struct HdfMapperInterfaceHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t MapperInterfaceDriverDispatch(
    struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    auto *hdfMapperInterfaceHost = CONTAINER_OF(client->device->service, struct HdfMapperInterfaceHost, ioService);

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

    return hdfMapperInterfaceHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfMapperInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    (void)deviceObject;
    HDF_LOGI("HdfMapperInterfaceDriverInit enter");
    return HDF_SUCCESS;
}

static int HdfMapperInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfMapperInterfaceDriverBind enter");

    auto *hdfMapperInterfaceHost = new (std::nothrow) HdfMapperInterfaceHost;
    if (hdfMapperInterfaceHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create create HdfMapperInterfaceHost object", __func__);
        return HDF_FAILURE;
    }

    hdfMapperInterfaceHost->ioService.Dispatch = MapperInterfaceDriverDispatch;
    hdfMapperInterfaceHost->ioService.Open = NULL;
    hdfMapperInterfaceHost->ioService.Release = NULL;

    auto serviceImpl = IMapperInterface::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfMapperInterfaceHost;
        return HDF_FAILURE;
    }

    hdfMapperInterfaceHost->stub =
        OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl, IMapperInterface::GetDescriptor());
    if (hdfMapperInterfaceHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfMapperInterfaceHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfMapperInterfaceHost->ioService;
    return HDF_SUCCESS;
}

static void HdfMapperInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfMapperInterfaceDriverRelease enter");
    if (deviceObject->service == nullptr) {
        HDF_LOGE("HdfMapperInterfaceDriverRelease not initted");
        return;
    }

    auto *hdfMapperInterfaceHost = CONTAINER_OF(deviceObject->service, struct HdfMapperInterfaceHost, ioService);
    delete hdfMapperInterfaceHost;
}

static struct HdfDriverEntry g_mapperinterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "display_buffer",
    .Bind = HdfMapperInterfaceDriverBind,
    .Init = HdfMapperInterfaceDriverInit,
    .Release = HdfMapperInterfaceDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif
HDF_INIT(g_mapperinterfaceDriverEntry);
#ifdef __cplusplus
}
#endif