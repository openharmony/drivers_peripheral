/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#include "v1_0/off_find_interface_stub.h"

#define HDF_LOG_TAG    off_find_interface_driver

using namespace OHOS::HDI::Nearlink::OffFind::V1_0;

struct HdfOffFindInterfaceHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
    HdfOffFindInterfaceHost()
    {
        ioService.object.objectId = 0;
        ioService.Open = nullptr;
        ioService.Release = nullptr;
        ioService.Dispatch = nullptr;
    }
};

static int32_t OffFindInterfaceDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    auto *hdfOffFindInterfaceHost = CONTAINER_OF(client->device->service, struct HdfOffFindInterfaceHost, ioService);

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

    return hdfOffFindInterfaceHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfOffFindInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver init start", __func__);
    return HDF_SUCCESS;
}

static int HdfOffFindInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver bind start", __func__);
    auto *hdfOffFindInterfaceHost = new (std::nothrow) HdfOffFindInterfaceHost;
    if (hdfOffFindInterfaceHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create create HdfOffFindInterfaceHost object", __func__);
        return HDF_FAILURE;
    }

    hdfOffFindInterfaceHost->ioService.Dispatch = OffFindInterfaceDriverDispatch;
    hdfOffFindInterfaceHost->ioService.Open = NULL;
    hdfOffFindInterfaceHost->ioService.Release = NULL;

    auto serviceImpl = OHOS::HDI::Nearlink::OffFind::V1_0::IOffFindInterface::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfOffFindInterfaceHost;
        return HDF_FAILURE;
    }

    hdfOffFindInterfaceHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        OHOS::HDI::Nearlink::OffFind::V1_0::IOffFindInterface::GetDescriptor());
    if (hdfOffFindInterfaceHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfOffFindInterfaceHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfOffFindInterfaceHost->ioService;
    return HDF_SUCCESS;
}

static void HdfOffFindInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: driver release start", __func__);
    if (deviceObject->service == nullptr) {
        return;
    }

    auto *hdfOffFindInterfaceHost = CONTAINER_OF(deviceObject->service, struct HdfOffFindInterfaceHost, ioService);
    if (hdfOffFindInterfaceHost != nullptr) {
        delete hdfOffFindInterfaceHost;
    }
}

struct HdfDriverEntry g_offfindinterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "off_find",
    .Bind = HdfOffFindInterfaceDriverBind,
    .Init = HdfOffFindInterfaceDriverInit,
    .Release = HdfOffFindInterfaceDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_offfindinterfaceDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */