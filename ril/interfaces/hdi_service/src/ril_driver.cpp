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

#include <hdf_log.h>

#include "hdf_base.h"
#include "hdf_device_desc.h"
#include "hdf_sbuf_ipc.h"
#include "v1_5/ril_stub.h"
#include "hril_hdf.h"

using namespace OHOS::HDI::Ril::V1_5;
using namespace OHOS::HDI::Ril;

struct HdfRilHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t RilDriverDispatch(
    struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    auto *hdfRilHost = CONTAINER_OF(client->device->service, struct HdfRilHost, ioService);

    OHOS::MessageParcel *dataParcel = nullptr;
    OHOS::MessageParcel *replyParcel = nullptr;
    OHOS::MessageOption option;

    if (SbufToParcel(data, &dataParcel) != HDF_SUCCESS) {
        HDF_LOGE("invalid data sbuf object to dispatch");
        return HDF_ERR_INVALID_PARAM;
    }
    if (SbufToParcel(reply, &replyParcel) != HDF_SUCCESS) {
        HDF_LOGE("invalid reply sbuf object to dispatch");
        return HDF_ERR_INVALID_PARAM;
    }
    int ret = hdfRilHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
    return ret;
}

static int32_t HdfRilDriverInit(struct HdfDeviceObject *deviceObject)
{
    InitRilAdapter();
    return HDF_SUCCESS;
}

static int32_t HdfRilDriverBind(struct HdfDeviceObject *deviceObject)
{
    auto *hdfRilHost = new (std::nothrow) HdfRilHost;
    if (hdfRilHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create HdfRilHost object", __func__);
        return HDF_FAILURE;
    }

    hdfRilHost->ioService.Dispatch = RilDriverDispatch;
    hdfRilHost->ioService.Open = nullptr;
    hdfRilHost->ioService.Release = nullptr;

    auto serviceImpl = V1_5::IRil::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfRilHost;
        hdfRilHost = nullptr;
        return HDF_FAILURE;
    }

    hdfRilHost->stub =
        OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl, V1_5::IRil::GetDescriptor());
    if (hdfRilHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfRilHost;
        hdfRilHost = nullptr;
        return HDF_FAILURE;
    }

    if (deviceObject == nullptr) {
        HDF_LOGE("%{public}s: failed to get device object", __func__);
        delete hdfRilHost;
        hdfRilHost = nullptr;
        return HDF_FAILURE;
    }
    deviceObject->service = &hdfRilHost->ioService;
    return HDF_SUCCESS;
}

static void HdfRilDriverRelease(struct HdfDeviceObject *deviceObject)
{
    if (deviceObject == nullptr || deviceObject->service == nullptr) {
        HDF_LOGE("HdfRilDriverRelease not initted");
        return;
    }
    ReleaseRilAdapter();
    auto *hdfRilHost = CONTAINER_OF(deviceObject->service, struct HdfRilHost, ioService);
    delete hdfRilHost;
}

static struct HdfDriverEntry g_RilDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "ril_service",
    .Bind = HdfRilDriverBind,
    .Init = HdfRilDriverInit,
    .Release = HdfRilDriverRelease,
};

#ifndef __cplusplus
extern "C" {
#endif
HDF_INIT(g_RilDriverEntry);
#ifndef __cplusplus
}
#endif