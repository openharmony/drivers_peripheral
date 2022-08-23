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
#include "v1_0/ril_interface_stub.h"
#include "hril_hdf.h"

using namespace OHOS::HDI::Ril::V1_0;
using namespace OHOS::HDI::Ril;

struct HdfRilInterfaceHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t RilInterfaceDriverDispatch(
    struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    auto *hdfRilInterfaceHost = CONTAINER_OF(client->device->service, struct HdfRilInterfaceHost, ioService);

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
    int ret = hdfRilInterfaceHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
    return ret;
}

static int32_t HdfRilInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    InitRilAdapter();
    return HDF_SUCCESS;
}

static int32_t HdfRilInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    auto *hdfRilInterfaceHost = new (std::nothrow) HdfRilInterfaceHost;
    if (hdfRilInterfaceHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create HdfRilInterfaceHost object", __func__);
        return HDF_FAILURE;
    }

    hdfRilInterfaceHost->ioService.Dispatch = RilInterfaceDriverDispatch;
    hdfRilInterfaceHost->ioService.Open = nullptr;
    hdfRilInterfaceHost->ioService.Release = nullptr;

    auto serviceImpl = IRilInterface::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfRilInterfaceHost;
        hdfRilInterfaceHost = nullptr;
        return HDF_FAILURE;
    }

    hdfRilInterfaceHost->stub =
        OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl, IRilInterface::GetDescriptor());
    if (hdfRilInterfaceHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfRilInterfaceHost;
        hdfRilInterfaceHost = nullptr;
        return HDF_FAILURE;
    }

    if (deviceObject == nullptr) {
        HDF_LOGE("%{public}s: failed to get device object", __func__);
        delete hdfRilInterfaceHost;
        hdfRilInterfaceHost = nullptr;
        return HDF_FAILURE;
    }
    deviceObject->service = &hdfRilInterfaceHost->ioService;
    return HDF_SUCCESS;
}

static void HdfRilInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    if (deviceObject == nullptr || deviceObject->service == nullptr) {
        HDF_LOGE("HdfRilInterfaceDriverRelease not initted");
        return;
    }

    auto *hdfRilInterfaceHost = CONTAINER_OF(deviceObject->service, struct HdfRilInterfaceHost, ioService);
    delete hdfRilInterfaceHost;
}

static struct HdfDriverEntry g_RilInterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "ril_interface_service",
    .Bind = HdfRilInterfaceDriverBind,
    .Init = HdfRilInterfaceDriverInit,
    .Release = HdfRilInterfaceDriverRelease,
};

#ifndef __cplusplus
extern "C" {
#endif
HDF_INIT(g_RilInterfaceDriverEntry);
#ifndef __cplusplus
}
#endif