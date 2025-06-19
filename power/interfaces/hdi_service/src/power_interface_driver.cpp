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
#include "v1_3/power_interface_stub.h"

#define HDF_LOG_TAG PowerInterfaceDriver

using namespace OHOS::HDI::Power;
using namespace OHOS::HDI::Power::V1_2;

namespace {
struct HdfPowerInterfaceHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};
}

static int32_t PowerInterfaceDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    auto *hdfPowerInterfaceHost = CONTAINER_OF(client->device->service, struct HdfPowerInterfaceHost, ioService);

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

    return hdfPowerInterfaceHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfPowerInterfaceDriverInit([[maybe_unused]] struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfPowerInterfaceDriverInit enter");
    return HDF_SUCCESS;
}

static int HdfPowerInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfPowerInterfaceDriverBind enter");

    auto *hdfPowerInterfaceHost = new (std::nothrow) HdfPowerInterfaceHost;
    if (hdfPowerInterfaceHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create HdfPowerInterfaceHost object", __func__);
        return HDF_FAILURE;
    }

    hdfPowerInterfaceHost->ioService.Dispatch = PowerInterfaceDriverDispatch;
    hdfPowerInterfaceHost->ioService.Open = NULL;
    hdfPowerInterfaceHost->ioService.Release = NULL;

    auto serviceImpl = V1_3::IPowerInterface::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfPowerInterfaceHost;
        return HDF_FAILURE;
    }

    hdfPowerInterfaceHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        V1_3::IPowerInterface::GetDescriptor());
    if (hdfPowerInterfaceHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfPowerInterfaceHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfPowerInterfaceHost->ioService;
    return HDF_SUCCESS;
}

static void HdfPowerInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfPowerInterfaceDriverRelease enter");
    if (deviceObject->service == nullptr) {
        HDF_LOGE("HdfPowerInterfaceDriverRelease not initted");
        return;
    }

    auto *hdfPowerInterfaceHost = CONTAINER_OF(deviceObject->service, struct HdfPowerInterfaceHost, ioService);
    delete hdfPowerInterfaceHost;
}

static struct HdfDriverEntry g_powerinterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "power_interface_service",
    .Bind = HdfPowerInterfaceDriverBind,
    .Init = HdfPowerInterfaceDriverInit,
    .Release = HdfPowerInterfaceDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_powerinterfaceDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
