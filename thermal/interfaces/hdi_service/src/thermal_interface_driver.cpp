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
#include <osal_mem.h>
#include "v1_0/thermal_interface_stub.h"

#define HDF_LOG_TAG ThermalInterfaceDriver

using namespace OHOS::HDI::Thermal::V1_0;

struct HdfThermalInterfaceHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t ThermalInterfaceDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    auto *hdfThermalInterfaceHost = CONTAINER_OF(client->device->service, struct HdfThermalInterfaceHost, ioService);

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

    return hdfThermalInterfaceHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

int HdfThermalInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfThermalInterfaceDriverInit enter");
    return HDF_SUCCESS;
}

int HdfThermalInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfThermalInterfaceDriverBind enter");

    auto *hdfThermalInterfaceHost = new (std::nothrow) HdfThermalInterfaceHost;
    if (hdfThermalInterfaceHost == nullptr) {
        HDF_LOGE("%{public}s failed to create HdfThermalInterfaceHost object", __func__);
        return HDF_FAILURE;
    }

    hdfThermalInterfaceHost->ioService.Dispatch = ThermalInterfaceDriverDispatch;
    hdfThermalInterfaceHost->ioService.Open = NULL;
    hdfThermalInterfaceHost->ioService.Release = NULL;

    auto serviceImpl = IThermalInterface::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        return HDF_FAILURE;
    }

    hdfThermalInterfaceHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        IThermalInterface::GetDescriptor());
    if (hdfThermalInterfaceHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfThermalInterfaceHost->ioService;
    return HDF_SUCCESS;
}

void HdfThermalInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfThermalInterfaceDriverRelease enter");
    auto *hdfThermalInterfaceHost = CONTAINER_OF(deviceObject->service, struct HdfThermalInterfaceHost, ioService);
    delete hdfThermalInterfaceHost;
}

struct HdfDriverEntry g_thermalinterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "thermal_interface_service",
    .Bind = HdfThermalInterfaceDriverBind,
    .Init = HdfThermalInterfaceDriverInit,
    .Release = HdfThermalInterfaceDriverRelease,
};

#ifndef __cplusplus
extern "C" {
#endif
HDF_INIT(g_thermalinterfaceDriverEntry);
#ifndef __cplusplus
}
#endif