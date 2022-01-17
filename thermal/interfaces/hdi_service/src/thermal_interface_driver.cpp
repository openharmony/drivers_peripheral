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
#include <hdf_base.h>
#include <osal_mem.h>
#include <hdf_device_desc.h>
#include "thermal_interface_stub.h"

using namespace hdi::thermal::v1_0;

struct HdfThermalInterfaceHost {
    struct IDeviceIoService ioservice;
    void *instance;
};

static int32_t ThermalInterfaceDriverDispatch(struct HdfDeviceIoClient *client, int cmdId,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    struct HdfThermalInterfaceHost *hdfThermalInterfaceHost = CONTAINER_OF(
        client->device->service, struct HdfThermalInterfaceHost, ioservice);
    return ThermalInterfaceServiceOnRemoteRequest(hdfThermalInterfaceHost->instance, cmdId, data, reply);
}

static int HdfThermalInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfThermalInterfaceDriverInit enter");
    return HDF_SUCCESS;
}

static int HdfThermalInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfThermalInterfaceDriverBind enter");

    struct HdfThermalInterfaceHost *hdfThermalInterfaceHost = (struct HdfThermalInterfaceHost *)OsalMemAlloc(
        sizeof(struct HdfThermalInterfaceHost));
    if (hdfThermalInterfaceHost == nullptr) {
        HDF_LOGE("HdfThermalInterfaceDriverBind OsalMemAlloc HdfThermalInterfaceHost failed!");
        return HDF_FAILURE;
    }

    hdfThermalInterfaceHost->ioservice.Dispatch = ThermalInterfaceDriverDispatch;
    hdfThermalInterfaceHost->ioservice.Open = NULL;
    hdfThermalInterfaceHost->ioservice.Release = NULL;
    hdfThermalInterfaceHost->instance = ThermalInterfaceStubInstance();

    deviceObject->service = &hdfThermalInterfaceHost->ioservice;
    return HDF_SUCCESS;
}

static void HdfThermalInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfThermalInterfaceDriverRelease enter");

    struct HdfThermalInterfaceHost *hdfThermalInterfaceHost =
        CONTAINER_OF(deviceObject->service, struct HdfThermalInterfaceHost, ioservice);
    ThermalInterfaceStubRelease(hdfThermalInterfaceHost->instance);
    OsalMemFree(hdfThermalInterfaceHost);
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