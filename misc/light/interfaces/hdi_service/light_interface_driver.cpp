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
#include <osal_mem.h>
#include "light_interface_stub.h"

using namespace light::v1_0;

struct HdfLightInterfaceHost {
    struct IDeviceIoService ioservice;
    void *instance;
};

static int32_t LightInterfaceDriverDispatch(struct HdfDeviceIoClient *client, int cmdId,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    struct HdfLightInterfaceHost *hdfLightInterfaceHost = CONTAINER_OF(
        client->device->service, struct HdfLightInterfaceHost, ioservice);
    return LightInterfaceServiceOnRemoteRequest(hdfLightInterfaceHost->instance, cmdId, data, reply);
}

static int HdfLightInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfLightInterfaceDriverInit enter");
    return HDF_SUCCESS;
}

static int HdfLightInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    struct HdfLightInterfaceHost *hdfLightInterfaceHost = (struct HdfLightInterfaceHost *)OsalMemAlloc(
        sizeof(struct HdfLightInterfaceHost));
    if (hdfLightInterfaceHost == nullptr) {
        HDF_LOGE("HdfLightInterfaceDriverBind OsalMemAlloc HdfLightInterfaceHost failed!");
        return HDF_FAILURE;
    }

    hdfLightInterfaceHost->ioservice.Dispatch = LightInterfaceDriverDispatch;
    hdfLightInterfaceHost->ioservice.Open = nullptr;
    hdfLightInterfaceHost->ioservice.Release = nullptr;
    hdfLightInterfaceHost->instance = LightInterfaceStubInstance();

    deviceObject->service = &hdfLightInterfaceHost->ioservice;
    HDF_LOGI("HdfLightInterfaceDriverBind success");
    return HDF_SUCCESS;
}

static void HdfLightInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    struct HdfLightInterfaceHost *hdfLightInterfaceHost =
        CONTAINER_OF(deviceObject->service, struct HdfLightInterfaceHost, ioservice);
    LightInterfaceStubRelease(hdfLightInterfaceHost->instance);
    OsalMemFree(hdfLightInterfaceHost);
    hdfLightInterfaceHost = nullptr;
    HDF_LOGI("HdfLightInterfaceDriverRelease success");
}

struct HdfDriverEntry g_lightinterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "light_service",
    .Bind = HdfLightInterfaceDriverBind,
    .Init = HdfLightInterfaceDriverInit,
    .Release = HdfLightInterfaceDriverRelease,
};

#ifndef __cplusplus
extern "C" {
#endif
HDF_INIT(g_lightinterfaceDriverEntry);
#ifndef __cplusplus
}
#endif
