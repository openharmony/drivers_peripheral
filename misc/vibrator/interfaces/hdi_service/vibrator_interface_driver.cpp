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
#include "vibrator_interface_stub.h"

using namespace vibrator::v1_0;

struct HdfVibratorInterfaceHost {
    struct IDeviceIoService ioservice;
    void *instance;
};

static int32_t VibratorInterfaceDriverDispatch(struct HdfDeviceIoClient *client, int cmdId,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    struct HdfVibratorInterfaceHost *hdfVibratorInterfaceHost = CONTAINER_OF(
        client->device->service, struct HdfVibratorInterfaceHost, ioservice);
    return VibratorInterfaceServiceOnRemoteRequest(hdfVibratorInterfaceHost->instance, cmdId, data, reply);
}

static int HdfVibratorInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfVibratorInterfaceDriverInit enter");
    return HDF_SUCCESS;
}

static int HdfVibratorInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    struct HdfVibratorInterfaceHost *hdfVibratorInterfaceHost = (struct HdfVibratorInterfaceHost *)OsalMemAlloc(
        sizeof(struct HdfVibratorInterfaceHost));
    if (hdfVibratorInterfaceHost == nullptr) {
        HDF_LOGE("HdfVibratorInterfaceDriverBind OsalMemAlloc HdfVibratorInterfaceHost failed!");
        return HDF_FAILURE;
    }

    hdfVibratorInterfaceHost->ioservice.Dispatch = VibratorInterfaceDriverDispatch;
    hdfVibratorInterfaceHost->ioservice.Open = NULL;
    hdfVibratorInterfaceHost->ioservice.Release = NULL;
    hdfVibratorInterfaceHost->instance = VibratorInterfaceStubInstance();

    deviceObject->service = &hdfVibratorInterfaceHost->ioservice;

    HDF_LOGI("HdfVibratorInterfaceDriverBind Success");
    return HDF_SUCCESS;
}

static void HdfVibratorInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    struct HdfVibratorInterfaceHost *hdfVibratorInterfaceHost =
        CONTAINER_OF(deviceObject->service, struct HdfVibratorInterfaceHost, ioservice);
    VibratorInterfaceStubRelease(hdfVibratorInterfaceHost->instance);
    OsalMemFree(hdfVibratorInterfaceHost);
    HDF_LOGI("HdfSensorInterfaceDriverRelease Success");
}

struct HdfDriverEntry g_vibratorInterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "vibrator_service",
    .Bind = HdfVibratorInterfaceDriverBind,
    .Init = HdfVibratorInterfaceDriverInit,
    .Release = HdfVibratorInterfaceDriverRelease,
};

#ifndef __cplusplus
extern "C" {
#endif
HDF_INIT(g_vibratorInterfaceDriverEntry);
#ifndef __cplusplus
}
#endif
