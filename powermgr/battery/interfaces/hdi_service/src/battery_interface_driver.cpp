/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "battery_interface_service.h"

using namespace hdi::battery::v1_0;

struct HdfBatteryInterfaceHost {
    struct IDeviceIoService ioservice;
    BatteryInterfaceService *service;
};

static int32_t BatteryInterfaceDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    struct HdfBatteryInterfaceHost *hdfBatteryInterfaceHost =
        CONTAINER_OF(client->device->service, struct HdfBatteryInterfaceHost, ioservice);

    OHOS::MessageParcel *dataParcel = nullptr;
    OHOS::MessageParcel *replyParcel = nullptr;
    OHOS::MessageOption option;

    (void)SbufToParcel(reply, &replyParcel);
    if (SbufToParcel(data, &dataParcel) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:invalid data sbuf object to dispatch", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return hdfBatteryInterfaceHost->service->OnRemoteRequest(cmdId, *dataParcel, *replyParcel, option);
}

int HdfBatteryInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfBatteryInterfaceDriverInit enter");
    return HDF_SUCCESS;
}

int HdfBatteryInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfBatteryInterfaceDriverBind enter");

    struct HdfBatteryInterfaceHost *hdfBatteryInterfaceHost = (struct HdfBatteryInterfaceHost *)OsalMemAlloc(
        sizeof(struct HdfBatteryInterfaceHost));
    if (hdfBatteryInterfaceHost == nullptr) {
        HDF_LOGE("HdfBatteryInterfaceDriverBind OsalMemAlloc HdfBatteryInterfaceHost failed!");
        return HDF_FAILURE;
    }

    hdfBatteryInterfaceHost->ioservice.Dispatch = BatteryInterfaceDriverDispatch;
    hdfBatteryInterfaceHost->ioservice.Open = NULL;
    hdfBatteryInterfaceHost->ioservice.Release = NULL;
    hdfBatteryInterfaceHost->service = new BatteryInterfaceService();

    deviceObject->service = &hdfBatteryInterfaceHost->ioservice;
    return HDF_SUCCESS;
}

void HdfBatteryInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfBatteryInterfaceDriverRelease enter");

    struct HdfBatteryInterfaceHost *hdfBatteryInterfaceHost = CONTAINER_OF(deviceObject->service,
        struct HdfBatteryInterfaceHost, ioservice);
    delete hdfBatteryInterfaceHost->service;
    OsalMemFree(hdfBatteryInterfaceHost);
}

struct HdfDriverEntry g_batteryinterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "battery_interface_service",
    .Bind = HdfBatteryInterfaceDriverBind,
    .Init = HdfBatteryInterfaceDriverInit,
    .Release = HdfBatteryInterfaceDriverRelease,
};

#ifndef __cplusplus
extern "C" {
#endif
HDF_INIT(g_batteryinterfaceDriverEntry);
#ifndef __cplusplus
}
#endif
