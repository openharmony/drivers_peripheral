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
#include "v1_0/geofence_interface_stub.h"

using namespace OHOS::HDI::Location::Geofence::V1_0;

struct HdfGeofenceInterfaceHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;

    HdfGeofenceInterfaceHost()
    {
        ioService.object.objectId = 0;
        ioService.Open = nullptr;
        ioService.Release = nullptr;
        ioService.Dispatch = nullptr;
    }
};

static int32_t GeofenceInterfaceDriverDispatch(struct HdfDeviceIoClient *client,
    int cmdId, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    auto *hdfGeofenceInterfaceHost = CONTAINER_OF(client->device->service, struct HdfGeofenceInterfaceHost, ioService);

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

    return hdfGeofenceInterfaceHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfGeofenceInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfGeofenceInterfaceDriverInit enter");
    return HDF_SUCCESS;
}

static int HdfGeofenceInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfGeofenceInterfaceDriverBind enter");

    auto *hdfGeofenceInterfaceHost = new (std::nothrow) HdfGeofenceInterfaceHost;
    if (hdfGeofenceInterfaceHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create create HdfGeofenceInterfaceHost object", __func__);
        return HDF_FAILURE;
    }

    hdfGeofenceInterfaceHost->ioService.Dispatch = GeofenceInterfaceDriverDispatch;

    auto serviceImpl = IGeofenceInterface::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfGeofenceInterfaceHost;
        return HDF_FAILURE;
    }

    hdfGeofenceInterfaceHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        IGeofenceInterface::GetDescriptor());
    if (hdfGeofenceInterfaceHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfGeofenceInterfaceHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfGeofenceInterfaceHost->ioService;
    return HDF_SUCCESS;
}

static void HdfGeofenceInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfGeofenceInterfaceDriverRelease enter");
    if (deviceObject->service == nullptr) {
        HDF_LOGE("HdfGeofenceInterfaceDriverRelease not initted");
        return;
    }

    auto *hdfGeofenceInterfaceHost = CONTAINER_OF(deviceObject->service, struct HdfGeofenceInterfaceHost, ioService);
    delete hdfGeofenceInterfaceHost;
    deviceObject->service = nullptr;
}

static struct HdfDriverEntry g_geofenceinterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "location_geofence",
    .Bind = HdfGeofenceInterfaceDriverBind,
    .Init = HdfGeofenceInterfaceDriverInit,
    .Release = HdfGeofenceInterfaceDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_geofenceinterfaceDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
