/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "sensor_uhdf_log.h"
#include <hdf_sbuf_ipc.h>
#include <osal_mem.h>
#include "sensor_if.h"
#include "v3_0/sensor_interface_stub.h"

#define HDF_LOG_TAG    uhdf_sensor_service

using namespace OHOS::HDI::Sensor::V3_0;

struct HdfSensorInterfaceHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t SensorInterfaceDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    auto *hdfSensorInterfaceHost = CONTAINER_OF(client->device->service, struct HdfSensorInterfaceHost, ioService);

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

    return hdfSensorInterfaceHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int32_t HdfSensorInterfaceDriverInit(struct HdfDeviceObject *deviceObject)
{
    (void)deviceObject;
    HDF_LOGI("HdfSensorInterfaceDriverInit enter");
    return HDF_SUCCESS;
}

static int32_t HdfSensorInterfaceDriverBind(struct HdfDeviceObject *deviceObject)
{
    auto *hdfSensorInterfaceHost = new (std::nothrow) HdfSensorInterfaceHost;
    if (hdfSensorInterfaceHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create HdfSensorInterfaceHost object", __func__);
        return HDF_FAILURE;
    }

    hdfSensorInterfaceHost->ioService.Dispatch = SensorInterfaceDriverDispatch;
    hdfSensorInterfaceHost->ioService.Open = nullptr;
    hdfSensorInterfaceHost->ioService.Release = nullptr;

    auto serviceImpl = OHOS::HDI::Sensor::V3_0::ISensorInterface::Get(true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfSensorInterfaceHost;
        return HDF_FAILURE;
    }

    hdfSensorInterfaceHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        OHOS::HDI::Sensor::V3_0::ISensorInterface::GetDescriptor());
    if (hdfSensorInterfaceHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfSensorInterfaceHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfSensorInterfaceHost->ioService;
    HDF_LOGI("HdfSensorInterfaceDriverBind Success");
    return HDF_SUCCESS;
}

static void HdfSensorInterfaceDriverRelease(struct HdfDeviceObject *deviceObject)
{
    if (deviceObject->service == nullptr) {
        HDF_LOGE("HdfSensorInterfaceDriverRelease not initted");
        return;
    }

    auto *hdfSensorInterfaceHost = CONTAINER_OF(deviceObject->service, struct HdfSensorInterfaceHost, ioService);
    delete hdfSensorInterfaceHost;
    HDF_LOGI("HdfSensorInterfaceDriverRelease Success");
}

static struct HdfDriverEntry g_sensorinterfaceDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "sensor_service",
    .Bind = HdfSensorInterfaceDriverBind,
    .Init = HdfSensorInterfaceDriverInit,
    .Release = HdfSensorInterfaceDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_sensorinterfaceDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
