/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "dcamera_host.h"
#include "v1_3/camera_host_stub.h"

#include <shared_mutex>
using namespace OHOS::HDI::Camera::V1_3;

namespace {
    std::shared_mutex mutex_;
}

struct HdfCameraHostHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t CameraHostDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
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

    std::shared_lock lock(mutex_);
    if (client == nullptr || client->device == nullptr || client->device->service == nullptr) {
        HDF_LOGE("%{public}s: client or client.device or service is nullptr", __func__);
        return HDF_FAILURE;
    }
    auto *hdfCameraHostHost = CONTAINER_OF(client->device->service, struct HdfCameraHostHost, ioService);
    if (hdfCameraHostHost == NULL || hdfCameraHostHost->stub == NULL) {
        HDF_LOGE("%{public}s:invalid hdfCameraHostHost", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return hdfCameraHostHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfCameraHostDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfCameraHostDriverInit enter");
    if (deviceObject == nullptr) {
        HDF_LOGE("HdfCameraHostDriverInit:: HdfDeviceObject is NULL !");
        return HDF_FAILURE;
    }

    if (!HdfDeviceSetClass(deviceObject, DEVICE_CLASS_CAMERA)) {
        HDF_LOGE("HdfCameraHostDriverInit set camera class failed");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int HdfCameraHostDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfCameraHostDriverBind enter");

    auto *hdfCameraHostHost = new (std::nothrow) HdfCameraHostHost;
    if (hdfCameraHostHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create create HdfCameraHostHost object", __func__);
        return HDF_FAILURE;
    }

    hdfCameraHostHost->ioService.Dispatch = CameraHostDriverDispatch;
    hdfCameraHostHost->ioService.Open = NULL;
    hdfCameraHostHost->ioService.Release = NULL;

    auto serviceImpl = OHOS::DistributedHardware::DCameraHost::GetInstance();
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfCameraHostHost;
        return HDF_FAILURE;
    }

    hdfCameraHostHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        HDI::Camera::V1_3::ICameraHost::GetDescriptor());
    if (hdfCameraHostHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfCameraHostHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfCameraHostHost->ioService;
    return HDF_SUCCESS;
}

static void HdfCameraHostDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("HdfCameraHostDriverRelease enter");
    if (deviceObject == nullptr || deviceObject->service == nullptr) {
        HDF_LOGE("HdfCameraHostDriverRelease not initted");
        return;
    }

    std::unique_lock lock(mutex_);
    auto *hdfCameraHostHost = CONTAINER_OF(deviceObject->service, struct HdfCameraHostHost, ioService);
    if (hdfCameraHostHost != nullptr) {
        hdfCameraHostHost->stub = nullptr;
    }
    delete hdfCameraHostHost;
    hdfCameraHostHost = nullptr;
    if (deviceObject != nullptr) {
        deviceObject->service = nullptr;
    }
}

static struct HdfDriverEntry g_camerahostDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "distributed_camera_service",
    .Bind = HdfCameraHostDriverBind,
    .Init = HdfCameraHostDriverInit,
    .Release = HdfCameraHostDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

HDF_INIT(g_camerahostDriverEntry);

#ifdef __cplusplus
}
#endif /* __cplusplus */
