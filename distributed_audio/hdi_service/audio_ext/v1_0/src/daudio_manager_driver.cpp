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
#include <v2_1/daudio_manager_stub.h>

#include <shared_mutex>
using namespace OHOS::HDI::DistributedAudio::Audioext::V2_1;

namespace {
    std::shared_mutex mutex_;
}

struct HdfDAudioManagerHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t DAudioManagerDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
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
    auto *hdfDAudioManagerHost = CONTAINER_OF(client->device->service, struct HdfDAudioManagerHost, ioService);
    if (hdfDAudioManagerHost == NULL || hdfDAudioManagerHost->stub == NULL) {
        HDF_LOGE("%{public}s:invalid hdfAudioManagerHost", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return hdfDAudioManagerHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

int HdfDAudioManagerDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("Hdf daudio manager driver init.");
    HdfDeviceSetClass(deviceObject, DEVICE_CLASS_AUDIO);
    return HDF_SUCCESS;
}

int HdfDAudioManagerDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("Hdf daudio manager driver bind.");
    if (deviceObject == nullptr) {
        HDF_LOGE("%{public}s: deviceObject is nullptr", __func__);
        return HDF_FAILURE;
    }

    auto *hdfDAudioManagerHost = new (std::nothrow) HdfDAudioManagerHost;
    if (hdfDAudioManagerHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create create HdfDAudioManagerHost object", __func__);
        return HDF_FAILURE;
    }

    hdfDAudioManagerHost->ioService.Dispatch = DAudioManagerDriverDispatch;
    hdfDAudioManagerHost->ioService.Open = NULL;
    hdfDAudioManagerHost->ioService.Release = NULL;

    auto serviceImpl = IDAudioManager::Get("daudio_ext_service", true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfDAudioManagerHost;
        return HDF_FAILURE;
    }

    hdfDAudioManagerHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        IDAudioManager::GetDescriptor());
    if (hdfDAudioManagerHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfDAudioManagerHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfDAudioManagerHost->ioService;
    return HDF_SUCCESS;
}

void HdfDAudioManagerDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("Hdf daudio manager driver release.");
    if (deviceObject == nullptr || deviceObject->service == nullptr) {
        HDF_LOGE("HdfDAudioManagerDriverRelease not initted");
        return;
    }

    std::unique_lock lock(mutex_);
    auto *hdfDAudioManagerHost = CONTAINER_OF(deviceObject->service, struct HdfDAudioManagerHost, ioService);
    if (hdfDAudioManagerHost != nullptr) {
        hdfDAudioManagerHost->stub = nullptr;
    }
    delete hdfDAudioManagerHost;
    hdfDAudioManagerHost = nullptr;
    if (deviceObject != nullptr) {
        deviceObject->service = nullptr;
    }
}

struct HdfDriverEntry g_daudiomanagerDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "daudioext",
    .Bind = HdfDAudioManagerDriverBind,
    .Init = HdfDAudioManagerDriverInit,
    .Release = HdfDAudioManagerDriverRelease,
};

#ifndef __cplusplus
extern "C" {
#endif
HDF_INIT(g_daudiomanagerDriverEntry);
#ifndef __cplusplus
}
#endif
