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
#include <v1_0/audio_manager_stub.h>

#include "audio_manager_interface_impl.h"
#include <shared_mutex>

using namespace OHOS::HDI::DistributedAudio::Audio::V1_0;

namespace {
    std::shared_mutex mutex_;
}

struct HdfAudioManagerHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t AudioManagerDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
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
    auto *hdfAudioManagerHost = CONTAINER_OF(client->device->service, struct HdfAudioManagerHost, ioService);
    if (hdfAudioManagerHost == NULL) {
        HDF_LOGE("%{public}s:invalid hdfAudioManagerHost", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return hdfAudioManagerHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

int HdfAudioManagerDriverInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("Hdf audio manager driver init.");
    AudioManagerInterfaceImpl::GetAudioManager()->SetDeviceObject(deviceObject);
    HdfDeviceSetClass(deviceObject, DEVICE_CLASS_AUDIO);
    return HDF_SUCCESS;
}

int HdfAudioManagerDriverBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("Hdf audio manager driver bind.");

    auto *hdfAudioManagerHost = new (std::nothrow) HdfAudioManagerHost;
    if (hdfAudioManagerHost == nullptr) {
        HDF_LOGE("%{public}s: failed to create create HdfAudioManagerHost object", __func__);
        return HDF_FAILURE;
    }

    hdfAudioManagerHost->ioService.Dispatch = AudioManagerDriverDispatch;
    hdfAudioManagerHost->ioService.Open = NULL;
    hdfAudioManagerHost->ioService.Release = NULL;

    auto serviceImpl = IAudioManager::Get("daudio_primary_service", true);
    if (serviceImpl == nullptr) {
        HDF_LOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfAudioManagerHost;
        return HDF_FAILURE;
    }

    hdfAudioManagerHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        IAudioManager::GetDescriptor());
    if (hdfAudioManagerHost->stub == nullptr) {
        HDF_LOGE("%{public}s: failed to get stub object", __func__);
        delete hdfAudioManagerHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfAudioManagerHost->ioService;
    return HDF_SUCCESS;
}

void HdfAudioManagerDriverRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("Hdf audio manager driver release.");
    std::unique_lock lock(mutex_);
    auto *hdfAudioManagerHost = CONTAINER_OF(deviceObject->service, struct HdfAudioManagerHost, ioService);
    delete hdfAudioManagerHost;
}

struct HdfDriverEntry g_audiomanagerDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "daudio",
    .Bind = HdfAudioManagerDriverBind,
    .Init = HdfAudioManagerDriverInit,
    .Release = HdfAudioManagerDriverRelease,
};

#ifndef __cplusplus
extern "C" {
#endif
HDF_INIT(g_audiomanagerDriverEntry);
#ifndef __cplusplus
}
#endif
