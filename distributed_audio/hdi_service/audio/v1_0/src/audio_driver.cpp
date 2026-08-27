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
#include <hdf_sbuf_ipc.h>
#include <v2_0/audio_manager_stub.h>

#include "daudio_log.h"
#include "audio_manager_interface_impl.h"
#include <shared_mutex>

#undef DH_LOG_TAG
#define DH_LOG_TAG "AudioDriver"

using namespace OHOS::HDI::DistributedAudio::Audio::V2_0;

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
        DHLOGE("%{public}s:invalid data sbuf object to dispatch", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (SbufToParcel(reply, &replyParcel) != HDF_SUCCESS) {
        DHLOGE("%{public}s:invalid reply sbuf object to dispatch", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    DHLOGI("AudioMgrDriverDispatch mutex before.");
    std::shared_lock lock(mutex_);
    DHLOGI("AudioMgrDriverDispatch mutex after.");
    if (client == nullptr || client->device == nullptr || client->device->service == nullptr) {
        DHLOGE("%{public}s: client or client.device or service is nullptr", __func__);
        return HDF_FAILURE;
    }
    auto *hdfAudioManagerHost = CONTAINER_OF(client->device->service, struct HdfAudioManagerHost, ioService);
    if (hdfAudioManagerHost == NULL || hdfAudioManagerHost->stub == NULL) {
        DHLOGE("%{public}s:invalid hdfAudioManagerHost", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return hdfAudioManagerHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

int HdfAudioManagerDriverInit(struct HdfDeviceObject *deviceObject)
{
    DHLOGI("Hdf audio manager driver init.");
    AudioManagerInterfaceImpl::GetAudioManager()->SetDeviceObject(deviceObject);
    HdfDeviceSetClass(deviceObject, DEVICE_CLASS_AUDIO);
    return HDF_SUCCESS;
}

int HdfAudioManagerDriverBind(struct HdfDeviceObject *deviceObject)
{
    DHLOGI("Hdf audio manager driver bind.");

    if (deviceObject == nullptr) {
        DHLOGE("%{public}s: deviceObject is nullptr", __func__);
        return HDF_FAILURE;
    }

    auto *hdfAudioManagerHost = new (std::nothrow) HdfAudioManagerHost;
    if (hdfAudioManagerHost == nullptr) {
        DHLOGE("%{public}s: failed to create create HdfAudioManagerHost object", __func__);
        return HDF_FAILURE;
    }

    hdfAudioManagerHost->ioService.Dispatch = AudioManagerDriverDispatch;
    hdfAudioManagerHost->ioService.Open = NULL;
    hdfAudioManagerHost->ioService.Release = NULL;

    auto serviceImpl = IAudioManager::Get("daudio_primary_service", true);
    if (serviceImpl == nullptr) {
        DHLOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfAudioManagerHost;
        hdfAudioManagerHost = nullptr;
        return HDF_FAILURE;
    }

    hdfAudioManagerHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        IAudioManager::GetDescriptor());
    if (hdfAudioManagerHost->stub == nullptr) {
        DHLOGE("%{public}s: failed to get stub object", __func__);
        delete hdfAudioManagerHost;
        hdfAudioManagerHost = nullptr;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfAudioManagerHost->ioService;
    return HDF_SUCCESS;
}

void HdfAudioManagerDriverRelease(struct HdfDeviceObject *deviceObject)
{
    DHLOGI("Hdf audio manager driver release.");
    if (deviceObject == nullptr || deviceObject->service == nullptr) {
        DHLOGE("%{public}s: deviceObject or service is nullptr", __func__);
        return;
    }
    DHLOGI("HdfAudioMgrDriverRelease mutex before.");
    std::unique_lock lock(mutex_);
    DHLOGI("HdfAudioMgrDriverRelease mutex after.");
    auto *hdfAudioManagerHost = CONTAINER_OF(deviceObject->service, struct HdfAudioManagerHost, ioService);
    if (hdfAudioManagerHost != nullptr) {
        hdfAudioManagerHost->stub = nullptr;
    }
    delete hdfAudioManagerHost;
    hdfAudioManagerHost = nullptr;
    if (deviceObject != nullptr) {
        deviceObject->service = nullptr;
    }
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
