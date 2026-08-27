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
#include <v3_0/daudio_manager_stub.h>

#include "daudio_log.h"
#include <shared_mutex>
#undef DH_LOG_TAG
#define DH_LOG_TAG "DAudioManagerDriver"
using namespace OHOS::HDI::DistributedAudio::Audioext::V3_0;

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
        DHLOGE("%{public}s:invalid data sbuf object to dispatch", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (SbufToParcel(reply, &replyParcel) != HDF_SUCCESS) {
        DHLOGE("%{public}s:invalid reply sbuf object to dispatch", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    DHLOGI("DAudioMgrDriverDispatch mutex before.");
    std::shared_lock lock(mutex_);
    DHLOGI("DAudioMgrDriverDispatch mutex after.");
    if (client == nullptr || client->device == nullptr || client->device->service == nullptr) {
        DHLOGE("%{public}s: client or client.device or service is nullptr", __func__);
        return HDF_FAILURE;
    }
    auto *hdfDAudioManagerHost = CONTAINER_OF(client->device->service, struct HdfDAudioManagerHost, ioService);
    if (hdfDAudioManagerHost == NULL || hdfDAudioManagerHost->stub == NULL) {
        DHLOGE("%{public}s:invalid hdfAudioManagerHost", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return hdfDAudioManagerHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

int HdfDAudioManagerDriverInit(struct HdfDeviceObject *deviceObject)
{
    DHLOGI("Hdf daudio manager driver init.");
    HdfDeviceSetClass(deviceObject, DEVICE_CLASS_AUDIO);
    return HDF_SUCCESS;
}

int HdfDAudioManagerDriverBind(struct HdfDeviceObject *deviceObject)
{
    DHLOGI("Hdf daudio manager driver bind.");
    if (deviceObject == nullptr) {
        DHLOGE("%{public}s: deviceObject is nullptr", __func__);
        return HDF_FAILURE;
    }

    auto *hdfDAudioManagerHost = new (std::nothrow) HdfDAudioManagerHost;
    if (hdfDAudioManagerHost == nullptr) {
        DHLOGE("%{public}s: failed to create create HdfDAudioManagerHost object", __func__);
        return HDF_FAILURE;
    }

    hdfDAudioManagerHost->ioService.Dispatch = DAudioManagerDriverDispatch;
    hdfDAudioManagerHost->ioService.Open = NULL;
    hdfDAudioManagerHost->ioService.Release = NULL;

    auto serviceImpl = IDAudioManager::Get("daudio_ext_service", true);
    if (serviceImpl == nullptr) {
        DHLOGE("%{public}s: failed to get of implement service", __func__);
        delete hdfDAudioManagerHost;
        return HDF_FAILURE;
    }

    hdfDAudioManagerHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        IDAudioManager::GetDescriptor());
    if (hdfDAudioManagerHost->stub == nullptr) {
        DHLOGE("%{public}s: failed to get stub object", __func__);
        delete hdfDAudioManagerHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfDAudioManagerHost->ioService;
    return HDF_SUCCESS;
}

void HdfDAudioManagerDriverRelease(struct HdfDeviceObject *deviceObject)
{
    DHLOGI("Hdf daudio manager driver release.");
    if (deviceObject == nullptr || deviceObject->service == nullptr) {
        DHLOGE("HdfDAudioManagerDriverRelease not initted");
        return;
    }
    DHLOGI("HdfDAudioMgrDriverRelease mutex before.");
    std::unique_lock lock(mutex_);
    DHLOGI("HdfDAudioMgrDriverRelease mutex after.");
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
