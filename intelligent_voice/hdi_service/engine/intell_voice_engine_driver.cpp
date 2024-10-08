/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <shared_mutex>
#include <hdf_base.h>
#include <hdf_device_desc.h>
#include "intell_voice_log.h"
#include <hdf_sbuf_ipc.h>
#include "v1_2/intell_voice_engine_manager_stub.h"

#undef HDF_LOG_TAG
#define HDF_LOG_TAG "IntellVoiceEngineDriver"

namespace {
    static std::shared_mutex g_engineMgrMutex;
}

struct HdfIntellVoiceEngineManagerHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t IntellVoiceEngineManagerDriverDispatch(struct HdfDeviceIoClient *client, int cmdId,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    OHOS::MessageParcel *dataParcel = nullptr;
    OHOS::MessageParcel *replyParcel = nullptr;
    OHOS::MessageOption option;

    if (SbufToParcel(data, &dataParcel) != HDF_SUCCESS) {
        INTELLIGENT_VOICE_LOGE("invalid data sbuf object to dispatch");
        return HDF_ERR_INVALID_PARAM;
    }
    if (SbufToParcel(reply, &replyParcel) != HDF_SUCCESS) {
        INTELLIGENT_VOICE_LOGE("invalid reply sbuf object to dispatch");
        return HDF_ERR_INVALID_PARAM;
    }

    std::shared_lock lock(g_engineMgrMutex);
    if ((client == nullptr) || (client->device == nullptr) || (client->device->service == nullptr)) {
        INTELLIGENT_VOICE_LOGE("client or device or service is nullptr");
        return HDF_FAILURE;
    }

    auto *hdfIntellVoiceEngineManagerHost = CONTAINER_OF(client->device->service,
        struct HdfIntellVoiceEngineManagerHost, ioService);
    if ((hdfIntellVoiceEngineManagerHost == nullptr) || (hdfIntellVoiceEngineManagerHost->stub == nullptr)) {
        INTELLIGENT_VOICE_LOGE("invalid hdfIntellVoiceEngineManagerHost");
        return HDF_FAILURE;
    }

    return hdfIntellVoiceEngineManagerHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfIntellVoiceEngineManagerDriverInit(struct HdfDeviceObject *deviceObject)
{
    INTELLIGENT_VOICE_LOGD("driver init start");
    return HDF_SUCCESS;
}

static int HdfIntellVoiceEngineManagerDriverBind(struct HdfDeviceObject *deviceObject)
{
    INTELLIGENT_VOICE_LOGI("enter");
    if (deviceObject == nullptr) {
        INTELLIGENT_VOICE_LOGE("deviceObject is nullptr");
        return HDF_FAILURE;
    }

    auto *hdfIntellVoiceEngineManagerHost = new (std::nothrow) HdfIntellVoiceEngineManagerHost;
    if (hdfIntellVoiceEngineManagerHost == nullptr) {
        INTELLIGENT_VOICE_LOGE("failed to create create HdfIntellVoiceEngineManagerHost object");
        return HDF_FAILURE;
    }

    hdfIntellVoiceEngineManagerHost->ioService.Dispatch = IntellVoiceEngineManagerDriverDispatch;
    hdfIntellVoiceEngineManagerHost->ioService.Open = NULL;
    hdfIntellVoiceEngineManagerHost->ioService.Release = NULL;

    auto serviceImpl = OHOS::HDI::IntelligentVoice::Engine::V1_2::IIntellVoiceEngineManager::Get(true);
    if (serviceImpl == nullptr) {
        INTELLIGENT_VOICE_LOGE("failed to get of implement service");
        delete hdfIntellVoiceEngineManagerHost;
        return HDF_FAILURE;
    }

    hdfIntellVoiceEngineManagerHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        OHOS::HDI::IntelligentVoice::Engine::V1_2::IIntellVoiceEngineManager::GetDescriptor());
    if (hdfIntellVoiceEngineManagerHost->stub == nullptr) {
        INTELLIGENT_VOICE_LOGE("failed to get stub object");
        delete hdfIntellVoiceEngineManagerHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfIntellVoiceEngineManagerHost->ioService;
    return HDF_SUCCESS;
}

static void HdfIntellVoiceEngineManagerDriverRelease(struct HdfDeviceObject *deviceObject)
{
    INTELLIGENT_VOICE_LOGI("enter");
    if ((deviceObject == nullptr) || (deviceObject->service == nullptr)) {
        INTELLIGENT_VOICE_LOGE("deviceObject is nullptr or service is nullptr");
        return;
    }

    std::unique_lock lock(g_engineMgrMutex);
    auto *hdfIntellVoiceEngineManagerHost = CONTAINER_OF(deviceObject->service,
        struct HdfIntellVoiceEngineManagerHost, ioService);
    if (hdfIntellVoiceEngineManagerHost != nullptr) {
        hdfIntellVoiceEngineManagerHost->stub = nullptr;
        delete hdfIntellVoiceEngineManagerHost;
    }
    deviceObject->service = nullptr;
}

static struct HdfDriverEntry g_intellvoiceEngineManagerDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "intell_voice_engine_service",
    .Bind = HdfIntellVoiceEngineManagerDriverBind,
    .Init = HdfIntellVoiceEngineManagerDriverInit,
    .Release = HdfIntellVoiceEngineManagerDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_intellvoiceEngineManagerDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
