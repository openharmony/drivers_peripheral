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
#include "v1_1/intell_voice_trigger_manager_stub.h"

#undef HDF_LOG_TAG
#define HDF_LOG_TAG "IntellVoiceTriggerDriver"

using namespace OHOS::HDI::IntelligentVoice::Trigger::V1_1;

namespace {
    static std::shared_mutex g_triggerMgrMutex;
}

struct HdfIntellVoiceTriggerManagerHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t IntellVoiceTriggerManagerDriverDispatch(struct HdfDeviceIoClient *client, int cmdId,
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

    std::shared_lock lock(g_triggerMgrMutex);
    if ((client == nullptr) || (client->device == nullptr) || (client->device->service == nullptr)) {
        INTELLIGENT_VOICE_LOGE("client or device or service is nullptr");
        return HDF_FAILURE;
    }

    auto *hdfIntellVoiceTriggerManagerHost = CONTAINER_OF(client->device->service,
        struct HdfIntellVoiceTriggerManagerHost, ioService);
    if ((hdfIntellVoiceTriggerManagerHost == nullptr) || (hdfIntellVoiceTriggerManagerHost->stub == nullptr)) {
        INTELLIGENT_VOICE_LOGE("invalid hdfIntellVoiceTriggerManagerHost");
        return HDF_FAILURE;
    }

    return hdfIntellVoiceTriggerManagerHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfIntellVoiceTriggerManagerDriverInit(struct HdfDeviceObject *deviceObject)
{
    INTELLIGENT_VOICE_LOGD("driver init start");
    return HDF_SUCCESS;
}

static int HdfIntellVoiceTriggerManagerDriverBind(struct HdfDeviceObject *deviceObject)
{
    INTELLIGENT_VOICE_LOGI("enter");
    if (deviceObject == nullptr) {
        INTELLIGENT_VOICE_LOGE("deviceObject is nullptr");
        return HDF_FAILURE;
    }

    auto *hdfIntellVoiceTriggerManagerHost = new (std::nothrow) HdfIntellVoiceTriggerManagerHost;
    if (hdfIntellVoiceTriggerManagerHost == nullptr) {
        INTELLIGENT_VOICE_LOGE("failed to create create HdfIntellVoiceTriggerManagerHost object");
        return HDF_FAILURE;
    }

    hdfIntellVoiceTriggerManagerHost->ioService.Dispatch = IntellVoiceTriggerManagerDriverDispatch;
    hdfIntellVoiceTriggerManagerHost->ioService.Open = NULL;
    hdfIntellVoiceTriggerManagerHost->ioService.Release = NULL;

    auto serviceImpl = OHOS::HDI::IntelligentVoice::Trigger::V1_1::IIntellVoiceTriggerManager::Get(true);
    if (serviceImpl == nullptr) {
        INTELLIGENT_VOICE_LOGE("failed to get of implement service");
        delete hdfIntellVoiceTriggerManagerHost;
        return HDF_FAILURE;
    }

    hdfIntellVoiceTriggerManagerHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        OHOS::HDI::IntelligentVoice::Trigger::V1_1::IIntellVoiceTriggerManager::GetDescriptor());
    if (hdfIntellVoiceTriggerManagerHost->stub == nullptr) {
        INTELLIGENT_VOICE_LOGE("failed to get stub object");
        delete hdfIntellVoiceTriggerManagerHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfIntellVoiceTriggerManagerHost->ioService;
    return HDF_SUCCESS;
}

static void HdfIntellVoiceTriggerManagerDriverRelease(struct HdfDeviceObject *deviceObject)
{
    INTELLIGENT_VOICE_LOGI("enetr");
    if ((deviceObject == nullptr) || (deviceObject->service == nullptr)) {
        INTELLIGENT_VOICE_LOGE("deviceObject is nullptr or service is nullptr");
        return;
    }

    std::unique_lock lock(g_triggerMgrMutex);
    auto *hdfIntellVoiceTriggerManagerHost = CONTAINER_OF(deviceObject->service,
        struct HdfIntellVoiceTriggerManagerHost, ioService);
    if (hdfIntellVoiceTriggerManagerHost != nullptr) {
        hdfIntellVoiceTriggerManagerHost->stub = nullptr;
        delete hdfIntellVoiceTriggerManagerHost;
    }
    deviceObject->service = nullptr;
}

static struct HdfDriverEntry g_intellvoiceTriggerManagerDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "intell_voice_trigger_service",
    .Bind = HdfIntellVoiceTriggerManagerDriverBind,
    .Init = HdfIntellVoiceTriggerManagerDriverInit,
    .Release = HdfIntellVoiceTriggerManagerDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_intellvoiceTriggerManagerDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
