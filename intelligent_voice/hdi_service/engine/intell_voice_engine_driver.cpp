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

#include <hdf_base.h>
#include <hdf_device_desc.h>
#include "intell_voice_log.h"
#include <hdf_sbuf_ipc.h>
#include "v1_0/intell_voice_engine_manager_stub.h"

#define LOG_TAG "IntellVoiceEngineDriver"

using namespace OHOS::HDI::IntelligentVoice::Engine::V1_0;

struct HdfIntellVoiceEngineManagerHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t IntellVoiceEngineManagerDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    auto *hdfIntellVoiceEngineManagerHost = CONTAINER_OF(client->device->service, struct HdfIntellVoiceEngineManagerHost, ioService);

    OHOS::MessageParcel *dataParcel = nullptr;
    OHOS::MessageParcel *replyParcel = nullptr;
    OHOS::MessageOption option;

    if (SbufToParcel(data, &dataParcel) != HDF_SUCCESS) {
        INTELL_VOICE_LOG_ERROR("%{public}s: invalid data sbuf object to dispatch", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (SbufToParcel(reply, &replyParcel) != HDF_SUCCESS) {
        INTELL_VOICE_LOG_ERROR("%{public}s: invalid reply sbuf object to dispatch", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return hdfIntellVoiceEngineManagerHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfIntellVoiceEngineManagerDriverInit(struct HdfDeviceObject *deviceObject)
{
    INTELL_VOICE_LOG_INFO("%{public}s: driver init start", __func__);
    return HDF_SUCCESS;
}

static int HdfIntellVoiceEngineManagerDriverBind(struct HdfDeviceObject *deviceObject)
{
    INTELL_VOICE_LOG_INFO("%{public}s: driver bind start", __func__);
    auto *hdfIntellVoiceEngineManagerHost = new (std::nothrow) HdfIntellVoiceEngineManagerHost;
    if (hdfIntellVoiceEngineManagerHost == nullptr) {
        INTELL_VOICE_LOG_ERROR("%{public}s: failed to create create HdfIntellVoiceEngineManagerHost object", __func__);
        return HDF_FAILURE;
    }

    hdfIntellVoiceEngineManagerHost->ioService.Dispatch = IntellVoiceEngineManagerDriverDispatch;
    hdfIntellVoiceEngineManagerHost->ioService.Open = NULL;
    hdfIntellVoiceEngineManagerHost->ioService.Release = NULL;

    auto serviceImpl = IIntellVoiceEngineManager::Get(true);
    if (serviceImpl == nullptr) {
        INTELL_VOICE_LOG_ERROR("%{public}s: failed to get of implement service", __func__);
        delete hdfIntellVoiceEngineManagerHost;
        return HDF_FAILURE;
    }

    hdfIntellVoiceEngineManagerHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        IIntellVoiceEngineManager::GetDescriptor());
    if (hdfIntellVoiceEngineManagerHost->stub == nullptr) {
        INTELL_VOICE_LOG_ERROR("%{public}s: failed to get stub object", __func__);
        delete hdfIntellVoiceEngineManagerHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfIntellVoiceEngineManagerHost->ioService;
    return HDF_SUCCESS;
}

static void HdfIntellVoiceEngineManagerDriverRelease(struct HdfDeviceObject *deviceObject)
{
    INTELL_VOICE_LOG_INFO("%{public}s: driver release start", __func__);
    if (deviceObject->service == nullptr) {
        return;
    }

    auto *hdfIntellVoiceEngineManagerHost = CONTAINER_OF(deviceObject->service, struct HdfIntellVoiceEngineManagerHost, ioService);
    if (hdfIntellVoiceEngineManagerHost != nullptr) {
        delete hdfIntellVoiceEngineManagerHost;
    }
}

struct HdfDriverEntry g_intellvoiceenginemanagerDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "intell_voice_engine_service",
    .Bind = HdfIntellVoiceEngineManagerDriverBind,
    .Init = HdfIntellVoiceEngineManagerDriverInit,
    .Release = HdfIntellVoiceEngineManagerDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_intellvoiceenginemanagerDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
