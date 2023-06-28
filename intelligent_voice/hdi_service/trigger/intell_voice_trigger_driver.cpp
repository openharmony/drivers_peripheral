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
#include "v1_0/intell_voice_trigger_manager_stub.h"

#define LOG_TAG "IntellVoiceTriggerDriver"

using namespace OHOS::HDI::IntelligentVoice::Trigger::V1_0;

struct HdfIntellVoiceTriggerManagerHost {
    struct IDeviceIoService ioService;
    OHOS::sptr<OHOS::IRemoteObject> stub;
};

static int32_t IntellVoiceTriggerManagerDriverDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    auto *hdfIntellVoiceTriggerManagerHost = CONTAINER_OF(client->device->service, struct HdfIntellVoiceTriggerManagerHost, ioService);

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

    return hdfIntellVoiceTriggerManagerHost->stub->SendRequest(cmdId, *dataParcel, *replyParcel, option);
}

static int HdfIntellVoiceTriggerManagerDriverInit(struct HdfDeviceObject *deviceObject)
{
    INTELL_VOICE_LOG_INFO("%{public}s: driver init start", __func__);
    return HDF_SUCCESS;
}

static int HdfIntellVoiceTriggerManagerDriverBind(struct HdfDeviceObject *deviceObject)
{
    INTELL_VOICE_LOG_INFO("%{public}s: driver bind start", __func__);
    auto *hdfIntellVoiceTriggerManagerHost = new (std::nothrow) HdfIntellVoiceTriggerManagerHost;
    if (hdfIntellVoiceTriggerManagerHost == nullptr) {
        INTELL_VOICE_LOG_ERROR("%{public}s: failed to create create HdfIntellVoiceTriggerManagerHost object", __func__);
        return HDF_FAILURE;
    }

    hdfIntellVoiceTriggerManagerHost->ioService.Dispatch = IntellVoiceTriggerManagerDriverDispatch;
    hdfIntellVoiceTriggerManagerHost->ioService.Open = NULL;
    hdfIntellVoiceTriggerManagerHost->ioService.Release = NULL;

    auto serviceImpl = IIntellVoiceTriggerManager::Get(true);
    if (serviceImpl == nullptr) {
        INTELL_VOICE_LOG_ERROR("%{public}s: failed to get of implement service", __func__);
        delete hdfIntellVoiceTriggerManagerHost;
        return HDF_FAILURE;
    }

    hdfIntellVoiceTriggerManagerHost->stub = OHOS::HDI::ObjectCollector::GetInstance().GetOrNewObject(serviceImpl,
        IIntellVoiceTriggerManager::GetDescriptor());
    if (hdfIntellVoiceTriggerManagerHost->stub == nullptr) {
        INTELL_VOICE_LOG_ERROR("%{public}s: failed to get stub object", __func__);
        delete hdfIntellVoiceTriggerManagerHost;
        return HDF_FAILURE;
    }

    deviceObject->service = &hdfIntellVoiceTriggerManagerHost->ioService;
    return HDF_SUCCESS;
}

static void HdfIntellVoiceTriggerManagerDriverRelease(struct HdfDeviceObject *deviceObject)
{
    INTELL_VOICE_LOG_INFO("%{public}s: driver release start", __func__);
    if (deviceObject->service == nullptr) {
        return;
    }

    auto *hdfIntellVoiceTriggerManagerHost = CONTAINER_OF(deviceObject->service, struct HdfIntellVoiceTriggerManagerHost, ioService);
    if (hdfIntellVoiceTriggerManagerHost != nullptr) {
        delete hdfIntellVoiceTriggerManagerHost;
    }
}

struct HdfDriverEntry g_intellvoicetriggermanagerDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "intell_voice_trigger_service",
    .Bind = HdfIntellVoiceTriggerManagerDriverBind,
    .Init = HdfIntellVoiceTriggerManagerDriverInit,
    .Release = HdfIntellVoiceTriggerManagerDriverRelease,
};

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
HDF_INIT(g_intellvoicetriggermanagerDriverEntry);
#ifdef __cplusplus
}
#endif /* __cplusplus */
