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

#include "hdf_device_desc.h"
#include "hdf_device_object.h"
#include "audio_adapter_info_common.h"
#include "audio_events.h"
#include "audio_uhdf_log.h"
#include "hdf_audio_events.h"
#include "hdf_audio_server_common.h"

#define HDF_LOG_TAG HDF_AUDIO_HAL_HOST

static void AudioHdiPrimaryServerRelease(struct HdfDeviceObject *deviceObject)
{
    AUDIO_FUNC_LOGI("enter!");
    /* g_renderAndCaptureManage release */
    AdaptersServerManageInfomationRecycle();
    ReleaseAudioManagerObjectComm(GetAudioManagerFuncs());

    if (deviceObject == NULL) {
        AUDIO_FUNC_LOGE("Parameter is null!");
        return;
    }
    deviceObject->service = NULL;
    AUDIO_FUNC_LOGD("end!");
    return;
}

static int AudioHdiPrimaryServerBind(struct HdfDeviceObject *deviceObject)
{
    AUDIO_FUNC_LOGI("enter!");
    if (deviceObject == NULL) {
        AUDIO_FUNC_LOGE("deviceObject is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    static struct IDeviceIoService hdiPrimaryService = {
        .Dispatch = HdiServiceDispatch,
        .Open = NULL,
        .Release = NULL,
    };
    AudioHdiSetLoadServerFlag(AUDIO_SERVER_PRIMARY);
    if (HdiServiceGetFuncs() < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    int ret = HdfDeviceObjectSetInterfaceDesc(deviceObject, "ohos.hdi.audio_service");
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("failed to set interface desc");
        return ret;
    }
    deviceObject->service = &hdiPrimaryService;

    AUDIO_FUNC_LOGD("end!");
    return AUDIO_HAL_SUCCESS;
}

static int AudioHdiPrimaryServerInit(struct HdfDeviceObject *deviceObject)
{
    AUDIO_FUNC_LOGI("enter!");
    if (deviceObject == NULL) {
        AUDIO_FUNC_LOGE("deviceObject is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (!HdfDeviceSetClass(deviceObject, DEVICE_CLASS_AUDIO)) {
        AUDIO_FUNC_LOGE("Set Primary DEVICE_CLASS_AUDIO fail!");
    }
    struct AudioEvent audioSrvEvent = {
        .eventType = HDF_AUDIO_SERVICE_VALID,
        .deviceType = HDF_AUDIO_PRIMARY_DEVICE,
    };
    AudioServiceStateChange(deviceObject, &audioSrvEvent);

    AUDIO_FUNC_LOGD("end!");
    return AUDIO_HAL_SUCCESS;
}

struct HdfDriverEntry g_hdiPrimaryServerEntry = {
    .moduleVersion = 1,
    .moduleName = "hdi_audio_primary_server",
    .Bind = AudioHdiPrimaryServerBind,
    .Init = AudioHdiPrimaryServerInit,
    .Release = AudioHdiPrimaryServerRelease,
};

HDF_INIT(g_hdiPrimaryServerEntry);
