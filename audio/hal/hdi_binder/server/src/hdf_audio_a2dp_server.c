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

#include "audio_adapter_info_common.h"
#include "audio_hal_log.h"
#include "hdf_audio_server_common.h"
#include "hdf_device_desc.h"

#define HDF_LOG_TAG HDF_AUDIO_HAL_HOST

void AudioHdiA2dpServerRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: enter!", __func__);
    /* g_renderAndCaptureManage release */
    AdaptersServerManageInfomationRecycle();

    if (deviceObject == NULL) {
        HDF_LOGE("%{public}s: deviceObject is null!", __func__);
        return;
    }
    deviceObject->service = NULL;
    HDF_LOGD("%{public}s: end!", __func__);
    return;
}

int AudioHdiA2dpServerBind(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: enter!", __func__);
    if (deviceObject == NULL) {
        HDF_LOGE("%{public}s: deviceObject is null!", __func__);
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    static struct IDeviceIoService hdiService = {
        .Dispatch = HdiServiceDispatch,
        .Open = NULL,
        .Release = NULL,
    };
    AudioHdiSetLoadServerFlag(AUDIO_SERVER_A2DP);
    if (HdiServiceGetFuncs()) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    int ret = HdfDeviceObjectSetInterfaceDesc(deviceObject, "ohos.hdi.audio_service");
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("failed to set interface desc");
        return ret;
    }
    deviceObject->service = &hdiService;

    HDF_LOGD("%{public}s: end!", __func__);
    return AUDIO_HAL_SUCCESS;
}

int AudioHdiA2dpServerInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: enter!", __func__);
    if (deviceObject == NULL) {
        HDF_LOGE("%{public}s: deviceObject is null!", __func__);
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (!HdfDeviceSetClass(deviceObject, DEVICE_CLASS_AUDIO)) {
        HDF_LOGE("%{public}s: Set A2dp DEVICE_CLASS_AUDIO fail!", __func__);
    }

    HDF_LOGD("%{public}s: end!", __func__);
    return AUDIO_HAL_SUCCESS;
}

struct HdfDriverEntry g_hdiAudioA2DPServerEntry = {
    .moduleVersion = 1,
    .moduleName = "hdi_audio_a2dp_server",
    .Bind = AudioHdiA2dpServerBind,
    .Init = AudioHdiA2dpServerInit,
    .Release = AudioHdiA2dpServerRelease,
};

HDF_INIT(g_hdiAudioA2DPServerEntry);
