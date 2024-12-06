/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <hdf_log.h>
#include "audio_internal.h"
#include "audio_adapter_info_common.h"
#include "audio_bluetooth_manager.h"
#include "audio_capture.h"
namespace OHOS::HDI::Audio_Bluetooth {
int32_t AudioCaptureStart(AudioHandle handle)
{
    HDF_LOGI("%{public}s enter", __func__);
#ifdef A2DP_HDI_SERVICE
    auto *hwCapture = reinterpret_cast<struct AudioHwCapture *>(handle);
    if (hwCapture == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    return OHOS::Bluetooth::StartCapture();
#endif
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t AudioCaptureStop(AudioHandle handle)
{
    HDF_LOGI("%{public}s enter", __func__);
#ifdef A2DP_HDI_SERVICE
    auto *hwCapture = reinterpret_cast<struct AudioHwCapture *>(handle);
    if (hwCapture == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    OHOS::Bluetooth::StopCapture();
    hwCapture->captureParam.captureMode.ctlParam.pause = false;
    return AUDIO_HAL_SUCCESS;
#endif
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t AudioCapturePause(AudioHandle handle)
{
    HDF_LOGI("%{public}s enter", __func__);
#ifdef A2DP_HDI_SERVICE
    auto *hwCapture = reinterpret_cast<struct AudioHwCapture *>(handle);
    if (hwCapture == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (hwCapture->captureParam.captureMode.ctlParam.pause) {
        HDF_LOGE("Audio is already pause");
        return AUDIO_HAL_ERR_NOT_SUPPORT;
    }
    OHOS::Bluetooth::StopCapture();
    hwCapture->captureParam.captureMode.ctlParam.pause = true;
    return AUDIO_HAL_SUCCESS;
#endif
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t AudioCaptureResume(AudioHandle handle)
{
    HDF_LOGI("%{public}s enter", __func__);
#ifdef A2DP_HDI_SERVICE
    auto *hwCapture = reinterpret_cast<struct AudioHwCapture *>(handle);
    if (hwCapture == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (!hwCapture->captureParam.captureMode.ctlParam.pause) {
        HDF_LOGE("Audio is already Resume");
        return AUDIO_HAL_ERR_NOT_SUPPORT;
    }
    OHOS::Bluetooth::StartCapture();
    hwCapture->captureParam.captureMode.ctlParam.pause = false;
    return AUDIO_HAL_SUCCESS;
#endif
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t AudioCaptureFlush(AudioHandle handle)
{
    HDF_LOGI("%{public}s enter", __func__);
    auto *hwCapture = reinterpret_cast<struct AudioHwCapture *>(handle);
    if (hwCapture == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t AudioCaptureSetMute(AudioHandle handle, bool mute)
{
    (void)mute;
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioCaptureGetMute(AudioHandle handle, bool *mute)
{
    (void)mute;
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioCaptureCaptureFrame(struct AudioCapture *capture, void *frame, uint64_t requestBytes, uint64_t *replyBytes)
{
    HDF_LOGD("%{public}s enter", __func__);
#ifdef A2DP_HDI_SERVICE
    auto *hwCapture = reinterpret_cast<struct AudioHwCapture *>(capture);
    if (hwCapture == nullptr || frame == nullptr || replyBytes == nullptr) {
        HDF_LOGE("Capture Frame Paras is NULL");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    auto *data = reinterpret_cast<uint8_t *>(frame);
    int32_t ret = OHOS::Bluetooth::ReadFrame(data, requestBytes);
    *replyBytes = ret;
    return ret;
#endif
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}
}