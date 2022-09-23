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

#include "audio_capture.h"
#include "osal_mem.h"
#include "audio_adapter_info_common.h"
#include "audio_uhdf_log.h"
#include "audio_interface_lib_capture.h"

#define HDF_LOG_TAG HDF_AUDIO_HAL_IMPL

#define CONFIG_FRAME_SIZE      (1024 * 2 * 1)
#define FRAME_SIZE              1024
#define BITS_TO_FROMAT          3
#define VOLUME_AVERAGE          2
#define INTEGER_TO_DEC          10
#define DECIMAL_PART            5

#define CONFIG_FRAME_COUNT     ((8000 * 2 * 1 + (CONFIG_FRAME_SIZE - 1)) / CONFIG_FRAME_SIZE)

/* add For Capture Bytes To Frames */
int32_t AudioCaptureStart(AudioHandle handle)
{
    AUDIO_FUNC_LOGI();
    int32_t ret = AudioCheckCaptureAddr(handle);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The capture address passed in is invalid");
        return ret;
    }
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL) {
        AUDIO_FUNC_LOGE("The hwCapture is NULL");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        AUDIO_FUNC_LOGE("pInterfaceLibModeCapture Fail!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (hwCapture->captureParam.frameCaptureMode.buffer != NULL) {
        AUDIO_FUNC_LOGE("AudioCapture already start!");
        return AUDIO_HAL_ERR_AI_BUSY; // capture is busy now
    }
    if (hwCapture->devDataHandle == NULL) {
        AUDIO_FUNC_LOGE("CaptureStart Bind Fail!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = (*pInterfaceLibModeCapture)(hwCapture->devDataHandle, &hwCapture->captureParam,
                                              AUDIO_DRV_PCM_IOCTRL_START_CAPTURE);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("AudioCaptureStart SetParams FAIL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    char *tbuffer = (char *)OsalMemCalloc(FRAME_DATA);
    if (tbuffer == NULL) {
        AUDIO_FUNC_LOGE("alloc Capture tbuffer Fail!");
        return AUDIO_HAL_ERR_MALLOC_FAIL;
    }
    hwCapture->captureParam.frameCaptureMode.buffer = tbuffer;
    AudioLogRecord(INFO, "[%s]-[%s]-[%d] :> [%s]", __FILE__, __func__, __LINE__, "Audio Capture Start");
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioCaptureStop(AudioHandle handle)
{
    AUDIO_FUNC_LOGI();
    int32_t ret = AudioCheckCaptureAddr(handle);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The capture address passed in is invalid");
        return ret;
    }
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL) {
        AUDIO_FUNC_LOGE("hwCapture is null");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (hwCapture->devDataHandle == NULL) {
        AUDIO_FUNC_LOGE("CaptureStart Bind Fail!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (hwCapture->captureParam.frameCaptureMode.buffer != NULL) {
        AudioMemFree((void **)&hwCapture->captureParam.frameCaptureMode.buffer);
    } else {
        AUDIO_FUNC_LOGE("Repeat invalid stop operation!");
        return AUDIO_HAL_ERR_NOT_SUPPORT;
    }
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        AUDIO_FUNC_LOGE("pInterfaceLibModeCapture Fail!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = (*pInterfaceLibModeCapture)(hwCapture->devDataHandle, &hwCapture->captureParam,
                                              AUDIO_DRV_PCM_IOCTRL_STOP_CAPTURE);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("AudioCaptureStop SetParams FAIL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    AudioLogRecord(INFO, "[%s]-[%s]-[%d] :> [%s]", __FILE__, __func__, __LINE__, "Audio Capture Stop");
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioCapturePause(AudioHandle handle)
{
    AUDIO_FUNC_LOGI();
    int32_t ret = AudioCheckCaptureAddr(handle);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The capture address passed in is invalid");
        return ret;
    }

    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL) {
        AUDIO_FUNC_LOGE("hwCapture is empty");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (hwCapture->captureParam.frameCaptureMode.buffer == NULL) {
        AUDIO_FUNC_LOGE("AudioCapture already stop!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (hwCapture->captureParam.captureMode.ctlParam.pause) {
        AUDIO_FUNC_LOGE("Audio capture is already pause!");
        return AUDIO_HAL_ERR_NOT_SUPPORT;
    }
    if (hwCapture->devDataHandle == NULL) {
        AUDIO_FUNC_LOGE("CaptureStart Bind Fail!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        AUDIO_FUNC_LOGE("pInterfaceLibModeCapture Fail!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    bool pauseStatus = hwCapture->captureParam.captureMode.ctlParam.pause;
    hwCapture->captureParam.captureMode.ctlParam.pause = true;
    ret = (*pInterfaceLibModeCapture)(hwCapture->devDataHandle, &hwCapture->captureParam,
                                              AUDIODRV_CTL_IOCTL_PAUSE_WRITE_CAPTURE);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Audio Capture Pause FAIL!");
        hwCapture->captureParam.captureMode.ctlParam.pause = pauseStatus;
        return AUDIO_HAL_ERR_INTERNAL;
    }
    AudioLogRecord(INFO, "[%s]-[%s]-[%d] :> [%s]", __FILE__, __func__, __LINE__, "Audio Capture Pause");
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioCaptureResume(AudioHandle handle)
{
    AUDIO_FUNC_LOGI();
    int32_t ret = AudioCheckCaptureAddr(handle);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The capture address passed in is invalid");
        return ret;
    }

    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL) {
        AUDIO_FUNC_LOGE("hwCapture is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (!hwCapture->captureParam.captureMode.ctlParam.pause) {
        AUDIO_FUNC_LOGE("Audio capture is already Resume !");
        return AUDIO_HAL_ERR_NOT_SUPPORT;
    }
    if (hwCapture->devDataHandle == NULL) {
        AUDIO_FUNC_LOGE("Capture Start Bind Fail!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        AUDIO_FUNC_LOGE("pInterfaceLibModeCapture Fail!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    bool resumeStatus = hwCapture->captureParam.captureMode.ctlParam.pause;
    hwCapture->captureParam.captureMode.ctlParam.pause = false;
    ret = (*pInterfaceLibModeCapture)(hwCapture->devDataHandle, &hwCapture->captureParam,
                                              AUDIODRV_CTL_IOCTL_PAUSE_WRITE_CAPTURE);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Audio capture Resume FAIL!");
        hwCapture->captureParam.captureMode.ctlParam.pause = resumeStatus;
        return AUDIO_HAL_ERR_INTERNAL;
    }
    AudioLogRecord(INFO, "[%s]-[%s]-[%d] :> [%s]", __FILE__, __func__, __LINE__, "Audio Capture Resume");
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioCaptureFlush(AudioHandle handle)
{
    AUDIO_FUNC_LOGI();
    int32_t ret = AudioCheckCaptureAddr(handle);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The capture address passed in is invalid, ret = %{public}d", ret);
        return ret;
    }
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL) {
        AUDIO_FUNC_LOGE("hwCapture is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t AudioCaptureGetFrameSize(AudioHandle handle, uint64_t *size)
{
    AUDIO_FUNC_LOGI();
    int32_t ret = AudioCheckCaptureAddr(handle);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The capture address passed in is invalid");
        return ret;
    }
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL || size == NULL) {
        AUDIO_FUNC_LOGE("hwCapture or size is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    uint32_t channelCount = hwCapture->captureParam.frameCaptureMode.attrs.channelCount;
    enum AudioFormat format = hwCapture->captureParam.frameCaptureMode.attrs.format;
    uint32_t formatBitsCapture = 0;
    ret = FormatToBits(format, &formatBitsCapture);
    if (ret != AUDIO_HAL_SUCCESS) {
        AUDIO_FUNC_LOGE("FormatToBits failed! ret = %{public}d", ret);
        return ret;
    }
    *size = FRAME_SIZE * channelCount * (formatBitsCapture >> BITS_TO_FROMAT);
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioCaptureGetFrameCount(AudioHandle handle, uint64_t *count)
{
    AUDIO_FUNC_LOGI();
    int32_t ret = AudioCheckCaptureAddr(handle);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The capture address passed in is invalid");
        return ret;
    }
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL || count == NULL) {
        AUDIO_FUNC_LOGE("hwCapture or count is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    *count = hwCapture->captureParam.frameCaptureMode.frames;
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioCaptureSetSampleAttributes(AudioHandle handle, const struct AudioSampleAttributes *attrs)
{
    AUDIO_FUNC_LOGI();
    int32_t ret = AudioCheckCaptureAddr(handle);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The capture address passed in is invalid");
        return ret;
    }
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL || attrs == NULL) {
        AUDIO_FUNC_LOGE("hwCapture or attrs is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    ret = AudioCheckParaAttr(attrs);
    if (ret != AUDIO_HAL_SUCCESS) {
        AUDIO_FUNC_LOGE("udioCheckParaAttr failed! ret = %{public}d", ret);
        return ret;
    }
    struct AudioSampleAttributes tempAttrs = hwCapture->captureParam.frameCaptureMode.attrs;
    hwCapture->captureParam.frameCaptureMode.attrs.format = attrs->format;
    hwCapture->captureParam.frameCaptureMode.attrs.sampleRate = attrs->sampleRate;
    hwCapture->captureParam.frameCaptureMode.attrs.channelCount = attrs->channelCount;
    hwCapture->captureParam.frameCaptureMode.attrs.interleaved = attrs->interleaved;
    hwCapture->captureParam.frameCaptureMode.attrs.type = attrs->type;
    hwCapture->captureParam.frameCaptureMode.attrs.period = attrs->period;
    hwCapture->captureParam.frameCaptureMode.attrs.frameSize = attrs->frameSize;
    hwCapture->captureParam.frameCaptureMode.attrs.isBigEndian = attrs->isBigEndian;
    hwCapture->captureParam.frameCaptureMode.attrs.isSignedData = attrs->isSignedData;
    hwCapture->captureParam.frameCaptureMode.attrs.startThreshold = attrs->startThreshold;
    hwCapture->captureParam.frameCaptureMode.attrs.stopThreshold = attrs->stopThreshold;
    hwCapture->captureParam.frameCaptureMode.attrs.silenceThreshold = attrs->silenceThreshold;
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        hwCapture->captureParam.frameCaptureMode.attrs = tempAttrs;
        AUDIO_FUNC_LOGE("pInterfaceLibModeCapture Fail!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (hwCapture->devDataHandle == NULL) {
        hwCapture->captureParam.frameCaptureMode.attrs = tempAttrs;
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = (*pInterfaceLibModeCapture)(hwCapture->devDataHandle, &hwCapture->captureParam,
                                              AUDIO_DRV_PCM_IOCTL_HW_PARAMS);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("CaptureSetSampleAttributes FAIL");
        hwCapture->captureParam.frameCaptureMode.attrs = tempAttrs;
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioCaptureGetSampleAttributes(AudioHandle handle, struct AudioSampleAttributes *attrs)
{
    AUDIO_FUNC_LOGI();
    int32_t ret = AudioCheckCaptureAddr(handle);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The capture address passed in is invalid! ret = %{public}d", ret);
        return ret;
    }
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL || attrs == NULL) {
        AUDIO_FUNC_LOGE("hwCapture or attrs is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    attrs->format = hwCapture->captureParam.frameCaptureMode.attrs.format;
    attrs->sampleRate = hwCapture->captureParam.frameCaptureMode.attrs.sampleRate;
    attrs->channelCount = hwCapture->captureParam.frameCaptureMode.attrs.channelCount;
    attrs->interleaved = hwCapture->captureParam.frameCaptureMode.attrs.interleaved;
    attrs->type = hwCapture->captureParam.frameCaptureMode.attrs.type;
    attrs->period = hwCapture->captureParam.frameCaptureMode.attrs.period;
    attrs->frameSize = hwCapture->captureParam.frameCaptureMode.attrs.frameSize;
    attrs->isBigEndian = hwCapture->captureParam.frameCaptureMode.attrs.isBigEndian;
    attrs->isSignedData = hwCapture->captureParam.frameCaptureMode.attrs.isSignedData;
    attrs->startThreshold = hwCapture->captureParam.frameCaptureMode.attrs.startThreshold;
    attrs->stopThreshold = hwCapture->captureParam.frameCaptureMode.attrs.stopThreshold;
    attrs->silenceThreshold = hwCapture->captureParam.frameCaptureMode.attrs.silenceThreshold;
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioCaptureGetCurrentChannelId(AudioHandle handle, uint32_t *channelId)
{
    AUDIO_FUNC_LOGI();
    int32_t ret = AudioCheckCaptureAddr(handle);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The capture address passed in is invalid! ret = %{public}d", ret);
        return ret;
    }
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL || channelId == NULL) {
        AUDIO_FUNC_LOGE("hwCapture or channelId is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    *channelId = hwCapture->captureParam.frameCaptureMode.attrs.channelCount;
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioCaptureCheckSceneCapability(AudioHandle handle, const struct AudioSceneDescriptor *scene,
                                         bool *supported)
{
    AUDIO_FUNC_LOGI();
    int32_t ret = AudioCheckCaptureAddr(handle);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The capture address passed in is invalid! ret = %{public}d", ret);
        return ret;
    }
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL || scene == NULL || supported == NULL) {
        AUDIO_FUNC_LOGE("hwCapture or scene or supported is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
#ifndef AUDIO_HAL_NOTSUPPORT_PATHSELECT
    *supported = false;
    /* Temporary storage does not save the structure */
    struct AudioHwCaptureParam captureParam = hwCapture->captureParam;
    captureParam.frameCaptureMode.attrs.type = (enum AudioCategory)scene->scene.id;
    captureParam.captureMode.hwInfo.deviceDescript.pins = scene->desc.pins;
    PathSelAnalysisJson *pPathSelAnalysisJson = AudioSoGetPathSelAnalysisJson();
    if (pPathSelAnalysisJson == NULL || *pPathSelAnalysisJson == NULL) {
        AUDIO_FUNC_LOGE("pPathSelAnalysisJson Is NULL!");
        return AUDIO_HAL_ERR_NOT_SUPPORT;
    }
    ret = (*pPathSelAnalysisJson)((void *)&captureParam, CHECKSCENE_PATH_SELECT_CAPTURE);
    if (ret < 0) {
        if (ret == AUDIO_HAL_ERR_NOT_SUPPORT) {
            AUDIO_FUNC_LOGE("AudioCaptureCheckSceneCapability not Support!");
            return AUDIO_HAL_ERR_NOT_SUPPORT;
        } else {
            AUDIO_FUNC_LOGE("AudioCaptureCheckSceneCapability fail!");
            return AUDIO_HAL_ERR_INTERNAL;
        }
    }
    *supported = true;
    return AUDIO_HAL_SUCCESS;
#else
    return AUDIO_HAL_ERR_NOT_SUPPORT;
#endif
}

int32_t AudioCaptureSelectScene(AudioHandle handle, const struct AudioSceneDescriptor *scene)
{
    int32_t ret = AudioCheckCaptureAddr(handle);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The capture address passed in is invalid! ret = %{public}d", ret);
        return ret;
    }
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL || scene == NULL) {
        AUDIO_FUNC_LOGE("hwCapture or scene  is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (hwCapture->devCtlHandle == NULL) {
        AUDIO_FUNC_LOGE("CaptureSelectScene Bind Fail!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
#ifndef AUDIO_HAL_NOTSUPPORT_PATHSELECT
    PathSelAnalysisJson *pPathSelAnalysisJson = AudioSoGetPathSelAnalysisJson();
    if (pPathSelAnalysisJson == NULL || *pPathSelAnalysisJson == NULL) {
        AUDIO_FUNC_LOGE("pPathSelAnalysisJson Is NULL!");
        return AUDIO_HAL_ERR_NOT_SUPPORT;
    }
    enum AudioCategory typeTemp = hwCapture->captureParam.frameCaptureMode.attrs.type;
    enum AudioPortPin pinsTemp = hwCapture->captureParam.captureMode.hwInfo.deviceDescript.pins;
    hwCapture->captureParam.frameCaptureMode.attrs.type = (enum AudioCategory)(scene->scene.id);
    hwCapture->captureParam.captureMode.hwInfo.deviceDescript.pins = scene->desc.pins;
    if ((*pPathSelAnalysisJson)((void *)&hwCapture->captureParam, CAPTURE_PATH_SELECT) < 0) {
        AUDIO_FUNC_LOGE("AudioCaptureSelectScene Fail!");
        hwCapture->captureParam.frameCaptureMode.attrs.type = typeTemp;
        hwCapture->captureParam.captureMode.hwInfo.deviceDescript.pins = pinsTemp;
        return AUDIO_HAL_ERR_INTERNAL;
    }
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        AUDIO_FUNC_LOGE("pInterfaceLibModeCapture Is NULL");
        hwCapture->captureParam.frameCaptureMode.attrs.type = typeTemp;
        hwCapture->captureParam.captureMode.hwInfo.deviceDescript.pins = pinsTemp;
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = (*pInterfaceLibModeCapture)(hwCapture->devCtlHandle, &hwCapture->captureParam,
                                              AUDIODRV_CTL_IOCTL_SCENESELECT_CAPTURE);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("SetSelectSceneParams FAIL!");
        hwCapture->captureParam.frameCaptureMode.attrs.type = typeTemp;
        hwCapture->captureParam.captureMode.hwInfo.deviceDescript.pins = pinsTemp;
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
#else
    return AUDIO_HAL_ERR_NOT_SUPPORT;
#endif
}

int32_t AudioCaptureSetMute(AudioHandle handle, bool mute)
{
    AUDIO_FUNC_LOGI();
    int32_t ret = AudioCheckCaptureAddr(handle);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The capture address passed in is invalid! ret = %{public}d", ret);
        return ret;
    }
    struct AudioHwCapture *impl = (struct AudioHwCapture *)handle;
    if (impl == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (impl->devCtlHandle == NULL) {
        AUDIO_FUNC_LOGE("CaptureSetMute Bind Fail!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        AUDIO_FUNC_LOGE("pInterfaceLibModeCapture Fail!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    bool muteStatus = impl->captureParam.captureMode.ctlParam.mute;
    impl->captureParam.captureMode.ctlParam.mute = mute;
    ret = (*pInterfaceLibModeCapture)(impl->devCtlHandle, &impl->captureParam,
                                              AUDIODRV_CTL_IOCTL_MUTE_WRITE_CAPTURE);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("SetMute SetParams FAIL");
        impl->captureParam.captureMode.ctlParam.mute = muteStatus;
        return AUDIO_HAL_ERR_INTERNAL;
    }
    AudioLogRecord(INFO, "[%s]-[%s]-[%d] :> [Setmute = %d]", __FILE__, __func__, __LINE__, mute);
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioCaptureGetMute(AudioHandle handle, bool *mute)
{
    AUDIO_FUNC_LOGI();
    int32_t ret = AudioCheckCaptureAddr(handle);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The capture address passed in is invalid! ret = %{public}d", ret);
        return ret;
    }
    struct AudioHwCapture *impl = (struct AudioHwCapture *)handle;
    if (impl == NULL || mute == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (impl->devCtlHandle == NULL) {
        AUDIO_FUNC_LOGE("CaptureGetMute Bind Fail!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        AUDIO_FUNC_LOGE("pInterfaceLibModeCapture Fail!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = (*pInterfaceLibModeCapture)(impl->devCtlHandle, &impl->captureParam,
                                              AUDIODRV_CTL_IOCTL_MUTE_READ_CAPTURE);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("GetMute SetParams FAIL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    *mute = impl->captureParam.captureMode.ctlParam.mute;
    AUDIO_FUNC_LOGI("Get Mute SUCCESS!");
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioCaptureSetVolume(AudioHandle handle, float volume)
{
    AUDIO_FUNC_LOGI();
    int32_t ret = AudioCheckCaptureAddr(handle);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The capture address passed in is invalid! ret = %{public}d", ret);
        return ret;
    }
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL) {
        AUDIO_FUNC_LOGE("The pointer is null");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    float volumeTemp = hwCapture->captureParam.captureMode.ctlParam.volume;
    float volMax = (float)hwCapture->captureParam.captureMode.ctlParam.volThreshold.volMax;
    float volMin = (float)hwCapture->captureParam.captureMode.ctlParam.volThreshold.volMin;
    if (hwCapture->devCtlHandle == NULL) {
        AUDIO_FUNC_LOGE("Bind Fail!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (volume < 0 || volume > 1) {
        AUDIO_FUNC_LOGE("set volume [%{public}f] out of range:[0-1]!", volume);
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        AUDIO_FUNC_LOGE("pInterfaceLibModeCapture Fail!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    volume = (volume == 0) ? 1 : (volume * VOLUME_CHANGE);
    /* change volume to db */
    float volTemp = ((volMax - volMin) / 2) * log10(volume) + volMin;
    if (volTemp < volMin || volTemp > volMax) {
        AUDIO_FUNC_LOGE("volTemp fail");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    hwCapture->captureParam.captureMode.ctlParam.volume = volTemp;
    ret = (*pInterfaceLibModeCapture)(hwCapture->devCtlHandle, &hwCapture->captureParam,
                                              AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("SetParams FAIL!");
        hwCapture->captureParam.captureMode.ctlParam.volume = volumeTemp;
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioCaptureGetVolume(AudioHandle handle, float *volume)
{
    AUDIO_FUNC_LOGI();
    int32_t ret = AudioCheckCaptureAddr(handle);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The capture address passed in is invalid! ret = %{public}d", ret);
        return ret;
    }
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL || volume == NULL) {
        AUDIO_FUNC_LOGE("hwCapture or volume is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (hwCapture->devCtlHandle == NULL) {
        AUDIO_FUNC_LOGE("CaptureStart Bind Fail!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        AUDIO_FUNC_LOGE("pInterfaceLibModeCapture Fail!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = (*pInterfaceLibModeCapture)(hwCapture->devCtlHandle, &hwCapture->captureParam,
                                          AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Get Volume FAIL!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    float volumeTemp = hwCapture->captureParam.captureMode.ctlParam.volume;
    float volMax = (float)hwCapture->captureParam.captureMode.ctlParam.volThreshold.volMax;
    float volMin = (float)hwCapture->captureParam.captureMode.ctlParam.volThreshold.volMin;
    if ((volMax - volMin) == 0) {
        AUDIO_FUNC_LOGE("Divisor cannot be zero!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    volumeTemp = (volumeTemp - volMin) / ((volMax - volMin) / VOLUME_AVERAGE);
    int volumeT = (int)((pow(INTEGER_TO_DEC, volumeTemp) + DECIMAL_PART) / INTEGER_TO_DEC); // delete 0.X num
    *volume = (float)volumeT / INTEGER_TO_DEC;                                               // get volume (0-1)
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioCaptureGetGainThreshold(AudioHandle handle, float *min, float *max)
{
    AUDIO_FUNC_LOGI();
    int32_t ret = AudioCheckCaptureAddr(handle);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The capture address passed in is invalid! ret = %{public}d", ret);
        return ret;
    }
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL || min == NULL || max == NULL) {
        AUDIO_FUNC_LOGE("hwCapture or min or max is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (hwCapture->devCtlHandle == NULL) {
        AUDIO_FUNC_LOGE("AudioCaptureGetGainThreshold Bind Fail!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        AUDIO_FUNC_LOGE("pInterfaceLibModeCapture Is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = (*pInterfaceLibModeCapture)(hwCapture->devCtlHandle, &hwCapture->captureParam,
                                              AUDIODRV_CTL_IOCTL_GAINTHRESHOLD_CAPTURE);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("SetParams FAIL!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    *max = hwCapture->captureParam.captureMode.ctlParam.audioGain.gainMax;
    *min = hwCapture->captureParam.captureMode.ctlParam.audioGain.gainMin;
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioCaptureGetGain(AudioHandle handle, float *gain)
{
    AUDIO_FUNC_LOGI();
    int32_t ret = AudioCheckCaptureAddr(handle);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The capture address passed in is invalid! ret = %{public}d", ret);
        return ret;
    }
    struct AudioHwCapture *impl = (struct AudioHwCapture *)handle;
    if (impl == NULL || gain == NULL) {
        AUDIO_FUNC_LOGE("impl or gain is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (impl->devCtlHandle == NULL) {
        AUDIO_FUNC_LOGE("CaptureStart Bind Fail!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        AUDIO_FUNC_LOGE("pInterfaceLibModeCapture Fail!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = (*pInterfaceLibModeCapture)(impl->devCtlHandle, &impl->captureParam,
                                              AUDIODRV_CTL_IOCTL_GAIN_READ_CAPTURE);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Get Volume FAIL!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    *gain = impl->captureParam.captureMode.ctlParam.audioGain.gain;
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioCaptureSetGain(AudioHandle handle, float gain)
{
    AUDIO_FUNC_LOGI();
    int32_t ret = AudioCheckCaptureAddr(handle);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The capture address passed in is invalid! ret = %{public}d", ret);
        return ret;
    }
    struct AudioHwCapture *impl = (struct AudioHwCapture *)handle;
    if (impl == NULL || gain < 0) {
        AUDIO_FUNC_LOGE("impl is null or gain < 0!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (impl->devCtlHandle == NULL) {
        AUDIO_FUNC_LOGE("CaptureSetGain Bind Fail!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    float gainTemp = impl->captureParam.captureMode.ctlParam.audioGain.gain;
    impl->captureParam.captureMode.ctlParam.audioGain.gain = gain;
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        AUDIO_FUNC_LOGE("pInterfaceLibModeCapture Fail!");
        impl->captureParam.captureMode.ctlParam.audioGain.gain = gainTemp;
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = (*pInterfaceLibModeCapture)(impl->devCtlHandle, &impl->captureParam,
                                              AUDIODRV_CTL_IOCTL_GAIN_WRITE_CAPTURE);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("CaptureSetGain FAIL!");
        impl->captureParam.captureMode.ctlParam.audioGain.gain = gainTemp;
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

static int32_t LogErrorGetRensonAndTime(struct AudioHwCapture *hwCapture, int errorReason)
{
    if (hwCapture == NULL) {
        AUDIO_FUNC_LOGE("param hwCapture is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (hwCapture->errorLog.iter >= ERROR_LOG_MAX_NUM) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (hwCapture->errorLog.errorDump[hwCapture->errorLog.iter].reason == NULL) {
        hwCapture->errorLog.errorDump[hwCapture->errorLog.iter].reason
            = (char *)OsalMemCalloc(ERROR_REASON_DESC_LEN);
        if (hwCapture->errorLog.errorDump[hwCapture->errorLog.iter].reason == NULL) {
            AUDIO_FUNC_LOGE("alloc reasonDesc Fail!");
            return AUDIO_HAL_ERR_MALLOC_FAIL;
        }
    }
    if (hwCapture->errorLog.errorDump[hwCapture->errorLog.iter].currentTime == NULL) {
        hwCapture->errorLog.errorDump[hwCapture->errorLog.iter].currentTime
            = (char *)OsalMemCalloc(ERROR_REASON_DESC_LEN);
        if (hwCapture->errorLog.errorDump[hwCapture->errorLog.iter].currentTime == NULL) {
            AUDIO_FUNC_LOGE("alloc time Fail!");
            return AUDIO_HAL_ERR_MALLOC_FAIL;
        }
    }
    (void)memset_s(hwCapture->errorLog.errorDump[hwCapture->errorLog.iter].reason,
        ERROR_REASON_DESC_LEN, 0, ERROR_REASON_DESC_LEN);
    (void)memset_s(hwCapture->errorLog.errorDump[hwCapture->errorLog.iter].currentTime,
        ERROR_REASON_DESC_LEN, 0, ERROR_REASON_DESC_LEN);
    int32_t ret = GetErrorReason(errorReason, hwCapture->errorLog.errorDump[hwCapture->errorLog.iter].reason);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Capture GetErrorReason failed! ret = %{public}d", ret);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = GetCurrentTime(hwCapture->errorLog.errorDump[hwCapture->errorLog.iter].currentTime);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Capture GetCurrentTime failed!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

static void LogErrorCapture(AudioHandle handle, int errorCode, int reason)
{
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL) {
        AUDIO_FUNC_LOGE("hwCapture is null!");
        return;
    }
    hwCapture->errorLog.totalErrors++;
    if (hwCapture->errorLog.iter >= ERROR_LOG_MAX_NUM) {
        hwCapture->errorLog.iter = 0;
    }
    int32_t ret = LogErrorGetRensonAndTime(hwCapture, reason);
    if (ret < 0) {
        return;
    }
    if (errorCode == WRITE_FRAME_ERROR_CODE) {
        hwCapture->errorLog.errorDump[hwCapture->errorLog.iter].errorCode = errorCode;
        hwCapture->errorLog.errorDump[hwCapture->errorLog.iter].count = (int32_t)hwCapture->errorLog.iter;
        hwCapture->errorLog.errorDump[hwCapture->errorLog.iter].frames =
            hwCapture->captureParam.frameCaptureMode.frames;
        hwCapture->errorLog.iter++;
    }
}

int32_t AudioCaptureCaptureFrame(struct AudioCapture *capture, void *frame,
                                 uint64_t requestBytes, uint64_t *replyBytes)
{
    int32_t ret = AudioCheckCaptureAddr((AudioHandle)capture);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The capture address passed in is invalid");
        return ret;
    }
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    if (hwCapture == NULL || frame == NULL || replyBytes == NULL ||
        hwCapture->captureParam.frameCaptureMode.buffer == NULL) {
        AUDIO_FUNC_LOGE("Param is NULL Fail!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        AUDIO_FUNC_LOGE("pInterfaceLibModeCapture Fail!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (hwCapture->devDataHandle == NULL) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = (*pInterfaceLibModeCapture)(hwCapture->devDataHandle, &hwCapture->captureParam,
                                              AUDIO_DRV_PCM_IOCTL_READ);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Capture Frame FAIL!");
        LogErrorCapture(capture, WRITE_FRAME_ERROR_CODE, ret);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (requestBytes < hwCapture->captureParam.frameCaptureMode.bufferSize) {
        AUDIO_FUNC_LOGE("Capture Frame requestBytes too little!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = memcpy_s(frame, (size_t)requestBytes, hwCapture->captureParam.frameCaptureMode.buffer,
        (size_t)hwCapture->captureParam.frameCaptureMode.bufferSize);
    if (ret != EOK) {
        AUDIO_FUNC_LOGE("memcpy_s fail");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    *replyBytes = hwCapture->captureParam.frameCaptureMode.bufferSize;
    hwCapture->captureParam.frameCaptureMode.frames += hwCapture->captureParam.frameCaptureMode.bufferFrameSize;
    if (hwCapture->captureParam.frameCaptureMode.attrs.sampleRate == 0) {
        AUDIO_FUNC_LOGE("Divisor cannot be zero!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (TimeToAudioTimeStamp(hwCapture->captureParam.frameCaptureMode.bufferFrameSize,
        &hwCapture->captureParam.frameCaptureMode.time,
        hwCapture->captureParam.frameCaptureMode.attrs.sampleRate) == HDF_FAILURE) {
        AUDIO_FUNC_LOGE("Frame is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioCaptureGetCapturePosition(struct AudioCapture *capture, uint64_t *frames, struct AudioTimeStamp *time)
{
    AUDIO_FUNC_LOGI();
    int32_t ret = AudioCheckCaptureAddr((AudioHandle)capture);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The capture address passed in is invalid");
        return ret;
    }
    struct AudioHwCapture *impl = (struct AudioHwCapture *)capture;
    if (impl == NULL || frames == NULL || time == NULL) {
        AUDIO_FUNC_LOGE("impl or frames or time is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    *frames = impl->captureParam.frameCaptureMode.frames;
    *time = impl->captureParam.frameCaptureMode.time;
    return AUDIO_HAL_SUCCESS;
}

static int32_t SetValueCapture(struct ExtraParams mExtraParams, struct AudioHwCapture *capture)
{
    if (capture == NULL) {
        AUDIO_FUNC_LOGE("param capture is null!");
        return HDF_FAILURE;
    }
    if (mExtraParams.route != -1) {
        capture->captureParam.captureMode.hwInfo.pathroute = mExtraParams.route;
    }
    if (mExtraParams.format != -1) {
        capture->captureParam.frameCaptureMode.attrs.format = mExtraParams.format;
    }
    if (mExtraParams.channels != 0) {
        capture->captureParam.frameCaptureMode.attrs.channelCount = mExtraParams.channels;
    }
    if (mExtraParams.flag) {
        capture->captureParam.frameCaptureMode.frames = mExtraParams.frames;
    }
    if (mExtraParams.sampleRate != 0) {
        capture->captureParam.frameCaptureMode.attrs.sampleRate = mExtraParams.sampleRate;
    }
    return HDF_SUCCESS;
}

int32_t AudioCaptureSetExtraParams(AudioHandle handle, const char *keyValueList)
{
    int32_t ret = AudioCheckCaptureAddr(handle);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The capture address passed in is invalid! ret = %{public}d", ret);
        return ret;
    }
    struct AudioHwCapture *capture = (struct AudioHwCapture *)handle;
    if (capture == NULL || keyValueList == NULL) {
        AUDIO_FUNC_LOGE("capture or keyValueList is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t sumOk = 0;
    struct ExtraParams mExtraParams;
    int32_t count = 0;
    if (AudioSetExtraParams(keyValueList, &count, &mExtraParams, &sumOk) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (count != 0 && sumOk == count) {
        SetValueCapture(mExtraParams, capture);
        return AUDIO_HAL_SUCCESS;
    } else {
        return AUDIO_HAL_ERR_INTERNAL;
    }
}

int32_t AudioCaptureGetExtraParams(const AudioHandle handle, char *keyValueList, int32_t listLenth)
{
    int32_t ret = AudioCheckCaptureAddr(handle);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The capture address passed in is invalid");
        return ret;
    }
    struct AudioHwCapture *capture = (struct AudioHwCapture *)handle;
    if (capture == NULL || keyValueList == NULL || listLenth <= 0) {
        AUDIO_FUNC_LOGE("capture or keyValueList is null or listLenth <= 0.");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t bufferSize = strlen(ROUTE_SAMPLE) + strlen(FORMAT_SAMPLE) + strlen(CHANNELS_SAMPLE)
                    + strlen(FRAME_COUNT_SAMPLE) + strlen(SAMPLING_RATE_SAMPLE) + 1;
    if (listLenth < bufferSize) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = AddElementToList(keyValueList, listLenth, AUDIO_ATTR_PARAM_ROUTE,
        &capture->captureParam.captureMode.hwInfo.pathroute);
    if (ret < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = AddElementToList(keyValueList, listLenth,
        AUDIO_ATTR_PARAM_FORMAT, &capture->captureParam.frameCaptureMode.attrs.format);
    if (ret < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = AddElementToList(keyValueList, listLenth, AUDIO_ATTR_PARAM_CHANNELS,
        &capture->captureParam.frameCaptureMode.attrs.channelCount);
    if (ret < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = AddElementToList(keyValueList, listLenth, AUDIO_ATTR_PARAM_FRAME_COUNT,
        &capture->captureParam.frameCaptureMode.frames);
    if (ret < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = AddElementToList(keyValueList, listLenth, AUDIO_ATTR_PARAM_SAMPLING_RATE,
        &capture->captureParam.frameCaptureMode.attrs.sampleRate);
    if (ret < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

static int32_t AudioCaptureReqMmapBufferInit(struct AudioHwCapture *capture, int32_t reqSize,
    struct AudioMmapBufferDescripter *desc)
{
    if (capture == NULL || capture->devDataHandle == NULL || desc == NULL) {
        AUDIO_FUNC_LOGE("capture or capture->devDataHandle or desc is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t flags;
    if (desc->isShareable) {
        flags = MAP_SHARED;
    } else {
        flags = MAP_PRIVATE;
    }
    uint32_t formatBits = 0;
    int32_t ret = FormatToBits(capture->captureParam.frameCaptureMode.attrs.format, &formatBits);
    if (ret < 0) {
        return ret;
    }
    int64_t filesize = lseek(desc->memoryFd, 0, SEEK_END);
    if ((int64_t)reqSize > filesize) {
        AUDIO_FUNC_LOGE("reqSize is out of file Size!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    desc->memoryAddress = mmap(NULL, reqSize, PROT_READ | PROT_WRITE, flags, desc->memoryFd, 0);
    if (desc->memoryAddress == NULL || desc->memoryAddress == (void *)-1) {
        AUDIO_FUNC_LOGE("AudioCaptureReqMmapBuffer mmap fail and errno is:%{public}d !", errno);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    // formatBits Move right 3
    desc->totalBufferFrames =
        reqSize / (int32_t)(capture->captureParam.frameCaptureMode.attrs.channelCount * (formatBits >> BITS_TO_FROMAT));
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        AUDIO_FUNC_LOGE("pInterfaceLibModeCapture Is NULL");
        munmap(desc->memoryAddress, reqSize);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    capture->captureParam.frameCaptureMode.mmapBufDesc.memoryAddress = desc->memoryAddress;
    capture->captureParam.frameCaptureMode.mmapBufDesc.memoryFd = desc->memoryFd;
    capture->captureParam.frameCaptureMode.mmapBufDesc.totalBufferFrames = desc->totalBufferFrames;
    capture->captureParam.frameCaptureMode.mmapBufDesc.transferFrameSize = desc->transferFrameSize;
    capture->captureParam.frameCaptureMode.mmapBufDesc.isShareable = desc->isShareable;
    capture->captureParam.frameCaptureMode.mmapBufDesc.offset = desc->offset;
    ret = (*pInterfaceLibModeCapture)(capture->devDataHandle, &capture->captureParam,
                                      AUDIO_DRV_PCM_IOCTL_MMAP_BUFFER_CAPTURE);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("AudioCaptureReqMmapBuffer FAIL!");
        munmap(desc->memoryAddress, reqSize);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioCaptureReqMmapBuffer(AudioHandle handle, int32_t reqSize, struct AudioMmapBufferDescripter *desc)
{
    int32_t ret = AudioCheckCaptureAddr(handle);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The capture address passed in is invalid! ret = %{public}d", ret);
        return ret;
    }
    struct AudioHwCapture *capture = (struct AudioHwCapture *)handle;
    if (capture == NULL || capture->devDataHandle == NULL || desc == NULL) {
        AUDIO_FUNC_LOGE("capture or capture->devDataHandle or desc is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    ret = AudioCaptureReqMmapBufferInit(capture, reqSize, desc);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("AudioCaptureReqMmapBufferInit failed! ret = %{public}d", ret);
        return ret;
    }
    AUDIO_FUNC_LOGI("Success!");
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioCaptureGetMmapPosition(AudioHandle handle, uint64_t *frames, struct AudioTimeStamp *time)
{
    int32_t ret = AudioCheckCaptureAddr(handle);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The capture address passed in is invalid! ret = %{public}d", ret);
        return ret;
    }

    struct AudioHwCapture *capture = (struct AudioHwCapture *)handle;
    if (capture == NULL || frames == NULL || time == NULL) {
        AUDIO_FUNC_LOGE("capture or frames or time is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        AUDIO_FUNC_LOGE("pInterfaceLibModeCapture Fail!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (capture->devDataHandle == NULL) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = (*pInterfaceLibModeCapture)(capture->devDataHandle, &capture->captureParam,
                                              AUDIO_DRV_PCM_IOCTL_MMAP_POSITION_CAPTURE);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("GetMmapPosition SetParams FAIL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    AUDIO_FUNC_LOGI("GetMmapPosition SUCCESS!");
    *frames = capture->captureParam.frameCaptureMode.frames;
    capture->captureParam.frameCaptureMode.time.tvSec = (int64_t)(capture->captureParam.frameCaptureMode.frames /
        capture->captureParam.frameCaptureMode.attrs.sampleRate);
    uint64_t lastBufFrames = capture->captureParam.frameCaptureMode.frames %
        capture->captureParam.frameCaptureMode.attrs.sampleRate;
    capture->captureParam.frameCaptureMode.time.tvNSec =
        (int64_t)((lastBufFrames * SEC_TO_NSEC) / capture->captureParam.frameCaptureMode.attrs.sampleRate);
    *time = capture->captureParam.frameCaptureMode.time;
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioCaptureAddEffect(AudioHandle handle, uint64_t effectid)
{
    (void)handle;
    (void)effectid;
    AUDIO_FUNC_LOGI("add capture effect success");
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioCaptureRemoveEffect(AudioHandle handle, uint64_t effectid)
{
    (void)handle;
    (void)effectid;
    AUDIO_FUNC_LOGI("remove capture effect success");
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioCaptureTurnStandbyMode(AudioHandle handle)
{
    int32_t ret = AudioCheckCaptureAddr(handle);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The capture address passed in is invalid! ret = %{public}d", ret);
        return ret;
    }
    struct AudioHwCapture *capture = (struct AudioHwCapture *)handle;
    if (capture == NULL) {
        AUDIO_FUNC_LOGE("capture is null");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    capture->captureParam.captureMode.hwInfo.deviceDescript.pins = PIN_NONE;
    ret = AudioCaptureStop((AudioHandle)capture);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("AudioCaptureStop failed! ret = %{public}d", ret);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioCaptureAudioDevDump(AudioHandle handle, int32_t range, int32_t fd)
{
    uint32_t i;
    int32_t ret = AudioCheckCaptureAddr(handle);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The capture address passed in is invalid! ret = %{public}d", ret);
        return ret;
    }
    struct AudioHwCapture *capture = (struct AudioHwCapture *)handle;
    if (capture == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    dprintf(fd, "%s%d\n", "Number of errors: ", capture->errorLog.totalErrors);
    if (range < RANGE_MIN - 1 || range > RANGE_MAX) {
        dprintf(fd, "%s\n", "Out of range, invalid output");
        return AUDIO_HAL_SUCCESS;
    }
    uint32_t mSize = capture->errorLog.iter;
    if (range < RANGE_MIN) {
        dprintf(fd, "%-5s  %-10s  %s\n", "count", "errorCode", "Time");
        for (i = 0; i < mSize; i++) {
            dprintf(fd, FORMAT_TWO, capture->errorLog.errorDump[i].count + 1,
                    capture->errorLog.errorDump[i].errorCode,
                    capture->errorLog.errorDump[i].currentTime);
        }
    } else {
        dprintf(fd, "%-5s  %-10s  %-20s  %-15s  %s\n", "count", "errorCode", "frames", "fail reason", "Time");
        for (i = 0; i < mSize; i++) {
            dprintf(fd, FORMAT_ONE, capture->errorLog.errorDump[i].count + 1,
                    capture->errorLog.errorDump[i].errorCode,
                    capture->errorLog.errorDump[i].frames,
                    capture->errorLog.errorDump[i].reason,
                    capture->errorLog.errorDump[i].currentTime);
        }
    }
    return AUDIO_HAL_SUCCESS;
}
