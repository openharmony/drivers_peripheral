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
#include "audio_interface_lib_capture.h"
#include "audio_internal.h"

#define CONFIG_FRAME_SIZE      (1024 * 2 * 1)
#define FRAME_SIZE              1024

#define CONFIG_FRAME_COUNT     ((8000 * 2 * 1 + (CONFIG_FRAME_SIZE - 1)) / CONFIG_FRAME_SIZE)

/* add For Capture Bytes To Frames */
int32_t FormatToBitsCapture(enum AudioFormat format, uint32_t *formatBits)
{
    LOG_FUN_INFO();
    if (formatBits == NULL) {
        return HDF_FAILURE;
    }
    switch (format) {
        case AUDIO_FORMAT_PCM_32_BIT:
            *formatBits = BIT_NUM_32;
            return HDF_SUCCESS;
        case AUDIO_FORMAT_PCM_24_BIT:
            *formatBits = BIT_NUM_24;
            return HDF_SUCCESS;
        case AUDIO_FORMAT_PCM_16_BIT:
            *formatBits = BIT_NUM_16;
            return HDF_SUCCESS;
        case AUDIO_FORMAT_PCM_8_BIT:
            *formatBits = BIT_NUM_8;
            return HDF_SUCCESS;
        default:
            return HDF_ERR_NOT_SUPPORT;
    }
}

int32_t AudioCaptureStart(AudioHandle handle)
{
    LOG_FUN_INFO();
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL) {
        return HDF_FAILURE;
    }
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        LOG_FUN_ERR("pInterfaceLibModeCapture Fail!");
        return HDF_FAILURE;
    }
    if (hwCapture->captureParam.frameCaptureMode.buffer != NULL) {
        LOG_FUN_ERR("AudioCapture already start!");
        return HDF_FAILURE;
    }
    if (hwCapture->devDataHandle == NULL) {
        LOG_FUN_ERR("CaptureStart Bind Fail!");
        return HDF_FAILURE;
    }
    int32_t ret = (*pInterfaceLibModeCapture)(hwCapture->devDataHandle, &hwCapture->captureParam,
                                              AUDIO_DRV_PCM_IOCTRL_START_CAPTURE);
    if (ret < 0) {
        LOG_FUN_ERR("AudioCaptureStart SetParams FAIL");
        return HDF_FAILURE;
    }
    char *tbuffer = (char *)calloc(1, FRAME_DATA);
    if (tbuffer == NULL) {
        LOG_FUN_ERR("Calloc Capture tbuffer Fail!");
        return HDF_FAILURE;
    }
    hwCapture->captureParam.frameCaptureMode.buffer = tbuffer;
    LOG_PARA_INFO("Capture Start SUCCESS!");
    return HDF_SUCCESS;
}

int32_t AudioCaptureStop(AudioHandle handle)
{
    LOG_FUN_INFO();
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL) {
        return HDF_FAILURE;
    }
    if (hwCapture->devDataHandle == NULL) {
        LOG_FUN_ERR("CaptureStart Bind Fail!");
        return HDF_FAILURE;
    }
    if (hwCapture->captureParam.frameCaptureMode.buffer != NULL) {
        AudioMemFree((void **)&hwCapture->captureParam.frameCaptureMode.buffer);
    } else {
        LOG_FUN_ERR("AudioCapture already stop!");
        return HDF_ERR_INVALID_OBJECT;
    }
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        LOG_FUN_ERR("pInterfaceLibModeCapture Fail!");
        return HDF_FAILURE;
    }
    int32_t ret = (*pInterfaceLibModeCapture)(hwCapture->devDataHandle, &hwCapture->captureParam,
                                              AUDIO_DRV_PCM_IOCTRL_STOP_CAPTURE);
    if (ret < 0) {
        LOG_FUN_ERR("AudioCaptureStart SetParams FAIL");
        return HDF_FAILURE;
    }
    LOG_PARA_INFO("Capture Stop SUCCESS!");
    return HDF_SUCCESS;
}

int32_t AudioCapturePause(AudioHandle handle)
{
    LOG_FUN_INFO();
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL) {
        return HDF_FAILURE;
    }
    if (hwCapture->captureParam.frameCaptureMode.buffer == NULL) {
        LOG_FUN_ERR("AudioCapture already stop!");
        return HDF_FAILURE;
    }
    if (hwCapture->captureParam.captureMode.ctlParam.pause) {
        LOG_FUN_ERR("Audio capture is already pause!");
        return HDF_FAILURE;
    }
    if (hwCapture->devDataHandle == NULL) {
        LOG_FUN_ERR("CaptureStart Bind Fail!");
        return HDF_FAILURE;
    }
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        LOG_FUN_ERR("pInterfaceLibModeCapture Fail!");
        return HDF_FAILURE;
    }
    bool pauseStatus = hwCapture->captureParam.captureMode.ctlParam.pause;
    hwCapture->captureParam.captureMode.ctlParam.pause = true;
    int32_t ret = (*pInterfaceLibModeCapture)(hwCapture->devDataHandle, &hwCapture->captureParam,
                                              AUDIODRV_CTL_IOCTL_PAUSE_WRITE_CAPTURE);
    if (ret < 0) {
        LOG_FUN_ERR("Audio Capture Pause FAIL!");
        hwCapture->captureParam.captureMode.ctlParam.pause = pauseStatus;
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCaptureResume(AudioHandle handle)
{
    LOG_FUN_INFO();
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL) {
        return HDF_FAILURE;
    }
    if (!hwCapture->captureParam.captureMode.ctlParam.pause) {
        LOG_FUN_ERR("Audio capture is already Resume !");
        return HDF_FAILURE;
    }
    if (hwCapture->devDataHandle == NULL) {
        LOG_FUN_ERR("Capture Start Bind Fail!");
        return HDF_FAILURE;
    }
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        LOG_FUN_ERR("pInterfaceLibModeCapture Fail!");
        return HDF_FAILURE;
    }
    bool resumeStatus = hwCapture->captureParam.captureMode.ctlParam.pause;
    hwCapture->captureParam.captureMode.ctlParam.pause = false;
    int32_t ret = (*pInterfaceLibModeCapture)(hwCapture->devDataHandle, &hwCapture->captureParam,
                                              AUDIODRV_CTL_IOCTL_PAUSE_WRITE_CAPTURE);
    if (ret < 0) {
        LOG_FUN_ERR("Audio capture Pause FAIL!");
        hwCapture->captureParam.captureMode.ctlParam.pause = resumeStatus;
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCaptureFlush(AudioHandle handle)
{
    LOG_FUN_INFO();
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL) {
        return HDF_FAILURE;
    }
    return HDF_ERR_NOT_SUPPORT;
}

int32_t AudioCaptureGetFrameSize(AudioHandle handle, uint64_t *size)
{
    LOG_FUN_INFO();
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL || size == NULL) {
        return HDF_FAILURE;
    }
    uint32_t channelCount = hwCapture->captureParam.frameCaptureMode.attrs.channelCount;
    enum AudioFormat format = hwCapture->captureParam.frameCaptureMode.attrs.format;
    uint32_t formatBitsCapture = 0;
    int32_t ret = FormatToBitsCapture(format, &formatBitsCapture);
    if (ret != HDF_SUCCESS) {
        return ret;
    }
    *size = FRAME_SIZE * channelCount * (formatBitsCapture >> 3);
    return HDF_SUCCESS;
}

int32_t AudioCaptureGetFrameCount(AudioHandle handle, uint64_t *count)
{
    LOG_FUN_INFO();
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL || count == NULL) {
        return HDF_FAILURE;
    }
    *count = hwCapture->captureParam.frameCaptureMode.frames;
    return HDF_SUCCESS;
}

int32_t AudioCaptureSetSampleAttributes(AudioHandle handle, const struct AudioSampleAttributes *attrs)
{
    LOG_FUN_INFO();
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL || attrs == NULL) {
        return HDF_FAILURE;
    }
    int32_t ret = AudioCheckParaAttr(attrs);
    if (ret != HDF_SUCCESS) {
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
        LOG_FUN_ERR("pInterfaceLibModeCapture Fail!");
        return HDF_FAILURE;
    }
    if (hwCapture->devDataHandle == NULL) {
        hwCapture->captureParam.frameCaptureMode.attrs = tempAttrs;
        return HDF_FAILURE;
    }
    ret = (*pInterfaceLibModeCapture)(hwCapture->devDataHandle, &hwCapture->captureParam,
                                              AUDIO_DRV_PCM_IOCTL_HW_PARAMS);
    if (ret < 0) {
        LOG_FUN_ERR("CaptureSetSampleAttributes FAIL");
        hwCapture->captureParam.frameCaptureMode.attrs = tempAttrs;
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCaptureGetSampleAttributes(AudioHandle handle, struct AudioSampleAttributes *attrs)
{
    LOG_FUN_INFO();
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL || attrs == NULL) {
        return HDF_FAILURE;
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
    return HDF_SUCCESS;
}

int32_t AudioCaptureGetCurrentChannelId(AudioHandle handle, uint32_t *channelId)
{
    LOG_FUN_INFO();
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL || channelId == NULL) {
        return HDF_FAILURE;
    }
    *channelId = hwCapture->captureParam.frameCaptureMode.attrs.channelCount;
    return HDF_SUCCESS;
}

int32_t AudioCaptureCheckSceneCapability(AudioHandle handle, const struct AudioSceneDescriptor *scene,
                                         bool *supported)
{
    LOG_FUN_INFO();
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL || scene == NULL || supported == NULL) {
        return HDF_FAILURE;
    }
#ifndef AUDIO_HAL_NOTSUPPORT_PATHSELECT
    *supported = false;
    /* Temporary storage does not save the structure */
    struct AudioHwCaptureParam captureParam;
    captureParam.frameCaptureMode.attrs.type = (enum AudioCategory)scene->scene.id;
    captureParam.captureMode.hwInfo.deviceDescript.pins = scene->desc.pins;
    PathSelAnalysisJson *pPathSelAnalysisJson = AudioSoGetPathSelAnalysisJson();
    if (pPathSelAnalysisJson == NULL || *pPathSelAnalysisJson == NULL) {
        LOG_FUN_ERR("pPathSelAnalysisJson Is NULL!");
        return HDF_ERR_NOT_SUPPORT;
    }
    int ret = (*pPathSelAnalysisJson)((void *)&captureParam, CHECKSCENE_PATH_SELECT_CAPTURE);
    if (ret < 0) {
        if (ret == HDF_ERR_NOT_SUPPORT) {
            LOG_FUN_ERR("AudioCaptureCheckSceneCapability not Support!");
            return HDF_ERR_NOT_SUPPORT;
        } else {
            LOG_FUN_ERR("AudioCaptureCheckSceneCapability fail!");
            return HDF_FAILURE;
        }
    }
    *supported = true;
    return HDF_SUCCESS;
#else
    return HDF_ERR_NOT_SUPPORT;
#endif
}

int32_t AudioCaptureSelectScene(AudioHandle handle, const struct AudioSceneDescriptor *scene)
{
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL || scene == NULL) {
        return HDF_FAILURE;
    }
    if (hwCapture->devCtlHandle == NULL) {
        LOG_FUN_ERR("CaptureSelectScene Bind Fail!");
        return HDF_FAILURE;
    }
#ifndef AUDIO_HAL_NOTSUPPORT_PATHSELECT
    PathSelAnalysisJson *pPathSelAnalysisJson = AudioSoGetPathSelAnalysisJson();
    if (pPathSelAnalysisJson == NULL || *pPathSelAnalysisJson == NULL) {
        LOG_FUN_ERR("pPathSelAnalysisJson Is NULL!");
        return HDF_ERR_NOT_SUPPORT;
    }
    enum AudioCategory typeTemp = hwCapture->captureParam.frameCaptureMode.attrs.type;
    enum AudioPortPin pinsTemp = hwCapture->captureParam.captureMode.hwInfo.deviceDescript.pins;
    hwCapture->captureParam.frameCaptureMode.attrs.type = (enum AudioCategory)(scene->scene.id);
    hwCapture->captureParam.captureMode.hwInfo.deviceDescript.pins = scene->desc.pins;
    if ((*pPathSelAnalysisJson)((void *)&hwCapture->captureParam, CAPTURE_PATH_SELECT) < 0) {
        LOG_FUN_ERR("AudioCaptureSelectScene Fail!");
        hwCapture->captureParam.frameCaptureMode.attrs.type = typeTemp;
        hwCapture->captureParam.captureMode.hwInfo.deviceDescript.pins = pinsTemp;
        return HDF_FAILURE;
    }
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        LOG_FUN_ERR("pInterfaceLibModeCapture Is NULL");
        hwCapture->captureParam.frameCaptureMode.attrs.type = typeTemp;
        hwCapture->captureParam.captureMode.hwInfo.deviceDescript.pins = pinsTemp;
        return HDF_FAILURE;
    }
    int32_t ret = (*pInterfaceLibModeCapture)(hwCapture->devCtlHandle, &hwCapture->captureParam,
                                              AUDIODRV_CTL_IOCTL_SCENESELECT_CAPTURE);
    if (ret < 0) {
        LOG_FUN_ERR("SetSelectSceneParams FAIL!");
        hwCapture->captureParam.frameCaptureMode.attrs.type = typeTemp;
        hwCapture->captureParam.captureMode.hwInfo.deviceDescript.pins = pinsTemp;
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
#else
    return HDF_ERR_NOT_SUPPORT;
#endif
}

int32_t AudioCaptureSetMute(AudioHandle handle, bool mute)
{
    LOG_FUN_INFO();
    struct AudioHwCapture *impl = (struct AudioHwCapture *)handle;
    if (impl == NULL) {
        return HDF_FAILURE;
    }
    if (impl->devCtlHandle == NULL) {
        LOG_FUN_ERR("CaptureSetMute Bind Fail!");
        return HDF_FAILURE;
    }
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        LOG_FUN_ERR("pInterfaceLibModeCapture Fail!");
        return HDF_FAILURE;
    }
    bool muteStatus = impl->captureParam.captureMode.ctlParam.mute;
    impl->captureParam.captureMode.ctlParam.mute = mute;
    int32_t ret = (*pInterfaceLibModeCapture)(impl->devCtlHandle, &impl->captureParam,
                                              AUDIODRV_CTL_IOCTL_MUTE_WRITE_CAPTURE);
    if (ret < 0) {
        LOG_FUN_ERR("SetMute SetParams FAIL");
        impl->captureParam.captureMode.ctlParam.mute = muteStatus;
        return HDF_FAILURE;
    }
    LOG_PARA_INFO("SetMute SUCCESS!");
    return HDF_SUCCESS;
}

int32_t AudioCaptureGetMute(AudioHandle handle, bool *mute)
{
    LOG_FUN_INFO();
    struct AudioHwCapture *impl = (struct AudioHwCapture *)handle;
    if (impl == NULL || mute == NULL) {
        return HDF_FAILURE;
    }
    if (impl->devCtlHandle == NULL) {
        LOG_FUN_ERR("CaptureGetMute Bind Fail!");
        return HDF_FAILURE;
    }
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        LOG_FUN_ERR("pInterfaceLibModeCapture Fail!");
        return HDF_FAILURE;
    }
    int32_t ret = (*pInterfaceLibModeCapture)(impl->devCtlHandle, &impl->captureParam,
                                              AUDIODRV_CTL_IOCTL_MUTE_READ_CAPTURE);
    if (ret < 0) {
        LOG_FUN_ERR("GetMute SetParams FAIL");
        return HDF_FAILURE;
    }
    *mute = impl->captureParam.captureMode.ctlParam.mute;
    LOG_PARA_INFO("Get Mute SUCCESS!");
    return HDF_SUCCESS;
}

int32_t AudioCaptureSetVolume(AudioHandle handle, float volume)
{
    LOG_FUN_INFO();
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL) {
        return HDF_FAILURE;
    }
    float volumeTemp = hwCapture->captureParam.captureMode.ctlParam.volume;
    float volMax = (float)hwCapture->captureParam.captureMode.ctlParam.volThreshold.volMax;
    float volMin = (float)hwCapture->captureParam.captureMode.ctlParam.volThreshold.volMin;
    if (hwCapture->devCtlHandle == NULL) {
        LOG_FUN_ERR("Bind Fail!");
        return HDF_FAILURE;
    }
    if (volume < 0 || volume > 1) {
        LOG_FUN_ERR("volume param Is error!");
        return HDF_FAILURE;
    }
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        LOG_FUN_ERR("pInterfaceLibModeCapture Fail!");
        return HDF_FAILURE;
    }
    volume = (volume == 0) ? 1 : (volume * VOLUME_CHANGE);
    /* change volume to db */
    float volTemp = ((volMax - volMin) / 2) * log10(volume) + volMin;
    if (volTemp < volMin || volTemp > volMax) {
        LOG_FUN_ERR("volTemp fail");
        return HDF_FAILURE;
    }
    hwCapture->captureParam.captureMode.ctlParam.volume = volTemp;
    int32_t ret = (*pInterfaceLibModeCapture)(hwCapture->devCtlHandle, &hwCapture->captureParam,
                                              AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE);
    if (ret < 0) {
        LOG_FUN_ERR("SetParams FAIL!");
        hwCapture->captureParam.captureMode.ctlParam.volume = volumeTemp;
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCaptureGetVolume(AudioHandle handle, float *volume)
{
    LOG_FUN_INFO();
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (NULL == hwCapture || NULL == volume) {
        return HDF_FAILURE;
    }
    if (hwCapture->devCtlHandle == NULL) {
        LOG_FUN_ERR("CaptureStart Bind Fail!");
        return HDF_FAILURE;
    }
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        LOG_FUN_ERR("pInterfaceLibModeCapture Fail!");
        return HDF_FAILURE;
    }
    int ret = (*pInterfaceLibModeCapture)(hwCapture->devCtlHandle, &hwCapture->captureParam,
                                          AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE);
    if (ret < 0) {
        LOG_FUN_ERR("Get Volume FAIL!");
        return HDF_FAILURE;
    }
    float volumeTemp = hwCapture->captureParam.captureMode.ctlParam.volume;
    float volMax = (float)hwCapture->captureParam.captureMode.ctlParam.volThreshold.volMax;
    float volMin = (float)hwCapture->captureParam.captureMode.ctlParam.volThreshold.volMin;
    if ((volMax - volMin) == 0) {
        LOG_FUN_ERR("Divisor cannot be zero!");
        return HDF_FAILURE;
    }
    volumeTemp = (volumeTemp - volMin) / ((volMax - volMin) / 2);
    int volumeT = (int)((pow(10, volumeTemp) + 5) / 10); // delet 0.X num
    *volume = (float)volumeT / 10;  // get volume (0-1)
    return HDF_SUCCESS;
}

int32_t AudioCaptureGetGainThreshold(AudioHandle handle, float *min, float *max)
{
    LOG_FUN_INFO();
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL || min == NULL || max == NULL) {
        return HDF_FAILURE;
    }
    if (hwCapture->devCtlHandle == NULL) {
        LOG_FUN_ERR("AudioCaptureGetGainThreshold Bind Fail!");
        return HDF_FAILURE;
    }
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        LOG_FUN_ERR("pInterfaceLibModeCapture Is NULL");
        return HDF_FAILURE;
    }
    int32_t ret = (*pInterfaceLibModeCapture)(hwCapture->devCtlHandle, &hwCapture->captureParam,
                                              AUDIODRV_CTL_IOCTL_GAINTHRESHOLD_CAPTURE);
    if (ret < 0) {
        LOG_FUN_ERR("SetParams FAIL!");
        return HDF_FAILURE;
    }
    *max = hwCapture->captureParam.captureMode.ctlParam.audioGain.gainMax;
    *min = hwCapture->captureParam.captureMode.ctlParam.audioGain.gainMin;
    return HDF_SUCCESS;
}

int32_t AudioCaptureGetGain(AudioHandle handle, float *gain)
{
    LOG_FUN_INFO();
    struct AudioHwCapture *impl = (struct AudioHwCapture *)handle;
    if (impl == NULL || gain == NULL) {
        return HDF_FAILURE;
    }
    if (impl->devCtlHandle == NULL) {
        LOG_FUN_ERR("CaptureStart Bind Fail!");
        return HDF_FAILURE;
    }
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        LOG_FUN_ERR("pInterfaceLibModeCapture Fail!");
        return HDF_FAILURE;
    }
    int32_t ret = (*pInterfaceLibModeCapture)(impl->devCtlHandle, &impl->captureParam,
                                              AUDIODRV_CTL_IOCTL_GAIN_READ_CAPTURE);
    if (ret < 0) {
        LOG_FUN_ERR("Get Volume FAIL!");
        return HDF_FAILURE;
    }
    *gain = impl->captureParam.captureMode.ctlParam.audioGain.gain;
    return HDF_SUCCESS;
}

int32_t AudioCaptureSetGain(AudioHandle handle, float gain)
{
    LOG_FUN_INFO();
    struct AudioHwCapture *impl = (struct AudioHwCapture *)handle;
    if (impl == NULL) {
        return HDF_FAILURE;
    }
    if (impl->devCtlHandle == NULL) {
        LOG_FUN_ERR("CaptureSetGain Bind Fail!");
        return HDF_FAILURE;
    }
    float gainTemp = impl->captureParam.captureMode.ctlParam.audioGain.gain;
    impl->captureParam.captureMode.ctlParam.audioGain.gain = gain;
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        LOG_FUN_ERR("pInterfaceLibModeCapture Fail!");
        impl->captureParam.captureMode.ctlParam.audioGain.gain = gainTemp;
        return HDF_FAILURE;
    }
    int32_t ret = (*pInterfaceLibModeCapture)(impl->devCtlHandle, &impl->captureParam,
                                              AUDIODRV_CTL_IOCTL_GAIN_WRITE_CAPTURE);
    if (ret < 0) {
        LOG_FUN_ERR("CaptureSetGain FAIL!");
        impl->captureParam.captureMode.ctlParam.audioGain.gain = gainTemp;
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t TimeToAudioTimeStampCapture(int64_t *totalTime, struct AudioTimeStamp *time)
{
    if (totalTime == NULL || time == NULL) {
        return HDF_FAILURE;
    }
    time->tvSec += (int64_t)(*totalTime) / SEC_TO_NSEC;
    time->tvNSec += (int64_t)(*totalTime) % SEC_TO_NSEC;
    int64_t carryBit = (int64_t)(time->tvNSec) / SEC_TO_NSEC;
    if (carryBit) {
        time->tvSec += carryBit;
        time->tvNSec -= (int64_t)carryBit * SEC_TO_NSEC;
    }
    return HDF_SUCCESS;
}

int32_t AudioCaptureCaptureFrame(struct AudioCapture *capture, void *frame,
                                 uint64_t requestBytes, uint64_t *replyBytes)
{
    LOG_FUN_INFO();
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    if (hwCapture == NULL || frame == NULL || replyBytes == NULL ||
        hwCapture->captureParam.frameCaptureMode.buffer == NULL) {
        LOG_FUN_ERR("Param is NULL Fail!");
        return HDF_FAILURE;
    }
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        LOG_FUN_ERR("pInterfaceLibModeCapture Fail!");
        return HDF_FAILURE;
    }
    if (hwCapture->devDataHandle == NULL) {
        return HDF_FAILURE;
    }
    memset_s(hwCapture->captureParam.frameCaptureMode.buffer, FRAME_DATA, 0, FRAME_DATA);
    int32_t ret = (*pInterfaceLibModeCapture)(hwCapture->devDataHandle, &hwCapture->captureParam,
                                              AUDIO_DRV_PCM_IOCTL_READ);
    if (ret < 0) {
        LOG_FUN_ERR("Capture Frame FAIL!");
        return HDF_FAILURE;
    }
    if (requestBytes < hwCapture->captureParam.frameCaptureMode.bufferSize) {
        LOG_FUN_ERR("Capture Frame requestBytes too little!");
        return HDF_FAILURE;
    }
    ret = memcpy_s(frame, requestBytes, hwCapture->captureParam.frameCaptureMode.buffer,
        hwCapture->captureParam.frameCaptureMode.bufferSize);
    if (ret != EOK) {
        LOG_FUN_ERR("memcpy_s fail");
        return HDF_FAILURE;
    }
    *replyBytes = hwCapture->captureParam.frameCaptureMode.bufferSize;
    hwCapture->captureParam.frameCaptureMode.frames += hwCapture->captureParam.frameCaptureMode.bufferFrameSize;
    if (hwCapture->captureParam.frameCaptureMode.attrs.sampleRate == 0) {
        LOG_FUN_ERR("Divisor cannot be zero!");
        return HDF_FAILURE;
    }
    int64_t totalTime = (hwCapture->captureParam.frameCaptureMode.bufferFrameSize * SEC_TO_NSEC) /
                        (int64_t)hwCapture->captureParam.frameCaptureMode.attrs.sampleRate;
    if (TimeToAudioTimeStampCapture(&totalTime, &hwCapture->captureParam.frameCaptureMode.time) == HDF_FAILURE) {
        LOG_FUN_ERR("Frame is NULL");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCaptureGetCapturePosition(struct AudioCapture *capture, uint64_t *frames, struct AudioTimeStamp *time)
{
    LOG_FUN_INFO();
    struct AudioHwCapture *impl = (struct AudioHwCapture *)capture;
    if (impl == NULL || frames == NULL || time == NULL) {
        return HDF_FAILURE;
    }
    *frames = impl->captureParam.frameCaptureMode.frames;
    *time = impl->captureParam.frameCaptureMode.time;

    return HDF_SUCCESS;
}
