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

#include "alsa_lib_render.h"

#define HDF_LOG_TAG HDF_AUDIO_HAL_RENDER

int32_t AudioCtlRenderSetVolume(
    const struct DevHandle *handle, int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    long vol;
    struct AlsaRender *renderIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    renderIns = RenderGetInstance(handleData->renderMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);

    vol = (long)handleData->renderMode.ctlParam.volume;
    ret = renderIns->SetVolume(renderIns, vol);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Render SetVolume fail!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioCtlRenderGetVolume(
    const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    long vol;
    struct AlsaRender *renderIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    renderIns = RenderGetInstance(handleData->renderMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);

    ret = renderIns->GetVolume(renderIns, &vol);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Render GetVolume failed!");
        return HDF_FAILURE;
    }
    handleData->renderMode.ctlParam.volume = (float)vol;

    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSetPauseStu(
    const struct DevHandle *handle, int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    struct AlsaRender *renderIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    renderIns = RenderGetInstance(handleData->renderMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);

    ret = renderIns->SetPauseState(renderIns, handleData->renderMode.ctlParam.pause);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Render set pause failed!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSetMuteStu(
    const struct DevHandle *handle, int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    struct AlsaRender *renderIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    renderIns = RenderGetInstance(handleData->renderMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);

    ret = renderIns->SetMute(renderIns, handleData->renderMode.ctlParam.mute);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Render SetMute failed!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioCtlRenderGetMuteStu(
    const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    struct AlsaRender *renderIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    renderIns = RenderGetInstance(handleData->renderMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);
    handleData->renderMode.ctlParam.mute = renderIns->GetMute(renderIns);

    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSetGainStu(
    const struct DevHandle *handle, int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    float gainValue;
    struct AlsaRender *renderIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    renderIns = RenderGetInstance(handleData->renderMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);

    gainValue = handleData->renderMode.ctlParam.audioGain.gain;
    ret = renderIns->SetGain(renderIns, gainValue);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Render set gain failed!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioCtlRenderGetGainStu(
    const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    float gainValue;
    struct AlsaRender *renderIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    renderIns = RenderGetInstance(handleData->renderMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);

    ret = renderIns->GetGain(renderIns, &gainValue);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Render get gain failed!");
        return HDF_FAILURE;
    }
    handleData->renderMode.ctlParam.audioGain.gain = gainValue;

    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSceneSelect(
    const struct DevHandle *handle, int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    enum AudioPortPin descPins;
    const struct PathDeviceInfo *deviceInfo;
    struct AlsaRender *renderIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    renderIns = RenderGetInstance(handleData->renderMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);

    descPins = handleData->renderMode.hwInfo.deviceDescript.pins;
    deviceInfo = &handleData->renderMode.hwInfo.pathSelect.deviceInfo;
    ret = renderIns->SelectScene(renderIns, descPins, deviceInfo);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Render select scene pin: (0x%{public}x) failed!", descPins);
        return HDF_FAILURE;
    }

    AUDIO_FUNC_LOGD("Render scene select pin: (0x%{public}x) success", descPins);
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSceneGetGainThreshold(
    const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    float gainMin = 0.0;
    float gainMax = 1.0;
    struct AlsaRender *renderIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    renderIns = RenderGetInstance(handleData->renderMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);

    ret = renderIns->GetGainThreshold(renderIns, &gainMin, &gainMax);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Render get gain threshold failed");
        return HDF_FAILURE;
    }
    handleData->renderMode.ctlParam.audioGain.gainMin = gainMin;
    handleData->renderMode.ctlParam.audioGain.gainMax = gainMax;

    return HDF_SUCCESS;
}

int32_t AudioCtlRenderGetVolThreshold(
    const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    long volMin = MIN_VOLUME;
    long volMax = MIN_VOLUME;
    struct AlsaRender *renderIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    renderIns = RenderGetInstance(handleData->renderMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);

    ret = renderIns->GetVolThreshold(renderIns, &volMin, &volMax);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Render get volume threshold failed!");
        return HDF_FAILURE;
    }
    handleData->renderMode.ctlParam.volThreshold.volMin = (int)volMin;
    handleData->renderMode.ctlParam.volThreshold.volMax = (int)volMax;

    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSetChannelMode(
    const struct DevHandle *handle, int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    enum AudioChannelMode mode;
    struct AlsaRender *renderIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    renderIns = RenderGetInstance(handleData->renderMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);

    mode = handleData->frameRenderMode.mode;
    ret = renderIns->SetChannelMode(renderIns, mode);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Render set channel mode failed!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioCtlRenderGetChannelMode(
    const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    enum AudioChannelMode mode;
    struct AlsaRender *renderIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    renderIns = RenderGetInstance(handleData->renderMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);

    ret = renderIns->GetChannelMode(renderIns, &mode);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Render get channel mode failed!");
        return HDF_FAILURE;
    }
    handleData->frameRenderMode.mode = mode;

    return HDF_SUCCESS;
}

int32_t AudioInterfaceLibCtlRender(
    const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    switch (cmdId) {
        case AUDIODRV_CTL_IOCTL_ELEM_READ:
            return (AudioCtlRenderGetVolume(handle, cmdId, handleData));
        case AUDIODRV_CTL_IOCTL_ELEM_WRITE:
            return (AudioCtlRenderSetVolume(handle, cmdId, handleData));
        case AUDIODRV_CTL_IOCTL_MUTE_READ:
            return (AudioCtlRenderGetMuteStu(handle, cmdId, handleData));
        case AUDIODRV_CTL_IOCTL_MUTE_WRITE:
            return (AudioCtlRenderSetMuteStu(handle, cmdId, handleData));
        case AUDIODRV_CTL_IOCTL_CHANNEL_MODE_READ:
            return (AudioCtlRenderGetChannelMode(handle, cmdId, handleData));
        case AUDIODRV_CTL_IOCTL_CHANNEL_MODE_WRITE:
            return (AudioCtlRenderSetChannelMode(handle, cmdId, handleData));
        case AUDIODRV_CTL_IOCTL_GAIN_WRITE:
            return (AudioCtlRenderSetGainStu(handle, cmdId, handleData));
        case AUDIODRV_CTL_IOCTL_GAIN_READ:
            return (AudioCtlRenderGetGainStu(handle, cmdId, handleData));
        case AUDIODRV_CTL_IOCTL_SCENESELECT_WRITE:
            return (AudioCtlRenderSceneSelect(handle, cmdId, handleData));
        case AUDIODRV_CTL_IOCTL_GAINTHRESHOLD_READ:
            return (AudioCtlRenderSceneGetGainThreshold(handle, cmdId, handleData));
        case AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ:
            return (AudioCtlRenderGetVolThreshold(handle, cmdId, handleData));
        default:
            AUDIO_FUNC_LOGE("Output Mode not support!");
            break;
    }

    return HDF_FAILURE;
}

int32_t AudioOutputRenderHwParams(
    const struct DevHandle *handle, int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    struct AlsaRender *renderIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    renderIns = RenderGetInstance(handleData->renderMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns->soundCard.pcmHandle);

    if (SndGetRunState(&renderIns->soundCard) >= SND_PCM_STATE_RUNNING) {
        AUDIO_FUNC_LOGE("Unable to set parameters during playback!");
        return HDF_FAILURE;
    }

    ret = RenderSetParams(renderIns, handleData);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Render set parameters failed!");
        return HDF_FAILURE;
    }

    AUDIO_FUNC_LOGI("Render set parameters success.");
    return HDF_SUCCESS;
}

/*
 * brief: Opens a PCM
 * param mode Open mode (see #SND_PCM_NONBLOCK, #SND_PCM_ASYNC)
 */
int32_t AudioOutputRenderOpen(
    const struct DevHandle *handle, int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    struct AlsaRender *renderIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    renderIns = RenderCreateInstance(handleData->renderMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);

    ret = renderIns->Open(renderIns);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Render open pcm failed!");
        return HDF_FAILURE;
    }

    ret = renderIns->Init(renderIns);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Render init failed!");
        return HDF_FAILURE;
    }

    AUDIO_FUNC_LOGI("Render open success.");
    return HDF_SUCCESS;
}

int32_t AudioOutputRenderWrite(
    const struct DevHandle *handle, int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    struct AlsaRender *renderIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    renderIns = RenderGetInstance(handleData->renderMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);

    ret = renderIns->Write(renderIns, handleData);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Render wirte frame failed!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioOutputRenderPrepare(
    const struct DevHandle *handle, int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    struct AlsaRender *renderIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    renderIns = RenderGetInstance(handleData->renderMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);

    ret = SndPcmPrepare(&renderIns->soundCard);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Render pcm prepare failed");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioOutputRenderStart(
    const struct DevHandle *handle, int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    struct AlsaRender *renderIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    renderIns = RenderGetInstance(handleData->renderMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);

    ret = renderIns->Start(renderIns);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Render start failed!");
        return ret;
    }

    AUDIO_FUNC_LOGI("Render start success.");
    return HDF_SUCCESS;
}

int32_t AudioOutputRenderStop(
    const struct DevHandle *handle, int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    struct AlsaRender *renderIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    renderIns = RenderGetInstance(handleData->renderMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);

    ret = renderIns->Stop(renderIns);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Render stop failed!");
        return ret;
    }

    AUDIO_FUNC_LOGI("Render stop success.");
    return HDF_SUCCESS;
}

int32_t AudioOutputRenderClose(
    const struct DevHandle *handle, int cmdId, const struct AudioHwRenderParam *handleData)
{
    struct AlsaRender *renderIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    renderIns = RenderGetInstance(handleData->renderMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);

    renderIns->Close(renderIns);

    AUDIO_FUNC_LOGI("Render close success.");
    return HDF_SUCCESS;
}

int32_t AudioOutputRenderReqMmapBuffer(
    const struct DevHandle *handle, int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    struct AlsaRender *renderIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    renderIns = RenderGetInstance(handleData->renderMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);

    ret = renderIns->MmapWrite(renderIns, handleData);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Render MmapWrite error!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioOutputRenderGetMmapPosition(
    const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    struct AlsaRender *renderIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    renderIns = RenderGetInstance(handleData->renderMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);

    handleData->frameRenderMode.frames = renderIns->GetMmapPosition(renderIns);

    return HDF_SUCCESS;
}

int32_t AudioInterfaceLibOutputRender(
    const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    switch (cmdId) {
        case AUDIO_DRV_PCM_IOCTL_HW_PARAMS:
            ret = AudioOutputRenderHwParams(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTL_WRITE:
            ret = AudioOutputRenderWrite(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTRL_STOP:
            ret = AudioOutputRenderStop(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTRL_START:
            ret = AudioOutputRenderStart(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTL_PREPARE:
            ret = AudioOutputRenderPrepare(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE:
            ret = AudioOutputRenderClose(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN:
            ret = AudioOutputRenderOpen(handle, cmdId, handleData);
            break;
        case AUDIODRV_CTL_IOCTL_PAUSE_WRITE:
            ret = AudioCtlRenderSetPauseStu(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTL_MMAP_BUFFER:
            ret = AudioOutputRenderReqMmapBuffer(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTL_MMAP_POSITION:
            ret = (AudioOutputRenderGetMmapPosition(handle, cmdId, handleData));
            break;
        default:
            AUDIO_FUNC_LOGE("Output Mode not support!");
            ret = HDF_FAILURE;
            break;
    }

    return ret;
}

int32_t AudioInterfaceLibModeRender(
    const struct DevHandle *handle, struct AudioHwRenderParam *handleData, int cmdId)
{
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    switch (cmdId) {
        case AUDIO_DRV_PCM_IOCTL_HW_PARAMS:
        case AUDIO_DRV_PCM_IOCTL_WRITE:
        case AUDIO_DRV_PCM_IOCTRL_STOP:
        case AUDIO_DRV_PCM_IOCTRL_START:
        case AUDIO_DRV_PCM_IOCTL_PREPARE:
        case AUDIODRV_CTL_IOCTL_PAUSE_WRITE:
        case AUDIO_DRV_PCM_IOCTL_MMAP_BUFFER:
        case AUDIO_DRV_PCM_IOCTL_MMAP_POSITION:
        case AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN:
        case AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE:
            return (AudioInterfaceLibOutputRender(handle, cmdId, handleData));
        case AUDIODRV_CTL_IOCTL_ELEM_WRITE:
        case AUDIODRV_CTL_IOCTL_ELEM_READ:
        case AUDIODRV_CTL_IOCTL_MUTE_WRITE:
        case AUDIODRV_CTL_IOCTL_MUTE_READ:
        case AUDIODRV_CTL_IOCTL_GAIN_WRITE:
        case AUDIODRV_CTL_IOCTL_GAIN_READ:
        case AUDIODRV_CTL_IOCTL_CHANNEL_MODE_WRITE:
        case AUDIODRV_CTL_IOCTL_CHANNEL_MODE_READ:
        case AUDIODRV_CTL_IOCTL_SCENESELECT_WRITE:
        case AUDIODRV_CTL_IOCTL_GAINTHRESHOLD_READ:
        case AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ:
            return (AudioInterfaceLibCtlRender(handle, cmdId, handleData));
        default:
            AUDIO_FUNC_LOGE("Mode Error!");
            break;
    }
    return HDF_ERR_NOT_SUPPORT;
}
