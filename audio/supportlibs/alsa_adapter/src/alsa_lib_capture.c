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

#include "alsa_lib_capture.h"

#define HDF_LOG_TAG HDF_AUDIO_HAL_CAPTURE

int32_t AudioCtlCaptureSetPauseStu(
    const struct DevHandle *handle, int cmdId, const struct AudioHwCaptureParam *handleData)
{
    int32_t ret;
    struct AlsaCapture *captureIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    captureIns = CaptureGetInstance(handleData->captureMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(captureIns);

    ret = captureIns->SetPauseState(captureIns, handleData->captureMode.ctlParam.pause);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Capture set pause failed!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureGetVolume(
    const struct DevHandle *handle, int cmdId, struct AudioHwCaptureParam *handleData)
{
    int32_t ret;
    long vol;
    struct AlsaCapture *captureIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    captureIns = CaptureGetInstance(handleData->captureMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(captureIns);

    ret = captureIns->GetVolume(captureIns, &vol);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Capture GetVolume failed!");
        return HDF_FAILURE;
    }
    handleData->captureMode.ctlParam.volume = (float)vol;

    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureSetVolume(
    const struct DevHandle *handle, int cmdId, const struct AudioHwCaptureParam *handleData)
{
    int32_t ret;
    long vol;
    struct AlsaCapture *captureIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    captureIns = CaptureGetInstance(handleData->captureMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(captureIns);

    vol = (long)handleData->captureMode.ctlParam.volume;
    ret = captureIns->SetVolume(captureIns, vol);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Capture SetVolume fail!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureSetMuteStu(
    const struct DevHandle *handle, int cmdId, const struct AudioHwCaptureParam *handleData)
{
    int32_t ret;
    struct AlsaCapture *captureIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    captureIns = CaptureGetInstance(handleData->captureMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(captureIns);

    ret = captureIns->SetMute(captureIns, handleData->captureMode.ctlParam.mute);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Capture set mute failed!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureGetMuteStu(
    const struct DevHandle *handle, int cmdId, struct AudioHwCaptureParam *handleData)
{
    struct AlsaCapture *captureIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    captureIns = CaptureGetInstance(handleData->captureMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(captureIns);
    handleData->captureMode.ctlParam.mute = captureIns->GetMute(captureIns);

    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureSetGainStu(
    const struct DevHandle *handle, int cmdId, const struct AudioHwCaptureParam *handleData)
{
    int32_t ret;
    float gainValue;
    struct AlsaCapture *captureIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    captureIns = CaptureGetInstance(handleData->captureMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(captureIns);

    gainValue = handleData->captureMode.ctlParam.audioGain.gain;
    ret = captureIns->SetGain(captureIns, gainValue);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Capture can not set gain!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureGetGainStu(
    const struct DevHandle *handle, int cmdId, struct AudioHwCaptureParam *handleData)
{
    int32_t ret;
    float gainValue;
    struct AlsaCapture *captureIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    captureIns = CaptureGetInstance(handleData->captureMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(captureIns);

    ret = captureIns->GetGain(captureIns, &gainValue);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Capture get gain failed!");
        return HDF_FAILURE;
    }
    handleData->captureMode.ctlParam.audioGain.gain = gainValue;

    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureSceneSelect(
    const struct DevHandle *handle, int cmdId, const struct AudioHwCaptureParam *handleData)
{
    int32_t ret;
    enum AudioPortPin descPins;
    const struct PathDeviceInfo *deviceInfo;
    struct AlsaCapture *captureIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    captureIns = CaptureGetInstance(handleData->captureMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(captureIns);

    descPins = handleData->captureMode.hwInfo.deviceDescript.pins;
    deviceInfo = &handleData->captureMode.hwInfo.pathSelect.deviceInfo;
    ret = captureIns->SelectScene(captureIns, descPins, deviceInfo);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Capture select scene pin: (0x%{public}x) failed", descPins);
        return HDF_FAILURE;
    }

    AUDIO_FUNC_LOGD("Capture scene select pin: (0x%{public}x) success", descPins);
    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureGetGainThreshold(
    const struct DevHandle *handle, int cmdId, struct AudioHwCaptureParam *handleData)
{
    int32_t ret;
    float gainMin = 0.0;
    float gainMax = 1.0;
    struct AlsaCapture *captureIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    captureIns = CaptureGetInstance(handleData->captureMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(captureIns);

    ret = captureIns->GetGainThreshold(captureIns, &gainMin, &gainMax);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Capture get gain threshold failed");
        return HDF_FAILURE;
    }
    handleData->captureMode.ctlParam.audioGain.gainMin = gainMin;
    handleData->captureMode.ctlParam.audioGain.gainMax = gainMax;

    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureGetVolThreshold(
    const struct DevHandle *handle, int cmdId, struct AudioHwCaptureParam *handleData)
{
    int32_t ret;
    long volMax = MIN_VOLUME;
    long volMin = MIN_VOLUME;
    struct AlsaCapture *captureIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    captureIns = CaptureGetInstance(handleData->captureMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(captureIns);

    ret = captureIns->GetVolThreshold(captureIns, &volMin, &volMax);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Capture get volume threshold failed!");
    }
    handleData->captureMode.ctlParam.volThreshold.volMax = (int)volMax;
    handleData->captureMode.ctlParam.volThreshold.volMin = (int)volMin;

    return HDF_SUCCESS;
}

int32_t AudioInterfaceLibCtlCapture(
    const struct DevHandle *handle, int cmdId, struct AudioHwCaptureParam *handleData)
{
    int32_t ret;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    switch (cmdId) {
        /* setPara: */
        case AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE:
            ret = AudioCtlCaptureSetVolume(handle, cmdId, handleData);
            break;
        case AUDIODRV_CTL_IOCTL_MUTE_WRITE_CAPTURE:
            ret = AudioCtlCaptureSetMuteStu(handle, cmdId, handleData);
            break;
        case AUDIODRV_CTL_IOCTL_MUTE_READ_CAPTURE:
            ret = AudioCtlCaptureGetMuteStu(handle, cmdId, handleData);
            break;
        /* getPara: */
        case AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE:
            ret = AudioCtlCaptureGetVolume(handle, cmdId, handleData);
            break;
        case AUDIODRV_CTL_IOCTL_GAIN_WRITE_CAPTURE:
            ret = AudioCtlCaptureSetGainStu(handle, cmdId, handleData);
            break;
        case AUDIODRV_CTL_IOCTL_GAIN_READ_CAPTURE:
            ret = AudioCtlCaptureGetGainStu(handle, cmdId, handleData);
            break;
        case AUDIODRV_CTL_IOCTL_SCENESELECT_CAPTURE:
            ret = AudioCtlCaptureSceneSelect(handle, cmdId, handleData);
            break;
        case AUDIODRV_CTL_IOCTL_GAINTHRESHOLD_CAPTURE:
            ret = AudioCtlCaptureGetGainThreshold(handle, cmdId, handleData);
            break;
        case AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_CAPTURE:
            ret = AudioCtlCaptureGetVolThreshold(handle, cmdId, handleData);
            break;
        default:
            AUDIO_FUNC_LOGE("Ctl Mode not support!");
            ret = HDF_FAILURE;
            break;
    }

    return ret;
}

int32_t AudioOutputCaptureHwParams(
    const struct DevHandle *handle, int cmdId, const struct AudioHwCaptureParam *handleData)
{
    int32_t ret;
    struct AlsaCapture *captureIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    captureIns = CaptureGetInstance(handleData->captureMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(captureIns);

    if (SndGetRunState(&captureIns->soundCard) >= SND_PCM_STATE_RUNNING) {
        AUDIO_FUNC_LOGE("Unable to set parameters during playback!");
        return HDF_FAILURE;
    }

    ret = CaptureSetParams(captureIns, handleData);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Capture set parameters failed!");
        return HDF_FAILURE;
    }

    AUDIO_FUNC_LOGI("Capture set hwparams success.");
    return HDF_SUCCESS;
}

/*
 * brief: Opens a capture PCM
 * param mode Open mode (see #SND_PCM_NONBLOCK, #SND_PCM_ASYNC)
 */
int32_t AudioOutputCaptureOpen(
    const struct DevHandle *handle, int cmdId, const struct AudioHwCaptureParam *handleData)
{
    int32_t ret;
    struct AlsaCapture *captureIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    captureIns = CaptureCreateInstance(handleData->captureMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(captureIns);

    ret = captureIns->Open(captureIns);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Capture open pcm failed.");
        return HDF_FAILURE;
    }

    ret = captureIns->Init(captureIns);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Capture init failed.");
        return HDF_FAILURE;
    }

    AUDIO_FUNC_LOGI("Capture open success.");
    return HDF_SUCCESS;
}


int32_t AudioOutputCaptureRead(
    const struct DevHandle *handle, int cmdId, struct AudioHwCaptureParam *handleData)
{
    int32_t ret;
    struct AlsaCapture *captureIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    captureIns = CaptureGetInstance(handleData->captureMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(captureIns);

    ret = captureIns->Read(captureIns, handleData);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("CaptureReadFrame failed");
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioOutputCapturePrepare(
    const struct DevHandle *handle, int cmdId, const struct AudioHwCaptureParam *handleData)
{
    int32_t ret;
    struct AlsaCapture *captureIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    captureIns = CaptureGetInstance(handleData->captureMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(captureIns);

    ret = SndPcmPrepare(&captureIns->soundCard);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("pcm prepare fail");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioOutputCaptureStart(
    const struct DevHandle *handle, int cmdId, const struct AudioHwCaptureParam *handleData)
{
    int32_t ret;
    struct AlsaCapture *captureIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    captureIns = CaptureGetInstance(handleData->captureMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(captureIns);

    ret = captureIns->Start(captureIns);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Capture start failed!");
        return ret;
    }

    AUDIO_FUNC_LOGI("Capture start success.");
    return HDF_SUCCESS;
}

int32_t AudioOutputCaptureStop(
    const struct DevHandle *handle, int cmdId, const struct AudioHwCaptureParam *handleData)
{
    int32_t ret;
    struct AlsaCapture *captureIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    captureIns = CaptureGetInstance(handleData->captureMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(captureIns);

    ret = captureIns->Stop(captureIns);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Capture stop route failed!");
        return ret;
    }

    AUDIO_FUNC_LOGI("Capture stop success.");
    return HDF_SUCCESS;
}

int32_t AudioOutputCaptureClose(
    const struct DevHandle *handle, int cmdId, const struct AudioHwCaptureParam *handleData)
{
    struct AlsaCapture *captureIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    captureIns = CaptureGetInstance(handleData->captureMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(captureIns);

    captureIns->Close(captureIns);

    AUDIO_FUNC_LOGI("Capture close success.");
    return HDF_SUCCESS;
}

int32_t AudioOutputCaptureReqMmapBuffer(
    const struct DevHandle *handle, int cmdId, const struct AudioHwCaptureParam *handleData)
{
    int32_t ret;
    struct AlsaCapture *captureIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    captureIns = CaptureGetInstance(handleData->captureMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(captureIns);

    ret = captureIns->MmapRead(captureIns, handleData);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Capture mmap write buffer failed!");
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioOutputCaptureGetMmapPosition(
    const struct DevHandle *handle, int cmdId, struct AudioHwCaptureParam *handleData)
{
    struct AlsaCapture *captureIns = NULL;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    captureIns = CaptureGetInstance(handleData->captureMode.hwInfo.adapterName);
    CHECK_NULL_PTR_RETURN_DEFAULT(captureIns);
    handleData->frameCaptureMode.frames = captureIns->GetMmapPosition(captureIns);

    return HDF_SUCCESS;
}

int32_t AudioInterfaceLibOutputCapture(
    const struct DevHandle *handle, int cmdId, struct AudioHwCaptureParam *handleData)
{
    int32_t ret;
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    switch (cmdId) {
        case AUDIO_DRV_PCM_IOCTL_HW_PARAMS:
            ret = AudioOutputCaptureHwParams(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTL_READ:
            ret = AudioOutputCaptureRead(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTRL_START_CAPTURE:
            ret = AudioOutputCaptureStart(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTL_PREPARE_CAPTURE:
            ret = AudioOutputCapturePrepare(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE:
            ret = AudioOutputCaptureClose(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTRL_CAPTURE_OPEN:
            ret = AudioOutputCaptureOpen(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTRL_STOP_CAPTURE:
            ret = AudioOutputCaptureStop(handle, cmdId, handleData);
            break;
        case AUDIODRV_CTL_IOCTL_PAUSE_WRITE_CAPTURE:
            ret = AudioCtlCaptureSetPauseStu(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTL_MMAP_BUFFER_CAPTURE:
            ret = AudioOutputCaptureReqMmapBuffer(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTL_MMAP_POSITION_CAPTURE:
            ret = AudioOutputCaptureGetMmapPosition(handle, cmdId, handleData);
            break;
        default:
            AUDIO_FUNC_LOGE("Output Mode not support!");
            ret = HDF_FAILURE;
            break;
    }

    return ret;
}

int32_t AudioInterfaceLibModeCapture(
    const struct DevHandle *handle, struct AudioHwCaptureParam *handleData, int cmdId)
{
    CHECK_NULL_PTR_RETURN_DEFAULT(handleData);

    switch (cmdId) {
        case AUDIO_DRV_PCM_IOCTL_HW_PARAMS:
        case AUDIO_DRV_PCM_IOCTL_READ:
        case AUDIO_DRV_PCM_IOCTRL_START_CAPTURE:
        case AUDIO_DRV_PCM_IOCTRL_STOP_CAPTURE:
        case AUDIO_DRV_PCM_IOCTL_PREPARE_CAPTURE:
        case AUDIODRV_CTL_IOCTL_PAUSE_WRITE_CAPTURE:
        case AUDIO_DRV_PCM_IOCTL_MMAP_BUFFER_CAPTURE:
        case AUDIO_DRV_PCM_IOCTL_MMAP_POSITION_CAPTURE:
        case AUDIO_DRV_PCM_IOCTRL_CAPTURE_OPEN:
        case AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE:
            return (AudioInterfaceLibOutputCapture(handle, cmdId, handleData));
        case AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE:
        case AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE:
        case AUDIODRV_CTL_IOCTL_MUTE_WRITE_CAPTURE:
        case AUDIODRV_CTL_IOCTL_MUTE_READ_CAPTURE:
        case AUDIODRV_CTL_IOCTL_GAIN_WRITE_CAPTURE:
        case AUDIODRV_CTL_IOCTL_GAIN_READ_CAPTURE:
        case AUDIODRV_CTL_IOCTL_SCENESELECT_CAPTURE:
        case AUDIODRV_CTL_IOCTL_GAINTHRESHOLD_CAPTURE:
        case AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_CAPTURE:
            return (AudioInterfaceLibCtlCapture(handle, cmdId, handleData));
        default:
            AUDIO_FUNC_LOGE("Mode Error!");
            break;
    }

    return HDF_ERR_NOT_SUPPORT;
}
