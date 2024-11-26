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

#include "audio_interface_lib_render.h"

#include <unistd.h>

#include "audio_common.h"
#include "audio_uhdf_log.h"
#include "hdf_io_service_if.h"
#include "osal_mem.h"
#include "securec.h"

#define HDF_LOG_TAG HDF_AUDIO_HAL_LIB
#define AUDIO_SBUF_EXTEND 64
#define TIME_COUNT_MS_TO_US 1000

/* Out Put Render */
static struct AudioPcmHwParams g_hwParams;

int32_t SetHwParams(const struct AudioHwRenderParam *handleData)
{
    if (handleData == NULL) {
        AUDIO_FUNC_LOGE("handleData is NULL!");
        return HDF_FAILURE;
    }
    (void)memset_s(&g_hwParams, sizeof(struct AudioPcmHwParams), 0, sizeof(struct AudioPcmHwParams));
    g_hwParams.streamType = AUDIO_RENDER_STREAM;
    g_hwParams.channels = handleData->frameRenderMode.attrs.channelCount;
    g_hwParams.rate = handleData->frameRenderMode.attrs.sampleRate;
    g_hwParams.periodSize = handleData->frameRenderMode.periodSize;
    g_hwParams.periodCount = handleData->frameRenderMode.periodCount;
    g_hwParams.cardServiceName = (char*)handleData->renderMode.hwInfo.cardServiceName;
    g_hwParams.format = handleData->frameRenderMode.attrs.format;
    g_hwParams.period = handleData->frameRenderMode.attrs.period;
    g_hwParams.frameSize = handleData->frameRenderMode.attrs.frameSize;
    g_hwParams.isBigEndian = handleData->frameRenderMode.attrs.isBigEndian;
    g_hwParams.isSignedData = handleData->frameRenderMode.attrs.isSignedData;
    g_hwParams.startThreshold = handleData->frameRenderMode.attrs.startThreshold;
    g_hwParams.stopThreshold = handleData->frameRenderMode.attrs.stopThreshold;
    g_hwParams.silenceThreshold = handleData->frameRenderMode.attrs.silenceThreshold;

    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSetVolumeSBuf(struct HdfSBuf *sBuf, const struct AudioHwRenderParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("RenderSetVolumeSBuf handleData or sBuf is NULL!");
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemValue;
    elemValue.id.cardServiceName = handleData->renderMode.hwInfo.cardServiceName;
    elemValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemValue.id.itemName = "Main Playback Volume";
    elemValue.value[0] = (int32_t)handleData->renderMode.ctlParam.volume;

    return AudioSetElemValue(sBuf, &elemValue, true);
}

int32_t AudioCtlRenderGetVolumeSBuf(struct HdfSBuf *sBuf, const struct AudioHwRenderParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("RenderGetVolumeSBuf handleData or sBuf is NULL!");
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemValue;
    elemValue.id.cardServiceName = handleData->renderMode.hwInfo.cardServiceName;
    elemValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemValue.id.itemName = "Main Playback Volume";

    return AudioSetElemValue(sBuf, &elemValue, false);
}

int32_t AudioCtlRenderSetVolume(const struct DevHandle *handle, int cmdId,
    const struct AudioHwRenderParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("RenderSetVolume parameter is empty!");
        return HDF_FAILURE;
    }

    struct HdfSBuf *sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("Failed to obtain sBuf");
        return HDF_FAILURE;
    }

    if (AudioCtlRenderSetVolumeSBuf(sBuf, handleData) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Failed to Set Volume sBuf!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    cmdId = AUDIODRV_CTL_IOCTL_ELEM_WRITE - CTRL_NUM;

    if (AudioServiceDispatch(handle->object, cmdId, sBuf, NULL) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Failed to AudioServiceDispatch!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    AudioFreeHdfSBuf(sBuf, NULL);
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderGetVolume(const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("RenderGetVolume parameter is empty!");
        return HDF_FAILURE;
    }

    struct AudioCtlElemValue elemValue;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = NULL;

    if (AudioAllocHdfSBuf(&sBuf, &reply) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }

    if (AudioCtlRenderGetVolumeSBuf(sBuf, handleData) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderGetVolume Failed to Get Volume sBuf!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    cmdId = AUDIODRV_CTL_IOCTL_ELEM_READ - CTRL_NUM;

    if (AudioServiceDispatch(handle->object, cmdId, sBuf, reply) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderGetVolume RenderDispatch Failed!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    (void)memset_s(&elemValue, sizeof(struct AudioCtlElemValue), 0, sizeof(struct AudioCtlElemValue));

    if (!HdfSbufReadInt32(reply, &elemValue.value[0])) {
        AUDIO_FUNC_LOGE("RenderGetVolume Failed to Get Volume sBuf!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    handleData->renderMode.ctlParam.volume = elemValue.value[0];
    AudioFreeHdfSBuf(sBuf, reply);
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSetPauseBuf(struct HdfSBuf *sBuf, const struct AudioHwRenderParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("RenderSetPauseBuf handleData or sBuf is NULL!");
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemValue;
    elemValue.id.cardServiceName = handleData->renderMode.hwInfo.cardServiceName;
    elemValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemValue.id.itemName = "Main Playback Pause";
    elemValue.value[0] = (int32_t)handleData->renderMode.ctlParam.pause;

    return AudioSetElemValue(sBuf, &elemValue, true);
}

int32_t AudioCtlRenderSetPauseStu(const struct DevHandle *handle,
    int cmdId, const struct AudioHwRenderParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("RenderSetPauseStu parameter is empty!");
        return HDF_FAILURE;
    }

    struct HdfSBuf *sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("RenderSetPauseStu Failed to obtain sBuf");
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteString(sBuf, handleData->renderMode.hwInfo.cardServiceName)) {
        AUDIO_FUNC_LOGE("HdfSbufWriteString cardServiceName failed!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    if (AudioCtlRenderSetPauseBuf(sBuf, handleData) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderSetPauseStu Failed to Set Pause sBuf!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    cmdId = handleData->renderMode.ctlParam.pause ?
        AUDIO_DRV_PCM_IOCTRL_PAUSE : AUDIO_DRV_PCM_IOCTRL_RESUME;

    if (AudioServiceDispatch(handle->object, cmdId, sBuf, NULL) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderSetPauseStu Failed!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    AudioFreeHdfSBuf(sBuf, NULL);
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSetMuteBuf(struct HdfSBuf *sBuf, const struct AudioHwRenderParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("RenderSetMuteBuf handleData or sBuf is NULL!");
        return HDF_FAILURE;
    }

    struct AudioCtlElemValue elemValue;
    elemValue.id.cardServiceName = handleData->renderMode.hwInfo.cardServiceName;
    elemValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemValue.id.itemName = "Playback Mute";
    elemValue.value[0] = (int32_t)handleData->renderMode.ctlParam.mute;

    return AudioSetElemValue(sBuf, &elemValue, true);
}

int32_t AudioCtlRenderSetMuteStu(const struct DevHandle *handle,
    int cmdId, const struct AudioHwRenderParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("RenderSetMuteStu paras is NULL!");
        return HDF_FAILURE;
    }

    struct HdfSBuf *sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("RenderSetMuteStu Failed to obtain sBuf");
        return HDF_FAILURE;
    }

    if (AudioCtlRenderSetMuteBuf(sBuf, handleData) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderSetMuteStu Failed to Set Mute sBuf!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    cmdId = AUDIODRV_CTL_IOCTL_ELEM_WRITE - CTRL_NUM;

    if (AudioServiceDispatch(handle->object, cmdId, sBuf, NULL) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderSetPauseStu Failed!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    AudioFreeHdfSBuf(sBuf, NULL);
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderGetMuteSBuf(struct HdfSBuf *sBuf, const struct AudioHwRenderParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("RenderGetMuteSBuf handleData or sBuf is NULL!");
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemValue;
    elemValue.id.cardServiceName = handleData->renderMode.hwInfo.cardServiceName;
    elemValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemValue.id.itemName = "Playback Mute";

    return AudioSetElemValue(sBuf, &elemValue, false);
}

int32_t AudioCtlRenderGetMuteStu(const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("RenderGetMuteStu paras is NULL!");
        return HDF_FAILURE;
    }

    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = NULL;
    struct AudioCtlElemValue muteValueStu;

    if (AudioAllocHdfSBuf(&sBuf, &reply) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("AudioAllocHdfSBuf Failed");
        return HDF_FAILURE;
    }

    if (AudioCtlRenderGetMuteSBuf(sBuf, handleData) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderGetMuteStu Failed to Get Mute sBuf!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    cmdId = AUDIODRV_CTL_IOCTL_ELEM_READ - CTRL_NUM;

    if (AudioServiceDispatch(handle->object, cmdId, sBuf, reply) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderGetMuteStu RenderDispatch Failed!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    (void)memset_s(&muteValueStu, sizeof(struct AudioCtlElemValue), 0, sizeof(struct AudioCtlElemValue));

    if (!HdfSbufReadInt32(reply, &muteValueStu.value[0])) {
        AUDIO_FUNC_LOGE("RenderGetMuteStu Failed to Get Volume sBuf!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    handleData->renderMode.ctlParam.mute = muteValueStu.value[0];
    AudioFreeHdfSBuf(sBuf, reply);
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSetGainBuf(struct HdfSBuf *sBuf, const struct AudioHwRenderParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("RenderSetGainBuf handleData or sBuf is NULL!");
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemValue;
    elemValue.id.cardServiceName = handleData->renderMode.hwInfo.cardServiceName;
    elemValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemValue.id.itemName = "Mic Left Gain";
    elemValue.value[0] = (int32_t)handleData->renderMode.ctlParam.audioGain.gain;

    return AudioSetElemValue(sBuf, &elemValue, true);
}

int32_t AudioCtlRenderSetGainStu(const struct DevHandle *handle,
    int cmdId, const struct AudioHwRenderParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("RenderSetGainStu paras is NULL!");
        return HDF_FAILURE;
    }

    struct HdfSBuf *sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("RenderSetGainStu Failed to obtain sBuf");
        return HDF_FAILURE;
    }

    if (AudioCtlRenderSetGainBuf(sBuf, handleData) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderSetGainStu Failed to Set Gain sBuf!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    cmdId = AUDIODRV_CTL_IOCTL_ELEM_WRITE - CTRL_NUM;

    if (AudioServiceDispatch(handle->object, cmdId, sBuf, NULL) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderSetGainStu Failed to send service call!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    AudioFreeHdfSBuf(sBuf, NULL);
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderGetGainSBuf(struct HdfSBuf *sBuf, const struct AudioHwRenderParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("RenderGetGainSBuf handleData or sBuf is NULL!");
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemValue;
    elemValue.id.cardServiceName = handleData->renderMode.hwInfo.cardServiceName;
    elemValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemValue.id.itemName = "Mic Left Gain";

    return AudioSetElemValue(sBuf, &elemValue, false);
}

int32_t AudioCtlRenderGetGainStu(const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("RenderGetGainStu paras is NULL!");
        return HDF_FAILURE;
    }

    struct AudioCtlElemValue gainValueStu;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = NULL;

    if (AudioAllocHdfSBuf(&sBuf, &reply) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderGetGainStu Failed to obtain sBuf");
        return HDF_FAILURE;
    }

    if (AudioCtlRenderGetGainSBuf(sBuf, handleData) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderGetGainStu ailed to Get Gain sBuf!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    cmdId = AUDIODRV_CTL_IOCTL_ELEM_READ - CTRL_NUM;

    if (AudioServiceDispatch(handle->object, cmdId, sBuf, reply) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Dispatch Fail!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    (void)memset_s(&gainValueStu, sizeof(struct AudioCtlElemValue), 0, sizeof(struct AudioCtlElemValue));

    if (!HdfSbufReadInt32(reply, &gainValueStu.value[0])) {
        AUDIO_FUNC_LOGE("Failed to Get Gain sBuf!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    handleData->renderMode.ctlParam.audioGain.gain = gainValueStu.value[0];
    AudioFreeHdfSBuf(sBuf, reply);
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSceneSelectSBuf(struct HdfSBuf *sBuf, const struct AudioHwRenderParam *handleData,
    const int32_t deviceIndex)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("RenderSceneSelectSBuf handleData or sBuf is NULL!");
        return HDF_FAILURE;
    }
    if (deviceIndex < 0 || deviceIndex > PATHPLAN_COUNT - 1) {
        AUDIO_FUNC_LOGE("deviceIndex is error!");
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemValue;
    elemValue.id.cardServiceName = handleData->renderMode.hwInfo.cardServiceName;
    elemValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemValue.id.itemName =
        handleData->renderMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[deviceIndex].deviceSwitch;
    elemValue.value[0] =
        handleData->renderMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[deviceIndex].value;

    return AudioSetElemValue(sBuf, &elemValue, true);
}

int32_t AudioCtlRenderSceneSelect(const struct DevHandle *handle,
    int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t index;
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("RenderSceneSelect paras is NULL!");
        return HDF_FAILURE;
    }
    if (strcmp(handleData->renderMode.hwInfo.adapterName, USB) == 0 ||
        strcmp(handleData->renderMode.hwInfo.adapterName, HDMI) == 0) {
        return HDF_SUCCESS;
    }
    struct HdfSBuf *sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("RenderSceneSelect Failed to obtain sBuf");
        return HDF_FAILURE;
    }

    int32_t deviceNum = handleData->renderMode.hwInfo.pathSelect.deviceInfo.deviceNum;
    if (deviceNum < AUDIO_MIN_DEVICENUM) {
        AUDIO_FUNC_LOGE("AUDIO_MIN_ADAPTERNUM Failed!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    cmdId = AUDIODRV_CTL_IOCTL_ELEM_WRITE - CTRL_NUM;

    for (index = 0; index < deviceNum; index++) {
        HdfSbufFlush(sBuf);
        if (AudioCtlRenderSceneSelectSBuf(sBuf, handleData, index) != HDF_SUCCESS) {
            AUDIO_FUNC_LOGE("AudioCtlRenderSceneSelectSBuf Failed!");
            AudioFreeHdfSBuf(sBuf, NULL);
            return HDF_FAILURE;
        }

        if (AudioServiceDispatch(handle->object, cmdId, sBuf, NULL) != HDF_SUCCESS) {
            AUDIO_FUNC_LOGE("Dispatch Fail!");
            AudioFreeHdfSBuf(sBuf, NULL);
            return HDF_FAILURE;
        }
    }

    AudioFreeHdfSBuf(sBuf, NULL);
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderGetVolThresholdSBuf(struct HdfSBuf *sBuf, const struct AudioHwRenderParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("RenderGetVolThresholdSBuf paras is NULL!");
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemInfo;
    elemInfo.id.cardServiceName = handleData->renderMode.hwInfo.cardServiceName;
    elemInfo.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemInfo.id.itemName = "Main Playback Volume";

    return AudioSetElemValue(sBuf, &elemInfo, false);
}

int32_t AudioCtlRenderSceneGetGainThresholdSBuf(struct HdfSBuf *sBuf,
    const struct AudioHwRenderParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("RenderSceneGetGainThresholdSBuf paras is NULL!");
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemInfo;
    elemInfo.id.cardServiceName = handleData->renderMode.hwInfo.cardServiceName;
    elemInfo.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemInfo.id.itemName = "Mic Left Gain";

    return AudioSetElemValue(sBuf, &elemInfo, false);
}

int32_t AudioCtlRenderSceneGetGainThreshold(const struct DevHandle *handle,
    int cmdId, struct AudioHwRenderParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("RenderSceneGetGainThreshold paras is NULL!");
        return HDF_FAILURE;
    }

    struct AudioCtrlElemInfo gainThreshold;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = NULL;

    if (AudioAllocHdfSBuf(&sBuf, &reply) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderSceneGetGainThreshold Failed to obtain sBuf");
        return HDF_FAILURE;
    }

    if (AudioCtlRenderSceneGetGainThresholdSBuf(sBuf, handleData) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderSceneGetGainThreshold Get Threshold sBuf Fail!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    cmdId = AUDIODRV_CTL_IOCTL_ELEM_INFO - CTRL_NUM;

    if (AudioServiceDispatch(handle->object, cmdId, sBuf, reply) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Dispatch Fail!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    (void)memset_s(&gainThreshold, sizeof(struct AudioCtrlElemInfo), 0, sizeof(struct AudioCtrlElemInfo));

    if (!HdfSbufReadInt32(reply, &gainThreshold.type)) {
        AUDIO_FUNC_LOGE("RenderSceneGetGainThreshold Failed to Get Volume sBuf!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    if (!HdfSbufReadInt32(reply, &gainThreshold.max)) {
        AUDIO_FUNC_LOGE("RenderSceneGetGainThreshold Failed to Get Volume sBuf!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    handleData->renderMode.ctlParam.audioGain.gainMax = gainThreshold.max;
    handleData->renderMode.ctlParam.audioGain.gainMin = 0;
    AudioFreeHdfSBuf(sBuf, reply);
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderGetVolThreshold(const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("paras is NULL!");
        return HDF_FAILURE;
    }

    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = NULL;

    if (AudioAllocHdfSBuf(&sBuf, &reply) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderGetVolThreshold Failed to obtain sBuf");
        return HDF_FAILURE;
    }

    if (AudioCtlRenderGetVolThresholdSBuf(sBuf, handleData) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Get Threshold sBuf Fail!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    cmdId = AUDIODRV_CTL_IOCTL_ELEM_INFO - CTRL_NUM;
    int32_t ret = AudioServiceDispatch(handle->object, cmdId, sBuf, reply);
    if (ret == HDF_ERR_NOT_SUPPORT) {
        AUDIO_FUNC_LOGW("This sound card does not have a volume control component!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_SUCCESS;
    } else if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Dispatch Fail!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    struct AudioCtrlElemInfo volThreshold;
    if (AudioGetElemValue(reply, &volThreshold) < 0) {
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    handleData->renderMode.ctlParam.volThreshold.volMax = volThreshold.max;
    handleData->renderMode.ctlParam.volThreshold.volMin = volThreshold.min;
    AudioFreeHdfSBuf(sBuf, reply);
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSetChannelModeBuf(struct HdfSBuf *sBuf, const struct AudioHwRenderParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("RenderSetChannelModeBuf parameter is empty!");
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemValue;
    elemValue.id.cardServiceName = handleData->renderMode.hwInfo.cardServiceName;
    elemValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemValue.id.itemName = "Render Channel Mode";
    elemValue.value[0] = handleData->frameRenderMode.mode;

    return AudioSetElemValue(sBuf, &elemValue, true);
}

int32_t AudioCtlRenderSetChannelMode(const struct DevHandle *handle,
    int cmdId, const struct AudioHwRenderParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("RenderSetChannelMode paras is NULL!");
        return HDF_FAILURE;
    }

    struct HdfSBuf *sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("RenderSetChannelMode Failed to obtain sBuf");
        return HDF_FAILURE;
    }

    if (AudioCtlRenderSetChannelModeBuf(sBuf, handleData) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderSetChannelMode Failed to Set ChannelMode sBuf!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    cmdId = AUDIODRV_CTL_IOCTL_ELEM_WRITE - CTRL_NUM;

    if (AudioServiceDispatch(handle->object, cmdId, sBuf, NULL) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderSetChannelMode Failed to send service call!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    AudioFreeHdfSBuf(sBuf, NULL);
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderGetChannelModeSBuf(struct HdfSBuf *sBuf, const struct AudioHwRenderParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("RenderGetChannelModeSBuf parameter is empty!");
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemValue;
    elemValue.id.cardServiceName = handleData->renderMode.hwInfo.cardServiceName;
    elemValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemValue.id.itemName = "Render Channel Mode";

    return AudioSetElemValue(sBuf, &elemValue, false);
}

int32_t AudioCtlRenderGetChannelMode(const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("RenderGetChannelMode paras is NULL!");
        return HDF_FAILURE;
    }

    struct AudioCtlElemValue elemValue;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = NULL;

    if (AudioAllocHdfSBuf(&sBuf, &reply) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderGetVolThreshold Failed to obtain sBuf");
        return HDF_FAILURE;
    }

    if (AudioCtlRenderGetChannelModeSBuf(sBuf, handleData) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderGetChannelMode Failed to Get Channel Mode sBuf!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    handleData->frameRenderMode.mode = 1;
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_READ - CTRL_NUM;

    if (AudioServiceDispatch(handle->object, cmdId, sBuf, reply) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderGetChannelMode Failed to send service call!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    (void)memset_s(&elemValue, sizeof(struct AudioCtlElemValue), 0, sizeof(struct AudioCtlElemValue));

    if (!HdfSbufReadInt32(reply, &elemValue.value[0])) {
        AUDIO_FUNC_LOGE("Failed to Get ChannelMode sBuf!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    handleData->frameRenderMode.mode = (enum AudioChannelMode)elemValue.value[0];
    AudioFreeHdfSBuf(sBuf, reply);
    return HDF_SUCCESS;
}

int32_t AudioInterfaceLibCtlRender(const struct DevHandle *handle, int cmdId,
    struct AudioHwRenderParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("paras is NULL!");
        return HDF_FAILURE;
    }
    if (cmdId < AUDIODRV_CTL_IOCTL_ELEM_INFO || cmdId > AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ) {
        AUDIO_FUNC_LOGE("cmdId Not Supported!");
        return HDF_FAILURE;
    }
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

int32_t ParamsSbufWriteBuffer(struct HdfSBuf *sBuf)
{
    if (!HdfSbufWriteUint32(sBuf, (uint32_t)g_hwParams.streamType)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, g_hwParams.channels)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, g_hwParams.rate)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, g_hwParams.periodSize) ||
        !HdfSbufWriteUint32(sBuf, g_hwParams.periodCount)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, (uint32_t)(g_hwParams.format))) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_hwParams.cardServiceName)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, g_hwParams.period) ||
        !HdfSbufWriteUint32(sBuf, g_hwParams.frameSize)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, (uint32_t)(g_hwParams.isBigEndian)) ||
        !HdfSbufWriteUint32(sBuf, (uint32_t)(g_hwParams.isSignedData))) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, g_hwParams.startThreshold) ||
        !HdfSbufWriteUint32(sBuf, g_hwParams.stopThreshold)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, g_hwParams.silenceThreshold)) {
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t FrameSbufWriteBuffer(struct HdfSBuf *sBuf, const struct AudioHwRenderParam *handleData)
{
    if (sBuf == NULL || handleData == NULL || handleData->frameRenderMode.buffer == NULL) {
        AUDIO_FUNC_LOGE("param is null!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, handleData->renderMode.hwInfo.cardServiceName)) {
        AUDIO_FUNC_LOGE("[HdfSbufWriteString]-[cardServiceName] failed!");
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteUint32(sBuf, (uint32_t)(handleData->frameRenderMode.bufferFrameSize))) {
        AUDIO_FUNC_LOGE("[HdfSbufWriteUint32]-[bufferFrameSize] failed!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteBuffer(sBuf, handleData->frameRenderMode.buffer,
        (uint32_t)handleData->frameRenderMode.bufferSize)) {
        AUDIO_FUNC_LOGE("[HdfSbufWriteBuffer]-[buffer] failed!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioOutputRenderHwParams(const struct DevHandle *handle,
    int cmdId, const struct AudioHwRenderParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("The parameter is empty");
        return HDF_FAILURE;
    }

    struct HdfSBuf *sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("HdfSbufObtainDefaultSize failed!");
        return HDF_FAILURE;
    }

    if (SetHwParams(handleData) < 0) {
        AUDIO_FUNC_LOGE("SetHwParams failed!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    if (ParamsSbufWriteBuffer(sBuf)) {
        AUDIO_FUNC_LOGE("ParamsSbufWriteBuffer failed!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    if (AudioServiceDispatch(handle->object, cmdId, sBuf, NULL) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderHwParams Failed to send service call!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    AudioFreeHdfSBuf(sBuf, NULL);
    return HDF_SUCCESS;
}

int32_t AudioCallbackModeStatus(const struct AudioHwRenderParam *handleData,
    enum AudioCallbackType callbackType)
{
    if (handleData == NULL) {
        AUDIO_FUNC_LOGE("param handleData is null!");
        return HDF_FAILURE;
    }

    bool callBackStatus = handleData->renderMode.hwInfo.callBackEnable;
    if (callBackStatus) {
        handleData->frameRenderMode.callbackProcess(handleData->frameRenderMode.renderhandle, callbackType);
    }
    return HDF_SUCCESS;
}

int32_t AudioOutputRenderWriteFrame(struct HdfIoService *service,
    int cmdId, struct HdfSBuf *sBuf, struct HdfSBuf *reply, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    int32_t tryNum = 50; // try send sBuf 50 count
    int32_t buffStatus = 0;
    int32_t ms;
    if (service == NULL || sBuf == NULL || reply == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("param service or sBuf or reply or handleData is null!");
        return HDF_FAILURE;
    }
    if (service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        AUDIO_FUNC_LOGE("service->dispatcher or service->dispatcher->Dispatch is null!");
        return HDF_FAILURE;
    }
    do {
        ret = service->dispatcher->Dispatch(&service->object, cmdId, sBuf, reply);
        if (ret != HDF_SUCCESS) {
            AUDIO_FUNC_LOGE("Failed to send service call!");
            return ret;
        }
        if (!HdfSbufReadInt32(reply, &buffStatus)) {
            AUDIO_FUNC_LOGE("Failed to Get buffStatus!");
            return HDF_FAILURE;
        }

        if (buffStatus != CIR_BUFF_NORMAL) {
            (void)AudioCallbackModeStatus(handleData, AUDIO_RENDER_FULL);
            tryNum--;
            ms = buffStatus >= 0 ? buffStatus : 10; // 10 is wait for 10 ms
            usleep(ms * TIME_COUNT_MS_TO_US);
            AUDIO_FUNC_LOGD("Cir buff is full, wait for %{public}d ms", ms);
            continue;
        }
        break;
    } while (tryNum > 0);
    if (tryNum > 0) {
        (void)AudioCallbackModeStatus(handleData, AUDIO_NONBLOCK_WRITE_COMPLETED);
        return HDF_SUCCESS;
    } else {
        (void)AudioCallbackModeStatus(handleData, AUDIO_ERROR_OCCUR);
        AUDIO_FUNC_LOGE("Out of tryNum!");
        return HDF_FAILURE;
    }
}

int32_t AudioOutputRenderWrite(const struct DevHandle *handle,
    int cmdId, const struct AudioHwRenderParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    size_t sbufSize = (size_t)handleData->frameRenderMode.bufferSize + AUDIO_SBUF_EXTEND;

    struct HdfSBuf *sBuf = HdfSbufTypedObtainCapacity(SBUF_RAW, sbufSize);
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("Get sBuf Fail");
        return HDF_FAILURE;
    }

    struct HdfSBuf *reply = HdfSbufObtainDefaultSize();
    if (reply == NULL) {
        AUDIO_FUNC_LOGE("reply is empty");
        HdfSbufRecycle(sBuf);
        return HDF_FAILURE;
    }

    if (FrameSbufWriteBuffer(sBuf, handleData) != HDF_SUCCESS) {
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    service = (struct HdfIoService *)handle->object;
    int32_t ret = AudioOutputRenderWriteFrame(service, cmdId, sBuf, reply, handleData);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("AudioOutputRenderWriteFrame is Fail!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    AudioFreeHdfSBuf(sBuf, reply);
    return HDF_SUCCESS;
}

int32_t AudioOutputRenderStartPrepare(const struct DevHandle *handle,
    int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;

    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameters!");
        return HDF_FAILURE;
    }
    struct HdfSBuf *sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("HdfSbufObtainDefaultSize failed!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, handleData->renderMode.hwInfo.cardServiceName)) {
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    ret = AudioServiceDispatch(handle->object, cmdId, sBuf, NULL);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderStartPrepare Failed to send service call cmdId = %{public}d!", cmdId);
    }

    AudioFreeHdfSBuf(sBuf, NULL);
    return ret;
}

int32_t AudioOutputRenderOpen(const struct DevHandle *handle,
    int cmdId, const struct AudioHwRenderParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("handle or handle->object or handleData is null!");
        return HDF_FAILURE;
    }

    struct HdfSBuf *sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("HdfSbufObtainDefaultSize failed!");
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteString(sBuf, handleData->renderMode.hwInfo.cardServiceName)) {
        AUDIO_FUNC_LOGE("HdfSbufWriteString cardServiceName failed!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    int32_t ret = AudioServiceDispatch(handle->object, cmdId, sBuf, NULL);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderStartPrepare Failed to send service call cmdId = %{public}d!", cmdId);
    }

    AudioFreeHdfSBuf(sBuf, NULL);
    return ret;
}

int32_t AudioOutputRenderStop(const struct DevHandle *handle,
    int cmdId, const struct AudioHwRenderParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("handle or handle->object or handleData is null!");
        return HDF_FAILURE;
    }

    struct HdfSBuf *sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("HdfSbufObtainDefaultSize failed!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, handleData->renderMode.hwInfo.cardServiceName)) {
        AUDIO_FUNC_LOGE("HdfSbufWriteString cardServiceName failed!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteUint32(sBuf, handleData->renderMode.ctlParam.turnStandbyStatus)) {
        AUDIO_FUNC_LOGE("HdfSbufWriteUint32 turnStandbyStatus failed!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    int32_t ret = AudioServiceDispatch(handle->object, cmdId, sBuf, NULL);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderStop Failed to send service call!");
    }

    AudioFreeHdfSBuf(sBuf, NULL);
    return ret;
}

int32_t MmapDescWriteBuffer(struct HdfSBuf *sBuf, const struct AudioHwRenderParam *handleData)
{
    if (sBuf == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("param sBuf or handleData is null!");
        return HDF_FAILURE;
    }
    uint64_t mmapAddr = (uint64_t)(uintptr_t)(handleData->frameRenderMode.mmapBufDesc.memoryAddress);
    if (!HdfSbufWriteString(sBuf, handleData->renderMode.hwInfo.cardServiceName)) {
        AUDIO_FUNC_LOGE("HdfSbufWriteString cardServiceName failed!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint64(sBuf, mmapAddr)) {
        AUDIO_FUNC_LOGE("HdfSbufWriteUint64 mmapAddr failed!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, handleData->frameRenderMode.mmapBufDesc.memoryFd)) {
        AUDIO_FUNC_LOGE("HdfSbufWriteUint64 memoryFd failed!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, handleData->frameRenderMode.mmapBufDesc.totalBufferFrames)) {
        AUDIO_FUNC_LOGE("HdfSbufWriteUint64 totalBufferFrames failed!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, handleData->frameRenderMode.mmapBufDesc.transferFrameSize)) {
        AUDIO_FUNC_LOGE("HdfSbufWriteUint64 transferFrameSize failed!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, handleData->frameRenderMode.mmapBufDesc.isShareable)) {
        AUDIO_FUNC_LOGE("HdfSbufWriteUint64 isShareable failed!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, handleData->frameRenderMode.mmapBufDesc.offset)) {
        AUDIO_FUNC_LOGE("HdfSbufWriteUint64 offset failed!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioOutputRenderReqMmapBuffer(const struct DevHandle *handle,
    int cmdId, const struct AudioHwRenderParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("handle or handle->object or handleData is null!");
        return HDF_FAILURE;
    }

    struct HdfSBuf *sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("HdfSbufObtainDefaultSize failed!");
        return HDF_FAILURE;
    }
    if (MmapDescWriteBuffer(sBuf, handleData)) {
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    int32_t ret = AudioServiceDispatch(handle->object, cmdId, sBuf, NULL);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Failed to send service call!");
    }

    AudioFreeHdfSBuf(sBuf, NULL);
    return ret;
}

int32_t AudioOutputRenderGetMmapPosition(const struct DevHandle *handle,
    int cmdId, struct AudioHwRenderParam *handleData)
{
    uint64_t frames = 0;

    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("handle or handle->object or handleData is null!");
        return HDF_FAILURE;
    }

    struct HdfSBuf *reply = HdfSbufObtainDefaultSize();
    if (reply == NULL) {
        AUDIO_FUNC_LOGE("RenderGetMmapPosition Failed to obtain reply");
        return HDF_FAILURE;
    }
    struct HdfSBuf *sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("HdfSbufObtainDefaultSize failed!");
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteString(sBuf, handleData->renderMode.hwInfo.cardServiceName)) {
        AUDIO_FUNC_LOGE("HdfSbufWriteString cardServiceName failed!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    int32_t ret = AudioServiceDispatch(handle->object, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Failed to send service call!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }
    AudioFreeHdfSBuf(sBuf, NULL);

    if (!HdfSbufReadUint64(reply, &frames)) {
        AUDIO_FUNC_LOGE("failed to get mmap position sBuf!");
        AudioFreeHdfSBuf(reply, NULL);
        return HDF_FAILURE;
    }

    handleData->frameRenderMode.frames = frames;
    AudioFreeHdfSBuf(reply, NULL);
    return HDF_SUCCESS;
}

int32_t AudioInterfaceLibOutputRender(const struct DevHandle *handle,
    int cmdId, struct AudioHwRenderParam *handleData)
{
    if (handle == NULL) {
        AUDIO_FUNC_LOGE("Input Render handle is NULL!");
        return HDF_FAILURE;
    }
    if (handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("handle->object or handleData is null!");
        return HDF_FAILURE;
    }

    switch (cmdId) {
        case AUDIO_DRV_PCM_IOCTL_HW_PARAMS:
            return AudioOutputRenderHwParams(handle, cmdId, handleData);
        case AUDIO_DRV_PCM_IOCTL_WRITE:
            return AudioOutputRenderWrite(handle, cmdId, handleData);
        case AUDIO_DRV_PCM_IOCTRL_STOP:
            return AudioOutputRenderStop(handle, cmdId, handleData);
        case AUDIO_DRV_PCM_IOCTRL_START:
        case AUDIO_DRV_PCM_IOCTL_PREPARE:
        case AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE:
            return AudioOutputRenderStartPrepare(handle, cmdId, handleData);
        case AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN:
            return AudioOutputRenderOpen(handle, cmdId, handleData);
        case AUDIODRV_CTL_IOCTL_PAUSE_WRITE:
            return AudioCtlRenderSetPauseStu(handle, cmdId, handleData);
        case AUDIO_DRV_PCM_IOCTL_MMAP_BUFFER:
            return AudioOutputRenderReqMmapBuffer(handle, cmdId, handleData);
        case AUDIO_DRV_PCM_IOCTL_MMAP_POSITION:
            return (AudioOutputRenderGetMmapPosition(handle, cmdId, handleData));
        default:
            AUDIO_FUNC_LOGE("Output Mode not support!");
            return HDF_FAILURE;
    }
}

int32_t AudioInterfaceLibModeRender(const struct DevHandle *handle,
    struct AudioHwRenderParam *handleData, int cmdId)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("paras is NULL!");
        return HDF_FAILURE;
    }
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
        case AUDIODRV_CTL_IOCTL_ELEM_LIST:
        case AUDIODRV_CTL_IOCTL_ELEM_CARD:
        case AUDIODRV_CTL_IOCTL_ELEM_HDMI:
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
