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
#include "audio_common.h"
#include "audio_uhdf_log.h"
#include "osal_mem.h"

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
    if (!HdfSbufWriteInt32(sBuf, elemValue.value[0])) {
        AUDIO_FUNC_LOGE("RenderSetVolumeSBuf Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, elemValue.id.iface)) {
        AUDIO_FUNC_LOGE("RenderSetVolumeSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemValue.id.cardServiceName)) {
        AUDIO_FUNC_LOGE("RenderSetVolumeSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemValue.id.itemName)) {
        AUDIO_FUNC_LOGE("RenderSetVolumeSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
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
    if (!HdfSbufWriteInt32(sBuf, elemValue.id.iface)) {
        AUDIO_FUNC_LOGE("RenderGetVolumeSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemValue.id.cardServiceName)) {
        AUDIO_FUNC_LOGE("RenderGetVolumeSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemValue.id.itemName)) {
        AUDIO_FUNC_LOGE("RenderGetVolumeSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSetVolume(const struct DevHandle *handle, int cmdId,
    const struct AudioHwRenderParam *handleData)
{
    int32_t ret;

    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("RenderSetVolume parameter is empty!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    ret = AudioCtlRenderSetVolumeSBuf(sBuf, handleData);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Failed to Set Volume sBuf!");
        AudioSbufRecycle(sBuf);
        return ret;
    }
    service = (struct HdfIoService *)handle->object;
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_WRITE - CTRL_NUM;
    ret = AudioServiceDispatch(service, cmdId, sBuf, NULL);
    AudioSbufRecycle(sBuf);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Failed to AudioServiceDispatch!");
    }
    return ret;
}

int32_t AudioCtlRenderGetVolume(const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("RenderGetVolume parameter is empty!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("RenderGetVolume Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    reply = AudioObtainHdfSBuf();
    if (reply == NULL) {
        AUDIO_FUNC_LOGE("RenderGetVolume Failed to obtain reply");
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    ret = AudioCtlRenderGetVolumeSBuf(sBuf, handleData);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("RenderGetVolume Failed to Get Volume sBuf!");
        AudioBufReplyRecycle(sBuf, reply);
        return ret;
    }
    service = (struct HdfIoService *)handle->object;
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_READ - CTRL_NUM;
    ret = AudioServiceDispatch(service, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderGetVolume RenderDispatch Failed!");
        AudioBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemValue;
    (void)memset_s(&elemValue, sizeof(struct AudioCtlElemValue), 0, sizeof(struct AudioCtlElemValue));
    if (!HdfSbufReadInt32(reply, &elemValue.value[0])) {
        AUDIO_FUNC_LOGE("RenderGetVolume Failed to Get Volume sBuf!");
        AudioBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    handleData->renderMode.ctlParam.volume = elemValue.value[0];
    AudioBufReplyRecycle(sBuf, reply);
    return ret;
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
    if (!HdfSbufWriteInt32(sBuf, elemValue.value[0])) {
        AUDIO_FUNC_LOGE("RenderSetPauseBuf pause Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, elemValue.id.iface)) {
        AUDIO_FUNC_LOGE("RenderSetPauseBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemValue.id.cardServiceName)) {
        AUDIO_FUNC_LOGE("RenderSetPauseBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemValue.id.itemName)) {
        AUDIO_FUNC_LOGE("RenderSetPauseBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSetPauseStu(const struct DevHandle *handle,
    int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;

    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("RenderSetPauseStu parameter is empty!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("RenderSetPauseStu Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    ret = AudioCtlRenderSetPauseBuf(sBuf, handleData);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("RenderSetPauseStu Failed to Set Pause sBuf!");
        AudioSbufRecycle(sBuf);
        return ret;
    }
    service = (struct HdfIoService *)handle->object;
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        AUDIO_FUNC_LOGE("RenderSetPauseStu Service is NULL!");
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    cmdId = handleData->renderMode.ctlParam.pause ?
        AUDIO_DRV_PCM_IOCTRL_PAUSE : AUDIO_DRV_PCM_IOCTRL_RESUME;
    ret = service->dispatcher->Dispatch(&service->object, cmdId, sBuf, NULL);
    AudioSbufRecycle(sBuf);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderSetPauseStu Failed to send service call!");
    }
    return ret;
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
    if (!HdfSbufWriteInt32(sBuf, elemValue.value[0])) {
        AUDIO_FUNC_LOGE("RenderSetMuteBuf value[0] Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, elemValue.id.iface)) {
        AUDIO_FUNC_LOGE("RenderSetMuteBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemValue.id.cardServiceName)) {
        AUDIO_FUNC_LOGE("RenderSetMuteBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemValue.id.itemName)) {
        AUDIO_FUNC_LOGE("RenderSetMuteBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSetMuteStu(const struct DevHandle *handle,
    int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;

    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("RenderSetMuteStu paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("RenderSetMuteStu Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    ret = AudioCtlRenderSetMuteBuf(sBuf, handleData);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("RenderSetMuteStu Failed to Set Mute sBuf!");
        AudioSbufRecycle(sBuf);
        return ret;
    }
    service = (struct HdfIoService *)handle->object;
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        AUDIO_FUNC_LOGE("RenderSetMuteStu Service is NULL!");
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_WRITE - CTRL_NUM;
    ret = service->dispatcher->Dispatch(&service->object, cmdId, sBuf, NULL);
    AudioSbufRecycle(sBuf);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderSetMuteStu Failed to send service call!");
    }
    return ret;
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
    if (!HdfSbufWriteInt32(sBuf, elemValue.id.iface)) {
        AUDIO_FUNC_LOGE("RenderGetMuteSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemValue.id.cardServiceName)) {
        AUDIO_FUNC_LOGE("RenderGetMuteSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemValue.id.itemName)) {
        AUDIO_FUNC_LOGE("RenderGetMuteSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderGetMuteStu(const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    int32_t ret;

    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("RenderGetMuteStu paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("RenderGetMuteStu Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    reply = AudioObtainHdfSBuf();
    if (reply == NULL) {
        AUDIO_FUNC_LOGE("RenderGetMuteStu Failed to obtain reply");
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    ret = AudioCtlRenderGetMuteSBuf(sBuf, handleData);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("RenderGetMuteStu Failed to Get Mute sBuf!");
        AudioBufReplyRecycle(sBuf, reply);
        return ret;
    }
    service = (struct HdfIoService *)handle->object;
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_READ - CTRL_NUM;
    ret = AudioServiceDispatch(service, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderGetMuteStu RenderDispatch Failed!");
        AudioBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue muteValueStu;
    (void)memset_s(&muteValueStu, sizeof(struct AudioCtlElemValue), 0, sizeof(struct AudioCtlElemValue));
    if (!HdfSbufReadInt32(reply, &muteValueStu.value[0])) {
        AUDIO_FUNC_LOGE("RenderGetMuteStu Failed to Get Volume sBuf!");
        AudioBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    handleData->renderMode.ctlParam.mute = muteValueStu.value[0];
    AudioBufReplyRecycle(sBuf, reply);
    return ret;
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
    if (!HdfSbufWriteInt32(sBuf, elemValue.value[0])) {
        AUDIO_FUNC_LOGE("RenderSetGainBuf value[0] Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, elemValue.id.iface)) {
        AUDIO_FUNC_LOGE("RenderSetGainBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemValue.id.cardServiceName)) {
        AUDIO_FUNC_LOGE("RenderSetGainBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemValue.id.itemName)) {
        AUDIO_FUNC_LOGE("RenderSetGainBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSetGainStu(const struct DevHandle *handle,
    int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;

    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("RenderSetGainStu paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("RenderSetGainStu Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    ret = AudioCtlRenderSetGainBuf(sBuf, handleData);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("RenderSetGainStu Failed to Set Gain sBuf!");
        AudioSbufRecycle(sBuf);
        return ret;
    }
    service = (struct HdfIoService *)handle->object;
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        AUDIO_FUNC_LOGE("RenderSetGainStu Service is NULL!");
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_WRITE - CTRL_NUM;
    ret = service->dispatcher->Dispatch(&service->object, cmdId, sBuf, reply);
    AudioSbufRecycle(sBuf);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderSetGainStu Failed to send service call!");
    }
    return ret;
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
    if (!HdfSbufWriteInt32(sBuf, elemValue.id.iface)) {
        AUDIO_FUNC_LOGE("RenderGetGainSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemValue.id.cardServiceName)) {
        AUDIO_FUNC_LOGE("RenderGetGainSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemValue.id.itemName)) {
        AUDIO_FUNC_LOGE("RenderGetGainSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderGetGainStu(const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    int32_t ret;

    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("RenderGetGainStu paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("RenderGetGainStu Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    reply = AudioObtainHdfSBuf();
    if (reply == NULL) {
        AUDIO_FUNC_LOGE("RenderGetGainStu Failed to obtain reply");
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    ret = AudioCtlRenderGetGainSBuf(sBuf, handleData);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("RenderGetGainStu ailed to Get Gain sBuf!");
        AudioBufReplyRecycle(sBuf, reply);
        return ret;
    }
    service = (struct HdfIoService *)handle->object;
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_READ - CTRL_NUM;
    ret = AudioServiceDispatch(service, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Dispatch Fail!");
        AudioBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue gainValueStu;
    (void)memset_s(&gainValueStu, sizeof(struct AudioCtlElemValue), 0, sizeof(struct AudioCtlElemValue));
    if (!HdfSbufReadInt32(reply, &gainValueStu.value[0])) {
        AUDIO_FUNC_LOGE("Failed to Get Gain sBuf!");
        AudioBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    handleData->renderMode.ctlParam.audioGain.gain = gainValueStu.value[0];
    AudioBufReplyRecycle(sBuf, reply);
    return ret;
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
    if (!HdfSbufWriteInt32(sBuf, elemValue.value[0])) {
        AUDIO_FUNC_LOGE("RenderSceneSelectSBuf Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, elemValue.id.iface)) {
        AUDIO_FUNC_LOGE("RenderSceneSelectSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemValue.id.cardServiceName)) {
        AUDIO_FUNC_LOGE("RenderSceneSelectSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemValue.id.itemName)) {
        AUDIO_FUNC_LOGE("RenderSceneSelectSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSceneSelect(const struct DevHandle *handle,
    int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t index;
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("RenderSceneSelect paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("RenderSceneSelect Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    service = (struct HdfIoService *)handle->object;
    int32_t deviceNum = handleData->renderMode.hwInfo.pathSelect.deviceInfo.deviceNum;
    if (deviceNum < AUDIO_MIN_DEVICENUM) {
        AUDIO_FUNC_LOGE("AUDIO_MIN_ADAPTERNUM Failed!");
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        AUDIO_FUNC_LOGE("Service is NULL!");
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_WRITE - CTRL_NUM;
    for (index = 0; index < deviceNum; index++) {
        HdfSbufFlush(sBuf);
        if (AudioCtlRenderSceneSelectSBuf(sBuf, handleData, index) < 0) {
            AUDIO_FUNC_LOGE("AudioCtlRenderSceneSelectSBuf Failed!");
            AudioSbufRecycle(sBuf);
            return HDF_FAILURE;
        }
        if (service->dispatcher->Dispatch(&service->object, cmdId, sBuf, NULL) < 0) {
            AUDIO_FUNC_LOGE("Failed to send service call!");
            AudioSbufRecycle(sBuf);
            return HDF_FAILURE;
        }
    }
    AudioSbufRecycle(sBuf);
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderGetVolThresholdSBuf(struct HdfSBuf *sBuf, const struct AudioHwRenderParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("RenderGetVolThresholdSBuf paras is NULL!");
        return HDF_FAILURE;
    }
    struct AudioCtrlElemInfo elemInfo;
    elemInfo.id.cardServiceName = handleData->renderMode.hwInfo.cardServiceName;
    elemInfo.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemInfo.id.itemName = "Main Playback Volume";
    if (!HdfSbufWriteInt32(sBuf, elemInfo.id.iface)) {
        AUDIO_FUNC_LOGE("RenderGetVolThresholdSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemInfo.id.cardServiceName)) {
        AUDIO_FUNC_LOGE("RenderGetVolThresholdSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemInfo.id.itemName)) {
        AUDIO_FUNC_LOGE("RenderGetVolThresholdSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSceneGetGainThresholdSBuf(struct HdfSBuf *sBuf,
    const struct AudioHwRenderParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("RenderSceneGetGainThresholdSBuf paras is NULL!");
        return HDF_FAILURE;
    }
    struct AudioCtrlElemInfo elemInfo;
    elemInfo.id.cardServiceName = handleData->renderMode.hwInfo.cardServiceName;
    elemInfo.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemInfo.id.itemName = "Mic Left Gain";
    if (!HdfSbufWriteInt32(sBuf, elemInfo.id.iface)) {
        AUDIO_FUNC_LOGE("RenderSceneGetGainThresholdSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemInfo.id.cardServiceName)) {
        AUDIO_FUNC_LOGE("RenderSceneGetGainThresholdSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemInfo.id.itemName)) {
        AUDIO_FUNC_LOGE("RenderSceneGetGainThresholdSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSceneGetGainThreshold(const struct DevHandle *handle,
    int cmdId, struct AudioHwRenderParam *handleData)
{
    int32_t ret;

    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("RenderSceneGetGainThreshold paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("RenderSceneGetGainThreshold Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    reply = AudioObtainHdfSBuf();
    if (reply == NULL) {
        AUDIO_FUNC_LOGE("RenderSceneGetGainThreshold reply is NULL");
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    ret = AudioCtlRenderSceneGetGainThresholdSBuf(sBuf, handleData);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("RenderSceneGetGainThreshold Get Threshold sBuf Fail!");
        AudioBufReplyRecycle(sBuf, reply);
        return ret;
    }
    service = (struct HdfIoService *)handle->object;
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_INFO - CTRL_NUM;
    ret = AudioServiceDispatch(service, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        AudioBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    struct AudioCtrlElemInfo gainThreshold;
    (void)memset_s(&gainThreshold, sizeof(struct AudioCtrlElemInfo), 0, sizeof(struct AudioCtrlElemInfo));
    if (!HdfSbufReadInt32(reply, &gainThreshold.type)) {
        AUDIO_FUNC_LOGE("RenderSceneGetGainThreshold Failed to Get Volume sBuf!");
        AudioBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadInt32(reply, &gainThreshold.max)) {
        AUDIO_FUNC_LOGE("RenderSceneGetGainThreshold Failed to Get Volume sBuf!");
        AudioBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    AudioBufReplyRecycle(sBuf, reply);
    handleData->renderMode.ctlParam.audioGain.gainMax = gainThreshold.max;
    handleData->renderMode.ctlParam.audioGain.gainMin = 0;
    return ret;
}

int32_t AudioCtlRenderGetVolThreshold(const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    struct HdfSBuf *reply = AudioObtainHdfSBuf();
    if (reply == NULL) {
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    int32_t ret = AudioCtlRenderGetVolThresholdSBuf(sBuf, handleData);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Get Threshold sBuf Fail!");
        AudioBufReplyRecycle(sBuf, reply);
        return ret;
    }
    struct HdfIoService *service = (struct HdfIoService *)handle->object;
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_INFO - CTRL_NUM;
    ret = AudioServiceDispatch(service, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        AudioBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    struct AudioCtrlElemInfo volThreshold;
    if (AudioCtlGetVolThresholdRead(reply, &volThreshold) < 0) {
        AudioBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    AudioBufReplyRecycle(sBuf, reply);
    handleData->renderMode.ctlParam.volThreshold.volMax = volThreshold.max;
    handleData->renderMode.ctlParam.volThreshold.volMin = volThreshold.min;
    return ret;
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
    if (!HdfSbufWriteInt32(sBuf, elemValue.value[0])) {
        AUDIO_FUNC_LOGE("RenderSetChannelModeBuf mode Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, elemValue.id.iface)) {
        AUDIO_FUNC_LOGE("RenderSetChannelModeBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemValue.id.cardServiceName)) {
        AUDIO_FUNC_LOGE("RenderSetChannelModeBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemValue.id.itemName)) {
        AUDIO_FUNC_LOGE("RenderSetChannelModeBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSetChannelMode(const struct DevHandle *handle,
    int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;

    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("RenderSetChannelMode paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("RenderSetChannelMode Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    ret = AudioCtlRenderSetChannelModeBuf(sBuf, handleData);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("RenderSetChannelMode Failed to Set ChannelMode sBuf!");
        AudioSbufRecycle(sBuf);
        return ret;
    }
    service = (struct HdfIoService *)handle->object;
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        AUDIO_FUNC_LOGE("RenderSetChannelMode Service is NULL!");
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_WRITE - CTRL_NUM;
    ret = service->dispatcher->Dispatch(&service->object, cmdId, sBuf, NULL);
    AudioSbufRecycle(sBuf);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderSetChannelMode Failed to send service call!");
    }
    return ret;
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
    if (!HdfSbufWriteInt32(sBuf, elemValue.id.iface)) {
        AUDIO_FUNC_LOGE("RenderGetChannelModeSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemValue.id.cardServiceName)) {
        AUDIO_FUNC_LOGE("RenderGetChannelModeSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemValue.id.itemName)) {
        AUDIO_FUNC_LOGE("RenderGetChannelModeSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderGetChannelMode(const struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    int32_t ret;

    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("RenderGetChannelMode paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("RenderGetChannelMode Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    reply = AudioObtainHdfSBuf();
    if (reply == NULL) {
        AUDIO_FUNC_LOGE("RenderGetChannelMode Failed to obtain reply");
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    ret = AudioCtlRenderGetChannelModeSBuf(sBuf, handleData);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("RenderGetChannelMode Failed to Get Channel Mode sBuf!");
        AudioBufReplyRecycle(sBuf, reply);
        return ret;
    }
    service = (struct HdfIoService *)handle->object;
    handleData->frameRenderMode.mode = 1;
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_READ - CTRL_NUM;
    ret = AudioServiceDispatch(service, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        AudioBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemValue;
    (void)memset_s(&elemValue, sizeof(struct AudioCtlElemValue), 0, sizeof(struct AudioCtlElemValue));
    if (!HdfSbufReadInt32(reply, &elemValue.value[0])) {
        AUDIO_FUNC_LOGE("Failed to Get ChannelMode sBuf!");
        AudioBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    handleData->frameRenderMode.mode = (enum AudioChannelMode)elemValue.value[0];
    AudioBufReplyRecycle(sBuf, reply);
    return ret;
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
    int32_t ret;
    struct HdfIoService *service = NULL;
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("The parameter is empty");
        return HDF_FAILURE;
    }
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("AudioObtainHdfSBuf failed!");
        return HDF_FAILURE;
    }
    if (SetHwParams(handleData) < 0) {
        AUDIO_FUNC_LOGE("SetHwParams failed!");
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    if (ParamsSbufWriteBuffer(sBuf)) {
        AUDIO_FUNC_LOGE("ParamsSbufWriteBuffer failed!");
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }

    service = (struct HdfIoService *)handle->object;
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        AUDIO_FUNC_LOGE("The pointer is null!");
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    ret = service->dispatcher->Dispatch(&service->object, cmdId, sBuf, NULL);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("failed to send service call, ret = %{public}d.", ret);
    }
    AudioBufReplyRecycle(sBuf, NULL);
    return ret;
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
        (void)AudioCallbackModeStatus(handleData, AUDIO_NONBLOCK_WRITE_COMPELETED);
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
    struct HdfSBuf *reply = AudioObtainHdfSBuf();
    if (reply == NULL) {
        AUDIO_FUNC_LOGE("reply is empty");
        HdfSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    if (FrameSbufWriteBuffer(sBuf, handleData) != HDF_SUCCESS) {
        AudioBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    service = (struct HdfIoService *)handle->object;
    int32_t ret = AudioOutputRenderWriteFrame(service, cmdId, sBuf, reply, handleData);
    AudioBufReplyRecycle(sBuf, reply);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("AudioOutputRenderWriteFrame is Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioOutputRenderStartPrepare(const struct DevHandle *handle,
    int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    struct HdfIoService *service = NULL;

    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("Invalid parameters!");
        return HDF_FAILURE;
    }

    service = (struct HdfIoService *)handle->object;
    if (service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        AUDIO_FUNC_LOGE("Failed to obtain the service.!");
        return HDF_FAILURE;
    }

    ret = service->dispatcher->Dispatch(&service->object, cmdId, NULL, NULL);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderStartPrepare Failed to send service call cmdId = %{public}d!", cmdId);
    }

    return ret;
}

int32_t AudioOutputRenderOpen(const struct DevHandle *handle,
    int cmdId, const struct AudioHwRenderParam *handleData)
{
    int32_t ret;

    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("handle or handle->object or handleData is null!");
        return HDF_FAILURE;
    }

    struct HdfIoService *service = (struct HdfIoService *)handle->object;
    if (service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        AUDIO_FUNC_LOGE("RenderStartPrepare Service is NULL!");
        return HDF_FAILURE;
    }

    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("AudioObtainHdfSBuf failed!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, handleData->renderMode.hwInfo.cardServiceName)) {
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }

    ret = service->dispatcher->Dispatch(&service->object, cmdId, sBuf, NULL);
    AudioSbufRecycle(sBuf);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderStartPrepare Failed to send service call cmdId = %{public}d!", cmdId);
    }
    return ret;
}

int32_t AudioOutputRenderStop(const struct DevHandle *handle,
    int cmdId, const struct AudioHwRenderParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("handle or handle->object or handleData is null!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    service = (struct HdfIoService *)handle->object;
    if (service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        AUDIO_FUNC_LOGE("RenderStop Service is NULL!");
        return HDF_FAILURE;
    }
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("AudioObtainHdfSBuf failed!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, handleData->renderMode.ctlParam.turnStandbyStatus)) {
        AUDIO_FUNC_LOGE("HdfSbufWriteUint32 turnStandbyStatus failed!");
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    int32_t ret = service->dispatcher->Dispatch(&service->object, cmdId, sBuf, NULL);
    AudioSbufRecycle(sBuf);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RenderStop Failed to send service call!");
    }
    return ret;
}

int32_t MmapDescWriteBuffer(struct HdfSBuf *sBuf, const struct AudioHwRenderParam *handleData)
{
    if (sBuf == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("param sBuf or handleData is null!");
        return HDF_FAILURE;
    }
    uint64_t mmapAddr = (uint64_t)(uintptr_t)(handleData->frameRenderMode.mmapBufDesc.memoryAddress);
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
    struct HdfIoService *service = NULL;
    int32_t ret;
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("AudioObtainHdfSBuf failed!");
        return HDF_FAILURE;
    }
    if (MmapDescWriteBuffer(sBuf, handleData)) {
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    service = (struct HdfIoService *)handle->object;
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        AudioSbufRecycle(sBuf);
        AUDIO_FUNC_LOGE("service or service->dispatcher or service->dispatcher->Dispatch is null!");
        return HDF_FAILURE;
    }
    ret = service->dispatcher->Dispatch(&service->object, cmdId, sBuf, NULL);
    AudioSbufRecycle(sBuf);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Failed to send service call!");
    }
    return ret;
}

int32_t AudioOutputRenderGetMmapPosition(const struct DevHandle *handle,
    int cmdId, struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    uint64_t frames = 0;
    struct HdfSBuf *reply = NULL;
    struct HdfIoService *service = NULL;

    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("handle or handle->object or handleData is null!");
        return HDF_FAILURE;
    }

    service = (struct HdfIoService *)handle->object;
    if (service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        AUDIO_FUNC_LOGE("service or service->dispatcher or service->dispatcher->Dispatch is null!");
        return HDF_FAILURE;
    }
    reply = AudioObtainHdfSBuf();
    if (reply == NULL) {
        AUDIO_FUNC_LOGE("RenderGetMmapPosition Failed to obtain reply");
        return HDF_FAILURE;
    }
    ret = service->dispatcher->Dispatch(&service->object, cmdId, NULL, reply);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("failed to send service call!");
        AudioSbufRecycle(reply);
        return HDF_FAILURE;
    }

    if (!HdfSbufReadUint64(reply, &frames)) {
        AUDIO_FUNC_LOGE("failed to get mmap position sBuf!");
        AudioSbufRecycle(reply);
        return HDF_FAILURE;
    }
    handleData->frameRenderMode.frames = frames;
    AudioSbufRecycle(reply);

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
    int32_t ret;
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
        case AUDIO_DRV_PCM_IOCTL_PREPARE:
        case AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE:
            ret = AudioOutputRenderStartPrepare(handle, cmdId, handleData);
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

int32_t AudioBindServiceRenderObject(struct DevHandle *handle, const char *name)
{
    if (handle == NULL || name == NULL) {
        AUDIO_FUNC_LOGE("service name or handle is NULL!");
        return HDF_FAILURE;
    }
    char *serviceName = (char *)OsalMemCalloc(NAME_LEN);
    if (serviceName == NULL) {
        AUDIO_FUNC_LOGE("Failed to alloc serviceName");
        return HDF_FAILURE;
    }
    int ret = snprintf_s(serviceName, NAME_LEN - 1, SERVIC_NAME_MAX_LEN + 1, "hdf_audio_%s", name);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Failed to snprintf_s");
        AudioMemFree((void **)&serviceName);
        return HDF_FAILURE;
    }
    struct HdfIoService *service = HdfIoServiceBindName(serviceName);
    if (service == NULL) {
        AUDIO_FUNC_LOGE("Failed to get service!");
        AudioMemFree((void **)&serviceName);
        return HDF_FAILURE;
    }
    AudioMemFree((void **)&serviceName);
    handle->object = service;
    return HDF_SUCCESS;
}

/* CreatRender for Bind handle */
struct DevHandle *AudioBindServiceRender(const char *name)
{
    struct DevHandle *handle = NULL;
    if (name == NULL) {
        AUDIO_FUNC_LOGE("service name NULL!");
        return NULL;
    }
    handle = (struct DevHandle *)OsalMemCalloc(sizeof(struct DevHandle));
    if (handle == NULL) {
        AUDIO_FUNC_LOGE("Failed to alloc handle");
        return NULL;
    }
    int32_t ret = AudioBindServiceRenderObject(handle, name);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("handle->object is NULL!");
        AudioMemFree((void **)&handle);
        return NULL;
    }
    AUDIO_FUNC_LOGI("BIND SERVICE SUCCESS!");
    return handle;
}

void AudioCloseServiceRender(const struct DevHandle *handle)
{
    if (handle == NULL || handle->object == NULL) {
        AUDIO_FUNC_LOGE("Render handle or handle->object is NULL");
        return;
    }
    struct HdfIoService *service = (struct HdfIoService *)handle->object;
    HdfIoServiceRecycle(service);
    AudioMemFree((void **)&handle);
    return;
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
