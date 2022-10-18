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

#include "audio_interface_lib_capture.h"
#include "osal_mem.h"
#include "audio_common.h"
#include "audio_uhdf_log.h"

#define HDF_LOG_TAG HDF_AUDIO_HAL_LIB

/* virtual mixer device */
#define AUDIO_REPLY_EXTEND 64
#define AUDIO_SIZE_FRAME_16K (16 * 1024)
#define AUDIO_TRYNUM 2
#define AUDIO_TRYNUM_TIME 3000
#define AUDIO_US_TO_MS 1000

/* Out Put Capture */
static struct AudioPcmHwParams g_hwParams;

int32_t SetHwParamsCapture(const struct AudioHwCaptureParam * const handleData)
{
    if (handleData == NULL) {
        AUDIO_FUNC_LOGE("handleData is NULL!");
        return HDF_FAILURE;
    }
    (void)memset_s(&g_hwParams, sizeof(struct AudioPcmHwParams), 0, sizeof(struct AudioPcmHwParams));
    g_hwParams.streamType = AUDIO_CAPTURE_STREAM;
    g_hwParams.channels = handleData->frameCaptureMode.attrs.channelCount;
    g_hwParams.rate = handleData->frameCaptureMode.attrs.sampleRate;
    g_hwParams.periodSize = handleData->frameCaptureMode.periodSize;
    g_hwParams.periodCount = handleData->frameCaptureMode.periodCount;
    g_hwParams.cardServiceName = (char*)handleData->captureMode.hwInfo.cardServiceName;
    g_hwParams.format = handleData->frameCaptureMode.attrs.format;
    g_hwParams.period = handleData->frameCaptureMode.attrs.period;
    g_hwParams.frameSize = handleData->frameCaptureMode.attrs.frameSize;
    g_hwParams.isBigEndian = handleData->frameCaptureMode.attrs.isBigEndian;
    g_hwParams.isSignedData = handleData->frameCaptureMode.attrs.isSignedData;
    g_hwParams.startThreshold = handleData->frameCaptureMode.attrs.startThreshold;
    g_hwParams.stopThreshold = handleData->frameCaptureMode.attrs.stopThreshold;
    g_hwParams.silenceThreshold = handleData->frameCaptureMode.attrs.silenceThreshold;
    return HDF_SUCCESS;
}

int32_t ParamsSbufWriteBuffer(struct HdfSBuf *sBuf)
{
    if (sBuf == NULL) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, (uint32_t)g_hwParams.streamType)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, g_hwParams.channels)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, g_hwParams.rate)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, g_hwParams.periodSize)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, g_hwParams.periodCount)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, (uint32_t)(g_hwParams.format))) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_hwParams.cardServiceName)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, g_hwParams.period)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, g_hwParams.frameSize)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, (uint32_t)(g_hwParams.isBigEndian))) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, (uint32_t)(g_hwParams.isSignedData))) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, g_hwParams.startThreshold)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, g_hwParams.stopThreshold)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, g_hwParams.silenceThreshold)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureSetPauseBuf(struct HdfSBuf *sBuf, const struct AudioHwCaptureParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("handleData or sBuf is NULL!");
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemCaptureValue;
    elemCaptureValue.id.cardServiceName = handleData->captureMode.hwInfo.cardServiceName;
    elemCaptureValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemCaptureValue.id.itemName = "Main Playback Pause";
    elemCaptureValue.value[0] = (int32_t)handleData->captureMode.ctlParam.pause;
    if (!HdfSbufWriteInt32(sBuf, elemCaptureValue.value[0])) {
        AUDIO_FUNC_LOGE("CaptureSetPauseBuf pause Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, elemCaptureValue.id.iface)) {
        AUDIO_FUNC_LOGE("CaptureSetPauseBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemCaptureValue.id.cardServiceName)) {
        AUDIO_FUNC_LOGE("CaptureSetPauseBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemCaptureValue.id.itemName)) {
        AUDIO_FUNC_LOGE("CaptureSetPauseBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureSetPauseStu(const struct DevHandleCapture *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData)
{
    int32_t ret;

    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("CaptureSetPauseStu paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("CaptureSetPauseStu Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    ret = AudioCtlCaptureSetPauseBuf(sBuf, handleData);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Failed to Set Pause sBuf!");
        AudioSbufRecycle(sBuf);
        return ret;
    }
    service = (struct HdfIoService *)handle->object;
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        AUDIO_FUNC_LOGE("SetPauseStu Service is NULL!");
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    cmdId = handleData->captureMode.ctlParam.pause ?
        AUDIO_DRV_PCM_IOCTRL_PAUSE_CAPTURE : AUDIO_DRV_PCM_IOCTRL_RESUME_CAPTURE;
    ret = service->dispatcher->Dispatch(&service->object, cmdId, sBuf, NULL);
    AudioSbufRecycle(sBuf);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("SetPauseStu Failed to send service call!");
    }
    return ret;
}

int32_t AudioCtlCaptureGetVolumeSBuf(struct HdfSBuf *sBuf, const struct AudioHwCaptureParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("CaptureGetVolumeSBuf  parameter is empty!");
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemCaptureValue;
    elemCaptureValue.id.cardServiceName = handleData->captureMode.hwInfo.cardServiceName;
    elemCaptureValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemCaptureValue.id.itemName = "Main Capture Volume";
    if (!HdfSbufWriteInt32(sBuf, elemCaptureValue.id.iface)) {
        AUDIO_FUNC_LOGE("CaptureGetVolumeSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemCaptureValue.id.cardServiceName)) {
        AUDIO_FUNC_LOGE("CaptureGetVolumeSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemCaptureValue.id.itemName)) {
        AUDIO_FUNC_LOGE("CaptureGetVolumeSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureGetVolume(const struct DevHandleCapture *handle,
    int cmdId, struct AudioHwCaptureParam *handleData)
{
    int32_t ret;
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("CaptureGetVolume paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("CaptureGetVolume Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    reply = AudioObtainHdfSBuf();
    if (reply == NULL) {
        AUDIO_FUNC_LOGE("Failed to obtain reply");
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    ret = AudioCtlCaptureGetVolumeSBuf(sBuf, handleData);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Failed to Get Volume sBuf!");
        AudioBufReplyRecycle(sBuf, reply);
        return ret;
    }
    service = (struct HdfIoService *)handle->object;
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE - CTRL_NUM;
    ret = AudioServiceDispatch(service, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("GetVolume Dispatch Fail!");
        AudioBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    int32_t elemValue = 0;
    if (!HdfSbufReadInt32(reply, &elemValue)) {
        AUDIO_FUNC_LOGE("Failed to Get Volume sBuf!");
        AudioBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    AudioBufReplyRecycle(sBuf, reply);
    handleData->captureMode.ctlParam.volume = (float)elemValue;
    return ret;
}

int32_t AudioCtlCaptureSetVolumeSBuf(struct HdfSBuf *sBuf, const struct AudioHwCaptureParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("CaptureSetVolumeSBuf parameter is empty!");
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemCaptureValue;
    elemCaptureValue.id.cardServiceName = handleData->captureMode.hwInfo.cardServiceName;
    elemCaptureValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemCaptureValue.id.itemName = "Main Capture Volume";
    elemCaptureValue.value[0] = (int32_t)handleData->captureMode.ctlParam.volume;
    if (!HdfSbufWriteInt32(sBuf, elemCaptureValue.value[0])) {
        AUDIO_FUNC_LOGE("CaptureSetVolumeSBuf value[0] Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, elemCaptureValue.id.iface)) {
        AUDIO_FUNC_LOGE("CaptureSetVolumeSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemCaptureValue.id.cardServiceName)) {
        AUDIO_FUNC_LOGE("CaptureSetVolumeSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemCaptureValue.id.itemName)) {
        AUDIO_FUNC_LOGE("CaptureSetVolumeSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureSetVolume(const struct DevHandleCapture *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData)
{
    int32_t ret;
    AUDIO_FUNC_LOGI();
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("CaptureSetVolume paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("CaptureSetVolume Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    ret = AudioCtlCaptureSetVolumeSBuf(sBuf, handleData);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("CaptureSetVolume Failed to Set Volume sBuf!");
        AudioSbufRecycle(sBuf);
        return ret;
    }
    service = (struct HdfIoService *)handle->object;
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        AUDIO_FUNC_LOGE("CaptureSetVolume Service is NULL!");
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE - CTRL_NUM;
    ret = service->dispatcher->Dispatch(&service->object, cmdId, sBuf, reply);
    AudioSbufRecycle(sBuf);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("CaptureSetVolume Failed to send service call!");
    }
    return ret;
}

int32_t AudioCtlCaptureSetMuteSBuf(struct HdfSBuf *sBuf, const struct AudioHwCaptureParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("handleData or sBuf is NULL!");
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemCaptureValue;
    elemCaptureValue.id.cardServiceName = handleData->captureMode.hwInfo.cardServiceName;
    elemCaptureValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemCaptureValue.id.itemName = "Capture Mute";
    elemCaptureValue.value[0] = (int32_t)handleData->captureMode.ctlParam.mute;
    if (!HdfSbufWriteInt32(sBuf, elemCaptureValue.value[0])) {
        AUDIO_FUNC_LOGE("CaptureSetMuteSBuf mute Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, elemCaptureValue.id.iface)) {
        AUDIO_FUNC_LOGE("CaptureSetMuteSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemCaptureValue.id.cardServiceName)) {
        AUDIO_FUNC_LOGE("CaptureSetMuteSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemCaptureValue.id.itemName)) {
        AUDIO_FUNC_LOGE("CaptureSetMuteSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureSetMuteStu(const struct DevHandleCapture *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData)
{
    int32_t ret;

    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("CaptureSetMuteStu paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("CaptureSetMuteStu Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    ret = AudioCtlCaptureSetMuteSBuf(sBuf, handleData);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("CaptureSetMuteStu Failed to Get Mute sBuf!");
        AudioSbufRecycle(sBuf);
        return ret;
    }
    service = (struct HdfIoService *)handle->object;
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        AUDIO_FUNC_LOGE("CaptureSetMuteStu Service is NULL!");
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE - CTRL_NUM;
    ret = service->dispatcher->Dispatch(&service->object, cmdId, sBuf, NULL);
    AudioSbufRecycle(sBuf);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("CaptureSetMuteStu Failed to send service call!");
    }
    return ret;
}

int32_t AudioCtlCaptureGetMuteSBuf(struct HdfSBuf *sBuf, const struct AudioHwCaptureParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("The parameter is empty!");
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemCaptureValue;
    elemCaptureValue.id.cardServiceName = handleData->captureMode.hwInfo.cardServiceName;
    elemCaptureValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemCaptureValue.id.itemName = "Capture Mute";
    if (!HdfSbufWriteInt32(sBuf, elemCaptureValue.id.iface)) {
        AUDIO_FUNC_LOGE("CaptureGetMuteSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemCaptureValue.id.cardServiceName)) {
        AUDIO_FUNC_LOGE("CaptureGetMuteSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemCaptureValue.id.itemName)) {
        AUDIO_FUNC_LOGE("CaptureGetMuteSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureGetMuteStu(const struct DevHandleCapture *handle,
    int cmdId, struct AudioHwCaptureParam *handleData)
{
    int32_t ret;

    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("CaptureGetMuteStu paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("CaptureGetMuteStu Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    reply = AudioObtainHdfSBuf();
    if (reply == NULL) {
        AUDIO_FUNC_LOGE("Failed to obtain reply");
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    ret = AudioCtlCaptureGetMuteSBuf(sBuf, handleData);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Failed to Get Mute sBuf!");
        AudioBufReplyRecycle(sBuf, reply);
        return ret;
    }
    service = (struct HdfIoService *)handle->object;
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE - CTRL_NUM;
    ret = AudioServiceDispatch(service, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("CaptureGetMuteStu Dispatch Fail!");
        AudioBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    int32_t muteValueStu = 0;
    if (!HdfSbufReadInt32(reply, &muteValueStu)) {
        AUDIO_FUNC_LOGE("CaptureGetMuteStu Failed to Get Volume sBuf!");
        AudioBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    AudioBufReplyRecycle(sBuf, reply);
    handleData->captureMode.ctlParam.mute = (bool)muteValueStu;
    return ret;
}

int32_t AudioCtlCaptureSetGainSBuf(struct HdfSBuf *sBuf, const struct AudioHwCaptureParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("CaptureSetGainSBuf( handleData or sBuf is NULL!");
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemCaptureValue;
    elemCaptureValue.id.cardServiceName = handleData->captureMode.hwInfo.cardServiceName;
    elemCaptureValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemCaptureValue.id.itemName = "Mic Left Gain";
    elemCaptureValue.value[0] = handleData->captureMode.ctlParam.audioGain.gain;
    if (!HdfSbufWriteInt32(sBuf, elemCaptureValue.value[0])) {
        AUDIO_FUNC_LOGE("CaptureSetGainSBuf mute Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, elemCaptureValue.id.iface)) {
        AUDIO_FUNC_LOGE("CaptureSetGainSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemCaptureValue.id.cardServiceName)) {
        AUDIO_FUNC_LOGE("CaptureSetGainSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemCaptureValue.id.itemName)) {
        AUDIO_FUNC_LOGE("CaptureSetGainSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureSetGainStu(const struct DevHandleCapture *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData)
{
    int32_t ret;

    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("CaptureSetGainStu paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("CaptureSetGainStu Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    ret = AudioCtlCaptureSetGainSBuf(sBuf, handleData);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("CaptureSetGainStu Failed to Get Gain sBuf!");
        AudioSbufRecycle(sBuf);
        return ret;
    }
    service = (struct HdfIoService *)handle->object;
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        AUDIO_FUNC_LOGE("CaptureSetGainStu Service is NULL!");
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE - CTRL_NUM;
    ret = service->dispatcher->Dispatch(&service->object, cmdId, sBuf, NULL);
    AudioSbufRecycle(sBuf);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("CaptureSetGainStu Failed to send service call!");
    }
    return ret;
}

int32_t AudioCtlCaptureGetGainSBuf(struct HdfSBuf *sBuf, const struct AudioHwCaptureParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("CaptureGetGainSBuf paras is NULL!");
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemCaptureValue;
    elemCaptureValue.id.cardServiceName = handleData->captureMode.hwInfo.cardServiceName;
    elemCaptureValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemCaptureValue.id.itemName = "Mic Left Gain";
    if (!HdfSbufWriteInt32(sBuf, elemCaptureValue.id.iface)) {
        AUDIO_FUNC_LOGE("CaptureGetGainSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemCaptureValue.id.cardServiceName)) {
        AUDIO_FUNC_LOGE("CaptureGetGainSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemCaptureValue.id.itemName)) {
        AUDIO_FUNC_LOGE("CaptureGetGainSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureGetGainStu(const struct DevHandleCapture *handle,
    int cmdId, struct AudioHwCaptureParam *handleData)
{
    int32_t ret;

    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("CaptureGetGainStu paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("CaptureGetGainStu Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    reply = AudioObtainHdfSBuf();
    if (reply == NULL) {
        AUDIO_FUNC_LOGE("Failed to obtain reply");
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    ret = AudioCtlCaptureGetGainSBuf(sBuf, handleData);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Failed to Get Gain sBuf!");
        AudioBufReplyRecycle(sBuf, reply);
        return ret;
    }
    service = (struct HdfIoService *)handle->object;
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE - CTRL_NUM;
    ret = AudioServiceDispatch(service, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("GetGainStu Dispatch Fail!");
        AudioBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    int32_t muteValueStu = 0;
    if (!HdfSbufReadInt32(reply, &muteValueStu)) {
        AUDIO_FUNC_LOGE("Failed to GetGain sBuf!");
        AudioBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    AudioBufReplyRecycle(sBuf, reply);
    handleData->captureMode.ctlParam.audioGain.gain = (float)muteValueStu;
    return ret;
}

int32_t AudioCtlCaptureSceneSelectSBuf(struct HdfSBuf *sBuf,
    const struct AudioHwCaptureParam *handleData, int32_t deviceIndex)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("CaptureSceneSelectSBuf handleData or sBufs is NULL!");
        return HDF_FAILURE;
    }
    if (deviceIndex < 0 || deviceIndex > PATHPLAN_COUNT - 1) {
        AUDIO_FUNC_LOGE("deviceIndex is Invalid!");
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemCaptureValue;
    elemCaptureValue.id.cardServiceName = handleData->captureMode.hwInfo.cardServiceName;
    elemCaptureValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemCaptureValue.id.itemName =
        handleData->captureMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[deviceIndex].deviceSwitch;
    elemCaptureValue.value[0] = handleData->captureMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[deviceIndex].value;
    if (!HdfSbufWriteInt32(sBuf, elemCaptureValue.value[0])) {
        AUDIO_FUNC_LOGE("CaptureSceneSelectSBuf Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, elemCaptureValue.id.iface)) {
        AUDIO_FUNC_LOGE("CaptureSceneSelectSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemCaptureValue.id.cardServiceName)) {
        AUDIO_FUNC_LOGE("CaptureSceneSelectSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemCaptureValue.id.itemName)) {
        AUDIO_FUNC_LOGE("CaptureSceneSelectSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureSceneSelect(const struct DevHandleCapture *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData)
{
    int32_t index;

    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("CaptureSceneSelect parameter is empty!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    service = (struct HdfIoService *)handle->object;
    int32_t deviceNum = handleData->captureMode.hwInfo.pathSelect.deviceInfo.deviceNum;
    if (deviceNum < AUDIO_MIN_DEVICENUM) {
        AUDIO_FUNC_LOGE("AUDIO_MIN_ADAPTERNUM Failed!");
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        AUDIO_FUNC_LOGE("CaptureSceneSelect Service is NULL!");
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE - CTRL_NUM;
    for (index = 0; index < deviceNum; index++) {
        HdfSbufFlush(sBuf);
        if (AudioCtlCaptureSceneSelectSBuf(sBuf, handleData, index) < 0) {
            AUDIO_FUNC_LOGE("AudioCtlCaptureSceneSelectSBuf Failed!");
            AudioSbufRecycle(sBuf);
            return HDF_FAILURE;
        }
        if (service->dispatcher->Dispatch(&service->object, cmdId, sBuf, NULL) < 0) {
            AUDIO_FUNC_LOGE("CaptureSceneSelect Failed to send service call!");
            AudioSbufRecycle(sBuf);
            return HDF_FAILURE;
        }
    }
    AudioSbufRecycle(sBuf);
    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureGetGainThresholdSBuf(struct HdfSBuf *sBuf, const struct AudioHwCaptureParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("CaptureGetGainThresholdSBuf paras is empty!");
        return HDF_FAILURE;
    }
    struct AudioCtrlElemInfo elemCaptureInfo;
    elemCaptureInfo.id.cardServiceName = handleData->captureMode.hwInfo.cardServiceName;
    elemCaptureInfo.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemCaptureInfo.id.itemName = "Mic Left Gain";
    if (!HdfSbufWriteInt32(sBuf, elemCaptureInfo.id.iface)) {
        AUDIO_FUNC_LOGE("CaptureGetGainThresholdSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemCaptureInfo.id.cardServiceName)) {
        AUDIO_FUNC_LOGE("CaptureGetGainThresholdSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemCaptureInfo.id.itemName)) {
        AUDIO_FUNC_LOGE("CaptureGetGainThresholdSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureGetGainThreshold(const struct DevHandleCapture *handle,
    int cmdId, struct AudioHwCaptureParam *handleData)
{
    int32_t ret;

    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("CaptureGetGainThreshold paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("CaptureGetGainThreshold Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    reply = AudioObtainHdfSBuf();
    if (reply == NULL) {
        AUDIO_FUNC_LOGE("CaptureGetGainThreshold Failed to obtain reply");
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    ret = AudioCtlCaptureGetGainThresholdSBuf(sBuf, handleData);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("CaptureGetGainThreshold Failed to Get Threshold sBuf!");
        AudioBufReplyRecycle(sBuf, reply);
        return ret;
    }
    service = (struct HdfIoService *)handle->object;
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_INFO_CAPTURE - CTRL_NUM;
    ret = AudioServiceDispatch(service, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        AudioBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    struct AudioCtrlElemInfo gainThreshold;
    (void)memset_s(&gainThreshold, sizeof(struct AudioCtrlElemInfo), 0, sizeof(struct AudioCtrlElemInfo));
    if (!HdfSbufReadInt32(reply, &gainThreshold.type)) {
        AUDIO_FUNC_LOGE("CaptureGetGainThreshold Failed to HdfSbufReadBuffer!");
        AudioBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadInt32(reply, &gainThreshold.max)) {
        AUDIO_FUNC_LOGE("CaptureGetGainThreshold Failed to HdfSbufReadBuffer!");
        AudioBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    AudioBufReplyRecycle(sBuf, reply);
    handleData->captureMode.ctlParam.audioGain.gainMax = gainThreshold.max;
    handleData->captureMode.ctlParam.audioGain.gainMin = 0;
    return ret;
}

int32_t AudioCtlCaptureGetVolThresholdSBuf(struct HdfSBuf *sBuf, const struct AudioHwCaptureParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("CaptureGetVolThresholdSBuf paras is empty!");
        return HDF_FAILURE;
    }
    struct AudioCtrlElemInfo elemCaptureInfo;
    elemCaptureInfo.id.cardServiceName = handleData->captureMode.hwInfo.cardServiceName;
    elemCaptureInfo.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemCaptureInfo.id.itemName = "Main Capture Volume";
    if (!HdfSbufWriteInt32(sBuf, elemCaptureInfo.id.iface)) {
        AUDIO_FUNC_LOGE("elemCaptureInfo.id.iface iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemCaptureInfo.id.cardServiceName)) {
        AUDIO_FUNC_LOGE("CaptureGetVolThresholdSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, elemCaptureInfo.id.itemName)) {
        AUDIO_FUNC_LOGE("CaptureGetVolThresholdSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureGetVolThreshold(const struct DevHandleCapture *handle,
    int cmdId, struct AudioHwCaptureParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("Failed to Get sBuf");
        return HDF_FAILURE;
    }
    struct HdfSBuf *reply = AudioObtainHdfSBuf();
    if (reply == NULL) {
        AUDIO_FUNC_LOGE("Failed to obtain reply");
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    int32_t ret = AudioCtlCaptureGetVolThresholdSBuf(sBuf, handleData);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Failed to Get Threshold sBuf!");
        AudioBufReplyRecycle(sBuf, reply);
        return ret;
    }
    struct HdfIoService *service = (struct HdfIoService *)handle->object;
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_INFO_CAPTURE - CTRL_NUM;
    ret = AudioServiceDispatch(service, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        AudioBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    struct AudioCtrlElemInfo volThreshold;
    ret = AudioCtlGetVolThresholdRead(reply, &volThreshold);
    AudioBufReplyRecycle(sBuf, reply);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("[AudioCtlGetVolThresholdRead] failed!");
        return HDF_FAILURE;
    }
    handleData->captureMode.ctlParam.volThreshold.volMax = volThreshold.max;
    handleData->captureMode.ctlParam.volThreshold.volMin = volThreshold.min;
    return ret;
}

int32_t AudioInterfaceLibCtlCapture(const struct DevHandleCapture *handle,
    int cmdId, struct AudioHwCaptureParam *handleData)
{
    int32_t ret;

    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("paras is NULL!");
        return HDF_FAILURE;
    }
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

int32_t AudioOutputCaptureHwParams(const struct DevHandleCapture *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("Function parameter is NULL!");
        return HDF_FAILURE;
    }
    int32_t ret;
    struct HdfIoService *service = NULL;
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    if (SetHwParamsCapture(handleData) < 0) {
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    if (ParamsSbufWriteBuffer(sBuf) < 0) {
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    service = (struct HdfIoService *)handle->object;
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        AUDIO_FUNC_LOGE("Function parameter is empty!");
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    ret = service->dispatcher->Dispatch(&service->object, cmdId, sBuf, NULL);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Failed to send service call: ret = %{public}d!", ret);
    }
    AudioBufReplyRecycle(sBuf, NULL);

    return ret;
}

int32_t AudioOutputCaptureOpen(const struct DevHandleCapture *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("Function parameter is NULL!");
        return HDF_FAILURE;
    }
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, handleData->captureMode.hwInfo.cardServiceName)) {
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    struct HdfIoService *service = (struct HdfIoService *)handle->object;
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        AUDIO_FUNC_LOGE("Function parameter is empty!");
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    int32_t ret = service->dispatcher->Dispatch(&service->object, cmdId, sBuf, NULL);
    AudioSbufRecycle(sBuf);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Failed to send service call!");
    }
    return ret;
}

int32_t AudioOutputCaptureReadFrame(struct HdfIoService *service, int cmdId, struct HdfSBuf *reply)
{
    int32_t ret;
    int32_t buffStatus = 0;
    int32_t tryNumReply = 100; // try get reply count
    if (service == NULL || reply == NULL) {
        AUDIO_FUNC_LOGE("paras is NULL!");
        return HDF_FAILURE;
    }
    if (service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        AUDIO_FUNC_LOGE("service->dispatcher is null!");
        return HDF_FAILURE;
    }
    do {
        ret = service->dispatcher->Dispatch(&service->object, cmdId, NULL, reply);
        if (ret != HDF_SUCCESS) {
            AUDIO_FUNC_LOGE("Failed to send service call!");
            return ret;
        }
        if (!HdfSbufReadInt32(reply, &buffStatus)) {
            AUDIO_FUNC_LOGE("Failed to Get buffStatus!");
            return HDF_FAILURE;
        }
        if (buffStatus == CIR_BUFF_EMPTY) {
            tryNumReply--;
            HdfSbufFlush(reply);
            usleep(AUDIO_CAP_WAIT_DELAY + (tryNumReply % AUDIO_TRYNUM) * AUDIO_TRYNUM_TIME);
            AUDIO_FUNC_LOGD("Cir buff empty wait");
            continue;
        } else if (buffStatus >= 0) {
            AUDIO_FUNC_LOGD("capture need wait for %{public}d ms!", buffStatus);
            usleep(buffStatus * AUDIO_US_TO_MS);
            tryNumReply--;
            HdfSbufFlush(reply);
            continue;
        }
        break;
    } while (tryNumReply > 0);
    if (tryNumReply <= 0) {
        AUDIO_FUNC_LOGE("Out of tryNumReply!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

#ifdef MONO_TO_STEREO
void CaptureChannelFixed(void *data, uint32_t len)
{
    int16_t *pcmLeft = (int16_t*)data;
    int16_t *pcmRight = pcmLeft + 1; // right channel offset + 1

    for (uint32_t index = 0; index < len; index += 2) { // 16bit, step = 2
        pcmRight[index] = pcmLeft[index];
    }
    return;
}
#endif

int32_t AudioInputCaptureReadInfoToHandleData(struct AudioHwCaptureParam *handleData,
    char *frame, uint32_t frameCount, uint32_t dataSize)
{
    int32_t ret = memcpy_s(handleData->frameCaptureMode.buffer, FRAME_DATA, frame, dataSize);
    if (ret != 0) {
        return HDF_FAILURE;
    }
#ifdef MONO_TO_STEREO
    if (g_hwParams.channels == 2) { // if rk3568 channel = 2, and 16bit
        CaptureChannelFixed(handleData->frameCaptureMode.buffer, dataSize / 2); // len = dataSize / 2
    }
#endif
    handleData->frameCaptureMode.bufferSize = dataSize;
    handleData->frameCaptureMode.bufferFrameSize = frameCount;
    return HDF_SUCCESS;
}

int32_t AudioOutputCaptureRead(const struct DevHandleCapture *handle,
    int cmdId, struct AudioHwCaptureParam *handleData)
{
    uint32_t dataSize = 0;
    uint32_t frameCount = 0;
    size_t replySize = AUDIO_SIZE_FRAME_16K + AUDIO_REPLY_EXTEND;
    char *frame = NULL;
    struct HdfIoService *service = NULL;
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfSBuf *reply = HdfSbufTypedObtainCapacity(SBUF_RAW, replySize);
    if (reply == NULL) {
        AUDIO_FUNC_LOGE("HdfSbufTypedObtainCapacity replySize failed!");
        return HDF_FAILURE;
    }
    service = (struct HdfIoService *)handle->object;
    int32_t ret = AudioOutputCaptureReadFrame(service, cmdId, reply);
    if (ret != HDF_SUCCESS) {
        AudioSbufRecycle(reply);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadBuffer(reply, (const void **)&frame, &dataSize)) {
        AUDIO_FUNC_LOGE("[HdfSbufReadBuffer]-[frame] failed!");
        AudioSbufRecycle(reply);
        return HDF_FAILURE;
    }
    if (dataSize > FRAME_DATA || handleData->frameCaptureMode.buffer == NULL) {
        AUDIO_FUNC_LOGE("Buffer is NULL or DataSize overflow!");
        AudioSbufRecycle(reply);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(reply, &frameCount)) {
        AUDIO_FUNC_LOGE("Failed to Get buffStatus!");
        AudioSbufRecycle(reply);
        return HDF_FAILURE;
    }
    ret = AudioInputCaptureReadInfoToHandleData(handleData, frame, frameCount, dataSize);
    AudioSbufRecycle(reply);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("AudioInputCaptureReadInfoToHandleData Failed!");
    }
    return ret;
}

int32_t AudioOutputCaptureStartPrepare(const struct DevHandleCapture *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData)
{
    int32_t ret;
    struct HdfIoService *service = NULL;
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("CaptureStartPrepare paras is NULL!");
        return HDF_FAILURE;
    }
    service = (struct HdfIoService *)handle->object;
    if (service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        AUDIO_FUNC_LOGE("CaptureStartPrepare Service is NULL!");
        return HDF_FAILURE;
    }
    ret = service->dispatcher->Dispatch(&service->object, cmdId, NULL, NULL);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("CaptureStartPrepare Failed to send service call!");
    }
    return ret;
}

int32_t AudioOutputCaptureStop(const struct DevHandleCapture *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData)
{
    int32_t ret;
    struct HdfIoService *service = NULL;
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("CaptureStop paras is NULL!");
        return HDF_FAILURE;
    }
    service = (struct HdfIoService *)handle->object;
    if (service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        AUDIO_FUNC_LOGE("CaptureStop Service is NULL!");
        return HDF_FAILURE;
    }
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("AudioObtainHdfSBuf failed!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, AUDIO_TURN_STANDBY_LATER)) {
        AudioSbufRecycle(sBuf);
        return HDF_FAILURE;
    }
    ret = service->dispatcher->Dispatch(&service->object, cmdId, sBuf, NULL);
    AudioSbufRecycle(sBuf);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("CaptureStop Failed to send service call!");
    }
    return ret;
}

int32_t MmapDescWriteBufferCapture(struct HdfSBuf *sBuf, const struct AudioHwCaptureParam *handleData)
{
    if (sBuf == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("param sBuf or handleData is null!");
        return HDF_FAILURE;
    }
    uint64_t mmapAddr = (uint64_t)(uintptr_t)(handleData->frameCaptureMode.mmapBufDesc.memoryAddress);
    if (!HdfSbufWriteUint64(sBuf, mmapAddr)) {
        AUDIO_FUNC_LOGE("HdfSbufWriteUint64 memoryAddress failed!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, handleData->frameCaptureMode.mmapBufDesc.memoryFd)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, handleData->frameCaptureMode.mmapBufDesc.totalBufferFrames)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, handleData->frameCaptureMode.mmapBufDesc.transferFrameSize)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, handleData->frameCaptureMode.mmapBufDesc.isShareable)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, handleData->frameCaptureMode.mmapBufDesc.offset)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioOutputCaptureReqMmapBuffer(const struct DevHandleCapture *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("handle or handle->object or handleData is null!");
        return HDF_FAILURE;
    }
    int32_t ret;
    struct HdfIoService *service = NULL;
    struct HdfSBuf *sBuf = AudioObtainHdfSBuf();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("AudioObtainHdfSBuf failed!");
        return HDF_FAILURE;
    }
    if (MmapDescWriteBufferCapture(sBuf, handleData)) {
        AudioSbufRecycle(sBuf);
        AUDIO_FUNC_LOGE("MmapDescWriteBufferCapture failed!");
        return HDF_FAILURE;
    }
    service = (struct HdfIoService *)handle->object;
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        AudioSbufRecycle(sBuf);
        AUDIO_FUNC_LOGE("The pointer is empty!");
        return HDF_FAILURE;
    }
    ret = service->dispatcher->Dispatch(&service->object, cmdId, sBuf, NULL);
    AudioSbufRecycle(sBuf);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Failed to send service call!");
    }
    return ret;
}

int32_t AudioOutputCaptureGetMmapPosition(const struct DevHandleCapture *handle,
    int cmdId, struct AudioHwCaptureParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("handle or handle->object or handleData is null!");
        return HDF_FAILURE;
    }
    int32_t ret;
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    service = (struct HdfIoService *)handle->object;
    if (service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        AUDIO_FUNC_LOGE("The pointer is empty!");
        return HDF_FAILURE;
    }
    reply = AudioObtainHdfSBuf();
    if (reply == NULL) {
        AUDIO_FUNC_LOGE("CaptureGetMmapPosition Failed to obtain reply");
        return HDF_FAILURE;
    }
    ret = service->dispatcher->Dispatch(&service->object, cmdId, NULL, reply);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Failed to send service call: ret = %{public}d.", ret);
        AudioSbufRecycle(reply);
        return HDF_FAILURE;
    }
    uint64_t frames = 0;
    if (!HdfSbufReadUint64(reply, &frames)) {
        AUDIO_FUNC_LOGE("Failed to Get frames sBuf:ret = %{public}d.", ret);
        AudioSbufRecycle(reply);
        return HDF_FAILURE;
    }
    AudioSbufRecycle(reply);
    handleData->frameCaptureMode.frames = frames;
    return ret;
}

int32_t AudioInterfaceLibOutputCapture(const struct DevHandleCapture *handle, int cmdId,
    struct AudioHwCaptureParam *handleData)
{
    if (handle == NULL) {
        AUDIO_FUNC_LOGE("Input Capture handle is NULL!");
        return HDF_FAILURE;
    }
    if (handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("handle->object or handleData is null!");
        return HDF_FAILURE;
    }
    int32_t ret;
    switch (cmdId) {
        case AUDIO_DRV_PCM_IOCTL_HW_PARAMS:
            ret = AudioOutputCaptureHwParams(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTL_READ:
            ret = AudioOutputCaptureRead(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTRL_START_CAPTURE:
        case AUDIO_DRV_PCM_IOCTL_PREPARE_CAPTURE:
        case AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE:
            ret = AudioOutputCaptureStartPrepare(handle, cmdId, handleData);
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

struct DevHandleCapture *AudioBindServiceCaptureObject(struct DevHandleCapture * const handle,
    const char *name)
{
    if (handle == NULL || name == NULL) {
        AUDIO_FUNC_LOGE("service name or handle is NULL!");
        return NULL;
    }
    char *serviceName = (char *)OsalMemCalloc(NAME_LEN);
    if (serviceName == NULL) {
        AUDIO_FUNC_LOGE("Failed to alloc serviceName");
        AudioMemFree((void **)&handle);
        return NULL;
    }
    int ret = snprintf_s(serviceName, NAME_LEN - 1, SERVIC_NAME_MAX_LEN + 1, "hdf_audio_%s", name);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Failed to snprintf_s");
        AudioMemFree((void **)&serviceName);
        AudioMemFree((void **)&handle);
        return NULL;
    }
    struct HdfIoService *service = HdfIoServiceBindName(serviceName);
    if (service == NULL) {
        AUDIO_FUNC_LOGE("Failed to get service!");
        AudioMemFree((void **)&serviceName);
        AudioMemFree((void **)&handle);
        return NULL;
    }
    AudioMemFree((void **)&serviceName);
    handle->object = service;
    return handle->object;
}

/* CreatCapture for Bind handle */
struct DevHandleCapture *AudioBindServiceCapture(const char *name)
{
    struct DevHandleCapture *handle = NULL;
    struct DevHandleCapture *object = NULL;
    if (name == NULL) {
        AUDIO_FUNC_LOGE("service name NULL!");
        return NULL;
    }
    handle = (struct DevHandleCapture *)OsalMemCalloc(sizeof(struct DevHandleCapture));
    if (handle == NULL) {
        AUDIO_FUNC_LOGE("Failed to alloc handle");
        return NULL;
    }
    object = AudioBindServiceCaptureObject(handle, name);
    if (object != NULL) {
        handle->object = object;
    } else {
        AUDIO_FUNC_LOGE("handle->object is NULL!");
        return NULL;
    }
    AUDIO_FUNC_LOGI("BIND SERVICE SUCCESS!");
    return handle;
}

void AudioCloseServiceCapture(const struct DevHandleCapture *handle)
{
    AUDIO_FUNC_LOGI();
    if (handle == NULL || handle->object == NULL) {
        AUDIO_FUNC_LOGE("Capture handle or handle->object is NULL");
        return;
    }
    struct HdfIoService *service = (struct HdfIoService *)handle->object;
    HdfIoServiceRecycle(service);
    AudioMemFree((void **)&handle);
    return;
}

int32_t AudioInterfaceLibModeCapture(const struct DevHandleCapture *handle,
    struct AudioHwCaptureParam *handleData, int cmdId)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("paras is NULL!");
        return HDF_FAILURE;
    }
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
