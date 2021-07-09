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

/* virtual mixer device */
#define AUDIODRV_CTL_CAPTUREELEM_IFACE_MIXER ((int32_t)2)
#define AUDIODRV_CTL_ELEM_IFACE_ADC 1
#define AUDIODRV_CTL_ELEM_IFACE_GAIN 2
#define AUDIODRV_CTL_ELEM_IFACE_SELECT 5

#define AUDIO_REPLY_EXTEND 16
#define AUDIO_SIZE_FRAME_16K (16 * 1024)
#define AUDIO_MIN_DEVICENUM 1

#define AUDIO_WAIT_MSEC 10000

/* Out Put Capture */
static struct AudioPcmHwParams {
    enum AudioStreamType streamType;
    uint32_t channels;
    uint32_t rate;
    uint32_t periodSize;
    uint32_t periodCount;
    enum AudioFormat format;
    char *cardServiceName;
    uint32_t period;
    uint32_t frameSize;
    bool isBigEndian;
    bool isSignedData;
    uint32_t startThreshold;
    uint32_t stopThreshold;
    uint32_t silenceThreshold;
} g_hwParams;

/* Frames data and size */
struct AudioCtlCaptureElemId {
    const char *cardServiceName;
    int32_t iface;
    const char *itemName;
};

static struct AudioCtlCaptureElemValue {
    struct AudioCtlCaptureElemId id;
    int32_t value[2];
} g_elemCaptureValue;

static struct AudioCtrlCaptureElemInfo {
    struct AudioCtlCaptureElemId id;
    uint32_t count;     /* count of values */
    int32_t type;       /* R: value type - AUDIODRV_CTL_ELEM_IFACE_MIXER_* */
    int32_t min;        /* R: minimum value */
    int32_t max;        /* R: maximum value */
} g_elemCaptureInfo;

struct HdfSBuf *AudioCapturebtainHdfSBuf()
{
    enum HdfSbufType bufType;
#ifdef AUDIO_HDF_SBUF_IPC
    bufType = SBUF_IPC;
#else
    bufType = SBUF_RAW;
#endif
    return HdfSBufTypedObtain(bufType);
}

char *g_audioServiceCapture[AUDIO_SERVICE_MAX] = {
    [AUDIO_SERVICE_IN] = "hdf_audio_codec_dev0",
    [AUDIO_SERVICE_OUT] = "hdf_audio_smartpa_dev0",
};

void AudioCaptureBufReplyRecycle(struct HdfSBuf *sBuf, struct HdfSBuf *reply)
{
    if (sBuf != NULL) {
        HdfSBufRecycle(sBuf);
    }
    if (reply != NULL) {
        HdfSBufRecycle(reply);
    }
    return;
}

int32_t AudioServiceCaptureDispatch(struct HdfIoService *service,
                                    int cmdId,
                                    struct HdfSBuf *sBuf,
                                    struct HdfSBuf *reply)
{
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL ||
        sBuf == NULL) {
        LOG_FUN_ERR("Service is NULL!");
        return HDF_FAILURE;
    }
    int32_t ret;
    ret = service->dispatcher->Dispatch(&(service->object), cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        LOG_FUN_ERR("Failed to send service call!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t SetHwParamsCapture(const struct AudioHwCaptureParam * const handleData)
{
    if (handleData == NULL) {
        LOG_FUN_ERR("handleData is NULL!");
        return HDF_FAILURE;
    }
    memset_s(&g_hwParams, sizeof(struct AudioPcmHwParams), 0, sizeof(struct AudioPcmHwParams));
    uint32_t card = handleData->captureMode.hwInfo.card;
    if (card < 0 || card >= AUDIO_SERVICE_MAX) {
        LOG_FUN_ERR("card is Error!");
        return HDF_FAILURE;
    }
    g_hwParams.streamType = AUDIO_CAPTURE_STREAM;
    g_hwParams.channels = handleData->frameCaptureMode.attrs.channelCount;
    g_hwParams.rate = handleData->frameCaptureMode.attrs.sampleRate;
    g_hwParams.periodSize = handleData->frameCaptureMode.periodSize;
    g_hwParams.periodCount = handleData->frameCaptureMode.periodCount;
    g_hwParams.cardServiceName = g_audioServiceCapture[card];
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

int32_t ParamsSbufWriteBufferCapture(struct HdfSBuf *sBuf)
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

int32_t AudioCtlCaptureSetPauseBuf(struct HdfSBuf *sBuf, struct AudioHwCaptureParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        LOG_FUN_ERR("handleData or sBuf is NULL!");
        return HDF_FAILURE;
    }
    memset_s(&g_elemCaptureValue, sizeof(struct AudioCtlCaptureElemValue), 0, sizeof(struct AudioCtlCaptureElemValue));
    uint32_t card = handleData->captureMode.hwInfo.card;
    if (card < 0 || card >= AUDIO_SERVICE_MAX) {
        LOG_FUN_ERR("wrong card!");
        return HDF_FAILURE;
    }
    g_elemCaptureValue.id.cardServiceName = g_audioServiceCapture[card];
    g_elemCaptureValue.id.iface = AUDIODRV_CTL_CAPTUREELEM_IFACE_MIXER;
    g_elemCaptureValue.id.itemName = "Master Playback Pause";
    g_elemCaptureValue.value[0] = (int32_t)handleData->captureMode.ctlParam.pause;
    if (!HdfSbufWriteInt32(sBuf, g_elemCaptureValue.value[0])) {
        LOG_FUN_ERR("CaptureSetPauseBuf pause Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, g_elemCaptureValue.id.iface)) {
        LOG_FUN_ERR("CaptureSetPauseBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemCaptureValue.id.cardServiceName)) {
        LOG_FUN_ERR("CaptureSetPauseBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemCaptureValue.id.itemName)) {
        LOG_FUN_ERR("CaptureSetPauseBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureSetPauseStu(struct DevHandleCapture *handle, int cmdId, struct AudioHwCaptureParam *handleData)
{
    int32_t ret;
    LOG_FUN_INFO();
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("CaptureSetPauseStu paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioCapturebtainHdfSBuf();
    if (sBuf == NULL) {
        LOG_FUN_ERR("CaptureSetPauseStu Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    ret = AudioCtlCaptureSetPauseBuf(sBuf, handleData);
    if (ret < 0) {
        LOG_FUN_ERR("Failed to Set Pause sBuf!");
        AudioCaptureBufReplyRecycle(sBuf, NULL);
        return ret;
    }
    if (handleData->captureMode.ctlParam.pause) {
        cmdId = AUDIO_DRV_PCM_IOCTRL_PAUSE_CAPTURE;
    } else {
        cmdId = AUDIO_DRV_PCM_IOCTRL_RESUME_CAPTURE;
    }
    service = (struct HdfIoService *)handle->object;
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        LOG_FUN_ERR("SetPauseStu Service is NULL!");
        AudioCaptureBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    ret = service->dispatcher->Dispatch(&service->object, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        LOG_FUN_ERR("SetPauseStu Failed to send service call!");
        AudioCaptureBufReplyRecycle(sBuf, NULL);
        return ret;
    }
    AudioCaptureBufReplyRecycle(sBuf, NULL);
    return ret;
}

int32_t AudioCtlCaptureGetVolumeSBuf(struct HdfSBuf *sBuf, struct AudioHwCaptureParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        LOG_FUN_ERR("CaptureGetVolumeSBuf  parameter is empty!");
        return HDF_FAILURE;
    }
    memset_s(&g_elemCaptureValue, sizeof(struct AudioCtlCaptureElemValue), 0, sizeof(struct AudioCtlCaptureElemValue));
    uint32_t card = handleData->captureMode.hwInfo.card;
    if (card < 0 || card >= AUDIO_SERVICE_MAX) {
        LOG_FUN_ERR("card is Error!");
        return HDF_FAILURE;
    }
    g_elemCaptureValue.id.cardServiceName = g_audioServiceCapture[card];
    g_elemCaptureValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_ADC;
    g_elemCaptureValue.id.itemName = "Master Capture Volume";
    if (!HdfSbufWriteInt32(sBuf, g_elemCaptureValue.id.iface)) {
        LOG_FUN_ERR("CaptureGetVolumeSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemCaptureValue.id.cardServiceName)) {
        LOG_FUN_ERR("CaptureGetVolumeSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemCaptureValue.id.itemName)) {
        LOG_FUN_ERR("CaptureGetVolumeSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureGetVolume(struct DevHandleCapture *handle, int cmdId, struct AudioHwCaptureParam *handleData)
{
    int32_t ret;
    LOG_FUN_INFO();
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("CaptureGetVolume paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioCapturebtainHdfSBuf();
    if (sBuf == NULL) {
        LOG_FUN_ERR("CaptureGetVolume Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    reply = AudioCapturebtainHdfSBuf();
    if (reply == NULL) {
        LOG_FUN_ERR("Failed to obtain reply");
        AudioCaptureBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    ret = AudioCtlCaptureGetVolumeSBuf(sBuf, handleData);
    if (ret < 0) {
        LOG_FUN_ERR("Failed to Get Volume sBuf!");
        AudioCaptureBufReplyRecycle(sBuf, reply);
        return ret;
    }
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE - CTRL_NUM; // ADM Ctrl Num Begin zero
    service = (struct HdfIoService *)handle->object;
    ret = AudioServiceCaptureDispatch(service, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        LOG_FUN_ERR("GetVolume Dispatch Fail!");
        AudioCaptureBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    struct AudioCtlCaptureElemValue elemValue;
    memset_s(&elemValue, sizeof(struct AudioCtlCaptureElemValue), 0, sizeof(struct AudioCtlCaptureElemValue));
    if (!HdfSbufReadInt32(reply, &elemValue.value[0])) {
        LOG_FUN_ERR("Failed to Get Volume sBuf!");
        AudioCaptureBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    handleData->captureMode.ctlParam.volume = elemValue.value[0];
    AudioCaptureBufReplyRecycle(sBuf, reply);
    return ret;
}

int32_t AudioCtlCaptureSetVolumeSBuf(struct HdfSBuf *sBuf, struct AudioHwCaptureParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        LOG_FUN_ERR("CaptureSetVolumeSBuf parameter is empty!");
        return HDF_FAILURE;
    }
    memset_s(&g_elemCaptureValue, sizeof(struct AudioCtlCaptureElemValue), 0, sizeof(struct AudioCtlCaptureElemValue));
    uint32_t card = handleData->captureMode.hwInfo.card;
    if (card < 0 || card >= AUDIO_SERVICE_MAX) {
        LOG_FUN_ERR("CaptureSetVolumeSBuf card is Error!");
        return HDF_FAILURE;
    }
    g_elemCaptureValue.id.cardServiceName = g_audioServiceCapture[card];
    g_elemCaptureValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_ADC;
    g_elemCaptureValue.id.itemName = "Master Capture Volume";
    g_elemCaptureValue.value[0] = (int32_t)handleData->captureMode.ctlParam.volume;
    if (!HdfSbufWriteInt32(sBuf, g_elemCaptureValue.value[0])) {
        LOG_FUN_ERR("CaptureSetVolumeSBuf value[0] Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, g_elemCaptureValue.id.iface)) {
        LOG_FUN_ERR("CaptureSetVolumeSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemCaptureValue.id.cardServiceName)) {
        LOG_FUN_ERR("CaptureSetVolumeSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemCaptureValue.id.itemName)) {
        LOG_FUN_ERR("CaptureSetVolumeSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureSetVolume(struct DevHandleCapture *handle, int cmdId, struct AudioHwCaptureParam *handleData)
{
    int32_t ret;
    LOG_FUN_INFO();
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("CaptureSetVolume paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioCapturebtainHdfSBuf();
    if (sBuf == NULL) {
        LOG_FUN_ERR("CaptureSetVolume Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    ret = AudioCtlCaptureSetVolumeSBuf(sBuf, handleData);
    if (ret < 0) {
        LOG_FUN_ERR("CaptureSetVolume Failed to Set Volume sBuf!");
        AudioCaptureBufReplyRecycle(sBuf, NULL);
        return ret;
    }
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE;
    cmdId -= CTRL_NUM;   // ADM Ctrl Num Begin zero
    service = (struct HdfIoService *)handle->object;
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        LOG_FUN_ERR("CaptureSetVolume Service is NULL!");
        AudioCaptureBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    ret = service->dispatcher->Dispatch(&service->object, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        LOG_FUN_ERR("CaptureSetVolume Failed to send service call!");
        AudioCaptureBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    AudioCaptureBufReplyRecycle(sBuf, NULL);
    return ret;
}

int32_t AudioCtlCaptureSetMuteSBuf(struct HdfSBuf *sBuf, struct AudioHwCaptureParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        LOG_FUN_ERR("handleData or sBuf is NULL!");
        return HDF_FAILURE;
    }
    memset_s(&g_elemCaptureValue, sizeof(struct AudioCtlCaptureElemValue), 0, sizeof(struct AudioCtlCaptureElemValue));
    uint32_t card = handleData->captureMode.hwInfo.card;
    if (card < 0 || card >= AUDIO_SERVICE_MAX) {
        LOG_FUN_ERR("CaptureSetMuteSBuf card is Error!");
        return HDF_FAILURE;
    }
    g_elemCaptureValue.id.cardServiceName = g_audioServiceCapture[card];
    g_elemCaptureValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_ADC;
    g_elemCaptureValue.id.itemName = "Capture Mute";
    g_elemCaptureValue.value[0] = (int32_t)handleData->captureMode.ctlParam.mute;
    if (!HdfSbufWriteInt32(sBuf, g_elemCaptureValue.value[0])) {
        LOG_FUN_ERR("CaptureSetMuteSBuf mute Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, g_elemCaptureValue.id.iface)) {
        LOG_FUN_ERR("CaptureSetMuteSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemCaptureValue.id.cardServiceName)) {
        LOG_FUN_ERR("CaptureSetMuteSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemCaptureValue.id.itemName)) {
        LOG_FUN_ERR("CaptureSetMuteSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureSetMuteStu(struct DevHandleCapture *handle, int cmdId, struct AudioHwCaptureParam *handleData)
{
    int32_t ret;
    LOG_FUN_INFO();
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("CaptureSetMuteStu paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioCapturebtainHdfSBuf();
    if (sBuf == NULL) {
        LOG_FUN_ERR("CaptureSetMuteStu Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    ret = AudioCtlCaptureSetMuteSBuf(sBuf, handleData);
    if (ret < 0) {
        LOG_FUN_ERR("CaptureSetMuteStu Failed to Get Mute sBuf!");
        AudioCaptureBufReplyRecycle(sBuf, NULL);
        return ret;
    }
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE;
    cmdId -= CTRL_NUM;   // ADM Ctrl Num Begin zero
    service = (struct HdfIoService *)handle->object;
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        LOG_FUN_ERR("CaptureSetMuteStu Service is NULL!");
        AudioCaptureBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    ret = service->dispatcher->Dispatch(&service->object, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        LOG_FUN_ERR("CaptureSetMuteStu Failed to send service call!");
        AudioCaptureBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    AudioCaptureBufReplyRecycle(sBuf, NULL);
    return ret;
}

int32_t AudioCtlCaptureGetMuteSBuf(struct HdfSBuf *sBuf, struct AudioHwCaptureParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        LOG_FUN_ERR("The parameter is empty!");
        return HDF_FAILURE;
    }
    memset_s(&g_elemCaptureValue, sizeof(struct AudioCtlCaptureElemValue), 0, sizeof(struct AudioCtlCaptureElemValue));
    uint32_t card = handleData->captureMode.hwInfo.card;
    if (card < 0 || card >= AUDIO_SERVICE_MAX) {
        LOG_FUN_ERR("CaptureGetMuteSBuf card is Error!");
        return HDF_FAILURE;
    }
    g_elemCaptureValue.id.cardServiceName = g_audioServiceCapture[card];
    g_elemCaptureValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_ADC;
    g_elemCaptureValue.id.itemName = "Capture Mute";
    if (!HdfSbufWriteInt32(sBuf, g_elemCaptureValue.id.iface)) {
        LOG_FUN_ERR("CaptureGetMuteSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemCaptureValue.id.cardServiceName)) {
        LOG_FUN_ERR("CaptureGetMuteSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemCaptureValue.id.itemName)) {
        LOG_FUN_ERR("CaptureGetMuteSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureGetMuteStu(struct DevHandleCapture *handle, int cmdId, struct AudioHwCaptureParam *handleData)
{
    int32_t ret;
    LOG_FUN_INFO();
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("CaptureGetMuteStu paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioCapturebtainHdfSBuf();
    if (sBuf == NULL) {
        LOG_FUN_ERR("CaptureGetMuteStu Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    reply = AudioCapturebtainHdfSBuf();
    if (reply == NULL) {
        LOG_FUN_ERR("Failed to obtain reply");
        AudioCaptureBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    ret = AudioCtlCaptureGetMuteSBuf(sBuf, handleData);
    if (ret < 0) {
        LOG_FUN_ERR("Failed to Get Mute sBuf!");
        AudioCaptureBufReplyRecycle(sBuf, reply);
        return ret;
    }
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE - CTRL_NUM; // ADM Ctrl Num Begin zero
    service = (struct HdfIoService *)handle->object;
    ret = AudioServiceCaptureDispatch(service, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        LOG_FUN_ERR("CaptureGetMuteStu Dispatch Fail!");
        AudioCaptureBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    struct AudioCtlCaptureElemValue muteValueStu;
    memset_s(&muteValueStu, sizeof(struct AudioCtlCaptureElemValue), 0, sizeof(struct AudioCtlCaptureElemValue));
    if (!HdfSbufReadInt32(reply, &muteValueStu.value[0])) {
        LOG_FUN_ERR("CaptureGetMuteStu Failed to Get Volume sBuf!");
        AudioCaptureBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    handleData->captureMode.ctlParam.mute = muteValueStu.value[0];
    AudioCaptureBufReplyRecycle(sBuf, reply);
    return ret;
}

int32_t AudioCtlCaptureSetGainSBuf(struct HdfSBuf *sBuf, struct AudioHwCaptureParam *handleData)
{
    LOG_FUN_INFO();
    if (handleData == NULL || sBuf == NULL) {
        LOG_FUN_ERR("CaptureSetGainSBuf( handleData or sBuf is NULL!");
        return HDF_FAILURE;
    }
    memset_s(&g_elemCaptureValue, sizeof(struct AudioCtlCaptureElemValue), 0, sizeof(struct AudioCtlCaptureElemValue));
    uint32_t card = handleData->captureMode.hwInfo.card;
    if (card < 0 || card >= AUDIO_SERVICE_MAX) {
        LOG_FUN_ERR("CaptureSetGainSBuf card is Error!");
        return HDF_FAILURE;
    }
    g_elemCaptureValue.id.cardServiceName = g_audioServiceCapture[card];
    g_elemCaptureValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_GAIN;
    g_elemCaptureValue.id.itemName = "Mic Left Gain";
    g_elemCaptureValue.value[0] = handleData->captureMode.ctlParam.audioGain.gain;
    if (!HdfSbufWriteInt32(sBuf, g_elemCaptureValue.value[0])) {
        LOG_FUN_ERR("CaptureSetGainSBuf mute Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, g_elemCaptureValue.id.iface)) {
        LOG_FUN_ERR("CaptureSetGainSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemCaptureValue.id.cardServiceName)) {
        LOG_FUN_ERR("CaptureSetGainSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemCaptureValue.id.itemName)) {
        LOG_FUN_ERR("CaptureSetGainSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureSetGainStu(struct DevHandleCapture *handle, int cmdId, struct AudioHwCaptureParam *handleData)
{
    LOG_FUN_INFO();
    int32_t ret;
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioCapturebtainHdfSBuf();
    if (sBuf == NULL) {
        LOG_FUN_ERR("CaptureSetGainStu Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    ret = AudioCtlCaptureSetGainSBuf(sBuf, handleData);
    if (ret < 0) {
        LOG_FUN_ERR("Failed to Get Gain sBuf!");
        AudioCaptureBufReplyRecycle(sBuf, NULL);
        return ret;
    }
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE;
    cmdId -= CTRL_NUM;   // ADM Ctrl Num Begin zero
    service = (struct HdfIoService *)handle->object;
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        LOG_FUN_ERR("CaptureSetGainStu Service is NULL!");
        AudioCaptureBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    ret = service->dispatcher->Dispatch(&service->object, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        LOG_FUN_ERR("CaptureSetGainStu Failed to send service call!");
        AudioCaptureBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    AudioCaptureBufReplyRecycle(sBuf, NULL);
    return ret;
}

int32_t AudioCtlCaptureGetGainSBuf(struct HdfSBuf *sBuf, struct AudioHwCaptureParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        LOG_FUN_ERR("CaptureGetGainSBuf paras is NULL!");
        return HDF_FAILURE;
    }
    memset_s(&g_elemCaptureValue, sizeof(struct AudioCtlCaptureElemValue), 0, sizeof(struct AudioCtlCaptureElemValue));
    uint32_t card = handleData->captureMode.hwInfo.card;
    if (card < 0 || card >= AUDIO_SERVICE_MAX) {
        LOG_FUN_ERR("CaptureGetGainSBuf card is Error!");
        return HDF_FAILURE;
    }
    g_elemCaptureValue.id.cardServiceName = g_audioServiceCapture[card];
    g_elemCaptureValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_GAIN;
    g_elemCaptureValue.id.itemName = "Mic Left Gain";
    if (!HdfSbufWriteInt32(sBuf, g_elemCaptureValue.id.iface)) {
        LOG_FUN_ERR("CaptureGetGainSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemCaptureValue.id.cardServiceName)) {
        LOG_FUN_ERR("CaptureGetGainSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemCaptureValue.id.itemName)) {
        LOG_FUN_ERR("CaptureGetGainSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureGetGainStu(struct DevHandleCapture *handle, int cmdId, struct AudioHwCaptureParam *handleData)
{
    LOG_FUN_INFO();
    int32_t ret;
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("CaptureGetGainStu paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioCapturebtainHdfSBuf();
    if (sBuf == NULL) {
        LOG_FUN_ERR("CaptureGetGainStu Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    reply = AudioCapturebtainHdfSBuf();
    if (reply == NULL) {
        LOG_FUN_ERR("Failed to obtain reply");
        AudioCaptureBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    ret = AudioCtlCaptureGetGainSBuf(sBuf, handleData);
    if (ret < 0) {
        LOG_FUN_ERR("Failed to Get Gain sBuf!");
        AudioCaptureBufReplyRecycle(sBuf, reply);
        return ret;
    }
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE - CTRL_NUM; // ADM Ctrl Num Begin zero
    service = (struct HdfIoService *)handle->object;
    ret = AudioServiceCaptureDispatch(service, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        LOG_FUN_ERR("GetGainStu Dispatch Fail!");
        AudioCaptureBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    struct AudioCtlCaptureElemValue muteValueStu;
    memset_s(&muteValueStu, sizeof(struct AudioCtlCaptureElemValue), 0, sizeof(struct AudioCtlCaptureElemValue));
    if (!HdfSbufReadInt32(reply, &muteValueStu.value[0])) {
        LOG_FUN_ERR("Failed to GetGain sBuf!");
        AudioCaptureBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    handleData->captureMode.ctlParam.audioGain.gain = muteValueStu.value[0];
    AudioCaptureBufReplyRecycle(sBuf, reply);
    return ret;
}

int32_t AudioCtlCaptureSceneSelectSBuf(struct HdfSBuf *sBuf,
                                       struct AudioHwCaptureParam *handleData,
                                       int32_t deviceIndex)
{
    if (handleData == NULL || sBuf == NULL) {
        LOG_FUN_ERR("CaptureSceneSelectSBuf handleData or sBufs is NULL!");
        return HDF_FAILURE;
    }
    if (deviceIndex < 0 || deviceIndex > PATHPLAN_COUNT - 1) {
        LOG_FUN_ERR("deviceIndex is Invalid!");
        return HDF_FAILURE;
    }
    memset_s(&g_elemCaptureValue, sizeof(struct AudioCtlCaptureElemValue), 0, sizeof(struct AudioCtlCaptureElemValue));
    uint32_t card = handleData->captureMode.hwInfo.card;
    if (card < 0 || card >= AUDIO_SERVICE_MAX) {
        LOG_FUN_ERR("CaptureSceneSelectSBuf card is Error!");
        return HDF_FAILURE;
    }
    g_elemCaptureValue.id.cardServiceName = g_audioServiceCapture[card];
    g_elemCaptureValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_SELECT;
    g_elemCaptureValue.id.itemName =
        handleData->captureMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[deviceIndex].deviceSwitch;
    g_elemCaptureValue.value[0] = handleData->captureMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[deviceIndex].value;
    if (!HdfSbufWriteInt32(sBuf, g_elemCaptureValue.value[0])) {
        LOG_FUN_ERR("CaptureSceneSelectSBuf Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, g_elemCaptureValue.id.iface)) {
        LOG_FUN_ERR("CaptureSceneSelectSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemCaptureValue.id.cardServiceName)) {
        LOG_FUN_ERR("CaptureSceneSelectSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemCaptureValue.id.itemName)) {
        LOG_FUN_ERR("CaptureSceneSelectSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureSceneSelect(struct DevHandleCapture *handle, int cmdId, struct AudioHwCaptureParam *handleData)
{
    LOG_FUN_INFO();
    int32_t index;
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("CaptureSceneSelect parameter is empty!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioCapturebtainHdfSBuf();
    if (sBuf == NULL) {
        LOG_FUN_ERR("Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE - CTRL_NUM; // ADM Ctrl Num Begin zero;
    service = (struct HdfIoService *)handle->object;
    int32_t deviceNum = handleData->captureMode.hwInfo.pathSelect.deviceInfo.deviceNum;
    if (deviceNum < AUDIO_MIN_DEVICENUM) {
        LOG_FUN_ERR("AUDIO_MIN_ADAPTERNUM Failed!");
        AudioCaptureBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    for (index = 0; index < deviceNum; index++) {
        HdfSbufFlush(sBuf);
        if (AudioCtlCaptureSceneSelectSBuf(sBuf, handleData, index) < 0) {
            LOG_FUN_ERR("AudioCtlRenderSceneSelectSBuf Failed!");
            AudioCaptureBufReplyRecycle(sBuf, NULL);
            return HDF_FAILURE;
        }
        if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
            LOG_FUN_ERR("CaptureSceneSelect Service is NULL!");
            AudioCaptureBufReplyRecycle(sBuf, NULL);
            return HDF_FAILURE;
        }
        if (service->dispatcher->Dispatch(&service->object, cmdId, sBuf, reply) < 0) {
            LOG_FUN_ERR("CaptureSceneSelect Failed to send service call!");
            AudioCaptureBufReplyRecycle(sBuf, NULL);
            return HDF_FAILURE;
        }
    }
    AudioCaptureBufReplyRecycle(sBuf, NULL);
    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureGetGainThresholdSBuf(struct HdfSBuf *sBuf, struct AudioHwCaptureParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        LOG_FUN_ERR("paras is empty!");
        return HDF_FAILURE;
    }
    memset_s(&g_elemCaptureInfo, sizeof(struct AudioCtrlCaptureElemInfo), 0, sizeof(struct AudioCtrlCaptureElemInfo));
    uint32_t card = handleData->captureMode.hwInfo.card;
    if (card < 0 || card >= AUDIO_SERVICE_MAX) {
        LOG_FUN_ERR("CaptureGetGainThresholdSBuf card is Error!");
        return HDF_FAILURE;
    }
    g_elemCaptureInfo.id.cardServiceName = g_audioServiceCapture[card];
    g_elemCaptureInfo.id.iface = AUDIODRV_CTL_CAPTUREELEM_IFACE_MIXER;
    g_elemCaptureInfo.id.itemName = "Mic Left Gain";
    if (!HdfSbufWriteInt32(sBuf, g_elemCaptureInfo.id.iface)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemCaptureInfo.id.cardServiceName)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemCaptureInfo.id.itemName)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureGetGainThreshold(struct DevHandleCapture *handle,
                                        int cmdId,
                                        struct AudioHwCaptureParam *handleData)
{
    LOG_FUN_INFO();
    int32_t ret;
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioCapturebtainHdfSBuf();
    if (sBuf == NULL) {
        LOG_FUN_ERR("Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    reply = AudioCapturebtainHdfSBuf();
    if (reply == NULL) {
        LOG_FUN_ERR("Failed to obtain reply");
        AudioCaptureBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    ret = AudioCtlCaptureGetGainThresholdSBuf(sBuf, handleData);
    if (ret < 0) {
        LOG_FUN_ERR("Failed to Get Threshold sBuf!");
        AudioCaptureBufReplyRecycle(sBuf, reply);
        return ret;
    }
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_INFO_CAPTURE - CTRL_NUM; // ADM Ctrl Num Begin zero
    service = (struct HdfIoService *)handle->object;
    ret = AudioServiceCaptureDispatch(service, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        AudioCaptureBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    struct AudioCtrlCaptureElemInfo gainThreshold;
    memset_s(&gainThreshold, sizeof(struct AudioCtrlCaptureElemInfo), 0, sizeof(struct AudioCtrlCaptureElemInfo));
    if (!HdfSbufReadInt32(reply, &gainThreshold.type)) {
        LOG_FUN_ERR("Failed to HdfSbufReadBuffer!");
        AudioCaptureBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadInt32(reply, &gainThreshold.max)) {
        LOG_FUN_ERR("Failed to HdfSbufReadBuffer!");
        AudioCaptureBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    handleData->captureMode.ctlParam.audioGain.gainMax = gainThreshold.max;
    handleData->captureMode.ctlParam.audioGain.gainMin = 0;
    AudioCaptureBufReplyRecycle(sBuf, reply);
    return ret;
}

int32_t AudioCtlCaptureGetVolThresholdSBuf(struct HdfSBuf *sBuf, struct AudioHwCaptureParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        LOG_FUN_ERR("paras is empty!");
        return HDF_FAILURE;
    }
    memset_s(&g_elemCaptureInfo, sizeof(struct AudioCtrlCaptureElemInfo), 0, sizeof(struct AudioCtrlCaptureElemInfo));
    uint32_t card = handleData->captureMode.hwInfo.card;
    if (card < 0 || card >= AUDIO_SERVICE_MAX) {
        LOG_FUN_ERR("CaptureGetGainThresholdSBuf card is Error!");
        return HDF_FAILURE;
    }
    g_elemCaptureInfo.id.cardServiceName = g_audioServiceCapture[card];
    g_elemCaptureInfo.id.iface = AUDIODRV_CTL_ELEM_IFACE_ADC;
    g_elemCaptureInfo.id.itemName = "Master Capture Volume";
    if (!HdfSbufWriteInt32(sBuf, g_elemCaptureInfo.id.iface)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemCaptureInfo.id.cardServiceName)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemCaptureInfo.id.itemName)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureGetVolThreshold(struct DevHandleCapture *handle,
    int cmdId, struct AudioHwCaptureParam *handleData)
{
    LOG_FUN_INFO();
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfSBuf *sBuf = AudioCapturebtainHdfSBuf();
    if (sBuf == NULL) {
        LOG_FUN_ERR("Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    struct HdfSBuf *reply = AudioCapturebtainHdfSBuf();
    if (reply == NULL) {
        LOG_FUN_ERR("Failed to obtain reply");
        AudioCaptureBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    int32_t ret = AudioCtlCaptureGetVolThresholdSBuf(sBuf, handleData);
    if (ret < 0) {
        LOG_FUN_ERR("Failed to Get Threshold sBuf!");
        AudioCaptureBufReplyRecycle(sBuf, reply);
        return ret;
    }
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_INFO_CAPTURE - CTRL_NUM; // ADM Ctrl Num Begin zero
    struct HdfIoService *service = (struct HdfIoService *)handle->object;
    ret = AudioServiceCaptureDispatch(service, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        AudioCaptureBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    struct AudioCtrlCaptureElemInfo volThreshold;
    memset_s(&volThreshold, sizeof(struct AudioCtrlCaptureElemInfo), 0, sizeof(struct AudioCtrlCaptureElemInfo));
    if (!HdfSbufReadInt32(reply, &volThreshold.type)) {
        AudioCaptureBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadInt32(reply, &volThreshold.max)) {
        AudioCaptureBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadInt32(reply, &volThreshold.min)) {
        AudioCaptureBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    handleData->captureMode.ctlParam.volThreshold.volMax = volThreshold.max;
    handleData->captureMode.ctlParam.volThreshold.volMin = volThreshold.min;
    AudioCaptureBufReplyRecycle(sBuf, reply);
    return ret;
}

int32_t AudioInterfaceLibCtlCapture(struct DevHandleCapture *handle, int cmdId, struct AudioHwCaptureParam *handleData)
{
    int32_t ret;
    LOG_FUN_INFO();
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("paras is NULL!");
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
            LOG_FUN_ERR("Ctl Mode not support!");
            ret = HDF_FAILURE;
            break;
    }
    return ret;
}

int32_t AudioOutputCaptureHwParams(struct DevHandleCapture *handle, int cmdId, struct AudioHwCaptureParam *handleData)
{
    LOG_FUN_INFO();
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *sBuf = AudioCapturebtainHdfSBuf();
    if (sBuf == NULL) {
        LOG_FUN_ERR("Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    if (SetHwParamsCapture(handleData) < 0) {
        AudioCaptureBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    if (ParamsSbufWriteBufferCapture(sBuf) < 0) {
        AudioCaptureBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    service = (struct HdfIoService *)handle->object;
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        LOG_FUN_ERR("Service is NULL!");
        AudioCaptureBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    int32_t ret = service->dispatcher->Dispatch(&service->object, cmdId, sBuf, NULL);
    if (ret != HDF_SUCCESS) {
        LOG_FUN_ERR("Failed to send service call!");
        AudioCaptureBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    AudioCaptureBufReplyRecycle(sBuf, NULL);
    return ret;
}

int32_t AudioOutputCaptureReadFrame(struct HdfIoService *service, int cmdId, struct HdfSBuf *reply)
{
    LOG_FUN_INFO();
    int32_t ret;
    uint32_t buffStatus = 0;
    int32_t tryNumReply = 50; // try get reply count
    if (service == NULL || reply == NULL) {
        LOG_FUN_ERR("paras is NULL!");
        return HDF_FAILURE;
    }
    do {
        ret = service->dispatcher->Dispatch(&service->object, cmdId, NULL, reply);
        if (ret != HDF_SUCCESS) {
            LOG_FUN_ERR("Failed to send service call!");
            HdfSBufRecycle(reply);
            return ret;
        }
        if (!HdfSbufReadUint32(reply, &buffStatus)) {
            LOG_FUN_ERR("Failed to Get buffStatus!");
            HdfSBufRecycle(reply);
            return HDF_FAILURE;
        }
        if (buffStatus == CIR_BUFF_EMPTY) {
            LOG_PARA_INFO("Cir buff empty wait 50ms");
            tryNumReply--;
            HdfSbufFlush(reply);
            usleep(AUDIO_WAIT_MSEC);  // wait 10ms
            continue;
        }
        break;
    } while (tryNumReply > 0);
    if (tryNumReply <= 0) {
        HdfSBufRecycle(reply);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioOutputCaptureRead(struct DevHandleCapture *handle, int cmdId, struct AudioHwCaptureParam *handleData)
{
    LOG_FUN_INFO();
    uint32_t dataSize = 0;
    uint32_t frameCount = 0;
    size_t replySize = AUDIO_SIZE_FRAME_16K + AUDIO_REPLY_EXTEND;
    char *frame = NULL;
    struct HdfIoService *service = NULL;
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfSBuf *reply = HdfSBufTypedObtainCapacity(SBUF_RAW, replySize);
    if (reply == NULL) {
        return HDF_FAILURE;
    }
    service = (struct HdfIoService *)handle->object;
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        LOG_FUN_ERR("Service is NULL!");
        AudioCaptureBufReplyRecycle(NULL, reply);
        return HDF_FAILURE;
    }
    int32_t ret = AudioOutputCaptureReadFrame(service, cmdId, reply);
    if (ret != 0) {
        LOG_FUN_ERR("AudioOutputCaptureReadFrame is Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadBuffer(reply, (const void **)&frame, &dataSize)) {
        HdfSBufRecycle(reply);
        return HDF_FAILURE;
    }
    if (dataSize > FRAME_DATA || handleData->frameCaptureMode.buffer == NULL) {
        LOG_FUN_ERR("Buffer is NULL or DataSize overflow!");
        HdfSBufRecycle(reply);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(reply, &frameCount)) {
        LOG_FUN_ERR("Failed to Get buffStatus!");
        HdfSBufRecycle(reply);
        return HDF_FAILURE;
    }
    memcpy_s(handleData->frameCaptureMode.buffer, FRAME_DATA, frame, dataSize);
    handleData->frameCaptureMode.bufferSize = dataSize;
    handleData->frameCaptureMode.bufferFrameSize = frameCount;
    HdfSBufRecycle(reply);
    return HDF_SUCCESS;
}

int32_t AudioOutputCaptureStartPrepare(struct DevHandleCapture *handle,
    int cmdId, struct AudioHwCaptureParam *handleData)
{
    LOG_FUN_INFO();
    int32_t ret;
    struct HdfIoService *service = NULL;
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("paras is NULL!");
        return HDF_FAILURE;
    }
    service = (struct HdfIoService *)handle->object;
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        LOG_FUN_ERR("Service is NULL!");
        return HDF_FAILURE;
    }
    ret = service->dispatcher->Dispatch(&service->object, cmdId, NULL, NULL);
    if (ret != HDF_SUCCESS) {
        LOG_FUN_ERR("Failed to send service call!");
        return ret;
    }
    return HDF_SUCCESS;
}

int32_t AudioOutputCaptureStop(struct DevHandleCapture *handle, int cmdId, struct AudioHwCaptureParam *handleData)
{
    LOG_FUN_INFO();
    int32_t ret;
    struct HdfIoService *service = NULL;
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("paras is NULL!");
        return HDF_FAILURE;
    }
    service = (struct HdfIoService *)handle->object;
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        LOG_FUN_ERR("Service is NULL!");
        return HDF_FAILURE;
    }
    ret = service->dispatcher->Dispatch(&service->object, cmdId, NULL, NULL);
    if (ret != HDF_SUCCESS) {
        LOG_FUN_ERR("Failed to send service call!");
        return ret;
    }
    return HDF_SUCCESS;
}

int32_t AudioInterfaceLibOutputCapture(struct DevHandleCapture *handle, int cmdId,
                                       struct AudioHwCaptureParam *handleData)
{
    LOG_FUN_INFO();
    if (handle == NULL) {
        LOG_FUN_ERR("Input handle is NULL!");
        return HDF_FAILURE;
    }
    if (handle->object == NULL || handleData == NULL) {
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
            ret = AudioOutputCaptureStartPrepare(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTRL_STOP_CAPTURE:
            ret = AudioOutputCaptureStop(handle, cmdId, handleData);
            break;
        case AUDIODRV_CTL_IOCTL_PAUSE_WRITE_CAPTURE:
            ret = AudioCtlCaptureSetPauseStu(handle, cmdId, handleData);
            break;
        default:
            LOG_FUN_ERR("Output Mode not support!");
            ret = HDF_FAILURE;
            break;
    }
    return ret;
}

struct HdfIoService *HdfIoServiceBindName(const char *serviceName)
{
    if (serviceName == NULL) {
        LOG_FUN_ERR("service name NULL!");
        return NULL;
    }
    if (strcmp(serviceName, "hdf_audio_control") == 0) {
        return (HdfIoServiceBind("hdf_audio_control"));
    }
    if (strcmp(serviceName, "hdf_audio_capture") == 0) {
        return (HdfIoServiceBind("hdf_audio_capture"));
    }
    LOG_FUN_ERR("service name not support!");
    return NULL;
}

struct DevHandleCapture *AudioBindServiceCaptureObject(struct DevHandleCapture * const handle,
    const char *name)
{
    LOG_FUN_INFO();
    if (handle == NULL || name == NULL) {
        LOG_FUN_ERR("service name or handle is NULL!");
        return NULL;
    }
    char *serviceName = (char *)calloc(1, NAME_LEN);
    if (serviceName == NULL) {
        LOG_FUN_ERR("Failed to OsalMemCalloc serviceName");
        AudioMemFree((void **)&handle);
        return NULL;
    }
    int ret = snprintf_s(serviceName, NAME_LEN - 1, SERVIC_NAME_MAX_LEN + 1, "hdf_audio_%s", name);
    if (ret < 0) {
        LOG_FUN_ERR("Failed to snprintf_s");
        AudioMemFree((void **)&serviceName);
        AudioMemFree((void **)&handle);
        return NULL;
    }
    struct HdfIoService *service = HdfIoServiceBindName(serviceName);
    if (service == NULL) {
        LOG_FUN_ERR("Failed to get service!");
        AudioMemFree((void **)&serviceName);
        AudioMemFree((void **)&handle);
        return NULL;
    }
    LOG_PARA_INFO("serviceName = %s", serviceName);
    AudioMemFree((void **)&serviceName);
    handle->object = service;
    return handle->object;
}

/* CreatCapture for Bind handle */
struct DevHandleCapture *AudioBindServiceCapture(const char *name)
{
    LOG_FUN_INFO();
    struct DevHandleCapture *handle = NULL;
    if (name == NULL) {
        LOG_FUN_ERR("service name NULL!");
        return NULL;
    }
    handle = (struct DevHandleCapture *)calloc(1, sizeof(struct DevHandleCapture));
    if (handle == NULL) {
        LOG_FUN_ERR("Failed to OsalMemCalloc handle");
        return NULL;
    }
    handle->object = AudioBindServiceCaptureObject(handle, name);
    if (handle->object == NULL) {
        LOG_FUN_ERR("handle->object is NULL!");
        return NULL;
    }
    LOG_PARA_INFO("BIND SERVICE SUCCESS!");
    return handle;
}

void AudioCloseServiceCapture(struct DevHandleCapture *handle)
{
    LOG_FUN_INFO();
    if (handle == NULL || handle->object == NULL) {
        LOG_FUN_ERR("handle or handle->object is NULL");
        return;
    }
    struct HdfIoService *service = (struct HdfIoService *)handle->object;
    HdfIoServiceRecycle(service);
    AudioMemFree((void **)&handle);
    return;
}

int32_t AudioInterfaceLibModeCapture(struct DevHandleCapture * const handle,
    struct AudioHwCaptureParam * const handleData, int cmdId)
{
    LOG_FUN_INFO();
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("paras is NULL!");
        return HDF_FAILURE;
    }
    switch (cmdId) {
        case AUDIO_DRV_PCM_IOCTL_HW_PARAMS:
        case AUDIO_DRV_PCM_IOCTL_READ:
        case AUDIO_DRV_PCM_IOCTRL_START_CAPTURE:
        case AUDIO_DRV_PCM_IOCTRL_STOP_CAPTURE:
        case AUDIO_DRV_PCM_IOCTL_PREPARE_CAPTURE:
        case AUDIODRV_CTL_IOCTL_PAUSE_WRITE_CAPTURE:
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
            LOG_FUN_ERR("Mode Error!");
            break;
    }
    return HDF_ERR_NOT_SUPPORT;
}

