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

#include "audio_interface_lib_common.h"

#define AUDIODRV_CTL_ELEM_IFACE_DAC 0
#define AUDIODRV_CTL_ELEM_IFACE_MIX 3
#define AUDIO_SBUF_EXTEND 16

#define AUDIODRV_CTL_ELEM_IFACE_MIXER ((int32_t)2) /* virtual mixer device */
#define AUDIODRV_CTL_ELEM_IFACE_ACODEC ((int32_t)4) /* Acodec device */
#define AUDIODRV_CTL_ELEM_IFACE_AIAO ((int32_t)6)

#define AUDIODRV_CTL_ACODEC_ENABLE 1
#define AUDIODRV_CTL_ACODEC_DISABLE 0
#define AUDIODRV_CTL_EXTERN_CODEC_STR "External Codec Enable"
#define AUDIODRV_CTL_INTERNAL_CODEC_STR "Internally Codec Enable"

/* Out Put Render/Capture */
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

struct AudioCtlElemId {
    const char *cardServiceName;
    int32_t iface;
    const char *itemName; /* ASCII name of item */
};

static struct AudioCtlElemValue {
    struct AudioCtlElemId id;
    int32_t value[2];
} g_elemValue;

static struct AudioCtrlElemInfo {
    struct AudioCtlElemId id;
    uint32_t count;     /* count of values */
    int32_t type;       /* R: value type - AUDIODRV_CTL_ELEM_IFACE_MIXER_* */
    int32_t min;        /* R: minimum value */
    int32_t max;        /* R: maximum value */
} g_elemInfo;

char *g_audioService[AUDIO_SERVICE_MAX] = {
    [AUDIO_SERVICE_IN] = "hdf_audio_codec_dev0",
    [AUDIO_SERVICE_OUT] = "hdf_audio_smartpa_dev0",
};

struct HdfSBuf *AudioRenderObtainHdfSBuf()
{
    enum HdfSbufType bufType;
#ifdef AUDIO_HDF_SBUF_IPC
    bufType = SBUF_IPC;
#else
    bufType = SBUF_RAW;
#endif
    return HdfSBufTypedObtain(bufType);
}

void AudioRenderBufReplyRecycle(struct HdfSBuf *sBuf, struct HdfSBuf *reply)
{
    if (sBuf != NULL) {
        HdfSBufRecycle(sBuf);
    }
    if (reply != NULL) {
        HdfSBufRecycle(reply);
    }
    return;
}

int32_t AudioServiceRenderDispatch(struct HdfIoService *service,
                                   int cmdId,
                                   struct HdfSBuf *sBuf,
                                   struct HdfSBuf *reply)
{
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL ||
        sBuf == NULL) {
        LOG_FUN_ERR("Service is NULL!");
        return HDF_FAILURE;
    }
    int32_t ret = service->dispatcher->Dispatch(&(service->object), cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        LOG_FUN_ERR("Failed to send service call!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t SetHwParams(const struct AudioHwRenderParam *handleData)
{
    if (handleData == NULL) {
        LOG_FUN_ERR("handleData is NULL!");
        return HDF_FAILURE;
    }
    memset_s(&g_hwParams, sizeof(struct AudioPcmHwParams), 0, sizeof(struct AudioPcmHwParams));
    uint32_t card = handleData->renderMode.hwInfo.card;
    if (card < 0 || card >= AUDIO_SERVICE_MAX) {
        LOG_FUN_ERR("card is Error!");
        return HDF_FAILURE;
    }
    g_hwParams.streamType = AUDIO_RENDER_STREAM;
    g_hwParams.channels = handleData->frameRenderMode.attrs.channelCount;
    g_hwParams.rate = handleData->frameRenderMode.attrs.sampleRate;
    g_hwParams.periodSize = handleData->frameRenderMode.periodSize;
    g_hwParams.periodCount = handleData->frameRenderMode.periodCount;
    g_hwParams.cardServiceName = g_audioService[card];
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

int32_t AudioCtlRenderSetVolumeSBuf(struct HdfSBuf *sBuf, struct AudioHwRenderParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        LOG_FUN_ERR("RenderSetVolumeSBuf handleData or sBuf is NULL!");
        return HDF_FAILURE;
    }
    memset_s(&g_elemValue, sizeof(struct AudioCtlElemValue), 0, sizeof(struct AudioCtlElemValue));
    uint32_t card = handleData->renderMode.hwInfo.card;
    if (card < 0 || card >= AUDIO_SERVICE_MAX) {
        LOG_FUN_ERR("RenderSetVolumeSBuf card is Error!");
        return HDF_FAILURE;
    }
    g_elemValue.id.cardServiceName = g_audioService[card];
    g_elemValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_DAC;
    g_elemValue.id.itemName = "Master Playback Volume";
    g_elemValue.value[0] = (int32_t)handleData->renderMode.ctlParam.volume;
    if (!HdfSbufWriteInt32(sBuf, g_elemValue.value[0])) {
        LOG_FUN_ERR("RenderSetVolumeSBuf Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, g_elemValue.id.iface)) {
        LOG_FUN_ERR("RenderSetVolumeSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemValue.id.cardServiceName)) {
        LOG_FUN_ERR("RenderSetVolumeSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemValue.id.itemName)) {
        LOG_FUN_ERR("RenderSetVolumeSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderGetVolumeSBuf(struct HdfSBuf *sBuf, struct AudioHwRenderParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        LOG_FUN_ERR("RenderGetVolumeSBuf handleData or sBuf is NULL!");
        return HDF_FAILURE;
    }
    memset_s(&g_elemValue, sizeof(struct AudioCtlElemValue), 0, sizeof(struct AudioCtlElemValue));
    uint32_t card = handleData->renderMode.hwInfo.card;
    if (card < 0 || card >= AUDIO_SERVICE_MAX) {
        LOG_FUN_ERR("RenderGetVolumeSBuf card is Error!");
        return HDF_FAILURE;
    }
    g_elemValue.id.cardServiceName = g_audioService[card];
    g_elemValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_DAC;
    g_elemValue.id.itemName = "Master Playback Volume";
    if (!HdfSbufWriteInt32(sBuf, g_elemValue.id.iface)) {
        LOG_FUN_ERR("RenderGetVolumeSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemValue.id.cardServiceName)) {
        LOG_FUN_ERR("RenderGetVolumeSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemValue.id.itemName)) {
        LOG_FUN_ERR("RenderGetVolumeSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSetVolume(struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    LOG_FUN_INFO();
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("RenderSetVolume parameter is empty!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioRenderObtainHdfSBuf();
    if (sBuf == NULL) {
        LOG_FUN_ERR("Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    ret = AudioCtlRenderSetVolumeSBuf(sBuf, handleData);
    if (ret < 0) {
        LOG_FUN_ERR("Failed to Set Volume sBuf!");
        AudioRenderBufReplyRecycle(sBuf, NULL);
        return ret;
    }
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_WRITE - CTRL_NUM; // ADM Ctrl Num Begin zero;
    service = (struct HdfIoService *)handle->object;
    ret = AudioServiceRenderDispatch(service, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        AudioRenderBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    AudioRenderBufReplyRecycle(sBuf, NULL);
    return ret;
}

int32_t AudioCtlRenderGetVolume(struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    LOG_FUN_INFO();
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("RenderGetVolume parameter is empty!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioRenderObtainHdfSBuf();
    if (sBuf == NULL) {
        LOG_FUN_ERR("RenderGetVolume Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    reply = AudioRenderObtainHdfSBuf();
    if (reply == NULL) {
        LOG_FUN_ERR("RenderGetVolume Failed to obtain reply");
        AudioRenderBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    ret = AudioCtlRenderGetVolumeSBuf(sBuf, handleData);
    if (ret < 0) {
        LOG_FUN_ERR("RenderGetVolume Failed to Get Volume sBuf!");
        AudioRenderBufReplyRecycle(sBuf, reply);
        return ret;
    }
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_READ - CTRL_NUM; // ADM Ctrl Num Begin zero
    service = (struct HdfIoService *)handle->object;
    ret = AudioServiceRenderDispatch(service, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        LOG_FUN_ERR("RenderGetVolume RenderDispatch Failed!");
        AudioRenderBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemValue;
    memset_s(&elemValue, sizeof(struct AudioCtlElemValue), 0, sizeof(struct AudioCtlElemValue));
    if (!HdfSbufReadInt32(reply, &elemValue.value[0])) {
        LOG_FUN_ERR("RenderGetVolume Failed to Get Volume sBuf!");
        AudioRenderBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    handleData->renderMode.ctlParam.volume = elemValue.value[0];
    AudioRenderBufReplyRecycle(sBuf, reply);
    return ret;
}

int32_t AudioCtlRenderSetPauseBuf(struct HdfSBuf *sBuf, struct AudioHwRenderParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        LOG_FUN_ERR("RenderSetPauseBuf handleData or sBuf is NULL!");
        return HDF_FAILURE;
    }
    memset_s(&g_elemValue, sizeof(struct AudioCtlElemValue), 0, sizeof(struct AudioCtlElemValue));
    uint32_t card = handleData->renderMode.hwInfo.card;
    if (card < 0 || card >= AUDIO_SERVICE_MAX) {
        LOG_FUN_ERR("RenderSetPauseBuf card is Error!");
        return HDF_FAILURE;
    }
    g_elemValue.id.cardServiceName = g_audioService[card];
    g_elemValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    g_elemValue.id.itemName = "Master Playback Pause";
    g_elemValue.value[0] = (int32_t)handleData->renderMode.ctlParam.pause;
    if (!HdfSbufWriteInt32(sBuf, g_elemValue.value[0])) {
        LOG_FUN_ERR("RenderSetPauseBuf pause Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, g_elemValue.id.iface)) {
        LOG_FUN_ERR("RenderSetPauseBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemValue.id.cardServiceName)) {
        LOG_FUN_ERR("RenderSetPauseBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemValue.id.itemName)) {
        LOG_FUN_ERR("RenderSetPauseBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSetPauseStu(struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    LOG_FUN_INFO();
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("RenderSetPauseStu parameter is empty!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioRenderObtainHdfSBuf();
    if (sBuf == NULL) {
        LOG_FUN_ERR("RenderSetPauseStu Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    ret = AudioCtlRenderSetPauseBuf(sBuf, handleData);
    if (ret < 0) {
        LOG_FUN_ERR("RenderSetPauseStu Failed to Set Pause sBuf!");
        AudioRenderBufReplyRecycle(sBuf, NULL);
        return ret;
    }
    if (handleData->renderMode.ctlParam.pause) {
        cmdId = AUDIO_DRV_PCM_IOCTRL_PAUSE;
    } else {
        cmdId = AUDIO_DRV_PCM_IOCTRL_RESUME;
    }
    service = (struct HdfIoService *)handle->object;
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        LOG_FUN_ERR("RenderSetPauseStu Service is NULL!");
        AudioRenderBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    ret = service->dispatcher->Dispatch(&service->object, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        LOG_FUN_ERR("RenderSetPauseStu Failed to send service call!");
        AudioRenderBufReplyRecycle(sBuf, NULL);
        return ret;
    }
    AudioRenderBufReplyRecycle(sBuf, NULL);
    return ret;
}

int32_t AudioCtlRenderSetMuteBuf(struct HdfSBuf *sBuf, struct AudioHwRenderParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        LOG_FUN_ERR("RenderSetMuteBuf handleData or sBuf is NULL!");
        return HDF_FAILURE;
    }
    memset_s(&g_elemValue, sizeof(struct AudioCtlElemValue), 0, sizeof(struct AudioCtlElemValue));
    uint32_t card = handleData->renderMode.hwInfo.card;
    if (card < 0 || card >= AUDIO_SERVICE_MAX) {
        LOG_FUN_ERR("RenderSetMuteBuf card is Error!");
        return HDF_FAILURE;
    }
    g_elemValue.id.cardServiceName = g_audioService[card];
    g_elemValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_DAC;
    g_elemValue.id.itemName = "Playback Mute";
    g_elemValue.value[0] = (int32_t)handleData->renderMode.ctlParam.mute;
    if (!HdfSbufWriteInt32(sBuf, g_elemValue.value[0])) {
        LOG_FUN_ERR("RenderSetMuteBuf value[0] Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, g_elemValue.id.iface)) {
        LOG_FUN_ERR("RenderSetMuteBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemValue.id.cardServiceName)) {
        LOG_FUN_ERR("RenderSetMuteBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemValue.id.itemName)) {
        LOG_FUN_ERR("RenderSetMuteBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSetMuteStu(struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    LOG_FUN_INFO();
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("RenderSetMuteStu paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioRenderObtainHdfSBuf();
    if (sBuf == NULL) {
        LOG_FUN_ERR("RenderSetMuteStu Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    ret = AudioCtlRenderSetMuteBuf(sBuf, handleData);
    if (ret < 0) {
        LOG_FUN_ERR("RenderSetMuteStu Failed to Set Mute sBuf!");
        AudioRenderBufReplyRecycle(sBuf, NULL);
        return ret;
    }
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_WRITE;
    cmdId -= CTRL_NUM;   // ADM Ctrl Num Begin zero
    service = (struct HdfIoService *)handle->object;
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        LOG_FUN_ERR("RenderSetMuteStu Service is NULL!");
        AudioRenderBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    ret = service->dispatcher->Dispatch(&service->object, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        LOG_FUN_ERR("RenderSetMuteStu Failed to send service call!");
        AudioRenderBufReplyRecycle(sBuf, NULL);
        return ret;
    }
    AudioRenderBufReplyRecycle(sBuf, NULL);
    return ret;
}

int32_t AudioCtlRenderGetMuteSBuf(struct HdfSBuf *sBuf, struct AudioHwRenderParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        LOG_FUN_ERR("RenderGetMuteSBuf handleData or sBuf is NULL!");
        return HDF_FAILURE;
    }
    memset_s(&g_elemValue, sizeof(struct AudioCtlElemValue), 0, sizeof(struct AudioCtlElemValue));
    uint32_t card = handleData->renderMode.hwInfo.card;
    if (card < 0 || card >= AUDIO_SERVICE_MAX) {
        LOG_FUN_ERR("RenderGetMuteSBuf card is Error!");
        return HDF_FAILURE;
    }
    g_elemValue.id.cardServiceName = g_audioService[card];
    g_elemValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_DAC;
    g_elemValue.id.itemName = "Playback Mute";
    if (!HdfSbufWriteInt32(sBuf, g_elemValue.id.iface)) {
        LOG_FUN_ERR("RenderGetMuteSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemValue.id.cardServiceName)) {
        LOG_FUN_ERR("RenderGetMuteSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemValue.id.itemName)) {
        LOG_FUN_ERR("RenderGetMuteSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderGetMuteStu(struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    LOG_FUN_INFO();
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("RenderGetMuteStu paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioRenderObtainHdfSBuf();
    if (sBuf == NULL) {
        LOG_FUN_ERR("RenderGetMuteStu Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    reply = AudioRenderObtainHdfSBuf();
    if (reply == NULL) {
        LOG_FUN_ERR("RenderGetMuteStu Failed to obtain reply");
        AudioRenderBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    ret = AudioCtlRenderGetMuteSBuf(sBuf, handleData);
    if (ret < 0) {
        LOG_FUN_ERR("RenderGetMuteStu Failed to Get Mute sBuf!");
        AudioRenderBufReplyRecycle(sBuf, reply);
        return ret;
    }
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_READ - CTRL_NUM; // ADM Ctrl Num Begin zero
    service = (struct HdfIoService *)handle->object;
    ret = AudioServiceRenderDispatch(service, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        LOG_FUN_ERR("RenderGetMuteStu RenderDispatch Failed!");
        AudioRenderBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue muteValueStu;
    memset_s(&muteValueStu, sizeof(struct AudioCtlElemValue), 0, sizeof(struct AudioCtlElemValue));
    if (!HdfSbufReadInt32(reply, &muteValueStu.value[0])) {
        LOG_FUN_ERR("RenderGetMuteStu Failed to Get Volume sBuf!");
        AudioRenderBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    handleData->renderMode.ctlParam.mute = muteValueStu.value[0];
    AudioRenderBufReplyRecycle(sBuf, reply);
    return ret;
}

int32_t AudioCtlRenderSetGainBuf(struct HdfSBuf *sBuf, struct AudioHwRenderParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        LOG_FUN_ERR("RenderSetGainBuf handleData or sBuf is NULL!");
        return HDF_FAILURE;
    }
    memset_s(&g_elemValue, sizeof(struct AudioCtlElemValue), 0, sizeof(struct AudioCtlElemValue));
    uint32_t card = handleData->renderMode.hwInfo.card;
    if (card < 0 || card >= AUDIO_SERVICE_MAX) {
        LOG_FUN_ERR("RenderSetGainBuf card is Error!");
        return HDF_FAILURE;
    }
    g_elemValue.id.cardServiceName = g_audioService[card];
    g_elemValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_GAIN;
    g_elemValue.id.itemName = "Mic Left Gain";
    g_elemValue.value[0] = (int32_t)handleData->renderMode.ctlParam.audioGain.gain;
    if (!HdfSbufWriteInt32(sBuf, g_elemValue.value[0])) {
        LOG_FUN_ERR("RenderSetGainBuf value[0] Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, g_elemValue.id.iface)) {
        LOG_FUN_ERR("RenderSetGainBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemValue.id.cardServiceName)) {
        LOG_FUN_ERR("RenderSetGainBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemValue.id.itemName)) {
        LOG_FUN_ERR("RenderSetGainBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSetGainStu(struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    LOG_FUN_INFO();
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("RenderSetGainStu paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioRenderObtainHdfSBuf();
    if (sBuf == NULL) {
        LOG_FUN_ERR("RenderSetGainStu Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    ret = AudioCtlRenderSetGainBuf(sBuf, handleData);
    if (ret < 0) {
        LOG_FUN_ERR("RenderSetGainStu Failed to Set Gain sBuf!");
        AudioRenderBufReplyRecycle(sBuf, NULL);
        return ret;
    }
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_WRITE;
    cmdId -= CTRL_NUM;   // ADM Ctrl Num Begin zero
    service = (struct HdfIoService *)handle->object;
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        LOG_FUN_ERR("RenderSetGainStu Service is NULL!");
        AudioRenderBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    ret = service->dispatcher->Dispatch(&service->object, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        LOG_FUN_ERR("RenderSetGainStu Failed to send service call!");
        AudioRenderBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    AudioRenderBufReplyRecycle(sBuf, NULL);
    return ret;
}

int32_t AudioCtlRenderGetGainSBuf(struct HdfSBuf *sBuf, struct AudioHwRenderParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        LOG_FUN_ERR("RenderGetGainSBuf handleData or sBuf is NULL!");
        return HDF_FAILURE;
    }
    memset_s(&g_elemValue, sizeof(struct AudioCtlElemValue), 0, sizeof(struct AudioCtlElemValue));
    uint32_t card = handleData->renderMode.hwInfo.card;
    if (card < 0 || card >= AUDIO_SERVICE_MAX) {
        LOG_FUN_ERR("RenderGetGainSBuf card is invalid!");
        return HDF_FAILURE;
    }
    g_elemValue.id.cardServiceName = g_audioService[card];
    g_elemValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_GAIN;
    g_elemValue.id.itemName = "Mic Left Gain";
    if (!HdfSbufWriteInt32(sBuf, g_elemValue.id.iface)) {
        LOG_FUN_ERR("RenderGetGainSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemValue.id.cardServiceName)) {
        LOG_FUN_ERR("RenderGetGainSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemValue.id.itemName)) {
        LOG_FUN_ERR("RenderGetGainSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderGetGainStu(struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    LOG_FUN_INFO();
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("RenderGetGainStu paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioRenderObtainHdfSBuf();
    if (sBuf == NULL) {
        LOG_FUN_ERR("RenderGetGainStu Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    reply = AudioRenderObtainHdfSBuf();
    if (reply == NULL) {
        LOG_FUN_ERR("RenderGetGainStu Failed to obtain reply");
        AudioRenderBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    ret = AudioCtlRenderGetGainSBuf(sBuf, handleData);
    if (ret < 0) {
        LOG_FUN_ERR("RenderGetGainStu ailed to Get Gain sBuf!");
        AudioRenderBufReplyRecycle(sBuf, reply);
        return ret;
    }
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_READ - CTRL_NUM; // ADM Ctrl Num Begin zero
    service = (struct HdfIoService *)handle->object;
    ret = AudioServiceRenderDispatch(service, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        LOG_FUN_ERR("Dispatch Fail!");
        AudioRenderBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue gainValueStu;
    memset_s(&gainValueStu, sizeof(struct AudioCtlElemValue), 0, sizeof(struct AudioCtlElemValue));
    if (!HdfSbufReadInt32(reply, &gainValueStu.value[0])) {
        LOG_FUN_ERR("Failed to Get Gain sBuf!");
        AudioRenderBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    handleData->renderMode.ctlParam.audioGain.gain = gainValueStu.value[0];
    AudioRenderBufReplyRecycle(sBuf, reply);
    return ret;
}

int32_t AudioCtlRenderSceneSelectSBuf(struct HdfSBuf *sBuf, struct AudioHwRenderParam *handleData, int32_t deviceIndex)
{
    LOG_FUN_INFO();
    if (handleData == NULL || sBuf == NULL) {
        LOG_FUN_ERR("RenderSceneSelectSBuf handleData or sBuf is NULL!");
        return HDF_FAILURE;
    }
    if (deviceIndex < 0 || deviceIndex > PATHPLAN_COUNT - 1) {
        LOG_FUN_ERR("deviceIndex is error!");
        return HDF_FAILURE;
    }
    memset_s(&g_elemValue, sizeof(struct AudioCtlElemValue), 0, sizeof(struct AudioCtlElemValue));
    uint32_t card = handleData->renderMode.hwInfo.card;
    if (card < 0 || card >= AUDIO_SERVICE_MAX) {
        LOG_FUN_ERR("card is invalid!");
        return HDF_FAILURE;
    }
    g_elemValue.id.cardServiceName = g_audioService[card];
    g_elemValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_DAC;
    g_elemValue.id.itemName =
        handleData->renderMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[deviceIndex].deviceSwitch;
    g_elemValue.value[0] =
        handleData->renderMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[deviceIndex].value;
    if (!HdfSbufWriteInt32(sBuf, g_elemValue.value[0])) {
        LOG_FUN_ERR("RenderSceneSelectSBuf Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, g_elemValue.id.iface)) {
        LOG_FUN_ERR("RenderSceneSelectSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemValue.id.cardServiceName)) {
        LOG_FUN_ERR("RenderSceneSelectSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemValue.id.itemName)) {
        LOG_FUN_ERR("RenderSceneSelectSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSceneSelect(struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    LOG_FUN_INFO();
    int32_t index;
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("RenderSceneSelect paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioRenderObtainHdfSBuf();
    if (sBuf == NULL) {
        LOG_FUN_ERR("RenderSceneSelect Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_WRITE - CTRL_NUM; // ADM Ctrl Num Begin zero
    service = (struct HdfIoService *)handle->object;
    int32_t deviceNum = handleData->renderMode.hwInfo.pathSelect.deviceInfo.deviceNum;
    if (deviceNum < AUDIO_MIN_DEVICENUM) {
        LOG_FUN_ERR("AUDIO_MIN_ADAPTERNUM Failed!");
        AudioRenderBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    for (index = 0; index < deviceNum; index++) {
        HdfSbufFlush(sBuf);
        if (AudioCtlRenderSceneSelectSBuf(sBuf, handleData, index) < 0) {
            LOG_FUN_ERR("AudioCtlRenderSceneSelectSBuf Failed!");
            AudioRenderBufReplyRecycle(sBuf, NULL);
            return HDF_FAILURE;
        }
        if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
            LOG_FUN_ERR("Service is NULL!");
            AudioRenderBufReplyRecycle(sBuf, NULL);
            return HDF_FAILURE;
        }
        if (service->dispatcher->Dispatch(&service->object, cmdId, sBuf, reply) < 0) {
            LOG_FUN_ERR("Failed to send service call!");
            AudioRenderBufReplyRecycle(sBuf, NULL);
            return HDF_FAILURE;
        }
    }
    AudioRenderBufReplyRecycle(sBuf, NULL);
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderGetVolThresholdSBuf(struct HdfSBuf *sBuf, struct AudioHwRenderParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        LOG_FUN_ERR("RenderGetVolThresholdSBuf paras is NULL!");
        return HDF_FAILURE;
    }
    memset_s(&g_elemInfo, sizeof(struct AudioCtrlElemInfo), 0, sizeof(struct AudioCtrlElemInfo));
    uint32_t card = handleData->renderMode.hwInfo.card;
    if (card < 0 || card >= AUDIO_SERVICE_MAX) {
        LOG_FUN_ERR("RenderGetVolThresholdSBuf card is Invalid!");
        return HDF_FAILURE;
    }
    g_elemInfo.id.cardServiceName = g_audioService[card];
    g_elemInfo.id.iface = AUDIODRV_CTL_ELEM_IFACE_DAC;
    g_elemInfo.id.itemName = "Master Playback Volume";
    if (!HdfSbufWriteInt32(sBuf, g_elemInfo.id.iface)) {
        LOG_FUN_ERR("RenderGetVolThresholdSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemInfo.id.cardServiceName)) {
        LOG_FUN_ERR("RenderGetVolThresholdSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemInfo.id.itemName)) {
        LOG_FUN_ERR("RenderGetVolThresholdSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSceneGetGainThresholdSBuf(struct HdfSBuf *sBuf, struct AudioHwRenderParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        LOG_FUN_ERR("RenderSceneGetGainThresholdSBuf paras is NULL!");
        return HDF_FAILURE;
    }
    memset_s(&g_elemInfo, sizeof(struct AudioCtrlElemInfo), 0, sizeof(struct AudioCtrlElemInfo));
    uint32_t card = handleData->renderMode.hwInfo.card;
    if (card < 0 || card >= AUDIO_SERVICE_MAX) {
        LOG_FUN_ERR("RenderSceneGetGainThresholdSBuf card is Invalid!");
        return HDF_FAILURE;
    }
    g_elemInfo.id.cardServiceName = g_audioService[card];
    g_elemInfo.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    g_elemInfo.id.itemName = "Mic Left Gain";
    if (!HdfSbufWriteInt32(sBuf, g_elemInfo.id.iface)) {
        LOG_FUN_ERR("RenderSceneGetGainThresholdSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemInfo.id.cardServiceName)) {
        LOG_FUN_ERR("RenderSceneGetGainThresholdSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemInfo.id.itemName)) {
        LOG_FUN_ERR("RenderSceneGetGainThresholdSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSceneGetGainThreshold(struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    LOG_FUN_INFO();
    int32_t ret;
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("RenderSceneGetGainThreshold paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioRenderObtainHdfSBuf();
    if (sBuf == NULL) {
        LOG_FUN_ERR("RenderSceneGetGainThreshold Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    reply = AudioRenderObtainHdfSBuf();
    if (reply == NULL) {
        LOG_FUN_ERR("RenderSceneGetGainThreshold reply is NULL");
        AudioRenderBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    ret = AudioCtlRenderSceneGetGainThresholdSBuf(sBuf, handleData);
    if (ret < 0) {
        LOG_FUN_ERR("RenderSceneGetGainThreshold Get Threshold sBuf Fail!");
        AudioRenderBufReplyRecycle(sBuf, reply);
        return ret;
    }
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_INFO - CTRL_NUM; // ADM Ctrl Num Begin zero
    service = (struct HdfIoService *)handle->object;
    ret = AudioServiceRenderDispatch(service, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        AudioRenderBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    struct AudioCtrlElemInfo gainThreshold;
    memset_s(&gainThreshold, sizeof(struct AudioCtrlElemInfo), 0, sizeof(struct AudioCtrlElemInfo));
    if (!HdfSbufReadInt32(reply, &gainThreshold.type)) {
        LOG_FUN_ERR("RenderSceneGetGainThreshold Failed to Get Volume sBuf!");
        AudioRenderBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadInt32(reply, &gainThreshold.max)) {
        LOG_FUN_ERR("RenderSceneGetGainThreshold Failed to Get Volume sBuf!");
        AudioRenderBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    handleData->renderMode.ctlParam.audioGain.gainMax = gainThreshold.max;
    handleData->renderMode.ctlParam.audioGain.gainMin = 0;
    AudioRenderBufReplyRecycle(sBuf, reply);
    return ret;
}

int32_t AudioCtlRenderGetVolThreshold(struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    LOG_FUN_INFO();
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfSBuf *sBuf = AudioRenderObtainHdfSBuf();
    if (sBuf == NULL) {
        LOG_FUN_ERR("Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    struct HdfSBuf *reply = AudioRenderObtainHdfSBuf();
    if (reply == NULL) {
        LOG_FUN_ERR("reply is NULL");
        AudioRenderBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    int32_t ret = AudioCtlRenderGetVolThresholdSBuf(sBuf, handleData);
    if (ret < 0) {
        LOG_FUN_ERR("Get Threshold sBuf Fail!");
        AudioRenderBufReplyRecycle(sBuf, reply);
        return ret;
    }
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_INFO - CTRL_NUM; // ADM Ctrl Num Begin zero
    struct HdfIoService *service = (struct HdfIoService *)handle->object;
    ret = AudioServiceRenderDispatch(service, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        AudioRenderBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    struct AudioCtrlElemInfo volThreshold;
    memset_s(&volThreshold, sizeof(struct AudioCtrlElemInfo), 0, sizeof(struct AudioCtrlElemInfo));
    if (!HdfSbufReadInt32(reply, &volThreshold.type)) {
        LOG_FUN_ERR("Failed to Get Volume sBuf!");
        AudioRenderBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadInt32(reply, &volThreshold.max)) {
        AudioRenderBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadInt32(reply, &volThreshold.min)) {
        AudioRenderBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    handleData->renderMode.ctlParam.volThreshold.volMax = volThreshold.max;
    handleData->renderMode.ctlParam.volThreshold.volMin = volThreshold.min;
    AudioRenderBufReplyRecycle(sBuf, reply);
    return ret;
}

int32_t AudioCtlRenderSetChannelModeBuf(struct HdfSBuf *sBuf, struct AudioHwRenderParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        LOG_FUN_ERR("RenderSetChannelModeBuf parameter is empty!");
        return HDF_FAILURE;
    }
    memset_s(&g_elemValue, sizeof(struct AudioCtlElemValue), 0, sizeof(struct AudioCtlElemValue));
    uint32_t card = handleData->renderMode.hwInfo.card;
    if (card < 0 || card >= AUDIO_SERVICE_MAX) {
        LOG_FUN_ERR("RenderSetChannelModeBuf card is Error!");
        return HDF_FAILURE;
    }
    g_elemValue.id.cardServiceName = g_audioService[card];
    g_elemValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_AIAO;
    g_elemValue.id.itemName = "Render Channel Mode";
    g_elemValue.value[0] = handleData->frameRenderMode.mode;
    if (!HdfSbufWriteInt32(sBuf, g_elemValue.value[0])) {
        LOG_FUN_ERR("RenderSetChannelModeBuf mode Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, g_elemValue.id.iface)) {
        LOG_FUN_ERR("RenderSetChannelModeBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemValue.id.cardServiceName)) {
        LOG_FUN_ERR("RenderSetChannelModeBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemValue.id.itemName)) {
        LOG_FUN_ERR("RenderSetChannelModeBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderSetChannelMode(struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    LOG_FUN_INFO();
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("RenderSetChannelMode paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioRenderObtainHdfSBuf();
    if (sBuf == NULL) {
        LOG_FUN_ERR("RenderSetChannelMode Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    ret = AudioCtlRenderSetChannelModeBuf(sBuf, handleData);
    if (ret < 0) {
        LOG_FUN_ERR("RenderSetChannelMode Failed to Set ChannelMode sBuf!");
        AudioRenderBufReplyRecycle(sBuf, NULL);
        return ret;
    }
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_WRITE;
    cmdId -= CTRL_NUM;   // ADM Ctrl Num Begin zero
    service = (struct HdfIoService *)handle->object;
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        LOG_FUN_ERR("RenderSetChannelMode Service is NULL!");
        AudioRenderBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    ret = service->dispatcher->Dispatch(&service->object, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        LOG_FUN_ERR("RenderSetChannelMode Failed to send service call!");
        AudioRenderBufReplyRecycle(sBuf, NULL);
        return ret;
    }
    AudioRenderBufReplyRecycle(sBuf, NULL);
    return ret;
}

int32_t AudioCtlRenderGetChannelModeSBuf(struct HdfSBuf *sBuf, struct AudioHwRenderParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        LOG_FUN_ERR("RenderGetChannelModeSBuf parameter is empty!");
        return HDF_FAILURE;
    }
    memset_s(&g_elemValue, sizeof(struct AudioCtlElemValue), 0, sizeof(struct AudioCtlElemValue));
    uint32_t card = handleData->renderMode.hwInfo.card;
    if (card < 0 || card >= AUDIO_SERVICE_MAX) {
        LOG_FUN_ERR("RenderGetChannelModeSBuf card is Error!");
        return HDF_FAILURE;
    }
    g_elemValue.id.cardServiceName = g_audioService[card];
    g_elemValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_AIAO;
    g_elemValue.id.itemName = "Render Channel Mode";
    if (!HdfSbufWriteInt32(sBuf, g_elemValue.id.iface)) {
        LOG_FUN_ERR("RenderGetChannelModeSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemValue.id.cardServiceName)) {
        LOG_FUN_ERR("RenderGetChannelModeSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemValue.id.itemName)) {
        LOG_FUN_ERR("RenderGetChannelModeSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderGetChannelMode(struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    int32_t ret;
    LOG_FUN_INFO();
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("RenderGetChannelMode paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = AudioRenderObtainHdfSBuf();
    if (sBuf == NULL) {
        LOG_FUN_ERR("RenderGetChannelMode Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    reply = AudioRenderObtainHdfSBuf();
    if (reply == NULL) {
        LOG_FUN_ERR("RenderGetChannelMode Failed to obtain reply");
        AudioRenderBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    ret = AudioCtlRenderGetChannelModeSBuf(sBuf, handleData);
    if (ret < 0) {
        LOG_FUN_ERR("RenderGetChannelMode Failed to Get Channel Mode sBuf!");
        AudioRenderBufReplyRecycle(sBuf, reply);
        return ret;
    }
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_READ - CTRL_NUM; // ADM Ctrl Num Begin zero
    service = (struct HdfIoService *)handle->object;
    handleData->frameRenderMode.mode = 1;
    ret = AudioServiceRenderDispatch(service, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        AudioRenderBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemValue;
    if (!HdfSbufReadInt32(reply, &elemValue.value[0])) {
        LOG_FUN_ERR("Failed to Get ChannelMode sBuf!");
        AudioRenderBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    handleData->frameRenderMode.mode = (enum AudioChannelMode)elemValue.value[0];
    AudioRenderBufReplyRecycle(sBuf, reply);
    return ret;
}

int32_t AudioCtlRenderSetAcodecSBuf(struct HdfSBuf *sBuf, const char *codec, int enable)
{
    if (sBuf == NULL) {
        LOG_FUN_ERR("handleData or sBuf is NULL!");
        return HDF_FAILURE;
    }
    memset_s(&g_elemValue, sizeof(struct AudioCtlElemValue), 0, sizeof(struct AudioCtlElemValue));
    g_elemValue.id.cardServiceName = g_audioService[0];
    g_elemValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_ACODEC;
    g_elemValue.id.itemName = codec;
    g_elemValue.value[0] = enable;
    if (!HdfSbufWriteInt32(sBuf, g_elemValue.value[0])) {
        LOG_FUN_ERR("RenderSetAcodecSBuf value Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(sBuf, g_elemValue.id.iface)) {
        LOG_FUN_ERR("RenderSetAcodecSBuf iface Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemValue.id.cardServiceName)) {
        LOG_FUN_ERR("RenderSetAcodecSBuf cardServiceName Write Fail!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_elemValue.id.itemName)) {
        LOG_FUN_ERR("RenderSetAcodecSBuf itemName Write Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlRenderChangeInAcodec(struct HdfIoService *service,
                                     const char *codecName,
                                     struct HdfSBuf *sBuf,
                                     int32_t status,
                                     int cmdId)
{
    LOG_FUN_INFO();
    if (service == NULL || sBuf == NULL) {
        LOG_FUN_ERR("service or sBuf is NULL!");
        return HDF_FAILURE;
    }
    if (AudioCtlRenderSetAcodecSBuf(sBuf, codecName, status)) {
        return HDF_FAILURE;
    }
    cmdId = AUDIODRV_CTL_IOCTL_ELEM_WRITE - CTRL_NUM;
    return (AudioServiceRenderDispatch(service, cmdId, sBuf, NULL));
}

int32_t AudioCtlRenderSetAcodecMode(struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    LOG_FUN_INFO();
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    struct HdfSBuf *sBuf = AudioRenderObtainHdfSBuf();
    if (sBuf == NULL) {
        LOG_FUN_ERR("Failed to obtain sBuf");
        return HDF_FAILURE;
    }
    service = (struct HdfIoService *)handle->object;
    if (cmdId == AUDIODRV_CTL_IOCTL_ACODEC_CHANGE_IN) {
        LOG_PARA_INFO("****Acodec is In****");
        /* disable  External Codec */
        if (AudioCtlRenderChangeInAcodec(service, AUDIODRV_CTL_EXTERN_CODEC_STR,
            sBuf, AUDIODRV_CTL_ACODEC_DISABLE, cmdId)) {
            AudioRenderBufReplyRecycle(sBuf, NULL);
            return HDF_FAILURE;
        }
        /* enable Internally Codec */
        HdfSbufFlush(sBuf);
        if (AudioCtlRenderChangeInAcodec(service, AUDIODRV_CTL_INTERNAL_CODEC_STR,
            sBuf, AUDIODRV_CTL_ACODEC_ENABLE, cmdId)) {
            AudioRenderBufReplyRecycle(sBuf, NULL);
            return HDF_FAILURE;
        }
    } else if (cmdId == AUDIODRV_CTL_IOCTL_ACODEC_CHANGE_OUT) {
        LOG_PARA_INFO("****Acodec is Out****");
        /* disable  Internally   Codec */
        if (AudioCtlRenderChangeInAcodec(service, AUDIODRV_CTL_INTERNAL_CODEC_STR,
            sBuf, AUDIODRV_CTL_ACODEC_DISABLE, cmdId)) {
            AudioRenderBufReplyRecycle(sBuf, NULL);
            return HDF_FAILURE;
        }
        /* enable External Codec */
        HdfSbufFlush(sBuf);
        if (AudioCtlRenderChangeInAcodec(service, AUDIODRV_CTL_EXTERN_CODEC_STR,
            sBuf, AUDIODRV_CTL_ACODEC_ENABLE, cmdId)) {
            AudioRenderBufReplyRecycle(sBuf, NULL);
            return HDF_FAILURE;
        }
    } else {
        return HDF_FAILURE;
    }
    AudioRenderBufReplyRecycle(sBuf, NULL);
    return HDF_SUCCESS;
}

int32_t AudioInterfaceLibCtlRender(struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    LOG_FUN_INFO();
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("paras is NULL!");
        return HDF_FAILURE;
    }
    if (cmdId < AUDIODRV_CTL_IOCTL_ELEM_INFO || cmdId > AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ) {
        LOG_FUN_ERR("cmdId Not Supported!");
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
        case AUDIODRV_CTL_IOCTL_ACODEC_CHANGE_IN:
        case AUDIODRV_CTL_IOCTL_ACODEC_CHANGE_OUT:
            return (AudioCtlRenderSetAcodecMode(handle, cmdId, handleData));
        case AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ:
            return (AudioCtlRenderGetVolThreshold(handle, cmdId, handleData));
        default:
            LOG_FUN_ERR("Output Mode not support!");
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

int32_t FrameSbufWriteBuffer(struct HdfSBuf *sBuf, const struct AudioHwRenderParam *handleData)
{
    LOG_FUN_INFO();
    if (sBuf == NULL || handleData == NULL) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, (uint32_t)(handleData->frameRenderMode.bufferFrameSize))) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteBuffer(sBuf, handleData->frameRenderMode.buffer, handleData->frameRenderMode.bufferSize)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioOutputRenderHwParams(struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    LOG_FUN_INFO();
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        return HDF_FAILURE;
    }
    int32_t ret;
    struct HdfIoService *service = NULL;
    struct HdfSBuf *sBuf = AudioRenderObtainHdfSBuf();
    if (sBuf == NULL) {
        return HDF_FAILURE;
    }
    if (SetHwParams(handleData) < 0) {
        AudioRenderBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    if (ParamsSbufWriteBuffer(sBuf)) {
        AudioRenderBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    service = (struct HdfIoService *)handle->object;
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        LOG_FUN_ERR("Service is NULL!");
        AudioRenderBufReplyRecycle(sBuf, NULL);
        return HDF_FAILURE;
    }
    ret = service->dispatcher->Dispatch(&service->object, cmdId, sBuf, NULL);
    if (ret != HDF_SUCCESS) {
        LOG_FUN_ERR("Failed to send service call!");
        AudioRenderBufReplyRecycle(sBuf, NULL);
        return ret;
    }
    AudioRenderBufReplyRecycle(sBuf, NULL);
    return HDF_SUCCESS;
}

int32_t AudioOutputRenderWriteFrame(struct HdfIoService *service,
                                    int cmdId,
                                    struct HdfSBuf *sBuf,
                                    struct HdfSBuf *reply)
{
    LOG_FUN_INFO();
    int32_t ret;
    uint32_t buffStatus = 0;
    int32_t tryNum = 50; // try send sBuf count
    if (service == NULL || sBuf == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    do {
        ret = service->dispatcher->Dispatch(&service->object, cmdId, sBuf, reply);
        if (ret != HDF_SUCCESS) {
            LOG_FUN_ERR("Failed to send service call!");
            AudioRenderBufReplyRecycle(sBuf, reply);
            return ret;
        }
        if (!HdfSbufReadUint32(reply, &buffStatus)) {
            LOG_FUN_ERR("Failed to Get buffStatus!");
            AudioRenderBufReplyRecycle(sBuf, reply);
            return HDF_FAILURE;
        }
        if (buffStatus == CIR_BUFF_FULL) {
            LOG_PARA_INFO("Cir buff fulled wait 10ms");
            tryNum--;
            usleep(10000);  // wait 10ms
            continue;
        }
        break;
    } while (tryNum > 0);
    AudioRenderBufReplyRecycle(sBuf, reply);
    if (tryNum > 0) {
        return HDF_SUCCESS;
    } else {
        LOG_FUN_ERR("Out of tryNum!");
        return HDF_FAILURE;
    }
}

int32_t AudioOutputRenderWrite(struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    LOG_FUN_INFO();
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        return HDF_FAILURE;
    }
    struct HdfIoService *service = NULL;
    size_t sbufSize = handleData->frameRenderMode.bufferSize + AUDIO_SBUF_EXTEND;
    struct HdfSBuf *sBuf = HdfSBufTypedObtainCapacity(SBUF_RAW, sbufSize);
    if (sBuf == NULL) {
        LOG_FUN_ERR("Get sBuf Fail");
        return HDF_FAILURE;
    }
    struct HdfSBuf *reply = AudioRenderObtainHdfSBuf();
    if (reply == NULL) {
        LOG_FUN_ERR("reply is empty");
        HdfSBufRecycle(sBuf);
        return HDF_FAILURE;
    }
    if (FrameSbufWriteBuffer(sBuf, handleData)) {
        AudioRenderBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    service = (struct HdfIoService *)handle->object;
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        LOG_FUN_ERR("Service is NULL!");
        AudioRenderBufReplyRecycle(sBuf, reply);
        return HDF_FAILURE;
    }
    int32_t ret = AudioOutputRenderWriteFrame(service, cmdId, sBuf, reply);
    if (ret != 0) {
        LOG_FUN_ERR("AudioOutputRenderWriteFrame is Fail!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioOutputRenderStartPrepare(struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    LOG_FUN_INFO();
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        return HDF_FAILURE;
    }
    int32_t ret;
    struct HdfIoService *service = NULL;
    service = (struct HdfIoService *)handle->object;
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        LOG_FUN_ERR("RenderStartPrepare Service is NULL!");
        return HDF_FAILURE;
    }
    ret = service->dispatcher->Dispatch(&service->object, cmdId, NULL, NULL);
    if (ret != HDF_SUCCESS) {
        LOG_FUN_ERR("RenderStartPrepare Failed to send service call!");
        return ret;
    }
    return HDF_SUCCESS;
}

int32_t AudioOutputRenderStop(struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    LOG_FUN_INFO();
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        return HDF_FAILURE;
    }
    int32_t ret;
    struct HdfIoService *service = NULL;
    service = (struct HdfIoService *)handle->object;
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        LOG_FUN_ERR("RenderStop Service is NULL!");
        return HDF_FAILURE;
    }
    ret = service->dispatcher->Dispatch(&service->object, cmdId, NULL, NULL);
    if (ret != HDF_SUCCESS) {
        LOG_FUN_ERR("RenderStop Failed to send service call!");
        return ret;
    }
    return HDF_SUCCESS;
}

int32_t AudioInterfaceLibOutputRender(struct DevHandle *handle, int cmdId, struct AudioHwRenderParam *handleData)
{
    LOG_FUN_INFO();
    if (handle == NULL) {
        LOG_FUN_ERR("Input Render handle is NULL!");
        return HDF_FAILURE;
    }
    if (handle->object == NULL || handleData == NULL) {
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
            ret = AudioOutputRenderStartPrepare(handle, cmdId, handleData);
            break;

        case AUDIODRV_CTL_IOCTL_PAUSE_WRITE:
            return (AudioCtlRenderSetPauseStu(handle, cmdId, handleData));

        default:
            LOG_FUN_ERR("Output Mode not support!");
            ret = HDF_FAILURE;
            break;
    }
    return ret;
}

int32_t AudioBindServiceRenderObject(struct DevHandle *handle, const char *name)
{
    LOG_FUN_INFO();
    if (handle == NULL || name == NULL) {
        LOG_FUN_ERR("service name or handle is NULL!");
        return HDF_FAILURE;
    }
    char *serviceName = (char *)calloc(1, NAME_LEN);
    if (serviceName == NULL) {
        LOG_FUN_ERR("Failed to OsalMemCalloc serviceName");
        return HDF_FAILURE;
    }
    int ret = snprintf_s(serviceName, NAME_LEN - 1, SERVIC_NAME_MAX_LEN + 1, "hdf_audio_%s", name);
    if (ret < 0) {
        LOG_FUN_ERR("Failed to snprintf_s");
        AudioMemFree((void **)&serviceName);
        return HDF_FAILURE;
    }
    struct HdfIoService *service = HdfIoServiceBindName(serviceName);
    if (service == NULL) {
        LOG_FUN_ERR("Failed to get service!");
        AudioMemFree((void **)&serviceName);
        return HDF_FAILURE;
    }
    LOG_PARA_INFO("serviceName = %s", serviceName);
    AudioMemFree((void **)&serviceName);
    handle->object = service;
    return HDF_SUCCESS;
}

/* CreatRender for Bind handle */
struct DevHandle *AudioBindServiceRender(const char *name)
{
    LOG_FUN_INFO();
    struct DevHandle *handle = NULL;
    if (name == NULL) {
        LOG_FUN_ERR("service name NULL!");
        return NULL;
    }
    handle = (struct DevHandle *)calloc(1, sizeof(struct DevHandle));
    if (handle == NULL) {
        LOG_FUN_ERR("Failed to OsalMemCalloc handle");
        return NULL;
    }
    int32_t ret = AudioBindServiceRenderObject(handle, name);
    if (ret != HDF_SUCCESS) {
        LOG_FUN_ERR("handle->object is NULL!");
        AudioMemFree((void **)&handle);
        return NULL;
    }
    LOG_PARA_INFO("BIND SERVICE SUCCESS!");
    return handle;
}

void AudioCloseServiceRender(struct DevHandle *handle)
{
    LOG_FUN_INFO();
    if (handle == NULL || handle->object == NULL) {
        LOG_FUN_ERR("Render handle or handle->object is NULL");
        return;
    }
    struct HdfIoService *service = (struct HdfIoService *)handle->object;
    HdfIoServiceRecycle(service);
    AudioMemFree((void **)&handle);
    return;
}

int32_t AudioInterfaceLibModeRender(struct DevHandle *handle, struct AudioHwRenderParam *handleData, int cmdId)
{
    LOG_FUN_INFO();
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        LOG_FUN_ERR("paras is NULL!");
        return HDF_FAILURE;
    }
    switch (cmdId) {
        case AUDIO_DRV_PCM_IOCTL_HW_PARAMS:
        case AUDIO_DRV_PCM_IOCTL_WRITE:
        case AUDIO_DRV_PCM_IOCTRL_STOP:
        case AUDIO_DRV_PCM_IOCTRL_START:
        case AUDIO_DRV_PCM_IOCTL_PREPARE:
        case AUDIODRV_CTL_IOCTL_PAUSE_WRITE:
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
        case AUDIODRV_CTL_IOCTL_ACODEC_CHANGE_IN:
        case AUDIODRV_CTL_IOCTL_ACODEC_CHANGE_OUT:
        case AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ:
            return (AudioInterfaceLibCtlRender(handle, cmdId, handleData));
        default:
            LOG_FUN_ERR("Mode Error!");
            break;
    }
    return HDF_ERR_NOT_SUPPORT;
}

