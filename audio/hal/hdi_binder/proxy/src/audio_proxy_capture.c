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

#include "audio_proxy_common.h"

static int32_t AudioProxyCaptureCtrl(int cmId, AudioHandle handle)
{
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessCapture(handle, &data, &reply) < 0) {
        return HDF_FAILURE;
    }
    int32_t ret = AudioProxyDispatchCall(cmId, data, reply);
    AudioProxyBufReplyRecycle(data, reply);
    return ret;
}

int32_t AudioProxyCaptureStart(AudioHandle handle)
{
    LOG_FUN_INFO();
    return AudioProxyCaptureCtrl(AUDIO_HDI_CAPTURE_START, handle);
}

int32_t AudioProxyCaptureStop(AudioHandle handle)
{
    LOG_FUN_INFO();
    return AudioProxyCaptureCtrl(AUDIO_HDI_CAPTURE_STOP, handle);
}

int32_t AudioProxyCapturePause(AudioHandle handle)
{
    LOG_FUN_INFO();
    return AudioProxyCaptureCtrl(AUDIO_HDI_CAPTURE_PAUSE, handle);
}

int32_t AudioProxyCaptureResume(AudioHandle handle)
{
    LOG_FUN_INFO();
    return AudioProxyCaptureCtrl(AUDIO_HDI_CAPTURE_RESUME, handle);
}

int32_t AudioProxyCaptureFlush(AudioHandle handle)
{
    LOG_FUN_INFO();
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL) {
        return HDF_FAILURE;
    }
    return HDF_ERR_NOT_SUPPORT;
}

int32_t AudioProxyCaptureGetFrameParameter(int cmId, AudioHandle handle, uint64_t *param)
{
    if (param == NULL) {
        return HDF_FAILURE;
    }
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessCapture(handle, &data, &reply) < 0) {
        return HDF_FAILURE;
    }
    int32_t ret = AudioProxyDispatchCall(cmId, data, reply);
    if (ret < 0) {
        LOG_FUN_ERR("AudioCaptureGetFrameSize FAIL");
        AudioProxyBufReplyRecycle(data, reply);
        return ret;
    }
    if (!HdfSbufReadUint64(reply, param)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    AudioProxyBufReplyRecycle(data, reply);
    return ret;
}

int32_t AudioProxyCaptureGetFrameSize(AudioHandle handle, uint64_t *size)
{
    return AudioProxyCaptureGetFrameParameter(AUDIO_HDI_CAPTURE_GET_FRAME_SIZE, handle, size);
}

int32_t AudioProxyCaptureGetFrameCount(AudioHandle handle, uint64_t *count)
{
    return AudioProxyCaptureGetFrameParameter(AUDIO_HDI_CAPTURE_GET_FRAME_COUNT, handle, count);
}

int32_t AudioProxyCaptureSetSampleAttributes(AudioHandle handle, const struct AudioSampleAttributes *attrs)
{
    if (handle == NULL || attrs == NULL) {
        return HDF_FAILURE;
    }
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessCapture(handle, &data, &reply) < 0) {
        return HDF_FAILURE;
    }
    if (AudioProxyWriteSampleAttributes(data, attrs) < 0) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    int32_t ret = AudioProxyDispatchCall(AUDIO_HDI_CAPTURE_SET_SAMPLE_ATTR, data, reply);
    AudioProxyBufReplyRecycle(data, reply);
    return ret;
}

int32_t AudioProxyCaptureGetSampleAttributes(AudioHandle handle, struct AudioSampleAttributes *attrs)
{
    if (attrs == NULL) {
        return HDF_FAILURE;
    }
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessCapture(handle, &data, &reply) < 0) {
        return HDF_FAILURE;
    }
    int32_t ret = AudioProxyDispatchCall(AUDIO_HDI_CAPTURE_GET_SAMPLE_ATTR, data, reply);
    if (ret < 0) {
        LOG_FUN_ERR("AudioCaptureGetSampleAttributes FAIL");
        AudioProxyBufReplyRecycle(data, reply);
        return ret;
    }
    if (AudioProxyReadSapmleAttrbutes(reply, attrs)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    AudioProxyBufReplyRecycle(data, reply);
    return HDF_SUCCESS;
}

int32_t AudioProxyCaptureGetCurrentChannelId(AudioHandle handle, uint32_t *channelId)
{
    if (channelId == NULL) {
        return HDF_FAILURE;
    }
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessCapture(handle, &data, &reply) < 0) {
        return HDF_FAILURE;
    }
    int32_t ret = AudioProxyDispatchCall(AUDIO_HDI_CAPTURE_GET_CUR_CHANNEL_ID, data, reply);
    if (ret < 0) {
        LOG_FUN_ERR("AudioCaptureGetFrameSize FAIL");
        AudioProxyBufReplyRecycle(data, reply);
        return ret;
    }
    if (!HdfSbufReadUint32(reply, channelId)) {
        LOG_FUN_ERR("Read reply FAIL");
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    AudioProxyBufReplyRecycle(data, reply);
    return HDF_SUCCESS;
}

int32_t AudioProxyCaptureCheckSceneCapability(AudioHandle handle,
    const struct AudioSceneDescriptor *scene, bool *supported)
{
    if (scene == NULL || supported == NULL) {
        return HDF_FAILURE;
    }
    uint32_t tempPins;
    uint32_t tempSupported = 0;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessCapture(handle, &data, &reply) < 0) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, scene->scene.id)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    tempPins = scene->desc.pins;
    if (!HdfSbufWriteUint32(data, tempPins)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    int32_t ret = AudioProxyDispatchCall(AUDIO_HDI_CAPTURE_CHECK_SCENE_CAPABILITY, data, reply);
    if (ret < 0) {
        LOG_FUN_ERR("AudioProxyCaptureCheckSceneCapability FAIL");
        AudioProxyBufReplyRecycle(data, reply);
        return ret;
    }
    if (!HdfSbufReadUint32(reply, &tempSupported)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    *supported = (bool)tempSupported;
    AudioProxyBufReplyRecycle(data, reply);
    return HDF_SUCCESS;
}

int32_t AudioProxyCaptureSelectScene(AudioHandle handle, const struct AudioSceneDescriptor *scene)
{
    if (scene == NULL) {
        return HDF_FAILURE;
    }
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessCapture(handle, &data, &reply) < 0) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, (enum AudioCategory)scene->scene.id)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    uint32_t tempPins = scene->desc.pins;
    if (!HdfSbufWriteUint32(data, tempPins)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    int32_t ret = AudioProxyDispatchCall(AUDIO_HDI_CAPTURE_SELECT_SCENE, data, reply);
    AudioProxyBufReplyRecycle(data, reply);
    return ret;
}

int32_t AudioProxyCaptureSetMute(AudioHandle handle, bool mute)
{
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessCapture(handle, &data, &reply) < 0) {
        return HDF_FAILURE;
    }
    uint32_t tempMute = (uint32_t)mute;
    if (!HdfSbufWriteUint32(data, tempMute)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    int32_t ret = AudioProxyDispatchCall(AUDIO_HDI_CAPTURE_SET_MUTE, data, reply);
    AudioProxyBufReplyRecycle(data, reply);
    return ret;
}

int32_t AudioProxyCaptureGetMute(AudioHandle handle, bool *mute)
{
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (mute == NULL) {
        return HDF_FAILURE;
    }
    if (AudioProxyPreprocessCapture(handle, &data, &reply) < 0) {
        return HDF_FAILURE;
    }
    int32_t ret = AudioProxyDispatchCall(AUDIO_HDI_CAPTURE_GET_MUTE, data, reply);
    if (ret < 0) {
        LOG_FUN_ERR("AudioCaptureGetMute FAIL");
        AudioProxyBufReplyRecycle(data, reply);
        return ret;
    }
    uint32_t tempMute = 0;
    if (!HdfSbufReadUint32(reply, &tempMute)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    *mute = (bool)tempMute;
    AudioProxyBufReplyRecycle(data, reply);
    return HDF_SUCCESS;
}

int32_t AudioProxyCaptureSetVolume(AudioHandle handle, float volume)
{
    return AudioProxyCommonSetCtrlParam(AUDIO_HDI_CAPTURE_SET_VOLUME, handle, volume);
}

int32_t AudioProxyCaptureGetVolume(AudioHandle handle, float *volume)
{
    return AudioProxyCommonGetCtrlParam(AUDIO_HDI_CAPTURE_GET_VOLUME, handle, volume);
}

int32_t AudioProxyCaptureGetGainThreshold(AudioHandle handle, float *min, float *max)
{
    if (NULL == min || NULL == max) {
        return HDF_FAILURE;
    }
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessCapture(handle, &data, &reply) < 0) {
        return HDF_FAILURE;
    }
    int32_t ret = AudioProxyDispatchCall(AUDIO_HDI_CAPTURE_GET_GAIN_THRESHOLD, data, reply);
    if (ret < 0) {
        LOG_FUN_ERR("AudioCaptureGetGainThreshold FAIL");
        AudioProxyBufReplyRecycle(data, reply);
        return ret;
    }
    uint32_t temp;
    if (!HdfSbufReadUint32(reply, &temp)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    *min = temp;
    if (!HdfSbufReadUint32(reply, &temp)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    *max = temp;
    AudioProxyBufReplyRecycle(data, reply);
    return HDF_SUCCESS;
}

int32_t AudioProxyCaptureGetGain(AudioHandle handle, float *gain)
{
    return AudioProxyCommonGetCtrlParam(AUDIO_HDI_CAPTURE_GET_GAIN, handle, gain);
}

int32_t AudioProxyCaptureSetGain(AudioHandle handle, float gain)
{
    return AudioProxyCommonSetCtrlParam(AUDIO_HDI_CAPTURE_SET_GAIN, handle, gain);
}

int32_t AudioProxyCaptureCaptureFrame(struct AudioCapture *capture, void *frame,
                                      uint64_t requestBytes, uint64_t *replyBytes)
{
    const char *buffer = NULL;
    uint32_t length;
    if (frame == NULL || replyBytes == NULL) {
        LOG_FUN_ERR("capture Frame Paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessCapture((AudioHandle)capture, &data, &reply) < 0) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint64(data, requestBytes)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    int32_t ret = AudioProxyDispatchCall(AUDIO_HDI_CAPTURE_CAPTURE_FRAME, data, reply);
    if (ret < 0) {
        if (ret != HDF_ERR_INVALID_OBJECT) {
            LOG_FUN_ERR("AudioCaptureCaptureFrame FAIL");
        }
        AudioProxyBufReplyRecycle(data, reply);
        return ret;
    }
    if (!HdfSbufReadBuffer(reply, (const void **)&buffer, &length)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    if ((uint64_t)length > requestBytes) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    memcpy_s(frame, requestBytes, buffer, length);
    if (!HdfSbufReadUint64(reply, replyBytes)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    AudioProxyBufReplyRecycle(data, reply);
    return HDF_SUCCESS;
}

int32_t AudioProxyCaptureGetCapturePosition(struct AudioCapture *capture, uint64_t *frames, struct AudioTimeStamp *time)
{
    if (frames == NULL || time == NULL) {
        return HDF_FAILURE;
    }
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessCapture((AudioHandle)capture, &data, &reply) < 0) {
        return HDF_FAILURE;
    }
    int32_t ret = AudioProxyDispatchCall(AUDIO_HDI_CAPTURE_GET_CAPTURE_POSITION, data, reply);
    if (ret < 0) {
        LOG_FUN_ERR("AudioCaptureGetCapturePosition FAIL");
        AudioProxyBufReplyRecycle(data, reply);
        return ret;
    }
    if (!HdfSbufReadUint64(reply, frames)) {
        LOG_FUN_ERR("Read Buf FAIL");
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadInt64(reply, &time->tvSec)) {
        LOG_FUN_ERR("Read Buf FAIL");
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadInt64(reply, &time->tvNSec)) {
        LOG_FUN_ERR("Read Buf FAIL");
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    AudioProxyBufReplyRecycle(data, reply);
    return HDF_SUCCESS;
}
