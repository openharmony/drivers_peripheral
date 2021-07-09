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

int32_t AudioProxyRenderCtrl(int cmId, AudioHandle handle)
{
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessRender(handle, &data, &reply) < 0) {
        return HDF_FAILURE;
    }
    int32_t ret = AudioProxyDispatchCall(cmId, data, reply);
    AudioProxyBufReplyRecycle(data, reply);
    return ret;
}

int32_t AudioProxyRenderStart(AudioHandle handle)
{
    LOG_FUN_INFO();
    return AudioProxyRenderCtrl(AUDIO_HDI_RENDER_START, handle);
}

int32_t AudioProxyRenderStop(AudioHandle handle)
{
    LOG_FUN_INFO();
    return AudioProxyRenderCtrl(AUDIO_HDI_RENDER_STOP, handle);
}

int32_t AudioProxyRenderPause(AudioHandle handle)
{
    LOG_FUN_INFO();
    return AudioProxyRenderCtrl(AUDIO_HDI_RENDER_PAUSE, handle);
}

int32_t AudioProxyRenderResume(AudioHandle handle)
{
    LOG_FUN_INFO();
    return AudioProxyRenderCtrl(AUDIO_HDI_RENDER_RESUME, handle);
}

int32_t AudioProxyRenderFlush(AudioHandle handle)
{
    struct AudioHwRender *hwRender = (struct AudioHwRender *)handle;
    if (hwRender == NULL) {
        return HDF_FAILURE;
    }
    return HDF_ERR_NOT_SUPPORT;
}

int32_t AudioProxyRenderGetFrameParameter(int cmId, AudioHandle handle, uint64_t *param)
{
    if (param == NULL) {
        return HDF_FAILURE;
    }
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessRender(handle, &data, &reply) < 0) {
        return HDF_FAILURE;
    }
    int32_t ret = AudioProxyDispatchCall(cmId, data, reply);
    if (ret < 0) {
        AudioProxyBufReplyRecycle(data, reply);
        return ret;
    }
    if (!HdfSbufReadUint64(reply, param)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    AudioProxyBufReplyRecycle(data, reply);
    return HDF_SUCCESS;
}

int32_t AudioProxyRenderGetFrameSize(AudioHandle handle, uint64_t *size)
{
    return AudioProxyRenderGetFrameParameter(AUDIO_HDI_RENDER_GET_FRAME_SIZE, handle, size);
}

int32_t AudioProxyRenderGetFrameCount(AudioHandle handle, uint64_t *count)
{
    return AudioProxyRenderGetFrameParameter(AUDIO_HDI_RENDER_GET_FRAME_COUNT, handle, count);
}

int32_t AudioProxyRenderSetSampleAttributes(AudioHandle handle, const struct AudioSampleAttributes *attrs)
{
    if (handle == NULL || attrs == NULL) {
        return HDF_FAILURE;
    }
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessRender(handle, &data, &reply) < 0) {
        return HDF_FAILURE;
    }
    if (AudioProxyWriteSampleAttributes(data, attrs) < 0) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    int32_t ret = AudioProxyDispatchCall(AUDIO_HDI_RENDER_SET_SAMPLE_ATTR, data, reply);
    AudioProxyBufReplyRecycle(data, reply);
    return ret;
}

int32_t AudioProxyRenderGetSampleAttributes(AudioHandle handle, struct AudioSampleAttributes *attrs)
{
    if (attrs == NULL) {
        return HDF_FAILURE;
    }
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessRender(handle, &data, &reply) < 0) {
        return HDF_FAILURE;
    }
    int32_t ret = AudioProxyDispatchCall(AUDIO_HDI_RENDER_GET_SAMPLE_ATTR, data, reply);
    if (ret < 0) {
        LOG_FUN_ERR("AudioRenderGetSampleAttributes FAIL");
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

int32_t AudioProxyRenderGetCurrentChannelId(AudioHandle handle, uint32_t *channelId)
{
    if (channelId == NULL) {
        return HDF_FAILURE;
    }
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessRender(handle, &data, &reply) < 0) {
        return HDF_FAILURE;
    }
    int32_t ret = AudioProxyDispatchCall(AUDIO_HDI_RENDER_GET_CUR_CHANNEL_ID, data, reply);
    if (ret < 0) {
        LOG_FUN_ERR("AudioRenderGetCurrentChannelId FAIL");
        AudioProxyBufReplyRecycle(data, reply);
        return ret;
    }
    if (!HdfSbufReadUint32(reply, channelId)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    AudioProxyBufReplyRecycle(data, reply);
    return HDF_SUCCESS;
}

int32_t AudioProxyRenderCheckSceneCapability(AudioHandle handle,
    const struct AudioSceneDescriptor *scene, bool *supported)
{
    if (scene == NULL || supported == NULL) {
        return HDF_FAILURE;
    }
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessRender(handle, &data, &reply) < 0) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, scene->scene.id)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    uint32_t tempPins = scene->desc.pins;
    if (!HdfSbufWriteUint32(data, tempPins)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    int32_t ret = AudioProxyDispatchCall(AUDIO_HDI_RENDER_CHECK_SCENE_CAPABILITY, data, reply);
    if (ret < 0) {
        LOG_FUN_ERR("AudioRenderCheckSceneCapability FAIL");
        AudioProxyBufReplyRecycle(data, reply);
        return ret;
    }
    uint32_t tempSupported = 0;
    if (!HdfSbufReadUint32(reply, &tempSupported)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    *supported = (bool)tempSupported;
    AudioProxyBufReplyRecycle(data, reply);
    return HDF_SUCCESS;
}

int32_t AudioProxyRenderSelectScene(AudioHandle handle, const struct AudioSceneDescriptor *scene)
{
    if (scene == NULL) {
        return HDF_FAILURE;
    }
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessRender(handle, &data, &reply) < 0) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, scene->scene.id)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    uint32_t tempPins = scene->desc.pins;
    if (!HdfSbufWriteUint32(data, tempPins)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    int32_t ret = AudioProxyDispatchCall(AUDIO_HDI_RENDER_SELECT_SCENE, data, reply);
    AudioProxyBufReplyRecycle(data, reply);
    return ret;
}

int32_t AudioProxyRenderSetMute(AudioHandle handle, bool mute)
{
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessRender(handle, &data, &reply) < 0) {
        return HDF_FAILURE;
    }
    uint32_t tempMute = (uint32_t)mute;
    if (!HdfSbufWriteUint32(data, tempMute)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    int32_t ret = AudioProxyDispatchCall(AUDIO_HDI_RENDER_SET_MUTE, data, reply);
    AudioProxyBufReplyRecycle(data, reply);
    return ret;
}

int32_t AudioProxyRenderGetMute(AudioHandle handle, bool *mute)
{
    if (mute == NULL) {
        return HDF_FAILURE;
    }
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessRender(handle, &data, &reply) < 0) {
        return HDF_FAILURE;
    }
    int32_t ret = AudioProxyDispatchCall(AUDIO_HDI_RENDER_GET_MUTE, data, reply);
    uint32_t tempMute;
    if (!HdfSbufReadUint32(reply, &tempMute)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    *mute = (bool)tempMute;
    AudioProxyBufReplyRecycle(data, reply);
    LOG_PARA_INFO("GetMute SUCCESS!");
    return ret;
}


int32_t AudioProxyRenderSetVolume(AudioHandle handle, float volume)
{
    LOG_FUN_INFO();
    return AudioProxyCommonSetCtrlParam(AUDIO_HDI_RENDER_SET_VOLUME, handle, volume);
}

int32_t AudioProxyRenderGetVolume(AudioHandle handle, float *volume)
{
    LOG_FUN_INFO();
    return AudioProxyCommonGetCtrlParam(AUDIO_HDI_RENDER_GET_VOLUME, handle, volume);
}

int32_t AudioProxyRenderGetGainThreshold(AudioHandle handle, float *min, float *max)
{
    if (NULL == min || NULL == max) {
        return HDF_FAILURE;
    }
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessRender(handle, &data, &reply) < 0) {
        return HDF_FAILURE;
    }
    int32_t ret = AudioProxyDispatchCall(AUDIO_HDI_RENDER_GET_GAIN_THRESHOLD, data, reply);
    if (ret < 0) {
        LOG_FUN_ERR("AudioRenderGetGainThreshold FAIL");
        AudioProxyBufReplyRecycle(data, reply);
        return ret;
    }
    uint32_t tempMin;
    uint32_t tempMax;
    if (!HdfSbufReadUint32(reply, &tempMin)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(reply, &tempMax)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    *min = (float)tempMin;
    *max = (float)tempMax;
    AudioProxyBufReplyRecycle(data, reply);
    return HDF_SUCCESS;
}

int32_t AudioProxyRenderGetGain(AudioHandle handle, float *gain)
{
    return AudioProxyCommonGetCtrlParam(AUDIO_HDI_RENDER_GET_GAIN, handle, gain);
}

int32_t AudioProxyRenderSetGain(AudioHandle handle, float gain)
{
    return AudioProxyCommonSetCtrlParam(AUDIO_HDI_RENDER_SET_GAIN, handle, gain);
}

int32_t AudioProxyRenderGetLatency(struct AudioRender *render, uint32_t *ms)
{
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessRender((AudioHandle)render, &data, &reply) < 0) {
        return HDF_FAILURE;
    }
    int32_t ret = AudioProxyDispatchCall(AUDIO_HDI_RENDER_GET_LATENCY, data, reply);
    if (ret < 0) {
        LOG_FUN_ERR("AudioRenderGetLatency FAIL");
        AudioProxyBufReplyRecycle(data, reply);
        return ret;
    }
    if (!HdfSbufReadUint32(reply, ms)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    AudioProxyBufReplyRecycle(data, reply);
    return HDF_SUCCESS;
}

int32_t AudioProxyRenderRenderFrame(struct AudioRender *render, const void *frame,
                                    uint64_t requestBytes, uint64_t *replyBytes)
{
    if (frame == NULL || replyBytes == NULL) {
        LOG_FUN_ERR("Render Frame Paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessRender((AudioHandle)render, &data, &reply) < 0) {
        LOG_FUN_ERR("AudioProxyPreprocessRender FAIL");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteBuffer(data, frame, (uint32_t)requestBytes)) {
        AudioProxyBufReplyRecycle(data, reply);
        LOG_FUN_ERR("HdfSbufWriteBuffer FAIL");
        return HDF_FAILURE;
    }
    int32_t ret = AudioProxyDispatchCall(AUDIO_HDI_RENDER_RENDER_FRAME, data, reply);
    if (ret < 0) {
        if (ret != HDF_ERR_INVALID_OBJECT) {
            LOG_FUN_ERR("AudioRenderRenderFrame FAIL");
        }
        AudioProxyBufReplyRecycle(data, reply);
        return ret;
    }
    *replyBytes = requestBytes;
    AudioProxyBufReplyRecycle(data, reply);
    return HDF_SUCCESS;
}

int32_t AudioProxyRenderGetRenderPosition(struct AudioRender *render, uint64_t *frames, struct AudioTimeStamp *time)
{
    if (frames == NULL || time == NULL) {
        return HDF_FAILURE;
    }
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessRender((AudioHandle)render, &data, &reply) < 0) {
        return HDF_FAILURE;
    }
    int32_t ret = AudioProxyDispatchCall(AUDIO_HDI_RENDER_GET_RENDER_POSITION, data, reply);
    if (ret < 0) {
        LOG_FUN_ERR("AudioRenderGetRenderPosition FAIL");
        AudioProxyBufReplyRecycle(data, reply);
        return ret;
    }
    if (!HdfSbufReadUint64(reply, frames)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadInt64(reply, &time->tvSec)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadInt64(reply, &time->tvNSec)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    AudioProxyBufReplyRecycle(data, reply);
    return HDF_SUCCESS;
}

int32_t AudioProxyRenderSetRenderSpeed(struct AudioRender *render, float speed)
{
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    if (hwRender == NULL) {
        return HDF_FAILURE;
    }
    return HDF_ERR_NOT_SUPPORT;
}

int32_t AudioProxyRenderGetRenderSpeed(struct AudioRender *render, float *speed)
{
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    if (hwRender == NULL || speed == NULL) {
        return HDF_FAILURE;
    }
    return HDF_ERR_NOT_SUPPORT;
}

int32_t AudioProxyRenderSetChannelMode(struct AudioRender *render, enum AudioChannelMode mode)
{
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessRender((AudioHandle)render, &data, &reply) < 0) {
        return HDF_FAILURE;
    }
    uint32_t tempMode = (uint32_t)mode;
    if (!HdfSbufWriteUint32(data, tempMode)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    int32_t ret = AudioProxyDispatchCall(AUDIO_HDI_RENDER_SET_CHANNEL_MODE, data, reply);
    AudioProxyBufReplyRecycle(data, reply);
    return ret;
}

int32_t AudioProxyRenderGetChannelMode(struct AudioRender *render, enum AudioChannelMode *mode)
{
    if (mode == NULL || render == NULL) {
        return HDF_FAILURE;
    }
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessRender((AudioHandle)render, &data, &reply) < 0) {
        LOG_FUN_ERR("AudioProxyRenderGetChannelMode FAIL");
        return HDF_FAILURE;
    }
    int32_t ret = AudioProxyDispatchCall(AUDIO_HDI_RENDER_GET_CHANNEL_MODE, data, reply);
    if (ret < 0) {
        LOG_FUN_ERR("AudioRenderGetChannelMode FAIL");
        AudioProxyBufReplyRecycle(data, reply);
        return ret;
    }
    uint32_t tempMode = 0;
    if (!HdfSbufReadUint32(reply, &tempMode)) {
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }
    *mode = (enum AudioChannelMode)tempMode;
    AudioProxyBufReplyRecycle(data, reply);
    return HDF_SUCCESS;
}

