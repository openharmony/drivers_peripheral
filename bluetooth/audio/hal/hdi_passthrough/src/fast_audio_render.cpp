/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "fast_audio_render.h"
#include "audio_adapter_info_common.h"
#include "audio_bluetooth_manager.h"
#include "audio_internal.h"
#include "hdf_log.h"
#include <string>

namespace OHOS::HDI::Audio_Bluetooth {
#ifdef A2DP_HDI_SERVICE
const uint32_t MIN_TIME_INTERVAL = 30;
const uint32_t MAX_TIME_INTERVAL = 80;
const int32_t MAX_ASHMEM_LEN = 100000;
const int32_t MIN_ASHMEM_LEN = 10;
const int32_t RENDER_TIME_INTERVAL = 5;
const int32_t PER_MS_SECOND = 1000;

static int32_t CalculateSampleNum(uint32_t sampleRate, uint32_t timeMs)
{
    return (sampleRate * timeMs) / PER_MS_SECOND;
}
#endif

int32_t FastRenderStart(AudioHandle handle)
{
    HDF_LOGI("%{public}s enter", __func__);
#ifdef A2DP_HDI_SERVICE
    AudioHwRender *hwRender = reinterpret_cast<struct AudioHwRender>(handle);
    if (hwRender == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    AudioSampleAttributes *attr = &hwRender->RenderParam.frameRenderMode.attrs;
    uint32_t format = static_cast<uint32_t>(attrs->format);
    return OHOS::Bluetooth::FastStartPlaying(attrs->sampleRate, attrs->channelCount, format);
#endif
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderStop(AudioHandle handle)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)handle;
#ifdef A2DP_HDI_SERVICE
    return OHOS::Bluetooth::FastStopPlaying();
#endif
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderPause(AudioHandle handle)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)handle;
#ifdef A2DP_HDI_SERVICE
    return OHOS::Bluetooth::FastSuspendPlaying();
#endif
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderResume(AudioHandle handle)
{
    HDF_LOGI("%{public}s enter", __func__);
#ifdef A2DP_HDI_SERVICE
    AudioHwRender *hwRender = reinterpret_cast<struct AudioHwRender>(handle);
    if (hwRender == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    AudioSampleAttributes *attr = &hwRender->RenderParam.frameRenderMode.attrs;
    uint32_t format = static_cast<uint32_t>(attrs->format);
    return OHOS::Bluetooth::FastStartPlaying(attrs->sampleRate, attrs->channelCount, format);
#endif
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderFlush(AudioHandle handle)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)handle;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderGetFrameSize(AudioHandle handle, uint64_t *size)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)handle;
    (void)size;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderGetFrameCount(AudioHandle handle, uint64_t *count)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)handle;
    (void)count;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderSetSampleAttributes(AudioHandle handle, const struct AudioSampleAttributes *attrs)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)handle;
    (void)attrs;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderGetSampleAttributes(AudioHandle handle, struct AudioSampleAttributes *attrs)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)handle;
    (void)attrs;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderGetCurrentChannelId(AudioHandle handle, uint32_t *channelId)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)handle;
    (void)channelId;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderCheckSceneCapability(AudioHandle handle, const struct AudioSceneDescriptor *scene, bool *supported)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)handle;
    (void)scene;
    (void)supported;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderSelectScene(AudioHandle handle, const struct AudioSceneDescriptor *scene)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)handle;
    (void)scene;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderSetMute(AudioHandle handle, bool mute)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)handle;
    (void)mute;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderGetMute(AudioHandle handle, bool *mute)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)handle;
    (void)mute;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderSetVolume(AudioHandle handle, float volume)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)handle;
    (void)volume;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderGetVolume(AudioHandle handle, float *volume)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)handle;
    (void)volume;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderGetGainThreshold(AudioHandle handle, float *min, float *max)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)handle;
    (void)min;
    (void)max;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderGetGain(AudioHandle handle, float *gain)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)handle;
    (void)gain;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderSetGain(AudioHandle handle, float gain)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)handle;
    (void)gain;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderGetLatency(struct AudioRender *render, uint32_t *ms)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)render;
    (void)ms;
#ifdef A2DP_HDI_SERVICE
    uint32_t latency = 0;
    OHOS::Bluetooth::FastGetLatency(latency);
    *ms = latency;
    return AUDIO_HAL_SUCCESS;
#endif
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderRenderFrame(
    struct AudioRender *render, const void *frame, uint64_t requestBytes, uint64_t *replyBytes)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)render;
    (void)frame;
    (void)requestBytes;
    (void)replyBytes;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderGetRenderPosition(struct AudioRender *render, uint64_t *frames, struct AudioTimeStamp *time)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)render;
    (void)frames;
    (void)time;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderSetRenderSpeed(struct AudioRender *render, float speed)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)render;
    (void)speed;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderGetRenderSpeed(struct AudioRender *render, float *speed)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)render;
    (void)speed;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderSetChannelMode(struct AudioRender *render, AudioChannelMode mode)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)render;
    (void)mode;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderGetChannelMode(struct AudioRender *render, AudioChannelMode *mode)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)render;
    (void)mode;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderSetExtraParams(AudioHandle handle, const char *keyValueList)
{
    HDF_LOGI("%{public}s enter", __func__);
    struct AudioHwRender *render = reinterpret_cast<struct AudioHwRender *>(handle);
    if (render == nullptr || keyValueList == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t count = 0;
    int32_t sumOk = 0;
    struct ExtraParams mExtraParams;
    if (AudioSetExtraParams(keyValueList, &count, &mExtraParams, &sumOk) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (count != 0 && sumOk == count) {
#ifdef A2DP_HDI_SERVICE
        if (mExtraParams.audioStreamCtl == 1) {
            HDF_LOGI("SetValue, try to fastSuspendPlaying");
            OHOS::Bluetooth::FastSuspendPlaying();
        }
#endif
        return AUDIO_HAL_SUCCESS;
    } else {
        return AUDIO_HAL_ERR_INTERNAL;
    }
}

int32_t FastRenderGetExtraParams(AudioHandle handle, char *keyValueList, int32_t listLength)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)handle;
    (void)keyValueList;
    (void)listLength;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderReqMmapBuffer(AudioHandle handle, int32_t reqSize, struct AudioMmapBufferDescriptor *desc)
{
    HDF_LOGI("%{public}s enter", __func__);
#ifdef A2DP_HDI_SERVICE
    AudioHwRender *render = reinterpret_cast<AudioHwRender *>(handle);
    if (render == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    AudioSampleAttributes attr = render->renderParam.frameRenderMode.attrs;

    int32_t minSize = CalculateSampleNum(attr.sampleRate, MIN_TIME_INTERVAL);
    int32_t maxSize = CalculateSampleNum(attr.sampleRate, MAX_TIME_INTERVAL);
    int32_t realSize = reqSize;
    if (reqSize < minSize) {
        realSize = minSize;
    } else if (reqSize > maxSize) {
        realSize = maxSize;
    }
    int32_t ashmemLength = realSize * static_cast<int32_t>(attr.channelCount) * attr.format;
    if (ashmemLength < MIN_ASHMEM_LEN || ashmemLength > MAX_ASHMEM_LEN) {
        HDF_LOGE("reqMmapBuffer failed, length is illegal %{public}d", ashmemLength);
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t fd = OHOS::Bluetooth::FastReqMmapBuffer(ashmemLength);
    if (fd < 0) {
        HDF_LOGE("reqMmapBuffer failed");
        return HDF_FAILURE;
    }
    desc->memoryFd = fd;
    desc->transferFrameSize = static_cast<int32_t>(CalculateSampleNum(attr.sampleRate, RENDER_TIME_INTERVAL));
    desc->totalBufferFrames = realSize;
    desc->isShareable = false;
    HDF_LOGI("%{public}s, fd=%{public}d, length=%{public}d, transferFrameSize=%{public}d, totalBufferFrames=%{public}d",
        __func__, desc->memoryFd, desc->transferFrameSize, desc->totalBufferFrames);
#endif
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderGetMmapPosition(AudioHandle handle, uint64_t *frames, struct AudioTimeStamp *time)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)handle;
#ifdef A2DP_HDI_SERVICE
    int64_t sec = 0;
    int64_t nSec = 0;
    uint64_t readFrames = 0;
    OHOS::Bluetooth::FastReadMmapPosition(sec, nSec, readFrames);
    *frames = readFrames;
    time->tvSec = sec;
    time->tvNSec = nSec;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
#endif
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderTurnStandbyMode(AudioHandle handle)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)handle;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderAudioDevDump(AudioHandle handle, int32_t range, int32_t fd)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)handle;
    (void)range;
    (void)fd;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderRegCallback(struct AudioRender *render, RenderCallback callback, void *cookie)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)render;
    (void)callback;
    (void)cookie;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t FastRenderDrainBuffer(struct AudioRender *render, AudioDrainNotifyType *type)
{
    HDF_LOGI("%{public}s enter", __func__);
    (void)render;
    (void)type;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}
} // namespace OHOS::HDI::Audio_Bluetooth