/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <hdf_log.h>
#include "audio_internal.h"
#include "audio_adapter_info_common.h"
#include "audio_bluetooth_manager.h"
#include "audio_render.h"

namespace OHOS::HDI::Audio_Bluetooth {

int32_t HearingAidStart(AudioHandle handle)
{
    HDF_LOGI("%{public}s enter", __func__);
#ifdef A2DP_HDI_SERVICE
    auto *hwRender = reinterpret_cast<struct AudioHwRender *>(handle);
    if (hwRender == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (hwRender->renderParam.frameRenderMode.buffer != nullptr) {
        HDF_LOGE("AudioRender already start!");
        return AUDIO_HAL_ERR_AO_BUSY; // render is busy now
    }
    if (OHOS::Bluetooth::StartHearingAid() != HDF_SUCCESS) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    char *buffer = static_cast<char *>(calloc(1, FRAME_DATA));
    if (buffer == nullptr) {
        HDF_LOGE("Calloc Render buffer Fail!");
        return AUDIO_HAL_ERR_MALLOC_FAIL;
    }
    hwRender->renderParam.frameRenderMode.buffer = buffer;
    return AUDIO_HAL_SUCCESS;
#endif
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidStop(AudioHandle handle)
{
    HDF_LOGI("%{public}s enter", __func__);
#ifdef A2DP_HDI_SERVICE
    auto *hwRender = reinterpret_cast<struct AudioHwRender *>(handle);
    if (hwRender == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (hwRender->renderParam.frameRenderMode.buffer != nullptr) {
        AudioMemFree(reinterpret_cast<void **>(&hwRender->renderParam.frameRenderMode.buffer));
    } else {
        HDF_LOGE("Repeat invalid stop operation!");
        return AUDIO_HAL_ERR_NOT_SUPPORT;
    }
    OHOS::Bluetooth::StopHearingAid();
    hwRender->renderParam.renderMode.ctlParam.pause = false;
    return AUDIO_HAL_SUCCESS;
#endif
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidPause(AudioHandle handle)
{
    HDF_LOGI("%{public}s enter", __func__);
#ifdef A2DP_HDI_SERVICE
    auto *hwRender = reinterpret_cast<struct AudioHwRender *>(handle);
    if (hwRender == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (hwRender->renderParam.frameRenderMode.buffer == nullptr) {
        HDF_LOGE("AudioRender already stop!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (hwRender->renderParam.renderMode.ctlParam.pause) {
        HDF_LOGE("Audio is already pause!");
        return AUDIO_HAL_ERR_NOT_SUPPORT;
    }
    OHOS::Bluetooth::StopHearingAid();
    hwRender->renderParam.renderMode.ctlParam.pause = true;
    return AUDIO_HAL_SUCCESS;
#endif
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidResume(AudioHandle handle)
{
    HDF_LOGI("%{public}s enter", __func__);
#ifdef A2DP_HDI_SERVICE
    auto *hwRender = reinterpret_cast<struct AudioHwRender *>(handle);
    if (hwRender == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (!hwRender->renderParam.renderMode.ctlParam.pause) {
        HDF_LOGE("Audio is already Resume!");
        return AUDIO_HAL_ERR_NOT_SUPPORT;
    }
    OHOS::Bluetooth::StartHearingAid();
    hwRender->renderParam.renderMode.ctlParam.pause = false;
    return AUDIO_HAL_SUCCESS;
#endif
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidFlush(AudioHandle handle)
{
    HDF_LOGI("%{public}s enter", __func__);
    auto *hwRender = reinterpret_cast<struct AudioHwRender *>(handle);
    if (hwRender == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidGetFrameSize(AudioHandle handle, uint64_t *size)
{
    (void)handle;
    (void)size;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidGetFrameCount(AudioHandle handle, uint64_t *count)
{
    (void)handle;
    (void)count;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidSetSampleAttributes(AudioHandle handle, const struct AudioSampleAttributes *attrs)
{
    (void)handle;
    (void)attrs;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidGetSampleAttributes(AudioHandle handle, struct AudioSampleAttributes *attrs)
{
    (void)handle;
    (void)attrs;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidGetCurrentChannelId(AudioHandle handle, uint32_t *channelId)
{
    (void)handle;
    (void)channelId;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidCheckSceneCapability(AudioHandle handle, const struct AudioSceneDescriptor *scene, bool *supported)
{
    (void)handle;
    (void)scene;
    (void)supported;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidSelectScene(AudioHandle handle, const struct AudioSceneDescriptor *scene)
{
    (void)handle;
    (void)scene;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidSetMute(AudioHandle handle, bool mute)
{
    (void)handle;
    (void)mute;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidGetMute(AudioHandle handle, bool *mute)
{
    (void)handle;
    (void)mute;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidSetVolume(AudioHandle handle, float volume)
{
    (void)handle;
    (void)volume;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidGetVolume(AudioHandle handle, float *volume)
{
    (void)handle;
    (void)volume;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidGetGainThreshold(AudioHandle handle, float *min, float *max)
{
    (void)handle;
    (void)min;
    (void)max;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidGetGain(AudioHandle handle, float *gain)
{
    (void)handle;
    (void)gain;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidSetGain(AudioHandle handle, float gain)
{
    (void)handle;
    (void)gain;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidGetLatency(struct AudioRender *render, uint32_t *ms)
{
    (void)render;
    (void)ms;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidRenderFrame(struct AudioRender *render, const void *frame,
    uint64_t requestBytes, uint64_t *replyBytes)
{
    HDF_LOGI("%{public}s enter", __func__);
    auto *hwRender = reinterpret_cast<struct AudioHwRender *>(render);
    if (hwRender == nullptr || frame == nullptr || replyBytes == nullptr ||
        hwRender->renderParam.frameRenderMode.buffer == nullptr) {
        HDF_LOGE("Hearing aid Frame Paras is nullptr!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (FRAME_DATA < requestBytes) {
        HDF_LOGE("Out of FRAME_DATA size!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    int32_t ret = memcpy_s(hwRender->renderParam.frameRenderMode.buffer, FRAME_DATA, frame, (uint32_t)requestBytes);
    if (ret != EOK) {
        HDF_LOGE("memcpy_s fail");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    hwRender->renderParam.frameRenderMode.bufferSize = requestBytes;
    uint32_t frameCount = 0;
    ret = PcmBytesToFrames(&hwRender->renderParam.frameRenderMode, requestBytes, &frameCount);
    if (ret != AUDIO_HAL_SUCCESS) {
        return ret;
    }
    *replyBytes = requestBytes;
    hwRender->renderParam.frameRenderMode.frames += hwRender->renderParam.frameRenderMode.bufferFrameSize;
    if (hwRender->renderParam.frameRenderMode.attrs.sampleRate == 0) {
        HDF_LOGE("Divisor cannot be zero!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (TimeToAudioTimeStamp(hwRender->renderParam.frameRenderMode.bufferFrameSize,
        &hwRender->renderParam.frameRenderMode.time,
        hwRender->renderParam.frameRenderMode.attrs.sampleRate) == HDF_FAILURE) {
        HDF_LOGE("Frame is nullptr");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    LOGV("%s, WriteFrame", __func__);
    const uint8_t *data = reinterpret_cast<const uint8_t *>(frame);
    AudioSampleAttributes *attrs = &hwRender->renderParam.frameRenderMode.attrs;
    return OHOS::Bluetooth::WriteFrameHearingAid(data, static_cast<uint32_t>(requestBytes), attrs);
}

int32_t HearingAidGetRenderPosition(struct AudioRender *render, uint64_t *frames, struct AudioTimeStamp *time)
{
    (void)render;
    (void)frames;
    (void)time;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidSetRenderSpeed(struct AudioRender *render, float speed)
{
    (void)render;
    (void)speed;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidGetRenderSpeed(struct AudioRender *render, float *speed)
{
    (void)render;
    (void)speed;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidSetChannelMode(struct AudioRender *render, AudioChannelMode mode)
{
    (void)render;
    (void)mode;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidGetChannelMode(struct AudioRender *render, AudioChannelMode *mode)
{
    (void)render;
    (void)mode;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidSetExtraParams(AudioHandle handle, const char *keyValueList)
{
    (void)handle;
    (void)keyValueList;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidGetExtraParams(AudioHandle handle, char *keyValueList, int32_t listLength)
{
    (void)handle;
    (void)keyValueList;
    (void)listLength;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidReqMmapBuffer(AudioHandle handle, int32_t reqSize, struct AudioMmapBufferDescriptor *desc)
{
    (void)handle;
    (void)reqSize;
    (void)desc;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidGetMmapPosition(AudioHandle handle, uint64_t *frames, struct AudioTimeStamp *time)
{
    (void)handle;
    (void)frames;
    (void)time;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidTurnStandbyMode(AudioHandle handle)
{
    (void)handle;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidAudioDevDump(AudioHandle handle, int32_t range, int32_t fd)
{
    (void)handle;
    (void)range;
    (void)fd;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidRegCallback(struct AudioRender *render, RenderCallback callback, void *cookie)
{
    (void)render;
    (void)callback;
    (void)cookie;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t HearingAidDrainBuffer(struct AudioRender *render, AudioDrainNotifyType *type)
{
    (void)render;
    (void)type;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}
} // namespace OHOS::HDI::Audio_Bluetooth