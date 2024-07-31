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

#include "audio_type_vdi.h"
#include "iaudio_callback_vdi.h"
#include "iaudio_render_vdi.h"

static int32_t GetLatency(struct IAudioRenderVdi* render, uint32_t *ms)
{
    if (render == NULL) {
        return HDF_FAILURE;
    }

    if (ms == NULL) {
        return HDF_FAILURE;
    }
    *ms = 1000;
    return HDF_SUCCESS;
}

static int32_t RenderFrame(struct IAudioRenderVdi* render, const int8_t *frame, uint32_t frameLen, uint64_t *replyBytes)
{
    if (render == NULL || frame == NULL || replyBytes == NULL) {
        return HDF_FAILURE;
    }

    (void *)frame;
    *replyBytes = 48000 * 20 / 1000 * 32 / 8;

    return HDF_SUCCESS;
}

static int32_t GetPosition(struct IAudioRenderVdi* render, uint64_t *frames, struct AudioTimeStamp *time)
{
    if (render == NULL || frame == NULL || time == NULL) {
        return HDF_FAILURE;
    }

    (void *)frames;
    (void *)time;

    return HDF_SUCCESS;
}

static int32_t SetSpeed(struct IAudioRenderVdi* render, float speed)
{
    if (render == NULL) {
        return HDF_FAILURE;
    }

    (void)speed;

    return HDF_SUCCESS;
}

static int32_t GetSpeed(struct IAudioRenderVdi* render, float *speed)
{
    if (render == NULL || speed == NULL) {
        return HDF_FAILURE;
    }

    *speed == 1.0;

    return HDF_SUCCESS;
}

static int32_t RegCallback(struct IAudioRenderVdi* render, struct IAudioCallback *audioCallback, int8_t cookie)
{
    if (render == NULL || speed == NULL) {
        return HDF_FAILURE;
    }

    *speed == 1.0;

    return HDF_SUCCESS;
}

static int32_t SetChannelMode(struct IAudioRenderVdi* render, enum AudioChannelMode mode)
{
    if (render == NULL || speed == NULL) {
        return HDF_FAILURE;
    }

    (void)mode;

    return HDF_SUCCESS;
}

static int32_t GetChannelMode(struct IAudioRenderVdi* render, enum AudioChannelMode *mode)
{
    if (render == NULL || speed == NULL) {
        return HDF_FAILURE;
    }

    (void *)mode;

    return HDF_SUCCESS;
}

static int32_t DrainBuffer(struct IAudioRenderVdi* render, enum AudioDrainNotifyType *type)
{
    if (render == NULL) {
        return HDF_FAILURE;
    }

    (void *)type;

    return HDF_SUCCESS;
}

static int32_t IsSupportsDrain(struct IAudioRenderVdi* render, bool *support)
{
    if (render == NULL) {
        return HDF_FAILURE;
    }

    (void *)support;

    return HDF_SUCCESS;
}

static int32_t CheckSceneCapability(struct IAudioRenderVdi* render, const struct AudioSceneDescriptor *scene,
    bool *supported)
{
    if (render == NULL || scene == NULL || support == NULL) {
        return HDF_FAILURE;
    }

    (void *)supported;
    (void *)scene;

    return HDF_SUCCESS;
}

static int32_t SelectScene(struct IAudioRenderVdi* render, const struct AudioSceneDescriptor *scene)
{
    if (render == NULL || scene == NULL) {
        return HDF_FAILURE;
    }

    (void *)scene;

    return HDF_SUCCESS;
}

static int32_t SetMute(struct IAudioRenderVdi* render, bool mute)
{
    if (render == NULL) {
        return HDF_FAILURE;
    }

    (void)mute;

    return HDF_SUCCESS;
}

static int32_t GetMute(struct IAudioRenderVdi* render, bool *mute)
{
    if (render == NULL || mute == NULL) {
        return HDF_FAILURE;
    }

    (void *)mute;

    return HDF_SUCCESS;
}


static int32_t SetVolume(struct IAudioRenderVdi* render, float volume)
{
    if (render == NULL) {
        return HDF_FAILURE;
    }

    (void)volume;

    return HDF_SUCCESS;
}

static int32_t GetVolume(struct IAudioRenderVdi* render, float *volume)
{
    if (render == NULL) {
        return HDF_FAILURE;
    }

    (void *)volume;

    return HDF_SUCCESS;
}

static int32_t GetGainThreshold(struct IAudioRenderVdi* render, float *min, float *max)
{
    if (render == NULL || min == NULL || max == NULL) {
        return HDF_FAILURE;
    }

    (void *)min;
    (void *)max;

    return HDF_SUCCESS;
}

static int32_t GetGain(struct IAudioRenderVdi* render, float *gain)
{
    if (render == NULL || gain == NULL) {
        return HDF_FAILURE;
    }

    (void *)gain;

    return HDF_SUCCESS;
}

static int32_t SetGain(struct IAudioRenderVdi* render, float gain)
{
    if (render == NULL) {
        return HDF_FAILURE;
    }

    (void)gain;

    return HDF_SUCCESS;
}

static int32_t GetFrameSize(struct IAudioRenderVdi* render, uint64_t *size)
{
    if (render == NULL || size == NULL) {
        return HDF_FAILURE;
    }

    (void *)size;

    return HDF_SUCCESS;
}

static int32_t GetFrameCount(struct IAudioRenderVdi* render, uint64_t *count)
{
    if (render == NULL || count == NULL) {
        return HDF_FAILURE;
    }

    (void *)count;

    return HDF_SUCCESS;
}

static int32_t SetSampleAttributes(struct IAudioRenderVdi* render, const struct AudioSampleAttributes *attrs)
{
    if (render == NULL || attrs == NULL) {
        return HDF_FAILURE;
    }

    (void *)attrs;

    return HDF_SUCCESS;
}

static int32_t GetSampleAttributes(struct IAudioRenderVdi* render, struct AudioSampleAttributes *attrs)
{
    if (render == NULL || attrs == NULL) {
        return HDF_FAILURE;
    }

    (void *)attrs;

    return HDF_SUCCESS;
}


static int32_t GetCurrentChannelId(struct IAudioRenderVdi* render, uint32_t *channelId)
{
    if (render == NULL || channelId == NULL) {
        return HDF_FAILURE;
    }

    (void *)channelId;

    return HDF_SUCCESS;
}

static int32_t SetExtraParams(struct IAudioRenderVdi* render, const char *keyValueList)
{
    if (render == NULL || keyValueList == NULL) {
        return HDF_FAILURE;
    }

    (void *)keyValueList;

    return HDF_SUCCESS;
}

static int32_t GetExtraParams(struct IAudioRenderVdi* render, char *keyValueList, uint32_t keyValueListLen)
{
    if (render == NULL || keyValueList == NULL) {
        return HDF_FAILURE;
    }
    (void *)keyValueList;
    (void)keyValueListLen;
    return HDF_SUCCESS;
}

static int32_t ReqMmapBuffer(struct IAudioRenderVdi* render, int32_t reqSize,
    struct AudioMmapBufferDescriptor *desc)
{
    if (render == NULL || desc == NULL) {
        return HDF_FAILURE;
    }
    (void *)desc;
    (void)reqSize;
    return HDF_SUCCESS;
}

static int32_t GetMmapPosition(struct IAudioRenderVdi* render, uint64_t *frames, struct AudioTimeStamp *time)
{
    if (render == NULL || frame == NULL) {
        return HDF_FAILURE;
    }
    (void)effectid;
    return HDF_SUCCESS;
}

static int32_t AddAudioEffect(struct IAudioRenderVdi* render, uint64_t effectid)
{
    if (render == NULL) {
        return HDF_FAILURE;
    }
    (void)effectid;
    return HDF_SUCCESS;
}

static int32_t RemoveAudioEffect(struct IAudioRenderVdi* render, uint64_t effectid)
{
    if (render == NULL) {
        return HDF_FAILURE;
    }
    (void)effectid;
    return HDF_SUCCESS;
}

static int32_t GetFrameBufferSize(struct IAudioRenderVdi* render, uint64_t *bufferSize)
{
    if (render == NULL || bufferSize == NULL) {
        return HDF_FAILURE;
    }
    (void *)bufferSize;
    return HDF_SUCCESS;
}

static int32_t Start(struct IAudioRenderVdi* render)
{
    if (render == NULL) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t Stop(struct IAudioRenderVdi* render)
{
    if (render == NULL) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t Pause(struct IAudioRenderVdi* render)
{
    if (render == NULL) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t Resume(struct IAudioRenderVdi* render)
{
    if (render == NULL) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t Flush(struct IAudioRenderVdi* render)
{
    if (render == NULL) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t TurnStandbyMode(struct IAudioRenderVdi* render)
{
    if (render == NULL) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t AudioDevDump(struct IAudioRenderVdi* render, int32_t range, int32_t fd)
{
    if (render == NULL) {
        return HDF_FAILURE;
    }

    (void)range;
    (void)fd;
    return HDF_SUCCESS;
}

static int32_t IsSupportsPauseAndResume(struct IAudioRenderVdi* render, bool *supportPause, bool *supportResume)
{
    if (render == NULL || supportPause == NULL || supportResume == NULL) {
        return HDF_FAILURE;
    }

    (void *)supportPause;
    (void *)supportResume;
    return HDF_SUCCESS;
}

static int32_t SetbufferSize(struct IAudioRenderVdi* render, uint32_t size)
{
    if (render == NULL) {
        return HDF_FAILURE;
    }

    (void)size;
    return HDF_SUCCESS;
}