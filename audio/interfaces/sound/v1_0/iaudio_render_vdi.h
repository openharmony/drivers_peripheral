/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_VDI_AUDIO_V1_0_IAUDIORENDER_H
#define OHOS_VDI_AUDIO_V1_0_IAUDIORENDER_H

#include <stdbool.h>
#include <stdint.h>
#include "audio_types_vdi.h"
#include "iaudio_callback_vdi.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define IAUDIO_VDI_RENDER_MAJOR_VERSION 1
#define IAUDIO_VDI_RENDER_MINOR_VERSION 0

struct IAudioRenderVdi {
    int32_t (*GetLatency)(struct IAudioRenderVdi *self, uint32_t *ms);
    int32_t (*RenderFrame)(struct IAudioRenderVdi *self, const int8_t *frame, uint32_t frameLen, uint64_t *replyBytes);
    int32_t (*GetRenderPosition)(struct IAudioRenderVdi *self, uint64_t *frames, struct AudioTimeStampVdi *time);
    int32_t (*SetRenderSpeed)(struct IAudioRenderVdi *self, float speed);
    int32_t (*GetRenderSpeed)(struct IAudioRenderVdi *self, float *speed);
    int32_t (*SetChannelMode)(struct IAudioRenderVdi *self, enum AudioChannelModeVdi mode);
    int32_t (*GetChannelMode)(struct IAudioRenderVdi *self, enum AudioChannelModeVdi *mode);
    int32_t (*RegCallback)(struct IAudioRenderVdi *self, RenderCallbackVdi audioCallback, void *cookie);
    int32_t (*DrainBuffer)(struct IAudioRenderVdi *self, enum AudioDrainNotifyTypeVdi *type);
    int32_t (*IsSupportsDrain)(struct IAudioRenderVdi *self, bool *support);
    int32_t (*CheckSceneCapability)(struct IAudioRenderVdi *self, const struct AudioSceneDescriptorVdi *scene,
        bool *supported);
    int32_t (*SelectScene)(struct IAudioRenderVdi *self, const struct AudioSceneDescriptorVdi *scene);
    int32_t (*SetMute)(struct IAudioRenderVdi *self, bool mute);
    int32_t (*GetMute)(struct IAudioRenderVdi *self, bool *mute);
    int32_t (*SetVolume)(struct IAudioRenderVdi *self, float volume);
    int32_t (*GetVolume)(struct IAudioRenderVdi *self, float *volume);
    int32_t (*GetGainThreshold)(struct IAudioRenderVdi *self, float *min, float *max);
    int32_t (*GetGain)(struct IAudioRenderVdi *self, float *gain);
    int32_t (*SetGain)(struct IAudioRenderVdi *self, float gain);
    int32_t (*GetFrameSize)(struct IAudioRenderVdi *self, uint64_t *size);
    int32_t (*GetFrameCount)(struct IAudioRenderVdi *self, uint64_t *count);
    int32_t (*SetSampleAttributes)(struct IAudioRenderVdi *self, const struct AudioSampleAttributesVdi *attrs);
    int32_t (*GetSampleAttributes)(struct IAudioRenderVdi *self, struct AudioSampleAttributesVdi *attrs);
    int32_t (*GetCurrentChannelId)(struct IAudioRenderVdi *self, uint32_t *channelId);
    int32_t (*SetExtraParams)(struct IAudioRenderVdi *self, const char *keyValueList);
    int32_t (*GetExtraParams)(struct IAudioRenderVdi *self, char *keyValueList, uint32_t keyValueListLen);
    int32_t (*ReqMmapBuffer)(struct IAudioRenderVdi *self, int32_t reqSize, struct AudioMmapBufferDescriptorVdi *desc);
    int32_t (*GetMmapPosition)(struct IAudioRenderVdi *self, uint64_t *frames, struct AudioTimeStampVdi *time);
    int32_t (*AddAudioEffect)(struct IAudioRenderVdi *self, uint64_t effectid);
    int32_t (*RemoveAudioEffect)(struct IAudioRenderVdi *self, uint64_t effectid);
    int32_t (*GetFrameBufferSize)(struct IAudioRenderVdi *self, uint64_t *bufferSize);
    int32_t (*Start)(struct IAudioRenderVdi *self);
    int32_t (*Stop)(struct IAudioRenderVdi *self);
    int32_t (*Pause)(struct IAudioRenderVdi *self);
    int32_t (*Resume)(struct IAudioRenderVdi *self);
    int32_t (*Flush)(struct IAudioRenderVdi *self);
    int32_t (*TurnStandbyMode)(struct IAudioRenderVdi *self);
    int32_t (*AudioDevDump)(struct IAudioRenderVdi *self, int32_t range, int32_t fd);
    int32_t (*IsSupportsPauseAndResume)(struct IAudioRenderVdi *self, bool *supportPause, bool *supportResume);
    int32_t (*SetBufferSize)(struct IAudioRenderVdi *self, uint32_t size);
};

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* OHOS_VDI_AUDIO_V1_0_IAUDIORENDER_H */