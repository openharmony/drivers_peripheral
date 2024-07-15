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

#ifndef OHOS_VDI_AUDIO_V1_0_IAUDIOCAPTURE_H
#define OHOS_VDI_AUDIO_V1_0_IAUDIOCAPTURE_H

#include <stdbool.h>
#include <stdint.h>
#include "audio_types_vdi.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define IAUDIO_VDI_CAPTURE_MAJOR_VERSION 1
#define IAUDIO_VDI_CAPTURE_MINOR_VERSION 0

struct IAudioCaptureVdi {
    int32_t (*CaptureFrame)(struct IAudioCaptureVdi *self, int8_t *frame, uint32_t *frameLen, uint64_t *replyBytes);
    int32_t (*CaptureFrameEc)(struct IAudioCaptureVdi *self, struct AudioCaptureFrameInfoVdi *info);
    int32_t (*GetCapturePosition)(struct IAudioCaptureVdi *self, uint64_t *frames, struct AudioTimeStampVdi *time);
    int32_t (*CheckSceneCapability)(struct IAudioCaptureVdi *self, const struct AudioSceneDescriptorVdi *scene,
        bool *supported);
    int32_t (*SelectScene)(struct IAudioCaptureVdi *self, const struct AudioSceneDescriptorVdi *scene);
    int32_t (*SetMute)(struct IAudioCaptureVdi *self, bool mute);
    int32_t (*GetMute)(struct IAudioCaptureVdi *self, bool *mute);
    int32_t (*SetVolume)(struct IAudioCaptureVdi *self, float volume);
    int32_t (*GetVolume)(struct IAudioCaptureVdi *self, float *volume);
    int32_t (*GetGainThreshold)(struct IAudioCaptureVdi *self, float *min, float *max);
    int32_t (*GetGain)(struct IAudioCaptureVdi *self, float *gain);
    int32_t (*SetGain)(struct IAudioCaptureVdi *self, float gain);
    int32_t (*GetFrameSize)(struct IAudioCaptureVdi *self, uint64_t *size);
    int32_t (*GetFrameCount)(struct IAudioCaptureVdi *self, uint64_t *count);
    int32_t (*SetSampleAttributes)(struct IAudioCaptureVdi *self, const struct AudioSampleAttributesVdi *attrs);
    int32_t (*GetSampleAttributes)(struct IAudioCaptureVdi *self, struct AudioSampleAttributesVdi *attrs);
    int32_t (*GetCurrentChannelId)(struct IAudioCaptureVdi *self, uint32_t *channelId);
    int32_t (*SetExtraParams)(struct IAudioCaptureVdi *self, const char *keyValueList);
    int32_t (*GetExtraParams)(struct IAudioCaptureVdi *self, char *keyValueList, uint32_t keyValueListLen);
    int32_t (*ReqMmapBuffer)(struct IAudioCaptureVdi *self, int32_t reqSize, struct AudioMmapBufferDescriptorVdi *desc);
    int32_t (*GetMmapPosition)(struct IAudioCaptureVdi *self, uint64_t *frames, struct AudioTimeStampVdi *time);
    int32_t (*AddAudioEffect)(struct IAudioCaptureVdi *self, uint64_t effectid);
    int32_t (*RemoveAudioEffect)(struct IAudioCaptureVdi *self, uint64_t effectid);
    int32_t (*GetFrameBufferSize)(struct IAudioCaptureVdi *self, uint64_t *bufferSize);
    int32_t (*Start)(struct IAudioCaptureVdi *self);
    int32_t (*Stop)(struct IAudioCaptureVdi *self);
    int32_t (*Pause)(struct IAudioCaptureVdi *self);
    int32_t (*Resume)(struct IAudioCaptureVdi *self);
    int32_t (*Flush)(struct IAudioCaptureVdi *self);
    int32_t (*TurnStandbyMode)(struct IAudioCaptureVdi *self);
    int32_t (*AudioDevDump)(struct IAudioCaptureVdi *self, int32_t range, int32_t fd);
    int32_t (*IsSupportsPauseAndResume)(struct IAudioCaptureVdi *self, bool *supportPause, bool *supportResume);
};

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* OHOS_VDI_AUDIO_V1_0_IAUDIOCAPTURE_H */