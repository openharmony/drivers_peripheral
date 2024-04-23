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

#ifndef FAST_AUDIO_RENDER_H
#define FAST_AUDIO_RENDER_H

#include "audio_common.h"
#include "audio_manager.h"
#include "hdf_base.h"

namespace OHOS::HDI::Audio_Bluetooth {
int32_t FastRenderStart(AudioHandle handle);
int32_t FastRenderStop(AudioHandle handle);
int32_t FastRenderPause(AudioHandle handle);
int32_t FastRenderResume(AudioHandle handle);
int32_t FastRenderFlush(AudioHandle handle);
int32_t FastRenderGetFrameSize(AudioHandle handle, uint64_t *size);
int32_t FastRenderGetFrameCount(AudioHandle handle, uint64_t *count);
int32_t FastRenderSetSampleAttributes(AudioHandle handle, const struct AudioSampleAttributes *attrs);
int32_t FastRenderGetSampleAttributes(AudioHandle handle, struct AudioSampleAttributes *attrs);
int32_t FastRenderGetCurrentChannelId(AudioHandle handle, uint32_t *channelId);
int32_t FastRenderCheckSceneCapability(AudioHandle handle, const struct AudioSceneDescriptor *scene, bool *supported);
int32_t FastRenderSelectScene(AudioHandle handle, const struct AudioSceneDescriptor *scene);
int32_t FastRenderSetMute(AudioHandle handle, bool mute);
int32_t FastRenderGetMute(AudioHandle handle, bool *mute);
int32_t FastRenderSetVolume(AudioHandle handle, float volume);
int32_t FastRenderGetVolume(AudioHandle handle, float *volume);
int32_t FastRenderGetGainThreshold(AudioHandle handle, float *min, float *max);
int32_t FastRenderGetGain(AudioHandle handle, float *gain);
int32_t FastRenderSetGain(AudioHandle handle, float gain);
int32_t FastRenderGetLatency(struct AudioRender *render, uint32_t *ms);
int32_t FastRenderRenderFrame(
    struct AudioRender *render, const void *frame, uint64_t requestBytes, uint64_t *replyBytes);
int32_t FastRenderGetRenderPosition(struct AudioRender *render, uint64_t *frames, struct AudioTimeStamp *time);
int32_t FastRenderSetRenderSpeed(struct AudioRender *render, float speed);
int32_t FastRenderGetRenderSpeed(struct AudioRender *render, float *speed);
int32_t FastRenderSetChannelMode(struct AudioRender *render, AudioChannelMode mode);
int32_t FastRenderGetChannelMode(struct AudioRender *render, AudioChannelMode *mode);
int32_t FastRenderSetExtraParams(AudioHandle handle, const char *keyValueList);
int32_t FastRenderGetExtraParams(AudioHandle handle, char *keyValueList, int32_t listLength);
int32_t FastRenderReqMmapBuffer(AudioHandle handle, int32_t reqSize, struct AudioMmapBufferDescriptor *desc);
int32_t FastRenderGetMmapPosition(AudioHandle handle, uint64_t *frames, struct AudioTimeStamp *time);
int32_t FastRenderTurnStandbyMode(AudioHandle handle);
int32_t FastRenderAudioDevDump(AudioHandle handle, int32_t range, int32_t fd);
int32_t FastRenderRegCallback(struct AudioRender *render, RenderCallback callback, void *cookie);
int32_t FastRenderDrainBuffer(struct AudioRender *render, AudioDrainNotifyType *type);
} // namespace OHOS::HDI::Audio_Bluetooth

#endif