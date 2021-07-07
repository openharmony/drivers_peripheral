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

#ifndef AUDIO_PROXY_INTERNAL_H
#define AUDIO_PROXY_INTERNAL_H

#include "audio_render.h"
#include "audio_capture.h"
#include "audio_adapter.h"
#include "audio_types.h"
#include "audio_control.h"
#include "audio_attribute.h"
#include "audio_scene.h"
#include "audio_volume.h"


int32_t AudioProxyAdapterInitAllPorts(struct AudioAdapter *adapter);
int32_t AudioProxyAdapterCreateRender(struct AudioAdapter *adapter,
    const struct AudioDeviceDescriptor *desc,
    const struct AudioSampleAttributes *attrs,
    struct AudioRender **render);
int32_t AudioProxyAdapterDestroyRender(struct AudioAdapter *adapter,
    struct AudioRender *render);
int32_t AudioProxyAdapterCreateCapture(struct AudioAdapter *adapter,
    const struct AudioDeviceDescriptor *desc,
    const struct AudioSampleAttributes *attrs,
    struct AudioCapture **capture);
int32_t AudioProxyAdapterDestroyCapture(struct AudioAdapter *adapter,
    struct AudioCapture *capture);
int32_t AudioProxyAdapterGetPortCapability(struct AudioAdapter *adapter,
    const struct AudioPort *port, struct AudioPortCapability *capability);
int32_t AudioProxyAdapterSetPassthroughMode(struct AudioAdapter *adapter,
    const struct AudioPort *port, enum AudioPortPassthroughMode mode);
int32_t AudioProxyAdapterGetPassthroughMode(struct AudioAdapter *adapter,
    const struct AudioPort *port, enum AudioPortPassthroughMode *mode);
int32_t AudioProxyRenderStart(AudioHandle handle);
int32_t AudioProxyRenderStop(AudioHandle handle);
int32_t AudioProxyRenderPause(AudioHandle handle);
int32_t AudioProxyRenderResume(AudioHandle handle);
int32_t AudioProxyRenderFlush(AudioHandle handle);
int32_t AudioProxyRenderGetFrameSize(AudioHandle handle, uint64_t *size);
int32_t AudioProxyRenderGetFrameCount(AudioHandle handle, uint64_t *count);
int32_t AudioProxyRenderSetSampleAttributes(AudioHandle handle,
    const struct AudioSampleAttributes *attrs);
int32_t AudioProxyRenderGetSampleAttributes(AudioHandle handle,
    struct AudioSampleAttributes *attrs);
int32_t AudioProxyRenderGetCurrentChannelId(AudioHandle handle, uint32_t *channelId);
int32_t AudioProxyRenderCheckSceneCapability(AudioHandle handle,
    const struct AudioSceneDescriptor *scene, bool *supported);
int32_t AudioProxyRenderSelectScene(AudioHandle handle,
    const struct AudioSceneDescriptor *scene);
int32_t AudioProxyRenderSetMute(AudioHandle handle, bool mute);
int32_t AudioProxyRenderGetMute(AudioHandle handle, bool *mute);
int32_t AudioProxyRenderSetVolume(AudioHandle handle, float volume);
int32_t AudioProxyRenderGetVolume(AudioHandle handle, float *volume);
int32_t AudioProxyRenderGetGainThreshold(AudioHandle handle, float *min, float *max);
int32_t AudioProxyRenderGetGain(AudioHandle handle, float *gain);
int32_t AudioProxyRenderSetGain(AudioHandle handle, float gain);
int32_t AudioProxyRenderGetLatency(struct AudioRender *render, uint32_t *ms);
int32_t AudioProxyRenderRenderFrame(struct AudioRender *render, const void *frame,
    uint64_t requestBytes, uint64_t *replyBytes);
int32_t AudioProxyRenderGetRenderPosition(struct AudioRender *render,
    uint64_t *frames, struct AudioTimeStamp *time);
int32_t AudioProxyRenderSetRenderSpeed(struct AudioRender *render, float speed);
int32_t AudioProxyRenderGetRenderSpeed(struct AudioRender *render, float *speed);
int32_t AudioProxyRenderSetChannelMode(struct AudioRender *render, enum AudioChannelMode mode);
int32_t AudioProxyRenderGetChannelMode(struct AudioRender *render, enum AudioChannelMode *mode);
int32_t AudioProxyCaptureStart(AudioHandle handle);
int32_t AudioProxyCaptureStop(AudioHandle handle);
int32_t AudioProxyCapturePause(AudioHandle handle);
int32_t AudioProxyCaptureResume(AudioHandle handle);
int32_t AudioProxyCaptureFlush(AudioHandle handle);
int32_t AudioProxyCaptureGetFrameSize(AudioHandle handle, uint64_t *size);
int32_t AudioProxyCaptureGetFrameCount(AudioHandle handle, uint64_t *count);
int32_t AudioProxyCaptureSetSampleAttributes(AudioHandle handle,
    const struct AudioSampleAttributes *attrs);
int32_t AudioProxyCaptureGetSampleAttributes(AudioHandle handle,
    struct AudioSampleAttributes *attrs);
int32_t AudioProxyCaptureGetCurrentChannelId(AudioHandle handle, uint32_t *channelId);
int32_t AudioProxyCaptureCheckSceneCapability(AudioHandle handle,
    const struct AudioSceneDescriptor *scene, bool *supported);
int32_t AudioProxyCaptureSelectScene(AudioHandle handle,
    const struct AudioSceneDescriptor *scene);
int32_t AudioProxyCaptureSetMute(AudioHandle handle, bool mute);
int32_t AudioProxyCaptureGetMute(AudioHandle handle, bool *mute);
int32_t AudioProxyCaptureSetVolume(AudioHandle handle, float volume);
int32_t AudioProxyCaptureGetVolume(AudioHandle handle, float *volume);
int32_t AudioProxyCaptureGetGainThreshold(AudioHandle handle, float *min, float *max);
int32_t AudioProxyCaptureGetGain(AudioHandle handle, float *gain);
int32_t AudioProxyCaptureSetGain(AudioHandle handle, float gain);
int32_t AudioProxyCaptureCaptureFrame(struct AudioCapture *capture,
    void *frame, uint64_t requestBytes, uint64_t *replyBytes);
int32_t AudioProxyCaptureGetCapturePosition(struct AudioCapture *capture,
    uint64_t *frames, struct AudioTimeStamp *time);

#endif
