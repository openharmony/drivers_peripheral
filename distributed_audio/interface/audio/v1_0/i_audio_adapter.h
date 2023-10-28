/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef HDF_I_AUDIO_ADAPTER_H
#define HDF_I_AUDIO_ADAPTER_H

#include <string>
#include <vector>

#include "i_audio_capture.h"
#include "i_audio_render.h"
#include "i_audio_param_callback.h"
#include "types.h"

namespace OHOS {
namespace DistributedHardware {
using RenderHandle = uint64_t;
using CaptureHandle = uint64_t;
using RouteHandle = int32_t;

class IAudioAdapter {
public:
    virtual int32_t InitAllPorts() = 0;

    virtual int32_t CreateRender(const AudioDeviceDescriptorHAL &desc, const AudioSampleAttributesHAL &attrs,
        RenderHandle &handle, IAudioRender &render) = 0;

    virtual int32_t DestoryRender(const RenderHandle handle) = 0;

    virtual int32_t CreateCapture(const AudioDeviceDescriptorHAL &desc, const AudioSampleAttributesHAL &attrs,
        CaptureHandle &handle, IAudioCapture &capture) = 0;

    virtual int32_t DestoryCapture(const CaptureHandle handle) = 0;

    virtual int32_t GetPortCapability(const AudioPortHAL &port, AudioPortCapabilityHAL &capability) = 0;

    virtual int32_t SetPassthroughMode(const AudioPortHAL &port, const AudioPortPassthroughModeHAL mode) = 0;

    virtual int32_t GetPassthroughMode(const AudioPortHAL &port, AudioPortPassthroughModeHAL &mode) = 0;

    virtual int32_t UpdateAudioRoute(const AudioRouteHAL &route, RouteHandle &handle) = 0;

    virtual int32_t ReleaseAudioRoute(const RouteHandle handle) = 0;

    virtual int32_t SetAudioParameters(const std::vector<AudioParameter> &param) = 0;

    virtual int32_t GetAudioParameters(std::vector<AudioParameter> &param) = 0;

    virtual int32_t RegAudioParamObserver(IAudioParamCallback &cbObj) = 0;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // HDF_I_AUDIO_ADAPTER_H