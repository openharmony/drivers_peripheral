/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DAUDIO_TEST_UTILS_H
#define OHOS_DAUDIO_TEST_UTILS_H

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <v1_0/iaudio_callback.h>
#include <v1_0/iaudio_capture.h>
#include <v1_0/iaudio_render.h>
#include <v2_1/id_audio_callback.h>

#include "daudio_errcode.h"

namespace OHOS {
namespace HDI {
namespace DistributedAudio {
namespace Audio {
namespace V1_0 {
using OHOS::HDI::DistributedAudio::Audioext::V2_1::DAudioEvent;
using OHOS::HDI::DistributedAudio::Audioext::V2_1::AudioData;
using OHOS::HDI::DistributedAudio::Audioext::V2_1::AudioParameter;
using OHOS::HDI::DistributedAudio::Audioext::V2_1::CurrentTime;
using OHOS::HDI::DistributedAudio::Audioext::V2_1::IDAudioCallback;
using OHOS::HDI::DistributedAudio::Audio::V1_0::IAudioCallback;
class MockIDAudioCallback : public IDAudioCallback {
public:
    MockIDAudioCallback() {}
    ~MockIDAudioCallback() {}

    int32_t CreateStream(int32_t streamId) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t DestroyStream(int32_t streamId) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t SetParameters(int32_t streamId, const AudioParameter &param) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t NotifyEvent(int32_t streamId, const DAudioEvent &event) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t WriteStreamData(int32_t streamId, const AudioData &data) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t ReadStreamData(int32_t streamId, AudioData &data) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t ReadMmapPosition(int32_t streamId, uint64_t &frames, CurrentTime &time) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t RefreshAshmemInfo(int32_t streamId, int fd, int32_t ashmemLength, int32_t lengthPerTrans) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t GetLatency(int32_t streamId, uint32_t& ms) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t GetRenderPosition(int32_t streamId, uint64_t &frames, CurrentTime &time) override
    {
        return DistributedHardware::DH_SUCCESS;
    }
};

class MockIAudioRender : public IAudioRender {
public:
    MockIAudioRender() {}
    ~MockIAudioRender() {}

    int32_t GetLatency(uint32_t &ms) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t RenderFrame(const std::vector<int8_t> &frame, uint64_t &replyBytes) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t GetRenderPosition(uint64_t &frames, AudioTimeStamp &time) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t SetRenderSpeed(float speed) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t GetRenderSpeed(float &speed) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t SetChannelMode(AudioChannelMode mode) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t GetChannelMode(AudioChannelMode &mode) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t RegCallback(const sptr<IAudioCallback> &audioCallback, int8_t cookie) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t DrainBuffer(AudioDrainNotifyType &type) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t IsSupportsDrain(bool &support) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t CheckSceneCapability(const AudioSceneDescriptor &scene, bool &supported) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t SelectScene(const AudioSceneDescriptor &scene) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t SetMute(bool mute) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t GetMute(bool &mute) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t SetVolume(float volume) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t GetVolume(float &volume) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t GetGainThreshold(float &min, float &max) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t SetGain(float gain) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t GetGain(float &gain) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t GetFrameSize(uint64_t &size) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t GetFrameCount(uint64_t &count) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t SetSampleAttributes(const AudioSampleAttributes &attrs) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t GetSampleAttributes(AudioSampleAttributes &attrs) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t GetCurrentChannelId(uint32_t &channelId) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t SetExtraParams(const std::string &keyValueList) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t GetExtraParams(std::string &keyValueList) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t ReqMmapBuffer(int32_t reqSize, AudioMmapBufferDescriptor &desc) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t GetMmapPosition(uint64_t &frames, AudioTimeStamp &time) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t AddAudioEffect(uint64_t effectid) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t RemoveAudioEffect(uint64_t effectid) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t GetFrameBufferSize(uint64_t &bufferSize) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t Start() override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t Stop() override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t Pause() override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t Resume() override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t Flush() override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t TurnStandbyMode() override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t AudioDevDump(int32_t range, int32_t fd) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t IsSupportsPauseAndResume(bool &supportPause, bool &supportResume) override
    {
        return DistributedHardware::DH_SUCCESS;
    }
};

class MockIAudioCapture : public IAudioCapture {
public:
    MockIAudioCapture() {}
    ~MockIAudioCapture() {}

    int32_t CaptureFrame(std::vector<int8_t> &frame, uint64_t &replyBytes) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t GetCapturePosition(uint64_t &frames, AudioTimeStamp &time) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t CheckSceneCapability(const AudioSceneDescriptor &scene, bool &supported) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t SelectScene(const AudioSceneDescriptor &scene) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t SetMute(bool mute) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t GetMute(bool &mute) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t SetVolume(float volume) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t GetVolume(float &volume) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t GetGainThreshold(float &min, float &max) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t GetGain(float &gain) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t SetGain(float gain) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t GetFrameSize(uint64_t &size) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t GetFrameCount(uint64_t &count) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t SetSampleAttributes(const AudioSampleAttributes &attrs) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t GetSampleAttributes(AudioSampleAttributes &attrs) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t GetCurrentChannelId(uint32_t &channelId) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t SetExtraParams(const std::string &keyValueList) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t GetExtraParams(std::string &keyValueList) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t ReqMmapBuffer(int32_t reqSize, AudioMmapBufferDescriptor &desc) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t GetMmapPosition(uint64_t &frames, AudioTimeStamp &time) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t AddAudioEffect(uint64_t effectid) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t RemoveAudioEffect(uint64_t effectid) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t GetFrameBufferSize(uint64_t &bufferSize) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t Start() override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t Stop() override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t Pause() override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t Resume() override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t Flush() override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t TurnStandbyMode() override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t AudioDevDump(int32_t range, int32_t fd) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t IsSupportsPauseAndResume(bool &supportPause, bool &supportResume) override
    {
        return DistributedHardware::DH_SUCCESS;
    }
};

class MockIAudioParamCallback : public IAudioCallback {
public:
    MockIAudioParamCallback() {}
    ~MockIAudioParamCallback() {}

    int32_t RenderCallback(AudioCallbackType type, int8_t &reserved, int8_t &cookie) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t ParamCallback(AudioExtParamKey key, const std::string& condition, const std::string& value,
        int8_t &reserved, int8_t cookie) override
    {
        return DistributedHardware::DH_SUCCESS;
    }
};

class MockRevertIAudioParamCallback : public IAudioCallback {
public:
    MockRevertIAudioParamCallback() {}
    ~MockRevertIAudioParamCallback() {}

    int32_t RenderCallback(AudioCallbackType type, int8_t &reserved, int8_t &cookie) override
    {
        return DistributedHardware::ERR_DH_AUDIO_HDF_FAIL;
    }

    int32_t ParamCallback(AudioExtParamKey key, const std::string& condition, const std::string& value,
        int8_t &reserved, int8_t cookie) override
    {
        return DistributedHardware::ERR_DH_AUDIO_HDF_FAIL;
    }
};

class MockRevertIDAudioCallback : public IDAudioCallback {
public:
    MockRevertIDAudioCallback() {}
    ~MockRevertIDAudioCallback() {}

    int32_t CreateStream(int32_t streamId) override
    {
        return DistributedHardware::ERR_DH_AUDIO_HDF_FAIL;
    }

    int32_t DestroyStream(int32_t streamId) override
    {
        return DistributedHardware::ERR_DH_AUDIO_HDF_FAIL;
    }

    int32_t SetParameters(int32_t streamId, const AudioParameter &param) override
    {
        return DistributedHardware::ERR_DH_AUDIO_HDF_FAIL;
    }

    int32_t NotifyEvent(int32_t streamId, const DAudioEvent &event) override
    {
        return DistributedHardware::ERR_DH_AUDIO_HDF_FAIL;
    }

    int32_t WriteStreamData(int32_t streamId, const AudioData &data) override
    {
        return DistributedHardware::ERR_DH_AUDIO_HDF_FAIL;
    }

    int32_t ReadStreamData(int32_t streamId, AudioData &data) override
    {
        return DistributedHardware::ERR_DH_AUDIO_HDF_FAIL;
    }

    int32_t ReadMmapPosition(int32_t streamId, uint64_t &frames, CurrentTime &time) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t RefreshAshmemInfo(int32_t streamId, int fd, int32_t ashmemLength, int32_t lengthPerTrans) override
    {
        return DistributedHardware::DH_SUCCESS;
    }

    int32_t GetLatency(int32_t streamId, uint32_t& ms) override
    {
        return DistributedHardware::ERR_DH_AUDIO_HDF_FAIL;
    }

    int32_t GetRenderPosition(int32_t streamId, uint64_t &frames, CurrentTime &time) override
    {
        return DistributedHardware::ERR_DH_AUDIO_HDF_FAIL;
    }
};
} // V1_0
} // AudioExt
} // Distributedaudio
} // HDI
} // OHOS
#endif // OHOS_DAUDIO_TEST_UTILS_H
