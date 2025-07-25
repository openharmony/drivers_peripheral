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

#ifndef OHOS_AUDIO_RENDER_EXT_IMPL_H
#define OHOS_AUDIO_RENDER_EXT_IMPL_H

#include <mutex>
#include <string>
#include <cmath>

#include "ashmem.h"
#include "audio_render_interface_impl_base.h"
#include "daudio_utils.h"

#include <v1_0/audio_types.h>
#include <v1_0/iaudio_render.h>
#include <v2_1/id_audio_manager.h>

namespace OHOS {
namespace HDI {
namespace DistributedAudio {
namespace Audio {
namespace V1_0 {
using OHOS::HDI::DistributedAudio::Audioext::V2_1::AudioData;
using OHOS::HDI::DistributedAudio::Audioext::V2_1::AudioParameter;
using OHOS::HDI::DistributedAudio::Audioext::V2_1::CurrentTime;
using OHOS::HDI::DistributedAudio::Audioext::V2_1::DAudioEvent;
using OHOS::HDI::DistributedAudio::Audioext::V2_1::IDAudioCallback;
class AudioRenderExtImpl : public AudioRenderInterfaceImplBase {
public:
    AudioRenderExtImpl();
    ~AudioRenderExtImpl() override;

    int32_t GetLatency(uint32_t &ms) override;
    int32_t RenderFrame(const std::vector<int8_t> &frame, uint64_t &replyBytes) override;
    int32_t GetRenderPosition(uint64_t &frames, AudioTimeStamp &time) override;
    int32_t SetRenderSpeed(float speed) override;
    int32_t GetRenderSpeed(float &speed) override;
    int32_t SetChannelMode(AudioChannelMode mode) override;
    int32_t GetChannelMode(AudioChannelMode &mode) override;
    int32_t RegCallback(const sptr<IAudioCallback> &audioCallback, int8_t cookie) override;
    int32_t DrainBuffer(AudioDrainNotifyType &type) override;
    int32_t IsSupportsDrain(bool &support) override;
    int32_t CheckSceneCapability(const AudioSceneDescriptor &scene, bool &supported) override;
    int32_t SelectScene(const AudioSceneDescriptor &scene) override;
    int32_t SetMute(bool mute) override;
    int32_t GetMute(bool &mute) override;
    int32_t SetVolume(float volume) override;
    int32_t GetVolume(float &volume) override;
    int32_t GetGainThreshold(float &min, float &max) override;
    int32_t SetGain(float gain) override;
    int32_t GetGain(float &gain) override;
    int32_t GetFrameSize(uint64_t &size) override;
    int32_t GetFrameCount(uint64_t &count) override;
    int32_t SetSampleAttributes(const AudioSampleAttributes &attrs) override;
    int32_t GetSampleAttributes(AudioSampleAttributes &attrs) override;
    int32_t GetCurrentChannelId(uint32_t &channelId) override;
    int32_t SetExtraParams(const std::string &keyValueList) override;
    int32_t GetExtraParams(std::string &keyValueList) override;
    int32_t ReqMmapBuffer(int32_t reqSize, AudioMmapBufferDescriptor &desc) override;
    int32_t GetMmapPosition(uint64_t &frames, AudioTimeStamp &time) override;
    int32_t AddAudioEffect(uint64_t effectid) override;
    int32_t RemoveAudioEffect(uint64_t effectid) override;
    int32_t GetFrameBufferSize(uint64_t &bufferSize) override;
    int32_t Start() override;
    int32_t Stop() override;
    int32_t Pause() override;
    int32_t Resume() override;
    int32_t Flush() override;
    int32_t TurnStandbyMode() override;
    int32_t AudioDevDump(int32_t range, int32_t fd) override;
    int32_t IsSupportsPauseAndResume(bool &supportPause, bool &supportResume) override;
    const AudioDeviceDescriptor &GetRenderDesc() override;
    void SetVolumeInner(const uint32_t vol) override;
    void SetVolumeRangeInner(const uint32_t volMax, const uint32_t volMin) override;
    uint32_t GetVolumeInner() override;
    uint32_t GetMaxVolumeInner() override;
    uint32_t GetMinVolumeInner() override;
    void SetAttrs(const std::string &adpName, const AudioDeviceDescriptor &desc, const AudioSampleAttributes &attrs,
        const sptr<IDAudioCallback> &callback, const int32_t dhId) override;
    void SetDumpFlagInner() override;

private:
    float GetFadeRate(uint32_t currentIndex, const uint32_t durationIndex);
    int32_t FadeInProcess(const uint32_t durationFrame, int8_t* frameData, const size_t frameLength);
    int32_t InitAshmem(int32_t ashmemLength);
    void UnInitAshmem();

private:
    std::string adapterName_;
    int32_t dhId_ = 0;
    uint32_t renderId_ = 0;
    AudioDeviceDescriptor devDesc_ = {};
    AudioSampleAttributes devAttrs_ = {};

    uint32_t timeInterval_ = AUDIO_MMAP_NOIRQ_INTERVAL;
    uint32_t minTimeInterval_ = 30;
    uint32_t maxTimeInterval_ = 80;
    float renderSpeed_ = 0;
    uint32_t currentFrame_ = 0;
    std::mutex renderMtx_;
    AudioChannelMode channelMode_ = AUDIO_CHANNEL_NORMAL;
    AudioRenderStatus renderStatus_ = RENDER_STATUS_CLOSE;
    sptr<IDAudioCallback> audioExtCallback_ = nullptr;
    sptr<IAudioCallback> renderCallback_ = nullptr;
    bool firstOpenFlag_ = true;
    OHOS::sptr<OHOS::Ashmem> ashmem_ = nullptr;
    int32_t ashmemLength_ = 0;
    int32_t lengthPerTrans_ = 0;
    int32_t fd_ = 0;

    std::mutex volMtx_;
    uint32_t vol_ = 0;
    uint32_t volMax_ = 0;
    uint32_t volMin_ = 0;
};
#ifdef __cplusplus
extern "C" {
#endif
__attribute__((visibility("default"))) AudioRenderInterfaceImplBase *GetRenderImplExt();
#ifdef __cplusplus
}
#endif
} // namespace V1_0
} // namespace Audio
} // namespace DistributedAudio
} // namespace HDI
} // namespace OHOS
#endif // OHOS_AUDIO_RENDER_EXT_IMPL_H
