/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "audio_render_ext_impl.h"

#include <hdf_base.h>
#include <unistd.h>
#include "sys/time.h"

#include "cJSON.h"

#include "daudio_constants.h"
#include "daudio_events.h"
#include "daudio_log.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "AudioRenderExtImpl"

using namespace OHOS::DistributedHardware;
namespace OHOS {
namespace HDI {
namespace DistributedAudio {
namespace Audio {
namespace V1_0 {
AudioRenderExtImpl::AudioRenderExtImpl()
{
    DHLOGI("Distributed lowlatency render constructed.");
}

AudioRenderExtImpl::~AudioRenderExtImpl()
{
    UnInitAshmem();
    DHLOGI("Distributed lowlatency render destructed, id(%{public}d).", devDesc_.pins);
}

int32_t AudioRenderExtImpl::InitAshmem(int32_t ashmemLength)
{
    std::string memory_name = "Render ShareMemory";
    if (ashmemLength < DAUDIO_MIN_ASHMEM_LEN || ashmemLength > DAUDIO_MAX_ASHMEM_LEN) {
        DHLOGE("Init ashmem failed. length is illegal.");
        return HDF_FAILURE;
    }
    ashmem_ = OHOS::Ashmem::CreateAshmem(memory_name.c_str(), ashmemLength);
    if (ashmem_ == nullptr) {
        DHLOGE("Create ashmem failed.");
        return HDF_FAILURE;
    }
    bool ret = ashmem_->MapReadAndWriteAshmem();
    if (ret != true) {
        DHLOGE("Mmap ashmem failed.");
        return HDF_FAILURE;
    }
    fd_ = ashmem_->GetAshmemFd();
    DHLOGI("Init Ashmem success, fd: %{public}d, length: %{public}d", fd_, ashmemLength);
    return HDF_SUCCESS;
}

void AudioRenderExtImpl::UnInitAshmem()
{
    if (ashmem_ != nullptr) {
        ashmem_->UnmapAshmem();
        ashmem_->CloseAshmem();
        ashmem_ = nullptr;
        DHLOGI("UnInitAshmem success.");
    }
}

int32_t AudioRenderExtImpl::GetLatency(uint32_t &ms)
{
    DHLOGD("Get render device latency, not support yet.");
    ms = 0;
    return HDF_SUCCESS;
}

float AudioRenderExtImpl::GetFadeRate(uint32_t currentIndex, const uint32_t durationIndex)
{
    if (currentIndex > durationIndex || durationIndex == 0) {
        return 1.0f;
    }

    float fadeRate = static_cast<float>(currentIndex) / durationIndex * DAUDIO_FADE_NORMALIZATION_FACTOR;
    if (fadeRate < 1) {
        return pow(fadeRate, DAUDIO_FADE_POWER_NUM) / DAUDIO_FADE_NORMALIZATION_FACTOR;
    }
    return -pow(fadeRate - DAUDIO_FADE_MAXIMUM_VALUE, DAUDIO_FADE_POWER_NUM) /
        DAUDIO_FADE_NORMALIZATION_FACTOR + 1;
}

int32_t AudioRenderExtImpl::FadeInProcess(const uint32_t durationFrame,
    int8_t* frameData, const size_t frameLength)
{
    int16_t* frame = reinterpret_cast<int16_t *>(frameData);
    const size_t newFrameLength = frameLength / 2;
    if (durationFrame < 1) {
        return HDF_FAILURE;
    }
    for (size_t k = 0; k < newFrameLength; ++k) {
        float rate = GetFadeRate(currentFrame_ * newFrameLength + k, durationFrame * newFrameLength);
        frame[k] = currentFrame_ == durationFrame - 1 ? frame[k] : static_cast<int16_t>(rate * frame[k]);
    }
    DHLOGI("Fade-in frame[currentFrame: %{public}d].", currentFrame_);
    ++currentFrame_;
    currentFrame_ = currentFrame_ >= durationFrame ? durationFrame - 1 : currentFrame_;

    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::RenderFrame(const std::vector<int8_t> &frame, uint64_t &replyBytes)
{
    DHLOGD("Render frame. not support in low-latency render");
    (void)devAttrs_.sampleRate;
    (void)devAttrs_.channelCount;
    (void)devAttrs_.format;

    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::GetRenderPosition(uint64_t &frames, AudioTimeStamp &time)
{
    DHLOGD("Get render position, not support yet.");
    (void)frames;
    (void)time;
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::SetRenderSpeed(float speed)
{
    DHLOGD("Set render speed, control render speed is not support yet.");
    renderSpeed_ = speed;
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::GetRenderSpeed(float &speed)
{
    DHLOGD("Get render speed, control render speed is not support yet.");
    speed = renderSpeed_;
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::SetChannelMode(AudioChannelMode mode)
{
    DHLOGD("Set channel mode, control channel mode is not support yet.");
    channelMode_ = mode;
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::GetChannelMode(AudioChannelMode &mode)
{
    DHLOGD("Get channel mode, control channel mode is not support yet.");
    mode = channelMode_;
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::RegCallback(const sptr<IAudioCallback> &audioCallback, int8_t cookie)
{
    DHLOGI("Register render callback.");
    (void)cookie;
    renderCallback_ = audioCallback;
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::DrainBuffer(AudioDrainNotifyType &type)
{
    DHLOGD("Drain audio buffer, not support yet.");
    (void)type;
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::IsSupportsDrain(bool &support)
{
    DHLOGD("Check whether drain is supported, not support yet.");
    (void)support;
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::Start()
{
    DHLOGI("Start render mmap.");
    if (audioExtCallback_ == nullptr) {
        DHLOGE("Callback is nullptr.");
        return HDF_FAILURE;
    }
    if (firstOpenFlag_) {
        firstOpenFlag_ = false;
    } else {
        std::string content;
        std::initializer_list<std::pair<std::string, std::string>> items = { {"ChangeType", HDF_EVENT_RESTART},
            {KEY_DH_ID, std::to_string(dhId_)} };
        if (WrapCJsonItem(items, content) != HDF_SUCCESS) {
            DHLOGE("Wrap the event failed.");
            return HDF_FAILURE;
        }
        DAudioEvent event = { HDF_AUDIO_EVENT_CHANGE_PLAY_STATUS, content };
        int32_t ret = audioExtCallback_->NotifyEvent(renderId_, event);
        if (ret != HDF_SUCCESS) {
            DHLOGE("Restart failed.");
        }
    }
    std::string content;
    std::initializer_list<std::pair<std::string, std::string>> items = { {KEY_DH_ID, std::to_string(dhId_)} };
    if (WrapCJsonItem(items, content) != HDF_SUCCESS) {
        DHLOGE("Wrap the event failed.");
        return HDF_FAILURE;
    }
    DAudioEvent event = { HDF_AUDIO_EVENT_MMAP_START, content };
    int32_t ret = audioExtCallback_->NotifyEvent(renderId_, event);
    if (ret != HDF_SUCCESS) {
        DHLOGE("Start render mmap failed.");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::Stop()
{
    DHLOGI("Stop render mmap.");
    if (audioExtCallback_ == nullptr) {
        DHLOGE("Callback is nullptr.");
        return HDF_FAILURE;
    }
    std::string content;
    std::initializer_list<std::pair<std::string, std::string>> items = { {KEY_DH_ID, std::to_string(dhId_)} };
    if (WrapCJsonItem(items, content) != HDF_SUCCESS) {
        DHLOGE("Wrap the event failed.");
        return HDF_FAILURE;
    }
    DAudioEvent event = { HDF_AUDIO_EVENT_MMAP_STOP, content };
    int32_t ret = audioExtCallback_->NotifyEvent(renderId_, event);
    if (ret != HDF_SUCCESS) {
        DHLOGE("Stop render mmap failed.");
        return HDF_FAILURE;
    }
    items = { {"ChangeType", HDF_EVENT_PAUSE},
        {KEY_DH_ID, std::to_string(dhId_)} };
    if (WrapCJsonItem(items, content) != HDF_SUCCESS) {
        DHLOGE("Wrap the event failed.");
        return HDF_FAILURE;
    }
    event = { HDF_AUDIO_EVENT_CHANGE_PLAY_STATUS, content };
    ret = audioExtCallback_->NotifyEvent(renderId_, event);
    if (ret != HDF_SUCCESS) {
        DHLOGE("Pause and clear cache streams failed.");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::Pause()
{
    DHLOGI("Pause render.");
    std::lock_guard<std::mutex> renderLck(renderMtx_);
    renderStatus_ = RENDER_STATUS_PAUSE;
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::Resume()
{
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::Flush()
{
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::TurnStandbyMode()
{
    DHLOGD("Turn stand by mode, not support yet.");
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::AudioDevDump(int32_t range, int32_t fd)
{
    DHLOGD("Dump audio info, not support yet.");
    (void)range;
    (void)fd;
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::IsSupportsPauseAndResume(bool &supportPause, bool &supportResume)
{
    DHLOGD("Check whether pause and resume is supported, not support yet.");
    (void)supportPause;
    (void)supportResume;
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::CheckSceneCapability(const AudioSceneDescriptor &scene, bool &supported)
{
    DHLOGD("Check scene capability.");
    (void)scene;
    (void)supported;
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::SelectScene(const AudioSceneDescriptor &scene)
{
    DHLOGD("Select audio scene, not support yet.");
    (void)scene;
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::SetMute(bool mute)
{
    DHLOGD("Set mute, not support yet.");
    (void)mute;
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::GetMute(bool &mute)
{
    DHLOGD("Get mute, not support yet.");
    (void)mute;
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::SetVolume(float volume)
{
    DHLOGD("Can not set vol not by this interface.");
    (void)volume;
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::GetVolume(float &volume)
{
    DHLOGD("Can not get vol not by this interface.");
    (void)volume;
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::GetGainThreshold(float &min, float &max)
{
    DHLOGD("Get gain threshold, not support yet.");
    min = 0;
    max = 0;
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::SetGain(float gain)
{
    DHLOGD("Set gain, not support yet.");
    (void) gain;
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::GetGain(float &gain)
{
    DHLOGD("Get gain, not support yet.");
    gain = 1.0;
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::GetFrameSize(uint64_t &size)
{
    (void)size;
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::GetFrameCount(uint64_t &count)
{
    (void)count;
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::SetSampleAttributes(const AudioSampleAttributes &attrs)
{
    DHLOGI("Set sample attributes.");
    devAttrs_ = attrs;
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::GetSampleAttributes(AudioSampleAttributes &attrs)
{
    DHLOGI("Get sample attributes.");
    attrs = devAttrs_;
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::GetCurrentChannelId(uint32_t &channelId)
{
    DHLOGD("Get current channel id, not support yet.");
    (void)channelId;
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::SetExtraParams(const std::string &keyValueList)
{
    DHLOGD("Set extra parameters, not support yet.");
    (void)keyValueList;
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::GetExtraParams(std::string &keyValueList)
{
    DHLOGD("Get extra parameters, not support yet.");
    (void)keyValueList;
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::ReqMmapBuffer(int32_t reqSize, AudioMmapBufferDescriptor &desc)
{
    DHLOGI("Request mmap buffer.");
    int32_t minSize = CalculateSampleNum(devAttrs_.sampleRate, minTimeInterval_);
    int32_t maxSize = CalculateSampleNum(devAttrs_.sampleRate, maxTimeInterval_);
    int32_t realSize = reqSize;
    if (reqSize < minSize) {
        realSize = minSize;
    } else if (reqSize > maxSize) {
        realSize = maxSize;
    }
    DHLOGI("ReqMmap buffer realsize : %{public}d, minsize: %{public}d, maxsize:%{public}d.",
        realSize, minSize, maxSize);
    desc.totalBufferFrames = realSize;
    int64_t result = static_cast<int64_t>(realSize) * static_cast<int64_t>(devAttrs_.channelCount) * static_cast<int64_t>(devAttrs_.format);
    CHECK_AND_RETURN_RET_LOG(result > INT32_MAX, HDF_FAILURE, "ashmemLength_ overflow");
    ashmemLength_ = static_cast<int32_t>(result);
    DHLOGI("Init ashmem real sample size : %{public}d, length: %{public}d.", realSize, ashmemLength_);
    int32_t ret = InitAshmem(ashmemLength_);
    if (ret != HDF_SUCCESS) {
        DHLOGE("Init ashmem error..");
        return HDF_FAILURE;
    }
    desc.memoryFd = fd_;
    desc.transferFrameSize = static_cast<int32_t>(CalculateSampleNum(devAttrs_.sampleRate, timeInterval_));
    lengthPerTrans_ = desc.transferFrameSize * static_cast<int32_t>(devAttrs_.channelCount) * devAttrs_.format;
    desc.isShareable = false;
    if (audioExtCallback_ == nullptr) {
        DHLOGE("Callback is nullptr.");
        return HDF_FAILURE;
    }
    ret = audioExtCallback_->RefreshAshmemInfo(renderId_, fd_, ashmemLength_, lengthPerTrans_);
    if (ret != HDF_SUCCESS) {
        DHLOGE("Refresh ashmem info failed.");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::GetMmapPosition(uint64_t &frames, AudioTimeStamp &time)
{
    DHLOGI("Get mmap render position.");
    if (audioExtCallback_ == nullptr) {
        DHLOGE("Callback is nullptr.");
        return HDF_FAILURE;
    }
    CurrentTime cTime;
    int32_t ret = audioExtCallback_->ReadMmapPosition(renderId_, frames, cTime);
    if (ret != HDF_SUCCESS) {
        DHLOGE("Read mmap position failed.");
        return HDF_FAILURE;
    }
    time.tvSec = cTime.tvSec;
    time.tvNSec = cTime.tvNSec;
    DHLOGI("Read mmap position. frames: %{public}" PRIu64", tvSec: %{public}" PRId64", tvNSec: %{public}" PRId64,
        frames, cTime.tvSec, cTime.tvNSec);
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::AddAudioEffect(uint64_t effectid)
{
    DHLOGD("Add audio effect, not support yet.");
    (void)effectid;
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::RemoveAudioEffect(uint64_t effectid)
{
    DHLOGD("Remove audio effect, not support yet.");
    (void)effectid;
    return HDF_SUCCESS;
}

int32_t AudioRenderExtImpl::GetFrameBufferSize(uint64_t &bufferSize)
{
    DHLOGD("Get frame buffer size, not support yet.");
    (void)bufferSize;
    return HDF_SUCCESS;
}

const AudioDeviceDescriptor &AudioRenderExtImpl::GetRenderDesc()
{
    return devDesc_;
}

void AudioRenderExtImpl::SetVolumeInner(const uint32_t vol)
{
    std::lock_guard<std::mutex> volLck(volMtx_);
    vol_ = vol;
}

void AudioRenderExtImpl::SetVolumeRangeInner(const uint32_t volMax, const uint32_t volMin)
{
    std::lock_guard<std::mutex> volLck(volMtx_);
    volMin_ = volMin;
    volMax_ = volMax;
}

uint32_t AudioRenderExtImpl::GetVolumeInner()
{
    std::lock_guard<std::mutex> volLck(volMtx_);
    return vol_;
}

uint32_t AudioRenderExtImpl::GetMaxVolumeInner()
{
    std::lock_guard<std::mutex> volLck(volMtx_);
    return volMax_;
}

uint32_t AudioRenderExtImpl::GetMinVolumeInner()
{
    std::lock_guard<std::mutex> volLck(volMtx_);
    return volMin_;
}

void AudioRenderExtImpl::SetAttrs(const std::string &adpName, const AudioDeviceDescriptor &desc,
    const AudioSampleAttributes &attrs, const sptr<IDAudioCallback> &callback, const int32_t dhId)
{
    adapterName_ = adpName;
    devDesc_ = desc;
    devAttrs_ = attrs;
    audioExtCallback_ = callback;
    dhId_ = dhId;
    if (attrs.type == AUDIO_MMAP_NOIRQ) {
        timeInterval_ = AUDIO_MMAP_NOIRQ_INTERVAL;
    } else if (attrs.type == AUDIO_MMAP_VOIP) {
        timeInterval_ = AUDIO_MMAP_VOIP_INTERVAL;
    }
    devAttrs_.frameSize = CalculateFrameSize(attrs.sampleRate, attrs.channelCount, attrs.format, timeInterval_, true);
    DHLOGI("Distributed lowlatency render set attrs, id(%{public}d). framesize(%{public}d)",
        dhId_, devAttrs_.frameSize);
}

void AudioRenderExtImpl::SetDumpFlagInner()
{
    DHLOGD("Set dump flag, not support yet.");
}

AudioRenderInterfaceImplBase *GetRenderImplExt()
{
    DHLOGI("Get low latency render impl.");
    static AudioRenderExtImpl *implBase = new AudioRenderExtImpl();
    if (implBase == nullptr) {
        return nullptr;
    }
    return implBase;
}
} // namespace V1_0
} // namespace Audio
} // namespace Distributedaudio
} // namespace HDI
} // namespace OHOS
