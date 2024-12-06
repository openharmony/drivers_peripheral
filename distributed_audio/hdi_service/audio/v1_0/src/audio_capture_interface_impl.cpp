/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "audio_capture_interface_impl.h"

#include <hdf_base.h>
#include <unistd.h>
#include "sys/time.h"
#include <securec.h>

#include "cJSON.h"

#include "daudio_constants.h"
#include "daudio_events.h"
#include "daudio_log.h"
#include "daudio_utils.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "AudioCaptureInterfaceImpl"

using namespace OHOS::DistributedHardware;
namespace OHOS {
namespace HDI {
namespace DistributedAudio {
namespace Audio {
namespace V1_0 {
AudioCaptureInterfaceImpl::AudioCaptureInterfaceImpl(const std::string &adpName, const AudioDeviceDescriptor &desc,
    const AudioSampleAttributes &attrs, const sptr<IDAudioCallback> &callback)
    : adapterName_(adpName), devDesc_(desc), devAttrs_(attrs), audioExtCallback_(callback)
{
    devAttrs_.frameSize = CalculateFrameSize(attrs.sampleRate, attrs.channelCount, attrs.format,
        AUDIO_NORMAL_INTERVAL, false);
    const int32_t sizePerSec = static_cast<int32_t>(attrs.sampleRate * attrs.channelCount) *attrs.format;
    if (sizePerSec == 0) {
        DHLOGE("The 'sizePerSec' is zero. In the constructor for x, the denominator of the division is zero.");
    } else {
        framePeriodNs_ = (static_cast<int64_t>(devAttrs_.frameSize) * AUDIO_NS_PER_SECOND) / sizePerSec;
    }
    DHLOGD("Distributed audio capture constructed, period(%{public}d),frameSize(%{public}d).",
        attrs.period, devAttrs_.frameSize);
    DHLOGD("Distributed audio capture constructed, id(%{public}d).", desc.pins);
}

AudioCaptureInterfaceImpl::~AudioCaptureInterfaceImpl()
{
    DHLOGD("Distributed audio capture destructed, id(%{public}d).", devDesc_.pins);
}

int32_t AudioCaptureInterfaceImpl::GetCapturePosition(uint64_t &frames, AudioTimeStamp &time)
{
    DHLOGI("Get capture position, not support yet.");
    (void)frames;
    (void)time;
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::CaptureFrame(std::vector<int8_t> &frame, uint64_t &replyBytes)
{
    DHLOGD("Capture frame[sampleRate:%{public}d, channelCount: %{public}d, format: %{public}d, frameSize: %{public}d].",
        devAttrs_.sampleRate, devAttrs_.channelCount, devAttrs_.format, devAttrs_.frameSize);
    int64_t timeOffset = UpdateTimeOffset(frameIndex_, framePeriodNs_, startTime_);

    int64_t startTime = GetNowTimeUs();
    std::lock_guard<std::mutex> captureLck(captureMtx_);
    if (captureStatus_ != CAPTURE_STATUS_START) {
        DHLOGE("Capture status wrong, return false.");
        return HDF_FAILURE;
    }
    if (audioExtCallback_ == nullptr) {
        DHLOGE("Callback is nullptr.");
        return HDF_FAILURE;
    }

    AudioData audioData;
    int32_t ret = audioExtCallback_->ReadStreamData(captureId_, audioData);
    if (ret != HDF_SUCCESS) {
        DHLOGE("Read stream data failed.");
        return HDF_FAILURE;
    }
    DumpFileUtil::WriteDumpFile(dumpFile_, static_cast<void *>(audioData.data.data()), audioData.data.size());
    frame.clear();
    frame.resize(devAttrs_.frameSize, 0);
    if (!muteState_.load() && memcpy_s(frame.data(), frame.size(), audioData.data.data(), audioData.data.size()) !=
        EOK) {
        DHLOGE("Copy capture frame failed");
        return HDF_FAILURE;
    }
    ++frameIndex_;
    AbsoluteSleep(startTime_ + frameIndex_ * framePeriodNs_ - timeOffset);
    DHLOGD("Capture audio frame success.");
    int64_t endTime = GetNowTimeUs();
    if (IsOutDurationRange(startTime, endTime, lastCaptureStartTime_)) {
        DHLOGD("This frame spend: %{public}" PRId64" us, interval of two frames: %{public}" PRId64" us",
            endTime - startTime, startTime - lastCaptureStartTime_);
    }
    lastCaptureStartTime_ = startTime;
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::Start()
{
    DHLOGI("Start capture.");
    cJSON *jParam = cJSON_CreateObject();
    if (jParam == nullptr) {
        DHLOGE("Failed to create cJSON object.");
        return HDF_FAILURE;
    }
    cJSON_AddStringToObject(jParam, KEY_DH_ID, std::to_string(devDesc_.pins).c_str());
    char *jsonData = cJSON_PrintUnformatted(jParam);
    if (jsonData == nullptr) {
        DHLOGE("Failed to create JSON data.");
        cJSON_Delete(jParam);
        return HDF_FAILURE;
    }
    std::string content(jsonData);
    cJSON_Delete(jParam);
    cJSON_free(jsonData);
    DAudioEvent event = { HDF_AUDIO_EVENT_START, content };
    if (audioExtCallback_ == nullptr) {
        DHLOGE("Callback is nullptr.");
        return HDF_FAILURE;
    }
    if (audioExtCallback_->NotifyEvent(captureId_, event) != HDF_SUCCESS) {
        DHLOGE("Notify start event failed.");
        return HDF_FAILURE;
    }
    std::lock_guard<std::mutex> captureLck(captureMtx_);
    captureStatus_ = CAPTURE_STATUS_START;
    frameIndex_ = 0;
    startTime_ = 0;
    DumpFileUtil::OpenDumpFile(DUMP_SERVER_PARA, HDF_CAPTURE_FROM_SA, &dumpFile_);
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::Stop()
{
    DHLOGI("Stop capture.");
    cJSON *jParam = cJSON_CreateObject();
    if (jParam == nullptr) {
        DHLOGE("Failed to create cJSON object.");
        return HDF_FAILURE;
    }
    cJSON_AddStringToObject(jParam, KEY_DH_ID, std::to_string(devDesc_.pins).c_str());
    char *jsonData = cJSON_PrintUnformatted(jParam);
    if (jsonData == nullptr) {
        DHLOGE("Failed to create JSON data.");
        cJSON_Delete(jParam);
        return HDF_FAILURE;
    }
    cJSON_Delete(jParam);
    cJSON_free(jsonData);
    std::string content(jsonData);
    DAudioEvent event = { HDF_AUDIO_EVENT_STOP, content };
    if (audioExtCallback_ == nullptr) {
        DHLOGE("Callback is nullptr.");
        return HDF_FAILURE;
    }
    if (audioExtCallback_->NotifyEvent(captureId_, event) != HDF_SUCCESS) {
        DHLOGE("Notify stop event failed.");
        return HDF_FAILURE;
    }
    std::lock_guard<std::mutex> captureLck(captureMtx_);
    captureStatus_ = CAPTURE_STATUS_STOP;
    DumpFileUtil::CloseDumpFile(&dumpFile_);
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::Pause()
{
    DHLOGI("Pause capture.");
    std::lock_guard<std::mutex> captureLck(captureMtx_);
    captureStatus_ = CAPTURE_STATUS_PAUSE;
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::Resume()
{
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::Flush()
{
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::TurnStandbyMode()
{
    DHLOGI("Turn stand by mode, not support yet.");
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::AudioDevDump(int32_t range, int32_t fd)
{
    DHLOGI("Dump audio info, not support yet.");
    (void)range;
    (void)fd;
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::IsSupportsPauseAndResume(bool &supportPause, bool &supportResume)
{
    DHLOGI("Check whether pause and resume is supported, not support yet.");
    (void)supportPause;
    (void)supportResume;
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::CheckSceneCapability(const AudioSceneDescriptor &scene, bool &supported)
{
    DHLOGI("Check scene capability.");
    (void)scene;
    supported = false;
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::SelectScene(const AudioSceneDescriptor &scene)
{
    DHLOGI("Select audio scene, not support yet.");
    (void)scene;
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::SetMute(bool mute)
{
    DHLOGI("Set audio mute state.");
    muteState_.store(mute);
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::GetMute(bool &mute)
{
    DHLOGI("Get audio mute state.");
    mute = muteState_.load();
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::SetVolume(float volume)
{
    DHLOGI("Can not set vol not by this interface.");
    (void)volume;
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::GetVolume(float &volume)
{
    DHLOGI("Can not get vol not by this interface.");
    (void)volume;
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::GetGainThreshold(float &min, float &max)
{
    DHLOGI("Get gain threshold, not support yet.");
    min = 0;
    max = 0;
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::SetGain(float gain)
{
    DHLOGI("Set gain, not support yet.");
    (void)gain;
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::GetGain(float &gain)
{
    DHLOGI("Get gain, not support yet.");
    gain = 1.0;
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::GetFrameSize(uint64_t &size)
{
    (void)size;
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::GetFrameCount(uint64_t &count)
{
    (void)count;
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::SetSampleAttributes(const AudioSampleAttributes &attrs)
{
    DHLOGI("Set sample attributes.");
    devAttrs_ = attrs;
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::GetSampleAttributes(AudioSampleAttributes &attrs)
{
    DHLOGI("Get sample attributes.");
    attrs = devAttrs_;
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::GetCurrentChannelId(uint32_t &channelId)
{
    DHLOGI("Get current channel id, not support yet.");
    (void)channelId;
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::SetExtraParams(const std::string &keyValueList)
{
    DHLOGI("Set extra parameters, not support yet.");
    (void)keyValueList;
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::GetExtraParams(std::string &keyValueList)
{
    DHLOGI("Get extra parameters, not support yet.");
    (void)keyValueList;
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::ReqMmapBuffer(int32_t reqSize, AudioMmapBufferDescriptor &desc)
{
    DHLOGI("Request mmap buffer, not support yet.");
    (void)reqSize;
    (void)desc;
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::GetMmapPosition(uint64_t &frames, AudioTimeStamp &time)
{
    DHLOGI("Get mmap position, not support yet.");
    (void)frames;
    (void)time;
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::AddAudioEffect(uint64_t effectid)
{
    DHLOGI("Add audio effect, not support yet.");
    (void)effectid;
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::RemoveAudioEffect(uint64_t effectid)
{
    DHLOGI("Remove audio effect, not support yet.");
    (void)effectid;
    return HDF_SUCCESS;
}

int32_t AudioCaptureInterfaceImpl::GetFrameBufferSize(uint64_t &bufferSize)
{
    DHLOGI("Get frame buffer size, not support yet.");
    (void)bufferSize;
    return HDF_SUCCESS;
}

void AudioCaptureInterfaceImpl::SetAttrs(const std::string &adpName, const AudioDeviceDescriptor &desc,
    const AudioSampleAttributes &attrs, const sptr<IDAudioCallback> &callback, const int32_t dhId)
{
    DHLOGI("Set attrs, not support yet.");
}

void AudioCaptureInterfaceImpl::SetDumpFlagInner()
{
    dumpFlag_ = true;
}

const AudioDeviceDescriptor &AudioCaptureInterfaceImpl::GetCaptureDesc()
{
    return devDesc_;
}
} // V1_0
} // Audio
} // Distributedaudio
} // HDI
} // OHOS
