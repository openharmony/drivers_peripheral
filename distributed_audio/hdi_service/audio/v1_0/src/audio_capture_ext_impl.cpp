/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "audio_capture_ext_impl.h"

#include <hdf_base.h>
#include <securec.h>
#include <unistd.h>
#include <sys/time.h>

#include "cJSON.h"

#include "daudio_constants.h"
#include "daudio_events.h"
#include "daudio_log.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "AudioCaptureExtImpl"

using namespace OHOS::DistributedHardware;
namespace OHOS {
namespace HDI {
namespace DistributedAudio {
namespace Audio {
namespace V1_0 {

AudioCaptureExtImpl::AudioCaptureExtImpl()
{
    DHLOGI("Distributed lowlatency capture constructed.");
}

AudioCaptureExtImpl::~AudioCaptureExtImpl()
{
    UnInitAshmem();
    DHLOGD("Distributed lowlatency capture destructed, id(%{public}d).", devDesc_.pins);
}

int32_t AudioCaptureExtImpl::InitAshmem(int32_t ashmemLength)
{
    std::string memory_name = "Capture ShareMemory";
    if (ashmemLength < DAUDIO_MIN_ASHMEM_LEN || ashmemLength > DAUDIO_MAX_ASHMEM_LEN) {
        DHLOGE("Init ashmem failed. length is illegal.");
        return HDF_FAILURE;
    }
    ashmem_ = OHOS::Ashmem::CreateAshmem(memory_name.c_str(), ashmemLength);
    if (ashmem_ == nullptr) {
        DHLOGE("Create ashmem failed.");
        return HDF_FAILURE;
    }
    if (!ashmem_->MapReadAndWriteAshmem()) {
        DHLOGE("Mmap ashmem failed.");
        return HDF_FAILURE;
    }
    fd_ = ashmem_->GetAshmemFd();
    DHLOGI("Init Ashmem success, fd: %{public}d, length: %{public}d", fd_, ashmemLength);
    return HDF_SUCCESS;
}

void AudioCaptureExtImpl::UnInitAshmem()
{
    if (ashmem_ != nullptr) {
        ashmem_->UnmapAshmem();
        ashmem_->CloseAshmem();
        ashmem_ = nullptr;
        DHLOGI("UnInitAshmem success.");
    }
}

int32_t AudioCaptureExtImpl::GetCapturePosition(uint64_t &frames, AudioTimeStamp &time)
{
    DHLOGI("Get capture position, not support yet.");
    (void)frames;
    (void)time;
    return HDF_SUCCESS;
}

int32_t AudioCaptureExtImpl::CaptureFrame(std::vector<int8_t> &frame, uint64_t &replyBytes)
{
    DHLOGI("Render frame. not support in low-latency capture");
    (void)devAttrs_.sampleRate;
    (void)devAttrs_.channelCount;
    (void)devAttrs_.format;
    return HDF_SUCCESS;
}

int32_t AudioCaptureExtImpl::Start()
{
    DHLOGI("Start capture mmap.");
    std::string content;
    std::initializer_list<std::pair<std::string, std::string>> items = { {KEY_DH_ID, std::to_string(dhId_)} };
    if (WrapCJsonItem(items, content) != HDF_SUCCESS) {
        DHLOGE("Wrap the event failed.");
        return HDF_FAILURE;
    }
    DAudioEvent event = { HDF_AUDIO_EVENT_MMAP_START_MIC, content };
    if (audioExtCallback_ == nullptr) {
        DHLOGE("Callback is nullptr.");
        return HDF_FAILURE;
    }
    int32_t ret = audioExtCallback_->NotifyEvent(captureId_, event);
    if (ret != HDF_SUCCESS) {
        DHLOGE("Start capture mmap failed.");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCaptureExtImpl::Stop()
{
    DHLOGI("Stop capture mmap.");
    std::string content;
    std::initializer_list<std::pair<std::string, std::string>> items = { {KEY_DH_ID, std::to_string(dhId_)} };
    if (WrapCJsonItem(items, content) != HDF_SUCCESS) {
        DHLOGE("Wrap the event failed.");
        return HDF_FAILURE;
    }
    DAudioEvent event = { HDF_AUDIO_EVENT_MMAP_STOP_MIC, content };
    if (audioExtCallback_ == nullptr) {
        DHLOGE("Callback is nullptr.");
        return HDF_FAILURE;
    }
    int32_t ret = audioExtCallback_->NotifyEvent(captureId_, event);
    if (ret != HDF_SUCCESS) {
        DHLOGE("Stop capture mmap failed.");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCaptureExtImpl::Pause()
{
    DHLOGI("Pause capture.");
    std::lock_guard<std::mutex> captureLck(captureMtx_);
    captureStatus_ = CAPTURE_STATUS_PAUSE;
    return HDF_SUCCESS;
}

int32_t AudioCaptureExtImpl::Resume()
{
    return HDF_SUCCESS;
}

int32_t AudioCaptureExtImpl::Flush()
{
    return HDF_SUCCESS;
}

int32_t AudioCaptureExtImpl::TurnStandbyMode()
{
    DHLOGI("Turn stand by mode, not support yet.");
    return HDF_SUCCESS;
}

int32_t AudioCaptureExtImpl::AudioDevDump(int32_t range, int32_t fd)
{
    DHLOGI("Dump audio info, not support yet.");
    (void)range;
    (void)fd;
    return HDF_SUCCESS;
}

int32_t AudioCaptureExtImpl::IsSupportsPauseAndResume(bool &supportPause, bool &supportResume)
{
    DHLOGI("Check whether pause and resume is supported, not support yet.");
    (void)supportPause;
    (void)supportResume;
    return HDF_SUCCESS;
}

int32_t AudioCaptureExtImpl::CheckSceneCapability(const AudioSceneDescriptor &scene, bool &supported)
{
    DHLOGI("Check scene capability.");
    (void)scene;
    supported = false;
    return HDF_SUCCESS;
}

int32_t AudioCaptureExtImpl::SelectScene(const AudioSceneDescriptor &scene)
{
    DHLOGI("Select audio scene, not support yet.");
    (void)scene;
    return HDF_SUCCESS;
}

int32_t AudioCaptureExtImpl::SetMute(bool mute)
{
    DHLOGI("Set mute, not support yet.");
    (void)mute;
    return HDF_SUCCESS;
}

int32_t AudioCaptureExtImpl::GetMute(bool &mute)
{
    DHLOGI("Get mute, not support yet.");
    (void)mute;
    return HDF_SUCCESS;
}

int32_t AudioCaptureExtImpl::SetVolume(float volume)
{
    DHLOGI("Can not set vol not by this interface.");
    (void)volume;
    return HDF_SUCCESS;
}

int32_t AudioCaptureExtImpl::GetVolume(float &volume)
{
    DHLOGI("Can not get vol not by this interface.");
    (void)volume;
    return HDF_SUCCESS;
}

int32_t AudioCaptureExtImpl::GetGainThreshold(float &min, float &max)
{
    DHLOGI("Get gain threshold, not support yet.");
    min = 0;
    max = 0;
    return HDF_SUCCESS;
}

int32_t AudioCaptureExtImpl::SetGain(float gain)
{
    DHLOGI("Set gain, not support yet.");
    (void) gain;
    return HDF_SUCCESS;
}

int32_t AudioCaptureExtImpl::GetGain(float &gain)
{
    DHLOGI("Get gain, not support yet.");
    gain = 1.0;
    return HDF_SUCCESS;
}

int32_t AudioCaptureExtImpl::GetFrameSize(uint64_t &size)
{
    (void)size;
    return HDF_SUCCESS;
}

int32_t AudioCaptureExtImpl::GetFrameCount(uint64_t &count)
{
    (void)count;
    return HDF_SUCCESS;
}

int32_t AudioCaptureExtImpl::SetSampleAttributes(const AudioSampleAttributes &attrs)
{
    DHLOGI("Set sample attributes.");
    devAttrs_ = attrs;
    return HDF_SUCCESS;
}

int32_t AudioCaptureExtImpl::GetSampleAttributes(AudioSampleAttributes &attrs)
{
    DHLOGI("Get sample attributes.");
    attrs = devAttrs_;
    return HDF_SUCCESS;
}

int32_t AudioCaptureExtImpl::GetCurrentChannelId(uint32_t &channelId)
{
    DHLOGI("Get current channel id, not support yet.");
    (void)channelId;
    return HDF_SUCCESS;
}

int32_t AudioCaptureExtImpl::SetExtraParams(const std::string &keyValueList)
{
    DHLOGI("Set extra parameters, not support yet.");
    (void)keyValueList;
    return HDF_SUCCESS;
}

int32_t AudioCaptureExtImpl::GetExtraParams(std::string &keyValueList)
{
    DHLOGI("Get extra parameters, not support yet.");
    (void)keyValueList;
    return HDF_SUCCESS;
}

int32_t AudioCaptureExtImpl::ReqMmapBuffer(int32_t reqSize, AudioMmapBufferDescriptor &desc)
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
    ashmemLength_ = realSize * static_cast<int32_t>(devAttrs_.channelCount) * devAttrs_.format;
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
    ret = audioExtCallback_->RefreshAshmemInfo(captureId_, fd_, ashmemLength_, lengthPerTrans_);
    if (ret != HDF_SUCCESS) {
        DHLOGE("Refresh ashmem info failed.");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCaptureExtImpl::GetMmapPosition(uint64_t &frames, AudioTimeStamp &time)
{
    DHLOGI("Get capture mmap position.");
    if (audioExtCallback_ == nullptr) {
        DHLOGE("Callback is nullptr.");
        return HDF_FAILURE;
    }
    CurrentTime cTime;
    int32_t ret = audioExtCallback_->ReadMmapPosition(captureId_, frames, cTime);
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

int32_t AudioCaptureExtImpl::AddAudioEffect(uint64_t effectid)
{
    DHLOGI("Add audio effect, not support yet.");
    (void)effectid;
    return HDF_SUCCESS;
}

int32_t AudioCaptureExtImpl::RemoveAudioEffect(uint64_t effectid)
{
    DHLOGI("Remove audio effect, not support yet.");
    (void)effectid;
    return HDF_SUCCESS;
}

int32_t AudioCaptureExtImpl::GetFrameBufferSize(uint64_t &bufferSize)
{
    DHLOGI("Get frame buffer size, not support yet.");
    (void)bufferSize;
    return HDF_SUCCESS;
}

const AudioDeviceDescriptor &AudioCaptureExtImpl::GetCaptureDesc()
{
    return devDesc_;
}

void AudioCaptureExtImpl::SetAttrs(const std::string &adpName, const AudioDeviceDescriptor &desc,
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
    DHLOGI("Distributed lowlatency capture set attrs, id(%{public}d). framesize(%{public}d)",
        dhId_, devAttrs_.frameSize);
}

void AudioCaptureExtImpl::SetDumpFlagInner()
{
    DHLOGI("Set dump flag, not support yet.");
}

AudioCaptureInterfaceImplBase *GetCaptureImplExt()
{
    DHLOGI("Get low latency capture impl.");
    static AudioCaptureExtImpl *implBase = new AudioCaptureExtImpl();
    return implBase;
}
} // namespace V1_0
} // namespace Audio
} // namespace Distributedaudio
} // namespace HDI
} // namespace OHOS
