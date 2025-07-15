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

#ifndef OHOS_AUDIO_ADAPTER_INTERFACE_IMPL_H
#define OHOS_AUDIO_ADAPTER_INTERFACE_IMPL_H

#include <condition_variable>
#include <map>
#include <mutex>

#include <v1_0/iaudio_adapter.h>
#include <v1_0/audio_types.h>
#include <v2_1/id_audio_manager.h>

#include "audio_capture_interface_impl.h"
#include "audio_capture_interface_impl_base.h"
#include "audio_render_interface_impl.h"
#include "audio_render_interface_impl_base.h"
#ifdef DAUDIO_SUPPORT_EXTENSION
#include "audio_capture_ext_impl.h"
#include "audio_render_ext_impl.h"
#endif

namespace OHOS {
namespace HDI {
namespace DistributedAudio {
namespace Audio {
namespace V1_0 {
using OHOS::HDI::DistributedAudio::Audioext::V2_1::DAudioEvent;
using OHOS::HDI::DistributedAudio::Audioext::V2_1::PortOperationMode;
using OHOS::HDI::DistributedAudio::Audioext::V2_1::AudioParameter;
using OHOS::HDI::DistributedAudio::Audioext::V2_1::IDAudioCallback;
using OHOS::HDI::DistributedAudio::Audio::V1_0::AudioPortPin;

typedef enum {
    STATUS_ONLINE = 0,
    STATUS_OFFLINE,
    STATUS_LOAD,
    STATUS_UNLOAD,
    STATUS_CREATE_RENDER,
} AudioAdapterStatus;

typedef enum {
    EVENT_DEV_CLOSED = 0,
    EVENT_OPEN_SPK,
    EVENT_CLOSE_SPK,
    EVENT_OPEN_MIC,
    EVENT_CLOSE_MIC,
} AudioDeviceEvent;

typedef enum {
    EVENT_GET_VOLUME = 1,
    EVENT_GET_MIN_VOLUME = 2,
    EVENT_GET_MAX_VOLUME = 3,
    EVENT_IS_STREAM_MUTE = 4,
} VolumeEventType;

class AudioAdapterInterfaceImpl : public IAudioAdapter {
public:
    explicit AudioAdapterInterfaceImpl(const AudioAdapterDescriptor &desc);
    ~AudioAdapterInterfaceImpl() override;

    int32_t InitAllPorts() override;
    int32_t CreateRender(const AudioDeviceDescriptor &desc, const AudioSampleAttributes &attrs,
        sptr<IAudioRender> &render, uint32_t &renderId) override;
    int32_t DestroyRender(uint32_t renderId) override;
    int32_t CreateCapture(const AudioDeviceDescriptor &desc, const AudioSampleAttributes &attrs,
        sptr<IAudioCapture> &capture, uint32_t &captureId) override;
    int32_t DestroyCapture(uint32_t captureId) override;
    int32_t GetPortCapability(const AudioPort &port, AudioPortCapability &capability) override;
    int32_t SetPassthroughMode(const AudioPort &port, AudioPortPassthroughMode mode) override;
    int32_t GetPassthroughMode(const AudioPort &port, AudioPortPassthroughMode &mode) override;
    int32_t GetDeviceStatus(AudioDeviceStatus& status) override;
    int32_t UpdateAudioRoute(const AudioRoute &route, int32_t &routeHandle) override;
    int32_t ReleaseAudioRoute(int32_t routeHandle) override;
    int32_t SetMicMute(bool mute) override;
    int32_t GetMicMute(bool& mute) override;
    int32_t SetVoiceVolume(float volume) override;
    int32_t SetExtraParams(AudioExtParamKey key, const std::string &condition, const std::string &value) override;
    int32_t GetExtraParams(AudioExtParamKey key, const std::string &condition, std::string &value) override;
    int32_t RegExtraParamObserver(const sptr<IAudioCallback> &audioCallback, int8_t cookie) override;

public:
    void SetSpeakerCallback(const int32_t dhId, const sptr<IDAudioCallback> &speakerCallback);
    void SetMicCallback(const int32_t dhId, const sptr<IDAudioCallback> &micCallback);
    AudioAdapterDescriptor GetAdapterDesc();
    std::string GetDeviceCapabilitys(const uint32_t devId);
    int32_t AdapterLoad();
    int32_t AdapterUnload();
    int32_t Notify(const uint32_t devId, const uint32_t streamId, const DAudioEvent &event);
    int32_t AddAudioDevice(const uint32_t devId, const std::string &caps);
    int32_t RemoveAudioDevice(const uint32_t devId);
    uint32_t GetVolumeGroup(const uint32_t devId);
    uint32_t GetInterruptGroup(const uint32_t devId);
    bool IsPortsNoReg();

private:
    int32_t OpenRenderDevice(const AudioDeviceDescriptor &desc, const AudioSampleAttributes &attrs,
        const sptr<IDAudioCallback> extSpkCallback, const int32_t dhId, const int32_t renderId = 0);
    int32_t CloseRenderDevice(const AudioDeviceDescriptor &desc, const sptr<IDAudioCallback> extSpkCallback,
        const int32_t dhId, const int32_t renderId = 0);
    int32_t OpenCaptureDevice(const AudioDeviceDescriptor &desc, const AudioSampleAttributes &attrs,
        const sptr<IDAudioCallback> extMicCallback, const int32_t dhId, const int32_t captureId = 0);
    int32_t CloseCaptureDevice(const AudioDeviceDescriptor &desc, const sptr<IDAudioCallback> extMicCallback,
        const int32_t dhId, const int32_t captureId = 0);
    int32_t SetAudioVolume(const std::string& condition, const std::string &param);
    int32_t GetAudioVolume(const std::string& condition, std::string &param);
    int32_t HandleFocusChangeEvent(const DAudioEvent &event);
    int32_t HandleRenderStateChangeEvent(const DAudioEvent &event);
    int32_t HandleVolumeChangeEvent(const DAudioEvent &event);
    int32_t HandleSANotifyEvent(const uint32_t streamId, const DAudioEvent &event);
    int32_t WaitForSANotify(const uint32_t streamId, const AudioDeviceEvent &event);
    int32_t HandleDeviceClosed(const uint32_t streamId, const DAudioEvent &event);
    int32_t HandleRenderCallback(const uint32_t devId, const DAudioEvent &event);
    int32_t getEventTypeFromCondition(const std::string& condition);
    sptr<AudioRenderInterfaceImplBase> CreateRenderImpl(const AudioDeviceDescriptor &desc,
        const AudioSampleAttributes &attrs, int32_t renderId);
    int32_t InsertRenderImpl(const AudioDeviceDescriptor &desc, const AudioSampleAttributes &attrs,
        sptr<AudioRenderInterfaceImplBase> &audioRender, const int32_t dhId, uint32_t &renderId);
    void DeleteRenderImpl(uint32_t renderId);
    int32_t InsertCapImpl(const sptr<AudioCaptureInterfaceImplBase> &audioCapture, const int32_t dhId,
        uint32_t &captureId);
    inline bool IsIdValid(const uint32_t id);
    bool CheckRendersValid();
    bool CheckCapsValid();
    bool CheckDevCapability(const AudioDeviceDescriptor &desc);
    void SetDumpFlag(bool isRender);
    sptr<IDAudioCallback> MatchStreamCallback(const AudioSampleAttributes &attrs,
        const AudioDeviceDescriptor &desc, int32_t &dhId);
    int32_t GetVolFromEvent(const std::string &content, const std::string &key, int32_t &vol);
    int32_t ConvertMsg2Code(const std::string &msg);
    std::string GetVolumeChangeString(const std::string &args);
    int32_t ParseDhIdFromJson(const std::string &args);
    int32_t ConvertString2Int(std::string val);
    sptr<AudioRenderInterfaceImplBase> GetRenderImpl(const std::string &content);
    void SetSpkStatus(const uint32_t streamId, bool status);
    bool GetSpkStatus(const uint32_t streamId);
    sptr<IAudioCallback> GetRenderCallback(const uint32_t devId);

private:
    static constexpr uint32_t WAIT_MILLISECONDS = 8000;
    static constexpr int32_t TYPE_CONDITION = 11;
    static constexpr int32_t MAX_EVENT_DIGITS = 3;
    AudioAdapterDescriptor adpDescriptor_;
    AudioAdapterStatus status_ = STATUS_OFFLINE;

    std::mutex extCallbackMtx_;
    std::map<int32_t, sptr<IDAudioCallback>> extCallbackMap_;
    sptr<IAudioCallback> paramCallback_ = nullptr;
    std::mutex renderDevMtx_;
    std::vector<std::pair<int32_t, sptr<AudioRenderInterfaceImplBase>>> renderDevs_;
    AudioParameter renderParam_;
    std::mutex capDevMtx_;
    std::vector<std::pair<int32_t, sptr<AudioCaptureInterfaceImplBase>>> captureDevs_;
    AudioParameter captureParam_;

    std::mutex devMapMtx_;
    std::mutex captureOptMtx_;
    std::mutex renderOptMtx_;
    std::map<uint32_t, std::string> mapAudioDevice_;
    std::mutex spkWaitMutex_;
    std::condition_variable spkWaitCond_;
    std::mutex micWaitMutex_;
    std::condition_variable micWaitCond_;

    std::mutex spkStatusMutex_;
    std::vector<bool> spkStatus_;
    int32_t errCode_ = -1;
    bool isMicOpened_ = false;
    bool spkNotifyFlag_ = false;
    bool micNotifyFlag_ = false;

    uint32_t spkPinInUse_ = 0;
    uint32_t micPinInUse_ = 0;
    uint32_t streamMuteStatus_ = 0;

    // mmap param
    PortOperationMode renderFlags_ = Audioext::V2_1::NORMAL_MODE;
    PortOperationMode capturerFlags_ = Audioext::V2_1::NORMAL_MODE;

    const std::string NOT_MUTE_STATUS = "0";
    const std::string IS_MUTE_STATUS = "1";
};
} // V1_0
} // Audio
} // Distributedaudio
} // HDI
} // OHOS
#endif // OHOS_AUDIO_ADAPTER_INTERFACE_IMPL_H