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

#include "audio_capture_interface_impl_test.h"

#include <hdf_base.h>
#include <unistd.h>
#include "sys/time.h"

#include "daudio_constants.h"
#include "daudio_log.h"

using namespace testing::ext;

namespace OHOS {
namespace HDI {
namespace DistributedAudio {
namespace Audio {
namespace V1_0 {
void AudioCaptureInterfaceImplTest::SetUpTestCase(void) {}

void AudioCaptureInterfaceImplTest::TearDownTestCase(void) {}

void AudioCaptureInterfaceImplTest::SetUp(void) {}

void AudioCaptureInterfaceImplTest::TearDown(void)
{
    audioCaptureInterfaceImpl_ = nullptr;
}

/**
 * @tc.name: GetCapturePosition_001
 * @tc.desc: Verify the GetCapturePosition function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, GetCapturePosition_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    uint64_t frames = 0;
    AudioTimeStamp time;
    EXPECT_EQ(HDF_SUCCESS, audioCaptureInterfaceImpl_->GetCapturePosition(frames, time));
}

/**
 * @tc.name: CaptureFrame_001
 * @tc.desc: Verify the CaptureFrame function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, CaptureFrame_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    vector<int8_t> frame;
    uint64_t requestBytes = 0;
    EXPECT_EQ(HDF_FAILURE, audioCaptureInterfaceImpl_->CaptureFrame(frame, requestBytes));
}

/**
 * @tc.name: CaptureFrame_002
 * @tc.desc: Verify the CaptureFrame function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, CaptureFrame_002, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    vector<int8_t> frame{1, 1, 1, 1, 1};
    uint64_t requestBytes = 0;
    audioCaptureInterfaceImpl_->captureStatus_ = CAPTURE_STATUS_START;
    audioCaptureInterfaceImpl_->audioExtCallback_ = nullptr;
    EXPECT_EQ(HDF_FAILURE, audioCaptureInterfaceImpl_->CaptureFrame(frame, requestBytes));
    audioCaptureInterfaceImpl_->audioExtCallback_ = new MockIDAudioCallback();
    EXPECT_NE(HDF_SUCCESS, audioCaptureInterfaceImpl_->CaptureFrame(frame, requestBytes));
}

/**
 * @tc.name: CaptureFrame_003
 * @tc.desc: Verify the CaptureFrame function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, CaptureFrame_003, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    vector<int8_t> frame;
    uint64_t requestBytes = 0;
    audioCaptureInterfaceImpl_->captureStatus_ = CAPTURE_STATUS_START;
    audioCaptureInterfaceImpl_->audioExtCallback_ = new MockRevertIDAudioCallback();
    EXPECT_EQ(HDF_FAILURE, audioCaptureInterfaceImpl_->CaptureFrame(frame, requestBytes));
}

/**
 * @tc.name: Start_001
 * @tc.desc: Verify the Start function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, Start_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    EXPECT_EQ(HDF_FAILURE, audioCaptureInterfaceImpl_->Start());
}

/**
 * @tc.name: Stop_001
 * @tc.desc: Verify the Stop function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, Stop_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    EXPECT_EQ(HDF_FAILURE, audioCaptureInterfaceImpl_->Stop());
}

/**
 * @tc.name: Pause_001
 * @tc.desc: Verify the Pause function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, Pause_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    EXPECT_EQ(HDF_SUCCESS, audioCaptureInterfaceImpl_->Pause());
}

/**
 * @tc.name: Resume_001
 * @tc.desc: Verify the Resume function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, Resume_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    EXPECT_EQ(HDF_SUCCESS, audioCaptureInterfaceImpl_->Resume());
}

/**
 * @tc.name: Flush_001
 * @tc.desc: Verify the Flush function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, Flush_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    EXPECT_EQ(HDF_SUCCESS, audioCaptureInterfaceImpl_->Flush());
}

/**
 * @tc.name: TurnStandbyMode_001
 * @tc.desc: Verify the TurnStandbyMode function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, TurnStandbyMode_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    EXPECT_EQ(HDF_SUCCESS, audioCaptureInterfaceImpl_->TurnStandbyMode());
}

/**
 * @tc.name: AudioDevDump_001
 * @tc.desc: Verify the AudioDevDump function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, AudioDevDump_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    int32_t range = 0;
    int32_t fd = 0;
    EXPECT_EQ(HDF_SUCCESS, audioCaptureInterfaceImpl_->AudioDevDump(range, fd));
}

/**
 * @tc.name: IsSupportsPauseAndResume_001
 * @tc.desc: Verify the IsSupportsPauseAndResume function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, IsSupportsPauseAndResume_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    bool supportPause = true;
    bool supportResume = true;
    EXPECT_EQ(HDF_SUCCESS, audioCaptureInterfaceImpl_->
        IsSupportsPauseAndResume(supportPause, supportResume));
}

/**
 * @tc.name: CheckSceneCapability_001
 * @tc.desc: Verify the CheckSceneCapability function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, CheckSceneCapability_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    AudioSceneDescriptor scene;
    bool support = false;
    EXPECT_EQ(HDF_SUCCESS, audioCaptureInterfaceImpl_->CheckSceneCapability(scene, support));
}

/**
 * @tc.name: SelectScene_001
 * @tc.desc: Verify the SelectScene function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, SelectScene_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    AudioSceneDescriptor scene;
    EXPECT_EQ(HDF_SUCCESS, audioCaptureInterfaceImpl_->SelectScene(scene));
}

/**
 * @tc.name: SetMute_001
 * @tc.desc: Verify the SetMute function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, SetMute_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    bool mute = true;
    EXPECT_EQ(HDF_SUCCESS, audioCaptureInterfaceImpl_->SetMute(mute));
}

/**
 * @tc.name: GetMute_001
 * @tc.desc: Verify the GetMute function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, GetMute_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    bool mute = true;

    EXPECT_EQ(HDF_SUCCESS, audioCaptureInterfaceImpl_->GetMute(mute));
}

/**
 * @tc.name: SetVolume_001
 * @tc.desc: Verify the SetVolume function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, SetVolume_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    float volume = 0;
    EXPECT_EQ(HDF_SUCCESS, audioCaptureInterfaceImpl_->SetVolume(volume));
}

/**
 * @tc.name: GetVolume_001
 * @tc.desc: Verify the GetVolume function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, GetVolume_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    float volume = 0;

    EXPECT_EQ(HDF_SUCCESS, audioCaptureInterfaceImpl_->GetVolume(volume));
}

/**
 * @tc.name: GetGainThreshold_001
 * @tc.desc: Verify the GetGainThreshold function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, GetGainThreshold_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    float min = 0;
    float max = 0;
    EXPECT_EQ(HDF_SUCCESS, audioCaptureInterfaceImpl_->GetGainThreshold(min, max));
}

/**
 * @tc.name: SetGain_001
 * @tc.desc: Verify the SetGain function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, SetGain_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    float gain = 0;
    EXPECT_EQ(HDF_SUCCESS, audioCaptureInterfaceImpl_->SetGain(gain));
}

/**
 * @tc.name: GetGain_001
 * @tc.desc: Verify the GetGain function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, GetGain_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    float gain = 0;
    EXPECT_EQ(HDF_SUCCESS, audioCaptureInterfaceImpl_->GetGain(gain));
}


/**
 * @tc.name: GetFrameSize_001
 * @tc.desc: Verify the GetFrameSize function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, GetFrameSize_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    uint64_t size = 0;
    EXPECT_EQ(HDF_SUCCESS, audioCaptureInterfaceImpl_->GetFrameSize(size));
}

/**
 * @tc.name: GetFrameCount_001
 * @tc.desc: Verify the GetFrameCount function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, GetFrameCount_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    uint64_t count = 0;
    EXPECT_EQ(HDF_SUCCESS, audioCaptureInterfaceImpl_->GetFrameCount(count));
}

/**
 * @tc.name: SetSampleAttributes_001
 * @tc.desc: Verify the SetSampleAttributes function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, SetSampleAttributes_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    AudioSampleAttributes attrs;
    EXPECT_EQ(HDF_SUCCESS, audioCaptureInterfaceImpl_->SetSampleAttributes(attrs));
}

/**
 * @tc.name: GetSampleAttributes_001
 * @tc.desc: Verify the GetSampleAttributes function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, GetSampleAttributes_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    AudioSampleAttributes attrs;
    EXPECT_EQ(HDF_SUCCESS, audioCaptureInterfaceImpl_->GetSampleAttributes(attrs));
}

/**
 * @tc.name: GetCurrentChannelId_001
 * @tc.desc: Verify the GetCurrentChannelId function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, GetCurrentChannelId_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    uint32_t channelId = 0;
    EXPECT_EQ(HDF_SUCCESS, audioCaptureInterfaceImpl_->GetCurrentChannelId(channelId));
}

/**
 * @tc.name: SetExtraParams_001
 * @tc.desc: Verify the SetExtraParams function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, SetExtraParams_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    std::string keyValueList;
    EXPECT_EQ(HDF_SUCCESS, audioCaptureInterfaceImpl_->SetExtraParams(keyValueList));
}

/**
 * @tc.name: GetExtraParams_001
 * @tc.desc: Verify the GetExtraParams function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, GetExtraParams_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    std::string keyValueList;
    EXPECT_EQ(HDF_SUCCESS, audioCaptureInterfaceImpl_->GetExtraParams(keyValueList));
}

/**
 * @tc.name: ReqMmapBuffer_001
 * @tc.desc: Verify the ReqMmapBuffer function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, ReqMmapBuffer_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    int32_t reqSize = 0;
    AudioMmapBufferDescriptor desc;
    EXPECT_EQ(HDF_SUCCESS, audioCaptureInterfaceImpl_->ReqMmapBuffer(reqSize, desc));
}

/**
 * @tc.name: GetMmapPosition_001
 * @tc.desc: Verify the GetMmapPosition function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, GetMmapPosition_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    uint64_t frames = 0;
    AudioTimeStamp time;
    EXPECT_EQ(HDF_SUCCESS, audioCaptureInterfaceImpl_->GetMmapPosition(frames, time));
}

/**
 * @tc.name: AddAudioEffect_001
 * @tc.desc: Verify the AddAudioEffect function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, AddAudioEffect_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    uint64_t effectid = 0;
    EXPECT_EQ(HDF_SUCCESS, audioCaptureInterfaceImpl_->AddAudioEffect(effectid));
}

/**
 * @tc.name: RemoveAudioEffect_001
 * @tc.desc: Verify the RemoveAudioEffect function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, RemoveAudioEffect_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    uint64_t effectid = 0;
    EXPECT_EQ(HDF_SUCCESS, audioCaptureInterfaceImpl_->RemoveAudioEffect(effectid));
}

/**
 * @tc.name: GetFrameBufferSize_001
 * @tc.desc: Verify the GetFrameBufferSize function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, GetFrameBufferSize_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    uint64_t bufferSize = 6;
    EXPECT_EQ(HDF_SUCCESS, audioCaptureInterfaceImpl_->GetFrameBufferSize(bufferSize));
}

/**
 * @tc.name: GetCaptureDesc_001
 * @tc.desc: Verify the GetCaptureDesc function.
 * @tc.type: FUNC
 * @tc.require: AR000H0E6H
 */
HWTEST_F(AudioCaptureInterfaceImplTest, GetCaptureDesc_001, TestSize.Level1)
{
    audioCaptureInterfaceImpl_ = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    desc_.portId = 0;
    desc_.pins = PIN_NONE;
    desc_.desc = "mic";
    auto audioCaptureInterfaceImplTmp = std::make_shared<AudioCaptureInterfaceImpl>(adpName_, desc_, attrs_, callback_);
    AudioDeviceDescriptor descriptorTmp = audioCaptureInterfaceImplTmp->GetCaptureDesc();

    EXPECT_EQ(desc_.portId, descriptorTmp.portId);
    EXPECT_EQ(desc_.pins, descriptorTmp.pins);
    EXPECT_EQ(desc_.desc, descriptorTmp.desc);
}
} // V1_0
} // Audio
} // Distributedaudio
} // HDI
} // OHOS