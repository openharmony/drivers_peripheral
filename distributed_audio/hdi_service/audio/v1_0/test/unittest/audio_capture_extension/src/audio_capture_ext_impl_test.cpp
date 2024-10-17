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

#include "audio_capture_ext_impl_test.h"

#include <hdf_base.h>
#include <unistd.h>
#include <sys/time.h>

#include "ashmem.h"
#include "daudio_constants.h"
#include "daudio_log.h"

using namespace testing::ext;

namespace OHOS {
namespace HDI {
namespace DistributedAudio {
namespace Audio {
namespace V1_0 {
void AudioCaptureExtImplTest::SetUpTestCase(void) {}

void AudioCaptureExtImplTest::TearDownTestCase(void) {}

void AudioCaptureExtImplTest::SetUp(void) {}

void AudioCaptureExtImplTest::TearDown(void)
{
    audioCapturelatencyImpl_ = nullptr;
}

/**
 * @tc.name: InitAshmem_001
 * @tc.desc: Verify the InitAshmem function.
 * @tc.type: FUNC
 * @tc.require: AR000HP6J4
 */
HWTEST_F(AudioCaptureExtImplTest, InitAshmem_001, TestSize.Level1)
{
    std::string adpName;
    AudioDeviceDescriptor desc;
    AudioSampleAttributes attrs;
    sptr<IDAudioCallback> callback;
    int32_t dhId = 1;
    audioCapturelatencyImpl_ = std::make_shared<AudioCaptureExtImpl>();
    audioCapturelatencyImpl_->SetAttrs(adpName, desc, attrs, callback, dhId);

    int32_t ashmemLength = 1024;
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->InitAshmem(ashmemLength));
    audioCapturelatencyImpl_->UnInitAshmem();
}

/**
 * @tc.name: InitAshmem_002
 * @tc.desc: Verify the InitAshmem function.
 * @tc.type: FUNC
 * @tc.require: AR000HP6J4
 */
HWTEST_F(AudioCaptureExtImplTest, InitAshmem_002, TestSize.Level1)
{
    std::string adpName;
    AudioDeviceDescriptor desc;
    AudioSampleAttributes attrs;
    sptr<IDAudioCallback> callback;
    int32_t dhId = 1;
    audioCapturelatencyImpl_ = std::make_shared<AudioCaptureExtImpl>();
    audioCapturelatencyImpl_->SetAttrs(adpName, desc, attrs, callback, dhId);

    int32_t ashmemLength = -1;
    EXPECT_EQ(HDF_FAILURE, audioCapturelatencyImpl_->InitAshmem(ashmemLength));
    audioCapturelatencyImpl_->UnInitAshmem();
}

/**
 * @tc.name: Start_001
 * @tc.desc: Verify the Start function.
 * @tc.type: FUNC
 * @tc.require: AR000HP6J4
 */
HWTEST_F(AudioCaptureExtImplTest, Start_001, TestSize.Level1)
{
    std::string adpName;
    AudioDeviceDescriptor desc;
    AudioSampleAttributes attrs;
    sptr<IDAudioCallback> callback;
    int32_t dhId = 1;
    audioCapturelatencyImpl_ = std::make_shared<AudioCaptureExtImpl>();
    audioCapturelatencyImpl_->SetAttrs(adpName, desc, attrs, callback, dhId);

    uint64_t frames = 0;
    AudioTimeStamp time;
    std::vector<int8_t> frame;
    uint64_t requestBytes = 1024;
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->GetCapturePosition(frames, time));
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->CaptureFrame(frame, requestBytes));
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->Pause());
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->Resume());
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->Flush());
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->TurnStandbyMode());
    EXPECT_EQ(HDF_FAILURE, audioCapturelatencyImpl_->GetMmapPosition(frames, time));
    audioCapturelatencyImpl_->audioExtCallback_ = sptr<IDAudioCallback>(new MockIDAudioCallback());
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->Start());
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->Stop());
}

/**
 * @tc.name: Start_002
 * @tc.desc: Verify the Start function.
 * @tc.type: FUNC
 * @tc.require: AR000HP6J4
 */
HWTEST_F(AudioCaptureExtImplTest, Start_002, TestSize.Level1)
{
    std::string adpName;
    AudioDeviceDescriptor desc;
    AudioSampleAttributes attrs;
    sptr<IDAudioCallback> callback;
    int32_t dhId = 1;
    audioCapturelatencyImpl_ = std::make_shared<AudioCaptureExtImpl>();
    audioCapturelatencyImpl_->SetAttrs(adpName, desc, attrs, callback, dhId);

    int32_t range = 1;
    int32_t fd = 1;
    bool supportPause = true;
    bool supportResume = true;
    AudioSceneDescriptor scene;
    bool supported = true;
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->AudioDevDump(range, fd));
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->IsSupportsPauseAndResume(supportPause, supportResume));
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->CheckSceneCapability(scene, supported));
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->SelectScene(scene));
    audioCapturelatencyImpl_->audioExtCallback_ = nullptr;
    EXPECT_EQ(HDF_FAILURE, audioCapturelatencyImpl_->Start());
}

/**
 * @tc.name: ReqMmapBuffer_001
 * @tc.desc: Verify the ReqMmapBuffer function.
 * @tc.type: FUNC
 * @tc.require: AR000HP6J4
 */
HWTEST_F(AudioCaptureExtImplTest, ReqMmapBuffer_001, TestSize.Level1)
{
    std::string adpName;
    AudioDeviceDescriptor descs;
    AudioSampleAttributes attrs;
    sptr<IDAudioCallback> callback;
    int32_t dhId = 1;
    audioCapturelatencyImpl_ = std::make_shared<AudioCaptureExtImpl>();
    audioCapturelatencyImpl_->SetAttrs(adpName, descs, attrs, callback, dhId);

    int32_t reqSize = 30;
    AudioMmapBufferDescriptor desc;
    EXPECT_EQ(HDF_FAILURE, audioCapturelatencyImpl_->ReqMmapBuffer(reqSize, desc));
    audioCapturelatencyImpl_->UnInitAshmem();
}

/**
 * @tc.name: ReqMmapBuffer_002
 * @tc.desc: Verify the ReqMmapBuffer function.
 * @tc.type: FUNC
 * @tc.require: AR000HP6J4
 */
HWTEST_F(AudioCaptureExtImplTest, ReqMmapBuffer_002, TestSize.Level1)
{
    std::string adpName;
    AudioDeviceDescriptor descs;
    AudioSampleAttributes attrs;
    sptr<IDAudioCallback> callback;
    int32_t dhId = 1;
    audioCapturelatencyImpl_ = std::make_shared<AudioCaptureExtImpl>();
    audioCapturelatencyImpl_->SetAttrs(adpName, descs, attrs, callback, dhId);

    int32_t reqSize = 30;
    AudioMmapBufferDescriptor desc;
    struct AudioSampleAttributes captureAttr = {
        .type = AUDIO_IN_MEDIA,
        .interleaved = 0,
        .format = AUDIO_FORMAT_TYPE_PCM_16_BIT,
        .sampleRate = 48000,
        .channelCount = 2,
        .period = 1024,
        .frameSize = 4,
        .isBigEndian = false,
        .isSignedData = true,
        .startThreshold = 1024,
        .stopThreshold = 0x7fffffff,
        .silenceThreshold = 0,
        .streamId = 1,
    };
    audioCapturelatencyImpl_->devAttrs_ = captureAttr;
    audioCapturelatencyImpl_->audioExtCallback_ = sptr<IDAudioCallback>(new MockIDAudioCallback());
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->ReqMmapBuffer(reqSize, desc));
    audioCapturelatencyImpl_->UnInitAshmem();
}

/**
 * @tc.name: SetMute_001
 * @tc.desc: Verify the SetMute function.
 * @tc.type: FUNC
 * @tc.require: AR000HP6J4
 */
HWTEST_F(AudioCaptureExtImplTest, SetMute_001, TestSize.Level1)
{
    std::string adpName;
    AudioDeviceDescriptor desc;
    AudioSampleAttributes attr;
    sptr<IDAudioCallback> callback;
    int32_t dhId = 1;
    audioCapturelatencyImpl_ = std::make_shared<AudioCaptureExtImpl>();
    audioCapturelatencyImpl_->SetAttrs(adpName, desc, attr, callback, dhId);

    bool mute = true;
    float volume = 0.0;
    float min = 0.0;
    float max = 10.0;
    uint64_t size = 1024;
    uint32_t channelId = 0;
    std::string keyValueList = "keyValueList";
    AudioSampleAttributes attrs;
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->SetMute(mute));
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->GetMute(mute));
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->SetVolume(volume));
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->GetGainThreshold(min, max));
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->SetGain(volume));
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->GetGain(volume));
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->GetFrameSize(size));
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->GetFrameCount(size));
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->SetSampleAttributes(attrs));
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->GetSampleAttributes(attrs));
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->GetCurrentChannelId(channelId));
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->SetExtraParams(keyValueList));
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->GetExtraParams(keyValueList));
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->AddAudioEffect(size));
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->RemoveAudioEffect(size));
    EXPECT_EQ(HDF_SUCCESS, audioCapturelatencyImpl_->GetFrameBufferSize(size));
}
} // namspace V1_0
} // namspace Audio
} // namspace Distributedaudio
} // namspace HDI
} // namspace OHOS
