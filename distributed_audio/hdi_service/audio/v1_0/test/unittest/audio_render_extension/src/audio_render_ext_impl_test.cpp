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

#include "audio_render_ext_impl_test.h"

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
void AudioRenderExtImplTest::SetUpTestCase(void) {}

void AudioRenderExtImplTest::TearDownTestCase(void) {}

void AudioRenderExtImplTest::SetUp(void) {}

void AudioRenderExtImplTest::TearDown(void)
{
    audioRenderlatencyImpl_ = nullptr;
}

/**
 * @tc.name: InitAshmem_001
 * @tc.desc: Verify the InitAshmem function.
 * @tc.type: FUNC
 * @tc.require: AR000HP6J4
 */
HWTEST_F(AudioRenderExtImplTest, InitAshmem_001, TestSize.Level1)
{
    std::string adpName;
    AudioDeviceDescriptor desc;
    AudioSampleAttributes attrs;
    sptr<IDAudioCallback> callback;
    int32_t dhId = 1;
    audioRenderlatencyImpl_ = std::make_shared<AudioRenderExtImpl>();
    audioRenderlatencyImpl_->SetAttrs(adpName, desc, attrs, callback, dhId);

    int fd = 1;
    uint32_t ms = 0;
    float speed = 0.0;
    uint64_t replyBytes = 0;
    int32_t ashmemLength = 1024;
    const std::vector<int8_t> frame;
    AudioTimeStamp time;
    audioRenderlatencyImpl_->audioExtCallback_ = sptr<IDAudioCallback>(new MockIDAudioCallback());
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->InitAshmem(ashmemLength));
    audioRenderlatencyImpl_->UnInitAshmem();
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->GetRenderPosition(replyBytes, time));
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->RenderFrame(frame, replyBytes));
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->GetLatency(ms));
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->SetRenderSpeed(speed));
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->GetRenderSpeed(speed));
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->SetVolume(speed));
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->GetVolume(speed));
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->AudioDevDump(ashmemLength, fd));
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->GetMmapPosition(replyBytes, time));
}

/**
 * @tc.name: InitAshmem_002
 * @tc.desc: Verify the InitAshmem function.
 * @tc.type: FUNC
 * @tc.require: AR000HP6J4
 */
HWTEST_F(AudioRenderExtImplTest, InitAshmem_002, TestSize.Level1)
{
    std::string adpName;
    AudioDeviceDescriptor desc;
    AudioSampleAttributes attrs;
    sptr<IDAudioCallback> callback;
    int32_t dhId = 1;
    audioRenderlatencyImpl_ = std::make_shared<AudioRenderExtImpl>();
    audioRenderlatencyImpl_->SetAttrs(adpName, desc, attrs, callback, dhId);

    int8_t cookie = 0;
    bool support = true;
    int32_t ashmemLength = -1;
    AudioDrainNotifyType type;
    AudioSceneDescriptor scene;
    sptr<IAudioCallback> audioCallback = nullptr;
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->Pause());
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->Resume());
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->Flush());
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->TurnStandbyMode());
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->DrainBuffer(type));
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->IsSupportsPauseAndResume(support, support));
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->CheckSceneCapability(scene, support));
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->SelectScene(scene));
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->SetMute(support));
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->GetMute(support));
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->IsSupportsDrain(support));
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->RegCallback(audioCallback, cookie));
    EXPECT_EQ(HDF_FAILURE, audioRenderlatencyImpl_->InitAshmem(ashmemLength));
    audioRenderlatencyImpl_->UnInitAshmem();
}

/**
 * @tc.name: GetFadeRate_001
 * @tc.desc: Verify the GetFadeRate function.
 * @tc.type: FUNC
 * @tc.require: AR000HP6J4
 */
HWTEST_F(AudioRenderExtImplTest, GetFadeRate_001, TestSize.Level1)
{
    std::string adpName;
    AudioDeviceDescriptor desc;
    AudioSampleAttributes attr;
    sptr<IDAudioCallback> callback;
    int32_t dhId = 1;
    audioRenderlatencyImpl_ = std::make_shared<AudioRenderExtImpl>();
    audioRenderlatencyImpl_->SetAttrs(adpName, desc, attr, callback, dhId);

    float min = 0.0;
    float max  = 10.0;
    uint64_t size = 1024;
    uint32_t currentIndex = 2;
    const uint32_t durationIndex = 5;
    AudioSampleAttributes attrs;
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->GetGainThreshold(min, max));
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->SetGain(min));
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->GetGain(min));
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->GetFrameSize(size));
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->GetFrameCount(size));
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->SetSampleAttributes(attrs));
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->GetSampleAttributes(attrs));
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->GetCurrentChannelId(currentIndex));
    float fadeRate = audioRenderlatencyImpl_->GetFadeRate(currentIndex, durationIndex);
    EXPECT_LE(0, fadeRate);
    EXPECT_GE(0.5f, fadeRate);
}

/**
 * @tc.name: FadeInprocess_001
 * @tc.desc: Verify the FadeInprocess function.
 * @tc.type: FUNC
 * @tc.require: AR000HP6J4
 */
HWTEST_F(AudioRenderExtImplTest, FadeInProcess_001, TestSize.Level1)
{
    std::string adpName;
    AudioDeviceDescriptor desc;
    AudioSampleAttributes attrs;
    sptr<IDAudioCallback> callback;
    int32_t dhId = 1;
    audioRenderlatencyImpl_ = std::make_shared<AudioRenderExtImpl>();
    audioRenderlatencyImpl_->SetAttrs(adpName, desc, attrs, callback, dhId);

    uint64_t effectid = 0;
    std::string keyValueList = "keyValueList";
    const uint32_t durationFrame = 10;
    const size_t frameLength = 4096;
    int8_t* frameData = new int8_t[frameLength];
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->SetExtraParams(keyValueList));
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->GetExtraParams(keyValueList));
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->AddAudioEffect(effectid));
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->RemoveAudioEffect(effectid));
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->GetFrameBufferSize(effectid));
    EXPECT_EQ(0, audioRenderlatencyImpl_->GetVolumeInner());
    EXPECT_EQ(0, audioRenderlatencyImpl_->GetMaxVolumeInner());
    EXPECT_EQ(0, audioRenderlatencyImpl_->GetMinVolumeInner());
    audioRenderlatencyImpl_->SetVolumeInner(durationFrame);
    audioRenderlatencyImpl_->SetVolumeRangeInner(durationFrame, durationFrame);
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->FadeInProcess(durationFrame, frameData, frameLength));
    delete[] frameData;
    frameData = nullptr;
}

/**
 * @tc.name: Start_001
 * @tc.desc: Verify the Start function.
 * @tc.type: FUNC
 * @tc.require: AR000HP6J4
 */
HWTEST_F(AudioRenderExtImplTest, Start_001, TestSize.Level1)
{
    std::string adpName;
    AudioDeviceDescriptor desc;
    AudioSampleAttributes attrs;
    sptr<IDAudioCallback> callback;
    int32_t dhId = 1;
    audioRenderlatencyImpl_ = std::make_shared<AudioRenderExtImpl>();
    audioRenderlatencyImpl_->SetAttrs(adpName, desc, attrs, callback, dhId);

    audioRenderlatencyImpl_->audioExtCallback_ = sptr<IDAudioCallback>(new MockIDAudioCallback());
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->Start());
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->Stop());
}

/**
 * @tc.name: Start_002
 * @tc.desc: Verify the Start function.
 * @tc.type: FUNC
 * @tc.require: AR000HP6J4
 */
HWTEST_F(AudioRenderExtImplTest, Start_002, TestSize.Level1)
{
    std::string adpName;
    AudioDeviceDescriptor desc;
    AudioSampleAttributes attrs;
    sptr<IDAudioCallback> callback;
    int32_t dhId = 1;
    audioRenderlatencyImpl_ = std::make_shared<AudioRenderExtImpl>();
    audioRenderlatencyImpl_->SetAttrs(adpName, desc, attrs, callback, dhId);

    audioRenderlatencyImpl_->audioExtCallback_ = nullptr;
    EXPECT_EQ(HDF_FAILURE, audioRenderlatencyImpl_->Start());
}

/**
 * @tc.name: ReqMmapBuffer_001
 * @tc.desc: Verify the ReqMmapBuffer function.
 * @tc.type: FUNC
 * @tc.require: AR000HP6J4
 */
HWTEST_F(AudioRenderExtImplTest, ReqMmapBuffer_001, TestSize.Level1)
{
    std::string adpName;
    AudioDeviceDescriptor descs;
    AudioSampleAttributes attrs;
    sptr<IDAudioCallback> callback;
    int32_t dhId = 1;
    audioRenderlatencyImpl_ = std::make_shared<AudioRenderExtImpl>();
    audioRenderlatencyImpl_->SetAttrs(adpName, descs, attrs, callback, dhId);

    int32_t reqSize = 30;
    AudioMmapBufferDescriptor desc;
    EXPECT_EQ(HDF_FAILURE, audioRenderlatencyImpl_->ReqMmapBuffer(reqSize, desc));
    audioRenderlatencyImpl_->UnInitAshmem();
}

/**
 * @tc.name: ReqMmapBuffer_002
 * @tc.desc: Verify the ReqMmapBuffer function.
 * @tc.type: FUNC
 * @tc.require: AR000HP6J4
 */
HWTEST_F(AudioRenderExtImplTest, ReqMmapBuffer_002, TestSize.Level1)
{
    std::string adpName;
    AudioDeviceDescriptor descs;
    AudioSampleAttributes attrs;
    sptr<IDAudioCallback> callback;
    int32_t dhId = 1;
    audioRenderlatencyImpl_ = std::make_shared<AudioRenderExtImpl>();
    audioRenderlatencyImpl_->SetAttrs(adpName, descs, attrs, callback, dhId);

    int32_t reqSize = 30;
    AudioMmapBufferDescriptor desc;
    struct AudioSampleAttributes renderAttr = {
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
    audioRenderlatencyImpl_->devAttrs_ = renderAttr;
    audioRenderlatencyImpl_->audioExtCallback_ = sptr<IDAudioCallback>(new MockIDAudioCallback());
    EXPECT_EQ(HDF_SUCCESS, audioRenderlatencyImpl_->ReqMmapBuffer(reqSize, desc));
    audioRenderlatencyImpl_->UnInitAshmem();
}
} // namspace V1_0
} // namspace Audio
} // namspace Distributedaudio
} // namspace HDI
} // namspace OHOS
