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

#include "audio_hdi_common.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
class AudioHdiCaptureHardwareDependenceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static TestAudioManager *manager;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
};

using THREAD_FUNC = void *(*)(void *);
TestAudioManager *AudioHdiCaptureHardwareDependenceTest::manager = nullptr;

void AudioHdiCaptureHardwareDependenceTest::SetUpTestCase(void)
{
    manager = GetAudioManagerFuncs();
    ASSERT_NE(nullptr, manager);
}

void AudioHdiCaptureHardwareDependenceTest::TearDownTestCase(void) {}

void AudioHdiCaptureHardwareDependenceTest::SetUp(void)
{
    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
}
void AudioHdiCaptureHardwareDependenceTest::TearDown(void)
{
    int32_t ret = ReleaseCaptureSource(manager, adapter, capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

/**
    * @tc.name  AudioCaptureGetFrameSize_004
    * @tc.desc  Test CaptureGetFrameSize interface,return 0 if get framesize define format as different values
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, AudioCaptureGetFrameSize_004, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t size = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, capture);
    InitAttrsCapture(attrs);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_NE(HDF_SUCCESS, ret);

    ret = capture->attr.GetFrameSize(capture, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);
}
#ifndef PRODUCT_RK3568
/**
    * @tc.name  AudioCaptureGetFrameSize_005
    * @tc.desc  Test CaptureGetFrameSize interface,return 0 if get framesize define sampleRate as different values
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, AudioCaptureGetFrameSize_005, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t size = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, capture);
    InitAttrsCapture(attrs);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_NE(HDF_SUCCESS, ret);

    ret = capture->attr.GetFrameSize(capture, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);
}
#endif
/**
    * @tc.name  AudioCaptureGetFrameSize_006
    * @tc.desc  Test CaptureGetFrameSize interface,return 0 if get framesize define channelCount as different values
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, AudioCaptureGetFrameSize_006, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t size = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, capture);
    InitAttrsCapture(attrs);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_NE(HDF_SUCCESS, ret);

    ret = capture->attr.GetFrameSize(capture, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);
}
#ifndef PRODUCT_RK3568
/**
    * @tc.name  AudioCaptureGetFrameSize_007
    * @tc.desc  Test CaptureGetFrameSize interface,return 0 if get framesize define sampleRate as different values
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, AudioCaptureGetFrameSize_007, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t size = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, capture);
    InitAttrsCapture(attrs);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_NE(HDF_SUCCESS, ret);

    ret = capture->attr.GetFrameSize(capture, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);
}
#endif
/**
    * @tc.name  AudioCaptureGetFrameCount_005
    * @tc.desc  Test CaptureGetFrameCount interface,return 0 if get framesize define channelCount as different values
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, AudioCaptureGetFrameCount_005, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t count = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, capture);
    InitAttrsCapture(attrs);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_NE(HDF_SUCCESS, ret);

    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->attr.GetFrameCount(capture, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
    * @tc.name  AudioCaptureGetFrameCount_006
    * @tc.desc  Test CaptureGetFrameCount interface,return 0 if get framesize define format as different values
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, AudioCaptureGetFrameCount_006, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t count = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, capture);
    InitAttrsCapture(attrs);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_NE(HDF_SUCCESS, ret);

    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->attr.GetFrameCount(capture, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
#ifndef PRODUCT_RK3568
/**
    * @tc.name  AudioCaptureGetFrameCount_007
    * @tc.desc  Test CaptureGetFrameCount interface,return 0 if get framesize define channelCount to different values
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, AudioCaptureGetFrameCount_007, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t count = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, capture);
    InitAttrsCapture(attrs);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_NE(HDF_SUCCESS, ret);

    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->attr.GetFrameCount(capture, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
    * @tc.name  AudioCaptureGetFrameCount_008
    * @tc.desc  Test CaptureGetFrameCount interface,return 0 if get framesize define format as different values
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, AudioCaptureGetFrameCount_008, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t count = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, capture);
    InitAttrsCapture(attrs);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_NE(HDF_SUCCESS, ret);

    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->attr.GetFrameCount(capture, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
#endif
#ifndef PRODUCT_RK3568
/**
    * @tc.name  AudioCaptureGetCurrentChannelId_002
    * @tc.desc  Test GetCurrentChannelId interface,return 0 if get channelId to 1 and set channelCount to 1
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, AudioCaptureGetCurrentChannelId_002, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint32_t channelId = 0;
    uint32_t channelIdExp = 1;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, capture);
    InitAttrsCapture(attrs);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_NE(HDF_SUCCESS, ret);

    ret = capture->attr.GetCurrentChannelId(capture, &channelId);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(channelIdExp, channelId);
}
#endif
/**
    * @tc.name  AudioCaptureGetCapturePosition_009
    * @tc.desc  Test GetCapturePosition interface,return 0 if get framesize
    * define format to AUDIO_FORMAT_PCM_16_BIT
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, AudioCaptureGetCapturePosition_009, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioTimeStamp time = {
        .tvSec = 0,
        .tvNSec = 0,
    };
    ASSERT_NE(nullptr, capture);
    InitAttrsCapture(attrs);
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = SAMPLE_RATE_48000;
    ret = capture->attr.SetSampleAttributes(capture, &attrs);
    EXPECT_NE(HDF_SUCCESS, ret);
    ret = capture->attr.GetSampleAttributes(capture, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);

    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetCapturePosition(capture, &frames, &time);
    EXPECT_NE(HDF_SUCCESS, ret);
    EXPECT_EQ((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_EQ(frames, INITIAL_VALUE);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
    * @tc.name  AudioCaptureGetCapturePosition_010
    * @tc.desc  Test GetCapturePosition interface,return 0 if get framesize
    * define format to AUDIO_FORMAT_PCM_24_BIT
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, AudioCaptureGetCapturePosition_010, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {
        .tvSec = 0,
        .tvNSec = 0,
    };
    ASSERT_NE(nullptr, capture);
    InitAttrsCapture(attrs);
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    ret = capture->attr.SetSampleAttributes(capture, &attrs);
    EXPECT_NE(HDF_SUCCESS, ret);
    ret = capture->attr.GetSampleAttributes(capture, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);

    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetCapturePosition(capture, &frames, &time);
    EXPECT_NE(HDF_SUCCESS, ret);
    EXPECT_EQ((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_EQ(frames, INITIAL_VALUE);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
#ifndef PRODUCT_RK3568
/**
    * @tc.name  AudioCaptureGetCapturePosition_011
    * @tc.desc  Test GetCapturePosition interface,return 0 if get framesize define channelCount  as different values
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, AudioCaptureGetCapturePosition_011, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {
        .tvSec = 0,
        .tvNSec = 0,
    };
    ASSERT_NE(nullptr, capture);
    InitAttrsCapture(attrs);
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = SAMPLE_RATE_48000;
    ret = capture->attr.SetSampleAttributes(capture, &attrs);
    EXPECT_NE(HDF_SUCCESS, ret);
    ret = capture->attr.GetSampleAttributes(capture, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);

    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetCapturePosition(capture, &frames, &time);
    EXPECT_NE(HDF_SUCCESS, ret);
    EXPECT_EQ((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_EQ(frames, INITIAL_VALUE);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
    * @tc.name  AudioCaptureGetCapturePosition_012
    * @tc.desc  Test GetCapturePosition interface,return 0 if get framesize define channelCount to 1
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, AudioCaptureGetCapturePosition_012, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioTimeStamp time = {
        .tvSec = 0,
        .tvNSec = 0,
    };
    ASSERT_NE(nullptr, capture);
    InitAttrsCapture(attrs);
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    ret = capture->attr.SetSampleAttributes(capture, &attrs);
    EXPECT_NE(HDF_SUCCESS, ret);
    ret = capture->attr.GetSampleAttributes(capture, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);

    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetCapturePosition(capture, &frames, &time);
    EXPECT_NE(HDF_SUCCESS, ret);
    EXPECT_EQ((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_EQ(frames, INITIAL_VALUE);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
#endif
}
