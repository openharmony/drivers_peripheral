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

#include <gtest/gtest.h>
#include "hdi_service_common.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
class AudioIdlHdiCaptureHardwareDependenceTest : public testing::Test {
public:
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioCapture *capture = nullptr;
    static TestAudioManager *manager;
};

TestAudioManager *AudioIdlHdiCaptureHardwareDependenceTest::manager = nullptr;
using THREAD_FUNC = void *(*)(void *);

void AudioIdlHdiCaptureHardwareDependenceTest::SetUpTestCase(void)
{
    manager = IAudioManagerGet(IS_STUB);
    ASSERT_NE(nullptr, manager);
}

void AudioIdlHdiCaptureHardwareDependenceTest::TearDownTestCase(void)
{
    if (manager != nullptr) {
        (void)IAudioManagerRelease(manager, IS_STUB);
    }
}

void AudioIdlHdiCaptureHardwareDependenceTest::SetUp(void)
{
    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

void AudioIdlHdiCaptureHardwareDependenceTest::TearDown(void)
{
    int32_t ret = ReleaseCaptureSource(manager, adapter, capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

/**
* @tc.name  AudioCaptureSetSampleAttributes_001
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = SAMPLE_RATE_8000;
*    attrs.channelCount = 1;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureHardwareDependenceTest, AudioCaptureSetSampleAttributes_001, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, capture);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_8000);
    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name  AudioCaptureSetSampleAttributes_002
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*    attrs.sampleRate = SAMPLE_RATE_11025;
*    attrs.channelCount = 2;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureHardwareDependenceTest, AudioCaptureSetSampleAttributes_002, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, capture);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_11025);
    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_11025, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);
}
/**
* @tc.name  AudioCaptureSetSampleAttributes_003
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = SAMPLE_RATE_22050;
*    attrs.channelCount = 1;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureHardwareDependenceTest, AudioCaptureSetSampleAttributes_003, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, capture);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_22050);
    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name  AudioCaptureSetSampleAttributes_004
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*    attrs.sampleRate = SAMPLE_RATE_32000;
*    attrs.channelCount = 2;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureHardwareDependenceTest, AudioCaptureSetSampleAttributes_004, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, capture);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_32000);
    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_32000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);
}
/**
* @tc.name  AudioCaptureSetSampleAttributes_005
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = SAMPLE_RATE_44100;
*    attrs.channelCount = 1;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureHardwareDependenceTest, AudioCaptureSetSampleAttributes_005, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, capture);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_44100);
    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name  AudioCaptureSetSampleAttributes_006
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_COMMUNICATION;
*    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*    attrs.sampleRate = SAMPLE_RATE_48000;
*    attrs.channelCount = 2;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureHardwareDependenceTest, AudioCaptureSetSampleAttributes_006, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, capture);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_48000);
    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);
}
/**
* @tc.name  AudioCaptureSetSampleAttributes_008
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = SAMPLE_RATE_12000;
*    attrs.channelCount = 1;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureHardwareDependenceTest, AudioCaptureSetSampleAttributes_008, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, capture);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_12000);
    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name  AudioCaptureSetSampleAttributes_009
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*    attrs.sampleRate = SAMPLE_RATE_16000;
*    attrs.channelCount = 1;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureHardwareDependenceTest, AudioCaptureSetSampleAttributes_009, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, capture);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_16000);
    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name  AudioCaptureSetSampleAttributes_010
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = SAMPLE_RATE_24000;
*    attrs.channelCount = 2;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureHardwareDependenceTest, AudioCaptureSetSampleAttributes_010, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, capture);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_24000);
    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_24000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);
}
/**
* @tc.name  AudioCaptureSetSampleAttributes_011
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = SAMPLE_RATE_64000;
*    attrs.channelCount = 1;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureHardwareDependenceTest, AudioCaptureSetSampleAttributes_011, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, capture);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_64000);
    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name  AudioCaptureSetSampleAttributes_012
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*    attrs.sampleRate = SAMPLE_RATE_96000;
*    attrs.channelCount = 1;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureHardwareDependenceTest, AudioCaptureSetSampleAttributes_012, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, capture);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_96000);
    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name  AudioCaptureSetSampleAttributes_013
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16;
*    attrs.sampleRate = 0xFFFFFFFFu;
*    attrs.channelCount = 2;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureHardwareDependenceTest, AudioCaptureSetSampleAttributes_013, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    ASSERT_NE(nullptr, capture);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, DOUBLE_CHANNEL_COUNT, 0xFFFFFFFFu);
    ret = capture->SetSampleAttributes(capture, &attrs);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
}
/**
* @tc.name  AudioCaptureSetSampleAttributes_014
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_8/32_BIT/AAC_MAIN;
*    attrs.sampleRate = SAMPLE_RATE_8000/SAMPLE_RATE_11025/SAMPLE_RATE_22050;
*    attrs.channelCount = 1/2;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureHardwareDependenceTest, AudioCaptureSetSampleAttributes_014, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs1 = {};
    struct AudioSampleAttributes attrs2 = {};
    struct AudioSampleAttributes attrs3 = {};
    ASSERT_NE(nullptr, capture);

    InitAttrsUpdate(attrs1, AUDIO_FORMAT_PCM_8_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_8000);
    ret = capture->SetSampleAttributes(capture, &attrs1);
    EXPECT_EQ(HDF_FAILURE, ret);

    InitAttrsUpdate(attrs2, AUDIO_FORMAT_PCM_32_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_11025);
    ret = capture->SetSampleAttributes(capture, &attrs2);
#ifdef ALSA_LIB_MODE
    EXPECT_EQ(HDF_SUCCESS, ret);
#else
    EXPECT_EQ(HDF_FAILURE, ret);
#endif
    InitAttrsUpdate(attrs3, AUDIO_FORMAT_AAC_MAIN, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_22050);
    ret = capture->SetSampleAttributes(capture, &attrs3);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name  AudioCaptureSetSampleAttributes_015
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_AAC_LC/LD/ELD;
*    attrs.sampleRate = SAMPLE_RATE_32000/SAMPLE_RATE_44100/SAMPLE_RATE_48000;
*    attrs.channelCount = 1/2;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureHardwareDependenceTest, AudioCaptureSetSampleAttributes_015, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs1 = {};
    struct AudioSampleAttributes attrs2 = {};
    struct AudioSampleAttributes attrs3 = {};
    ASSERT_NE(nullptr, capture);

    InitAttrsUpdate(attrs1, AUDIO_FORMAT_AAC_LC, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_32000);
    ret = capture->SetSampleAttributes(capture, &attrs1);
    EXPECT_EQ(HDF_FAILURE, ret);

    InitAttrsUpdate(attrs2, AUDIO_FORMAT_AAC_LD, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_44100);
    ret = capture->SetSampleAttributes(capture, &attrs2);
    EXPECT_EQ(HDF_FAILURE, ret);

    InitAttrsUpdate(attrs3, AUDIO_FORMAT_AAC_ELD, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_48000);
    ret = capture->SetSampleAttributes(capture, &attrs3);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name  AudioCaptureSetSampleAttributes_016
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_AAC_HE_V1/V2
*    attrs.sampleRate = SAMPLE_RATE_8000/SAMPLE_RATE_44100;
*    attrs.channelCount = 1/2;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureHardwareDependenceTest, AudioCaptureSetSampleAttributes_016, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs1 = {};
    struct AudioSampleAttributes attrs2 = {};
    ASSERT_NE(nullptr, capture);

    InitAttrsUpdate(attrs1, AUDIO_FORMAT_AAC_HE_V1, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_8000);
    ret = capture->SetSampleAttributes(capture, &attrs1);
    EXPECT_EQ(HDF_FAILURE, ret);

    InitAttrsUpdate(attrs2, AUDIO_FORMAT_AAC_HE_V2, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_44100);
    ret = capture->SetSampleAttributes(capture, &attrs2);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name  AudioCaptureSetSampleAttributes_017
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT
*    attrs.sampleRate = SAMPLE_RATE_8000;
*    attrs.channelCount = 5;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureHardwareDependenceTest, AudioCaptureSetSampleAttributes_017, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    ASSERT_NE(nullptr, capture);
    uint32_t channelCount = 5;
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, channelCount, SAMPLE_RATE_8000);
    ret = capture->SetSampleAttributes(capture, &attrs);
    EXPECT_EQ(HDF_FAILURE, ret);
}
#ifndef ALSA_LIB_MODE
/**
* @tc.name  AudioCaptureSetSampleAttributes_018
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT
*    attrs.sampleRate = SAMPLE_RATE_8000;
*    attrs.channelCount = 2;
*    silenceThreshold = 32*1024;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureHardwareDependenceTest, AudioCaptureSetSampleAttributes_018, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    ASSERT_NE(nullptr, capture);
    uint32_t silenceThreshold = 32*1024;
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_8000, silenceThreshold);
    ret = capture->SetSampleAttributes(capture, &attrs);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name  AudioCaptureSetSampleAttributes_019
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT
*    attrs.sampleRate = SAMPLE_RATE_8000;
*    attrs.channelCount = 2;
*    silenceThreshold = 2*1024;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureHardwareDependenceTest, AudioCaptureSetSampleAttributes_019, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    ASSERT_NE(nullptr, capture);
    uint32_t silenceThreshold = 2*1024;
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, 2, SAMPLE_RATE_8000, silenceThreshold);
    ret = capture->SetSampleAttributes(capture, &attrs);
    EXPECT_EQ(HDF_FAILURE, ret);
}
#endif
/**
* @tc.name  AudioCaptureGetSampleAttributes_001
* @tc.desc  Test AudioCaptureGetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = SAMPLE_RATE_8000;
*    attrs.channelCount = 1;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureHardwareDependenceTest, AudioCaptureGetSampleAttributes_001, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, capture);
    ret = capture->GetSampleAttributes(capture, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_32000);
    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name  AudioCaptureGetFrameSize_004
* @tc.desc  Test CaptureGetFrameSize interface,return 0 if get framesize define format as different values
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureHardwareDependenceTest, AudioCaptureGetFrameSize_004, TestSize.Level1)
{
    int32_t ret;
    uint64_t size = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, capture);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_48000);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = capture->GetFrameSize(capture, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);
}
/**
* @tc.name  AudioCaptureGetFrameSize_006
* @tc.desc  Test CaptureGetFrameSize interface,return 0 if get framesize define channelCount as different values
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureHardwareDependenceTest, AudioCaptureGetFrameSize_006, TestSize.Level1)
{
    int32_t ret;
    uint64_t size = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, capture);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_44100);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_44100, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = capture->GetFrameSize(capture, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);
}
/**
* @tc.name  AudioCaptureGetFrameCount_005
* @tc.desc  Test CaptureGetFrameCount interface,return 0 if get framesize define channelCount as different values
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureHardwareDependenceTest, AudioCaptureGetFrameCount_005, TestSize.Level1)
{
    int32_t ret;
    uint64_t count = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, capture);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_8000);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_8000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetFrameCount(capture, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioCaptureGetFrameCount_006
* @tc.desc  Test CaptureGetFrameCount interface,return 0 if get framesize define format as different values
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureHardwareDependenceTest, AudioCaptureGetFrameCount_006, TestSize.Level1)
{
    int32_t ret;
    uint64_t count = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, capture);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_8000);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_8000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetFrameCount(capture, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioCaptureGetCapturePosition_009
* @tc.desc  Test GetCapturePosition interface,return 0 if get framesize define format to AUDIO_FORMAT_PCM_16_BIT
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureHardwareDependenceTest, AudioCaptureGetCapturePosition_009, TestSize.Level1)
{
    int32_t ret;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    ASSERT_NE(nullptr, capture);
    InitAttrs(attrs);
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = SAMPLE_RATE_48000;
    attrs.channelCount = 2;
    ret = capture->SetSampleAttributes(capture, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetSampleAttributes(capture, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetCapturePosition(capture, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);
    capture->Stop(capture);
}
/**
* @tc.name  AudioCaptureGetCapturePosition_010
* @tc.desc  Test GetCapturePosition interface,return 0 if get framesize define format to AUDIO_FORMAT_PCM_24_BIT
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureHardwareDependenceTest, AudioCaptureGetCapturePosition_010, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    ASSERT_NE(nullptr, capture);
    InitAttrs(attrs);
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
    attrs.sampleRate = SAMPLE_RATE_48000;
    attrs.channelCount = 2;
    ret = capture->SetSampleAttributes(capture, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetSampleAttributes(capture, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);

    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetCapturePosition(capture, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);
    capture->Stop(capture);
}
}
