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
class AudioIdlHdiRenderHardwareDependenceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    struct IAudioRender *render = nullptr;
    static TestAudioManager *manager;
    struct IAudioAdapter *adapter = nullptr;
};

TestAudioManager *AudioIdlHdiRenderHardwareDependenceTest::manager = nullptr;
using THREAD_FUNC = void *(*)(void *);

void AudioIdlHdiRenderHardwareDependenceTest::SetUpTestCase(void)
{
    manager = IAudioManagerGet(IS_STUB);
    ASSERT_NE(nullptr, manager);
}

void AudioIdlHdiRenderHardwareDependenceTest::TearDownTestCase(void)
{
    if (manager != nullptr) {
        (void)IAudioManagerRelease(manager, IS_STUB);
    }
}

void AudioIdlHdiRenderHardwareDependenceTest::SetUp(void)
{
    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

void AudioIdlHdiRenderHardwareDependenceTest::TearDown(void)
{
    int32_t ret = ReleaseRenderSource(manager, adapter, render);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

/**
    * @tc.name  AudioRenderGetFrameSize_004
    * @tc.desc  Test RenderGetFrameSize interface,return 0 if get framesize define format as different values
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderGetFrameSize_004, TestSize.Level1)
{
    int32_t ret;
    uint64_t size = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);

    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_48000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = render->GetFrameSize(render, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);
}
/**
    * @tc.name  AudioRenderGetFrameSize_005
    * @tc.desc  Test RenderGetFrameSize interface,return 0 if get framesize define sampleRate as different values
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderGetFrameSize_005, TestSize.Level1)
{
    int32_t ret;
    uint64_t size = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};

    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_48000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = render->GetFrameSize(render, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);
}
/**
    * @tc.name  AudioRenderGetFrameSize_006
    * @tc.desc  Test RenderGetFrameSize interface,return 0 if get framesize define channelCount as different values
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderGetFrameSize_006, TestSize.Level1)
{
    int32_t ret;
    uint64_t size = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_44100);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_44100, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = render->GetFrameSize(render, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);
}
/**
    * @tc.name  AudioRenderGetFrameSize_007
    * @tc.desc  Test RenderGetFrameSize interface,return 0 if get framesize define sampleRate as different values
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderGetFrameSize_007, TestSize.Level1)
{
    int32_t ret;
    uint64_t size = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, 1, SAMPLE_RATE_48000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = render->GetFrameSize(render, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);
}
/**
    * @tc.name  AudioRenderGetFrameCount_004
    * @tc.desc  Test RenderGetFrameCount interface,return 0 if get framesize define channelCount as different values
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderGetFrameCount_004, TestSize.Level1)
{
    int32_t ret;
    uint64_t count = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_8000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_8000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetFrameCount(render, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
    * @tc.name  AudioRenderGetFrameCount_005
    * @tc.desc  Test RenderGetFrameCount interface,return 0 if get framesize define format as different values
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderGetFrameCount_005, TestSize.Level1)
{
    int32_t ret;
    uint64_t count = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_8000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_8000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetFrameCount(render, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
    * @tc.name  AudioRenderGetFrameCount_006
    * @tc.desc  Test RenderGetFrameCount interface,return 0 if get framesize define channelCount to different values
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderGetFrameCount_006, TestSize.Level1)
{
    int32_t ret;
    uint64_t count = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_44100);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_44100, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetFrameCount(render, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);
    render->Stop(render);
}
/**
    * @tc.name  AudioRenderGetFrameCount_007
    * @tc.desc  Test RenderGetFrameCount interface,return 0 if get framesize define format as different values
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderGetFrameCount_007, TestSize.Level1)
{
    int32_t ret;
    uint64_t count = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_32000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_32000, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetFrameCount(render, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);
    render->Stop(render);
}
/**
* @tc.name  AudioRenderSetSampleAttributes_001
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*     attrs.sampleRate = AUDIO_SAMPLE_RATE_MASK_8000;
*     attrs.channelCount = 1;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderSetSampleAttributes_001, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_8000);

    ret = render->SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    struct AudioSampleAttributes attrsValue = {};
    ret = render->GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_8000, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);
}
/**
* @tc.name  AudioRenderSetSampleAttributes_002
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*     attrs.sampleRate = SAMPLE_RATE_11025;
*     attrs.channelCount = 2;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderSetSampleAttributes_002, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_11025);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_11025, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);
}
/**
* @tc.name  AudioRenderSetSampleAttributes_003
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*     attrs.sampleRate = SAMPLE_RATE_22050;
*     attrs.channelCount = 1;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderSetSampleAttributes_003, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_22050);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_22050, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);
}
/**
* @tc.name  AudioRenderSetSampleAttributes_004
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*     attrs.sampleRate = SAMPLE_RATE_32000;
*     attrs.channelCount = 2;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderSetSampleAttributes_004, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_32000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_32000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);
}
/**
* @tc.name  AudioRenderSetSampleAttributes_005
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*     attrs.sampleRate = SAMPLE_RATE_44100;
*     attrs.channelCount = 1;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderSetSampleAttributes_005, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_44100);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_44100, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);
}
/**
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_COMMUNICATION;
*     attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*     attrs.sampleRate = SAMPLE_RATE_48000;
*     attrs.channelCount = 2;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderSetSampleAttributes_006, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_48000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);
}
/**
* @tc.name  AudioRenderSetSampleAttributes_008
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*     attrs.sampleRate = SAMPLE_RATE_12000;
*     attrs.channelCount = 1;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderSetSampleAttributes_008, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_12000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_12000, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);
}
/**
* @tc.name  AudioRenderSetSampleAttributes_009
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*     attrs.sampleRate = SAMPLE_RATE_16000;
*     attrs.channelCount = 1;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderSetSampleAttributes_009, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_16000);
    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_16000, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);
}
/**
* @tc.name  AudioRenderSetSampleAttributes_010
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*     attrs.sampleRate = SAMPLE_RATE_24000;
*     attrs.channelCount = 2;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderSetSampleAttributes_010, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);

    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_24000);
    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_24000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);
}
/**
* @tc.name  AudioRenderSetSampleAttributes_011
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*     attrs.sampleRate = SAMPLE_RATE_64000;
*     attrs.channelCount = 2;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderSetSampleAttributes_011, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_64000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_64000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);
}
/**
* @tc.name  AudioRenderSetSampleAttributes_012
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*     attrs.sampleRate = SAMPLE_RATE_96000;
*     attrs.channelCount = 1;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderSetSampleAttributes_012, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_96000);
    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_96000, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);
}
/**
* @tc.name  AudioRenderSetSampleAttributes_013
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*     attrs.sampleRate = 0xFFFFFFFFu;
*     attrs.channelCount = 2;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderSetSampleAttributes_013, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, DOUBLE_CHANNEL_COUNT, 0xFFFFFFFFu);

    ret = render->SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
}
/**
* @tc.name  AudioRenderSetSampleAttributes_014
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_PCM_8/32_BIT/AAC_MAIN;
*     attrs.sampleRate = SAMPLE_RATE_8000/SAMPLE_RATE_11025/SAMPLE_RATE_22050;
*     attrs.channelCount = 1/2;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderSetSampleAttributes_014, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs1 = {};
    struct AudioSampleAttributes attrs2 = {};
    struct AudioSampleAttributes attrs3 = {};
    ASSERT_NE(nullptr, render);

    InitAttrsUpdate(attrs1, AUDIO_FORMAT_PCM_8_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_8000);
    ret = render->SetSampleAttributes(render, &attrs1);
    EXPECT_EQ(HDF_FAILURE, ret);

    InitAttrsUpdate(attrs2, AUDIO_FORMAT_PCM_32_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_11025);
    ret = render->SetSampleAttributes(render, &attrs2);
#ifdef ALSA_LIB_MODE
    EXPECT_EQ(HDF_SUCCESS, ret);
#else
    EXPECT_EQ(HDF_FAILURE, ret);
#endif
    InitAttrsUpdate(attrs3, AUDIO_FORMAT_AAC_MAIN, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_22050);
    ret = render->SetSampleAttributes(render, &attrs3);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name  AudioRenderSetSampleAttributes_015
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_AAC_LC/LD/ELD;
*     attrs.sampleRate = SAMPLE_RATE_32000/SAMPLE_RATE_44100/SAMPLE_RATE_48000;
*     attrs.channelCount = 1/2;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderSetSampleAttributes_015, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs1 = {};
    struct AudioSampleAttributes attrs2 = {};
    struct AudioSampleAttributes attrs3 = {};
    ASSERT_NE(nullptr, render);

    InitAttrsUpdate(attrs1, AUDIO_FORMAT_AAC_LC, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_32000);
    ret = render->SetSampleAttributes(render, &attrs1);
    EXPECT_EQ(HDF_FAILURE, ret);

    InitAttrsUpdate(attrs2, AUDIO_FORMAT_AAC_LD, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_44100);
    ret = render->SetSampleAttributes(render, &attrs2);
    EXPECT_EQ(HDF_FAILURE, ret);

    InitAttrsUpdate(attrs3, AUDIO_FORMAT_AAC_ELD, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_48000);
    ret = render->SetSampleAttributes(render, &attrs3);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name  AudioRenderSetSampleAttributes_016
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_AAC_HE_V1/V2
*     attrs.sampleRate = SAMPLE_RATE_8000/SAMPLE_RATE_44100;
*     attrs.channelCount = 1/2;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderSetSampleAttributes_016, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs1 = {};
    struct AudioSampleAttributes attrs2 = {};
    ASSERT_NE(nullptr, render);

    InitAttrsUpdate(attrs1, AUDIO_FORMAT_AAC_HE_V1, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_8000);
    ret = render->SetSampleAttributes(render, &attrs1);
    EXPECT_EQ(HDF_FAILURE, ret);

    InitAttrsUpdate(attrs2, AUDIO_FORMAT_AAC_HE_V2, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_44100);
    ret = render->SetSampleAttributes(render, &attrs2);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name  AudioRenderSetSampleAttributes_017
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_PCM_16_BIT
*     attrs.sampleRate = SAMPLE_RATE_8000;
*     attrs.channelCount = 5;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderSetSampleAttributes_017, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    ASSERT_NE(nullptr, render);
    uint32_t silenceThreshold = 5;
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, silenceThreshold, SAMPLE_RATE_8000);
    ret = render->SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name  AudioRenderGetSampleAttributes_001
* @tc.desc    Test RenderGetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*     attrs.sampleRate = SAMPLE_RATE_8000;
*     attrs.channelCount = 1;
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderGetSampleAttributes_001, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);

    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_8000);
    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_8000, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);
}
/**
    * @tc.name  AudioRenderGetCurrentChannelId_003
    * @tc.desc    Test GetCurrentChannelId interface,return 0 if get channelId to 1 and set channelCount to 1
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderGetCurrentChannelId_002, TestSize.Level1)
{
    int32_t ret;
    uint32_t channelId = 0;
    uint32_t channelIdExp = 1;
    uint32_t channelCountExp = 1;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};

    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_32000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(channelCountExp, attrs.channelCount);

    ret = render->GetCurrentChannelId(render, &channelId);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(channelIdExp, channelId);
}
/**
    * @tc.name  AudioRenderGetRenderPosition_009
    * @tc.desc    Test GetRenderPosition interface,return 0 if get framesize define format to AUDIO_FORMAT_PCM_16_BIT
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderGetRenderPosition_009, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};

    ASSERT_NE(nullptr, render);
    InitAttrs(attrs);
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = SAMPLE_RATE_48000;
    attrs.channelCount = 2;
    ret = render->SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);
    render->Stop(render);
}
/**
    * @tc.name  AudioRenderGetRenderPosition_010
    * @tc.desc    Test GetRenderPosition interface,return 0 if get framesize define format to AUDIO_FORMAT_PCM_24_BIT
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderGetRenderPosition_010, TestSize.Level1)
{
    int32_t ret;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};

    ASSERT_NE(nullptr, render);
    InitAttrs(attrs);
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
    attrs.sampleRate = SAMPLE_RATE_48000;
    attrs.channelCount = 2;
    ret = render->SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);
    render->Stop(render);
}
/**
    * @tc.name  AudioRenderGetRenderPosition_011
    * @tc.desc    Test GetRenderPosition interface,return 0 if get framesize define channelCount as different values
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderGetRenderPosition_011, TestSize.Level1)
{
    int32_t ret;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};

    ASSERT_NE(nullptr, render);
    InitAttrs(attrs);
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = SAMPLE_RATE_48000;
    attrs.channelCount = 1;
    ret = render->SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);
    render->Stop(render);
}
/**
    * @tc.name  AudioRenderGetRenderPosition_012
    * @tc.desc    Test GetRenderPosition interface,return 0 if get framesize define channelCount to 1
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderGetRenderPosition_012, TestSize.Level1)
{
    int32_t ret;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};

    ASSERT_NE(nullptr, render);
    InitAttrs(attrs);
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
    attrs.sampleRate = SAMPLE_RATE_48000;
    attrs.channelCount = 1;
    ret = render->SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);
    render->Stop(render);
}
/**
* @tc.name  AudioRenderGetMmapPosition_002
* @tc.desc    Test GetMmapPosition interface,return 0 if Getting position successfully.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderGetMmapPosition_002, TestSize.Level1)
{
    int32_t ret;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    ASSERT_NE(nullptr, render);
    struct PrepareAudioPara audiopara = {
        .path = LOW_LATENCY_AUDIO_FILE.c_str(), .render = render
    };
    InitAttrs(audiopara.attrs);
    audiopara.attrs.format = AUDIO_FORMAT_PCM_24_BIT;
    audiopara.attrs.channelCount = 1;
    ret = audiopara.render->SetSampleAttributes(audiopara.render, &(audiopara.attrs));
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)PlayMapAudioFile, &audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    void *result = nullptr;
    pthread_join(audiopara.tids, &result);
    EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
    ret = audiopara.render->GetMmapPosition(audiopara.render, &frames, &(audiopara.time));
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT((audiopara.time.tvSec) * SECTONSEC + (audiopara.time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);
    audiopara.render->Stop(audiopara.render);
}
/**
    * @tc.name  AudioRenderSetChannelMode_001
    * @tc.desc    Test SetChannelMode interface,return 0 if set channel mode to different enumeration values
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderSetChannelMode_001, TestSize.Level1)
{
    int32_t ret;
    AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;
    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->SetChannelMode(render, mode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetChannelMode(render, &mode);
    EXPECT_EQ(HDF_SUCCESS, ret);
#ifndef ALSA_LIB_MODE
    EXPECT_EQ(AUDIO_CHANNEL_NORMAL, mode);
    AudioChannelMode modeOne = AUDIO_CHANNEL_BOTH_LEFT;
    AudioChannelMode modeSec = AUDIO_CHANNEL_BOTH_RIGHT;
    AudioChannelMode modeTrd = AUDIO_CHANNEL_EXCHANGE;
    ret = render->SetChannelMode(render, modeOne);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetChannelMode(render, &modeOne);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_BOTH_LEFT, modeOne);
    ret = render->SetChannelMode(render, modeSec);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetChannelMode(render, &modeSec);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_BOTH_RIGHT, modeSec);
    ret = render->SetChannelMode(render, modeTrd);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetChannelMode(render, &modeTrd);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_EXCHANGE, modeTrd);
#endif
    render->Stop(render);
}
#ifndef ALSA_LIB_MODE
/**
    * @tc.name  AudioRenderSetChannelMode_002
    * @tc.desc    Test SetChannelMode interface,return 0 if set channel mode to different values
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, AudioRenderSetChannelMode_002, TestSize.Level1)
{
    int32_t ret;
    AudioChannelMode mode = AUDIO_CHANNEL_MIX;
    AudioChannelMode modeOne = AUDIO_CHANNEL_LEFT_MUTE;
    AudioChannelMode modeSec = AUDIO_CHANNEL_RIGHT_MUTE;
    AudioChannelMode modeTrd = AUDIO_CHANNEL_BOTH_MUTE;
    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->SetChannelMode(render, mode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetChannelMode(render, &mode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_MIX, mode);
    ret = render->SetChannelMode(render, modeOne);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetChannelMode(render, &modeOne);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_LEFT_MUTE, modeOne);
    ret = render->SetChannelMode(render, modeSec);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetChannelMode(render, &modeSec);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_RIGHT_MUTE, modeSec);
    ret = render->SetChannelMode(render, modeTrd);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetChannelMode(render, &modeTrd);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_BOTH_MUTE, modeTrd);
    render->Stop(render);
}
#endif
}
