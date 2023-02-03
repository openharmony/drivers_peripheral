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
class AudioHdiRenderHardwareDependenceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static TestAudioManager *manager;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
};

using THREAD_FUNC = void *(*)(void *);
TestAudioManager *AudioHdiRenderHardwareDependenceTest::manager = nullptr;

void AudioHdiRenderHardwareDependenceTest::SetUpTestCase(void)
{
    manager = GetAudioManagerFuncs();
    ASSERT_NE(nullptr, manager);
}

void AudioHdiRenderHardwareDependenceTest::TearDownTestCase(void) {}
void AudioHdiRenderHardwareDependenceTest::SetUp(void)
{
    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);
}
void AudioHdiRenderHardwareDependenceTest::TearDown(void)
{
    int32_t ret = ReleaseRenderSource(manager, adapter, render);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

HWTEST_F(AudioHdiRenderHardwareDependenceTest, AudioRenderGetFrameSize_004, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t size = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_48000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_NE(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = render->attr.GetFrameSize(render, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);
}
#ifndef PRODUCT_RK3568
/**
    * @tc.name  AudioRenderGetFrameSize_005
    * @tc.desc  Test RenderGetFrameSize interface,return 0 if get framesize define sampleRate as different values
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, AudioRenderGetFrameSize_005, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t size = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_48000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_NE(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_NE(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = render->attr.GetFrameSize(render, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);
}
#endif
/**
    * @tc.name  AudioRenderGetFrameSize_006
    * @tc.desc  Test RenderGetFrameSize interface,return 0 if get framesize define channelCount as different values
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, AudioRenderGetFrameSize_006, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t size = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_44100);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_NE(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_NE(SAMPLE_RATE_44100, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = render->attr.GetFrameSize(render, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);
}
#ifndef PRODUCT_RK3568
/**
    * @tc.name  AudioRenderGetFrameSize_007
    * @tc.desc  Test RenderGetFrameSize interface,return 0 if get framesize define sampleRate as different values
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, AudioRenderGetFrameSize_007, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t size = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_48000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_NE(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_NE(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = render->attr.GetFrameSize(render, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);
}
#endif
/**
    * @tc.name  AudioRenderGetFrameCount_004
    * @tc.desc  Test RenderGetFrameCount interface,return 0 if get framesize define channelCount as different values
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, AudioRenderGetFrameCount_004, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t count = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_8000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_NE(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_NE(SAMPLE_RATE_8000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetFrameCount(render, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
    * @tc.name  AudioRenderGetFrameCount_005
    * @tc.desc  Test RenderGetFrameCount interface,return 0 if get framesize define format as different values
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, AudioRenderGetFrameCount_005, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t count = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_8000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_NE(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_NE(SAMPLE_RATE_8000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetFrameCount(render, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
#ifndef PRODUCT_RK3568
/**
    * @tc.name  AudioRenderGetFrameCount_006
    * @tc.desc  Test RenderGetFrameCount interface,return 0 if get framesize define channelCount to different values
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, AudioRenderGetFrameCount_006, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t count = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_44100);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_NE(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_NE(SAMPLE_RATE_44100, attrsValue.sampleRate);
    EXPECT_NE(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetFrameCount(render, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
    * @tc.name  AudioRenderGetFrameCount_007
    * @tc.desc  Test RenderGetFrameCount interface,return 0 if get framesize define format as different values
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, AudioRenderGetFrameCount_007, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t count = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_32000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_NE(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_NE(SAMPLE_RATE_32000, attrsValue.sampleRate);
    EXPECT_NE(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetFrameCount(render, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
#endif
#ifndef PRODUCT_RK3568
/**
    * @tc.name  AudioRenderGetCurrentChannelId_002
    * @tc.desc  Test GetCurrentChannelId interface,return 0 if get channelId to 1 and set channelCount to 1
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, AudioRenderGetCurrentChannelId_002, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
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

    ret = render->attr.GetCurrentChannelId(render, &channelId);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_NE(channelIdExp, channelId);
}
#endif
/**
    * @tc.name  AudioRenderGetRenderPosition_009
    * @tc.desc  Test GetRenderPosition interface,return 0 if get framesize define format to AUDIO_FORMAT_PCM_16_BIT
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, AudioRenderGetRenderPosition_009, TestSize.Level1)
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
    ASSERT_NE(nullptr, render);
    InitAttrs(attrs);
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = SAMPLE_RATE_48000;
    attrs.channelCount = DOUBLE_CHANNEL_COUNT;
    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_NE(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_NE(HDF_SUCCESS, ret);
    EXPECT_EQ((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_EQ(frames, INITIAL_VALUE);
    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
    * @tc.name  AudioRenderGetRenderPosition_011
    * @tc.desc  Test GetRenderPosition interface,return 0 if get framesize define channelCount  as different values
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, AudioRenderGetRenderPosition_010, TestSize.Level1)
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
    ASSERT_NE(nullptr, render);
    InitAttrs(attrs);
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = SAMPLE_RATE_48000;
    attrs.channelCount = SINGLE_CHANNEL_COUNT;
    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_NE(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_NE(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_NE(HDF_SUCCESS, ret);
    EXPECT_EQ((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_EQ(frames, INITIAL_VALUE);
    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
    * @tc.name  AudioRenderGetRenderPosition_012
    * @tc.desc  Test GetRenderPosition interface,return 0 if get framesize define channelCount to 1
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, AudioRenderGetRenderPosition_011, TestSize.Level1)
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
    ASSERT_NE(nullptr, render);
    InitAttrs(attrs);
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
    attrs.sampleRate = SAMPLE_RATE_48000;
    attrs.channelCount = SINGLE_CHANNEL_COUNT;
    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_NE(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_NE(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_NE(HDF_SUCCESS, ret);
    EXPECT_EQ((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_EQ(frames, INITIAL_VALUE);
    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
}