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
class AudioIdlHdiRenderTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    struct IAudioRender *render = nullptr;
    static TestAudioManager *manager;
    struct IAudioAdapter *adapter = nullptr;
    uint32_t renderId_ = 0;
};

TestAudioManager *AudioIdlHdiRenderTest::manager = nullptr;
using THREAD_FUNC = void *(*)(void *);

void AudioIdlHdiRenderTest::SetUpTestCase(void)
{
    manager = IAudioManagerGet(IS_STUB);
    ASSERT_NE(nullptr, manager);
}

void AudioIdlHdiRenderTest::TearDownTestCase(void)
{
    if (manager != nullptr) {
        (void)IAudioManagerRelease(manager, IS_STUB);
    }
}

void AudioIdlHdiRenderTest::SetUp(void)
{
    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render, &renderId_);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

void AudioIdlHdiRenderTest::TearDown(void)
{
    int32_t ret = ReleaseRenderSource(manager, adapter, render, renderId_);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

/**
* @tc.name  AudioRenderetLatency_001
* @tc.desc  test RenderGetLatency interface, return 0 if GetLatency successful
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderGetLatency_001, TestSize.Level0)
{
    int32_t ret;
    uint32_t latencyTime = 0;
    uint32_t expectLatency = 0;
    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->GetLatency(render, &latencyTime);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_LT(expectLatency, latencyTime);
    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioRenderGetLatencyNull_002
* @tc.desc    test RenderGetLatency interface, return -3/-4 if Setting parameters render is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderGetLatencyNull_002, TestSize.Level1)
{
    int32_t ret;
    uint32_t latencyTime = 0;
    struct IAudioRender *renderNull = nullptr;
    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->GetLatency(renderNull, &latencyTime);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioRenderGetLatencyNull_003
* @tc.desc    test RenderGetLatency interface,return -3 if Setting parameters ms is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderGetLatencyNull_003, TestSize.Level1)
{
    int32_t ret;
    uint32_t *latencyTime = nullptr;
    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->GetLatency(render, latencyTime);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioAudioRenderFrame_001
* @tc.desc  test RenderFrame interface,Returns 0 if the data is written successfully
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderFrame_001, TestSize.Level0)
{
    int32_t ret;
    uint64_t requestBytes = 0;
    uint64_t replyBytes = 0;
    char *frame = nullptr;
    ASSERT_NE(nullptr, render);
    ret = render->Start(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = RenderFramePrepare(AUDIO_FILE, frame, requestBytes);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->RenderFrame(render, (int8_t *)frame, requestBytes, &replyBytes);
    EXPECT_EQ(HDF_SUCCESS, ret);

    render->Stop(render);
    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}
/**
* @tc.name  AudioRenderFrameNull_002
* @tc.desc  Test RenderFrame interface,Returns -3/-4 if the incoming parameter render is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderFrameNull_002, TestSize.Level1)
{
    int32_t ret;
    uint64_t requestBytes = 0;
    uint64_t replyBytes = 0;
    struct IAudioRender *renderNull = nullptr;
    char *frame = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->Start(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = RenderFramePrepare(AUDIO_FILE, frame, requestBytes);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->RenderFrame(renderNull, (int8_t *)frame, requestBytes, &replyBytes);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);

    render->Stop(render);
    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}
/**
* @tc.name  AudioAudioRenderFrameNull_003
* @tc.desc  Test RenderFrame interface,Returns -3 if the incoming parameter frame is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderFrameNull_003, TestSize.Level1)
{
    int32_t ret;
    uint64_t requestBytes = 0;
    uint64_t replyBytes = 0;
    char *frame = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->Start(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->RenderFrame(render, (int8_t *)frame, requestBytes, &replyBytes);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    render->Stop(render);
}
/**
* @tc.name  AudioAudioRenderFrameNull_004
* @tc.desc  Test RenderFrame interface,Returns -3 if the incoming parameter replyBytes is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderFrameNull_004, TestSize.Level1)
{
    int32_t ret;
    uint64_t requestBytes = 0;
    char *frame = nullptr;
    uint64_t *replyBytes = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->Start(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = RenderFramePrepare(AUDIO_FILE, frame, requestBytes);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->RenderFrame(render, (int8_t *)frame, requestBytes, replyBytes);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    render->Stop(render);
    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}
/**
* @tc.name  AudioAudioRenderFrame_005
* @tc.desc  Test RenderFrame interface,Returns -3 if without calling interface renderstart
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderFrame_005, TestSize.Level0)
{
    int32_t ret;
    uint64_t replyBytes = 0;
    uint64_t requestBytes = 0;
    char *frame = nullptr;

    ASSERT_NE(nullptr, render);
    ret = RenderFramePrepare(AUDIO_FILE, frame, requestBytes);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->RenderFrame(render, (int8_t *)frame, requestBytes, &replyBytes);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_SUCCESS);

    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}

/**
* @tc.name  AudioRenderGetRenderPosition_001
* @tc.desc    Test GetRenderPosition interface,Returns 0 if get RenderPosition during playing.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderGetRenderPosition_001, TestSize.Level0)
{
    int32_t ret;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    ASSERT_NE(nullptr, render);
    struct PrepareAudioPara audiopara = {
        .path = AUDIO_FILE.c_str(), .render = render
    };

    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);
    sleep(1);
    if (audiopara.render != nullptr) {
        ret = audiopara.render->GetRenderPosition(audiopara.render, &frames, &time);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
        EXPECT_GT(frames, INITIAL_VALUE);
    }

    ret = ThreadRelease(audiopara);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioRenderGetRenderPosition_002
* @tc.desc     Test GetRenderPosition interface,Returns 0 if get RenderPosition after Pause and resume during playing
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderGetRenderPosition_002, TestSize.Level0)
{
    int32_t ret;
    int64_t timeExp = 0;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    ASSERT_NE(nullptr, render);
    struct PrepareAudioPara audiopara = {
        .path = AUDIO_FILE.c_str(), .render = render
    };

    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);
    sleep(1);
    if (audiopara.render != nullptr) {
        FrameStatus(0);
        usleep(1000);
        ret = audiopara.render->Pause(audiopara.render);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
        ret = audiopara.render->GetRenderPosition(audiopara.render, &frames, &time);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
        EXPECT_GT(frames, INITIAL_VALUE);
        usleep(1000);
        ret = audiopara.render->Resume(audiopara.render);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
        FrameStatus(1);
        ret = audiopara.render->GetRenderPosition(audiopara.render, &frames, &time);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
        EXPECT_GT(frames, INITIAL_VALUE);
    }

    ret = ThreadRelease(audiopara);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioRenderGetRenderPosition_003
* @tc.desc    Test GetRenderPosition interface,Returns 0 if get RenderPosition after stop
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderGetRenderPosition_003, TestSize.Level0)
{
    int32_t ret;
    int64_t timeExp = 0;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->GetRenderPosition(render, &frames, &time);
    if (ret == HDF_SUCCESS) {
        EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
        EXPECT_GT(frames, INITIAL_VALUE);
    }
}
/**
    * @tc.name  AudioRenderGetRenderPosition_004
    * @tc.desc    Test RenderGetRenderPosition interface, return 0 if setting the parameter render is legal
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderGetRenderPosition_004, TestSize.Level0)
{
    int32_t ret;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};

    ASSERT_NE(nullptr, render);
    ret = render->GetRenderPosition(render, &frames, &time);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_INVALID_PARAM);
    EXPECT_EQ((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
}
/**
    * @tc.name  AudioRenderGetRenderPositionNull_005
    * @tc.desc    Test RenderGetRenderPosition interface, return -3/-4 if setting the parameter render is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderGetRenderPositionNull_005, TestSize.Level1)
{
    int32_t ret;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {};
    struct IAudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->GetRenderPosition(renderNull, &frames, &time);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
}
/**
    * @tc.name  AudioRenderGetRenderPositionNull_006
    * @tc.desc    Test RenderGetRenderPosition interface, return -3 if setting the parameter frames is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderGetRenderPositionNull_006, TestSize.Level1)
{
    int32_t ret;
    uint64_t *framesNull = nullptr;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};

    ASSERT_NE(nullptr, render);
    ret = render->GetRenderPosition(render, framesNull, &time);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**
    * @tc.name  AudioRenderGetRenderPositionNull_007
    * @tc.desc    Test RenderGetRenderPosition interface, return -3 if setting the parameter time is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderGetRenderPositionNull_007, TestSize.Level1)
{
    int32_t ret;
    uint64_t frames = 0;
    struct AudioTimeStamp *timeNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->GetRenderPosition(render, &frames, timeNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**
    * @tc.name  AudioRenderGetRenderPosition_008
    * @tc.desc    Test RenderGetRenderPosition interface, return 0 if the GetRenderPosition was called twice
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderGetRenderPosition_008, TestSize.Level0)
{
    int32_t ret;
    int64_t timeExp = 0;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetRenderPosition(render, &frames, &time);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_INVALID_PARAM);
    ret = render->GetRenderPosition(render, &frames, &time);
    if (ret == HDF_SUCCESS) {
        EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
        EXPECT_GT(frames, INITIAL_VALUE);
    }
    render->Stop(render);
}
/**
    * @tc.name  AudioRenderSetRenderSpeed_001
    * @tc.desc    Test SetRenderSpeed interface,return -2 if setting RenderSpeed
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderSetRenderSpeed_001, TestSize.Level0)
{
    int32_t ret;
    float speed = 100;
    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_FAILURE);

    ret = render->SetRenderSpeed(render, speed);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
    render->Stop(render);
}
/**
    * @tc.name  AudioRenderSetRenderSpeedNull_002
    * @tc.desc    Test SetRenderSpeed interface,return -3/-4 if the incoming parameter handle is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderSetRenderSpeedNull_002, TestSize.Level1)
{
    int32_t ret;
    float speed = 0;
    struct IAudioRender *renderNull = nullptr;
    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->SetRenderSpeed(renderNull, speed);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
    render->Stop(render);
}
/**
    * @tc.name  AudioRenderGetRenderSpeed_001
    * @tc.desc    Test GetRenderSpeed interface,return -2 if getting RenderSpeed
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderGetRenderSpeed_001, TestSize.Level0)
{
    int32_t ret;
    float speed = 0;
    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetRenderSpeed(render, &speed);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
    render->Stop(render);
}
/**
    * @tc.name  AudioRenderGetRenderSpeedNull_002
    * @tc.desc    Test GetRenderSpeed interface,return -3/-4 if the incoming parameter handle is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderGetRenderSpeedNull_002, TestSize.Level1)
{
    int32_t ret;
    struct IAudioRender *renderNull = nullptr;
    float speed = 0;
    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->GetRenderSpeed(renderNull, &speed);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
    render->Stop(render);
}
#ifdef AUDIO_ADM_PASSTHROUGH
/**
    * @tc.name  AudioRenderGetRenderSpeedNull_003
    * @tc.desc    Test GetRenderSpeed interface,return -3/-4 if the incoming parameter speed is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderGetRenderSpeedNull_003, TestSize.Level1)
{
    int32_t ret;
    float *speedNull = nullptr;
    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->GetRenderSpeed(render, speedNull);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
    render->Stop(render);
}
#endif
#ifdef AUDIO_ADM_PASSTHROUGH
/**
* @tc.name  AudioRenderRegCallback_001
* @tc.desc    Test AudioRenderTurnStandbyMode interface,return 0 if the interface use correctly.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderRegCallback_001, TestSize.Level0)
{
    int32_t ret;

    ASSERT_NE(nullptr, render);
    struct IAudioCallback audioCallBack;
    audioCallBack.RenderCallback = AudioRenderCallback;
    ret = render->RegCallback(render, &audioCallBack, 1);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->Flush(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = CheckFlushValue();
    EXPECT_EQ(HDF_SUCCESS, ret);
}
#ifndef ALSA_LIB_MODE
/**
* @tc.name  AudioRenderRegCallback_002
* @tc.desc    Test AudioRenderRegCallback interface,return 0 if the interface use correctly.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderRegCallback_002, TestSize.Level0)
{
    int32_t ret;
    struct AudioSampleAttributes attrs;
    struct AudioHeadInfo headInfo;
    ASSERT_NE(nullptr, render);
    char absPath[PATH_MAX] = {0};
    realpath(AUDIO_FILE.c_str(), absPath);
    ASSERT_NE(realpath(AUDIO_FILE.c_str(), absPath), nullptr);

    FILE *file = fopen(absPath, "rb");
    ASSERT_NE(file, nullptr);
    ret = WavHeadAnalysis(headInfo, file, attrs);
    if (ret < 0) {
        fclose(file);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    struct IAudioCallback audioCallBack;
    audioCallBack.RenderCallback = AudioRenderCallback;
    ret = render->RegCallback(render, &audioCallBack, 1);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = FrameStart(headInfo, render, file, attrs);
    if (ret < 0) {
        fclose(file);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = CheckWriteCompleteValue();
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = CheckRenderFullValue();
    EXPECT_EQ(HDF_SUCCESS, ret);
    fclose(file);
}
#endif
/**
* @tc.name  AudioRenderRegCallback_003
* @tc.desc    Test AudioRenderRegCallback interface,return 0 if setting input paramter self is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderRegCallback_003, TestSize.Level0)
{
    int32_t ret;
    struct IAudioRender *renderNull = nullptr;
    ASSERT_NE(nullptr, render);
    struct IAudioCallback audioCallBack;
    audioCallBack.RenderCallback = AudioRenderCallback;

    ret = render->RegCallback(renderNull, &audioCallBack, 1);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**
* @tc.name  AudioRenderRegCallback_004
* @tc.desc    Test AudioRenderRegCallback interface,return -3 if setting input paramter IAudioCallback is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderRegCallback_004, TestSize.Level0)
{
    int32_t ret;
    struct IAudioCallback *AudioRenderCallbackNull = nullptr;
    ASSERT_NE(nullptr, render);

    ret = render->RegCallback(render, AudioRenderCallbackNull, 1);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**
* @tc.name  AudioRenderRegCallback_005
* @tc.desc    Test AudioRenderRegCallback interface,return -3 if setting input paramter callback function is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderRegCallback_005, TestSize.Level0)
{
    int32_t ret;
    ASSERT_NE(nullptr, render);
    struct IAudioCallback audioCallBack;
    audioCallBack.RenderCallback = nullptr;
    ret = render->RegCallback(render, &audioCallBack, 1);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
#endif
/**
    * @tc.name  AudioRenderSetChannelMode_003
    * @tc.desc    Test SetChannelMode interface,return 0 if set channel mode after render object is created
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderSetChannelMode_003, TestSize.Level0)
{
    int32_t ret;
    AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;
    ASSERT_NE(nullptr, render);

    ret = render->SetChannelMode(render, mode);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = render->GetChannelMode(render, &mode);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    EXPECT_EQ(AUDIO_CHANNEL_NORMAL, mode);
}

/**
    * @tc.name  AudioRenderSetChannelModeNull_004
    * @tc.desc    Test SetChannelMode interface,return -3/-4 if set the parameter render is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderSetChannelModeNull_004, TestSize.Level1)
{
    int32_t ret;
    struct IAudioRender *renderNull = nullptr;
    AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;
    ASSERT_NE(nullptr, render);

    ret = render->SetChannelMode(renderNull, mode);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
}
/**
    * @tc.name  AudioRenderGetChannelMode_001
    * @tc.desc    Test GetChannelMode interface,return 0 if getting the channel mode after setting
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderGetChannelMode_001, TestSize.Level0)
{
    int32_t ret;
    AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;
    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->GetChannelMode(render, &mode);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = render->SetChannelMode(render, mode);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = render->GetChannelMode(render, &mode);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    EXPECT_EQ(AUDIO_CHANNEL_NORMAL, mode);
    render->Stop(render);
}
/**
    * @tc.name  AudioRenderGetChannelModeNull_002
    * @tc.desc    Test GetChannelMode interface,return -3/-4 if getting the parameter render is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderGetChannelModeNull_002, TestSize.Level1)
{
    int32_t ret;
    struct IAudioRender *renderNull = nullptr;
    AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;
    AudioChannelMode *modeNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->GetChannelMode(renderNull, &mode);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
    ret = render->GetChannelMode(render, modeNull);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_NOT_SUPPORT);
    render->Stop(render);
}
/**
    * @tc.name  AudioenderGetChannelMode_003
    * @tc.desc    Test GetChannelMode interface,return 0 if getting the channel mode after the object is created
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderTest, AudioRenderGetChannelMode_003, TestSize.Level1)
{
    int32_t ret;
    AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;
    ASSERT_NE(nullptr, render);

    ret = render->GetChannelMode(render, &mode);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    EXPECT_EQ(AUDIO_CHANNEL_NORMAL, mode);
}
}