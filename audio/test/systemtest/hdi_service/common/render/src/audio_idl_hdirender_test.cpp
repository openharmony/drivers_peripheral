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
    struct AudioAdapter *adapter = nullptr;;
    struct AudioRender *render = nullptr;;
    static TestAudioManager *(*GetAudioManager)(const char *);
    static TestAudioManager *manager;
    static void *handleSo;
    static void (*AudioManagerRelease)(struct AudioManager *);
    static void (*AudioAdapterRelease)(struct AudioAdapter *);
    static void (*AudioRenderRelease)(struct AudioRender *);
    void ReleaseAudioSource(void);
};

using THREAD_FUNC = void *(*)(void *);
TestAudioManager *(*AudioIdlHdiRenderTest::GetAudioManager)(const char *) = nullptr;
TestAudioManager *AudioIdlHdiRenderTest::manager = nullptr;
void *AudioIdlHdiRenderTest::handleSo = nullptr;
void (*AudioIdlHdiRenderTest::AudioManagerRelease)(struct AudioManager *) = nullptr;
void (*AudioIdlHdiRenderTest::AudioAdapterRelease)(struct AudioAdapter *) = nullptr;
void (*AudioIdlHdiRenderTest::AudioRenderRelease)(struct AudioRender *) = nullptr;
void AudioIdlHdiRenderTest::SetUpTestCase(void)
{
    char absPath[PATH_MAX] = {0};
    char *path = realpath(RESOLVED_PATH.c_str(), absPath);
    ASSERT_NE(nullptr, path);
    handleSo = dlopen(absPath, RTLD_LAZY);
    ASSERT_NE(nullptr, handleSo);
    GetAudioManager = (TestAudioManager *(*)(const char *))(dlsym(handleSo, FUNCTION_NAME.c_str()));
    ASSERT_NE(nullptr, GetAudioManager);
    manager = GetAudioManager(IDL_SERVER_NAME.c_str());
    ASSERT_NE(nullptr, manager);
    AudioManagerRelease = (void (*)(struct AudioManager *))(dlsym(handleSo, "AudioManagerRelease"));
    ASSERT_NE(nullptr, AudioManagerRelease);
    AudioAdapterRelease = (void (*)(struct AudioAdapter *))(dlsym(handleSo, "AudioAdapterRelease"));
    ASSERT_NE(nullptr, AudioAdapterRelease);
    AudioRenderRelease = (void (*)(struct AudioRender *))(dlsym(handleSo, "AudioRenderRelease"));
    ASSERT_NE(nullptr, AudioRenderRelease);
}

void AudioIdlHdiRenderTest::TearDownTestCase(void)
{
    if (AudioManagerRelease !=nullptr) {
        AudioManagerRelease(manager);
        manager = nullptr;
    }
    if (GetAudioManager != nullptr) {
        GetAudioManager = nullptr;
    }
    if (handleSo != nullptr) {
        dlclose(handleSo);
        handleSo = nullptr;
    }
}

void AudioIdlHdiRenderTest::SetUp(void)
{
    int32_t ret;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

void AudioIdlHdiRenderTest::TearDown(void)
{
    ReleaseAudioSource();
}

void AudioIdlHdiRenderTest::ReleaseAudioSource(void)
{
    int32_t ret = -1;
    if (render != nullptr && AudioRenderRelease != nullptr) {
        ret = adapter->DestroyRender(adapter);
        EXPECT_EQ(HDF_SUCCESS, ret);
        AudioRenderRelease(render);
        render = nullptr;
    }
    if (adapter != nullptr && AudioAdapterRelease != nullptr) {
        ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
        EXPECT_EQ(HDF_SUCCESS, ret);
        AudioAdapterRelease(adapter);
        adapter = nullptr;
    }
}

/**
* @tc.name  Test RenderGetLatency API via legal
* @tc.number  SUB_Audio_HDI_RenderetLatency_001
* @tc.desc  test RenderGetLatency interface, return 0 if GetLatency successful
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderTest, SUB_Audio_HDI_RenderGetLatency_001, TestSize.Level1)
{
    int32_t ret = -1;
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
* @tc.name    Test RenderGetLatency API via Setting parameters render is nullptr
* @tc.number  SUB_Audio_HDI_RenderGetLatency_Null_002
* @tc.desc    test RenderGetLatency interface, return -3/-4 if Setting parameters render is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderTest, SUB_Audio_HDI_RenderGetLatency_Null_002, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t latencyTime = 0;
    struct AudioRender *renderNull = nullptr;
    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->GetLatency(renderNull, &latencyTime);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name    Test RenderGetLatency API via Setting parameters ms is nullptr
* @tc.number  SUB_Audio_HDI_RenderGetLatency_Null_003
* @tc.desc    test RenderGetLatency interface,return -3 if Setting parameters ms is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderTest, SUB_Audio_HDI_RenderGetLatency_Null_003, TestSize.Level1)
{
    int32_t ret = -1;
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
* @tc.name  Test RenderFrame API via legal input
* @tc.number  SUB_Audio_HDI_AudioRenderFrame_001
* @tc.desc  test RenderFrame interface,Returns 0 if the data is written successfully
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderTest, SUB_Audio_HDI_RenderFrame_001, TestSize.Level1)
{
    int32_t ret = -1;
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
* @tc.name  Test RenderFrame API via setting the incoming parameter render is nullptr
* @tc.number  SUB_Audio_HDI_RenderFrame_Null_002
* @tc.desc  Test RenderFrame interface,Returns -3/-4 if the incoming parameter render is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderTest, SUB_Audio_HDI_RenderFrame_Null_002, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t requestBytes = 0;
    uint64_t replyBytes = 0;
    struct AudioRender *renderNull = nullptr;
    char *frame = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->Start(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = RenderFramePrepare(AUDIO_FILE, frame, requestBytes);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->RenderFrame(renderNull, (int8_t *)frame, requestBytes, &replyBytes);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);

    render->Stop(render);
    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}
/**
* @tc.name  Test RenderFrame API via setting the incoming parameter frame is nullptr
* @tc.number  SUB_Audio_HDI_AudioRenderFrame_Null_003
* @tc.desc  Test RenderFrame interface,Returns -3 if the incoming parameter frame is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderTest, SUB_Audio_HDI_RenderFrame_Null_003, TestSize.Level1)
{
    int32_t ret = -1;
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
* @tc.name  Test RenderFrame API via setting the incoming parameter replyBytes is nullptr
* @tc.number  SUB_Audio_HDI_AudioRenderFrame_Null_004
* @tc.desc  Test RenderFrame interface,Returns -3 if the incoming parameter replyBytes is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderTest, SUB_Audio_HDI_RenderFrame_Null_004, TestSize.Level1)
{
    int32_t ret = -1;
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
* @tc.name  Test RenderFrame API without calling interface renderstart
* @tc.number  SUB_Audio_HDI_AudioRenderFrame_005
* @tc.desc  Test RenderFrame interface,Returns -3 if without calling interface renderstart
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderTest, SUB_Audio_HDI_RenderFrame_005, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t replyBytes = 0;
    uint64_t requestBytes = 0;
    char *frame = nullptr;

    ASSERT_NE(nullptr, render);
    ret = RenderFramePrepare(AUDIO_FILE, frame, requestBytes);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->RenderFrame(render, (int8_t *)frame, requestBytes, &replyBytes);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}

/**
* @tc.name    Test AudioRenderGetRenderPosition API via legal input
* @tc.number  SUB_Audio_HDI_RenderGetRenderPosition_001
* @tc.desc    Test GetRenderPosition interface,Returns 0 if get RenderPosition during playing.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderTest, SUB_Audio_HDI_RenderGetRenderPosition_001, TestSize.Level1)
{
    int32_t ret = -1;
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
* @tc.name    Test AudioRenderGetRenderPosition API via get RenderPosition after the audio file is Paused and resumed
* @tc.number  SUB_Audio_HDI_RenderGetRenderPosition_002
* @tc.desc     Test GetRenderPosition interface,Returns 0 if get RenderPosition after Pause and resume during playing
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderTest, SUB_Audio_HDI_RenderGetRenderPosition_002, TestSize.Level1)
{
    int32_t ret = -1;
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
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.render->GetRenderPosition(audiopara.render, &frames, &time);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
        EXPECT_GT(frames, INITIAL_VALUE);
        usleep(1000);
        ret = audiopara.render->Resume(audiopara.render);
        EXPECT_EQ(HDF_SUCCESS, ret);
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
* @tc.name    Test AudioRenderGetRenderPosition API via get RenderPosition after the audio file is stopped
* @tc.number  SUB_Audio_HDI_RenderGetRenderPosition_003
* @tc.desc    Test GetRenderPosition interface,Returns 0 if get RenderPosition after stop
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderTest, SUB_Audio_HDI_RenderGetRenderPosition_003, TestSize.Level1)
{
    int32_t ret = -1;
    int64_t timeExp = 0;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);
}
/**
    * @tc.name    Test AudioRenderGetRenderPosition API via  via legal input
    * @tc.number  SUB_Audio_HDI_RenderGetRenderPosition_004
    * @tc.desc    Test RenderGetRenderPosition interface, return 0 if setting the parameter render is legal
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderTest, SUB_Audio_HDI_RenderGetRenderPosition_004, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};

    ASSERT_NE(nullptr, render);
    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
}
/**
    * @tc.name    Test AudioRenderGetRenderPosition API via setting the parameter render is nullptr
    * @tc.number  SUB_Audio_HDI_RenderGetRenderPosition_Null_005
    * @tc.desc    Test RenderGetRenderPosition interface, return -3/-4 if setting the parameter render is nullptr
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderTest, SUB_Audio_HDI_RenderGetRenderPosition_Null_005, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {};
    struct AudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->GetRenderPosition(renderNull, &frames, &time);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
    * @tc.name    Test AudioRenderGetRenderPosition API via setting the parameter frames is nullptr
    * @tc.number  SUB_Audio_HDI_RenderGetRenderPosition_Null_006
    * @tc.desc    Test RenderGetRenderPosition interface, return -3 if setting the parameter frames is nullptr
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderTest, SUB_Audio_HDI_RenderGetRenderPosition_Null_006, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t *framesNull = nullptr;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};

    ASSERT_NE(nullptr, render);
    ret = render->GetRenderPosition(render, framesNull, &time);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**
    * @tc.name    Test AudioRenderGetRenderPosition API via setting the parameter time is nullptr
    * @tc.number  SUB_Audio_HDI_RenderGetRenderPosition_Null_007
    * @tc.desc    Test RenderGetRenderPosition interface, return -3 if setting the parameter time is nullptr
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderTest, SUB_Audio_HDI_RenderGetRenderPosition_Null_007, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t frames = 0;
    struct AudioTimeStamp *timeNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->GetRenderPosition(render, &frames, timeNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**
    * @tc.name    Test AudioRenderGetRenderPosition API via get RenderPosition continuously
    * @tc.number  SUB_Audio_HDI_RenderGetRenderPosition_008
    * @tc.desc    Test RenderGetRenderPosition interface, return 0 if the GetRenderPosition was called twice
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderTest, SUB_Audio_HDI_RenderGetRenderPosition_008, TestSize.Level1)
{
    int32_t ret = -1;
    int64_t timeExp = 0;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);
}
/**
    * @tc.name    Test SetRenderSpeed API via legal
    * @tc.number  SUB_Audio_HDI_RenderSetRenderSpeed_001
    * @tc.desc    Test SetRenderSpeed interface,return -2 if setting RenderSpeed
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderTest, SUB_Audio_HDI_RenderSetRenderSpeed_001, TestSize.Level1)
{
    int32_t ret = -1;
    float speed = 100;
    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->SetRenderSpeed(render, speed);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
    render->Stop(render);
}
/**
    * @tc.name    Test SetRenderSpeed API via setting the incoming parameter handle is nullptr
    * @tc.number  SUB_Audio_HDI_RenderSetRenderSpeed_Null_002
    * @tc.desc    Test SetRenderSpeed interface,return -3/-4 if the incoming parameter handle is nullptr
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderTest, SUB_Audio_HDI_RenderSetRenderSpeed_Null_002, TestSize.Level1)
{
    int32_t ret = -1;
    float speed = 0;
    struct AudioRender *renderNull = nullptr;
    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->SetRenderSpeed(renderNull, speed);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    render->Stop(render);
}
/**
    * @tc.name    Test GetRenderSpeed API via legal
    * @tc.number  SUB_Audio_HDI_RenderGetRenderSpeed_001
    * @tc.desc    Test GetRenderSpeed interface,return -2 if getting RenderSpeed
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderTest, SUB_Audio_HDI_RenderGetRenderSpeed_001, TestSize.Level1)
{
    int32_t ret = -1;
    float speed = 0;
    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetRenderSpeed(render, &speed);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
    render->Stop(render);
}
/**
    * @tc.name    Test GetRenderSpeed API via setting the incoming parameter handle is nullptr
    * @tc.number  SUB_Audio_HDI_RenderGetRenderSpeed_Null_002
    * @tc.desc    Test GetRenderSpeed interface,return -3/-4 if the incoming parameter handle is nullptr
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderTest, SUB_Audio_HDI_RenderGetRenderSpeed_Null_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioRender *renderNull = nullptr;
    float speed = 0;
    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->GetRenderSpeed(renderNull, &speed);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    render->Stop(render);
}
#ifdef AUDIO_ADM_PASSTHROUGH
/**
    * @tc.name    Test GetRenderSpeed API via setting the incoming parameter speed is nullptr
    * @tc.number  SUB_Audio_HDI_RenderGetRenderSpeed_Null_003
    * @tc.desc    Test GetRenderSpeed interface,return -3/-4 if the incoming parameter speed is nullptr
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderTest, SUB_Audio_HDI_RenderGetRenderSpeed_Null_003, TestSize.Level1)
{
    int32_t ret = -1;
    float *speedNull = nullptr;
    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->GetRenderSpeed(render, speedNull);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    render->Stop(render);
}
#endif
#ifdef AUDIO_ADM_PASSTHROUGH
/**
* @tc.name    Test AudioRenderTurnStandbyMode API via input "AUDIO_FLUSH_COMPLETED"
* @tc.number  SUB_Audio_HDI_RenderRegCallback_001
* @tc.desc    Test AudioRenderTurnStandbyMode interface,return 0 if the interface use correctly.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderTest, SUB_Audio_HDI_RenderRegCallback_001, TestSize.Level1)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    struct AudioCallback audioCallBack;
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
* @tc.name    Test AudioRenderRegCallback API via input "AUDIO_NONBLOCK_WRITE_COMPELETED"
* @tc.number  SUB_Audio_HDI_RenderRegCallback_002
* @tc.desc    Test AudioRenderRegCallback interface,return 0 if the interface use correctly.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderTest, SUB_Audio_HDI_RenderRegCallback_002, TestSize.Level1)
{
    int32_t ret = -1;
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
    struct AudioCallback audioCallBack;
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
* @tc.name    Test AudioRenderRegCallback API via setting input paramter self is nullptr
* @tc.number  SUB_Audio_HDI_RenderRegCallback_003
* @tc.desc    Test AudioRenderRegCallback interface,return 0 if setting input paramter self is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderTest, SUB_Audio_HDI_RenderRegCallback_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioRender *renderNull = nullptr;
    ASSERT_NE(nullptr, render);
    struct AudioCallback audioCallBack;
    audioCallBack.RenderCallback = AudioRenderCallback;

    ret = render->RegCallback(renderNull, &audioCallBack, 1);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**
* @tc.name    Test AudioRenderRegCallback API via setting input paramter AudioCallback is nullptr
* @tc.number  SUB_Audio_HDI_RenderRegCallback_004
* @tc.desc    Test AudioRenderRegCallback interface,return -3 if setting input paramter AudioCallback is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderTest, SUB_Audio_HDI_RenderRegCallback_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioCallback *AudioRenderCallbackNull = nullptr;
    ASSERT_NE(nullptr, render);

    ret = render->RegCallback(render, AudioRenderCallbackNull, 1);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**
* @tc.name    Test AudioRenderRegCallback API via setting input paramter Callback function is nullptr
* @tc.number  SUB_Audio_HDI_RenderRegCallback_005
* @tc.desc    Test AudioRenderRegCallback interface,return -3 if setting input paramter callback function is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderTest, SUB_Audio_HDI_RenderRegCallback_005, TestSize.Level1)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, render);
    struct AudioCallback audioCallBack;
    audioCallBack.RenderCallback = nullptr;
    ret = render->RegCallback(render, &audioCallBack, 1);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
#endif
}