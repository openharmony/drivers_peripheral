/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <pthread.h>
#include "audio_hdirender_reliability_test.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
const int PTHREAD_DIFFADA_COUNT = 1;
const int PTHREAD_SAMEADA_COUNT = 10;
mutex g_testMutex;
static struct PrepareAudioPara g_para[PTHREAD_DIFFADA_COUNT] = {
    {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),  .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    }
};

class AudioHdiRenderReliabilityTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static TestAudioManager *manager;
    AudioAdapter *adapter = nullptr;
    AudioRender *render = nullptr;
    static int32_t RelAudioRenderSetGain(struct PrepareAudioPara& ptr);
    static int32_t RelAudioRenderGetGain(struct PrepareAudioPara& ptr);
    static int32_t RelAudioRenderGetGainThreshold(struct PrepareAudioPara& ptr);
    static int32_t RelAudioRenderSetMute(struct PrepareAudioPara& ptr);
    static int32_t RelAudioRenderGetMute(struct PrepareAudioPara& ptr);
    static int32_t RelAudioRenderSetVolume(struct PrepareAudioPara& ptr);
    static int32_t RelAudioRenderGetVolume(struct PrepareAudioPara& ptr);
    static int32_t RelAudioRenderGetFrameSize(struct PrepareAudioPara& ptr);
    static int32_t RelAudioRenderGetFrameCount(struct PrepareAudioPara& ptr);
    static int32_t RelAudioRenderGetCurrentChannelId(struct PrepareAudioPara& ptr);
    static int32_t RelAudioRenderSetChannelMode(struct PrepareAudioPara& ptr);
    static int32_t RelAudioRenderGetChannelMode(struct PrepareAudioPara& ptr);
    static int32_t RelAudioRenderSetSampleAttributes(struct PrepareAudioPara& ptr);
    static int32_t RelAudioRenderGetSampleAttributes(struct PrepareAudioPara& ptr);
    static int32_t RelAudioRenderSelectScene(struct PrepareAudioPara& ptr);
    static int32_t RelAudioRenderCheckSceneCapability(struct PrepareAudioPara& ptr);
    static int32_t RelAudioRenderGetLatency(struct PrepareAudioPara& ptr);
};

using THREAD_FUNC = void *(*)(void *);
TestAudioManager *AudioHdiRenderReliabilityTest::manager = nullptr;

void AudioHdiRenderReliabilityTest::SetUpTestCase(void)
{
    manager = GetAudioManagerFuncs();
    ASSERT_NE(nullptr, manager);
}

void AudioHdiRenderReliabilityTest::TearDownTestCase(void) {}

void AudioHdiRenderReliabilityTest::SetUp(void)
{
    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
}

void AudioHdiRenderReliabilityTest::TearDown(void)
{
    int32_t ret = ReleaseRenderSource(manager, adapter, render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderGetGainThreshold(struct PrepareAudioPara& ptr)
{
    if (ptr.render == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = -1;
    g_testMutex.lock();
    ret = ptr.render->volume.GetGainThreshold(ptr.render, &(ptr.character.gainthresholdmin),
                                              &(ptr.character.gainthresholdmax));
    g_testMutex.unlock();
    return ret;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderSetGain(struct PrepareAudioPara& ptr)
{
    if (ptr.render == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = -1;
    g_testMutex.lock();
    ret = ptr.render->volume.SetGain(ptr.render, ptr.character.setgain);
    g_testMutex.unlock();
    return ret;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderGetGain(struct PrepareAudioPara& ptr)
{
    if (ptr.render == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = -1;
    g_testMutex.lock();
    ret = ptr.render->volume.GetGain(ptr.render, &(ptr.character.getgain));
    g_testMutex.unlock();
    return ret;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderSetMute(struct PrepareAudioPara& ptr)
{
    if (ptr.render == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = -1;
    g_testMutex.lock();
    ret = ptr.render->volume.SetMute(ptr.render, ptr.character.setmute);
    g_testMutex.unlock();
    return ret;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderGetMute(struct PrepareAudioPara& ptr)
{
    if (ptr.render == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = -1;
    g_testMutex.lock();
    ret = ptr.render->volume.GetMute(ptr.render, &(ptr.character.getmute));
    g_testMutex.unlock();
    return ret;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderSetVolume(struct PrepareAudioPara& ptr)
{
    if (ptr.render == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = -1;
    g_testMutex.lock();
    ret = ptr.render->volume.SetVolume(ptr.render, ptr.character.setvolume);
    g_testMutex.unlock();
    return ret;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderGetVolume(struct PrepareAudioPara& ptr)
{
    if (ptr.render == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = -1;
    g_testMutex.lock();
    ret = ptr.render->volume.GetVolume(ptr.render, &(ptr.character.getvolume));
    g_testMutex.unlock();
    return ret;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderGetFrameSize(struct PrepareAudioPara& ptr)
{
    if (ptr.render == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = -1;
    g_testMutex.lock();
    ret = ptr.render->attr.GetFrameSize(ptr.render, &(ptr.character.getframesize));
    g_testMutex.unlock();
    return ret;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderGetFrameCount(struct PrepareAudioPara& ptr)
{
    if (ptr.render == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = -1;
    g_testMutex.lock();
    ret = ptr.render->attr.GetFrameCount(ptr.render, &(ptr.character.getframecount));
    g_testMutex.unlock();
    return ret;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderGetCurrentChannelId(struct PrepareAudioPara& ptr)
{
    if (ptr.render == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = -1;
    g_testMutex.lock();
    ret = ptr.render->attr.GetCurrentChannelId(ptr.render, &(ptr.character.getcurrentchannelId));
    g_testMutex.unlock();
    return ret;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderSetSampleAttributes(struct PrepareAudioPara& ptr)
{
    if (ptr.render == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = -1;
    g_testMutex.lock();
    ret = ptr.render->attr.SetSampleAttributes(ptr.render, &(ptr.attrs));
    g_testMutex.unlock();
    return ret;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderGetSampleAttributes(struct PrepareAudioPara& ptr)
{
    if (ptr.render == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = -1;
    g_testMutex.lock();
    ret = ptr.render->attr.GetSampleAttributes(ptr.render, &(ptr.attrsValue));
    g_testMutex.unlock();
    return ret;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderSelectScene(struct PrepareAudioPara& ptr)
{
    if (ptr.render == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = -1;
    g_testMutex.lock();
    ret = ptr.render->scene.SelectScene(ptr.render, &(ptr.scenes));
    g_testMutex.unlock();
    return ret;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderCheckSceneCapability(struct PrepareAudioPara& ptr)
{
    if (ptr.render == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = -1;
    g_testMutex.lock();
    ret = ptr.render->scene.CheckSceneCapability(ptr.render, &ptr.scenes, &(ptr.character.supported));
    g_testMutex.unlock();
    return ret;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderSetChannelMode(struct PrepareAudioPara &ptr)
{
    if (ptr.render == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = -1;
    g_testMutex.lock();
    ret = ptr.render->SetChannelMode(ptr.render, ptr.character.setmode);
    g_testMutex.unlock();
    return ret;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderGetChannelMode(struct PrepareAudioPara &ptr)
{
    if (ptr.render == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = -1;
    g_testMutex.lock();
    ret = ptr.render->GetChannelMode(ptr.render, &(ptr.character.getmode));
    g_testMutex.unlock();
    return ret;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderGetLatency(struct PrepareAudioPara& ptr)
{
    if (ptr.render == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = -1;
    g_testMutex.lock();
    ret = ptr.render->GetLatency(ptr.render, &(ptr.character.latencyTime));
    g_testMutex.unlock();
    return ret;
}

/**
* @tc.name  AudiorenderGetVolumeReliability_001
* @tc.desc  test GetFrameSize interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiRenderReliabilityTest, AudioRenderGetFrameSizeReliability_001, TestSize.Level1)
{
    int32_t ret = -1;
    g_para[0].render = render;
    ASSERT_NE(nullptr, g_para[0].render);

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderGetFrameSize, &g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
        EXPECT_LT(INITIAL_VALUE, g_para[0].character.getframesize);
    }
}

/**
* @tc.name  AudiorenderGetVolumeReliability_001
* @tc.desc  test GetFrameCount interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiRenderReliabilityTest, AudioRenderGetFrameCountReliability_001, TestSize.Level1)
{
    int32_t ret = -1;
    g_para[0].render = render;
    ASSERT_NE(nullptr, g_para[0].render);

    ret = AudioRenderStartAndOneFrame(g_para[0].render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderGetFrameCount, &g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
        EXPECT_LT(INITIAL_VALUE, g_para[0].character.getframecount);
    }
    g_para[0].render->control.Stop(g_para[0].render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
}

/**
* @tc.name  AudiorenderGetVolumeReliability_001
* @tc.desc  test GetCurrentChannelId interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiRenderReliabilityTest, AudioRenderGetCurrentChannelIdReliability_001, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t channelIdValue = 2;
    g_para[0].render = render;
    ASSERT_NE(nullptr, g_para[0].render);
    struct PrepareAudioPara arrpara[PTHREAD_SAMEADA_COUNT];
    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(PrepareAudioPara), &g_para[0], sizeof(PrepareAudioPara));
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        arrpara[i].character.getcurrentchannelId = 0;
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderGetCurrentChannelId, &arrpara[i]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
        EXPECT_EQ(channelIdValue, arrpara[i].character.getcurrentchannelId);
    }
}

/**
* @tc.name  AudiorenderSetMuteReliability_001
* @tc.desc  test AudioRenderSetMute interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiRenderReliabilityTest, AudiorenderSetMuteReliability_001, TestSize.Level1)
{
    int32_t ret = -1;
    g_para[0].render = render;
    ASSERT_NE(nullptr, g_para[0].render);
    struct PrepareAudioPara arrpara[PTHREAD_SAMEADA_COUNT];

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(PrepareAudioPara), &g_para[0], sizeof(PrepareAudioPara));
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        ret = arrpara[i].render->volume.GetMute(arrpara[i].render, &(arrpara[i].character.getmute));
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        if (arrpara[i].character.getmute == false) {
            arrpara[i].character.setmute = true;
        } else {
            arrpara[i].character.setmute = false;
        }
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderSetMute, &arrpara[i]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
    }
}

/**
* @tc.name  AudiorenderGetMuteReliability_001
* @tc.desc  test AudioRenderGetMute interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiRenderReliabilityTest, AudiorenderGetMuteReliability_001, TestSize.Level1)
{
    int32_t ret = -1;
    g_para[0].render = render;
    ASSERT_NE(nullptr, g_para[0].render);
    struct PrepareAudioPara arrpara[PTHREAD_SAMEADA_COUNT];

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(PrepareAudioPara), &g_para[0], sizeof(PrepareAudioPara));
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        ret = arrpara[i].render->volume.SetMute(arrpara[i].render, false);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderGetMute, &arrpara[i]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
        EXPECT_FALSE(arrpara[i].character.getmute);
    }
}

/**
* @tc.name  AudiorenderSetVolumeReliability_001
* @tc.desc  test SetVolume interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiRenderReliabilityTest, AudiorenderSetVolumeReliability_001, TestSize.Level1)
{
    int32_t ret = -1;
    float volumeHighExpc = 0.70;
    g_para[0].render = render;
    ASSERT_NE(nullptr, g_para[0].render);
    struct PrepareAudioPara arrpara[PTHREAD_SAMEADA_COUNT];

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(PrepareAudioPara), &g_para[0], sizeof(PrepareAudioPara));
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        arrpara[i].character.setvolume = 0.70;
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderSetVolume, &arrpara[i]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
        ret = arrpara[i].render->volume.GetVolume(arrpara[i].render, &(arrpara[i].character.getvolume));
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_EQ(volumeHighExpc, arrpara[i].character.getvolume);
    }
}

/**
* @tc.name  AudiorenderGetVolumeReliability_001
* @tc.desc  test GetVolume interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiRenderReliabilityTest, AudiorenderGetVolumeReliability_001, TestSize.Level1)
{
    int32_t ret = -1;
    float volumeHighExpc = 0.7;
    g_para[0].render = render;
    ASSERT_NE(nullptr, g_para[0].render);
    struct PrepareAudioPara arrpara[PTHREAD_SAMEADA_COUNT];

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(PrepareAudioPara), &g_para[0], sizeof(PrepareAudioPara));
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        arrpara[i].character.setvolume = 0.7;
        ret = arrpara[i].render->volume.SetVolume(arrpara[i].render, arrpara[i].character.setvolume);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderGetVolume, &arrpara[i]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
        EXPECT_EQ(volumeHighExpc, arrpara[i].character.getvolume);
    }
}

/**
* @tc.name  AudioRenderSetSampleAttributesReliability_001
* @tc.desc  test AudioRenderSetSampleAttributes interface Reliability pass through pthread_create fun and adapterName
            is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiRenderReliabilityTest, AudioRenderSetSampleAttributesReliability_001, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t count = 2;
    uint32_t rateExpc = 48000;
    g_para[0].render = render;
    ASSERT_NE(nullptr, g_para[0].render);
    struct PrepareAudioPara arrpara[PTHREAD_SAMEADA_COUNT];
    InitAttrs(g_para[0].attrs);
    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(PrepareAudioPara), &g_para[0], sizeof(PrepareAudioPara));
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderSetSampleAttributes, &arrpara[i]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
        ret = arrpara[i].render->attr.GetSampleAttributes(arrpara[i].render, &(arrpara[i].attrsValue));
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_EQ(AUDIO_IN_MEDIA, arrpara[i].attrsValue.type);
        EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, arrpara[i].attrsValue.format);
        EXPECT_EQ(rateExpc, arrpara[i].attrsValue.sampleRate);
        EXPECT_EQ(count, arrpara[i].attrsValue.channelCount);
    }
}

/**
* @tc.name  AudioRenderGetSampleAttributesReliability_001
* @tc.desc  test AudioRenderGetSampleAttributes interface Reliability pass through pthread_create fun and adapterName
            is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiRenderReliabilityTest, AudioRenderGetSampleAttributesReliability_001, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t count = 2;
    uint32_t rateExpc = 48000;
    g_para[0].render = render;
    ASSERT_NE(nullptr, g_para[0].render);
    struct PrepareAudioPara arrpara[PTHREAD_SAMEADA_COUNT];
    InitAttrs(g_para[0].attrs);
    ret = g_para[0].render->attr.SetSampleAttributes(g_para[0].render, &(g_para[0].attrs));
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(PrepareAudioPara), &g_para[0], sizeof(PrepareAudioPara));
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderGetSampleAttributes, &arrpara[i]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
        EXPECT_EQ(AUDIO_IN_MEDIA, arrpara[i].attrsValue.type);
        EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, arrpara[i].attrsValue.format);
        EXPECT_EQ(rateExpc, arrpara[i].attrsValue.sampleRate);
        EXPECT_EQ(count, arrpara[i].attrsValue.channelCount);
    }
}

/**
* @tc.name  AudioRenderSelectSceneReliability_001
* @tc.desc  test AudioRenderSelectScene interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiRenderReliabilityTest, AudioRenderSelectSceneReliability_001, TestSize.Level1)
{
    int32_t ret = -1;
    g_para[0].render = render;
    ASSERT_NE(nullptr, g_para[0].render);
    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        g_para[0].scenes.scene.id = 0;
        g_para[0].scenes.desc.pins = PIN_OUT_SPEAKER;
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderSelectScene, &g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
    }
}

/**
* @tc.name  AudioRenderCheckSceneCapabilityReliability_001
* @tc.desc  test AudioRenderCheckSceneCapability interface Reliability pass through pthread_create fun and adapterName
            is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiRenderReliabilityTest, AudioRenderCheckSceneCapabilityReliability_001, TestSize.Level1)
{
    int32_t ret = -1;
    g_para[0].render = render;
    ASSERT_NE(nullptr, g_para[0].render);

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        g_para[0].scenes.scene.id = 0;
        g_para[0].scenes.desc.pins = PIN_OUT_SPEAKER;
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderCheckSceneCapability, &g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
    }
}

/**
* @tc.name  AudioRenderSetGainReliability_001
* @tc.desc  test AudioRenderSetGain interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiRenderReliabilityTest, AudioRenderSetGainReliability_001, TestSize.Level1)
{
    int32_t ret = -1;
    g_para[0].render = render;
    ASSERT_NE(nullptr, g_para[0].render);

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        g_para[0].character.setgain = 5;
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderSetGain, &g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
        EXPECT_LT(GAIN_MIN, g_para[0].character.setgain);
    }
}

/**
* @tc.name  AudioRenderGetGainReliability_001
* @tc.desc  test GetGain interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiRenderReliabilityTest, AudioRenderGetGainReliability_001, TestSize.Level1)
{
    int32_t ret = -1;
    g_para[0].render = render;
    ASSERT_NE(nullptr, g_para[0].render);
    struct PrepareAudioPara arrpara[PTHREAD_SAMEADA_COUNT];

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(PrepareAudioPara), &g_para[0], sizeof(PrepareAudioPara));
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        arrpara[i].character.setgain = 7;
        ret = arrpara[i].render->volume.SetGain(arrpara[i].render, arrpara[i].character.setgain);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderGetGain, &arrpara[i]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
        EXPECT_LT(GAIN_MIN, arrpara[i].character.setgain);
    }
}

/**
* @tc.name  AudioRenderGetGainThresholdReliability_001
* @tc.desc  test GetGainThreshold interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiRenderReliabilityTest, AudioRenderGetGainThresholdReliability_001, TestSize.Level1)
{
    int32_t ret = -1;
    g_para[0].render = render;
    ASSERT_NE(nullptr, g_para[0].render);
    struct PrepareAudioPara arrpara[PTHREAD_SAMEADA_COUNT];

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(PrepareAudioPara), &g_para[0], sizeof(PrepareAudioPara));
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderGetGainThreshold, &arrpara[i]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
        EXPECT_EQ(0, arrpara[i].character.gainthresholdmin);
        EXPECT_EQ(15, arrpara[i].character.gainthresholdmax);
    }
}

/**
* @tc.name  AudioRenderSetChannelModeReliability_001
* @tc.desc  test SetChannelMode interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiRenderReliabilityTest, AudioRenderSetChannelModeReliability_001, TestSize.Level1)
{
    int32_t ret = -1;
    g_para[0].render = render;
    ASSERT_NE(nullptr, g_para[0].render);
    struct PrepareAudioPara arrpara[PTHREAD_SAMEADA_COUNT];

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(PrepareAudioPara), &g_para[0], sizeof(PrepareAudioPara));
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        arrpara[i].character.setmode = AUDIO_CHANNEL_NORMAL;
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderSetChannelMode, &arrpara[i]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
        EXPECT_EQ(AUDIO_CHANNEL_NORMAL, arrpara[i].character.getmode);
    }
}

/**
* @tc.name  AudioRenderGetChannelModeReliability_001
* @tc.desc  test GetChannelMode interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiRenderReliabilityTest, AudioRenderGetChannelModeReliability_001, TestSize.Level1)
{
    int32_t ret = -1;
    g_para[0].render = render;
    ASSERT_NE(nullptr, g_para[0].render);
    struct PrepareAudioPara arrpara[PTHREAD_SAMEADA_COUNT];

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(PrepareAudioPara), &g_para[0], sizeof(PrepareAudioPara));
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        arrpara[i].character.setmode = AUDIO_CHANNEL_NORMAL;
        ret = arrpara[i].render->SetChannelMode(arrpara[i].render, arrpara[i].character.setmode);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderSetChannelMode, &arrpara[i]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
        EXPECT_EQ(AUDIO_CHANNEL_NORMAL, arrpara[i].character.getmode);
    }
}

/**
* @tc.name  AudioRenderRenderGetLatencyReliability_001
* @tc.desc  test GetLatency interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiRenderReliabilityTest, AudioRenderRenderGetLatencyReliability_001, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t expectLatency = 0;
    g_para[0].render = render;
    ASSERT_NE(nullptr, g_para[0].render);
    struct PrepareAudioPara arrpara[PTHREAD_SAMEADA_COUNT];
    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(PrepareAudioPara), &g_para[0], sizeof(PrepareAudioPara));
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderGetLatency, &arrpara[i]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
        EXPECT_LT(expectLatency, arrpara[i].character.latencyTime);
    }
}
}
