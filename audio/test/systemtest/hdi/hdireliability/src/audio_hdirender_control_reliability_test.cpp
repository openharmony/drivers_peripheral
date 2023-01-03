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
#include "audio_hdirender_control_reliability_test.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
const int PTHREAD_SAMEADA_COUNT = 10;
const int PTHREAD_DIFFADA_COUNT = 1;
mutex g_testMutex;
static struct PrepareAudioPara g_para[PTHREAD_DIFFADA_COUNT] = {
    {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),  .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    }
};

class AudioHdiRenderControlReliabilityTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static TestAudioManager *manager;
    static int32_t RelGetAllAdapter(struct PrepareAudioPara& ptr);
    static int32_t RelLoadAdapter(struct PrepareAudioPara& ptr);
    static int32_t RelUnloadAdapter(struct PrepareAudioPara& ptr);
    static int32_t RelAudioRenderStart(struct PrepareAudioPara& ptr);
    static int32_t RelAudioRenderFrame(struct PrepareAudioPara& ptr);
    static int32_t RelAudioRenderStop(struct PrepareAudioPara& ptr);
    static int32_t RelAudioRenderProcedure(struct PrepareAudioPara& ptr);
    static int32_t RelAudioRenderPause(struct PrepareAudioPara& ptr);
    static int32_t RelAudioRenderResume(struct PrepareAudioPara& ptr);
    static int32_t RelAudioRenderGetRenderPosition(struct PrepareAudioPara& ptr);
};

using THREAD_FUNC = void *(*)(void *);
TestAudioManager *AudioHdiRenderControlReliabilityTest::manager = nullptr;

void AudioHdiRenderControlReliabilityTest::SetUpTestCase(void)
{
    manager = GetAudioManagerFuncs();
    ASSERT_NE(nullptr, manager);
}

void AudioHdiRenderControlReliabilityTest::TearDownTestCase(void) {}

void AudioHdiRenderControlReliabilityTest::SetUp(void) {}

void AudioHdiRenderControlReliabilityTest::TearDown(void) {}

int32_t AudioHdiRenderControlReliabilityTest::RelGetAllAdapter(struct PrepareAudioPara& ptr)
{
    if (ptr.manager == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int size = 0;
    g_testMutex.lock();
    int32_t ret = ptr.manager->GetAllAdapters(ptr.manager, &ptr.descs, &size);
    g_testMutex.unlock();
    if (ret < 0) {
        return ret;
    }
    if (ptr.descs == nullptr || size == 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    int index = SwitchAdapter(ptr.descs, ptr.adapterName, ptr.portType, ptr.audioPort, size);
    if (index < 0) {
        return index;
    }
    ptr.desc = &ptr.descs[index];
    if (ptr.desc == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioHdiRenderControlReliabilityTest::RelLoadAdapter(struct PrepareAudioPara& ptr)
{
    if (ptr.manager == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    g_testMutex.lock();
    int32_t ret = ptr.manager->LoadAdapter(ptr.manager, ptr.desc, &ptr.adapter);
    g_testMutex.unlock();
    if (ret < 0) {
        return ret;
    }

    if (ptr.adapter == nullptr) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return ret;
}

int32_t AudioHdiRenderControlReliabilityTest::RelAudioRenderStart(struct PrepareAudioPara& ptr)
{
    if (ptr.render == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = -1;
    g_testMutex.lock();
    ret = ptr.render->control.Start((AudioHandle)(ptr.render));
    g_testMutex.unlock();
    return ret;
}

int32_t AudioHdiRenderControlReliabilityTest::RelAudioRenderFrame(struct PrepareAudioPara& ptr)
{
    if (ptr.render == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = -1;
    uint64_t requestBytes = 0;
    uint64_t replyBytes = 0;
    char *frame = nullptr;

    ret = RenderFramePrepare(ptr.path, frame, requestBytes);
    if (ret < 0) {
        return ret;
    }
    g_testMutex.lock();
    ret = ptr.render->RenderFrame(ptr.render, frame, requestBytes, &replyBytes);
    g_testMutex.unlock();
    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
    return ret;
}

int32_t AudioHdiRenderControlReliabilityTest::RelAudioRenderStop(struct PrepareAudioPara& ptr)
{
    if (ptr.render == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = -1;
    g_testMutex.lock();
    ret = ptr.render->control.Stop((AudioHandle)(ptr.render));
    g_testMutex.unlock();
    return ret;
}

int32_t AudioHdiRenderControlReliabilityTest::RelAudioRenderPause(struct PrepareAudioPara& ptr)
{
    if (ptr.render == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = -1;
    g_testMutex.lock();
    ret = ptr.render->control.Pause((AudioHandle)(ptr.render));
    g_testMutex.unlock();
    return ret;
}

int32_t AudioHdiRenderControlReliabilityTest::RelAudioRenderResume(struct PrepareAudioPara& ptr)
{
    if (ptr.render == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = -1;
    g_testMutex.lock();
    ret = ptr.render->control.Resume((AudioHandle)(ptr.render));
    g_testMutex.unlock();
    return ret;
}

int32_t AudioHdiRenderControlReliabilityTest::RelAudioRenderProcedure(struct PrepareAudioPara& ptr)
{
    int32_t ret = -1;
    g_testMutex.lock();
    ret = AudioCreateRender(ptr.manager, ptr.pins, ptr.adapterName, &ptr.adapter, &ptr.render);
    g_testMutex.unlock();
    if (ret < 0) {
        return ret;
    }
    ret = AudioRenderStartAndOneFrame(ptr.render);
    return ret;
}

int32_t AudioHdiRenderControlReliabilityTest::RelAudioRenderGetRenderPosition(struct PrepareAudioPara& ptr)
{
    if (ptr.render == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = -1;
    g_testMutex.lock();
    ret = ptr.render->GetRenderPosition(ptr.render, &(ptr.character.getframes), &(ptr.time));
    g_testMutex.unlock();
    return ret;
}

/**
* @tc.name  AudioGetAllAdapterReliability_001
* @tc.desc  test Reliability GetAllAdapters interface.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiRenderControlReliabilityTest, AudioGetAllAdapterReliability_001, TestSize.Level1)
{
    int32_t ret = -1;
    g_para[0].manager = manager;
    ASSERT_NE(nullptr, g_para[0].manager);
    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelGetAllAdapter, &g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
    }
}

/**
* @tc.name  AudioLoadlAdapterReliability_001
* @tc.desc  test LoadAdapter interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiRenderControlReliabilityTest, AudioLoadlAdapterReliability_001, TestSize.Level1)
{
    int32_t ret = -1;
    g_para[0].manager = manager;
    ASSERT_NE(nullptr, g_para[0].manager);
    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    ret = RelGetAllAdapter(g_para[0]);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelLoadAdapter, &g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *loadadapterresult = nullptr;
        pthread_join(tids[i], &loadadapterresult);
        ret = (intptr_t)loadadapterresult;
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    g_para[0].manager->UnloadAdapter(g_para[0].manager, g_para[0].adapter);
    g_para[0].adapter = nullptr;
}

/**
* @tc.name  AudioRenderStartReliability_001
* @tc.desc  test AudioRenderStart interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiRenderControlReliabilityTest, AudioRenderStartReliability_001, TestSize.Level1)
{
    int32_t ret = -1;
    int32_t failcount = 0;
    int32_t succeedcount = 0;
    g_para[0].manager = manager;
    ASSERT_NE(nullptr, g_para[0].manager);
    ret = AudioCreateRender(g_para[0].manager, g_para[0].pins, g_para[0].adapterName, &g_para[0].adapter,
                            &g_para[0].render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderStart, &g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *renderStartResult = nullptr;
        pthread_join(tids[i], &renderStartResult);
        ret = (intptr_t)renderStartResult;
        if (ret == 0) {
            EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
            succeedcount = succeedcount + 1;
        } else {
            EXPECT_EQ(AUDIO_HAL_ERR_AO_BUSY, ret);
            failcount = failcount + 1;
        }
    }
    if (g_para[0].adapter != nullptr) {
        ret = StopAudio(g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_EQ(failcount, PTHREAD_SAMEADA_COUNT - 1);
        EXPECT_EQ(succeedcount, 1);
        g_para[0].render = nullptr;
    }
}

/**
* @tc.name  AudioRelAudioRenderFrameReliability_001
* @tc.desc  test AudioRenderFrame iinterface Reliability pass through pthread_create fun and adapterName is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiRenderControlReliabilityTest, AudioRenderFrameReliability_001, TestSize.Level1)
{
    g_para[0].manager = manager;
    ASSERT_NE(nullptr, g_para[0].manager);
    int32_t ret = -1;
    ret = AudioCreateRender(g_para[0].manager, g_para[0].pins, g_para[0].adapterName, &g_para[0].adapter,
                            &g_para[0].render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = RelAudioRenderStart(g_para[0]);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderFrame, &g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
    }
    ret = StopAudio(g_para[0]);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    g_para[0].render = nullptr;
}

/**
* @tc.name  AudioRenderStopReliability_001
* @tc.desc  test AudioRenderStop interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiRenderControlReliabilityTest, AudioRenderStopReliability_001, TestSize.Level1)
{
    int32_t ret = -1;
    int32_t failcount = 0;
    int32_t succeedcount = 0;
    g_para[0].manager = manager;
    ASSERT_NE(nullptr, g_para[0].manager);
    ret = RelAudioRenderProcedure(g_para[0]);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderStop, &g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *renderStopResult = nullptr;
        pthread_join(tids[i], &renderStopResult);
        ret = (intptr_t)renderStopResult;
        if (ret == 0) {
            EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
            succeedcount = succeedcount + 1;
        } else {
            EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, ret);
            failcount = failcount + 1;
        }
    }
    if (g_para[0].manager != nullptr && g_para[0].adapter != nullptr) {
        g_para[0].adapter->DestroyRender(g_para[0].adapter, g_para[0].render);
        g_para[0].manager->UnloadAdapter(g_para[0].manager, g_para[0].adapter);
        EXPECT_EQ(failcount, PTHREAD_SAMEADA_COUNT - 1);
        EXPECT_EQ(succeedcount, 1);
        g_para[0].render = nullptr;
    }
}

/**
* @tc.name  AudioRenderPauseReliability_001
* @tc.desc  test AudioRenderPause interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiRenderControlReliabilityTest, AudioRenderPauseReliability_001, TestSize.Level1)
{
    int32_t ret = -1;
    int32_t failcount = 0;
    g_para[0].manager = manager;
    ASSERT_NE(nullptr, g_para[0].manager);
    int32_t succeedcount = 0;

    ret = RelAudioRenderProcedure(g_para[0]);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderPause, &g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *renderPauseResult = nullptr;
        pthread_join(tids[i], &renderPauseResult);
        ret = (intptr_t)renderPauseResult;
        if (ret == 0) {
            EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
            succeedcount = succeedcount + 1;
        } else {
            EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, ret);
            failcount = failcount + 1;
        }
    }
    if (g_para[0].adapter != nullptr) {
        ret = StopAudio(g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_EQ(failcount, PTHREAD_SAMEADA_COUNT - 1);
        EXPECT_EQ(succeedcount, 1);
        g_para[0].render = nullptr;
    }
}

/**
* @tc.name  AudioRenderResumeReliability_001
* @tc.desc  test RelAudioRenderResume interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiRenderControlReliabilityTest, AudioRenderResumeReliability_001, TestSize.Level1)
{
    int32_t ret = -1;
    int32_t failcount = 0;
    int32_t succeedcount = 0;
    g_para[0].manager = manager;
    ASSERT_NE(nullptr, g_para[0].manager);
    ret = RelAudioRenderProcedure(g_para[0]);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = RelAudioRenderPause(g_para[0]);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderResume, &g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *renderResumeResult = nullptr;
        pthread_join(tids[i], &renderResumeResult);
        ret = (intptr_t)renderResumeResult;
        if (ret == 0) {
            EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
            succeedcount = succeedcount + 1;
        } else {
            EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, ret);
            failcount = failcount + 1;
        }
    }
    if (g_para[0].adapter != nullptr) {
        ret = StopAudio(g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        g_para[0].render = nullptr;
    }
}

/**
* @tc.name  AudiorenderGetVolumeReliability_001
* @tc.desc  test GetRenderPosition interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiRenderControlReliabilityTest, AudioRenderGetRenderPositionReliability_001,
         TestSize.Level1)
{
    int32_t ret = -1;
    int64_t timeExp = 0;
    g_para[0].manager = manager;
    ASSERT_NE(nullptr, g_para[0].manager);
    struct PrepareAudioPara arrpara[PTHREAD_SAMEADA_COUNT];
    ret = RelAudioRenderProcedure(g_para[0]);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(PrepareAudioPara), &g_para[0], sizeof(PrepareAudioPara));
        arrpara[i].time = {.tvSec = 0, .tvNSec = 0};
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderGetRenderPosition, &arrpara[i]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
        EXPECT_LT(INITIAL_VALUE, arrpara[i].character.getframes);
        EXPECT_LT(timeExp, (arrpara[i].time.tvSec) * SECTONSEC + (arrpara[i].time.tvNSec));
    }
    if (g_para[0].adapter != nullptr) {
        ret = StopAudio(g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        g_para[0].render = nullptr;
    }
}
}
