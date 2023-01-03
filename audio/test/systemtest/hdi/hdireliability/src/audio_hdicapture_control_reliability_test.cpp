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
#include "audio_hdicapture_control_reliability_test.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
const int PTHREAD_SAMEADA_COUNT = 3;
const int PTHREAD_DIFFADA_COUNT = 1;
const int BUFFER_SIZE = 16384;
mutex g_testMutex;
static struct PrepareAudioPara g_para[PTHREAD_DIFFADA_COUNT] = {
    {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC,
        .path = AUDIO_CAPTURE_FILE.c_str()
    }
};

class AudioHdiCaptureControlReliabilityTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static TestAudioManager *manager;
    static int32_t RelAudioCreateCapture(struct PrepareAudioPara& ptr);
    static int32_t RelAudioCaptureStart(struct PrepareAudioPara& ptr);
    static int32_t RelGetAllAdapter(struct PrepareAudioPara& ptr);
    static int32_t RelLoadAdapter(struct PrepareAudioPara& ptr);
    static int32_t RelAudioCaptureStop(struct PrepareAudioPara& ptr);
    static int32_t RelAudioCaptureResume(struct PrepareAudioPara& ptr);
    static int32_t RelAudioCapturePause(struct PrepareAudioPara& ptr);
    static int32_t RelAudioCaptureProcedure(struct PrepareAudioPara& ptr);
    static int32_t RelAudioCaptureFrame(struct PrepareAudioPara& ptr);
    static int32_t RelAudioCaptureStartAndCaputreFrame(struct PrepareAudioPara& ptr);
    static int32_t RelAudioAdapterInitAllPorts(struct PrepareAudioPara& ptr);
    static int32_t RelAudioAdapterGetPortCapability(struct PrepareAudioPara& ptr);
    static int32_t RelAudioAdapterSetPassthroughMode(struct PrepareAudioPara& ptr);
    static int32_t RelAudioAdapterGetPassthroughMode(struct PrepareAudioPara& ptr);
    static int32_t RelAudioCaptureGetCapturePosition(struct PrepareAudioPara& ptr);
};

using THREAD_FUNC = void *(*)(void *);
TestAudioManager *AudioHdiCaptureControlReliabilityTest::manager = nullptr;

void AudioHdiCaptureControlReliabilityTest::SetUpTestCase(void)
{
    manager = GetAudioManagerFuncs();
    ASSERT_NE(nullptr, manager);
}

void AudioHdiCaptureControlReliabilityTest::TearDownTestCase(void) {}

void AudioHdiCaptureControlReliabilityTest::SetUp(void) {}

void AudioHdiCaptureControlReliabilityTest::TearDown(void) {}

int32_t AudioHdiCaptureControlReliabilityTest::RelGetAllAdapter(struct PrepareAudioPara& ptr)
{
    int size = 0;
    if (ptr.manager == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
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
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ptr.desc = &ptr.descs[index];
    if (ptr.desc == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioHdiCaptureControlReliabilityTest::RelLoadAdapter(struct PrepareAudioPara& ptr)
{
    if (ptr.desc == nullptr || ptr.manager == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    g_testMutex.lock();
    int32_t ret = ptr.manager->LoadAdapter(ptr.manager, ptr.desc, &ptr.adapter);
    g_testMutex.unlock();
    if (ret < 0) {
        return ret;
    }
    if (ptr.adapter == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    return ret;
}

int32_t AudioHdiCaptureControlReliabilityTest::RelAudioCreateCapture(struct PrepareAudioPara& ptr)
{
    int32_t ret = -1;
    if (ptr.adapter == nullptr  || ptr.manager == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    InitAttrs(ptr.attrs);
    InitDevDesc(ptr.devDesc, ptr.audioPort->portId, ptr.pins);
    g_testMutex.lock();
    ret = ptr.adapter->CreateCapture(ptr.adapter, &ptr.devDesc, &ptr.attrs, &ptr.capture);
    g_testMutex.unlock();
    if (ret < 0) {
        ptr.manager->UnloadAdapter(ptr.manager, ptr.adapter);
        return ret;
    }
    if (ptr.capture == nullptr) {
        ptr.manager->UnloadAdapter(ptr.manager, ptr.adapter);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioHdiCaptureControlReliabilityTest::RelAudioCaptureStart(struct PrepareAudioPara& ptr)
{
    if (ptr.capture == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = -1;
    g_testMutex.lock();
    ret = ptr.capture->control.Start((AudioHandle)(ptr.capture));
    g_testMutex.unlock();
    return ret;
}

int32_t AudioHdiCaptureControlReliabilityTest::RelAudioCaptureFrame(struct PrepareAudioPara& ptr)
{
    int32_t ret = -1;
    uint64_t requestBytes = BUFFER_SIZE;
    uint64_t replyBytes = 0;

    char *frame = static_cast<char *>(calloc(1, BUFFER_SIZE));
    if (frame == nullptr) {
        return HDF_ERR_MALLOC_FAIL;
    }

    g_testMutex.lock();
    ret = ptr.capture->CaptureFrame(ptr.capture, frame, requestBytes, &replyBytes);
    g_testMutex.unlock();
    free(frame);
    frame = nullptr;
    return ret;
}

int32_t AudioHdiCaptureControlReliabilityTest::RelAudioCaptureStartAndCaputreFrame(struct PrepareAudioPara& ptr)
{
    int32_t ret = -1;
    FILE *file = fopen(ptr.path, "wb+");
    if (file == nullptr) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    InitAttrs(ptr.attrs);

    ret = FrameStartCapture(ptr.capture, file, ptr.attrs);
    if (ret < 0) {
        fclose(file);
        return ret;
    }
    (void)fclose(file);
    return ret;
}

int32_t AudioHdiCaptureControlReliabilityTest::RelAudioCaptureStop(struct PrepareAudioPara& ptr)
{
    if (ptr.capture == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = -1;
    g_testMutex.lock();
    ret = ptr.capture->control.Stop((AudioHandle)(ptr.capture));
    g_testMutex.unlock();
    return ret;
}

int32_t AudioHdiCaptureControlReliabilityTest::RelAudioCapturePause(struct PrepareAudioPara& ptr)
{
    if (ptr.capture == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = -1;
    g_testMutex.lock();
    ret = ptr.capture->control.Pause((AudioHandle)(ptr.capture));
    g_testMutex.unlock();
    return ret;
}

int32_t AudioHdiCaptureControlReliabilityTest::RelAudioCaptureResume(struct PrepareAudioPara& ptr)
{
    if (ptr.capture == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = -1;
    g_testMutex.lock();
    ret = ptr.capture->control.Resume((AudioHandle)(ptr.capture));
    g_testMutex.unlock();
    return ret;
}

int32_t AudioHdiCaptureControlReliabilityTest::RelAudioCaptureProcedure(struct PrepareAudioPara& ptr)
{
    int32_t ret = -1;
    ret = RelGetAllAdapter(ptr);
    if (ret < 0) {
        return ret;
    }

    ret = RelLoadAdapter(ptr);
    if (ret < 0) {
        return ret;
    }

    ret = RelAudioCreateCapture(ptr);
    if (ret < 0) {
        return ret;
    }

    ret = RelAudioCaptureStartAndCaputreFrame(ptr);
    if (ret < 0) {
        ptr.adapter->DestroyCapture(ptr.adapter, ptr.capture);
        ptr.manager->UnloadAdapter(ptr.manager, ptr.adapter);
        return ret;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioHdiCaptureControlReliabilityTest::RelAudioAdapterInitAllPorts(struct PrepareAudioPara& ptr)
{
    int32_t ret = -1;
    if (ptr.adapter == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    g_testMutex.lock();
    ret = ptr.adapter->InitAllPorts(ptr.adapter);
    g_testMutex.unlock();
    return ret;
}

int32_t AudioHdiCaptureControlReliabilityTest::RelAudioAdapterGetPortCapability(struct PrepareAudioPara& ptr)
{
    int32_t ret = -1;
    if (ptr.adapter == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    g_testMutex.lock();
    ret = ptr.adapter->GetPortCapability(ptr.adapter, ptr.audioPort, &(ptr.capability));
    g_testMutex.unlock();
    return ret;
}

int32_t AudioHdiCaptureControlReliabilityTest::RelAudioAdapterSetPassthroughMode(struct PrepareAudioPara& ptr)
{
    int32_t ret = -1;
    if (ptr.adapter == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    g_testMutex.lock();
    ret = ptr.adapter->SetPassthroughMode(ptr.adapter, ptr.audioPort, ptr.mode);
    g_testMutex.unlock();
    return ret;
}

int32_t AudioHdiCaptureControlReliabilityTest::RelAudioAdapterGetPassthroughMode(struct PrepareAudioPara& ptr)
{
    int32_t ret = -1;
    if (ptr.adapter == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    g_testMutex.lock();
    ret = ptr.adapter->GetPassthroughMode(ptr.adapter, ptr.audioPort, &(ptr.mode));
    g_testMutex.unlock();
    return ret;
}

int32_t AudioHdiCaptureControlReliabilityTest::RelAudioCaptureGetCapturePosition(struct PrepareAudioPara& ptr)
{
    if (ptr.capture == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = -1;
    g_testMutex.lock();
    ret = ptr.capture->GetCapturePosition(ptr.capture, &(ptr.character.getframes), &(ptr.time));
    g_testMutex.unlock();
    return ret;
}

/**
* @tc.name  AudioCaptureFrameReliability_001
* @tc.desc  test AudioCaptureFrame interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiCaptureControlReliabilityTest, AudioCaptureFrameReliability_001, TestSize.Level1)
{
    int32_t ret = -1;
    g_para[0].manager = manager;
    ASSERT_NE(nullptr, g_para[0].manager);
    ret = RelGetAllAdapter(g_para[0]);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = RelLoadAdapter(g_para[0]);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = RelAudioCreateCapture(g_para[0]);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = RelAudioCaptureStart(g_para[0]);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureFrame, &g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
    }
    if (g_para[0].adapter != nullptr) {
        ret = StopAudio(g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
}

/**
* @tc.name  AudioCaptureStartReliability_001
* @tc.desc  test AudioCaptureStart interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiCaptureControlReliabilityTest, AudioCaptureStartReliability_001, TestSize.Level1)
{
    int32_t ret = -1;
    int32_t failcount = 0;
    int32_t succeedcount = 0;
    g_para[0].manager = manager;
    ASSERT_NE(nullptr, g_para[0].manager);
    ret = RelGetAllAdapter(g_para[0]);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = RelLoadAdapter(g_para[0]);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = RelAudioCreateCapture(g_para[0]);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureStart, &g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *captureStartResult = nullptr;
        pthread_join(tids[i], &captureStartResult);
        ret = (intptr_t)captureStartResult;
        if (ret == 0) {
            EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
            succeedcount = succeedcount + 1;
        } else {
            EXPECT_EQ(AUDIO_HAL_ERR_AI_BUSY, ret);
            failcount = failcount + 1;
        }
    }
    if (g_para[0].adapter != nullptr) {
        ret = StopAudio(g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_EQ(failcount, PTHREAD_SAMEADA_COUNT - 1);
        EXPECT_EQ(succeedcount, 1);
    }
}


/**
* @tc.name  AudioCaptureStopReliability_001
* @tc.desc  test AudioCaptureStop interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiCaptureControlReliabilityTest, AudioCaptureStopReliability_001, TestSize.Level1)
{
    int32_t ret = -1;
    int32_t failcount = 0;
    int32_t succeedcount = 0;
    g_para[0].manager = manager;
    ASSERT_NE(nullptr, g_para[0].manager);
    ret = RelAudioCaptureProcedure(g_para[0]);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureStop, &g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *captureStopResult = nullptr;
        pthread_join(tids[i], &captureStopResult);
        if ((int32_t)(intptr_t)captureStopResult == 0) {
            EXPECT_EQ(AUDIO_HAL_SUCCESS, (int32_t)(intptr_t)captureStopResult);
            succeedcount = succeedcount + 1;
        } else {
            EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, (int32_t)(intptr_t)captureStopResult);
            failcount = failcount + 1;
        }
    }
    if (g_para[0].manager != nullptr && g_para[0].adapter != nullptr) {
        g_para[0].adapter->DestroyCapture(g_para[0].adapter, g_para[0].capture);
        g_para[0].manager->UnloadAdapter(g_para[0].manager, g_para[0].adapter);
        EXPECT_EQ(failcount, PTHREAD_SAMEADA_COUNT - 1);
        EXPECT_EQ(succeedcount, 1);
    }
}


/**
* @tc.name  AudioCapturePauseReliability_001
* @tc.desc  test AudioCapturePause interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiCaptureControlReliabilityTest, AudioCapturePauseReliability_001, TestSize.Level1)
{
    int32_t ret = -1;
    int32_t failcount = 0;
    int32_t succeedcount = 0;
    g_para[0].manager = manager;
    ASSERT_NE(nullptr, g_para[0].manager);
    ASSERT_NE(nullptr, g_para[0].manager);
    ret = RelAudioCaptureProcedure(g_para[0]);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCapturePause, &g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *CapturePauseResult = nullptr;
        pthread_join(tids[i], &CapturePauseResult);
        if ((int32_t)(intptr_t)CapturePauseResult == 0) {
            EXPECT_EQ(AUDIO_HAL_SUCCESS, (int32_t)(intptr_t)CapturePauseResult);
            succeedcount = succeedcount + 1;
        } else {
            EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, (int32_t)(intptr_t)CapturePauseResult);
            failcount = failcount + 1;
        }
    }
    if (g_para[0].adapter != nullptr) {
        ret = StopAudio(g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_EQ(failcount, PTHREAD_SAMEADA_COUNT - 1);
        EXPECT_EQ(succeedcount, 1);
    }
}

/**
* @tc.name  AudioInitAllPortsReliability_002
* @tc.desc  test InitAllPorts interface, return 0 if the ports is initialize successfully.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiCaptureControlReliabilityTest, AudioInitAllPortsReliability_002, TestSize.Level1)
{
    int32_t ret = -1;
    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    g_para[0].manager = manager;
    ASSERT_NE(nullptr, g_para[0].manager);
    ret = RelGetAllAdapter(g_para[0]);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = RelLoadAdapter(g_para[0]);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioAdapterInitAllPorts, &g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
    }
    g_para[0].manager->UnloadAdapter(g_para[0].manager, g_para[0].adapter);
}

/**
* @tc.name  AudioGetPortCapabilityReliability_002
* @tc.desc  test GetPortCapability interface,return 0 if the Get Port capability successfully.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiCaptureControlReliabilityTest, AudioGetPortCapabilityReliability_002, TestSize.Level1)
{
    int32_t ret = -1;
    g_para[0].manager = manager;
    ASSERT_NE(nullptr, g_para[0].manager);
    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    ret = RelGetAllAdapter(g_para[0]);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = RelLoadAdapter(g_para[0]);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = RelAudioAdapterInitAllPorts(g_para[0]);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioAdapterGetPortCapability, &g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
    }
    g_para[0].manager->UnloadAdapter(g_para[0].manager, g_para[0].adapter);
}

/**
* @tc.name  AudioSetPassthroughModeReliability_002
* @tc.desc  test SetPassthroughMode interface,return 0 if the Set Passthrough Mode successfully.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiCaptureControlReliabilityTest, AudioSetPassthroughModeReliability_002, TestSize.Level1)
{
    int32_t ret = -1;
    g_para[0].mode = PORT_PASSTHROUGH_LPCM;
    g_para[0].portType = PORT_OUT;
    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    g_para[0].manager = manager;
    ASSERT_NE(nullptr, g_para[0].manager);
    ret = RelGetAllAdapter(g_para[0]);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = RelLoadAdapter(g_para[0]);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = RelAudioAdapterInitAllPorts(g_para[0]);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioAdapterSetPassthroughMode, &g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
        ret = g_para[0].adapter->GetPassthroughMode(g_para[0].adapter, g_para[0].audioPort, &(g_para[0].mode));
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_EQ(PORT_PASSTHROUGH_LPCM, g_para[0].mode);
    }
    g_para[0].manager->UnloadAdapter(g_para[0].manager, g_para[0].adapter);
}

/**
* @tc.name  AudioGetPassthroughModeReliability_002
* @tc.desc  test GetPassthroughMode interface,return 0 if the Get Passthrough Mode successfully.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiCaptureControlReliabilityTest, AudioGetPassthroughModeReliability_002, TestSize.Level1)
{
    int32_t ret = -1;
    g_para[0].portType = PORT_OUT;
    g_para[0].mode = PORT_PASSTHROUGH_LPCM;
    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    g_para[0].manager = manager;
    ASSERT_NE(nullptr, g_para[0].manager);
    ret = RelGetAllAdapter(g_para[0]);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = RelLoadAdapter(g_para[0]);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = RelAudioAdapterInitAllPorts(g_para[0]);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = RelAudioAdapterSetPassthroughMode(g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioAdapterGetPassthroughMode, &g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
        EXPECT_EQ(PORT_PASSTHROUGH_LPCM, g_para[0].mode);
    }
    g_para[0].manager->UnloadAdapter(g_para[0].manager, g_para[0].adapter);
}
/**
* @tc.name  AudioCaptureResumeReliability_001
* @tc.desc  test RelAudioCaptureResume interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiCaptureControlReliabilityTest, AudioCaptureResumeReliability_001, TestSize.Level1)
{
    int32_t ret = -1;
    int32_t failcount = 0;
    int32_t succeedcount = 0;
    g_para[0].manager = manager;
    ASSERT_NE(nullptr, g_para[0].manager);
    ret = RelAudioCaptureProcedure(g_para[0]);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = RelAudioCapturePause(g_para[0]);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&g_para[0], sizeof(PrepareAudioPara), &g_para[0], sizeof(PrepareAudioPara));
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureResume, &g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *captureResumeResult = nullptr;
        pthread_join(tids[i], &captureResumeResult);
        if ((int32_t)(intptr_t)captureResumeResult == 0) {
            EXPECT_EQ(AUDIO_HAL_SUCCESS, (int32_t)(intptr_t)captureResumeResult);
            succeedcount = succeedcount + 1;
        } else {
            EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, (int32_t)(intptr_t)captureResumeResult);
            failcount = failcount + 1;
        }
    }
    if (g_para[0].adapter != nullptr) {
        ret = StopAudio(g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_EQ(failcount, PTHREAD_SAMEADA_COUNT - 1);
        EXPECT_EQ(succeedcount, 1);
    }
}
/**
* @tc.name  AudioGetCapturePositionReliability_001
* @tc.desc  test AudioGetCapturePosition interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.type: RELI
*/
HWTEST_F(AudioHdiCaptureControlReliabilityTest, AudioGetCapturePositionReliability_001, TestSize.Level1)
{
    int32_t ret = -1;
    int64_t timeExp = 0;
    g_para[0].manager = manager;
    ASSERT_NE(nullptr, g_para[0].manager);
    ret = RelAudioCaptureProcedure(g_para[0]);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureGetCapturePosition, &g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
        EXPECT_LT(INITIAL_VALUE, g_para[0].character.getframes);
        EXPECT_LT(timeExp, g_para[0].time.tvNSec);
    }
    if (g_para[0].adapter != nullptr) {
        ret = StopAudio(g_para[0]);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
}
}
