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

/**
 * @addtogroup Audio
 * @{
 *
 * @brief Test the delayTime of audio playback interface.
 *
 * @since 1.0
 * @version 1.0
 */

/**
 * @file audio_hdi_common.h
 *
 * @brief Declares APIs for operations related to the audio delayTime.
 *
 * @since 1.0
 * @version 1.0
 */

#include "audio_hdi_common.h"
#include "audio_hdirender_performace_test.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
const float COUNT = 1000;
const int32_t LOWLATENCY = 10000;
const int32_t NORMALLATENCY = 30000;
const int32_t HIGHLATENCY = 60000;

class AudioHdiRenderPerformaceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static TestAudioManager *manager;
};

TestAudioManager *AudioHdiRenderPerformaceTest::manager = nullptr;

void AudioHdiRenderPerformaceTest::SetUpTestCase(void)
{
    manager = GetAudioManagerFuncs();
    ASSERT_NE(nullptr, manager);
}

void AudioHdiRenderPerformaceTest::TearDownTestCase(void) {}

void AudioHdiRenderPerformaceTest::SetUp(void) {}

void AudioHdiRenderPerformaceTest::TearDown(void) {}

/**
* @tc.name  AudioManagerGetAllAdapterPerformance_001
* @tc.desc  tests the performance of AudioManagerGetAllAdapters interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioManagerGetAllAdaptersPerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    int size = 0;
    struct PrepareAudioPara audiopara = { .totalTime = 0 };

    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.manager->GetAllAdapters(audiopara.manager, &audiopara.descs, &size);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  AudioManagerLoadAdapterPerformance_001
* @tc.desc  tests the performance of AudioManagerLoadAdapter interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioManagerLoadAdapterPerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    int size = 0;
    struct PrepareAudioPara audiopara = { .totalTime = 0 };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = audiopara.manager->GetAllAdapters(audiopara.manager, &audiopara.descs, &size);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    audiopara.desc = &audiopara.descs[0];
    ASSERT_NE(nullptr, audiopara.desc);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.manager->LoadAdapter(audiopara.manager, audiopara.desc, &audiopara.adapter);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        audiopara.adapter = nullptr;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  AudioManagerUnLoadAdapterPerformance_001
* @tc.desc  tests the performance of AudioManagerLoadAdapter interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioManagerUnLoadAdapterPerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    int size = 0;
    struct PrepareAudioPara audiopara = { .totalTime = 0 };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = audiopara.manager->GetAllAdapters(audiopara.manager, &audiopara.descs, &size);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    audiopara.desc = &audiopara.descs[0];
    ASSERT_NE(nullptr, audiopara.desc);

    for (int i = 0; i < COUNT; ++i) {
        ret = audiopara.manager->LoadAdapter(audiopara.manager, audiopara.desc, &audiopara.adapter);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        gettimeofday(&audiopara.end, NULL);
        audiopara.adapter = nullptr;
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  AudioManagerInitAllPortsPerformance_001
* @tc.desc  tests the performance of AudioInitAllPorts interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioManagerInitAllPortsPerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = GetLoadAdapter(audiopara.manager, audiopara.portType, audiopara.adapterName,
                         &audiopara.adapter, audiopara.audioPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.adapter->InitAllPorts(audiopara.adapter);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  AudioGetPortCapabilityPerformance_001
* @tc.desc  tests the performance of AudioGetPortCapability interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioGetPortCapabilityPerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = GetLoadAdapter(audiopara.manager, audiopara.portType, audiopara.adapterName,
                         &audiopara.adapter, audiopara.audioPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = audiopara.adapter->InitAllPorts(audiopara.adapter);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.adapter->GetPortCapability(audiopara.adapter, audiopara.audioPort, &audiopara.capability);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  AudioSetPassthroughModePerformance_001
* @tc.desc  tests the performance of AudioSetPassthroughMode interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioSetPassthroughModePerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .mode = PORT_PASSTHROUGH_LPCM,
        .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = GetLoadAdapter(audiopara.manager, audiopara.portType, audiopara.adapterName,
                         &audiopara.adapter, audiopara.audioPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = audiopara.adapter->InitAllPorts(audiopara.adapter);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.adapter->SetPassthroughMode(audiopara.adapter, audiopara.audioPort, audiopara.mode);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = audiopara.adapter->GetPassthroughMode(audiopara.adapter, audiopara.audioPort, &audiopara.mode);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_EQ(PORT_PASSTHROUGH_LPCM, audiopara.mode);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  AudioGetPassthroughModePerformance_001
* @tc.desc  tests the performance of AudioGetPassthroughMode interface by executing 1000 times,
* and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioGetPassthroughModePerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .mode = PORT_PASSTHROUGH_LPCM,
        .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = GetLoadAdapter(audiopara.manager, audiopara.portType, audiopara.adapterName,
                         &audiopara.adapter, audiopara.audioPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = audiopara.adapter->InitAllPorts(audiopara.adapter);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = audiopara.adapter->SetPassthroughMode(audiopara.adapter, audiopara.audioPort, audiopara.mode);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.adapter->GetPassthroughMode(audiopara.adapter, audiopara.audioPort, &audiopara.mode);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_EQ(PORT_PASSTHROUGH_LPCM, audiopara.mode);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  AudioRenderGetLatencyPerformance_001
* @tc.desc  tests the performance of AudioRenderGetLatency interface by executing 1000 times,
* and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioRenderGetLatencyPerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str(), .totalTime = 0
    };
    uint32_t latencyTimeExpc = 0;
    uint32_t latencyTime = 0;
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = PlayAudioFile(audiopara);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        if (audiopara.render != nullptr) {
            gettimeofday(&audiopara.start, NULL);
            ret = audiopara.render->GetLatency(audiopara.render, &latencyTime);
            gettimeofday(&audiopara.end, NULL);
            EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
            EXPECT_LT(latencyTimeExpc, latencyTime);
            audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
            audiopara.totalTime += audiopara.delayTime;
        }
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = StopAudio(audiopara);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
}

/**
* @tc.name  AudioCreateRenderPerformance_001
* @tc.desc  tests the performance of AudioCreateRender interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioCreateRenderPerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = GetLoadAdapter(audiopara.manager, audiopara.portType, audiopara.adapterName,
                         &audiopara.adapter, audiopara.audioPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrs(audiopara.attrs);
    InitDevDesc(audiopara.devDesc, audiopara.audioPort->portId, audiopara.pins);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.adapter->CreateRender(audiopara.adapter, &audiopara.devDesc, &audiopara.attrs,
                                              &audiopara.render);
        gettimeofday(&audiopara.end, NULL);
        if (ret < 0 || audiopara.render == nullptr) {
            audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
            audiopara.adapter = nullptr;
            ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        }
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(HIGHLATENCY, audiopara.averageDelayTime);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  AudioDestroyRenderPerformance_001
* @tc.desc  tests the performance of AudioDestroyRender interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioDestroyRenderPerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = GetLoadAdapter(audiopara.manager, audiopara.portType, audiopara.adapterName,
                         &audiopara.adapter, audiopara.audioPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrs(audiopara.attrs);
    InitDevDesc(audiopara.devDesc, audiopara.audioPort->portId, audiopara.pins);
    for (int i = 0; i < COUNT; ++i) {
        ret = audiopara.adapter->CreateRender(audiopara.adapter, &audiopara.devDesc, &audiopara.attrs,
                                              &audiopara.render);
        if (ret < 0 || audiopara.render == nullptr) {
            audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
            audiopara.adapter = nullptr;
            ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        }
        gettimeofday(&audiopara.start, NULL);
        audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
        gettimeofday(&audiopara.end, NULL);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  AudioRenderGetRenderPositionPerformance_001
* @tc.desc  tests the performance of AudioRenderGetRenderPosition interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioRenderGetRenderPositionPerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str(), .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = PlayAudioFile(audiopara);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        if (audiopara.render != nullptr) {
            gettimeofday(&audiopara.start, NULL);
            ret = audiopara.render->GetRenderPosition(audiopara.render, &audiopara.character.getframes,
                &audiopara.time);
            gettimeofday(&audiopara.end, NULL);
            EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
            audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
            audiopara.totalTime += audiopara.delayTime;
        }
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = StopAudio(audiopara);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
}

/**
* @tc.name  AudioRenderSetRenderSpeedPerformance_001
* @tc.desc  tests the performance of AudioRenderSetRenderSpeed interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioRenderSetRenderSpeedPerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    float speedNormal = 30;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = audiopara.render->control.Start((AudioHandle)audiopara.render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->SetRenderSpeed(audiopara.render, speedNormal);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
        ret = audiopara.render->GetRenderSpeed(audiopara.render, &speedNormal);
        EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = StopAudio(audiopara);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
}

/**
* @tc.name  AudioRenderGetRenderSpeedPerformance_001
* @tc.desc  tests the performance of AudioRenderGetRenderSpeed interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioRenderGetRenderSpeedPerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    float speedValue = 30;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = audiopara.render->control.Start((AudioHandle)audiopara.render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->GetRenderSpeed(audiopara.render, &speedValue);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = StopAudio(audiopara);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
}

/**
* @tc.name  AudioRenderSetChannelModePerformance_001
* @tc.desc  tests the performance of AudioRenderSetChannelMode interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioRenderSetChannelModePerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    enum AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = audiopara.render->control.Start((AudioHandle)audiopara.render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->SetChannelMode(audiopara.render, mode);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = audiopara.render->GetChannelMode(audiopara.render, &mode);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_EQ(AUDIO_CHANNEL_NORMAL, mode);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = StopAudio(audiopara);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
}

/**
* @tc.name  AudioRenderGetChannelModePerformance_001
* @tc.desc  tests the performance of AudioRenderGetChannelMode interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioRenderGetChannelModePerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    enum AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = audiopara.render->control.Start((AudioHandle)audiopara.render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = audiopara.render->SetChannelMode(audiopara.render, mode);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->GetChannelMode(audiopara.render, &mode);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_EQ(AUDIO_CHANNEL_NORMAL, mode);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = StopAudio(audiopara);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
}

/**
* @tc.name  AudioRenderGetFrameCountPerformance_001
* @tc.desc  tests the performance of AudioRenderGetFrameCount interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioRenderGetFrameCountPerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = audiopara.render->control.Start((AudioHandle)audiopara.render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->attr.GetFrameCount(audiopara.render, &audiopara.character.getframecount);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = StopAudio(audiopara);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
}

/**
* @tc.name  AudioRenderGetCurrentChannelIdPerformance_001
* @tc.desc  tests the performance of AudioRenderGetCurrentChannelId interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioRenderGetCurrentChannelIdPerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->attr.GetCurrentChannelId(audiopara.render, &audiopara.character.getcurrentchannelId);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.render = nullptr;
    audiopara.adapter = nullptr;
}

/**
* @tc.name  AudioRenderFlushPerformance_001
* @tc.desc  tests the performance of AudioRenderFlush interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioRenderFlushPerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);

    for (int i = 0; i < COUNT; ++i) {
        ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                                &audiopara.render);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ret = audiopara.render->control.Start((AudioHandle)audiopara.render);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->control.Flush((AudioHandle)audiopara.render);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = StopAudio(audiopara);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  AudioRenderGetFrameSizePerformance_001
* @tc.desc  tests the performance of AudioRenderGetFrameSize interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioRenderGetFrameSizePerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t zero = 0;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        ret = audiopara.render->control.Start((AudioHandle)audiopara.render);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->attr.GetFrameSize(audiopara.render, &audiopara.character.getframesize);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_GT(audiopara.character.getframesize, zero);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = audiopara.render->control.Stop((AudioHandle)audiopara.render);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.render = nullptr;
    audiopara.adapter = nullptr;
}


/**
* @tc.name  AudioRenderCheckSceneCapabilityPerformance_001
* @tc.desc  tests the performance of AudioRenderCheckSceneCapability interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioRenderCheckSceneCapabilityPerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .totalTime = 0
    };
    struct AudioSceneDescriptor scenes = {.scene.id = 0, .desc.pins = PIN_OUT_SPEAKER};
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->scene.CheckSceneCapability(audiopara.render, &scenes, &audiopara.character.supported);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.render = nullptr;
    audiopara.adapter = nullptr;
}

/**
* @tc.name  AudioRenderSelectScenePerformance_001
* @tc.desc  tests the performance of AudioRenderSelectScene interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioRenderSelectScenePerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .totalTime = 0
    };
    struct AudioSceneDescriptor scenes = {.scene.id = 0, .desc.pins = PIN_OUT_SPEAKER};
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->scene.SelectScene(audiopara.render, &scenes);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.render = nullptr;
    audiopara.adapter = nullptr;
}

/**
* @tc.name  AudiorenderSetMutePerformance_001
* @tc.desc  tests the performance of AudiorenderSetMute interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudiorenderSetMutePerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->volume.SetMute(audiopara.render, false);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = audiopara.render->volume.GetMute(audiopara.render, &audiopara.character.getmute);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_FALSE(audiopara.character.getmute);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.render = nullptr;
    audiopara.adapter = nullptr;
}

/**
* @tc.name  AudiorenderGetMutePerformance_001
* @tc.desc  tests the performance of AudiorenderGetMute interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudiorenderGetMutePerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = audiopara.render->volume.SetMute(audiopara.render, false);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->volume.GetMute(audiopara.render, &audiopara.character.getmute);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_FALSE(audiopara.character.getmute);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.render = nullptr;
    audiopara.adapter = nullptr;
}

/**
* @tc.name  AudiorenderSetVolumePerformance_001
* @tc.desc  tests the performance of AudiorenderSetVolume interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudiorenderSetVolumePerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .character.setvolume = 0.8, .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->volume.SetVolume(audiopara.render, audiopara.character.setvolume);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = audiopara.render->volume.GetVolume(audiopara.render, &audiopara.character.getvolume);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_EQ(audiopara.character.setvolume, audiopara.character.getvolume);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.render = nullptr;
    audiopara.adapter = nullptr;
}

/**
* @tc.name  AudiorenderGetVolumePerformance_001
* @tc.desc  tests the performance of AudiorenderGetVolume interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudiorenderGetVolumePerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->volume.GetVolume(audiopara.render, &audiopara.character.getvolume);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.render = nullptr;
    audiopara.adapter = nullptr;
}

/**
* @tc.name  AudiorenderGetGainThresholdPerformance_001
* @tc.desc  tests the performance of AudiorenderGetGainThreshold interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudiorenderGetGainThresholdPerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->volume.GetGainThreshold(audiopara.render, &audiopara.character.gainthresholdmin,
                &audiopara.character.gainthresholdmax);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.render = nullptr;
    audiopara.adapter = nullptr;
}

/**
* @tc.name  AudiorenderGetGainPerformance_001
* @tc.desc  tests the performance of AudiorenderGetGain interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudiorenderGetGainPerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->volume.GetGain(audiopara.render, &audiopara.character.getgain);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.render = nullptr;
    audiopara.adapter = nullptr;
}

/**
* @tc.name  AudiorenderSetGainPerformance_001
* @tc.desc  tests the performance of AudiorenderSetGain interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudiorenderSetGainPerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .character.setgain = 7, .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->volume.SetGain(audiopara.render, audiopara.character.setgain);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = audiopara.render->volume.GetGain(audiopara.render, &audiopara.character.getgain);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_EQ(audiopara.character.setgain, audiopara.character.getgain);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.render = nullptr;
    audiopara.adapter = nullptr;
}

/**
* @tc.name  AudioRenderFramePerformance_001
* @tc.desc  tests the performance of AudioRenderFrame interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioRenderFramePerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str(), .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = audiopara.render->control.Start((AudioHandle)audiopara.render);
    if (ret < 0) {
        audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        audiopara.render = nullptr;
        audiopara.adapter = nullptr;
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    ret = RenderFramePrepare(audiopara.path, audiopara.frame, audiopara.requestBytes);
    if (ret < 0) {
        audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        audiopara.render = nullptr;
        audiopara.adapter = nullptr;
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->RenderFrame(audiopara.render, audiopara.frame, audiopara.requestBytes,
                                            &audiopara.replyBytes);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    ret = StopAudio(audiopara);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    if (audiopara.frame != nullptr) {
        free(audiopara.frame);
        audiopara.frame = nullptr;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(NORMALLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  AudioRenderStartPerformance_001
* @tc.desc  tests the performance of AudioRenderStart interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioRenderStartPerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);

    for (int i = 0; i < COUNT; ++i) {
        ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                                &audiopara.render);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->control.Start((AudioHandle)audiopara.render);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = StopAudio(audiopara);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}
/**
* @tc.name  AudioRenderStopPerformance_001
* @tc.desc  tests the performance of AudioRenderStop interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioRenderStopPerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);

    for (int i = 0; i < COUNT; ++i) {
        ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                                &audiopara.render);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ret = audiopara.render->control.Start((AudioHandle)audiopara.render);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->control.Stop((AudioHandle)audiopara.render);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        audiopara.render = nullptr;
        audiopara.adapter = nullptr;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}
/**
* @tc.name  AudioRenderSetSampleAttributesPerformance_001
* @tc.desc  tests the performance of AudioRenderSetSampleAttributes interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioRenderSetSampleAttributesPerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrs(audiopara.attrs);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->attr.SetSampleAttributes(audiopara.render, &audiopara.attrs);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.render = nullptr;
    audiopara.adapter = nullptr;
}
/**
* @tc.name  AudioRenderPausePerformance_001
* @tc.desc  tests the performance of AudioRenderPause interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioRenderPausePerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = audiopara.render->control.Start((AudioHandle)audiopara.render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->control.Pause((AudioHandle)audiopara.render);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        ret = audiopara.render->control.Resume((AudioHandle)audiopara.render);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = StopAudio(audiopara);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
}

/**
* @tc.name  AudioRenderResumePerformance_001
* @tc.desc  tests the performance of AudioRenderResume interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioRenderResumePerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = audiopara.render->control.Start((AudioHandle)audiopara.render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        ret = audiopara.render->control.Pause((AudioHandle)audiopara.render);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->control.Resume((AudioHandle)audiopara.render);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = StopAudio(audiopara);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
}
/**
* @tc.name  AudioRenderGetSampleAttributesPerformance_001
* @tc.desc  tests the performance of AudioRenderGetSampleAttributes interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioRenderGetSampleAttributesPerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrs(audiopara.attrs);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->attr.GetSampleAttributes(audiopara.render, &audiopara.attrs);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.render = nullptr;
    audiopara.adapter = nullptr;
}
/**
* @tc.name  AudioRenderReqMmapBufferPerformance_001
* @tc.desc  tests the performance of AudioRenderReqMmapBuffer interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioRenderReqMmapBufferPerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    bool isRender = true;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc = {};
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                                &audiopara.render);
    ASSERT_NE(nullptr, audiopara.render);
    for (int i = 0; i < COUNT; ++i) {
        FILE *fp = fopen(LOW_LATENCY_AUDIO_FILE.c_str(), "rb+");
        if (fp == nullptr) {
            audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
            audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
            ASSERT_NE(nullptr, fp);
        }
        ret = InitMmapDesc(fp, desc, reqSize, isRender);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        ret = audiopara.render->control.Start((AudioHandle)audiopara.render);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->attr.ReqMmapBuffer((AudioHandle)audiopara.render, reqSize, &desc);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        if (ret == 0) {
            munmap(desc.memoryAddress, reqSize);
        }
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        audiopara.render->control.Stop((AudioHandle)audiopara.render);
        fclose(fp);
        usleep(500);
    }

    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  AudioRenderGetMmapPositionPerformance_001
* @tc.desc  tests the performance of AudioRenderRenderGetMmapPosition interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioRenderGetMmapPositionPerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t framesRendering = 0;
    int64_t timeExp = 0;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .path = LOW_LATENCY_AUDIO_FILE.c_str(), .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = PlayMapAudioFile(audiopara);
    if (ret != 0) {
        audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        audiopara.render = nullptr;
        audiopara.adapter = nullptr;
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->attr.GetMmapPosition(audiopara.render, &framesRendering, &(audiopara.time));
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_GT((audiopara.time.tvSec) * SECTONSEC + (audiopara.time.tvNSec), timeExp);
        EXPECT_GT(framesRendering, INITIAL_VALUE);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.render = nullptr;
    audiopara.adapter = nullptr;
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  AudioRenderSetExtraParamsPerformance_001
* @tc.desc  tests the performance of AudioRenderSetExtraParams interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioRenderSetExtraParamsPerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;attr-frame-count=82;attr-sampling-rate=48000";
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateStartRender(audiopara.manager, &audiopara.render, &audiopara.adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->attr.SetExtraParams((AudioHandle)audiopara.render, keyValueList);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    ret = StopAudio(audiopara);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  AudioRenderGetExtraParamsPerformance_001
* @tc.desc  tests the performance of AudioRenderGetExtraParams interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioHdiRenderPerformaceTest, AudioRenderGetExtraParamsPerformance_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .pins = PIN_OUT_SPEAKER, .path = AUDIO_FILE.c_str()
    };
    char keyValueList[] = "attr-format=24;attr-frame-count=4096;";
    char keyValueListExp[] = "attr-route=0;attr-format=24;attr-channels=2;attr-frame-count=4096;\
attr-sampling-rate=48000";
    int32_t listLenth = 256;
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);

    ret = AudioCreateStartRender(audiopara.manager, &audiopara.render, &audiopara.adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = audiopara.render->attr.SetExtraParams((AudioHandle)audiopara.render, keyValueList);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        char keyValueListValue[256] = {};
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->attr.GetExtraParams((AudioHandle)audiopara.render, keyValueListValue, listLenth);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_STREQ(keyValueListExp, keyValueListValue);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    ret = StopAudio(audiopara);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}
}
