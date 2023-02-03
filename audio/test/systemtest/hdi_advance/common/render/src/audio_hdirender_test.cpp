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

/**
 * @addtogroup Audio
 * @{
 *
 * @brief Defines audio-related APIs, including custom data types and functions for loading drivers,
 * accessing a driver adapter, and rendering audios.
 *
 * @since 1.0
 * @version 1.0
 */

/**
 * @file audio_hdi_common.h
 *
 * @brief Declares APIs for operations related to the audio render adapter.
 *
 * @since 1.0
 * @version 1.0
 */

#include "audio_hdi_common.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
class AudioHdiRenderTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static TestAudioManager *manager;
};

using THREAD_FUNC = void *(*)(void *);
TestAudioManager *AudioHdiRenderTest::manager = nullptr;

void AudioHdiRenderTest::SetUpTestCase(void)
{
    manager = GetAudioManagerFuncs();
    ASSERT_NE(nullptr, manager);
}

void AudioHdiRenderTest::TearDownTestCase(void) {}

void AudioHdiRenderTest::SetUp(void) {}

void AudioHdiRenderTest::TearDown(void) {}

/**
* @tc.name  AudioRenderGetLatency_001
* @tc.desc  test RenderGetLatency interface, return 0 if GetLatency successful
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderTest, AudioRenderGetLatency_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint32_t latencyTime = 0;
    uint32_t expectLatency = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = render->GetLatency(render, &latencyTime);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_LT(expectLatency, latencyTime);

    ret = render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderGetLatency_002
* @tc.desc  test RenderGetLatency interface, return -1 if Setting parameters render is empty
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderTest, AudioRenderGetLatency_002, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint32_t latencyTime = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = render->GetLatency(renderNull, &latencyTime);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    ret = render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderGetLatency_003
* @tc.desc  test RenderGetLatency interface,return -1 if Setting parameters ms is empty
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderTest, AudioRenderGetLatency_003, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint32_t *latencyTime = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioAdapter *adapter = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = render->GetLatency(render, latencyTime);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    ret = render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioRenderGetRenderPosition_001
* @tc.desc  Test GetRenderPosition interface,Returns 0 if get RenderPosition during playing.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderTest, AudioRenderGetRenderPosition_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {
        .tvSec = 0,
        .tvNSec = 0,
    };
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT,
        .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str(),
    };
    audiopara.manager = manager;
    ASSERT_NE(audiopara.manager, nullptr);

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
* @tc.desc   Test GetRenderPosition interface,Returns 0 if get RenderPosition after Pause and resume during playing
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderTest, AudioRenderGetRenderPosition_002, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    int64_t timeExp = 0;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT,
        .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str(),
    };
    audiopara.manager = manager;
    ASSERT_NE(audiopara.manager, nullptr);

    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);
    sleep(1);
    if (audiopara.render != nullptr) {
        FrameStatus(0);
        usleep(1000);
        ret = audiopara.render->control.Pause((AudioHandle)(audiopara.render));
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = audiopara.render->GetRenderPosition(audiopara.render, &frames, &time);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
        EXPECT_GT(frames, INITIAL_VALUE);
        usleep(1000);
        ret = audiopara.render->control.Resume((AudioHandle)(audiopara.render));
        EXPECT_NE(HDF_SUCCESS, ret);
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
* @tc.desc  Test GetRenderPosition interface,Returns 0 if get RenderPosition after stop
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderTest, AudioRenderGetRenderPosition_003, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    int64_t timeExp = 0;
    uint64_t frames = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioTimeStamp time = {
        .tvSec = 0,
        .tvNSec = 0,
    };
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = render->control.Stop((AudioHandle)render);
    EXPECT_NE(HDF_SUCCESS, ret);

    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_NE(HDF_SUCCESS, ret);
    EXPECT_EQ((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_EQ(frames, INITIAL_VALUE);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetRenderPosition_004
    * @tc.desc  Test AudioRenderGetRenderPosition interface, return -1 if setting the parameter render is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderTest, AudioRenderGetRenderPosition_004, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioRender *render = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioTimeStamp time = {
        .tvSec = 0,
        .tvNSec = 0,
    };

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_NE(HDF_SUCCESS, ret);
    EXPECT_EQ((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetRenderPosition_005
    * @tc.desc  Test AudioRenderGetRenderPosition interface, return -1 if setting the parameter render is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderTest, AudioRenderGetRenderPosition_005, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = render->GetRenderPosition(renderNull, &frames, &time);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetRenderPosition_006
    * @tc.desc  Test AudioRenderGetRenderPosition interface, return -1 if setting the parameter frames is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderTest, AudioRenderGetRenderPosition_006, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t *framesNull = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioTimeStamp time = {
        .tvSec = 0,
        .tvNSec = 0,
    };

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = render->GetRenderPosition(render, framesNull, &time);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetRenderPosition_007
    * @tc.desc  Test AudioRenderGetRenderPosition interface, return -1 if setting the parameter time is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderTest, AudioRenderGetRenderPosition_007, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t frames = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioTimeStamp *timeNull = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = render->GetRenderPosition(render, &frames, timeNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetRenderPosition_008
    * @tc.desc  Test AudioRenderGetRenderPosition interface, return 0 if the GetRenderPosition was called twice
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderTest, AudioRenderGetRenderPosition_008, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    int64_t timeExp = 0;
    uint64_t frames = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioTimeStamp time = {
        .tvSec = 0,
        .tvNSec = 0,
    };
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_NE(HDF_SUCCESS, ret);
    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_NE(HDF_SUCCESS, ret);
    EXPECT_EQ((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_EQ(frames, INITIAL_VALUE);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
}
