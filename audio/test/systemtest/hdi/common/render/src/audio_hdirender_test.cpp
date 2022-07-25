/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "audio_hdirender_test.h"

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
    static TestAudioManager *(*GetAudioManager)();
    static void *handleSo;
    static int32_t GetLoadAdapterAudioPara(struct PrepareAudioPara& audiopara);
};

using THREAD_FUNC = void *(*)(void *);

TestAudioManager *(*AudioHdiRenderTest::GetAudioManager)() = nullptr;
void *AudioHdiRenderTest::handleSo = nullptr;
void AudioHdiRenderTest::SetUpTestCase(void)
{
    char absPath[PATH_MAX] = {0};
    if (realpath(RESOLVED_PATH.c_str(), absPath) == nullptr) {
        return;
    }
    handleSo = dlopen(absPath, RTLD_LAZY);
    if (handleSo == nullptr) {
        return;
    }
    GetAudioManager = (TestAudioManager *(*)())(dlsym(handleSo, FUNCTION_NAME.c_str()));
    if (GetAudioManager == nullptr) {
        return;
    }
}

void AudioHdiRenderTest::TearDownTestCase(void)
{
    if (handleSo != nullptr) {
        dlclose(handleSo);
        handleSo = nullptr;
    }
    if (GetAudioManager != nullptr) {
        GetAudioManager = nullptr;
    }
}

void AudioHdiRenderTest::SetUp(void) {}

void AudioHdiRenderTest::TearDown(void) {}

int32_t AudioHdiRenderTest::GetLoadAdapterAudioPara(struct PrepareAudioPara& audiopara)
{
    int32_t ret = -1;
    int size = 0;
    auto *inst = (AudioHdiRenderTest *)audiopara.self;
    if (inst != nullptr && inst->GetAudioManager != nullptr) {
        audiopara.manager = inst->GetAudioManager();
    }
    if (audiopara.manager == nullptr) {
        return HDF_FAILURE;
    }
    ret = audiopara.manager->GetAllAdapters(audiopara.manager, &audiopara.descs, &size);
    if (ret < 0) {
        return ret;
    }
    if (audiopara.descs == nullptr || size == 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    int index = SwitchAdapter(audiopara.descs, audiopara.adapterName,
        audiopara.portType, audiopara.audioPort, size);
    if (index < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    } else {
        audiopara.desc = &audiopara.descs[index];
    }
    if (audiopara.desc == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    } else {
        ret = audiopara.manager->LoadAdapter(audiopara.manager, audiopara.desc, &audiopara.adapter);
    }
    if (ret < 0) {
        return ret;
    }
    if (audiopara.adapter == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    return HDF_SUCCESS;
}

/**
* @tc.name  Test RenderGetLatency API via legal
* @tc.number  SUB_Audio_HDI_RenderGetLatency_0001
* @tc.desc  test RenderGetLatency interface, return 0 if GetLatency successful
* @tc.author: wangkang
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetLatency_0001, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t latencyTime = 0;
    uint32_t expectLatency = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(GetAudioManager, nullptr);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->GetLatency(render, &latencyTime);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_LT(expectLatency, latencyTime);

    ret = render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test RenderGetLatency API via Setting parameters render is empty
* @tc.number  SUB_Audio_HDI_AudioRenderGetLatency_0002
* @tc.desc  test RenderGetLatency interface, return -1 if Setting parameters render is empty
* @tc.author: wangkang
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetLatency_0002, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t latencyTime = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    ASSERT_NE(GetAudioManager, nullptr);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->GetLatency(renderNull, &latencyTime);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    ret = render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test RenderGetLatency API via Setting parameters ms is empty
* @tc.number  SUB_Audio_HDI_AudioRenderGetLatency_0003
* @tc.desc  test RenderGetLatency interface,return -1 if Setting parameters ms is empty
* @tc.author: wangkang
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetLatency_0003, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t *latencyTime = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioAdapter *adapter = nullptr;
    ASSERT_NE(GetAudioManager, nullptr);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->GetLatency(render, latencyTime);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    ret = render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test SetRenderSpeed API via legal
    * @tc.number  SUB_Audio_HDI_AudioRenderSetRenderSpeed_0001
    * @tc.desc  Test SetRenderSpeed interface,return -2 if setting RenderSpeed
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderSetRenderSpeed_0001, TestSize.Level1)
{
    int32_t ret = -1;
    float speed = 100;
    TestAudioManager* manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(GetAudioManager, nullptr);
    manager = GetAudioManager();
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->SetRenderSpeed(render, speed);
    EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test SetRenderSpeed API via setting the incoming parameter handle is nullptr
    * @tc.number  SUB_Audio_HDI_AudioRenderSetRenderSpeed_0002
    * @tc.desc  Test SetRenderSpeed interface,return -2 if the incoming parameter handle is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderSetRenderSpeed_0002, TestSize.Level1)
{
    int32_t ret = -1;
    float speed = 0;
    TestAudioManager* manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    ASSERT_NE(GetAudioManager, nullptr);
    manager = GetAudioManager();
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->SetRenderSpeed(renderNull, speed);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test GetRenderSpeed API via legal
    * @tc.number  SUB_Audio_HDI_AudioRenderGetRenderSpeed_0001
    * @tc.desc  Test GetRenderSpeed interface,return -2 if getting RenderSpeed
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetRenderSpeed_0001, TestSize.Level1)
{
    int32_t ret = -1;
    float speed = 0;
    TestAudioManager* manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(GetAudioManager, nullptr);
    manager = GetAudioManager();
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetRenderSpeed(render, &speed);
    EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test GetRenderSpeed API via setting the incoming parameter handle is nullptr
    * @tc.number  SUB_Audio_HDI_AudioRenderGetRenderSpeed_0002
    * @tc.desc  Test GetRenderSpeed interface,return -2 if the incoming parameter handle is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetRenderSpeed_0002, TestSize.Level1)
{
    int32_t ret = -1;
    TestAudioManager* manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    float speed = 0;
    ASSERT_NE(GetAudioManager, nullptr);
    manager = GetAudioManager();
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->GetRenderSpeed(renderNull, &speed);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test GetRenderSpeed API via setting the incoming parameter speed is nullptr
    * @tc.number  SUB_Audio_HDI_AudioRenderGetRenderSpeed_0002
    * @tc.desc  Test GetRenderSpeed interface,return -2 if the incoming parameter speed is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetRenderSpeed_0003, TestSize.Level1)
{
    int32_t ret = -1;
    TestAudioManager* manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    float *speedNull = nullptr;
    ASSERT_NE(GetAudioManager, nullptr);
    manager = GetAudioManager();
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->GetRenderSpeed(render, speedNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioRenderFrame API via legal input
* @tc.number  SUB_Audio_HDI_AudioRenderFrame_0001
* @tc.desc  test AudioRenderFrame interface,Returns 0 if the data is written successfully
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderFrame_0001, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t requestBytes = 0;
    uint64_t replyBytes = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    char *frame = nullptr;
    ASSERT_NE(GetAudioManager, nullptr);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Start((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = RenderFramePrepare(AUDIO_FILE, frame, requestBytes);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->RenderFrame(render, frame, requestBytes, &replyBytes);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}
/**
* @tc.name  Test AudioRenderFrame API via setting the incoming parameter render is nullptr
* @tc.number  SUB_Audio_HDI_AudioRenderFrame_0002
* @tc.desc  Test AudioRenderFrame interface,Returns -1 if the incoming parameter render is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderFrame_0002, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t requestBytes = 0;
    uint64_t replyBytes = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    char *frame = nullptr;

    ASSERT_NE(GetAudioManager, nullptr);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Start((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = RenderFramePrepare(AUDIO_FILE, frame, requestBytes);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->RenderFrame(renderNull, frame, requestBytes, &replyBytes);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    ret = render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}
/**
* @tc.name  Test AudioRenderFrame API via setting the incoming parameter frame is nullptr
* @tc.number  SUB_Audio_HDI_AudioRenderFrame_0003
* @tc.desc  Test AudioRenderFrame interface,Returns -1 if the incoming parameter frame is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderFrame_0003, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t requestBytes = 0;
    uint64_t replyBytes = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    char *frame = nullptr;

    ASSERT_NE(GetAudioManager, nullptr);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Start((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->RenderFrame(render, frame, requestBytes, &replyBytes);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    ret = render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioRenderFrame API via setting the incoming parameter replyBytes is nullptr
* @tc.number  SUB_Audio_HDI_AudioRenderFrame_0004
* @tc.desc  Test AudioRenderFrame interface,Returns -1 if the incoming parameter replyBytes is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderFrame_0004, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t requestBytes = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    char *frame = nullptr;
    uint64_t *replyBytes = nullptr;

    ASSERT_NE(GetAudioManager, nullptr);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Start((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = RenderFramePrepare(AUDIO_FILE, frame, requestBytes);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->RenderFrame(render, frame, requestBytes, replyBytes);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    ret = render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}
/**
* @tc.name  Test AudioRenderFrame API without calling interface renderstart
* @tc.number  SUB_Audio_HDI_AudioRenderFrame_0005
* @tc.desc  Test AudioRenderFrame interface,Returns -1 if without calling interface renderstart
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderFrame_0005, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t replyBytes = 0;
    uint64_t requestBytes = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    char *frame = nullptr;

    ASSERT_NE(GetAudioManager, nullptr);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = RenderFramePrepare(AUDIO_FILE, frame, requestBytes);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->RenderFrame(render, frame, requestBytes, &replyBytes);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}
/**
* @tc.name  Test GetRenderPosition API via legal input
* @tc.number  SUB_Audio_HDI_AudioRenderGetRenderPosition_0001
* @tc.desc  Test GetRenderPosition interface,Returns 0 if get RenderPosition during playing.
* @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetRenderPosition_0001, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .self = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };
    ASSERT_NE(GetAudioManager, nullptr);
    audiopara.manager = GetAudioManager();
    ASSERT_NE(audiopara.manager, nullptr);

    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    sleep(1);
    if (audiopara.render != nullptr) {
        ret = audiopara.render->GetRenderPosition(audiopara.render, &frames, &time);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
        EXPECT_GT(frames, INITIAL_VALUE);
    }

    ret = ThreadRelease(audiopara);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
}
/**
* @tc.name  Test AudioRenderGetRenderPosition API via get RenderPosition after the audio file is Paused and resumed
* @tc.number  SUB_Audio_HDI_AudioRenderGetRenderPosition_0002
* @tc.desc   Test GetRenderPosition interface,Returns 0 if get RenderPosition after Pause and resume during playing
* @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetRenderPosition_0002, TestSize.Level1)
{
    int32_t ret = -1;
    int64_t timeExp = 0;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .self = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };
    ASSERT_NE(GetAudioManager, nullptr);
    audiopara.manager = GetAudioManager();
    ASSERT_NE(audiopara.manager, nullptr);

    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    sleep(1);
    if (audiopara.render != nullptr) {
        FrameStatus(0);
        usleep(1000);
        ret = audiopara.render->control.Pause((AudioHandle)(audiopara.render));
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        ret = audiopara.render->GetRenderPosition(audiopara.render, &frames, &time);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
        EXPECT_GT(frames, INITIAL_VALUE);
        usleep(1000);
        ret = audiopara.render->control.Resume((AudioHandle)(audiopara.render));
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        FrameStatus(1);
        ret = audiopara.render->GetRenderPosition(audiopara.render, &frames, &time);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
        EXPECT_GT(frames, INITIAL_VALUE);
    }

    ret = ThreadRelease(audiopara);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
}
/**
* @tc.name  Test GetRenderPosition API via get RenderPosition after the audio file is stopped
* @tc.number  SUB_Audio_HDI_AudioRenderGetRenderPosition_0003
* @tc.desc  Test GetRenderPosition interface,Returns 0 if get RenderPosition after stop
* @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetRenderPosition_0003, TestSize.Level1)
{
    int32_t ret = -1;
    int64_t timeExp = 0;
    uint64_t frames = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    ASSERT_NE(GetAudioManager, nullptr);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test AudioRenderGetRenderPosition API via setting the parameter render is nullptr
    * @tc.number  SUB_Audio_HDI_AudioRenderGetRenderPosition_0004
    * @tc.desc  Test AudioRenderGetRenderPosition interface, return -1 if setting the parameter render is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetRenderPosition_0004, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioRender *render = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};

    ASSERT_NE(GetAudioManager, nullptr);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test AudioRenderGetRenderPosition API via setting the parameter render is nullptr
    * @tc.number  SUB_Audio_HDI_AudioRenderGetRenderPosition_0005
    * @tc.desc  Test AudioRenderGetRenderPosition interface, return -1 if setting the parameter render is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetRenderPosition_0005, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;

    ASSERT_NE(GetAudioManager, nullptr);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetRenderPosition(renderNull, &frames, &time);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test AudioRenderGetRenderPosition API via setting the parameter frames is nullptr
    * @tc.number  SUB_Audio_HDI_AudioRenderGetRenderPosition_0006
    * @tc.desc  Test AudioRenderGetRenderPosition interface, return -1 if setting the parameter frames is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetRenderPosition_0006, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t *framesNull = nullptr;
    TestAudioManager* manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};

    ASSERT_NE(GetAudioManager, nullptr);
    manager = GetAudioManager();
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetRenderPosition(render, framesNull, &time);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test AudioRenderGetRenderPosition API via setting the parameter time is nullptr
    * @tc.number  SUB_Audio_HDI_AudioRenderGetRenderPosition_0007
    * @tc.desc  Test AudioRenderGetRenderPosition interface, return -1 if setting the parameter time is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetRenderPosition_0007, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t frames = 0;
    TestAudioManager* manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioTimeStamp *timeNull = nullptr;

    ASSERT_NE(GetAudioManager, nullptr);
    manager = GetAudioManager();
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->GetRenderPosition(render, &frames, timeNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test AudioRenderGetRenderPosition API via get RenderPosition continuously
    * @tc.number  SUB_Audio_HDI_AudioRenderGetRenderPosition_0008
    * @tc.desc  Test AudioRenderGetRenderPosition interface, return 0 if the GetRenderPosition was called twice
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_AudioRenderGetRenderPosition_0008, TestSize.Level1)
{
    int32_t ret = -1;
    int64_t timeExp = 0;
    uint64_t frames = 0;
    TestAudioManager* manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    ASSERT_NE(GetAudioManager, nullptr);
    manager = GetAudioManager();
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test ReqMmapBuffer API via legal input
* @tc.number  SUB_Audio_HDI_RenderReqMmapBuffer_0001
* @tc.desc  Test ReqMmapBuffer interface,return 0 if call ReqMmapBuffer interface successfully
* @tc.author: liweiming
*/

HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_RenderReqMmapBuffer_0001, TestSize.Level1)
{
    int32_t ret = -1;
    bool isRender = true;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc = {};
    struct AudioRender *render = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioSampleAttributes attrs = {};
    ASSERT_NE(GetAudioManager, nullptr);
    FILE *fp = fopen(LOW_LATENCY_AUDIO_FILE.c_str(), "rb+");
    ASSERT_NE(fp, nullptr);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    if (ret < 0 || render == nullptr) {
        fclose(fp);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ASSERT_EQ(nullptr, render);
    }
    InitAttrs(attrs);
    attrs.startThreshold = 0;
    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = InitMmapDesc(fp, desc, reqSize, isRender);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret =  render->control.Start((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret =  render->attr.ReqMmapBuffer((AudioHandle)render, reqSize, &desc);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    fclose(fp);
    if (ret == 0) {
        munmap(desc.memoryAddress, reqSize);
    }
    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test ReqMmapBuffer API via setting the incoming parameter reqSize is bigger than
            the size of actual audio file
* @tc.number  SUB_Audio_HDI_RenderReqMmapBuffer_0002
* @tc.desc  Test ReqMmapBuffer interface,return -3 if call ReqMmapBuffer interface unsuccessfully when setting the
            incoming parameter reqSize is bigger than the size of actual audio file
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_RenderReqMmapBuffer_0002, TestSize.Level1)
{
    int32_t ret = -1;
    bool isRender = true;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc = {};
    struct AudioRender *render = nullptr;
    struct AudioAdapter *adapter = nullptr;
    ASSERT_NE(GetAudioManager, nullptr);
    TestAudioManager *manager = GetAudioManager();
    FILE *fp = fopen(LOW_LATENCY_AUDIO_FILE.c_str(), "rb+");
    ASSERT_NE(fp, nullptr);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    if (ret < 0 || render == nullptr) {
        fclose(fp);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ASSERT_EQ(nullptr, render);
    }
    ret = InitMmapDesc(fp, desc, reqSize, isRender);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    reqSize = reqSize + BUFFER_LENTH;
    ret =  render->control.Start((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret =  render->attr.ReqMmapBuffer((AudioHandle)render, reqSize, &desc);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    fclose(fp);
    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test ReqMmapBuffer API via setting the incoming parameter reqSize is smaller than
            the size of actual audio file
* @tc.number  SUB_Audio_HDI_RenderReqMmapBuffer_0003
* @tc.desc  Test ReqMmapBuffer interface,return 0 if call ReqMmapBuffer interface successfully when setting the
            incoming parameter reqSize is smaller than the size of actual audio file
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_RenderReqMmapBuffer_0003, TestSize.Level1)
{
    int32_t ret = -1;
    bool isRender = true;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc = {};
    struct AudioRender *render = nullptr;
    struct AudioAdapter *adapter = nullptr;
    ASSERT_NE(GetAudioManager, nullptr);
    TestAudioManager *manager = GetAudioManager();
    FILE *fp = fopen(LOW_LATENCY_AUDIO_FILE.c_str(), "rb+");
    ASSERT_NE(fp, nullptr);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    if (ret < 0 || render == nullptr) {
        fclose(fp);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ASSERT_EQ(nullptr, render);
    }
    ret = InitMmapDesc(fp, desc, reqSize, isRender);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    reqSize = reqSize / 2;
    ret =  render->control.Start((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret =  render->attr.ReqMmapBuffer((AudioHandle)render, reqSize, &desc);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    fclose(fp);
    if (ret == 0) {
        munmap(desc.memoryAddress, reqSize);
    }
    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test ReqMmapBuffer API via setting the incoming parameter reqSize is zero
* @tc.number  SUB_Audio_HDI_RenderReqMmapBuffer_0003
* @tc.desc  Test ReqMmapBuffer interface,return -1 if call ReqMmapBuffer interface unsuccessfully when setting the
            incoming parameter reqSize is zero
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_RenderReqMmapBuffer_0004, TestSize.Level1)
{
    int32_t ret = -1;
    bool isRender = true;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc = {};
    struct AudioRender *render = nullptr;
    struct AudioAdapter *adapter = nullptr;
    ASSERT_NE(GetAudioManager, nullptr);
    TestAudioManager *manager = GetAudioManager();
    FILE *fp = fopen(LOW_LATENCY_AUDIO_FILE.c_str(), "rb+");
    ASSERT_NE(fp, nullptr);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    if (ret < 0 || render == nullptr) {
        fclose(fp);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ASSERT_EQ(nullptr, render);
    }
    ret = InitMmapDesc(fp, desc, reqSize, isRender);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    reqSize = 0;
    ret =  render->control.Start((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret =  render->attr.ReqMmapBuffer((AudioHandle)render, reqSize, &desc);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
    fclose(fp);
    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test ReqMmapBuffer API via setting the incoming parameter memoryFd  of desc is illegal
* @tc.number  SUB_Audio_HDI_RenderReqMmapBuffer_0003
* @tc.desc  Test ReqMmapBuffer interface,return -3 if call ReqMmapBuffer interface unsuccessfully when setting the
            incoming parameter memoryFd  of desc is illegal
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_RenderReqMmapBuffer_0005, TestSize.Level1)
{
    int32_t ret = -1;
    bool isRender = true;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc = {};
    struct AudioRender *render = nullptr;
    struct AudioAdapter *adapter = nullptr;
    ASSERT_NE(GetAudioManager, nullptr);
    FILE *fp = fopen(LOW_LATENCY_AUDIO_FILE.c_str(), "rb+");
    ASSERT_NE(fp, nullptr);
    TestAudioManager *manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    if (ret < 0 || render == nullptr) {
        fclose(fp);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ASSERT_EQ(nullptr, render);
    }
    ret = InitMmapDesc(fp, desc, reqSize, isRender);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    desc.memoryFd = 1;
    ret =  render->control.Start((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret =  render->attr.ReqMmapBuffer((AudioHandle)render, reqSize, &desc);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    fclose(fp);
    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test ReqMmapBuffer API via the incoming parameter handle is nullptr
* @tc.number  SUB_Audio_HDI_RenderReqMmapBuffer_0005
* @tc.desc  Test ReqMmapBuffer interface,return -3 if call ReqMmapBuffer interface unsuccessfully when setting the
            incoming parameter handle is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_RenderReqMmapBuffer_0006, TestSize.Level1)
{
    int32_t ret = -1;
    bool isRender = true;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc = {};
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    struct AudioAdapter *adapter = nullptr;
    ASSERT_NE(GetAudioManager, nullptr);
    TestAudioManager* manager = GetAudioManager();
    FILE *fp = fopen(LOW_LATENCY_AUDIO_FILE.c_str(), "rb+");
    ASSERT_NE(fp, nullptr);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    if (ret < 0 || render == nullptr) {
        fclose(fp);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ASSERT_EQ(nullptr, render);
    }
    ret = InitMmapDesc(fp, desc, reqSize, isRender);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret =  render->control.Start((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret =  render->attr.ReqMmapBuffer((AudioHandle)renderNull, reqSize, &desc);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    fclose(fp);
    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test ReqMmapBuffer API via the incoming parameter desc is nullptr
* @tc.number  SUB_Audio_HDI_RenderReqMmapBuffer_0006
* @tc.desc  Test ReqMmapBuffer interface,return -3 if call ReqMmapBuffer interface unsuccessfully when setting the
            incoming parameter desc is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_RenderReqMmapBuffer_0007, TestSize.Level1)
{
    int32_t ret = -1;
    bool isRender = true;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc = {};
    struct AudioMmapBufferDescripter *descNull = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioAdapter *adapter = nullptr;
    ASSERT_NE(GetAudioManager, nullptr);
    TestAudioManager* manager = GetAudioManager();
    FILE *fp = fopen(LOW_LATENCY_AUDIO_FILE.c_str(), "rb+");
    ASSERT_NE(fp, nullptr);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    if (ret < 0 || render == nullptr) {
        fclose(fp);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ASSERT_EQ(nullptr, render);
    }
    ret = InitMmapDesc(fp, desc, reqSize, isRender);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret =  render->control.Start((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret =  render->attr.ReqMmapBuffer((AudioHandle)render, reqSize, descNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    fclose(fp);
    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test GetMmapPosition API via Getting position is normal in Before playing and Playing.
* @tc.number  SUB_Audio_HDI_RenderGetMmapPosition_0001
* @tc.desc  Test GetMmapPosition interface,return 0 if Getting position successfully.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_RenderGetMmapPosition_0001, TestSize.Level1)
{
    uint64_t frames = 0;
    uint64_t framesRendering = 0;
    uint64_t framesexpRender = 0;
    int64_t timeExp = 0;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .path = LOW_LATENCY_AUDIO_FILE.c_str()
    };
    ASSERT_NE(GetAudioManager, nullptr);
    audiopara.manager = GetAudioManager();
    ASSERT_NE(audiopara.manager, nullptr);
    int32_t ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.render);
    if (ret < 0 || audiopara.render == nullptr) {
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ASSERT_EQ(nullptr, audiopara.render);
    }
    InitAttrs(audiopara.attrs);
    audiopara.attrs.startThreshold = 0;
    ret = audiopara.render->attr.SetSampleAttributes(audiopara.render, &(audiopara.attrs));
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = audiopara.render->attr.GetMmapPosition(audiopara.render, &frames, &(audiopara.time));
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ((audiopara.time.tvSec) * SECTONSEC + (audiopara.time.tvNSec), timeExp);
    EXPECT_EQ(frames, INITIAL_VALUE);

    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)PlayMapAudioFile, &audiopara);
    if (ret != 0) {
        audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    sleep(1);
    ret = audiopara.render->attr.GetMmapPosition(audiopara.render, &framesRendering, &(audiopara.time));
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT((audiopara.time.tvSec) * SECTONSEC + (audiopara.time.tvNSec), timeExp);
    EXPECT_GT(framesRendering, INITIAL_VALUE);
    int64_t timeExprendering = (audiopara.time.tvSec) * SECTONSEC + (audiopara.time.tvNSec);
    void *result = nullptr;
    pthread_join(audiopara.tids, &result);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
    ret = audiopara.render->attr.GetMmapPosition(audiopara.render, &framesexpRender, &(audiopara.time));
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GE((audiopara.time.tvSec) * SECTONSEC + (audiopara.time.tvNSec), timeExprendering);
    EXPECT_GE(framesexpRender, framesRendering);
    audiopara.render->control.Stop((AudioHandle)audiopara.render);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Test ReqMmapBuffer API via inputtint frame is nullptr.
* @tc.number  SUB_Audio_HDI_RenderGetMmapPosition_0003
* @tc.desc  Test GetMmapPosition interface,return -3 if Error in incoming parameter.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_RenderGetMmapPosition_0003, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t *frames = nullptr;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .self = this, .pins = PIN_OUT_SPEAKER,
        .path = LOW_LATENCY_AUDIO_FILE.c_str()
    };
    ASSERT_NE(GetAudioManager, nullptr);
    audiopara.manager = GetAudioManager();
    ASSERT_NE(audiopara.manager, nullptr);
    ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.render);
    if (ret < 0 || audiopara.render == nullptr) {
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ASSERT_EQ(nullptr, audiopara.render);
    }

    ret = audiopara.render->attr.GetMmapPosition(audiopara.render, frames, &(audiopara.time));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Test ReqMmapBuffer API via inputtint time is nullptr.
* @tc.number  SUB_Audio_HDI_RenderGetMmapPosition_0004
* @tc.desc  Test GetMmapPosition interface,return -3 if Error in incoming parameter.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_RenderGetMmapPosition_0004, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t frames = 0;
    struct AudioTimeStamp *time = nullptr;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .self = this, .pins = PIN_OUT_SPEAKER,
        .path = LOW_LATENCY_AUDIO_FILE.c_str()
    };
    ASSERT_NE(GetAudioManager, nullptr);
    audiopara.manager = GetAudioManager();
    ASSERT_NE(audiopara.manager, nullptr);
    ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.render);
    if (ret < 0 || audiopara.render == nullptr) {
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ASSERT_EQ(nullptr, audiopara.render);
    }

    ret = audiopara.render->attr.GetMmapPosition(audiopara.render, &frames, time);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Test ReqMmapBuffer API via inputtint render is nullptr.
* @tc.number  SUB_Audio_HDI_RenderGetMmapPosition_0005
* @tc.desc  Test GetMmapPosition interface,return -3 if Error in incoming parameter.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderTest, SUB_Audio_HDI_RenderGetMmapPosition_0005, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t frames = 0;
    struct AudioRender *renderNull = nullptr;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .self = this, .pins = PIN_OUT_SPEAKER,
        .path = LOW_LATENCY_AUDIO_FILE.c_str()
    };
    ASSERT_NE(GetAudioManager, nullptr);
    audiopara.manager = GetAudioManager();
    ASSERT_NE(audiopara.manager, nullptr);
    ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.render);
    if (ret < 0 || audiopara.render == nullptr) {
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ASSERT_EQ(nullptr, audiopara.render);
    }

    ret = audiopara.render->attr.GetMmapPosition(renderNull, &frames, &(audiopara.time));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
}
