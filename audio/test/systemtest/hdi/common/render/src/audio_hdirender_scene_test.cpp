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
#include "audio_hdirender_scene_test.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
class AudioHdiRenderSceneTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static TestAudioManager *manager;
};

using THREAD_FUNC = void *(*)(void *);
TestAudioManager *AudioHdiRenderSceneTest::manager = nullptr;

void AudioHdiRenderSceneTest::SetUpTestCase(void)
{
    manager = GetAudioManagerFuncs();
    ASSERT_NE(nullptr, manager);
}

void AudioHdiRenderSceneTest::TearDownTestCase(void) {}

void AudioHdiRenderSceneTest::SetUp(void) {}

void AudioHdiRenderSceneTest::TearDown(void) {}

/**
* @tc.name  AudioRenderCheckSceneCapability_001
* @tc.desc  Test AudioRenderCheckSceneCapability interface,return 0 if check scene's capability successful.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderSceneTest, AudioRenderCheckSceneCapability_001, TestSize.Level1)
{
    int32_t ret = -1;
    bool supported = false;
    struct AudioSceneDescriptor scenes = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    scenes.scene.id = 0;
    scenes.desc.pins = PIN_OUT_SPEAKER;
    ret = render->scene.CheckSceneCapability(render, &scenes, &supported);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_TRUE(supported);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderCheckSceneCapability_002
* @tc.desc  Test RenderCheckSceneCapability interface,return -1 if the scene is not configured in the josn.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderSceneTest, AudioRenderCheckSceneCapability_002, TestSize.Level1)
{
    int32_t ret = -1;
    bool supported = true;
    struct AudioSceneDescriptor scenes = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    scenes.scene.id = 5;
    scenes.desc.pins = PIN_OUT_SPEAKER;
    ret = render->scene.CheckSceneCapability(render, &scenes, &supported);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderCheckSceneCapability_003
* @tc.desc  Test AudioRenderCheckSceneCapability,return -1 if the render is empty.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderSceneTest, AudioRenderCheckSceneCapability_003, TestSize.Level1)
{
    int32_t ret = -1;
    bool supported = true;
    struct AudioSceneDescriptor scenes = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    scenes.scene.id = 0;
    scenes.desc.pins = PIN_OUT_SPEAKER;
    ret = render->scene.CheckSceneCapability(renderNull, &scenes, &supported);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderCheckSceneCapability_004
* @tc.desc  Test AudioRenderCheckSceneCapability interface,return -1 if the scene is empty.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderSceneTest, AudioRenderCheckSceneCapability_004, TestSize.Level1)
{
    int32_t ret = -1;
    bool supported = true;
    struct AudioSceneDescriptor *scenes = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->scene.CheckSceneCapability(render, scenes, &supported);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderCheckSceneCapability_005
* @tc.desc  Test AudioRenderCheckSceneCapability interface,return -1 if the supported is empty.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderSceneTest, AudioRenderCheckSceneCapability_005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor scenes = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    scenes.scene.id = 0;
    scenes.desc.pins = PIN_OUT_SPEAKER;
    ret = render->scene.CheckSceneCapability(render, &scenes, nullptr);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderSelectScene_001
* @tc.desc  Test AudioRenderSelectScene interface,return 0 if select Render's scene successful.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderSceneTest, AudioRenderSelectScene_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor scenes = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    scenes.scene.id = 0;
    scenes.desc.pins = PIN_OUT_SPEAKER;

    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->scene.SelectScene(render, &scenes);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderSelectScene_002
* @tc.desc  Test AudioRenderSelectScene, return 0 if select Render's scene successful after Render start.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderSceneTest, AudioRenderSelectScene_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor scenes = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    scenes.scene.id = 0;
    scenes.desc.pins = PIN_OUT_SPEAKER;
    ret = render->scene.SelectScene(render, &scenes);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderSelectScene_003
* @tc.desc  Test AudioRenderSelectScene, return -1 if the parameter handle is empty.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderSceneTest, AudioRenderSelectScene_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor scenes = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    scenes.scene.id = 0;
    scenes.desc.pins = PIN_IN_MIC;
    ret = render->scene.SelectScene(renderNull, &scenes);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderSelectScene_004
* @tc.desc  Test AudioRenderSelectScene, return -1 if the parameter scene is empty.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderSceneTest, AudioRenderSelectScene_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor *scenes = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->scene.SelectScene(render, scenes);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderSelectScene_005
* @tc.desc  Test AudioRenderSelectScene, return -1 if the scene is not configured in the josn.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderSceneTest, AudioRenderSelectScene_005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor scenes = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    scenes.scene.id = 5;
    scenes.desc.pins = PIN_OUT_HDMI;
    ret = render->scene.SelectScene(render, &scenes);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
#ifdef AUDIO_ADM_SO
/**
* @tc.name  AudioRenderRegCallback_001
* @tc.desc  Test AudioRenderTurnStandbyMode interface,return 0 if the interface use correctly.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderSceneTest, AudioRenderRegCallback_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->RegCallback(render, AudioRenderCallback, nullptr);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->control.Flush((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = CheckFlushValue();
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
#ifndef ALSA_LIB_MODE
/**
* @tc.name  AudioRenderRegCallback_002
* @tc.desc  Test AudioRenderRegCallback interface,return 0 if the interface use correctly.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderSceneTest, AudioRenderRegCallback_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs;
    struct AudioHeadInfo headInfo;
    char absPath[PATH_MAX] = {0};
    realpath(AUDIO_FILE.c_str(), absPath);
    ASSERT_NE(realpath(AUDIO_FILE.c_str(), absPath), nullptr);

    FILE *file = fopen(absPath, "rb");
    ASSERT_NE(file, nullptr);
    ASSERT_NE(nullptr, manager);
    ret = WavHeadAnalysis(headInfo, file, attrs);
    if (ret < 0) {
        fclose(file);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->RegCallback(render, AudioRenderCallback, nullptr);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = FrameStart(headInfo, render, file, attrs);
    if (ret < 0) {
        adapter->DestroyRender(adapter, render);
        manager->UnloadAdapter(manager, adapter);
        fclose(file);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    }

    ret = CheckWriteCompleteValue();
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = CheckRenderFullValue();
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
    fclose(file);
}
#endif
/**
* @tc.name  AudioRenderTurnStandbyMode_001
* @tc.desc  Test AudioRenderTurnStandbyMode interface,return 0 if the interface use correctly.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderSceneTest, AudioRenderTurnStandbyMode_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->control.TurnStandbyMode((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    sleep(3);

    ret = render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderAudioDevDump_001
* @tc.desc  Test AudioRenderAudioDevDump interface,return 0 if the interface use correctly.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderSceneTest, AudioRenderAudioDevDump_001, TestSize.Level1)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, manager);
    char pathBuf[] = "./DevDump.log";
    FILE *fp = fopen(pathBuf, "wb+");
    ASSERT_NE(nullptr, fp);
    int fd = fileno(fp);
    if (fd == -1) {
        fclose(fp);
        ASSERT_NE(fd, -1);
    }
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };
    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    if (ret < 0) {
        fclose(fp);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    sleep(1);
    FrameStatus(0);
    ret = audiopara.render->control.Pause((AudioHandle)audiopara.render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    sleep(1);
    FrameStatus(1);
    ret = audiopara.render->control.Resume((AudioHandle)audiopara.render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = audiopara.render->control.AudioDevDump((AudioHandle)audiopara.render, RANGE, fd);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    fclose(fp);
    ret = ThreadRelease(audiopara);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
}
#endif
}
