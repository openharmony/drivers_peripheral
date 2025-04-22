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
class AudioIdlHdiRenderSceneTest : public testing::Test {
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

TestAudioManager *AudioIdlHdiRenderSceneTest::manager = nullptr;

void AudioIdlHdiRenderSceneTest::SetUpTestCase(void)
{
    manager = IAudioManagerGet(IS_STUB);
    ASSERT_NE(nullptr, manager);
}

void AudioIdlHdiRenderSceneTest::TearDownTestCase(void)
{
    if (manager != nullptr) {
        (void)IAudioManagerRelease(manager, IS_STUB);
    }
}

void AudioIdlHdiRenderSceneTest::SetUp(void)
{
    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render, &renderId_);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

void AudioIdlHdiRenderSceneTest::TearDown(void)
{
    int32_t ret = ReleaseRenderSource(manager, adapter, render, renderId_);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

/**
* @tc.name  AudioRenderCheckSceneCapability_001
* @tc.desc    Test AudioRenderCheckSceneCapability interface,return 0 if check scene's capability successful.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderSceneTest, AudioRenderCheckSceneCapability_001, TestSize.Level0)
{
    int32_t ret = -1;
    bool supported = false;
    struct AudioSceneDescriptor scenes = {};
    scenes.scene.id = 0;
    scenes.desc.pins = PIN_OUT_SPEAKER;
    scenes.desc.desc = strdup("mic");

    ASSERT_NE(nullptr, render);
    ret = render->CheckSceneCapability(render, &scenes, &supported);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_TRUE(supported);
    free(scenes.desc.desc);
}
/**
* @tc.name  AudioRenderCheckSceneCapability_002
* @tc.desc    Test RenderCheckSceneCapability interface,return -1 if the scene is not configed in the josn.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderSceneTest, AudioRenderCheckSceneCapability_002, TestSize.Level0)
{
    int32_t ret = -1;
    bool supported = true;
    struct AudioSceneDescriptor scenes = {};
    scenes.scene.id = 5;
    scenes.desc.pins = PIN_OUT_SPEAKER;
    scenes.desc.desc = strdup("mic");

    ASSERT_NE(nullptr, render);
    ret = render->CheckSceneCapability(render, &scenes, &supported);
    ASSERT_TRUE(ret == HDF_FAILURE || ret == HDF_ERR_NOT_SUPPORT || ret == HDF_SUCCESS);
    free(scenes.desc.desc);
}
/**
* @tc.name  AudioRenderCheckSceneCapabilityNull_003
* @tc.desc    Test AudioRenderCheckSceneCapability,return -3/-4 if the render is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderSceneTest, AudioRenderCheckSceneCapabilityNull_003, TestSize.Level1)
{
    int32_t ret = -1;
    bool supported = true;
    struct AudioSceneDescriptor scenes = {};
    struct IAudioRender *renderNull = nullptr;
    scenes.scene.id = 0;
    scenes.desc.pins = PIN_OUT_SPEAKER;
    scenes.desc.desc = strdup("mic");

    ASSERT_NE(nullptr, render);
    ret = render->CheckSceneCapability(renderNull, &scenes, &supported);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
    free(scenes.desc.desc);
}
/**
* @tc.name  AudioRenderCheckSceneCapabilityNull_004
* @tc.desc    Test AudioRenderCheckSceneCapability interface,return -3 if the scene is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderSceneTest, AudioRenderCheckSceneCapabilityNull_004, TestSize.Level1)
{
    int32_t ret = -1;
    bool supported = true;
    struct AudioSceneDescriptor *scenes = nullptr;
    ASSERT_NE(nullptr, render);

    ret = render->CheckSceneCapability(render, scenes, &supported);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
#ifdef AUDIO_ADM_PASSTHROUGH
/**
* @tc.name  AudioRenderCheckSceneCapabilityNull_005
* @tc.desc    Test AudioRenderCheckSceneCapability interface,return -3 if the supported is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderSceneTest, AudioRenderCheckSceneCapabilityNull_005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor scenes = {};
    scenes.scene.id = 0;
    scenes.desc.pins = PIN_OUT_SPEAKER;
    scenes.desc.desc = strdup("mic");

    ASSERT_NE(nullptr, render);
    ret = render->CheckSceneCapability(render, &scenes, nullptr);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    free(scenes.desc.desc);
}
#endif
/**
* @tc.name  AudioRenderSelectScene_001
* @tc.desc    Test RenderSelectScene interface,return 0 if select Render's scene successful.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderSceneTest, AudioRenderSelectScene_001, TestSize.Level0)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor scenes = {};
    scenes.scene.id = 0;
    scenes.desc.pins = PIN_OUT_SPEAKER;
    scenes.desc.desc = strdup("mic");

    ASSERT_NE(nullptr, render);
    ret = render->SelectScene(render, &scenes);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(scenes.desc.desc);
}
/**
* @tc.name  AudioRenderSelectScene_002
* @tc.desc    Test RenderSelectScene, return 0 if select Render's scene successful after Render start.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderSceneTest, AudioRenderSelectScene_002, TestSize.Level0)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor scenes = {};
    scenes.scene.id = 0;
    scenes.desc.pins = PIN_OUT_SPEAKER;
    scenes.desc.desc = strdup("mic");

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->SelectScene(render, &scenes);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(scenes.desc.desc);
}
/**
* @tc.name  AudioRenderSelectSceneNull_003
* @tc.desc    Test RenderSelectScene, return -3/-4 if the parameter handle is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderSceneTest, AudioRenderSelectSceneNull_003, TestSize.Level1)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, render);
    struct AudioSceneDescriptor scenes = {};
    scenes.scene.id = 0;
    scenes.desc.pins = PIN_IN_MIC;
    struct IAudioRender *renderNull = nullptr;
    scenes.desc.desc = strdup("mic");

    ret = render->SelectScene(renderNull, &scenes);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
    free(scenes.desc.desc);
}
/**
* @tc.name  AudioRenderSelectSceneNull_004
* @tc.desc    Test RenderSelectScene, return -3 if the parameter scene is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderSceneTest, AudioRenderSelectSceneNull_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor *scenes = nullptr;
    ASSERT_NE(nullptr, render);

    ret = render->SelectScene(render, scenes);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**
* @tc.name  AudioAudioRenderSelectScene_005
* @tc.desc    Test AudioRenderSelectScene, return -1 if the scene is not configed in the josn.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderSceneTest, AudioAudioRenderSelectScene_005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor scenes = {};
    scenes.scene.id = 99;
    scenes.desc.pins = PIN_OUT_HDMI;
    scenes.desc.desc = strdup("mic");

    ASSERT_NE(nullptr, render);
    ret = render->SelectScene(render, &scenes);
    ASSERT_TRUE(ret == HDF_FAILURE || ret == HDF_ERR_NOT_SUPPORT);
    free(scenes.desc.desc);
}
}
