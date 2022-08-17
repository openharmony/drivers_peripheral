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

#include "hdf_remote_adapter_if.h"
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
    static void *handle;
    static TestGetAudioManager getAudioManager;
    static TestAudioManagerRelease managerRelease;
    static TestAudioAdapterRelease adapterRelease;
    static TestAudioRenderRelease renderRelease;
};

TestGetAudioManager AudioIdlHdiRenderSceneTest::getAudioManager = nullptr;
TestAudioManager *AudioIdlHdiRenderSceneTest::manager = nullptr;
void *AudioIdlHdiRenderSceneTest::handle = nullptr;
TestAudioManagerRelease AudioIdlHdiRenderSceneTest::managerRelease = nullptr;
TestAudioAdapterRelease AudioIdlHdiRenderSceneTest::adapterRelease = nullptr;
TestAudioRenderRelease AudioIdlHdiRenderSceneTest::renderRelease = nullptr;

void AudioIdlHdiRenderSceneTest::SetUpTestCase(void)
{
    int32_t ret = LoadFuctionSymbol(handle, getAudioManager, managerRelease, adapterRelease);
    ASSERT_EQ(HDF_SUCCESS, ret);
    renderRelease = (TestAudioRenderRelease)(dlsym(handle, "AudioRenderRelease"));
    ASSERT_NE(nullptr, renderRelease);
    (void)HdfRemoteGetCallingPid();
    manager = getAudioManager(IDL_SERVER_NAME.c_str());
    ASSERT_NE(nullptr, manager);
}

void AudioIdlHdiRenderSceneTest::TearDownTestCase(void)
{
    if (managerRelease != nullptr && manager != nullptr) {
        (void)managerRelease(manager);
    }
    if (handle != nullptr) {
        (void)dlclose(handle);
    }
}

void AudioIdlHdiRenderSceneTest::SetUp(void)
{
    int32_t ret;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

void AudioIdlHdiRenderSceneTest::TearDown(void)
{
    int32_t ret = ReleaseRenderSource(manager, adapter, render, adapterRelease, renderRelease);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

/**
* @tc.name     Test AudioRenderCheckSceneCapability API and check scene's capability
* @tc.number  SUB_Audio_HDI_RenderCheckSceneCapability_001
* @tc.desc    Test AudioRenderCheckSceneCapability interface,return 0 if check scene's capability successful.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderSceneTest, SUB_Audio_HDI_RenderCheckSceneCapability_001, TestSize.Level1)
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
* @tc.name     Test checking scene's capability where the scene is not configed in the josn.
* @tc.number  SUB_Audio_HDI_RenderCheckSceneCapability_002
* @tc.desc    Test RenderCheckSceneCapability interface,return -1 if the scene is not configed in the josn.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderSceneTest, SUB_Audio_HDI_RenderCheckSceneCapability_002, TestSize.Level1)
{
    int32_t ret = -1;
    bool supported = true;
    struct AudioSceneDescriptor scenes = {};
    scenes.scene.id = 5;
    scenes.desc.pins = PIN_OUT_SPEAKER;
    scenes.desc.desc = strdup("mic");

    ASSERT_NE(nullptr, render);
    ret = render->CheckSceneCapability(render, &scenes, &supported);
    EXPECT_EQ(HDF_FAILURE, ret);
    free(scenes.desc.desc);
}
/**
* @tc.name     Test checking scene's capability where the render is nullptr
* @tc.number  SUB_Audio_HDI_RenderCheckSceneCapability_Null_003
* @tc.desc    Test AudioRenderCheckSceneCapability,return -3/-4 if the render is nullptr.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderSceneTest, SUB_Audio_HDI_RenderCheckSceneCapability_Null_003, TestSize.Level1)
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
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    free(scenes.desc.desc);
}
/**
* @tc.name     Test AudioRenderCheckSceneCapability API and check scene's capability
* @tc.number  SUB_Audio_HDI_RenderCheckSceneCapability_Null_004
* @tc.desc    Test AudioRenderCheckSceneCapability interface,return -3 if the scene is nullptr.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderSceneTest, SUB_Audio_HDI_RenderCheckSceneCapability_Null_004, TestSize.Level1)
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
* @tc.name     Test AudioRenderCheckSceneCapability API and check scene's capability
* @tc.number  SUB_Audio_HDI_RenderCheckSceneCapability_Null_005
* @tc.desc    Test AudioRenderCheckSceneCapability interface,return -3 if the supported is nullptr.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderSceneTest, SUB_Audio_HDI_RenderCheckSceneCapability_Null_005, TestSize.Level1)
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
* @tc.name    Test RenderSelectScene API via legal input
* @tc.number  SUB_Audio_HDI_RenderSelectScene_001
* @tc.desc    Test RenderSelectScene interface,return 0 if select Render's scene successful.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderSceneTest, SUB_Audio_HDI_RenderSelectScene_001, TestSize.Level1)
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
* @tc.name    Test RenderSelectScene API after Render start.
* @tc.number  SUB_Audio_HDI_RenderSelectScene_002
* @tc.desc    Test RenderSelectScene, return 0 if select Render's scene successful after Render start.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderSceneTest, SUB_Audio_HDI_RenderSelectScene_002, TestSize.Level1)
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
* @tc.name    Test RenderSelectScene API where the parameter handle is nullptr.
* @tc.number  SUB_Audio_HDI_RenderSelectScene_Null_003
* @tc.desc    Test RenderSelectScene, return -3/-4 if the parameter handle is nullptr.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderSceneTest, SUB_Audio_HDI_RenderSelectScene_Null_003, TestSize.Level1)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, render);
    struct AudioSceneDescriptor scenes = {};
    scenes.scene.id = 0;
    scenes.desc.pins = PIN_IN_MIC;
    struct IAudioRender *renderNull = nullptr;
    scenes.desc.desc = strdup("mic");

    ret = render->SelectScene(renderNull, &scenes);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    free(scenes.desc.desc);
}
/**
* @tc.name    Test RenderSelectScene API where the parameter scene is nullptr.
* @tc.number  SUB_Audio_HDI_RenderSelectScene_Null_004
* @tc.desc    Test RenderSelectScene, return -3 if the parameter scene is nullptr.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderSceneTest, SUB_Audio_HDI_RenderSelectScene_Null_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor *scenes = nullptr;
    ASSERT_NE(nullptr, render);

    ret = render->SelectScene(render, scenes);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**
* @tc.name    Test AudioRenderSelectScene API where the scene is not configed in the josn.
* @tc.number  SUB_Audio_HDI_AudioRenderSelectScene_005
* @tc.desc    Test AudioRenderSelectScene, return -1 if the scene is not configed in the josn.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderSceneTest, SUB_Audio_HDI_AudioRenderSelectScene_005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor scenes = {};
    scenes.scene.id = 5;
    scenes.desc.pins = PIN_OUT_HDMI;
    scenes.desc.desc = strdup("mic");

    ASSERT_NE(nullptr, render);
    ret = render->SelectScene(render, &scenes);
    EXPECT_EQ(HDF_FAILURE, ret);
    free(scenes.desc.desc);
}
}
