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
using namespace HMOS::Audio;

namespace {
const string AUDIO_FILE = "//bin/audiorendertest.wav";
const string ADAPTER_NAME = "hdmi";
const string ADAPTER_NAME2 = "usb";
const string ADAPTER_NAME3 = "internal";

class AudioHdiRenderSceneTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    struct AudioManager *(*GetAudioManager)() = nullptr;
    void *handleSo = nullptr;
    int32_t GetLoadAdapter(struct AudioManager manager, enum AudioPortDirection portType,
                           const string adapterName, struct AudioAdapter **adapter, struct AudioPort& audioPort) const;
    int32_t AudioCreateRender(enum AudioPortPin pins, struct AudioManager manager, struct AudioAdapter *adapter,
                              const struct AudioPort renderPort, struct AudioRender **render) const;
    int32_t AudioRenderStart(const string path, struct AudioRender *render) const;
    static int32_t GetLoadAdapterAudioPara(struct PrepareAudioPara& audiopara);
    static int32_t PlayAudioFile(struct PrepareAudioPara& audiopara);
};

using THREAD_FUNC = void *(*)(void *);

void AudioHdiRenderSceneTest::SetUpTestCase(void) {}

void AudioHdiRenderSceneTest::TearDownTestCase(void) {}

void AudioHdiRenderSceneTest::SetUp(void)
{
    char resolvedPath[] = "//system/lib/libaudio_hdi_proxy_server.z.so";
    handleSo = dlopen(resolvedPath, RTLD_LAZY);
    if (handleSo == nullptr) {
        return;
    }
    GetAudioManager = (struct AudioManager* (*)())(dlsym(handleSo, "GetAudioProxyManagerFuncs"));
    if (GetAudioManager == nullptr) {
        return;
    }
}

void AudioHdiRenderSceneTest::TearDown(void)
{
    if (GetAudioManager != nullptr) {
        GetAudioManager = nullptr;
    }
}

int32_t AudioHdiRenderSceneTest::GetLoadAdapter(struct AudioManager manager, enum AudioPortDirection portType,
    const string adapterName, struct AudioAdapter **adapter, struct AudioPort& audioPort) const
{
    int32_t ret = -1;
    int size = 0;
    struct AudioAdapterDescriptor *desc = nullptr;
    struct AudioAdapterDescriptor *descs = nullptr;
    if (adapter == nullptr) {
        return HDF_FAILURE;
    }
    ret = manager.GetAllAdapters(&manager, &descs, &size);
    if (ret < 0 || descs == nullptr || size == 0) {
        return HDF_FAILURE;
    } else {
        int index = SwitchAdapter(descs, adapterName, portType, audioPort, size);
        if (index < 0) {
            return HDF_FAILURE;
        } else {
            desc = &descs[index];
        }
    }
    if (desc == nullptr) {
        return HDF_FAILURE;
    } else {
        ret = manager.LoadAdapter(&manager, desc, adapter);
    }
    if (ret < 0 || adapter == nullptr) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiRenderSceneTest::AudioCreateRender(enum AudioPortPin pins, struct AudioManager manager,
    struct AudioAdapter *adapter, const struct AudioPort renderPort, struct AudioRender **render) const
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    if (adapter == nullptr || adapter->CreateRender == nullptr || render == nullptr) {
        return HDF_FAILURE;
    }
    ret = InitAttrs(attrs);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    ret = InitDevDesc(devDesc, renderPort.portId, pins);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, render);
    if (ret < 0 || *render == nullptr) {
        manager.UnloadAdapter(&manager, adapter);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiRenderSceneTest::AudioRenderStart(const string path, struct AudioRender *render) const
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioHeadInfo headInfo = {};

    if (render == nullptr) {
        return HDF_FAILURE;
    }
    ret = InitAttrs(attrs);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    char absPath[PATH_MAX] = {0};
    if (realpath(path.c_str(), absPath) == nullptr) {
        printf("path is not exist");
        return HDF_FAILURE;
    }
    FILE *file = fopen(absPath, "rb");
    if (file == nullptr) {
        return HDF_FAILURE;
    }
    ret = WavHeadAnalysis(headInfo, file, attrs);
    if (ret < 0) {
        fclose(file);
        return HDF_FAILURE;
    }
    ret = FrameStart(headInfo, render, file, attrs);
    if (ret < 0) {
        fclose(file);
        return HDF_FAILURE;
    }
    fclose(file);
    return HDF_SUCCESS;
}

struct PrepareAudioPara {
    struct AudioManager *manager;
    enum AudioPortDirection portType;
    const char *adapterName;
    struct AudioAdapter *adapter;
    struct AudioPort audioPort;
    void *self;
    enum AudioPortPin pins;
    const char *path;
    struct AudioRender *render;
    struct AudioCapture *capture;
    struct AudioHeadInfo headInfo;
    struct AudioAdapterDescriptor *desc;
    struct AudioAdapterDescriptor *descs;
    char *frame;
    uint64_t requestBytes;
    uint64_t replyBytes;
    uint64_t fileSize;
    struct AudioSampleAttributes attrs;
};

int32_t AudioHdiRenderSceneTest::GetLoadAdapterAudioPara(struct PrepareAudioPara& audiopara)
{
    int32_t ret = -1;
    int size = 0;
    auto *inst = (AudioHdiRenderSceneTest *)audiopara.self;
    if (inst != nullptr && inst->GetAudioManager != nullptr) {
        audiopara.manager = inst->GetAudioManager();
    }
    if (audiopara.manager == nullptr) {
        return HDF_FAILURE;
    }
    ret = audiopara.manager->GetAllAdapters(audiopara.manager, &audiopara.descs, &size);
    if (ret < 0 || audiopara.descs == nullptr || size == 0) {
        return HDF_FAILURE;
    } else {
        int index = SwitchAdapter(audiopara.descs, audiopara.adapterName,
            audiopara.portType, audiopara.audioPort, size);
        if (index < 0) {
            return HDF_FAILURE;
        } else {
            audiopara.desc = &audiopara.descs[index];
        }
    }
    if (audiopara.desc == nullptr) {
        return HDF_FAILURE;
    } else {
        ret = audiopara.manager->LoadAdapter(audiopara.manager, audiopara.desc, &audiopara.adapter);
    }
    if (ret < 0 || audiopara.adapter == nullptr) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiRenderSceneTest::PlayAudioFile(struct PrepareAudioPara& audiopara)
{
    int32_t ret = -1;
    struct AudioDeviceDescriptor devDesc = {};
    char absPath[PATH_MAX] = {0};
    if (realpath(audiopara.path, absPath) == nullptr) {
        printf("path is not exist");
        return HDF_FAILURE;
    }
    FILE *file = fopen(absPath, "rb");
    if (file == nullptr) {
        return HDF_FAILURE;
    }
    if (audiopara.adapter == nullptr  || audiopara.manager == nullptr) {
        return HDF_FAILURE;
    }
    ret = HMOS::Audio::InitAttrs(audiopara.attrs);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    if (WavHeadAnalysis(audiopara.headInfo, file, audiopara.attrs) < 0) {
        return HDF_FAILURE;
    }

    ret = HMOS::Audio::InitDevDesc(devDesc, (&audiopara.audioPort)->portId, audiopara.pins);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    ret = audiopara.adapter->CreateRender(audiopara.adapter, &devDesc, &(audiopara.attrs), &audiopara.render);
    if (ret < 0 || audiopara.render == nullptr) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        return HDF_FAILURE;
    }
    ret = HMOS::Audio::FrameStart(audiopara.headInfo, audiopara.render, file, audiopara.attrs);
    if (ret == HDF_SUCCESS) {
        fclose(file);
    } else {
        audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
        fclose(file);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/**
* @tc.name   Test AudioRenderCheckSceneCapability API and check scene's capability
* @tc.number  SUB_Audio_HDI_RenderCheckSceneCapability_0001
* @tc.desc  Test AudioRenderCheckSceneCapability interface,return 0 if check scene's capability successful.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderSceneTest, SUB_Audio_HDI_RenderCheckSceneCapability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    bool supported = false;
    struct AudioSceneDescriptor scenes = {};
    struct AudioPort renderPort = {};
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    scenes.scene.id = 0;
    scenes.desc.pins = PIN_OUT_SPEAKER;
    ret = render->scene.CheckSceneCapability(render, &scenes, &supported);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_TRUE(supported);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name   Test checking scene's capability where the scene is not configed in the josn.
* @tc.number  SUB_Audio_HDI_RenderCheckSceneCapability_0002
* @tc.desc  Test RenderCheckSceneCapability interface,return -1 if the scene is not configed in the josn.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderSceneTest, SUB_Audio_HDI_RenderCheckSceneCapability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    bool supported = true;
    struct AudioSceneDescriptor scenes = {};
    struct AudioPort renderPort = {};
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    scenes.scene.id = 5;
    scenes.desc.pins = PIN_OUT_SPEAKER;
    ret = render->scene.CheckSceneCapability(render, &scenes, &supported);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name   Test checking scene's capability where the render is empty
* @tc.number  SUB_Audio_HDI_RenderCheckSceneCapability_0003
* @tc.desc  Test AudioRenderCheckSceneCapability,return -1 if the render is empty.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderSceneTest, SUB_Audio_HDI_RenderCheckSceneCapability_0003, TestSize.Level1)
{
    int32_t ret = -1;
    bool supported = true;
    struct AudioSceneDescriptor scenes = {};
    struct AudioPort renderPort = {};
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    scenes.scene.id = 0;
    scenes.desc.pins = PIN_OUT_SPEAKER;
    ret = render->scene.CheckSceneCapability(renderNull, &scenes, &supported);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name   Test AudioRenderCheckSceneCapability API and check scene's capability
* @tc.number  SUB_Audio_HDI_RenderCheckSceneCapability_0004
* @tc.desc  Test AudioRenderCheckSceneCapability interface,return -1 if the scene is empty.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderSceneTest, SUB_Audio_HDI_RenderCheckSceneCapability_0004, TestSize.Level1)
{
    int32_t ret = -1;
    bool supported = true;
    struct AudioSceneDescriptor *scenes = nullptr;
    struct AudioPort renderPort = {};
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = render->scene.CheckSceneCapability(render, scenes, &supported);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name   Test AudioRenderCheckSceneCapability API and check scene's capability
* @tc.number  SUB_Audio_HDI_RenderCheckSceneCapability_0005
* @tc.desc  Test AudioRenderCheckSceneCapability interface,return -1 if the supported is empty.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderSceneTest, SUB_Audio_HDI_RenderCheckSceneCapability_0005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor scenes = {};
    struct AudioPort renderPort = {};
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    scenes.scene.id = 0;
    scenes.desc.pins = PIN_OUT_SPEAKER;
    ret = render->scene.CheckSceneCapability(render, &scenes, nullptr);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioRenderSelectScene API via legal input
* @tc.number  SUB_Audio_HDI_AudioRenderSelectScene_0001
* @tc.desc  Test AudioRenderSelectScene interface,return 0 if select Render's scene successful.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderSceneTest, SUB_Audio_HDI_AudioRenderSelectScene_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor scenes = {};
    struct AudioPort renderPort = {};
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    scenes.scene.id = 0;
    scenes.desc.pins = PIN_OUT_SPEAKER;

    ret = render->scene.SelectScene(render, &scenes);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioRenderSelectScene API after Render start.
* @tc.number  SUB_Audio_HDI_AudioRenderSelectScene_0002
* @tc.desc  Test AudioRenderSelectScene, return 0 if select Render's scene successful after Render start.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderSceneTest, SUB_Audio_HDI_AudioRenderSelectScene_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor scenes = {};
    struct AudioPort renderPort = {};
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    scenes.scene.id = 0;
    scenes.desc.pins = PIN_OUT_SPEAKER;
    ret = render->scene.SelectScene(render, &scenes);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioRenderSelectScene API where the parameter handle is empty.
* @tc.number  SUB_Audio_HDI_AudioRenderSelectScene_0003
* @tc.desc  Test AudioRenderSelectScene, return -1 if the parameter handle is empty.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderSceneTest, SUB_Audio_HDI_AudioRenderSelectScene_0003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor scenes = {};
    struct AudioPort renderPort = {};
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    scenes.scene.id = 0;
    scenes.desc.pins = PIN_IN_MIC;
    ret = render->scene.SelectScene(renderNull, &scenes);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioRenderSelectScene API where the parameter scene is empty.
* @tc.number  SUB_Audio_HDI_AudioRenderSelectScene_0004
* @tc.desc  Test AudioRenderSelectScene, return -1 if the parameter scene is empty.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderSceneTest, SUB_Audio_HDI_AudioRenderSelectScene_0004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor *scenes = nullptr;
    struct AudioPort renderPort = {};
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = render->scene.SelectScene(render, scenes);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioRenderSelectScene API where the scene is not configed in the josn.
* @tc.number  SUB_Audio_HDI_AudioRenderSelectScene_0005
* @tc.desc  Test AudioRenderSelectScene, return -1 if the scene is not configed in the josn.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderSceneTest, SUB_Audio_HDI_AudioRenderSelectScene_0005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor scenes = {};
    struct AudioPort renderPort = {};
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    scenes.scene.id = 5;
    scenes.desc.pins = PIN_OUT_HDMI;
    ret = render->scene.SelectScene(render, &scenes);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
}