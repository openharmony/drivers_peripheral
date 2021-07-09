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
#include "audio_hdirender_control_test.h"

using namespace std;
using namespace testing::ext;
using namespace HMOS::Audio;

namespace {
const string AUDIO_FILE = "//bin/audiorendertest.wav";
const string ADAPTER_NAME = "hdmi";
const string ADAPTER_NAME2 = "usb";
const string ADAPTER_NAME3 = "internal";

class AudioHdiRenderControlTest : public testing::Test {
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
};

void AudioHdiRenderControlTest::SetUpTestCase(void) {}

void AudioHdiRenderControlTest::TearDownTestCase(void) {}

void AudioHdiRenderControlTest::SetUp(void)
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

void AudioHdiRenderControlTest::TearDown(void)
{
    if (GetAudioManager != nullptr) {
        GetAudioManager = nullptr;
    }
}

int32_t AudioHdiRenderControlTest::GetLoadAdapter(struct AudioManager manager, enum AudioPortDirection portType,
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
int32_t AudioHdiRenderControlTest::AudioCreateRender(enum AudioPortPin pins, struct AudioManager manager,
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
int32_t AudioHdiRenderControlTest::AudioRenderStart(const string path, struct AudioRender *render) const
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

/**
    * @tc.name  Test AudioRenderStart API via  legal input
    * @tc.number  SUB_Audio_HDI_RenderStart_0001
    * @tc.desc  Test AudioRenderStart interface,return 0 if the audiorender object is created successfully.
    * @tc.author: wangqian
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_RenderStart_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    } else {
        ret = render->control.Start((AudioHandle)render);
        EXPECT_EQ(HDF_SUCCESS, ret);

        ret = render->control.Stop((AudioHandle)render);
        EXPECT_EQ(HDF_SUCCESS, ret);

        adapter->DestroyRender(adapter, render);
        manager.UnloadAdapter(&manager, adapter);
    }
}
/**
    * @tc.name  Test AudioRenderStart API via setting the incoming parameter handle is nullptr
    * @tc.number  SUB_Audio_HDI_RenderStart_0002
    * @tc.desc  Test AudioRenderStart interface, return -1 if the  incoming parameter handle is nullptr
    * @tc.author: wangqian
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_RenderStart_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    } else {
        ret = render->control.Start((AudioHandle)renderNull);
        EXPECT_EQ(HDF_FAILURE, ret);

        adapter->DestroyRender(adapter, render);
        manager.UnloadAdapter(&manager, adapter);
    }
}
/**
* @tc.name Test AudioRenderStart API via the interface is called twice in a row
* @tc.number  SUB_Audio_HDI_RenderStart_0003
* @tc.desc  Test AudioRenderStart interface,return -1 the second time if the RenderStart is called twice
* @tc.author: Xuhuandi
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_RenderStart_0003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = render->control.Start((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->control.Start((AudioHandle)render);
    EXPECT_EQ(HDF_FAILURE, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name Test AudioRenderStop API via legal input
* @tc.number  SUB_Audio_HDI_RenderStop_0001
* @tc.desc  test AudioRenderStop interface. return 0 if the rendering is successfully stopped.
* @tc.author: Xuhuandi
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_RenderStop_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    } else {
        ret = render->control.Start((AudioHandle)render);
        EXPECT_EQ(HDF_SUCCESS, ret);

        ret = render->control.Stop((AudioHandle)render);
        EXPECT_EQ(HDF_SUCCESS, ret);

        adapter->DestroyRender(adapter, render);
        manager.UnloadAdapter(&manager, adapter);
    }
}
/**
* @tc.name Test AudioRenderStop API via the render does not start and stop only
* @tc.number  SUB_Audio_HDI_RenderStop_0002
* @tc.desc  test AudioRenderStop interface. return -4 if the render does not start and stop only
* @tc.author: Xuhuandi
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_RenderStop_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    } else {
        ret = render->control.Stop((AudioHandle)render);
        EXPECT_EQ(HDF_ERR_INVALID_OBJECT, ret);

        adapter->DestroyRender(adapter, render);
        manager.UnloadAdapter(&manager, adapter);
    }
}
/**
* @tc.name Test RenderStop API via the interface is called twice in a row
* @tc.number  SUB_Audio_HDI_RenderStop_0003
* @tc.desc  Test RenderStop interface,return -4 the second time if the RenderStop is called twice
* @tc.author: Xuhuandi
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_RenderStop_0003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    } else {
        ret = render->control.Start((AudioHandle)render);
        EXPECT_EQ(HDF_SUCCESS, ret);

        ret = render->control.Stop((AudioHandle)render);
        EXPECT_EQ(HDF_SUCCESS, ret);

        ret = render->control.Stop((AudioHandle)render);
        EXPECT_EQ(HDF_ERR_INVALID_OBJECT, ret);

        adapter->DestroyRender(adapter, render);
        manager.UnloadAdapter(&manager, adapter);
    }
}
/**
* @tc.name Test RenderStop API via setting the incoming parameter handle is nullptr
* @tc.number  SUB_Audio_HDI_RenderStop_0004
* @tc.desc  Test RenderStop interface, return -1 if the incoming parameter handle is nullptr
* @tc.author: Xuhuandi
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_RenderStop_0004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    } else {
        ret = render->control.Start((AudioHandle)render);
        EXPECT_EQ(HDF_SUCCESS, ret);

        ret = render->control.Stop((AudioHandle)renderNull);
        EXPECT_EQ(HDF_FAILURE, ret);

        render->control.Stop((AudioHandle)render);
        adapter->DestroyRender(adapter, render);
        manager.UnloadAdapter(&manager, adapter);
    }
}
/**
    * @tc.name  Test RenderPause API via legal input
    * @tc.number  SUB_Audio_HDI_RenderPause_001
    * @tc.desc  test HDI RenderPause interface，return 0 if the render is paused after start
    * @tc.author: Xuhuandi
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_RenderPause_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->control.Pause((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name Test AudioRenderPause API via the interface is called twice in a row
* @tc.number  SUB_Audio_HDI_RenderPause_0002
* @tc.desc  Test AudioRenderPause interface, return -1 the second time if RenderPause is called twice
* @tc.author: Xuhuandi
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_RenderPause_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->control.Pause((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->control.Pause((AudioHandle)render);
    EXPECT_EQ(HDF_FAILURE, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name Test AudioRenderPause API via the render is paused before Started.
* @tc.number  SUB_Audio_HDI_RenderPause_0003
* @tc.desc  Test AudioRenderPause interface,return -1 if the render is paused before Started.
* @tc.author: Xuhuandi
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_RenderPause_0003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = render->control.Pause((AudioHandle)render);
    EXPECT_EQ(HDF_FAILURE, ret);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name Test AudioRenderPause API via the render is paused after resumed.
* @tc.number  SUB_Audio_HDI_RenderPause_0004
* @tc.desc  Test AudioRenderPause interface,return 0 if the render is paused after resumed.
* @tc.author: Xuhuandi
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_RenderPause_0004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->control.Pause((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->control.Resume((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->control.Pause((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name Test AudioRenderPause API via the render is paused after stoped.
* @tc.number  SUB_Audio_HDI_RenderPause_0005
* @tc.desc  Test AudioRenderPause interface, return -1 the render is paused after stoped.
* @tc.author: Xuhuandi
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_RenderPause_0005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->control.Stop((AudioHandle)render);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = render->control.Pause((AudioHandle)render);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test RenderResume API via the render is resumed after started
    * @tc.number  SUB_Audio_HDI_RenderResume_0001
    * @tc.desc  test HDI RenderResume interface,return -1 if the render is resumed after started
    * @tc.author: Xuhuandi
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_RenderResume_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->control.Resume((AudioHandle)render);
    EXPECT_EQ(HDF_FAILURE, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test RenderResume API via the render is resumed after stopped
    * @tc.number  SUB_Audio_HDI_RenderResume_0002
    * @tc.desc  test HDI RenderResume interface,return -1 if the render is resumed after stopped
    * @tc.author: Xuhuandi
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_RenderResume_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->control.Resume((AudioHandle)render);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test RenderResume API via legal input
    * @tc.number  SUB_Audio_HDI_RenderResume_0003
    * @tc.desc  Test AudioRenderResume interface,return 0 if the render is resumed after paused
    * @tc.author: Xuhuandi
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_RenderResume_0003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->control.Pause((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->control.Resume((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test RenderResume API via the interface is called twice in a row
    * @tc.number  SUB_Audio_HDI_RenderResume_0004
    * @tc.desc  Test RenderResume interface,return -1 the second time if the RenderResume is called twice
    * @tc.author: Xuhuandi
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_RenderResume_0004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->control.Pause((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->control.Resume((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->control.Resume((AudioHandle)render);
    EXPECT_EQ(HDF_FAILURE, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test RenderResume API via the render Continue to start after resume
    * @tc.number  SUB_Audio_HDI_RenderResume_0005
    * @tc.desc  test HDI RenderResume interface,return -1 if the render Continue to start after resume
    * @tc.author: Xuhuandi
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_RenderResume_0005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->control.Pause((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->control.Resume((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_FAILURE, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test RenderResume API via the render is resumed before stopped
    * @tc.number  SUB_Audio_HDI_RenderResume_0006
    * @tc.desc  test HDI RenderResume interface,return 0 if the render is resumed before stopped
    * @tc.author: Xuhuandi
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_RenderResume_0006, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->control.Pause((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->control.Resume((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test AudioCreateRender API via legal input.
    * @tc.number  SUB_Audio_HDI_CreateRender_0001
    * @tc.desc  test AudioCreateRender interface,return 0 if render is created successful.
    * @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_CreateRender_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test AudioCreateRender API when two renders is created successful.
    * @tc.number  SUB_Audio_HDI_AudioCreateRender_0002
    * @tc.desc  Test AudioCreateRender interface,return 0 when two renders is created successful.
    * @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_AudioCreateRender_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioAdapter *adapter2 = nullptr;
    struct AudioPort renderPort = {};
    struct AudioPort renderPort2 = {};
    struct AudioRender *render = nullptr;
    struct AudioRender *render2 = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter2, renderPort2);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter2, renderPort2, &render2);
    EXPECT_EQ(HDF_SUCCESS, ret);
    adapter->DestroyRender(adapter2, render2);
    manager.UnloadAdapter(&manager, adapter2);
}
/**
    * @tc.name  Test AudioCreateRender API via setting the incoming parameter pins is PIN_IN_MIC.
    * @tc.number  SUB_Audio_HDI_CreateRender_0003
    * @tc.desc  test AudioCreateRender interface,return -1 if the incoming parameter pins is PIN_IN_MIC.
    * @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_CreateRender_0003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    InitAttrs(attrs);
    InitDevDesc(devDesc, renderPort.portId, PIN_IN_MIC);

    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render);
    EXPECT_EQ(HDF_FAILURE, ret);
    manager.UnloadAdapter(&manager, adapter);
}

/**
    * @tc.name  Test AudioCreateRender API via setting the incoming parameter attr is error.
    * @tc.number  SUB_Audio_HDI_CreateRender_0004
    * @tc.desc  test AudioCreateRender interface,return -1 if the incoming parameter attr is error.
    * @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_CreateRender_0004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    uint32_t channelCountErr = 5;
    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    InitAttrs(attrs);
    InitDevDesc(devDesc, renderPort.portId, PIN_OUT_SPEAKER);
    attrs.format = AUDIO_FORMAT_AAC_MAIN;
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render);
    EXPECT_EQ(HDF_FAILURE, ret);
    attrs.channelCount = channelCountErr;
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render);
    EXPECT_EQ(HDF_FAILURE, ret);
    attrs.type = AUDIO_IN_COMMUNICATION;
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render);
    EXPECT_EQ(HDF_FAILURE, ret);

    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test AudioCreateRender API via setting the incoming parameter adapter is nullptr
    * @tc.number  SUB_Audio_HDI_CreateRender_0005
    * @tc.desc  test AudioCreateRender interface,Returns -1 if the incoming parameter adapter is nullptr.
    * @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_CreateRender_0005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioAdapter *adapterNull = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    InitAttrs(attrs);
    InitDevDesc(devDesc, renderPort.portId, PIN_OUT_SPEAKER);

    ret = adapter->CreateRender(adapterNull, &devDesc, &attrs, &render);
    EXPECT_EQ(HDF_FAILURE, ret);

    manager.UnloadAdapter(&manager, adapter);
}

/**
    * @tc.name  Test AudioCreateRender API via setting the incoming parameter devDesc is nullptr
    * @tc.number  SUB_Audio_HDI_CreateRender_0006
    * @tc.desc  test AudioCreateRender interface,Returns -1 if the incoming parameter devDesc is nullptr.
    * @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_CreateRender_0006, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor *devDescNull = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    InitAttrs(attrs);

    ret = adapter->CreateRender(adapter, devDescNull, &attrs, &render);
    EXPECT_EQ(HDF_FAILURE, ret);

    manager.UnloadAdapter(&manager, adapter);
}

/**
    * @tc.name  Test AudioCreateRender API via setting the incoming parameter attrs is nullptr
    * @tc.number  SUB_Audio_HDI_CreateRender_0007
    * @tc.desc  test AudioCreateRender interface,Returns -1 if the incoming parameter attrs is nullptr.
    * @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_CreateRender_0007, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes *attrsNull = nullptr;
    struct AudioDeviceDescriptor devDesc = {};
    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    InitDevDesc(devDesc, renderPort.portId, PIN_OUT_SPEAKER);

    ret = adapter->CreateRender(adapter, &devDesc, attrsNull, &render);
    EXPECT_EQ(HDF_FAILURE, ret);

    manager.UnloadAdapter(&manager, adapter);
}

/**
    * @tc.name  Test AudioCreateRender API via setting the incoming parameter render is nullptr
    * @tc.number  SUB_Audio_HDI_CreateRender_0008
    * @tc.desc  test AudioCreateRender interface,Returns -1 if the incoming parameter render is nullptr.
    * @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_CreateRender_0008, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender **renderNull = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    InitAttrs(attrs);
    InitDevDesc(devDesc, renderPort.portId, PIN_OUT_SPEAKER);

    ret = adapter->CreateRender(adapter, &devDesc, &attrs, renderNull);
    EXPECT_EQ(HDF_FAILURE, ret);

    manager.UnloadAdapter(&manager, adapter);
}

/**
    * @tc.name  Test AudioCreateRender API via setting the incoming parameter devDesc is error
    * @tc.number  SUB_Audio_HDI_CreateRender_0009
    * @tc.desc  test AudioCreateRender interface,Returns -1 if the incoming parameter devDesc is error.
    * @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_CreateRender_0009, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = InitAttrs(attrs);
    InitDevDesc(devDesc, renderPort.portId, PIN_OUT_SPEAKER);

    devDesc.portId = -5;
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render);
    EXPECT_EQ(HDF_FAILURE, ret);
    devDesc.pins = PIN_NONE;
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render);
    EXPECT_EQ(HDF_FAILURE, ret);
    devDesc.desc = "devtestname";
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render);
    EXPECT_EQ(HDF_FAILURE, ret);

    manager.UnloadAdapter(&manager, adapter);
}

/**
    * @tc.name  Test AudioDestroyRender API via legal input.
    * @tc.number  SUB_Audio_HDI_DestroyRender_0001
    * @tc.desc  Test AudioDestroyRender interface, return 0 if render is destroyed successful.
    * @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_DestroyRender_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = adapter->DestroyRender(adapter, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test AudioDestroyRender API,where the parameter render is empty.
    * @tc.number  SUB_Audio_HDI_DestroyRender_0002
    * @tc.desc  Test AudioDestroyRender interface, return -1 if the parameter render is empty.
    * @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_DestroyRender_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = adapter->DestroyRender(adapter, renderNull);
    EXPECT_EQ(HDF_FAILURE, ret);
    manager.UnloadAdapter(&manager, adapter);
}

/**
    * @tc.name  Test RenderFlush API via legal input Verify that the data in the buffer is flushed after stop
    * @tc.number  SUB_Audio_HDI_RenderFlush_0001
    * @tc.desc  Test RenderFlush interface,return -2 if the data in the buffer is flushed successfully after stop
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_RenderFlush_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->control.Flush((AudioHandle)render);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test RenderFlush that the data in the buffer is flushed when handle is nullptr after paused
    * @tc.number  SUB_Audio_HDI_RenderFlush_0002
    * @tc.desc  Test RenderFlush, return -2 if the data in the buffer is flushed when handle is nullptr after paused
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderControlTest, SUB_Audio_HDI_RenderFlush_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME2, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->control.Pause((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->control.Flush((AudioHandle)renderNull);
    EXPECT_EQ(HDF_FAILURE, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
}