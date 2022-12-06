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
using namespace OHOS::Audio;

namespace {
class AudioHdiRenderControlTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static TestAudioManager *manager;
};

TestAudioManager *AudioHdiRenderControlTest::manager = nullptr;

void AudioHdiRenderControlTest::SetUpTestCase(void)
{
    manager = GetAudioManagerFuncs();
    ASSERT_NE(nullptr, manager);
}

void AudioHdiRenderControlTest::TearDownTestCase(void) {}

void AudioHdiRenderControlTest::SetUp(void) {}

void AudioHdiRenderControlTest::TearDown(void) {}

/**
    * @tc.name  AudioRenderStart_001
    * @tc.desc  Test AudioRenderStart interface,return 0 if the audiorender object is created successfully.
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioRenderStart_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Start((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderStart_002
    * @tc.desc  Test AudioRenderStart interface, return -1 if the  incoming parameter handle is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioRenderStart_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Start((AudioHandle)renderNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderStart_003
* @tc.desc  Test AudioRenderStart interface,return -1 the second time if the RenderStart is called twice
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioRenderStart_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Start((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Start((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_ERR_AO_BUSY, ret);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderStop_001
* @tc.desc  test AudioRenderStop interface. return 0 if the rendering is successfully stopped.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioRenderStop_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Start((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderStop_002
* @tc.desc  test AudioRenderStop interface. return -4 if the render does not start and stop only
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioRenderStop_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderStop_003
* @tc.desc  Test RenderStop interface,return -4 the second time if the RenderStop is called twice
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioRenderStop_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Start((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderStop_004
* @tc.desc  Test RenderStop interface, return -1 if the incoming parameter handle is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioRenderStop_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Start((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Stop((AudioHandle)renderNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderPause_001
    * @tc.desc  test HDI RenderPause interface，return 0 if the render is paused after start
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioRenderPause_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Pause((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderPause_002
* @tc.desc  Test AudioRenderPause interface, return -1 the second time if RenderPause is called twice
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioRenderPause_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Pause((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Pause((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderPause_003
* @tc.desc  Test AudioRenderPause interface,return -1 if the render is paused after created.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioRenderPause_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Pause((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderPause_004
* @tc.desc  Test AudioRenderPause interface,return 0 if the render is paused after resumed.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioRenderPause_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Pause((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Resume((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Pause((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderPause_005
* @tc.desc  Test AudioRenderPause interface, return -1 the render is paused after stopped.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioRenderPause_005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Stop((AudioHandle)render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Pause((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderPause_006
* @tc.desc  Test RenderPause interface, return -1 if the incoming parameter handle is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioRenderPause_006, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Pause((AudioHandle)renderNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderResume_001
    * @tc.desc  test HDI RenderResume interface,return -1 if the render is resumed after started
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioRenderResume_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Resume((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, ret);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderResume_002
    * @tc.desc  test HDI RenderResume interface,return -1 if the render is resumed after stopped
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioRenderResume_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Resume((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderResume_003
    * @tc.desc  Test AudioRenderResume interface,return 0 if the render is resumed after paused
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioRenderResume_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Pause((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Resume((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderResume_004
    * @tc.desc  Test RenderResume interface,return -1 the second time if the RenderResume is called twice
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioRenderResume_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Pause((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Resume((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Resume((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, ret);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderResume_005
    * @tc.desc  test HDI RenderResume interface,return -1 if the render Continue to start after resume
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioRenderResume_005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Pause((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Resume((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Start((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_ERR_AO_BUSY, ret);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderResume_007
* @tc.desc  Test RenderResume interface, return -1 if the incoming parameter handle is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioRenderResume_006, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Pause((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Resume((AudioHandle)renderNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCreateRender_001
    * @tc.desc  test AudioCreateRender interface,return 0 if render is created successful.
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioCreateRender_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCreateRender_003
    * @tc.desc  test AudioCreateRender interface,return -1 if the incoming parameter pins is PIN_IN_MIC.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioCreateRender_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioPort* renderPort = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    InitAttrs(attrs);
    InitDevDesc(devDesc, renderPort->portId, PIN_IN_MIC);

    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
    manager->UnloadAdapter(manager, adapter);
}

/**
    * @tc.name  AudioCreateRender_004
    * @tc.desc  test AudioCreateRender interface,return -1 if the incoming parameter attr is error.
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioCreateRender_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioPort* renderPort = nullptr;
    uint32_t channelCountErr = 5;
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    InitAttrs(attrs);
    InitDevDesc(devDesc, renderPort->portId, PIN_OUT_SPEAKER);
    attrs.format = AUDIO_FORMAT_AAC_MAIN;
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
    attrs.channelCount = channelCountErr;
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
    attrs.type = AUDIO_IN_COMMUNICATION;
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCreateRender_005
    * @tc.desc  test AudioCreateRender interface,Returns -1 if the incoming parameter adapter is nullptr.
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioCreateRender_005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioAdapter *adapterNull = nullptr;
    struct AudioPort* renderPort = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    InitAttrs(attrs);
    InitDevDesc(devDesc, renderPort->portId, PIN_OUT_SPEAKER);

    ret = adapter->CreateRender(adapterNull, &devDesc, &attrs, &render);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    manager->UnloadAdapter(manager, adapter);
}

/**
    * @tc.name  AudioCreateRender_006
    * @tc.desc  test AudioCreateRender interface,Returns -1 if the incoming parameter devDesc is nullptr.
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioCreateRender_006, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioRender *render = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort* renderPort = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor *devDescNull = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    InitAttrs(attrs);

    ret = adapter->CreateRender(adapter, devDescNull, &attrs, &render);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    manager->UnloadAdapter(manager, adapter);
}

/**
    * @tc.name  AudioCreateRender_007
    * @tc.desc  test AudioCreateRender interface,Returns -1 if the incoming parameter attrs is nullptr.
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioCreateRender_007, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort* renderPort = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes *attrsNull = nullptr;
    struct AudioDeviceDescriptor devDesc = {};
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    InitDevDesc(devDesc, renderPort->portId, PIN_OUT_SPEAKER);

    ret = adapter->CreateRender(adapter, &devDesc, attrsNull, &render);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    manager->UnloadAdapter(manager, adapter);
}

/**
    * @tc.name  AudioCreateRender_008
    * @tc.desc  test AudioCreateRender interface,Returns -1 if the incoming parameter render is nullptr.
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioCreateRender_008, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender **renderNull = nullptr;
    struct AudioPort* renderPort = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    InitAttrs(attrs);
    InitDevDesc(devDesc, renderPort->portId, PIN_OUT_SPEAKER);

    ret = adapter->CreateRender(adapter, &devDesc, &attrs, renderNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    manager->UnloadAdapter(manager, adapter);
}

/**
    * @tc.name  AudioCreateRender_009
    * @tc.desc  test AudioCreateRender interface,Returns -1 if the incoming parameter devDesc is error.
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioCreateRender_009, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioPort* renderPort = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    InitAttrs(attrs);
    InitDevDesc(devDesc, renderPort->portId, PIN_OUT_SPEAKER);

    devDesc.portId = -5;
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
    devDesc.pins = PIN_NONE;
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
    devDesc.desc = "devtestname";
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCreateRender_010
    * @tc.desc  test AudioCreateRender interface,Returns -1 if the incoming desc which portID is not configured
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioCreateRender_010, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioPort* renderPort = nullptr;
    uint32_t portID = 10;
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    InitAttrs(attrs);
    InitDevDesc(devDesc, portID, PIN_OUT_SPEAKER);

    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
    ret = adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioDestroyRender_001
    * @tc.desc  Test AudioDestroyRender interface, return 0 if render is destroyed successful.
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioDestroyRender_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = adapter->DestroyRender(adapter, render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioDestroyRender_002
    * @tc.desc  Test AudioDestroyRender interface, return -1 if the parameter render is empty.
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioDestroyRender_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = adapter->DestroyRender(adapter, renderNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    ret = adapter->DestroyRender(adapter, render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    manager->UnloadAdapter(manager, adapter);
}

/**
    * @tc.name  AudioRenderFlush_001
    * @tc.desc  Test RenderFlush interface,return -2 if the data in the buffer is flushed successfully after stop
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioRenderFlush_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Flush((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderFlush_002
    * @tc.desc  Test RenderFlush, return -1 if the data in the buffer is flushed when handle is nullptr after paused
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderControlTest, AudioRenderFlush_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Pause((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Flush((AudioHandle)renderNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
}
