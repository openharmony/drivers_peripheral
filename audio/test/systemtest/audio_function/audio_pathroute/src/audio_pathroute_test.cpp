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
 * @brief Test audio route path function
 *
 * @since 1.0
 * @version 1.0
 */

#include "audio_hdi_common.h"
#include "audio_pathroute_test.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
const int REGISTER_STATUS_ON = 1;
const int REGISTER_STATUS_OFF = 0;
static struct AudioCtlElemValue g_elemValues[4] = {
    {
        .id.cardServiceName = "hdf_audio_codec_primary_dev0",
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER,
        .id.itemName = "Dacl enable",
        .value[0] = 0,
    }, {
        .id.cardServiceName = "hdf_audio_codec_primary_dev0",
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER,
        .id.itemName = "Dacr enable",
        .value[0] = 0,
    }, {
        .id.cardServiceName = "hdf_audio_codec_primary_dev0",
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER,
        .id.itemName = "LPGA MIC Switch",
        .value[0] = 0,
    }, {
        .id.cardServiceName = "hdf_audio_codec_primary_dev0",
        .id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER,
        .id.itemName = "RPGA MIC Switch",
        .value[0] = 0,
    }
};
class AudioPathRouteTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static TestAudioManager *manager;
};

TestAudioManager *AudioPathRouteTest::manager = nullptr;

void AudioPathRouteTest::SetUpTestCase(void)
{
    manager = GetAudioManagerFuncs();
    ASSERT_NE(nullptr, manager);
}

void AudioPathRouteTest::TearDownTestCase(void) {}

void AudioPathRouteTest::SetUp(void) {}

void AudioPathRouteTest::TearDown(void) {}

/**
* @tc.name  AudioPathRoute_001
* @tc.desc  The audio path route can be opened successfully,When it is set to
            palyback scene(attrs.type = AUDIO_IN_MEDIA,pins = PIN_OUT_SPEAKER)
* @tc.type: FUNC
*/
HWTEST_F(AudioPathRouteTest, AudioPathRoute_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioRender *render = nullptr;
    struct AudioAdapter *adapter = nullptr;
    ret = PowerOff(g_elemValues[0], g_elemValues[1]);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = CheckRegisterStatus(g_elemValues[0].id, g_elemValues[1].id, REGISTER_STATUS_ON, REGISTER_STATUS_ON);
    EXPECT_EQ(HDF_SUCCESS, ret);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioPathRoute_002
* @tc.desc  The audio path route can be opened successfully,When switching
            device(attrs.type = AUDIO_IN_MEDIA,pins = PIN_OUT_HEADSET)
* @tc.type: FUNC
*/
HWTEST_F(AudioPathRouteTest, AudioPathRoute_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioRender *render = nullptr;
    struct AudioAdapter *adapter = nullptr;
    g_elemValues[0].value[0] = 1;
    g_elemValues[1].value[0] = 1;
    ret = PowerOff(g_elemValues[0], g_elemValues[1]);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    struct AudioSceneDescriptor scene = {
        .scene.id = 0,
        .desc.pins = PIN_OUT_HEADSET,
    };
    ret = render->scene.SelectScene(AudioHandle(render), &scene);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = CheckRegisterStatus(g_elemValues[0].id, g_elemValues[1].id, REGISTER_STATUS_OFF, REGISTER_STATUS_OFF);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioPathRoute_003
* @tc.desc  The audio path route of playback scene can be opened successfully,When The current
            audio path route has been opened
* @tc.type: FUNC
*/
HWTEST_F(AudioPathRouteTest, AudioPathRoute_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioRender *render = nullptr;
    struct AudioAdapter *adapter = nullptr;
    ret = PowerOff(g_elemValues[0], g_elemValues[1]);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    struct AudioSceneDescriptor scene = {
        .scene.id = 0,
        .desc.pins = PIN_OUT_SPEAKER,
    };
    ret = render->scene.SelectScene(AudioHandle(render), &scene);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = CheckRegisterStatus(g_elemValues[0].id, g_elemValues[1].id, REGISTER_STATUS_ON, REGISTER_STATUS_ON);
    EXPECT_EQ(HDF_SUCCESS, ret);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioPathRoute_004
* @tc.desc  The audio path route can be opened successfully,When it is set to
            recording scene(attrs.type = AUDIO_IN_MEDIA,pins = PIN_IN_MIC)
* @tc.type: FUNC
*/
HWTEST_F(AudioPathRouteTest, AudioPathRoute_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    g_elemValues[3].value[0] = 1;
    ret = PowerOff(g_elemValues[2], g_elemValues[3]);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = CheckRegisterStatus(g_elemValues[2].id, g_elemValues[3].id, REGISTER_STATUS_ON, REGISTER_STATUS_OFF);
    EXPECT_EQ(HDF_SUCCESS, ret);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioPathRoute_005
* @tc.desc  The audio path route can be opened successfully,When it is set to
            recording scene(attrs.type = AUDIO_IN_MEDIA,pins = PIN_IN_HS_MIC)
* @tc.type: FUNC
*/
HWTEST_F(AudioPathRouteTest, AudioPathRoute_005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    g_elemValues[2].value[0] = 1;
    g_elemValues[3].value[0] = 1;
    ret = PowerOff(g_elemValues[2], g_elemValues[3]);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    struct AudioSceneDescriptor scene = {
        .scene.id = 0,
        .desc.pins = PIN_IN_HS_MIC,
    };
    ret = capture->scene.SelectScene(AudioHandle(capture), &scene);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = CheckRegisterStatus(g_elemValues[2].id, g_elemValues[3].id, REGISTER_STATUS_OFF, REGISTER_STATUS_OFF);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioPathRoute_006
* @tc.desc  The audio path route of recording scene can be opened successfully,When The current
            audio path route has been opened
* @tc.type: FUNC
*/
HWTEST_F(AudioPathRouteTest, AudioPathRoute_006, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    g_elemValues[3].value[0] = 1;
    ret = PowerOff(g_elemValues[2], g_elemValues[3]);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    struct AudioSceneDescriptor scene = {
        .scene.id = 0,
        .desc.pins = PIN_IN_MIC,
    };
    ret = capture->scene.SelectScene(AudioHandle(capture), &scene);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = CheckRegisterStatus(g_elemValues[2].id, g_elemValues[3].id, REGISTER_STATUS_ON, REGISTER_STATUS_OFF);
    EXPECT_EQ(HDF_SUCCESS, ret);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioPathRoute_007
* @tc.desc  The audio path route can be opened successfully,When running multi service scenarios
* @tc.type: FUNC
*/
HWTEST_F(AudioPathRouteTest, AudioPathRoute_007, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioPort* audioPort = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor renderDevDesc = {};
    struct AudioDeviceDescriptor captureDevDesc = {};
    ret = PowerOff(g_elemValues[0], g_elemValues[1]);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = PowerOff(g_elemValues[2], g_elemValues[3]);
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrs(attrs);
    InitDevDesc(renderDevDesc, audioPort->portId, PIN_OUT_SPEAKER);
    InitDevDesc(captureDevDesc, audioPort->portId, PIN_IN_MIC);
    ret = adapter->CreateRender(adapter, &renderDevDesc, &attrs, &render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = CheckRegisterStatus(g_elemValues[0].id, g_elemValues[1].id, REGISTER_STATUS_ON, REGISTER_STATUS_ON);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->CreateCapture(adapter, &captureDevDesc, &attrs, &capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = CheckRegisterStatus(g_elemValues[2].id, g_elemValues[3].id, REGISTER_STATUS_ON, REGISTER_STATUS_OFF);
    EXPECT_EQ(HDF_SUCCESS, ret);

    adapter->DestroyCapture(adapter, capture);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
}
