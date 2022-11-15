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
 * @brief Test audio-related APIs, including custom data types and functions for loading drivers,
 * accessing a driver adapter.
 *
 * @since 1.0
 * @version 1.0
 */

/**
 * @file audio_hdi_common.h
 *
 * @brief Declares APIs for operations related to the audio adapter.
 *
 * @since 1.0
 * @version 1.0
 */

#include "audio_hdi_common.h"
#include "audio_usb_render_test.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
const string ADAPTER_NAME_USB = "usb";

class AudioUsbRenderTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static TestAudioManager *manager;
};

using THREAD_FUNC = void *(*)(void *);
TestAudioManager *AudioUsbRenderTest::manager = nullptr;

void AudioUsbRenderTest::SetUpTestCase(void)
{
    manager = GetAudioManagerFuncs();
    ASSERT_NE(nullptr, manager);
}

void AudioUsbRenderTest::TearDownTestCase(void) {}

void AudioUsbRenderTest::SetUp(void) {}

void AudioUsbRenderTest::TearDown(void) {}

/**
* @tc.name  AudioRenderGetMute_001
* @tc.desc  Test AudioRenderGetMute interface , return 0 if the audiocapture gets mute successfully.
* @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderGetMute_001, TestSize.Level1)
{
    int32_t ret = -1;
    bool muteTrue = true;
    bool muteFalse = false;
    bool defaultmute = false;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->volume.GetMute(render, &muteFalse);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(muteFalse, defaultmute);

    ret = render->volume.SetMute(render, muteTrue);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->volume.GetMute(render, &muteTrue);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_TRUE(muteTrue);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioRenderSetMute_001
* @tc.desc  Test AudioRenderSetMute interface , return 0 if the audiorender object sets mute successfully.
* @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderSetMute_001, TestSize.Level1)
{
    int32_t ret = -1;
    bool muteFalse = false;
    bool muteTrue = true;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->volume.SetMute(render, muteFalse);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->volume.GetMute(render, &muteFalse);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(false, muteFalse);

    ret = render->volume.SetMute(render, muteTrue);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->volume.GetMute(render, &muteTrue);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(true, muteTrue);

    muteTrue = false;
    ret = render->volume.SetMute(render, muteTrue);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_FALSE(muteTrue);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderSetVolume_001
* @tc.desc  Test AudioRenderSetVolume interface , return 0 if the audiocapture sets volume successfully.
* @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderSetVolume_001, TestSize.Level1)
{
    int32_t ret = -1;
    float volumeInit = 0.20;
    float volumeInitExpc = 0.20;
    float volumeLow = 0.10;
    float volumeLowExpc = 0.10;
    float volumeMid = 0.50;
    float volumeMidExpc = 0.50;
    float volumeHigh = 0.80;
    float volumeHighExpc = 0.80;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->volume.SetVolume(render, volumeInit);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->volume.GetVolume(render, &volumeInit);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(volumeInitExpc, volumeInit);
    ret = render->volume.SetVolume(render, volumeLow);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->volume.GetVolume(render, &volumeLow);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(volumeLowExpc, volumeLow);
    ret = render->volume.SetVolume(render, volumeMid);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->volume.GetVolume(render, &volumeMid);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(volumeMidExpc, volumeMid);
    ret = render->volume.SetVolume(render, volumeHigh);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->volume.GetVolume(render, &volumeHigh);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(volumeHighExpc, volumeHigh);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderGetVolume_001
* @tc.desc  Test AudioRenderGetVolume interface , return 0 if the audiocapture is get successful.
* @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderGetVolume_001, TestSize.Level1)
{
    int32_t ret = -1;
    float volume = 0.30;
    float volumeDefault = 0.30;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->volume.SetVolume(render, volume);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->volume.GetVolume(render, &volume);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(volumeDefault, volume);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioRenderSetSampleAttributes_001
* @tc.desc  Test AudioRenderSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = AUDIO_SAMPLE_RATE_MASK_8000;
*    attrs.channelCount = 1;
* @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderSetSampleAttributes_001, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t ret1 = 1;
    uint32_t ret2 = 8000;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, 1, 8000);

    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->attr.GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(ret2, attrsValue.sampleRate);
    EXPECT_EQ(ret1, attrsValue.channelCount);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderGetSampleAttributes_001
* @tc.desc  Test AudioRenderGetSampleAttributes ,the setting parameters are as follows.
* @tc.type: FUNC
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = 8000;
*    attrs.channelCount = 1;
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderGetSampleAttributes_001, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t ret1 = 8000;
    uint32_t ret2 = 1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, 1, 8000);
    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(ret1, attrsValue.sampleRate);
    EXPECT_EQ(ret2, attrsValue.channelCount);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderStart_001
    * @tc.desc  Test AudioRenderStart interface,return 0 if the audiorender object is created successfully.
    * @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderStart_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Start((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderStart_003
* @tc.desc  Test AudioRenderStart interface,return -1 the second time if the RenderStart is called twice
* @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderStart_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
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
HWTEST_F(AudioUsbRenderTest, AudioRenderStop_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
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
HWTEST_F(AudioUsbRenderTest, AudioRenderStop_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
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
HWTEST_F(AudioUsbRenderTest, AudioRenderStop_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
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
    * @tc.name  AudioRenderPause_01
    * @tc.desc  test HDI RenderPause interface，return 0 if the render is paused after start
    * @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderPause_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME_USB);
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
HWTEST_F(AudioUsbRenderTest, AudioRenderPause_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME_USB);
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
HWTEST_F(AudioUsbRenderTest, AudioRenderPause_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Pause((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderPause_005
* @tc.desc  Test AudioRenderPause interface, return -1 the render is paused after stopped.
* @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderPause_005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME_USB);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Stop((AudioHandle)render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Pause((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderResume_001
    * @tc.desc  test HDI RenderResume interface,return -1 if the render is resumed after started
    * @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderResume_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME_USB);
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
HWTEST_F(AudioUsbRenderTest, AudioRenderResume_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME_USB);
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
HWTEST_F(AudioUsbRenderTest, AudioRenderResume_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME_USB);
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
HWTEST_F(AudioUsbRenderTest, AudioRenderResume_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME_USB);
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
HWTEST_F(AudioUsbRenderTest, AudioRenderResume_005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME_USB);
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
* @tc.name  AudioRenderFrame_001
* @tc.desc  test AudioRenderFrame interface,Returns 0 if the data is written successfully
* @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderFrame_001, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t requestBytes = 0;
    uint64_t replyBytes = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    char *frame = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
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
* @tc.name  AudioRenderFrame_005
* @tc.desc  Test AudioRenderFrame interface,Returns -1 if without calling interface renderstart
* @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderFrame_005, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t replyBytes = 0;
    uint64_t requestBytes = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    char *frame = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = RenderFramePrepare(AUDIO_FILE, frame, requestBytes);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->RenderFrame(render, frame, requestBytes, &replyBytes);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}
/**
    * @tc.name  AudioRenderSetChannelMode_001
    * @tc.desc  Test SetChannelMode interface,return 0 if set channel mode to different enumeration values
    * @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderSetChannelMode_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;
    AudioChannelMode modeOne = AUDIO_CHANNEL_BOTH_LEFT;
    AudioChannelMode modeSec = AUDIO_CHANNEL_BOTH_RIGHT;
    AudioChannelMode modeTrd = AUDIO_CHANNEL_EXCHANGE;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME_USB);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->SetChannelMode(render, mode);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetChannelMode(render, &mode);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_NORMAL, mode);
    ret = render->SetChannelMode(render, modeOne);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetChannelMode(render, &modeOne);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_BOTH_LEFT, modeOne);
    ret = render->SetChannelMode(render, modeSec);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetChannelMode(render, &modeSec);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_BOTH_RIGHT, modeSec);
    ret = render->SetChannelMode(render, modeTrd);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetChannelMode(render, &modeTrd);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_EXCHANGE, modeTrd);
    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderSetChannelMode_002
    * @tc.desc  Test SetChannelMode interface,return 0 if set channel mode to different values
    * @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderSetChannelMode_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    AudioChannelMode mode = AUDIO_CHANNEL_MIX;
    AudioChannelMode modeOne = AUDIO_CHANNEL_LEFT_MUTE;
    AudioChannelMode modeSec = AUDIO_CHANNEL_RIGHT_MUTE;
    AudioChannelMode modeTrd = AUDIO_CHANNEL_BOTH_MUTE;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME_USB);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->SetChannelMode(render, mode);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetChannelMode(render, &mode);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_MIX, mode);
    ret = render->SetChannelMode(render, modeOne);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetChannelMode(render, &modeOne);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_LEFT_MUTE, modeOne);
    ret = render->SetChannelMode(render, modeSec);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetChannelMode(render, &modeSec);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_RIGHT_MUTE, modeSec);
    ret = render->SetChannelMode(render, modeTrd);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetChannelMode(render, &modeTrd);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_BOTH_MUTE, modeTrd);
    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderSetChannelMode_003
    * @tc.desc  Test SetChannelMode interface,return 0 if set channel mode after render object is created
    * @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderSetChannelMode_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->SetChannelMode(render, mode);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetChannelMode(render, &mode);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_NORMAL, mode);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetChannelMode_001
    * @tc.desc  Test GetChannelMode interface,return 0 if getting the channel mode after setting
    * @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderGetChannelMode_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME_USB);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->GetChannelMode(render, &mode);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->SetChannelMode(render, mode);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetChannelMode(render, &mode);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_NORMAL, mode);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetChannelMode_003
    * @tc.desc  Test GetChannelMode interface,return 0 if getting the channel mode after the object is created
    * @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderGetChannelMode_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetChannelMode(render, &mode);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_NORMAL, mode);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderSetRenderSpeed_001
    * @tc.desc  Test SetRenderSpeed interface,return -2 if setting RenderSpeed
    * @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderSetRenderSpeed_001, TestSize.Level1)
{
    int32_t ret = -1;
    float speed = 100;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME_USB);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->SetRenderSpeed(render, speed);
    EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetRenderSpeed_001
    * @tc.desc  Test GetRenderSpeed interface,return -2 if getting RenderSpeed
    * @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderGetRenderSpeed_001, TestSize.Level1)
{
    int32_t ret = -1;
    float speed = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME_USB);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetRenderSpeed(render, &speed);
    EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderGetLatency_001
* @tc.desc  test RenderGetLatency interface, return 0 if GetLatency successful
* @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderGetLatency_001, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t latencyTime = 0;
    uint32_t expectLatency = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME_USB);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->GetLatency(render, &latencyTime);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_LT(expectLatency, latencyTime);

    ret = render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderFlush_001
    * @tc.desc  Test RenderFlush interface,return -2 if the data in the buffer is flushed successfully after stop
    * @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderFlush_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME_USB);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->control.Flush((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetFrameSize_001
    * @tc.desc  Test RenderGetFrameSize interface,return 0 if the FrameSize was obtained successfully
    * @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderGetFrameSize_001, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t size = 0;
    uint64_t zero = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->attr.GetFrameSize(render, &size);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT(size, zero);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetFrameSize_004
    * @tc.desc  Test RenderGetFrameSize interface,return 0 if get framesize define format as different values
    * @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderGetFrameSize_004, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t size = 0;
    uint64_t channelCountExp = 2;
    uint32_t sampleRateExp = 48000;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, 2, 48000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(sampleRateExp, attrsValue.sampleRate);
    EXPECT_EQ(channelCountExp, attrsValue.channelCount);

    ret = render->attr.GetFrameSize(render, &size);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetFrameCount_001
    * @tc.desc  Test RenderGetFrameCount interface, return 0 if the FrameSize was obtained successfully
    * @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderGetFrameCount_001, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t count = 0;
    uint64_t zero = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME_USB);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->attr.GetFrameCount(render, &count);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT(count, zero);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetFrameCount_004
    * @tc.desc  Test RenderGetFrameCount interface,return 0 if get framesize define channelCount as different values
    * @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderGetFrameCount_004, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t count = 0;
    uint64_t channelCountExp = 2;
    uint32_t sampleRateExp = 8000;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, 2, 8000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(sampleRateExp, attrsValue.sampleRate);
    EXPECT_EQ(channelCountExp, attrsValue.channelCount);

    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->attr.GetFrameCount(render, &count);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetCurrentChannelId_001
    * @tc.desc  Test RenderGetCurrentChannelId, return 0 if the default CurrentChannelId is obtained successfully
    * @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderGetCurrentChannelId_001, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t channelId = 0;
    uint32_t channelIdValue = CHANNELCOUNT;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->attr.GetCurrentChannelId(render, &channelId);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(channelIdValue, channelId);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetCurrentChannelId_003
    * @tc.desc  Test GetCurrentChannelId interface,return 0 if get channelId to 1 and set channelCount to 1
    * @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderGetCurrentChannelId_002, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t channelId = 0;
    uint32_t channelIdExp = 1;
    uint32_t channelCountExp = 1;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, 1, 32000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(channelCountExp, attrs.channelCount);

    ret = render->attr.GetCurrentChannelId(render, &channelId);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(channelIdExp, channelId);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetCurrentChannelId_003
    * @tc.desc  Test RenderGetCurrentChannelId interface, return 0 if CurrentChannelId is obtained after created
    * @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderGetCurrentChannelId_003, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t channelId = 0;
    uint32_t channelIdExp = 2;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->attr.GetCurrentChannelId(render, &channelId);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(channelIdExp, channelId);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderCheckSceneCapability_001
* @tc.desc  Test AudioRenderCheckSceneCapability interface,return 0 if check scene's capability successful.
* @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderCheckSceneCapability_001, TestSize.Level1)
{
    int32_t ret = -1;
    bool supported = false;
    struct AudioSceneDescriptor scenes = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
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
HWTEST_F(AudioUsbRenderTest, AudioRenderCheckSceneCapability_002, TestSize.Level1)
{
    int32_t ret = -1;
    bool supported = true;
    struct AudioSceneDescriptor scenes = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    scenes.scene.id = 5;
    scenes.desc.pins = PIN_OUT_SPEAKER;
    ret = render->scene.CheckSceneCapability(render, &scenes, &supported);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderSelectScene_001
* @tc.desc  Test AudioRenderSelectScene interface,return 0 if select Render's scene successful.
* @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderSelectScene_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor scenes = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    scenes.scene.id = 0;
    scenes.desc.pins = PIN_OUT_SPEAKER;

    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
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
HWTEST_F(AudioUsbRenderTest, AudioRenderSelectScene_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor scenes = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME_USB);
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
HWTEST_F(AudioUsbRenderTest, AudioRenderSelectScene_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor scenes = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    scenes.scene.id = 0;
    scenes.desc.pins = PIN_IN_MIC;
    ret = render->scene.SelectScene(renderNull, &scenes);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderSelectScene_005
* @tc.desc  Test AudioRenderSelectScene, return -1 if the scene is not configured in the josn.
* @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderSelectScene_005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSceneDescriptor scenes = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    scenes.scene.id = 5;
    scenes.desc.pins = PIN_OUT_HDMI;
    ret = render->scene.SelectScene(render, &scenes);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetGainThreshold_001
    * @tc.desc  Test RenderGetGainThreshold interface,return 0 if the GetGainThreshold is obtained successfully
    * @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderGetGainThreshold_001, TestSize.Level1)
{
    int32_t ret = -1;
    float min = 0;
    float max = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->volume.GetGainThreshold((AudioHandle)render, &min, &max);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(min, GAIN_MIN);
    EXPECT_EQ(max, GAIN_MAX);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderSetGain_001
    * @tc.desc  Test RenderSetGain interface,return 0 if Set gain to normal value, maximum or minimum and get success
    * @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderSetGain_001, TestSize.Level1)
{
    int32_t ret = -1;
    float min = 0;
    float max = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->volume.GetGainThreshold((AudioHandle)render, &min, &max);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    float gain = 10.8;
    float gainMax = max;
    float gainMin = min;
    float gainExpc = 10;
    float gainMaxExpc = max;
    float gainMinExpc = min;
    ret = render->volume.SetGain(render, gain);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->volume.GetGain(render, &gain);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(gainExpc, gain);

    ret = render->volume.SetGain(render, gainMax);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->volume.GetGain(render, &gainMax);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(gainMaxExpc, gainMax);

    ret = render->volume.SetGain(render, gainMin);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->volume.GetGain(render, &gainMin);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(gainMinExpc, gainMin);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetGain_001
    * @tc.desc  Test RenderGetGain interface,return 0 if the RenderGetGain was obtained successfully
    * @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderGetGain_001, TestSize.Level1)
{
    int32_t ret = -1;
    float min = 0;
    float max = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->volume.GetGainThreshold((AudioHandle)render, &min, &max);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    float gain = min + 1;
    float gainValue = min + 1;
    ret = render->volume.SetGain(render, gain);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->volume.GetGain(render, &gain);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(gainValue, gain);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderGetRenderPosition_001
* @tc.desc  Test GetRenderPosition interface,Returns 0 if get RenderPosition during playing.
* @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderGetRenderPosition_001, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME_USB.c_str(), .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };
    audiopara.manager = manager;
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
* @tc.name  AudioRenderGetRenderPosition_002
* @tc.desc   Test GetRenderPosition interface,Returns 0 if get RenderPosition after Pause and resume during playing
* @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderGetRenderPosition_002, TestSize.Level1)
{
    int32_t ret = -1;
    int64_t timeExp = 0;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME_USB.c_str(), .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };
    audiopara.manager = manager;
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
* @tc.name  AudioRenderGetRenderPosition_003
* @tc.desc  Test GetRenderPosition interface,Returns 0 if get RenderPosition after stop
* @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderGetRenderPosition_003, TestSize.Level1)
{
    int32_t ret = -1;
    int64_t timeExp = 0;
    uint64_t frames = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME_USB);
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
    * @tc.name  AudioRenderSetExtraParams_001
    * @tc.desc  Test RenderSetExtraParams interface,return 0 if the ExtraParams is set during playback
    * @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderSetExtraParams_001, TestSize.Level1)
{
    int32_t ret = -1;
    char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;attr-frame-count=82;attr-sampling-rate=48000";
    char keyValueListExp[] = "attr-route=1;attr-format=32;attr-channels=2;attr-sampling-rate=48000";
    size_t index = 1;
    char keyValueListValue[256] = {};
    int32_t listLenth = 256;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME_USB.c_str(), .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);

    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    sleep(1);
    if (audiopara.render != nullptr) {
        ret = audiopara.render->attr.SetExtraParams((AudioHandle)audiopara.render, keyValueList);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        ret = audiopara.render->attr.GetExtraParams((AudioHandle)audiopara.render, keyValueListValue, listLenth);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        string strGetValue = keyValueListValue;
        size_t indexAttr = strGetValue.find("attr-frame-count");
        size_t indexFlag = strGetValue.rfind(";");
        if (indexAttr != string::npos && indexFlag != string::npos) {
            strGetValue.replace(indexAttr, indexFlag - indexAttr + index, "");
        }
        EXPECT_STREQ(keyValueListExp, strGetValue.c_str());
    }

    ret = ThreadRelease(audiopara);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
}
/**
    * @tc.name  AudioRenderSetExtraParams_002
    * @tc.desc  Test RenderSetExtraParams interface,return 0 if some parameters is set after playing
    * @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderSetExtraParams_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    char keyValueListOne[] = "attr-frame-count=1024;";
    char keyValueListOneExp[] = "attr-route=0;attr-format=16;attr-channels=2;attr-frame-count=1024;\
attr-sampling-rate=48000";
    char keyValueListTwo[] = "attr-format=16;attr-frame-count=1024;";
    char keyValueListTwoExp[] = "attr-route=0;attr-format=16;attr-channels=2;attr-frame-count=1024;\
attr-sampling-rate=48000";
    char keyValueListThr[] = "attr-route=1;attr-channels=1;attr-frame-count=1024;";
    char keyValueListThrExp[] = "attr-route=1;attr-format=16;attr-channels=1;attr-frame-count=1024;\
attr-sampling-rate=48000";
    char keyValueListFour[] = "attr-format=32;attr-channels=2;attr-frame-count=4096;attr-sampling-rate=48000";
    char keyValueListFourExp[] = "attr-route=1;attr-format=32;attr-channels=2;attr-frame-count=4096;\
attr-sampling-rate=48000";
    char keyValueListValueOne[256] = {};
    char keyValueListValueTwo[256] = {};
    char keyValueListValueThr[256] = {};
    char keyValueListValueFour[256] = {};
    int32_t listLenth = 256;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME_USB);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->attr.SetExtraParams((AudioHandle)render, keyValueListOne);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->attr.GetExtraParams((AudioHandle)render, keyValueListValueOne, listLenth);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_STREQ(keyValueListOneExp, keyValueListValueOne);
    ret = render->attr.SetExtraParams((AudioHandle)render, keyValueListTwo);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->attr.GetExtraParams((AudioHandle)render, keyValueListValueTwo, listLenth);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_STREQ(keyValueListTwoExp, keyValueListValueTwo);
    ret = render->attr.SetExtraParams((AudioHandle)render, keyValueListThr);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->attr.GetExtraParams((AudioHandle)render, keyValueListValueThr, listLenth);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_STREQ(keyValueListThrExp, keyValueListValueThr);
    ret = render->attr.SetExtraParams((AudioHandle)render, keyValueListFour);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->attr.GetExtraParams((AudioHandle)render, keyValueListValueFour, listLenth);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_STREQ(keyValueListFourExp, keyValueListValueFour);
    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetExtraParams_001
    * @tc.desc  Test RenderGetExtraParams interface,return 0 if the RenderGetExtraParams was obtained successfully
    * @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderGetExtraParams_001, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t count = 0;
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrsValue = {};
    char keyValueList[] = "attr-format=24;attr-frame-count=4096;";
    char keyValueListExp[] = "attr-route=0;attr-format=24;attr-channels=2;attr-frame-count=4096;\
attr-sampling-rate=48000";
    char keyValueListValue[256] = {};
    int32_t listLenth = 256;
    int32_t formatExp = 3;
    uint32_t sampleRateExp = 48000;
    uint32_t channelCountExp = 2;
    uint32_t frameCountExp = 4096;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME_USB);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->attr.SetExtraParams((AudioHandle)render, keyValueList);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->attr.GetExtraParams((AudioHandle)render, keyValueListValue, listLenth);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_STREQ(keyValueListExp, keyValueListValue);

    ret = render->attr.GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(formatExp, attrsValue.format);
    EXPECT_EQ(sampleRateExp, attrsValue.sampleRate);
    EXPECT_EQ(channelCountExp, attrsValue.channelCount);
    ret = render->attr.GetFrameCount(render, &count);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(count, frameCountExp);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioRenderTurnStandbyMode_001
* @tc.desc  Test AudioRenderTurnStandbyMode interface,return 0 if the interface use correctly.
* @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderTurnStandbyMode_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME_USB);
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
HWTEST_F(AudioUsbRenderTest, AudioRenderAudioDevDump_001, TestSize.Level1)
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
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME_USB.c_str(), .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };
    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    if (ret < 0) {
        fclose(fp);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    sleep(1);
    ret = audiopara.render->control.Pause((AudioHandle)audiopara.render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    sleep(1);
    ret = audiopara.render->control.Resume((AudioHandle)audiopara.render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = audiopara.render->control.AudioDevDump((AudioHandle)audiopara.render, RANGE, fd);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    fclose(fp);
    ret = ThreadRelease(audiopara);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
}

/**
* @tc.name  AudioRenderReqMmapBuffer_001
* @tc.desc  Test ReqMmapBuffer interface,return 0 if call ReqMmapBuffer interface successfully
* @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderReqMmapBuffer_001, TestSize.Level1)
{
    int32_t ret = -1;
    bool isRender = true;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc = {};
    struct AudioRender *render = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioSampleAttributes attrs = {};
    ASSERT_NE(nullptr, manager);
    FILE *fp = fopen(LOW_LATENCY_AUDIO_FILE.c_str(), "rb+");
    ASSERT_NE(fp, nullptr);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
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
* @tc.name  AudioRenderGetMmapPosition_001
* @tc.desc  Test GetMmapPosition interface,return 0 if Getting position successfully.
* @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderGetMmapPosition_001, TestSize.Level1)
{
    uint64_t frames = 0;
    uint64_t framesRendering = 0;
    uint64_t framesexpRender = 0;
    int64_t timeExp = 0;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME_USB.c_str(), .pins = PIN_OUT_SPEAKER,
        .path = LOW_LATENCY_AUDIO_FILE.c_str()
    };
    audiopara.manager = manager;
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
* @tc.name  AudioRenderGetMmapPosition_002
* @tc.desc  Test GetMmapPosition interface,return 0 if Getting position successfully.
* @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderGetMmapPosition_002, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME_USB.c_str(), .pins = PIN_OUT_SPEAKER,
        .path = LOW_LATENCY_AUDIO_FILE.c_str()
    };
    audiopara.manager = manager;
    ASSERT_NE(audiopara.manager, nullptr);
    ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.render);
    if (ret < 0 || audiopara.render == nullptr) {
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ASSERT_EQ(nullptr, audiopara.render);
    }
    InitAttrs(audiopara.attrs);
    audiopara.attrs.format = AUDIO_FORMAT_PCM_24_BIT;
    audiopara.attrs.channelCount = 1;
    ret = audiopara.render->attr.SetSampleAttributes(audiopara.render, &(audiopara.attrs));
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)PlayMapAudioFile, &audiopara);
    if (ret != 0) {
        audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    }

    void *result = nullptr;
    pthread_join(audiopara.tids, &result);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
    ret = audiopara.render->attr.GetMmapPosition(audiopara.render, &frames, &(audiopara.time));
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT((audiopara.time.tvSec) * SECTONSEC + (audiopara.time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);
    audiopara.render->control.Stop((AudioHandle)audiopara.render);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}

#ifdef AUDIO_ADM_SO
/**
* @tc.name  AudioRenderRegCallback_001
* @tc.desc  Test AudioRenderTurnStandbyMode interface,return 0 if the interface use correctly.
* @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderRegCallback_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
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

/**
* @tc.name  AudioRenderRegCallback_002
* @tc.desc  Test AudioRenderRegCallback interface,return 0 if the interface use correctly.
* @tc.type: FUNC
*/
HWTEST_F(AudioUsbRenderTest, AudioRenderRegCallback_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs;
    struct AudioHeadInfo headInfo;
    ASSERT_NE(nullptr, manager);
    char absPath[PATH_MAX] = {0};
    realpath(AUDIO_FILE.c_str(), absPath);
    ASSERT_NE(realpath(AUDIO_FILE.c_str(), absPath), nullptr);

    FILE *file = fopen(absPath, "rb");
    ASSERT_NE(file, nullptr);
    ret = WavHeadAnalysis(headInfo, file, attrs);
    if (ret < 0) {
        fclose(file);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
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
}
