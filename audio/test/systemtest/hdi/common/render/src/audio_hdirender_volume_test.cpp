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
#include "audio_hdirender_volume_test.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
class AudioHdiRenderVolumeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static TestAudioManager *manager;
};

TestAudioManager *AudioHdiRenderVolumeTest::manager = nullptr;

void AudioHdiRenderVolumeTest::SetUpTestCase(void)
{
    manager = GetAudioManagerFuncs();
    ASSERT_NE(nullptr, manager);
}

void AudioHdiRenderVolumeTest::TearDownTestCase(void) {}

void AudioHdiRenderVolumeTest::SetUp(void) {}
void AudioHdiRenderVolumeTest::TearDown(void) {}

/**
    * @tc.name  AudioRenderGetGainThreshold_001
    * @tc.desc  Test RenderGetGainThreshold interface,return 0 if the GetGainThreshold is obtained successfully
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderVolumeTest, AudioRenderGetGainThreshold_001, TestSize.Level1)
{
    int32_t ret = -1;
    float min = 0;
    float max = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->volume.GetGainThreshold((AudioHandle)render, &min, &max);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
#ifndef ALSA_LIB_MODE
    EXPECT_EQ(min, GAIN_MIN);
    EXPECT_EQ(max, GAIN_MAX);
#endif
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetGainThreshold_002
    * @tc.desc  Test RenderGetGainThreshold interface, return -1 if set render to nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderVolumeTest, AudioRenderGetGainThreshold_002, TestSize.Level1)
{
    int32_t ret = -1;
    float min = 0;
    float max = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->volume.GetGainThreshold((AudioHandle)renderNull, &min, &max);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetGainThreshold_003
    * @tc.desc  Test RenderGetGainThreshold interface, return -1 if set min to nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderVolumeTest, AudioRenderGetGainThreshold_003, TestSize.Level1)
{
    int32_t ret = -1;
    float max = 0;
    float *minNull = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->volume.GetGainThreshold((AudioHandle)render, minNull, &max);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetGainThreshold_004
    * @tc.desc  Test RenderGetGainThreshold interface, return -1 if set max to nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderVolumeTest, AudioRenderGetGainThreshold_004, TestSize.Level1)
{
    int32_t ret = -1;
    float min = 0;
    float *maxNull = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->volume.GetGainThreshold(render, &min, maxNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderSetGain_001
    * @tc.desc  Test RenderSetGain interface,return 0 if Set gain to normal value, maximum or minimum and get success
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderVolumeTest, AudioRenderSetGain_001, TestSize.Level1)
{
    int32_t ret = -1;
    float gain = 10.8;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
#ifdef ALSA_LIB_MODE
    ret = render->volume.SetGain(render, gain);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
#else
    float min = 0;
    float max = 0;
    ret = render->volume.GetGainThreshold((AudioHandle)render, &min, &max);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
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
#endif
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
#ifndef ALSA_LIB_MODE
/**
    * @tc.name  AudioRenderSetGain_002
    * @tc.desc  Test RenderSetGain interface,return -1 if Set gain to exceed the boundary value
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderVolumeTest, AudioRenderSetGain_002, TestSize.Level1)
{
    int32_t ret = -1;
    float min = 0;
    float max = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->volume.GetGainThreshold((AudioHandle)render, &min, &max);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    float gainOne = max + 1;
    float gainSec = min - 1;
    ret = render->volume.SetGain(render, gainOne);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    ret = render->volume.SetGain(render, gainSec);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderSetGain_003
    * @tc.desc  Test RenderSetGain interface,return -1 if set gain to exception type
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderVolumeTest, AudioRenderSetGain_003, TestSize.Level1)
{
    int32_t ret = -1;
    char gain = 'a';
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->volume.SetGain(render, gain);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
#endif
/**
    * @tc.name  AudioRenderSetGain_004
    * @tc.desc  Test RenderSetGain interface, return -1 if set render to nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderVolumeTest, AudioRenderSetGain_004, TestSize.Level1)
{
    int32_t ret = -1;
    float gain = 1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->volume.SetGain((AudioHandle)renderNull, gain);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetGain_001
    * @tc.desc  Test RenderGetGain interface,return 0 if the RenderGetGain was obtained successfully
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderVolumeTest, AudioRenderGetGain_001, TestSize.Level1)
{
    int32_t ret = -1;
    float min = 0;
    float max = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
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
    * @tc.name  AudioRenderGetGain_002
    * @tc.desc  Test RenderGetGain interface, return -1 if get gain set render to nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderVolumeTest, AudioRenderGetGain_002, TestSize.Level1)
{
    int32_t ret = -1;
    float gain = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->volume.GetGain((AudioHandle)renderNull, &gain);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetGain_003
    * @tc.desc  Test RenderGetGainThreshold interface, return 0 if get gain before start successfully
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderVolumeTest, AudioRenderGetGain_003, TestSize.Level1)
{
    int32_t ret = -1;
    float gain = GAIN_MAX - 1;
    float gainOne = GAIN_MAX - 1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->volume.SetGain(render, gain);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->volume.GetGain(render, &gain);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(gain, gainOne);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetGain_004
    * @tc.desc  Test RenderGetGain interface, return -1 if get gain set gain to nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderVolumeTest, AudioRenderGetGain_004, TestSize.Level1)
{
    int32_t ret = -1;
    float *gainNull = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->volume.GetGain((AudioHandle)render, gainNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderSetMute_001
* @tc.desc  Test AudioRenderSetMute interface , return 0 if the audiorender object sets mute successfully.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderVolumeTest, AudioRenderSetMute_001, TestSize.Level1)
{
    int32_t ret = -1;
    bool muteFalse = false;
    bool muteTrue = true;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
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
* @tc.name  AudioRenderSetMute_002
* @tc.desc  Test AudioRenderSetMute interface, return -1 if the incoming parameter render is empty.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderVolumeTest, AudioRenderSetMute_002, TestSize.Level1)
{
    int32_t ret = -1;
    bool mute = true;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->volume.SetMute(renderNull, mute);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderSetMute_003
* @tc.desc  Test AudioRenderSetMute interface and set the parameter mutevalue with 2.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderVolumeTest, AudioRenderSetMute_003, TestSize.Level1)
{
    int32_t ret = -1;
    bool muteValue = 2;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->volume.SetMute(render, muteValue);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->volume.GetMute(render, &muteValue);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(true, muteValue);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderGetMute_001
* @tc.desc  Test AudioRenderGetMute interface , return 0 if the audiocapture gets mute successfully.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderVolumeTest, AudioRenderGetMute_001, TestSize.Level1)
{
    int32_t ret = -1;
    bool muteTrue = true;
    bool muteFalse = false;
#ifdef ALSA_LIB_MODE
    bool defaultmute = false;
#else
    bool defaultmute = true;
#endif
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->volume.GetMute(render, &muteTrue);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(muteTrue, defaultmute);

    ret = render->volume.SetMute(render, muteFalse);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->volume.GetMute(render, &muteFalse);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_FALSE(muteFalse);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderGetMute_002
* @tc.desc  Test AudioRenderGetMute interface, return -1 if the incoming parameter render is empty.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderVolumeTest, AudioRenderGetMute_002, TestSize.Level1)
{
    int32_t ret = -1;
    bool muteTrue = true;
    bool muteFalse = false;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->volume.GetMute(renderNull, &muteTrue);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    ret = render->volume.GetMute(renderNull, &muteFalse);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    ret = render->volume.GetMute(render, nullptr);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderSetVolume_001
* @tc.desc  Test AudioRenderSetVolume interface , return 0 if the audiocapture sets volume successfully.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderVolumeTest, AudioRenderSetVolume_001, TestSize.Level1)
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
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
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
* @tc.name  AudioRenderSetVolume_002
* @tc.desc  Test AudioRenderSetVolume,return 0 if volume is set maximum value or minimum value.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderVolumeTest, AudioRenderSetVolume_002, TestSize.Level1)
{
    int32_t ret = -1;
    float volumeMin = 0;
    float volumeMinExpc = 0;
    float volumeMax = 1.0;
    float volumeMaxExpc = 1.0;
    float volumeMinBoundary = -1;
    float volumeMaxBoundary = 1.01;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->volume.SetVolume(render, volumeMin);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->volume.GetVolume(render, &volumeMin);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(volumeMinExpc, volumeMin);

    ret = render->volume.SetVolume(render, volumeMax);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->volume.GetVolume(render, &volumeMax);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(volumeMaxExpc, volumeMax);

    ret = render->volume.SetVolume(render, volumeMinBoundary);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    ret = render->volume.SetVolume(render, volumeMaxBoundary);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderSetVolume_003
* @tc.desc  Test AudioRenderSetVolume,return -1 when incoming parameter render is empty.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderVolumeTest, AudioRenderSetVolume_003, TestSize.Level1)
{
    int32_t ret = -1;
    float volume = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->volume.SetVolume(renderNull, volume);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderGetVolume_001
* @tc.desc  Test AudioRenderGetVolume interface , return 0 if the audiocapture is get successful.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderVolumeTest, AudioRenderGetVolume_001, TestSize.Level1)
{
    int32_t ret = -1;
    float volume = 0.30;
    float volumeDefault = 0.30;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
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
* @tc.name  AudioRenderGetVolume_002.
* @tc.desc  Test AudioRenderGetVolume,return 0 when when capturing is in progress.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderVolumeTest, AudioRenderGetVolume_002, TestSize.Level1)
{
    int32_t ret = -1;
    float volume = 0.30;
    float defaultVolume = 0.30;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->volume.SetVolume(render, volume);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->volume.GetVolume(render, &volume);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(defaultVolume, volume);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderGetVolume_003
* @tc.desc  Test AudioRenderGetVolume,return -1 when incoming parameter render is empty.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderVolumeTest, AudioRenderGetVolume_003, TestSize.Level1)
{
    int32_t ret = -1;
    float volume = 0.3;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->volume.GetVolume(renderNull, &volume);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
}
