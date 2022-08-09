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
class AudioIdlHdiRendervolumeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    static TestAudioManager *(*GetAudioManager)(const char *);
    static TestAudioManager *manager;
    static void *handleSo;
    static void (*AudioManagerRelease)(struct AudioManager *);
    static void (*AudioAdapterRelease)(struct AudioAdapter *);
    static void (*AudioRenderRelease)(struct AudioRender *);
    void ReleaseAudioSource(void);
};

TestAudioManager *(*AudioIdlHdiRendervolumeTest::GetAudioManager)(const char *) = nullptr;
TestAudioManager *AudioIdlHdiRendervolumeTest::manager = nullptr;
void *AudioIdlHdiRendervolumeTest::handleSo = nullptr;
void (*AudioIdlHdiRendervolumeTest::AudioManagerRelease)(struct AudioManager *) = nullptr;
void (*AudioIdlHdiRendervolumeTest::AudioAdapterRelease)(struct AudioAdapter *) = nullptr;
void (*AudioIdlHdiRendervolumeTest::AudioRenderRelease)(struct AudioRender *) = nullptr;

void AudioIdlHdiRendervolumeTest::SetUpTestCase(void)
{
    char absPath[PATH_MAX] = {0};
    char *path = realpath(RESOLVED_PATH.c_str(), absPath);
    ASSERT_NE(nullptr, path);
    handleSo = dlopen(absPath, RTLD_LAZY);
    ASSERT_NE(nullptr, handleSo);
    GetAudioManager = (TestAudioManager *(*)(const char *))(dlsym(handleSo, FUNCTION_NAME.c_str()));
    ASSERT_NE(nullptr, GetAudioManager);
    (void)HdfRemoteGetCallingPid();
    manager = GetAudioManager(IDL_SERVER_NAME.c_str());
    ASSERT_NE(nullptr, manager);
    AudioManagerRelease = (void (*)(struct AudioManager *))(dlsym(handleSo, "AudioManagerRelease"));
    ASSERT_NE(nullptr, AudioManagerRelease);
    AudioAdapterRelease = (void (*)(struct AudioAdapter *))(dlsym(handleSo, "AudioAdapterRelease"));
    ASSERT_NE(nullptr, AudioAdapterRelease);
    AudioRenderRelease = (void (*)(struct AudioRender *))(dlsym(handleSo, "AudioRenderRelease"));
    ASSERT_NE(nullptr, AudioRenderRelease);
}

void AudioIdlHdiRendervolumeTest::TearDownTestCase(void)
{
    if (AudioManagerRelease !=nullptr) {
        AudioManagerRelease(manager);
        manager = nullptr;
    }
    if (GetAudioManager != nullptr) {
        GetAudioManager = nullptr;
    }
    if (handleSo != nullptr) {
        dlclose(handleSo);
        handleSo = nullptr;
    }
}

void AudioIdlHdiRendervolumeTest::SetUp(void)
{
    int32_t ret;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

void AudioIdlHdiRendervolumeTest::TearDown(void)
{
    ReleaseAudioSource();
}

void AudioIdlHdiRendervolumeTest::ReleaseAudioSource(void)
{
    int32_t ret = -1;
    if (render != nullptr && AudioRenderRelease != nullptr) {
        ret = adapter->DestroyRender(adapter);
        EXPECT_EQ(HDF_SUCCESS, ret);
        AudioRenderRelease(render);
        render = nullptr;
    }
    if (adapter != nullptr && AudioAdapterRelease != nullptr) {
        ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
        EXPECT_EQ(HDF_SUCCESS, ret);
        AudioAdapterRelease(adapter);
        adapter = nullptr;
    }
}
/**
    * @tc.name    Test RenderGetGainThreshold API via legal input
    * @tc.number  SUB_Audio_HDI_RenderGetGainThreshold_001
    * @tc.desc    Test RenderGetGainThreshold interface,return 0 if the GetGainThreshold is obtained successfully
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRendervolumeTest, SUB_Audio_HDI_RenderGetGainThreshold_001, TestSize.Level1)
{
    int32_t ret = -1;
    float min = 0;
    float max = 0;

    ASSERT_NE(nullptr, render);
    ret = render->GetGainThreshold(render, &min, &max);
    EXPECT_EQ(HDF_SUCCESS, ret);
#ifndef ALSA_LIB_MODE
    EXPECT_EQ(min, GAIN_MIN);
    EXPECT_EQ(max, GAIN_MAX);
#endif
}
/**
    * @tc.name    Test RenderGetGainThreshold API via set the parameter render to nullptr
    * @tc.number  SUB_Audio_HDI_RenderGetGainThreshold_Null_002
    * @tc.desc    Test RenderGetGainThreshold interface, return -3/-4 if set render to nullptr
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRendervolumeTest, SUB_Audio_HDI_RenderGetGainThreshold_Null_002, TestSize.Level1)
{
    int32_t ret = -1;
    float min = 0;
    float max = 0;
    struct AudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->GetGainThreshold(renderNull, &min, &max);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
    * @tc.name    Test RenderGetGainThreshold API via set the parameter min to nullptr
    * @tc.number  SUB_Audio_HDI_RenderGetGainThreshold_Null_003
    * @tc.desc    Test RenderGetGainThreshold interface, return -3 if set min to nullptr
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRendervolumeTest, SUB_Audio_HDI_RenderGetGainThreshold_Null_003, TestSize.Level1)
{
    int32_t ret = -1;
    float max = 0;
    float *minNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->GetGainThreshold(render, minNull, &max);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**
    * @tc.name    Test RenderGetGainThreshold API via set the parameter max to nullptr
    * @tc.number  SUB_Audio_HDI_RenderGetGainThreshold_Null_004
    * @tc.desc    Test RenderGetGainThreshold interface, return -3 if set max to nullptr
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRendervolumeTest, SUB_Audio_HDI_RenderGetGainThreshold_Null_004, TestSize.Level1)
{
    int32_t ret = -1;
    float min = 0;
    float *maxNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->GetGainThreshold(render, &min, maxNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**
    * @tc.name    Test RenderSetGain API via legal input
    * @tc.number  SUB_Audio_HDI_RenderSetGain_001
    * @tc.desc    Test RenderSetGain interface,return 0 if Set gain to normal value, maximum or minimum and get success
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRendervolumeTest, SUB_Audio_HDI_RenderSetGain_001, TestSize.Level1)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, render);
    float gain = 10.8;
    ret = render->SetGain(render, gain);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetGain(render, &gain);
    EXPECT_EQ(HDF_SUCCESS, ret);
#ifndef ALSA_LIB_MODE
    float gainExpc = 10;
    EXPECT_EQ(gainExpc, gain);
    float min = 0;
    float max = 0;
    ret = render->GetGainThreshold(render, &min, &max);
    EXPECT_EQ(HDF_SUCCESS, ret);
    float gainMax = max;
    float gainMin = min;
    float gainMaxExpc = max;
    float gainMinExpc = min;
    ret = render->SetGain(render, gainMax);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetGain(render, &gainMax);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(gainMaxExpc, gainMax);

    ret = render->SetGain(render, gainMin);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetGain(render, &gainMin);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(gainMinExpc, gainMin);
#endif
}
#ifndef ALSA_LIB_MODE
/**
    * @tc.name    Test RenderSetGain API via set gain to the boundary value
    * @tc.number  SUB_Audio_HDI_RenderSetGain_002
    * @tc.desc    Test RenderSetGain interface,return -3 if Set gain to exceed the boundary value
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRendervolumeTest, SUB_Audio_HDI_RenderSetGain_002, TestSize.Level1)
{
    int32_t ret = -1;
    float min = 0;
    float max = 0;

    ASSERT_NE(nullptr, render);
    ret = render->GetGainThreshold(render, &min, &max);
    EXPECT_EQ(HDF_SUCCESS, ret);

    float gainOne = max+1;
    float gainSec = min-1;
    ret = render->SetGain(render, gainOne);
    EXPECT_EQ(HDF_FAILURE, ret);

    ret = render->SetGain(render, gainSec);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**
    * @tc.name    Test RenderSetGain API via set gain to exception type
    * @tc.number  SUB_Audio_HDI_RenderSetGain_003
    * @tc.desc    Test RenderSetGain interface,return -1 if set gain to exception type
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRendervolumeTest, SUB_Audio_HDI_RenderSetGain_003, TestSize.Level1)
{
    int32_t ret = -1;
    char gain = 'a';

    ASSERT_NE(nullptr, render);
    ret = render->SetGain(render, gain);
    EXPECT_EQ(HDF_FAILURE, ret);
}
#endif
/**
    * @tc.name    Test RenderSetGain API via set the parameter render to nullptr
    * @tc.number  SUB_Audio_HDI_RenderSetGain_Null_004
    * @tc.desc    Test RenderSetGain interface, return -3/-4 if set render to nullptr
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRendervolumeTest, SUB_Audio_HDI_RenderSetGain_Null_004, TestSize.Level1)
{
    int32_t ret = -1;
    float gain = 1;
    struct AudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->SetGain(renderNull, gain);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
    * @tc.name    Test RenderGetGain API via legal input
    * @tc.number  SUB_Audio_HDI_RenderGetGain_001
    * @tc.desc    Test RenderGetGain interface,return 0 if the RenderGetGain was obtained successfully
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRendervolumeTest, SUB_Audio_HDI_RenderGetGain_001, TestSize.Level1)
{
    int32_t ret = -1;
    float min = 0;
    float max = 0;

    ASSERT_NE(nullptr, render);
    ret = render->GetGainThreshold(render, &min, &max);
    EXPECT_EQ(HDF_SUCCESS, ret);

    float gain = min+1;
    float gainValue = min+1;
    ret = render->SetGain(render, gain);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetGain(render, &gain);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(gainValue, gain);
}
/**
    * @tc.name    Test RenderGetGain API via set the parameter render to nullptr
    * @tc.number  SUB_Audio_HDI_RenderGetGain_Null_002
    * @tc.desc    Test RenderGetGain interface, return -3/-4 if get gain set render to nullptr
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRendervolumeTest, SUB_Audio_HDI_RenderGetGain_Null_002, TestSize.Level1)
{
    int32_t ret = -1;
    float gain = 0;
    struct AudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->GetGain(renderNull, &gain);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
    * @tc.name    Test RenderGetGain API via legal input in difference scenes
    * @tc.number  SUB_Audio_HDI_RenderGetGain_003
    * @tc.desc    Test RenderGetGainThreshold interface, return 0 if get gain before start successfully
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRendervolumeTest, SUB_Audio_HDI_RenderGetGain_003, TestSize.Level1)
{
    int32_t ret = -1;
    float gain = GAIN_MAX-1;
    float gainOne = GAIN_MAX-1;

    ASSERT_NE(nullptr, render);
    ret = render->SetGain(render, gain);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetGain(render, &gain);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(gain, gainOne);
}
/**
    * @tc.name    Test RenderGetGain API via set the parameter gain to nullptr
    * @tc.number  SUB_Audio_HDI_RenderGetGain_Null_004
    * @tc.desc    Test RenderGetGain interface, return -3 if get gain set gain to nullptr
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRendervolumeTest, SUB_Audio_HDI_RenderGetGain_Null_004, TestSize.Level1)
{
    int32_t ret = -1;
    float *gainNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->GetGain(render, gainNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**
* @tc.name    Test AudioRenderSetMute API via legal input.
* @tc.number  SUB_Audio_HDI_RenderSetMute_001
* @tc.desc    Test AudioRenderSetMute interface , return 0 if the audiorender object sets mute successfully.
* @tc.author:liweiming
*/
HWTEST_F(AudioIdlHdiRendervolumeTest, SUB_Audio_HDI_RenderSetMute_001, TestSize.Level1)
{
    int32_t ret = -1;
    bool muteFalse = false;
    bool muteTrue = true;

    ASSERT_NE(nullptr, render);
    ret = render->SetMute(render, muteFalse);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetMute(render, &muteFalse);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(false, muteFalse);

    ret = render->SetMute(render, muteTrue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetMute(render, &muteTrue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(true, muteTrue);

    muteTrue = false;
    ret = render->SetMute(render, muteTrue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_FALSE(muteTrue);
}
/**
* @tc.name    Test AudioRenderSetMute API via setting the incoming parameter render is empty .
* @tc.number  SUB_Audio_HDI_RenderSetMute_Null_002
* @tc.desc    Test AudioRenderSetMute interface, return -3/-4 if the incoming parameter render is empty.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRendervolumeTest, SUB_Audio_HDI_RenderSetMute_Null_002, TestSize.Level1)
{
    int32_t ret = -1;
    bool mute = true;
    struct AudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->SetMute(renderNull, mute);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
* @tc.name    Test AudioRenderSetMute API,when the parameter mutevalue equals 2.
* @tc.number  SUB_Audio_HDI_RenderSetMute_003
* @tc.desc    Test AudioRenderSetMute interface and set the parameter mutevalue with 2.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRendervolumeTest, SUB_Audio_HDI_RenderSetMute_003, TestSize.Level1)
{
    int32_t ret = -1;
    bool muteValue = 2;

    ASSERT_NE(nullptr, render);
    ret = render->SetMute(render, muteValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetMute(render, &muteValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(true, muteValue);
}
/**
* @tc.name    Test AudioRenderGetMute API via legal input.
* @tc.number  SUB_Audio_HDI_RenderGetMute_001
* @tc.desc    Test AudioRenderGetMute interface , return 0 if the audiocapture gets mute successfully.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRendervolumeTest, SUB_Audio_HDI_RenderGetMute_001, TestSize.Level1)
{
    int32_t ret = -1;
    bool muteTrue = true;
    bool muteFalse = false;
#ifdef ALSA_LIB_MODE
    bool defaultmute = false;
#else
    bool defaultmute = true;
#endif
    ASSERT_NE(nullptr, render);
    ret = render->GetMute(render, &muteTrue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(muteTrue, defaultmute);

    ret = render->SetMute(render, muteFalse);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->GetMute(render, &muteFalse);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_FALSE(muteFalse);
}
/**
* @tc.name    Test interface AudioRenderGetMute when incoming parameter render is empty.
* @tc.number  SUB_Audio_HDI_RenderGetMute_Null_002
* @tc.desc    Test AudioRenderGetMute interface, return -3/-4 if the incoming parameter render is empty.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRendervolumeTest, SUB_Audio_HDI_RenderGetMute_Null_002, TestSize.Level1)
{
    int32_t ret = -1;
    bool muteTrue = true;
    bool muteFalse = false;
    struct AudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->GetMute(renderNull, &muteTrue);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);

    ret = render->GetMute(renderNull, &muteFalse);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
* @tc.name    Test interface AudioRenderGetMute when incoming parameter mute is empty.
* @tc.number  SUB_Audio_HDI_RenderGetMute_Null_003
* @tc.desc    Test AudioRenderGetMute interface, return -3 if the incoming parameter mute is empty.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRendervolumeTest, SUB_Audio_HDI_RenderGetMute_Null_003, TestSize.Level1)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, render);
    ret = render->GetMute(render, nullptr);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}

/**
* @tc.name    Test AudioRenderSetVolume API via legal input.
* @tc.number  SUB_Audio_HDI_RenderSetVolume_001
* @tc.desc    Test AudioRenderSetVolume interface , return 0 if the audiocapture sets volume successfully.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRendervolumeTest, SUB_Audio_HDI_RenderSetVolume_001, TestSize.Level1)
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

    ASSERT_NE(nullptr, render);
    ret = render->SetVolume(render, volumeInit);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetVolume(render, &volumeInit);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(volumeInitExpc, volumeInit);
    ret = render->SetVolume(render, volumeLow);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetVolume(render, &volumeLow);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(volumeLowExpc, volumeLow);
    ret = render->SetVolume(render, volumeMid);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetVolume(render, &volumeMid);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(volumeMidExpc, volumeMid);
    ret = render->SetVolume(render, volumeHigh);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetVolume(render, &volumeHigh);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(volumeHighExpc, volumeHigh);
}
/**
* @tc.name    Test AudioRenderSetVolume,when volume is set maximum value or minimum value.
* @tc.number  SUB_Audio_HDI_RenderSetVolume_002
* @tc.desc    Test AudioRenderSetVolume,return 0 if volume is set maximum value or minimum value.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRendervolumeTest, SUB_Audio_HDI_RenderSetVolume_002, TestSize.Level1)
{
    int32_t ret = -1;
    float volumeMin = 0;
    float volumeMinExpc = 0;
    float volumeMax = 1.0;
    float volumeMaxExpc = 1.0;
    float volumeMinBoundary = -1;
    float volumeMaxBoundary = 1.01;

    ASSERT_NE(nullptr, render);
    ret = render->SetVolume(render, volumeMin);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetVolume(render, &volumeMin);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(volumeMinExpc, volumeMin);

    ret = render->SetVolume(render, volumeMax);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetVolume(render, &volumeMax);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(volumeMaxExpc, volumeMax);

    ret = render->SetVolume(render, volumeMinBoundary);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    ret = render->SetVolume(render, volumeMaxBoundary);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**
* @tc.name    Test AudioRenderSetVolume,when incoming parameter render is empty.
* @tc.number  SUB_Audio_HDI_RenderSetVolume_Null_003
* @tc.desc    Test AudioRenderSetVolume,return -3/-4 when incoming parameter render is empty.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRendervolumeTest, SUB_Audio_HDI_RenderSetVolume_Null_003, TestSize.Level1)
{
    int32_t ret = -1;
    float volume = 0;
    struct AudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->SetVolume(renderNull, volume);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
* @tc.name    Test AudioRenderGetVolume API via legal input.
* @tc.number  SUB_Audio_HDI_RenderGetVolume_001
* @tc.desc    Test AudioRenderGetVolume interface , return 0 if the audiocapture is get successful.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRendervolumeTest, SUB_Audio_HDI_RenderGetVolume_001, TestSize.Level1)
{
    int32_t ret = -1;
    float volume = 0.30;
    float volumeDefault = 0.30;

    ASSERT_NE(nullptr, render);
    ret = render->SetVolume(render, volume);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetVolume(render, &volume);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(volumeDefault, volume);
}
/**
* @tc.name    Test AudioRenderGetVolume when when rendering is in progress.
* @tc.number  SUB_Audio_HDI_RenderGetVolume_002.
* @tc.desc    Test AudioRenderGetVolume,return 0 when when rendering is in progress.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRendervolumeTest, SUB_Audio_HDI_RenderGetVolume_002, TestSize.Level1)
{
    int32_t ret = -1;
    float volume = 0.30;
    float defaultVolume = 0.30;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->SetVolume(render, volume);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetVolume(render, &volume);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(defaultVolume, volume);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name    Test AudioRenderGetVolume,when incoming parameter render is empty.
* @tc.number  SUB_Audio_HDI_RenderGetVolume_Null_003
* @tc.desc    Test AudioRenderGetVolume,return -3/-4 when incoming parameter render is empty.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRendervolumeTest, SUB_Audio_HDI_RenderGetVolume_Null_003, TestSize.Level1)
{
    int32_t ret = -1;
    float volume = 0.3;
    struct AudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->GetVolume(renderNull, &volume);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
* @tc.name    Test AudioRenderGetVolume,when incoming parameter render is empty.
* @tc.number  SUB_Audio_HDI_RenderGetVolume_Null_004
* @tc.desc    Test AudioRenderGetVolume,return -3 when incoming parameter render is empty.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRendervolumeTest, SUB_Audio_HDI_RenderGetVolume_Null_004, TestSize.Level1)
{
    int32_t ret = -1;
    float *volumeNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->GetVolume(render, volumeNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
}