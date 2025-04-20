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
class AudioIdlHdiCaptureVolumeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static TestAudioManager *manager;
    struct IAudioCapture *capture = nullptr;
    struct IAudioAdapter *adapter = nullptr;
    uint32_t captureId_ = 0;
};

TestAudioManager *AudioIdlHdiCaptureVolumeTest::manager = nullptr;
using THREAD_FUNC = void *(*)(void *);

void AudioIdlHdiCaptureVolumeTest::SetUpTestCase(void)
{
    manager = IAudioManagerGet(IS_STUB);
    ASSERT_NE(nullptr, manager);
}

void AudioIdlHdiCaptureVolumeTest::TearDownTestCase(void)
{
    if (manager != nullptr) {
        (void)IAudioManagerRelease(manager, IS_STUB);
    }
}

void AudioIdlHdiCaptureVolumeTest::SetUp(void)
{
    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture, &captureId_);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

void AudioIdlHdiCaptureVolumeTest::TearDown(void)
{
    int32_t ret = ReleaseCaptureSource(manager, adapter, capture, captureId_);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

/**
* @tc.name  AudioCaptureSetMute_001
* @tc.desc  Test AudioCaptureSetMute interface , return 0 if the audiocapture object sets mute successfully.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, AudioCaptureSetMute_001, TestSize.Level0)
{
    int32_t ret = -1;
    bool muteTrue = true;
    bool muteFalse = false;
    ASSERT_NE(nullptr, capture);

    ret = capture->SetMute(capture, muteTrue);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);

    ret = capture->GetMute(capture, &muteTrue);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    EXPECT_TRUE(muteTrue);

    ret = capture->SetMute(capture, muteFalse);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);

    ret = capture->GetMute(capture, &muteFalse);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    EXPECT_FALSE(muteFalse);
}
/**
* @tc.name  AudioCaptureSetMuteNull_002
* @tc.desc  Test AudioCaptureSetMute interface, return -3/-4 if the capture is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, AudioCaptureSetMuteNull_002, TestSize.Level1)
{
    bool muteTrue = true;
    bool muteFalse = false;
    int32_t ret = -1;
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = capture->SetMute(captureNull, muteTrue);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);

    ret = capture->SetMute(captureNull, muteFalse);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
}
/**
* @tc.name  AudioCaptureSetMute_003
* @tc.desc  Test AudioCaptureSetMute interface and set the parameter mutevalue with 2.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, AudioCaptureSetMute_003, TestSize.Level0)
{
    bool muteValue = 2;
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);

    ret = capture->SetMute(capture, muteValue);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);

    ret = capture->GetMute(capture, &muteValue);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    EXPECT_TRUE(muteValue);
}
/**
* @tc.name  AudioCaptureGetMute_001
* @tc.desc  Test AudioCaptureGetMute interface , return 0 if the audiocapture gets mute successfully.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, AudioCaptureGetMute_001, TestSize.Level0)
{
    int32_t ret = -1;
    bool muteTrue = true;
    bool muteFalse = false;
#ifdef ALSA_LIB_MODE
    bool defaultmute = false;
#else
    bool defaultmute = true;
#endif
    ASSERT_NE(nullptr, capture);
    ret = capture->GetMute(capture, &muteTrue);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    EXPECT_EQ(muteTrue, defaultmute);

    ret = capture->SetMute(capture, muteFalse);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);

    ret = capture->GetMute(capture, &muteFalse);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    EXPECT_FALSE(muteFalse);
}
/**
* @tc.name  AudioCaptureGetMuteNull_002
* @tc.desc  Test AudioCreateCapture interface, return -3/-4 if the capture is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, AudioCaptureGetMuteNull_002, TestSize.Level1)
{
    int32_t ret = -1;
    bool muteTrue = true;
    bool muteFalse = false;
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = capture->GetMute(captureNull, &muteTrue);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);

    ret = capture->GetMute(captureNull, &muteFalse);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);

    ret = capture->GetMute(capture, nullptr);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_NOT_SUPPORT);
}
/**
* @tc.name  AudioCaptureSetVolume_001
* @tc.desc  Test AudioCaptureSetVolume interface , return 0 if the audiocapture sets volume successfully.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, AudioCaptureSetVolume_001, TestSize.Level0)
{
    int32_t ret = -1;
    float volumeInit = 0.30;
    float volumeInitExpc = 0.30;
    float volumeLow = 0.10;
    float volumeLowExpc = 0.10;
    float volumeMid = 0.40;
    float volumeMidExpc = 0.40;
    float volumeHigh = 0.70;
    float volumeHighExpc = 0.70;
    ASSERT_NE(nullptr, capture);
    ret = capture->SetVolume(capture, volumeInit);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = capture->GetVolume(capture, &volumeInit);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    EXPECT_EQ(volumeInitExpc, volumeInit);
    ret = capture->SetVolume(capture, volumeLow);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = capture->GetVolume(capture, &volumeLow);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    EXPECT_EQ(volumeLowExpc, volumeLow);
    ret = capture->SetVolume(capture, volumeMid);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = capture->GetVolume(capture, &volumeMid);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    EXPECT_EQ(volumeMidExpc, volumeMid);
    ret = capture->SetVolume(capture, volumeHigh);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = capture->GetVolume(capture, &volumeHigh);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    EXPECT_EQ(volumeHighExpc, volumeHigh);
}
/**
* @tc.name  AudioCaptureSetVolume_002
* @tc.desc  Test AudioCaptureSetVolume,return -3 if volume is set maximum value or minimum value.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, AudioCaptureSetVolume_002, TestSize.Level0)
{
    int32_t ret = -1;
    float volumeMin = 0;
    float volumeMinExpc = 0;
    float volumeMax = 1.0;
    float volumeMaxExpc = 1.0;
    float volumeMinBoundary = -1;
    float volumeMaxBoundary = 1.1;
    ASSERT_NE(nullptr, capture);

    ret = capture->SetVolume(capture, volumeMin);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = capture->GetVolume(capture, &volumeMin);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    EXPECT_EQ(volumeMinExpc, volumeMin);

    ret = capture->SetVolume(capture, volumeMax);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = capture->GetVolume(capture, &volumeMax);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    EXPECT_EQ(volumeMaxExpc, volumeMax);

    ret = capture->SetVolume(capture, volumeMinBoundary);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_NOT_SUPPORT);

    ret = capture->SetVolume(capture, volumeMaxBoundary);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_NOT_SUPPORT);
}
/**
* @tc.name  AudioCaptureSetVolumeNull_003
* @tc.desc  Test AudioCaptureSetVolume,return -3/-4 when capture is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, AudioCaptureSetVolumeNull_003, TestSize.Level1)
{
    int32_t ret = -1;
    float volume = 0;
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);

    ret = capture->SetVolume(captureNull, volume);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
}
/**
* @tc.name  AudioCaptureGetVolume_001
* @tc.desc  Test AudioCaptureGetVolume interface , return 0 if the audiocapture is get successful.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, AudioCaptureGetVolume_001, TestSize.Level0)
{
    int32_t ret = -1;
    float volume = 0.60;
    float defaultVolume = 0.60;
    ASSERT_NE(nullptr, capture);

    ret = capture->SetVolume(capture, volume);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = capture->GetVolume(capture, &volume);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    EXPECT_EQ(defaultVolume, volume);
}
/**
* @tc.name  AudioCaptureGetVolume_002.
* @tc.desc  Test AudioCaptureGetVolume,return 0 when when capturing is in progress.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, AudioCaptureGetVolume_002, TestSize.Level0)
{
    int32_t ret = -1;
    float volume = 0.60;
    float defaultVolume = 0.60;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->SetVolume(capture, volume);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = capture->GetVolume(capture, &volume);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    EXPECT_EQ(defaultVolume, volume);

    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioCaptureGetVolumeNull_003
* @tc.desc  Test AudioCaptureGetVolume,return -3/-4 when capture is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, AudioCaptureGetVolumeNull_003, TestSize.Level1)
{
    int32_t ret = -1;
    float volume = 0.30;
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);

    ret = capture->GetVolume(captureNull, &volume);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
}
/**
* @tc.name  AudioCaptureGetGainThreshold_001
* @tc.desc  test AudioCaptureGetGainThreshold interface, return 0 is call successfully.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, AudioCaptureGetGainThreshold_001, TestSize.Level0)
{
    int32_t ret = -1;
    float min = 0;
    float max = 0;
    ASSERT_NE(nullptr, capture);

    ret = capture->GetGainThreshold(capture, &min, &max);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
#ifndef ALSA_LIB_MODE
    EXPECT_EQ(min, GAIN_MIN);
    EXPECT_LE(max, GAIN_MAX);
#endif
}
/**
* @tc.name  AudioCaptureGetGainThresholdNull_002
* @tc.desc  test AudioCaptureGetGainThreshold interface, return -3/-4 if the incoming parameter handle is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, AudioCaptureGetGainThresholdNull_002, TestSize.Level1)
{
    int32_t ret = -1;
    float min = 0;
    float max = 0;
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);

    ret = capture->GetGainThreshold(captureNull, &min, &max);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
}
/**
* @tc.name  AudioCaptureGetGainThresholdNull_003
* @tc.desc  test AudioCaptureGetGainThreshold interface, return -3 if the incoming parameter min is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, AudioCaptureGetGainThresholdNull_003, TestSize.Level1)
{
    int32_t ret = -1;
    float max = 0;
    float* minNull = nullptr;
    ASSERT_NE(nullptr, capture);

    ret = capture->GetGainThreshold(capture, minNull, &max);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_NOT_SUPPORT);
}
/**
* @tc.name  AudioCaptureGetGainThresholdNull_004
* @tc.desc  test AudioCaptureGetGainThreshold interface, return -3 if the incoming parameter max is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, AudioCaptureGetGainThresholdNull_004, TestSize.Level1)
{
    int32_t ret = -1;
    float min = 0;
    float* maxNull = nullptr;
    ASSERT_NE(nullptr, capture);

    ret = capture->GetGainThreshold(capture, &min, maxNull);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_NOT_SUPPORT);
}
/**
* @tc.name  AudioCaptureSetGain_001
* @tc.desc  test AudioCaptureSetGain interface, return 0 is call successfully.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, AudioCaptureSetGain_001, TestSize.Level0)
{
    int32_t ret = -1;
    float min = 0;
    float max = 0;
    ASSERT_NE(nullptr, capture);

    ret = capture->GetGainThreshold(capture, &min, &max);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    float gain = max - 1;
    float gainMax = max;
    float gainMin = min;
    float gainExpc = max - 1;
    float gainMaxExpc = max;
    float gainMinExpc = min;
    ret = capture->SetGain(capture, gainMax);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = capture->GetGain(capture, &gainMax);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    EXPECT_EQ(gainMaxExpc, gainMax);

    ret = capture->SetGain(capture, gainMin);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = capture->GetGain(capture, &gainMin);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    EXPECT_EQ(gainMinExpc, gainMin);

    ret = capture->SetGain(capture, gain);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = capture->GetGain(capture, &gain);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    EXPECT_EQ(gainExpc, gain);
}
#ifndef ALSA_LIB_MODE
/**
* @tc.name  AudioCaptureSetGain_002
* @tc.desc  test AudioCaptureSetGain interface, return -3 if gain greater than the maximum and less than the minimum
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, AudioCaptureSetGain_002, TestSize.Level0)
{
    int32_t ret = -1;
    float min = 0;
    float max = 0;
    ASSERT_NE(nullptr, capture);
    ret = capture->GetGainThreshold(capture, &min, &max);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);

    float gainOne = max + 1;
    float gainSec = min - 1;
    ret = capture->SetGain(capture, gainOne);
    ASSERT_TRUE(ret == HDF_FAILURE || ret == HDF_ERR_NOT_SUPPORT);

    ret = capture->SetGain(capture, gainSec);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_NOT_SUPPORT);
}
#endif
/**
* @tc.name  AudioCaptureSetGainNull_003
* @tc.desc  test AudioCaptureSetGain interface, return -3/-4 if the incoming parameter handle is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, AudioCaptureSetGainNull_003, TestSize.Level1)
{
    int32_t ret = -1;
    float gain = 0;
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);

    ret = capture->SetGain(captureNull, gain);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
}
/**
* @tc.name  AudioCaptureGetGain_001
* @tc.desc  test AudioCaptureGetGain interface, return 0 if CaptureGetGain is call successfully.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, AudioCaptureGetGain_001, TestSize.Level0)
{
    int32_t ret = -1;
    float min = 0;
    float max = 0;
    ASSERT_NE(nullptr, capture);
    ret = capture->GetGainThreshold(capture, &min, &max);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);

    float gain = min + 1;
    float gainValue = min + 1;
    ret = capture->SetGain(capture, gain);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = capture->GetGain(capture, &gain);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    EXPECT_EQ(gainValue, gain);
}
/**
* @tc.name  AudioCaptureGetGainNull_002
* @tc.desc  test AudioCaptureGetGain interface, return -3 if the incoming parameter handle is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, AudioCaptureGetGainNull_002, TestSize.Level1)
{
    int32_t ret = -1;
    float gainValue = 0;
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = capture->GetGain(captureNull, &gainValue);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
}
/**
* @tc.name  AudioCaptureGetGain_003
* @tc.desc  test AudioCaptureGetGain interface, return 0 if get gain after creating the capture object.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, AudioCaptureGetGain_003, TestSize.Level0)
{
    int32_t ret = -1;
    float gain = GAIN_MAX - 1;
    float gainOne = GAIN_MAX - 1;
    ASSERT_NE(nullptr, capture);

    ret = capture->SetGain(capture, gain);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = capture->GetGain(capture, &gain);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    EXPECT_EQ(gainOne, gain);
}
/**
* @tc.name  AudioCaptureGetGainNull_004
* @tc.desc  test AudioCaptureGetGain interface, return -3 if the parameter gain is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, AudioCaptureGetGainNull_004, TestSize.Level1)
{
    int32_t ret = -1;
    float *gainNull = nullptr;
    ASSERT_NE(nullptr, capture);

    ret = capture->GetGain(capture, gainNull);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_NOT_SUPPORT);
}
}