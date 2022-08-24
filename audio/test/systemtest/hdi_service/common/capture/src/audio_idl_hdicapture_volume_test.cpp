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
class AudioIdlHdiCaptureVolumeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioCapture *capture = nullptr;
    static TestAudioManager *(*GetAudioManager)(const char *);
    static TestAudioManager *manager;
    static void *handleSo;
    static void (*AudioManagerRelease)(struct IAudioManager *);
    static void (*AudioAdapterRelease)(struct IAudioAdapter *);
    static void (*AudioCaptureRelease)(struct IAudioCapture *);
    void ReleaseCaptureSource(void);
};

using THREAD_FUNC = void *(*)(void *);

TestAudioManager *(*AudioIdlHdiCaptureVolumeTest::GetAudioManager)(const char *) = nullptr;
TestAudioManager *AudioIdlHdiCaptureVolumeTest::manager = nullptr;
void *AudioIdlHdiCaptureVolumeTest::handleSo = nullptr;
void (*AudioIdlHdiCaptureVolumeTest::AudioManagerRelease)(struct IAudioManager *) = nullptr;
void (*AudioIdlHdiCaptureVolumeTest::AudioAdapterRelease)(struct IAudioAdapter *) = nullptr;
void (*AudioIdlHdiCaptureVolumeTest::AudioCaptureRelease)(struct IAudioCapture *) = nullptr;

void AudioIdlHdiCaptureVolumeTest::SetUpTestCase(void)
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
    AudioManagerRelease = (void (*)(struct IAudioManager *))(dlsym(handleSo, "AudioManagerRelease"));
    ASSERT_NE(nullptr, AudioManagerRelease);
    AudioAdapterRelease = (void (*)(struct IAudioAdapter *))(dlsym(handleSo, "AudioAdapterRelease"));
    ASSERT_NE(nullptr, AudioAdapterRelease);
    AudioCaptureRelease = (void (*)(struct IAudioCapture *))(dlsym(handleSo, "AudioCaptureRelease"));
    ASSERT_NE(nullptr, AudioCaptureRelease);
}

void AudioIdlHdiCaptureVolumeTest::TearDownTestCase(void)
{
    if (AudioManagerRelease != nullptr) {
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

void AudioIdlHdiCaptureVolumeTest::SetUp(void)
{
    int32_t ret;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

void AudioIdlHdiCaptureVolumeTest::TearDown(void)
{
    ReleaseCaptureSource();
}

void AudioIdlHdiCaptureVolumeTest::ReleaseCaptureSource(void)
{
    if (capture != nullptr && AudioCaptureRelease != nullptr) {
        adapter->DestroyCapture(adapter);
        AudioCaptureRelease(capture);
        capture = nullptr;
    }
    if (adapter != nullptr && AudioAdapterRelease != nullptr) {
        manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
        AudioAdapterRelease(adapter);
        adapter = nullptr;
    }
}

/**
* @tc.name  Test AudioCaptureSetMute API via legal input.
* @tc.number  SUB_Audio_HDI_CaptureSetMute_001
* @tc.desc  Test AudioCaptureSetMute interface , return 0 if the audiocapture object sets mute successfully.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, SUB_Audio_HDI_CaptureSetMute_001, TestSize.Level1)
{
    int32_t ret = -1;
    bool muteTrue = true;
    bool muteFalse = false;
    ASSERT_NE(nullptr, capture);

    ret = capture->SetMute(capture, muteTrue);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->GetMute(capture, &muteTrue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_TRUE(muteTrue);

    ret = capture->SetMute(capture, muteFalse);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->GetMute(capture, &muteFalse);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_FALSE(muteFalse);
}
/**
* @tc.name  Test AudioCaptureSetMute API via setting the capture is nullptr .
* @tc.number  SUB_Audio_HDI_CaptureSetMute_Null_002
* @tc.desc  Test AudioCaptureSetMute interface, return -3/-4 if the capture is nullptr.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, SUB_Audio_HDI_CaptureSetMute_Null_002, TestSize.Level1)
{
    bool muteTrue = true;
    bool muteFalse = false;
    int32_t ret = -1;
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = capture->SetMute(captureNull, muteTrue);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);

    ret = capture->SetMute(captureNull, muteFalse);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
* @tc.name  Test AudioCaptureSetMute API,when the parameter mutevalue equals 2.
* @tc.number  SUB_Audio_HDI_CaptureSetMute_003
* @tc.desc  Test AudioCaptureSetMute interface and set the parameter mutevalue with 2.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, SUB_Audio_HDI_CaptureSetMute_003, TestSize.Level1)
{
    bool muteValue = 2;
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);

    ret = capture->SetMute(capture, muteValue);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->GetMute(capture, &muteValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_TRUE(muteValue);
}
/**
* @tc.name  Test AudioCaptureGetMute API via legal input.
* @tc.number  SUB_Audio_HDI_CaptureGetMute_001
* @tc.desc  Test AudioCaptureGetMute interface , return 0 if the audiocapture gets mute successfully.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, SUB_Audio_HDI_CaptureGetMute_001, TestSize.Level1)
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
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(muteTrue, defaultmute);

    ret = capture->SetMute(capture, muteFalse);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->GetMute(capture, &muteFalse);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_FALSE(muteFalse);
}
/**
* @tc.name  Test interface AudioCaptureGetMute when capture is nullptr.
* @tc.number  SUB_Audio_HDI_CaptureGetMute_Null_002
* @tc.desc  Test AudioCreateCapture interface, return -3/-4 if the capture is nullptr.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, SUB_Audio_HDI_CaptureGetMute_Null_002, TestSize.Level1)
{
    int32_t ret = -1;
    bool muteTrue = true;
    bool muteFalse = false;
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = capture->GetMute(captureNull, &muteTrue);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);

    ret = capture->GetMute(captureNull, &muteFalse);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);

    ret = capture->GetMute(capture, nullptr);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
* @tc.name  Test AudioCaptureSetVolume API via legal input.
* @tc.number  SUB_Audio_HDI_CaptureSetVolume_001
* @tc.desc  Test AudioCaptureSetVolume interface , return 0 if the audiocapture sets volume successfully.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, SUB_Audio_HDI_CaptureSetVolume_001, TestSize.Level1)
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
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetVolume(capture, &volumeInit);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(volumeInitExpc, volumeInit);
    ret = capture->SetVolume(capture, volumeLow);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetVolume(capture, &volumeLow);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(volumeLowExpc, volumeLow);
    ret = capture->SetVolume(capture, volumeMid);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetVolume(capture, &volumeMid);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(volumeMidExpc, volumeMid);
    ret = capture->SetVolume(capture, volumeHigh);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetVolume(capture, &volumeHigh);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(volumeHighExpc, volumeHigh);
}
/**
* @tc.name  Test AudioCaptureSetVolume,when volume is set maximum value or minimum value.
* @tc.number  SUB_Audio_HDI_CaptureSetVolume_002
* @tc.desc  Test AudioCaptureSetVolume,return -3 if volume is set maximum value or minimum value.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, SUB_Audio_HDI_CaptureSetVolume_002, TestSize.Level1)
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
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetVolume(capture, &volumeMin);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(volumeMinExpc, volumeMin);

    ret = capture->SetVolume(capture, volumeMax);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetVolume(capture, &volumeMax);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(volumeMaxExpc, volumeMax);

    ret = capture->SetVolume(capture, volumeMinBoundary);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    ret = capture->SetVolume(capture, volumeMaxBoundary);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**
* @tc.name  Test AudioCaptureSetVolume,when capture is nullptr.
* @tc.number  SUB_Audio_HDI_CaptureSetVolume_Null_003
* @tc.desc  Test AudioCaptureSetVolume,return -3/-4 when capture is nullptr.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, SUB_Audio_HDI_CaptureSetVolume_Null_003, TestSize.Level1)
{
    int32_t ret = -1;
    float volume = 0;
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);

    ret = capture->SetVolume(captureNull, volume);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
* @tc.name  Test AudioCaptureGetVolume API via legal input.
* @tc.number  SUB_Audio_HDI_CaptureGetVolume_001
* @tc.desc  Test AudioCaptureGetVolume interface , return 0 if the audiocapture is get successful.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, SUB_Audio_HDI_CaptureGetVolume_001, TestSize.Level1)
{
    int32_t ret = -1;
    float volume = 0.60;
    float defaultVolume = 0.60;
    ASSERT_NE(nullptr, capture);

    ret = capture->SetVolume(capture, volume);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetVolume(capture, &volume);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(defaultVolume, volume);
}
/**
* @tc.name  Test AudioCaptureGetVolume when when capturing is in progress.
* @tc.number  SUB_Audio_HDI_CaptureGetVolume_002.
* @tc.desc  Test AudioCaptureGetVolume,return 0 when when capturing is in progress.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, SUB_Audio_HDI_CaptureGetVolume_002, TestSize.Level1)
{
    int32_t ret = -1;
    float volume = 0.60;
    float defaultVolume = 0.60;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->SetVolume(capture, volume);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetVolume(capture, &volume);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(defaultVolume, volume);

    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  Test AudioCaptureGetVolume,when capture is nullptr.
* @tc.number  SUB_Audio_HDI_CaptureGetVolume_Null_003
* @tc.desc  Test AudioCaptureGetVolume,return -3/-4 when capture is nullptr.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, SUB_Audio_HDI_CaptureGetVolume_Null_003, TestSize.Level1)
{
    int32_t ret = -1;
    float volume = 0.30;
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);

    ret = capture->GetVolume(captureNull, &volume);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
* @tc.name  Test AudioCaptureGetGainThreshold API via legal input
* @tc.number  SUB_Audio_HDI_CaptureGetGainThreshold_001
* @tc.desc  test AudioCaptureGetGainThreshold interface, return 0 is call successfully.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, SUB_Audio_HDI_CaptureGetGainThreshold_001, TestSize.Level1)
{
    int32_t ret = -1;
    float min = 0;
    float max = 0;
    ASSERT_NE(nullptr, capture);

    ret = capture->GetGainThreshold(capture, &min, &max);
    EXPECT_EQ(HDF_SUCCESS, ret);
#ifndef ALSA_LIB_MODE
    EXPECT_EQ(min, GAIN_MIN);
    EXPECT_EQ(max, GAIN_MAX);
#endif
}
/**
* @tc.name  Test AudioCaptureGetGainThreshold API via setting the incoming parameter handle is nullptr
* @tc.number  SUB_Audio_HDI_CaptureGetGainThreshold_Null_002
* @tc.desc  test AudioCaptureGetGainThreshold interface, return -3/-4 if the incoming parameter handle is nullptr.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, SUB_Audio_HDI_CaptureGetGainThreshold_Null_002, TestSize.Level1)
{
    int32_t ret = -1;
    float min = 0;
    float max = 0;
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);

    ret = capture->GetGainThreshold(captureNull, &min, &max);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
* @tc.name  Test AudioCaptureGetGainThreshold API via setting the incoming parameter min is nullptr
* @tc.number  SUB_Audio_HDI_CaptureGetGainThreshold_Null_003
* @tc.desc  test AudioCaptureGetGainThreshold interface, return -3 if the incoming parameter min is nullptr.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, SUB_Audio_HDI_CaptureGetGainThreshold_Null_003, TestSize.Level1)
{
    int32_t ret = -1;
    float max = 0;
    float* minNull = nullptr;
    ASSERT_NE(nullptr, capture);

    ret = capture->GetGainThreshold(capture, minNull, &max);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**
* @tc.name  Test AudioCaptureGetGainThreshold API via setting the incoming parameter max is nullptr
* @tc.number  SUB_Audio_HDI_CaptureGetGainThreshold_Null_004
* @tc.desc  test AudioCaptureGetGainThreshold interface, return -3 if the incoming parameter max is nullptr.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, SUB_Audio_HDI_CaptureGetGainThreshold_Null_004, TestSize.Level1)
{
    int32_t ret = -1;
    float min = 0;
    float* maxNull = nullptr;
    ASSERT_NE(nullptr, capture);

    ret = capture->GetGainThreshold(capture, &min, maxNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**
* @tc.name  Test AudioCaptureSetGain API via legal input
* @tc.number  SUB_Audio_HDI_CaptureSetGain_001
* @tc.desc  test AudioCaptureSetGain interface, return 0 is call successfully.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, SUB_Audio_HDI_CaptureSetGain_001, TestSize.Level1)
{
    int32_t ret = -1;
    float min = 0;
    float max = 0;
    ASSERT_NE(nullptr, capture);

    ret = capture->GetGainThreshold(capture, &min, &max);
    EXPECT_EQ(HDF_SUCCESS, ret);
    float gain = max - 1;
    float gainMax = max;
    float gainMin = min;
    float gainExpc = max - 1;
    float gainMaxExpc = max;
    float gainMinExpc = min;
    ret = capture->SetGain(capture, gainMax);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetGain(capture, &gainMax);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(gainMaxExpc, gainMax);

    ret = capture->SetGain(capture, gainMin);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetGain(capture, &gainMin);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(gainMinExpc, gainMin);

    ret = capture->SetGain(capture, gain);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetGain(capture, &gain);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(gainExpc, gain);
}
#ifndef ALSA_LIB_MODE
/**
* @tc.name  Test AudioCaptureSetGain API via setting gain greater than the maximum and less than the minimum
* @tc.number  SUB_Audio_HDI_CaptureSetGain_002
* @tc.desc  test AudioCaptureSetGain interface, return -3 if gain greater than the maximum and less than the minimum
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, SUB_Audio_HDI_CaptureSetGain_002, TestSize.Level1)
{
    int32_t ret = -1;
    float min = 0;
    float max = 0;
    ASSERT_NE(nullptr, capture);
    ret = capture->GetGainThreshold(capture, &min, &max);
    EXPECT_EQ(HDF_SUCCESS, ret);

    float gainOne = max + 1;
    float gainSec = min - 1;
    ret = capture->SetGain(capture, gainOne);
    EXPECT_EQ(HDF_FAILURE, ret);

    ret = capture->SetGain(capture, gainSec);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
#endif
/**
* @tc.name  Test AudioCaptureSetGain API via setting the incoming parameter handle is nullptr.
* @tc.number  SUB_Audio_HDI_CaptureSetGain_Null_003
* @tc.desc  test AudioCaptureSetGain interface, return -3/-4 if the incoming parameter handle is nullptr.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, SUB_Audio_HDI_CaptureSetGain_Null_003, TestSize.Level1)
{
    int32_t ret = -1;
    float gain = 0;
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);

    ret = capture->SetGain(captureNull, gain);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
* @tc.name  Test AudioCaptureGetGain API via legal input
* @tc.number  SUB_Audio_HDI_CaptureGetGain_001
* @tc.desc  test AudioCaptureGetGain interface, return 0 if CaptureGetGain is call successfully.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, SUB_Audio_HDI_CaptureGetGain_001, TestSize.Level1)
{
    int32_t ret = -1;
    float min = 0;
    float max = 0;
    ASSERT_NE(nullptr, capture);
    ret = capture->GetGainThreshold(capture, &min, &max);
    EXPECT_EQ(HDF_SUCCESS, ret);

    float gain = min + 1;
    float gainValue = min + 1;
    ret = capture->SetGain(capture, gain);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetGain(capture, &gain);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(gainValue, gain);
}
/**
* @tc.name  Test AudioCaptureGetGain API via setting the incoming parameter handle is nullptr
* @tc.number  SUB_Audio_HDI_CaptureGetGain_Null_002
* @tc.desc  test AudioCaptureGetGain interface, return -3 if the incoming parameter handle is nullptr.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, SUB_Audio_HDI_CaptureGetGain_Null_002, TestSize.Level1)
{
    int32_t ret = -1;
    float gainValue = 0;
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = capture->GetGain(captureNull, &gainValue);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
* @tc.name  Test AudioCaptureGetGain API via legal input in difference scenes
* @tc.number  SUB_Audio_HDI_CaptureGetGain_003
* @tc.desc  test AudioCaptureGetGain interface, return 0 if get gain after creating the capture object.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, SUB_Audio_HDI_CaptureGetGain_003, TestSize.Level1)
{
    int32_t ret = -1;
    float gain = GAIN_MAX - 1;
    float gainOne = GAIN_MAX - 1;
    ASSERT_NE(nullptr, capture);

    ret = capture->SetGain(capture, gain);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetGain(capture, &gain);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(gainOne, gain);
}
/**
* @tc.name  Test AudioCaptureGetGain API via setting the parameter gain is nullptr
* @tc.number  SUB_Audio_HDI_CaptureGetGain_Null_004
* @tc.desc  test AudioCaptureGetGain interface, return -3 if the parameter gain is nullptr.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureVolumeTest, SUB_Audio_HDI_CaptureGetGain_Null_004, TestSize.Level1)
{
    int32_t ret = -1;
    float *gainNull = nullptr;
    ASSERT_NE(nullptr, capture);

    ret = capture->GetGain(capture, gainNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
}