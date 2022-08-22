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
 * @brief Test audio recording interface delayTime.
 *
 * @since 1.0
 * @version 1.0
 */

/**
 * @file audio_hdi_common.h
 *
 * @brief Declares APIs for operations related to the audio delayTime.
 *
 * @since 1.0
 * @version 1.0
 */

#include "audio_hdi_common.h"
#include "audio_hdicapture_performace_test.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
const float COUNT = 1000;
const int32_t LOWLATENCY = 10000;
const int32_t NORMALLATENCY = 30000;
const int32_t HIGHLATENCY = 60000;
const int BUFFER = 1024 * 4;

class AudioHdiCapturePerformaceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static void *handle;
    static TestGetAudioManager getAudioManager;
    static TestAudioManager *manager;
};

void *AudioHdiCapturePerformaceTest::handle = nullptr;
TestGetAudioManager AudioHdiCapturePerformaceTest::getAudioManager = nullptr;
TestAudioManager *AudioHdiCapturePerformaceTest::manager = nullptr;

void AudioHdiCapturePerformaceTest::SetUpTestCase(void)
{
    int32_t ret = LoadFunction(handle, getAudioManager);
    ASSERT_EQ(HDF_SUCCESS, ret);
    manager = getAudioManager();
    ASSERT_NE(nullptr, manager);
}

void AudioHdiCapturePerformaceTest::TearDownTestCase(void)
{
    if (handle != nullptr) {
        (void)dlclose(handle);
    }
    if (getAudioManager != nullptr) {
        getAudioManager = nullptr;
    }
}

void AudioHdiCapturePerformaceTest::SetUp(void) {}

void AudioHdiCapturePerformaceTest::TearDown(void) {}

/**
* @tc.name  the performance of AudioCreateCapture
* @tc.number  SUB_Audio_HDI_AudioCreateCapture_Performance_0001
* @tc.devDesc  tests the performance of AudioCreateCapture interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCapturePerformaceTest, SUB_Audio_HDI_AudioCreateCapture_Performance_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = GetLoadAdapter(audiopara.manager, audiopara.portType, audiopara.adapterName,
                         &audiopara.adapter, audiopara.audioPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrs(audiopara.attrs);
    InitDevDesc(audiopara.devDesc, audiopara.audioPort->portId, audiopara.pins);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.adapter->CreateCapture(audiopara.adapter, &audiopara.devDesc, &audiopara.attrs,
                                               &audiopara.capture);
        gettimeofday(&audiopara.end, NULL);
        if (ret < 0 || audiopara.capture == nullptr) {
            audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
            audiopara.adapter = nullptr;
            ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        }
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
        audiopara.capture = nullptr;
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(HIGHLATENCY, audiopara.averageDelayTime);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performance of AudioDestroyCapture
* @tc.number  SUB_Audio_HDI_AudioDestroyCapture_Performance_0001
* @tc.devDesc  tests the performance of AudioDestroyCapture interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCapturePerformaceTest, SUB_Audio_HDI_AudioDestroyCapture_Performance_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    for (int i = 0; i < COUNT; ++i) {
        ret = AudioCreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                                 &audiopara.capture);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.capture = nullptr;
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        audiopara.adapter = nullptr;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  the performance of AudioCaptureStart
* @tc.number  SUB_Audio_HDI_AudioCaptureStart_Performance_0001
* @tc.devDesc  tests the performance of AudioCaptureStart interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCapturePerformaceTest, SUB_Audio_HDI_AudioCaptureStart_Performance_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    for (int i = 0; i < COUNT; ++i) {
        ret = AudioCreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                                 &audiopara.capture);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->control.Start((AudioHandle)audiopara.capture);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = StopAudio(audiopara);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}
/**
* @tc.name  the performance of AudioCapturePause
* @tc.number  SUB_Audio_HDI_AudioCapturePause_Performance_0001
* @tc.devDesc  tests the performance of AudioCapturePause interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCapturePerformaceTest, SUB_Audio_HDI_AudioCapturePause_Performance_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                             &audiopara.capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = audiopara.capture->control.Start((AudioHandle)audiopara.capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->control.Pause((AudioHandle)audiopara.capture);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        ret = audiopara.capture->control.Resume((AudioHandle)audiopara.capture);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = StopAudio(audiopara);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
}

/**
* @tc.name  the performance of AudioCaptureResume
* @tc.number  SUB_Audio_HDI_AudioCaptureResume_Performance_0001
* @tc.devDesc  tests the performance of AudioCaptureResume interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCapturePerformaceTest, SUB_Audio_HDI_AudioCaptureResume_Performance_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                             &audiopara.capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = audiopara.capture->control.Start((AudioHandle)audiopara.capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        ret = audiopara.capture->control.Pause((AudioHandle)audiopara.capture);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->control.Resume((AudioHandle)audiopara.capture);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = StopAudio(audiopara);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
}
/**
* @tc.name  the performance of AudioCaptureStop
* @tc.number  SUB_Audio_HDI_AudioCaptureStop_Performance_0001
* @tc.devDesc  tests the performance of AudioCaptureStop interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCapturePerformaceTest, SUB_Audio_HDI_AudioCaptureStop_Performance_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    for (int i = 0; i < COUNT; ++i) {
        ret = AudioCreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                                 &audiopara.capture);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ret = audiopara.capture->control.Start((AudioHandle)audiopara.capture);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->control.Stop((AudioHandle)audiopara.capture);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.capture = nullptr;
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        audiopara.adapter = nullptr;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  the performance of AudioCaptureSetSampleAttributes
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_Performance_0001
* @tc.devDesc  tests the performance of AudioCaptureSetSampleAttributes interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCapturePerformaceTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_Performance_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                             &audiopara.capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrs(audiopara.attrs);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->attr.SetSampleAttributes(audiopara.capture, &audiopara.attrs);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.adapter = nullptr;
}
/**
* @tc.name  the performance of AudioCaptureCaptureFrame
* @tc.number  SUB_Audio_HDI_AudioCaptureCaptureFrame_Performance_0001
* @tc.devDesc  tests the performance of AudioCaptureCaptureFrame interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCapturePerformaceTest, SUB_Audio_HDI_AudioCaptureCaptureFrame_Performance_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0,
        .requestBytes = BUFFER_LENTH
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    audiopara.frame = (char *)calloc(1, BUFFER_LENTH);
    ASSERT_NE(nullptr, audiopara.frame);
    for (int i = 0; i < COUNT; ++i) {
        ret = GetLoadAdapter(audiopara.manager, audiopara.portType, audiopara.adapterName, &(audiopara.adapter),
                             audiopara.audioPort);
        if (ret < 0 || audiopara.adapter == nullptr) {
            free(audiopara.frame);
            audiopara.frame = nullptr;
            ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        }
        InitAttrs(audiopara.attrs);
        audiopara.attrs.silenceThreshold = BUFFER;
        InitDevDesc(audiopara.devDesc, audiopara.audioPort->portId, audiopara.pins);
        ret = audiopara.adapter->CreateCapture(audiopara.adapter, &audiopara.devDesc, &audiopara.attrs,
                                               &audiopara.capture);
        if (ret < 0) {
            audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
            free(audiopara.frame);
            audiopara.frame = nullptr;
            ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        }
        ret = audiopara.capture->control.Start((AudioHandle)audiopara.capture);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->CaptureFrame(audiopara.capture, audiopara.frame, audiopara.requestBytes,
                                              &audiopara.replyBytes);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = StopAudio(audiopara);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(NORMALLATENCY, audiopara.averageDelayTime);
    free(audiopara.frame);
    audiopara.frame = nullptr;
}
/**
* @tc.name  the performance of AudioCaptureGetSampleAttributes
* @tc.number  SUB_Audio_HDI_AudioCaptureGetSampleAttributes_Performance_0001
* @tc.devDesc  tests the performance of AudioCaptureGetSampleAttributes interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCapturePerformaceTest, SUB_Audio_HDI_AudioCaptureGetSampleAttributes_Performance_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                             &audiopara.capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrs(audiopara.attrs);
    ret = audiopara.capture->attr.SetSampleAttributes(audiopara.capture, &audiopara.attrs);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->attr.GetSampleAttributes(audiopara.capture, &audiopara.attrsValue);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performance of AudioCaptureSetMute
* @tc.number  SUB_Audio_HDI_AudioCaptureSetMute_Performance_0001
* @tc.devDesc  tests the performance of AudioCaptureSetMute interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCapturePerformaceTest, SUB_Audio_HDI_AudioCaptureSetMute_Performance_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                             &audiopara.capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->volume.SetMute(audiopara.capture, false);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = audiopara.capture->volume.GetMute(audiopara.capture, &audiopara.character.getmute);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_FALSE(audiopara.character.getmute);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performance of AudioCaptureGetMute
* @tc.number  SUB_Audio_HDI_AudioCaptureGetMute_Performance_0001
* @tc.devDesc  tests the performance of AudioCaptureGetMute interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCapturePerformaceTest, SUB_Audio_HDI_AudioCaptureGetMute_Performance_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                             &audiopara.capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = audiopara.capture->volume.SetMute(audiopara.capture, false);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->volume.GetMute(audiopara.capture, &audiopara.character.getmute);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_FALSE(audiopara.character.getmute);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performance of AudioCaptureSetVolume
* @tc.number  SUB_Audio_HDI_AudioCaptureSetVolume_Performance_0001
* @tc.devDesc  tests the performance of AudioCaptureSetVolume interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCapturePerformaceTest, SUB_Audio_HDI_AudioCaptureSetVolume_Performance_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0,
        .character.setvolume = 0.7
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                             &audiopara.capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->volume.SetVolume(audiopara.capture, audiopara.character.setvolume);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        ret = audiopara.capture->volume.GetVolume(audiopara.capture, &audiopara.character.getvolume);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_EQ(audiopara.character.setvolume, audiopara.character.getvolume);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performance of AudioCaptureGetVolume
* @tc.number  SUB_Audio_HDI_AudioCaptureGetVolume_Performance_0001
* @tc.devDesc  tests the performance of AudioCaptureGetVolume interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCapturePerformaceTest, SUB_Audio_HDI_AudioCaptureGetVolume_Performance_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0,
        .character.setvolume = 0.8
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                             &audiopara.capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = audiopara.capture->volume.SetVolume(audiopara.capture, audiopara.character.setvolume);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->volume.GetVolume(audiopara.capture, &audiopara.character.getvolume);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_EQ(audiopara.character.setvolume, audiopara.character.getvolume);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performance of AudioCaptureGetGain
* @tc.number  SUB_Audio_HDI_AudioCaptureGetGain_Performance_0001
* @tc.devDesc  tests the performance of AudioCaptureGetGain interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCapturePerformaceTest, SUB_Audio_HDI_AudioCaptureGetGain_Performance_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0,
        .character.setgain = 7
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                             &audiopara.capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = audiopara.capture->volume.SetGain(audiopara.capture, audiopara.character.setgain);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->volume.GetGain(audiopara.capture, &audiopara.character.getgain);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_EQ(audiopara.character.setgain, audiopara.character.getgain);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performance of AudioCaptureSetGain
* @tc.number  SUB_Audio_HDI_AudioCaptureSetGain_Performance_0001
* @tc.devDesc  tests the performance of AudioCaptureSetGain interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCapturePerformaceTest, SUB_Audio_HDI_AudioCaptureSetGain_Performance_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0,
        .character.setgain = 8
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                             &audiopara.capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->volume.SetGain(audiopara.capture, audiopara.character.setgain);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        ret = audiopara.capture->volume.GetGain(audiopara.capture, &audiopara.character.getgain);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_EQ(audiopara.character.setgain, audiopara.character.getgain);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performance of AudioCaptureGetCurrentChannelId
* @tc.number  SUB_Audio_HDI_AudioCaptureGetCurrentChannelId_Performance_0001
* @tc.devDesc  tests the performance of AudioCaptureGetCurrentChannelId interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCapturePerformaceTest, SUB_Audio_HDI_AudioCaptureGetCurrentChannelId_Performance_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                             &audiopara.capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->attr.GetCurrentChannelId(audiopara.capture, &audiopara.character.getcurrentchannelId);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performance of AudioCaptureGetFrameCount
* @tc.number  SUB_Audio_HDI_AudioCaptureGetFrameCount_Performance_0001
* @tc.devDesc  tests the performance of AudioCaptureGetFrameCount interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCapturePerformaceTest, SUB_Audio_HDI_AudioCaptureGetFrameCount_Performance_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                             &audiopara.capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->attr.GetFrameCount(audiopara.capture, &audiopara.character.getframecount);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_EQ(INITIAL_VALUE, audiopara.character.getframecount);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performance of AudioCaptureGetFrameSize
* @tc.number  SUB_Audio_HDI_AudioCaptureGetFrameSize_Performance_0001
* @tc.devDesc  tests the performance of AudioCaptureGetFrameSize interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCapturePerformaceTest, SUB_Audio_HDI_AudioCaptureGetFrameSize_Performance_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                             &audiopara.capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->attr.GetFrameSize(audiopara.capture, &audiopara.character.getframesize);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_GT(audiopara.character.getframesize, INITIAL_VALUE);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performance of AudioCaptureFlush
* @tc.number  SUB_Audio_HDI_AudioCaptureFlush_Performance_0001
* @tc.devDesc  tests the performance of AudioCaptureFlush interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCapturePerformaceTest, SUB_Audio_HDI_AudioCaptureFlush_Performance_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    for (int i = 0; i < COUNT; ++i) {
        ret = AudioCreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                                 &audiopara.capture);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ret = audiopara.capture->control.Start((AudioHandle)audiopara.capture);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->control.Flush((AudioHandle)audiopara.capture);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = StopAudio(audiopara);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  the performance of AudioCaptureGetGainThreshold
* @tc.number  SUB_Audio_HDI_AudioCaptureGetGainThreshold_Performance_0001
* @tc.devDesc  tests the performance of AudioCaptureGetGainThreshold interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCapturePerformaceTest, SUB_Audio_HDI_AudioCaptureGetGainThreshold_Performance_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                             &audiopara.capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->volume.GetGainThreshold(audiopara.capture, &audiopara.character.gainthresholdmin,
                &audiopara.character.gainthresholdmax);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_EQ(audiopara.character.gainthresholdmin, GAIN_MIN);
        EXPECT_EQ(audiopara.character.gainthresholdmax, GAIN_MAX);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performance of AudioCaptureCheckSceneCapability
* @tc.number  SUB_Audio_HDI_AudioCaptureCheckSceneCapability_Performance_0001
* @tc.devDesc  tests the performance of AudioCaptureCheckSceneCapability interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCapturePerformaceTest, SUB_Audio_HDI_AudioCaptureCheckSceneCapability_Performance_0001,
         TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    struct AudioSceneDescriptor scenes = { .scene.id = 0, .desc.pins = PIN_IN_MIC };
    bool supported = false;
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                             &audiopara.capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->scene.CheckSceneCapability(audiopara.capture, &scenes, &supported);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performance of AudioCaptureSelectScene
* @tc.number  SUB_Audio_HDI_AudioCaptureSelectScene_Performance_0001
* @tc.devDesc  tests the performance of AudioCaptureSelectScene interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCapturePerformaceTest, SUB_Audio_HDI_AudioCaptureSelectScene_Performance_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    struct AudioSceneDescriptor scenes = { .scene.id = 0, .desc.pins = PIN_IN_MIC };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                             &audiopara.capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->scene.SelectScene(audiopara.capture, &scenes);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performance of AudioGetCapturePosition
* @tc.number  SUB_Audio_HDI_AudioGetCapturePosition_Performance_0001
* @tc.devDesc  tests the performance of AudioCaptureGetCapturePosition interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCapturePerformaceTest, SUB_Audio_HDI_AudioGetCapturePosition_Performance_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                             &audiopara.capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = audiopara.capture->control.Start((AudioHandle)audiopara.capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->GetCapturePosition(audiopara.capture, &audiopara.character.getframes, &audiopara.time);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = StopAudio(audiopara);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
}

/**
* @tc.name  the performance of AudioCaptureSetExtraParams
* @tc.number  SUB_Audio_HDI_AudioCaptureSetExtraParams_Performance_0001
* @tc.desc  tests the performance of AudioCaptureSetExtraParams interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCapturePerformaceTest, SUB_Audio_HDI_AudioCaptureSetExtraParams_Performance_0001, TestSize.Level1)
{
    int32_t ret = -1;
    char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;attr-frame-count=82;attr-sampling-rate=48000";
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateStartCapture(audiopara.manager, &audiopara.capture, &audiopara.adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->attr.SetExtraParams((AudioHandle)audiopara.capture, keyValueList);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    ret = StopAudio(audiopara);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  the performance of AudioCaptureGetExtraParams
* @tc.number  SUB_Audio_HDI_AudioCaptureGetExtraParams_Performance_0001
* @tc.desc  tests the performance of AudioCaptureGetExtraParams interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCapturePerformaceTest, SUB_Audio_HDI_AudioCaptureGetExtraParams_Performance_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    char keyValueList[] = "attr-format=24;attr-frame-count=4096;";
    char keyValueListExp[] = "attr-route=0;attr-format=24;attr-channels=2;attr-frame-count=4096;\
attr-sampling-rate=48000";
    int32_t listLenth = 256;
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);

    ret = AudioCreateStartCapture(audiopara.manager, &audiopara.capture, &audiopara.adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = audiopara.capture->attr.SetExtraParams((AudioHandle)audiopara.capture, keyValueList);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        char keyValueListValue[256] = {};
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->attr.GetExtraParams((AudioHandle)audiopara.capture, keyValueListValue, listLenth);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_STREQ(keyValueListExp, keyValueListValue);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    ret = StopAudio(audiopara);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  the performance of AudioCaptureGetMmapPosition
* @tc.number  SUB_Audio_HDI_AudioCaptureGetMmapPosition_Performance_0001
* @tc.desc  tests the performance of AudioCaptureGetMmapPosition interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCapturePerformaceTest, SUB_Audio_HDI_AudioCaptureGetMmapPosition_Performance_0001, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                             &audiopara.capture);
    if (ret < 0 || audiopara.capture == nullptr) {
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ASSERT_EQ(nullptr, audiopara.capture);
    }

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->attr.GetMmapPosition(audiopara.capture, &frames, &(audiopara.time));
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_EQ((audiopara.time.tvSec) * SECTONSEC + (audiopara.time.tvNSec), timeExp);
        EXPECT_EQ(frames, INITIAL_VALUE);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    audiopara.capture = nullptr;
    audiopara.adapter = nullptr;
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}
}
