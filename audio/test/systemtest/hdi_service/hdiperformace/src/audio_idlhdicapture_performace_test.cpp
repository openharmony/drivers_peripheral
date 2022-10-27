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
const float COUNT = 1000;         // number of interface calls
const long LOWLATENCY = 10000;    // low interface delay:10ms
const long NORMALLATENCY = 30000; // normal interface delay:30ms
const int BUFFER = 1024 * 4;

class AudioIdlHdiCapturePerformaceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static TestAudioManager *manager;
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioCapture *capture = nullptr;
};

TestAudioManager *AudioIdlHdiCapturePerformaceTest::manager = nullptr;

void AudioIdlHdiCapturePerformaceTest::SetUpTestCase(void)
{
    manager = IAudioManagerGet(IS_STUB);
    ASSERT_NE(nullptr, manager);
}

void AudioIdlHdiCapturePerformaceTest::TearDownTestCase(void)
{
    if (manager != nullptr) {
        (void)IAudioManagerRelease(manager, IS_STUB);
    }
}

void AudioIdlHdiCapturePerformaceTest::SetUp(void)
{
    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

void AudioIdlHdiCapturePerformaceTest::TearDown(void)
{
    int32_t ret = ReleaseCaptureSource(manager, adapter, capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioCaptureStartPerformance_001
* @tc.devDesc  tests the performace of AudioCaptureStart interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, AudioCaptureStartPerformance_001, TestSize.Level1)
{
    struct PrepareAudioPara audiopara = {
        .capture = capture, .delayTime = 0, .totalTime = 0, .averageDelayTime =0,
    };
    ASSERT_NE(nullptr, audiopara.capture);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        int32_t ret = audiopara.capture->Start(audiopara.capture);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = audiopara.capture->Stop(audiopara.capture);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}
/**
* @tc.name  AudioCapturePausePerformance_001
* @tc.devDesc  tests the performace of AudioCapturePause interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, AudioCapturePausePerformance_001, TestSize.Level1)
{
    struct PrepareAudioPara audiopara = {
        .capture = capture, .delayTime = 0, .totalTime = 0, .averageDelayTime =0,
    };
    ASSERT_NE(nullptr, audiopara.capture);
    int32_t ret = audiopara.capture->Start(audiopara.capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->Pause(audiopara.capture);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.capture->Resume(audiopara.capture);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.capture->Stop(audiopara.capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
* @tc.name  AudioCaptureResumePerformance_001
* @tc.devDesc  tests the performace of AudioCaptureResume interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, AudioCaptureResumePerformance_001, TestSize.Level1)
{
    struct PrepareAudioPara audiopara = {
        .capture = capture, .delayTime = 0, .totalTime = 0, .averageDelayTime =0,
    };
    ASSERT_NE(nullptr, audiopara.capture);
    int32_t ret = audiopara.capture->Start(audiopara.capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        ret = audiopara.capture->Pause(audiopara.capture);
        EXPECT_EQ(HDF_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->Resume(audiopara.capture);
        gettimeofday(&audiopara.end, NULL);
        ASSERT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.capture->Stop(audiopara.capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
* @tc.name  AudioCaptureStopPerformance_001
* @tc.devDesc  tests the performace of AudioCaptureStop interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, AudioCaptureStopPerformance_001, TestSize.Level1)
{
    struct PrepareAudioPara audiopara = {
        .capture = capture, .delayTime = 0, .totalTime = 0, .averageDelayTime =0,
    };
    ASSERT_NE(nullptr, audiopara.capture);
    for (int i = 0; i < COUNT; ++i) {
        int32_t ret = audiopara.capture->Start(audiopara.capture);
        EXPECT_EQ(HDF_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->Stop(audiopara.capture);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  AudioCaptureSetSampleAttributesPerformance_001
* @tc.devDesc  tests the performace of AudioCaptureSetSampleAttributes interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, AudioCaptureSetSampleAttributesPerformance_001, TestSize.Level1)
{
    struct PrepareAudioPara audiopara = {
        .capture = capture, .delayTime = 0, .totalTime = 0, .averageDelayTime =0,
    };
    ASSERT_NE(nullptr, audiopara.capture);
    InitAttrs(audiopara.attrs);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        int32_t ret = audiopara.capture->SetSampleAttributes(audiopara.capture, &audiopara.attrs);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}
/**
* @tc.name  AudioCaptureCaptureFramePerformance_001
* @tc.devDesc  tests the performace of AudioCaptureCaptureFrame interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, AudioCaptureCaptureFramePerformance_001, TestSize.Level1)
{
    struct PrepareAudioPara audiopara = {
        .capture = capture, .delayTime = 0, .totalTime = 0, .averageDelayTime =0,
        .replyBytes = BUFFER, .requestBytes = BUFFER
    };
    ASSERT_NE(nullptr, audiopara.capture);
    audiopara.frame = (char *)calloc(1, BUFFER);
    ASSERT_NE(nullptr, audiopara.frame);
    InitAttrs(audiopara.attrs);
    audiopara.attrs.silenceThreshold = BUFFER;
    int32_t ret = audiopara.capture->SetSampleAttributes(audiopara.capture, &audiopara.attrs);
    ret = audiopara.capture->Start(audiopara.capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->CaptureFrame(audiopara.capture, (int8_t*) audiopara.frame, &audiopara.replyBytes,
                                              audiopara.requestBytes);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    ret = audiopara.capture->Stop(audiopara.capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(NORMALLATENCY, audiopara.averageDelayTime);
    free(audiopara.frame);
    audiopara.frame = nullptr;
}
/**
* @tc.name  AudioCaptureGetSampleAttributesPerformance_001
* @tc.devDesc  tests the performace of AudioCaptureGetSampleAttributes interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, AudioCaptureGetSampleAttributesPerformance_001, TestSize.Level1)
{
    struct PrepareAudioPara audiopara = {
        .capture = capture, .delayTime = 0, .totalTime = 0, .averageDelayTime =0,
    };
    ASSERT_NE(nullptr, audiopara.capture);
    InitAttrs(audiopara.attrs);
    int32_t ret = audiopara.capture->SetSampleAttributes(audiopara.capture, &audiopara.attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->GetSampleAttributes(audiopara.capture, &audiopara.attrsValue);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  AudioCaptureSetMutePerformance_001
* @tc.devDesc  tests the performace of AudioCaptureSetMute interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/

HWTEST_F(AudioIdlHdiCapturePerformaceTest, AudioCaptureSetMutePerformance_001, TestSize.Level1)
{
    struct PrepareAudioPara audiopara = {
        .capture = capture, .delayTime = 0, .totalTime = 0, .averageDelayTime =0,
    };
    ASSERT_NE(nullptr, audiopara.capture);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        int32_t ret = audiopara.capture->SetMute(audiopara.capture, false);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = audiopara.capture->GetMute(audiopara.capture, &audiopara.character.getmute);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_FALSE(audiopara.character.getmute);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  AudioCaptureGetMutePerformance_001
* @tc.devDesc  tests the performace of AudioCaptureGetMute interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, AudioCaptureGetMutePerformance_001, TestSize.Level1)
{
    struct PrepareAudioPara audiopara = {
        .capture = capture, .delayTime = 0, .totalTime = 0, .averageDelayTime =0,
    };
    ASSERT_NE(nullptr, audiopara.capture);
    int32_t ret = audiopara.capture->SetMute(audiopara.capture, false);
    EXPECT_EQ(HDF_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->GetMute(audiopara.capture, &audiopara.character.getmute);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_FALSE(audiopara.character.getmute);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  AudioCaptureSetVolumePerformance_001
* @tc.devDesc  tests the performace of AudioCaptureSetVolume interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, AudioCaptureSetVolumePerformance_001, TestSize.Level1)
{
    struct PrepareAudioPara audiopara = {
        .capture = capture, .delayTime = 0, .totalTime = 0, .averageDelayTime =0, .character.setvolume = 0.7
    };
    ASSERT_NE(nullptr, audiopara.capture);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        int32_t ret = audiopara.capture->SetVolume(audiopara.capture, audiopara.character.setvolume);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.capture->GetVolume(audiopara.capture, &audiopara.character.getvolume);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(audiopara.character.setvolume, audiopara.character.getvolume);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  AudioCaptureGetVolumePerformance_001
* @tc.devDesc  tests the performace of AudioCaptureGetVolume interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, AudioCaptureGetVolumePerformance_001, TestSize.Level1)
{
    struct PrepareAudioPara audiopara = {
        .capture = capture, .delayTime = 0, .totalTime = 0, .averageDelayTime =0, .character.setvolume = 0.8
    };
    ASSERT_NE(nullptr, audiopara.capture);
    int32_t ret = audiopara.capture->SetVolume(audiopara.capture, audiopara.character.setvolume);
    EXPECT_EQ(HDF_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->GetVolume(audiopara.capture, &audiopara.character.getvolume);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(audiopara.character.setvolume, audiopara.character.getvolume);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  AudioCaptureGetGainPerformance_001
* @tc.devDesc  tests the performace of AudioCaptureGetGain interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, AudioCaptureGetGainPerformance_001, TestSize.Level1)
{
    struct PrepareAudioPara audiopara = {
        .capture = capture, .delayTime = 0, .totalTime = 0, .averageDelayTime =0, .character.setgain = 7
    };
    ASSERT_NE(nullptr, audiopara.capture);
    int32_t ret = audiopara.capture->SetGain(audiopara.capture, audiopara.character.setgain);
    EXPECT_EQ(HDF_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->GetGain(audiopara.capture, &audiopara.character.getgain);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(audiopara.character.setgain, audiopara.character.getgain);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  AudioCaptureSetGainPerformance_001
* @tc.devDesc  tests the performace of AudioCaptureSetGain interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, AudioCaptureSetGainPerformance_001, TestSize.Level1)
{
    struct PrepareAudioPara audiopara = {
        .capture = capture, .delayTime = 0, .totalTime = 0, .averageDelayTime =0, .character.setgain = 8
    };
    ASSERT_NE(nullptr, audiopara.capture);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        int32_t ret = audiopara.capture->SetGain(audiopara.capture, audiopara.character.setgain);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.capture->GetGain(audiopara.capture, &audiopara.character.getgain);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(audiopara.character.setgain, audiopara.character.getgain);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  AudioCaptureGetCurrentChannelIdPerformance_001
* @tc.devDesc  tests the performace of AudioCaptureGetCurrentChannelId interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, AudioCaptureGetCurrentChannelIdPerformance_001, TestSize.Level1)
{
    struct PrepareAudioPara audiopara = {
        .capture = capture, .delayTime = 0, .totalTime = 0, .averageDelayTime =0
    };
    ASSERT_NE(nullptr, audiopara.capture);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        int32_t ret = audiopara.capture->GetCurrentChannelId(audiopara.capture,
            &audiopara.character.getcurrentchannelId);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  AudioCaptureGetFrameCountPerformance_001
* @tc.devDesc  tests the performace of AudioCaptureGetFrameCount interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, AudioCaptureGetFrameCountPerformance_001, TestSize.Level1)
{
    struct PrepareAudioPara audiopara = {
        .capture = capture, .delayTime = 0, .totalTime = 0, .averageDelayTime =0
    };
    ASSERT_NE(nullptr, audiopara.capture);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        int32_t ret = audiopara.capture->GetFrameCount(audiopara.capture, &audiopara.character.getframecount);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(INITIAL_VALUE, audiopara.character.getframecount);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  AudioCaptureGetFrameSizePerformance_001
* @tc.devDesc  tests the performace of AudioCaptureGetFrameSize interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, AudioCaptureGetFrameSizePerformance_001, TestSize.Level1)
{
    struct PrepareAudioPara audiopara = {
        .capture = capture, .delayTime = 0, .totalTime = 0, .averageDelayTime =0
    };
    ASSERT_NE(nullptr, audiopara.capture);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        int32_t ret = audiopara.capture->GetFrameSize(audiopara.capture, &audiopara.character.getframesize);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_GT(audiopara.character.getframesize, INITIAL_VALUE);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  AudioCaptureFlushPerformance_001
* @tc.devDesc  tests the performace of AudioCaptureFlush interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, AudioCaptureFlushPerformance_001, TestSize.Level1)
{
    struct PrepareAudioPara audiopara = {
        .capture = capture, .delayTime = 0, .totalTime = 0, .averageDelayTime =0
    };
    ASSERT_NE(nullptr, audiopara.capture);
    for (int i = 0; i < COUNT; ++i) {
        int32_t ret = audiopara.capture->Start(audiopara.capture);
        EXPECT_EQ(HDF_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->Flush(audiopara.capture);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = audiopara.capture->Stop(audiopara.capture);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  AudioCaptureGetGainThresholdPerformance_001
* @tc.devDesc  tests the performace of AudioCaptureGetGainThreshold interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, AudioCaptureGetGainThresholdPerformance_001, TestSize.Level1)
{
    struct PrepareAudioPara audiopara = {
        .capture = capture, .delayTime = 0, .totalTime = 0, .averageDelayTime =0
    };
    ASSERT_NE(nullptr, audiopara.capture);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        int32_t ret = audiopara.capture->GetGainThreshold(audiopara.capture, &audiopara.character.gainthresholdmin,
                &audiopara.character.gainthresholdmax);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(audiopara.character.gainthresholdmin, GAIN_MIN);
        EXPECT_EQ(audiopara.character.gainthresholdmax, GAIN_MAX);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  AudioCaptureCheckSceneCapabilityPerformance_001
* @tc.devDesc  tests the performace of AudioCaptureCheckSceneCapability interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, AudioCaptureCheckSceneCapabilityPerformance_001,
         TestSize.Level1)
{
    struct PrepareAudioPara audiopara = {
        .capture = capture, .delayTime = 0, .totalTime = 0, .averageDelayTime =0
    };
    ASSERT_NE(nullptr, audiopara.capture);
    struct AudioSceneDescriptor scenes = { .scene.id = 0, .desc.pins = PIN_IN_MIC };
    bool supported = false;
    for (int i = 0; i < COUNT; ++i) {
        scenes.desc.desc = strdup("mic");
        gettimeofday(&audiopara.start, NULL);
        int32_t ret = audiopara.capture->CheckSceneCapability(audiopara.capture, &scenes, &supported);
        gettimeofday(&audiopara.end, NULL);
        free(scenes.desc.desc);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  AudioCaptureSelectScenePerformance_001
* @tc.devDesc  tests the performace of AudioCaptureSelectScene interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, AudioCaptureSelectScenePerformance_001, TestSize.Level1)
{
    struct PrepareAudioPara audiopara = {
        .capture = capture, .delayTime = 0, .totalTime = 0, .averageDelayTime =0
    };
    ASSERT_NE(nullptr, audiopara.capture);
    struct AudioSceneDescriptor scenes = { .scene.id = 0, .desc.pins = PIN_IN_MIC };
    for (int i = 0; i < COUNT; ++i) {
        scenes.desc.desc = strdup("mic");
        gettimeofday(&audiopara.start, NULL);
        int32_t ret = audiopara.capture->SelectScene(audiopara.capture, &scenes);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        free(scenes.desc.desc);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  AudioGetCapturePositionPerformance_001
* @tc.devDesc  tests the performace of AudioCaptureGetCapturePosition interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, AudioGetCapturePositionPerformance_001, TestSize.Level1)
{
    struct PrepareAudioPara audiopara = {
        .capture = capture, .delayTime = 0, .totalTime = 0, .averageDelayTime =0
    };
    ASSERT_NE(nullptr, audiopara.capture);
    int32_t ret = audiopara.capture->Start(audiopara.capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->GetCapturePosition(audiopara.capture, &audiopara.character.getframes, &audiopara.time);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  AudioCaptureSetExtraParamsPerformance_001
* @tc.desc  tests the performace of AudioCaptureSetExtraParams interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, AudioCaptureSetExtraParamsPerformance_001, TestSize.Level1)
{
    char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;attr-frame-count=82;attr-sampling-rate=48000";
    struct PrepareAudioPara audiopara = {
        .capture = capture, .delayTime = 0, .totalTime = 0, .averageDelayTime =0
    };
    ASSERT_NE(nullptr, audiopara.capture);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        int32_t ret = audiopara.capture->SetExtraParams(audiopara.capture, keyValueList);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  AudioCaptureGetExtraParamsPerformance_001
* @tc.desc  tests the performace of AudioCaptureGetExtraParams interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, AudioCaptureGetExtraParamsPerformance_001, TestSize.Level1)
{
    struct PrepareAudioPara audiopara = {
        .capture = capture, .delayTime = 0, .totalTime = 0, .averageDelayTime =0
    };
    ASSERT_NE(nullptr, audiopara.capture);
    char keyValueList[] = "attr-format=24;attr-frame-count=4096;";
    char keyValueListExp[] = "attr-route=0;attr-format=24;attr-channels=2;\
attr-frame-count=4096;attr-sampling-rate=48000";
    int32_t listLenth = 256;
    int32_t ret = audiopara.capture->SetExtraParams(audiopara.capture, keyValueList);
    EXPECT_EQ(HDF_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        char keyValueListValue[256] = {};
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->GetExtraParams(audiopara.capture, keyValueListValue, listLenth);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_STREQ(keyValueListExp, keyValueListValue);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  AudioCaptureGetMmapPositionPerformance_001
* @tc.desc  tests the performace of AudioCaptureGetMmapPosition interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, AudioCaptureGetMmapPositionPerformance_001, TestSize.Level1)
{
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct PrepareAudioPara audiopara = {
        .capture = capture, .delayTime = 0, .totalTime = 0, .averageDelayTime =0
    };
    ASSERT_NE(nullptr, audiopara.capture);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        int32_t ret = audiopara.capture->GetMmapPosition(audiopara.capture, &frames, &(audiopara.time));
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ((audiopara.time.tvSec) * SECTONSEC + (audiopara.time.tvNSec), timeExp);
        EXPECT_EQ(frames, INITIAL_VALUE);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}
}