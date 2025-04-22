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
const int BUFFER_SIZE_LITTLE = 0;
const uint64_t FILESIZE = 1024;

class AudioIdlHdiCaptureTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioCapture *capture = nullptr;
    static TestAudioManager *manager;
    uint32_t captureId_ = 0;
};

TestAudioManager *AudioIdlHdiCaptureTest::manager = nullptr;
using THREAD_FUNC = void *(*)(void *);

void AudioIdlHdiCaptureTest::SetUpTestCase(void)
{
    manager = IAudioManagerGet(IS_STUB);
    ASSERT_NE(nullptr, manager);
}

void AudioIdlHdiCaptureTest::TearDownTestCase(void)
{
    if (manager != nullptr) {
        (void)IAudioManagerRelease(manager, IS_STUB);
    }
}

void AudioIdlHdiCaptureTest::SetUp(void)
{
    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture, &captureId_);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

void AudioIdlHdiCaptureTest::TearDown(void)
{
    int32_t ret = ReleaseCaptureSource(manager, adapter, capture, captureId_);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

/**
* @tc.name  AudioCaptureFrame_001
* @tc.desc  test AudioCaptureCaptureFrame interface,Returns 0 if the input data is read successfully
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureFrame_001, TestSize.Level0)
{
    int32_t ret;
    uint32_t replyBytes = 0;
    uint64_t requestBytes = 0;
    uint32_t bufferSize = 0;
    ASSERT_NE(nullptr, capture);
    ret = GetCaptureBufferSize(capture, bufferSize);
    EXPECT_EQ(HDF_SUCCESS, ret);
    replyBytes = bufferSize;
    requestBytes = bufferSize;
    ret = capture->Start(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    int8_t *frame = (int8_t *)calloc(1, bufferSize);
    EXPECT_NE(nullptr, frame);
    ret = capture->CaptureFrame(capture, frame, &replyBytes, &requestBytes);
    EXPECT_EQ(HDF_SUCCESS, ret);
    capture->Stop(capture);

    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}
/**
* @tc.name  AudioCaptureFrameNull_002
* @tc.desc  test AudioCaptureCaptureFrame interface,Returns -3 if the incoming parameter frame is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureFrameNull_002, TestSize.Level1)
{
    int32_t ret;
    uint32_t replyBytes = 0;
    uint64_t requestBytes = 0;
    int8_t *frame = nullptr;
    uint32_t bufferSize = 0;
    ASSERT_NE(nullptr, capture);
    ret = GetCaptureBufferSize(capture, bufferSize);
    EXPECT_EQ(HDF_SUCCESS, ret);
    replyBytes = bufferSize;
    requestBytes = bufferSize;
    ret = capture->Start(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->CaptureFrame(capture, frame, &replyBytes, &requestBytes);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    capture->Stop(capture);
}
#ifdef AUDIO_ADM_PASSTHROUGH
/**
* @tc.name  AudioCaptureFrameNull_003
* @tc.desc  test AudioCaptureCaptureFrame interface,Returns -3 if the incoming parameter replyBytes is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureFrameNull_003, TestSize.Level1)
{
    int32_t ret;
    uint64_t requestBytes = 0;
    uint32_t *replyBytes = nullptr;
    uint32_t bufferSize = 0;
    ASSERT_NE(nullptr, capture);
    ret = GetCaptureBufferSize(capture, bufferSize);
    EXPECT_EQ(HDF_SUCCESS, ret);
    requestBytes = bufferSize;
    ret = capture->Start(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    int8_t *frame = (int8_t *)calloc(1, bufferSize);
    EXPECT_NE(nullptr, frame);
    ret = capture->CaptureFrame(capture, frame, replyBytes, &requestBytes);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    capture->Stop(capture);

    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}
#endif
/**
* @tc.name  AudioCaptureFrameNull_004
* @tc.desc  test AudioCaptureCaptureFrame interface,Returns -3/-4 if the incoming parameter capture is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureFrameNull_004, TestSize.Level1)
{
    int32_t ret;
    uint64_t requestBytes = 0;
    uint32_t replyBytes = 0;
    struct IAudioCapture *captureNull = nullptr;
    uint32_t bufferSize = 0;
    ASSERT_NE(nullptr, capture);
    ret = GetCaptureBufferSize(capture, bufferSize);
    EXPECT_EQ(HDF_SUCCESS, ret);
    replyBytes = bufferSize;
    requestBytes = bufferSize;
    ret = capture->Start(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    int8_t *frame = (int8_t *)calloc(1, bufferSize);
    EXPECT_NE(nullptr, frame);
    ret = capture->CaptureFrame(captureNull, frame, &replyBytes, &requestBytes);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);

    capture->Stop(capture);

    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}
/**
* @tc.name  AudioCaptureFrame_005
* @tc.desc  Test AudioCaptureFrame interface,Returns -3 if without calling interface capturestart
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureFrame_005, TestSize.Level0)
{
    int32_t ret;
    uint64_t requestBytes = 0;
    uint32_t replyBytes = 0;
    uint32_t bufferSize = 0;
    ASSERT_NE(nullptr, capture);
    ret = GetCaptureBufferSize(capture, bufferSize);
    EXPECT_EQ(HDF_SUCCESS, ret);
    replyBytes = bufferSize;
    requestBytes = bufferSize;
    int8_t *frame = (int8_t *)calloc(1, bufferSize);
    EXPECT_NE(nullptr, frame);
    ret = capture->CaptureFrame(capture, frame, &replyBytes, &requestBytes);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_SUCCESS);

    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}
/**
    less than interface requirements
* @tc.name  AudioCaptureFrame_006
* @tc.desc  test AudioCaptureCaptureFrame interface,Returns -1 if the incoming parameter
    requestBytes less than interface requirements
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureFrame_006, TestSize.Level0)
{
    int32_t ret;
    uint64_t requestBytes = BUFFER_SIZE_LITTLE;
    uint32_t replyBytes = 0;

    uint32_t bufferSize = 0;
    ASSERT_NE(nullptr, capture);
    ret = GetCaptureBufferSize(capture, bufferSize);
    EXPECT_EQ(HDF_SUCCESS, ret);
    replyBytes = bufferSize;
    ret = capture->Start(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    int8_t *frame = (int8_t *)calloc(1, bufferSize);
    EXPECT_NE(nullptr, frame);
    ret = capture->CaptureFrame(capture, frame, &replyBytes, &requestBytes);
    EXPECT_EQ(HDF_SUCCESS, ret);

    capture->Stop(capture);

    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}
/**
* @tc.name  AudioCaptureGetCapturePosition_001
* @tc.desc  Test AudioCaptureGetCapturePosition interface,Returns 0 if get CapturePosition during playing.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureGetCapturePosition_001, TestSize.Level0)
{
    int32_t ret;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    ASSERT_NE(nullptr, capture);
    struct PrepareAudioPara audiopara = {
        .capture = capture, .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC,
        .path = AUDIO_CAPTURE_FILE.c_str(), .fileSize = FILESIZE
    };

    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)RecordAudio, &audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);
    sleep(1);
    if (audiopara.capture != nullptr) {
        ret = audiopara.capture->GetCapturePosition(audiopara.capture, &frames, &time);
        if (ret == HDF_SUCCESS) {
            EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
            EXPECT_GT(frames, INITIAL_VALUE);
        }
    }

    ret = ThreadRelease(audiopara);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
}
/**
* @tc.name  AudioCaptureGetCapturePosition_002
* @tc.desc   Test GetCapturePosition interface,Returns 0 if get Position after Pause and resume during playing
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureGetCapturePosition_002, TestSize.Level0)
{
    int32_t ret;
    int64_t timeExp = 0;
    uint64_t frames = 0;
    struct AudioTimeStamp timeCount = {.tvSec = 0, .tvNSec = 0};
    ASSERT_NE(nullptr, capture);
    struct PrepareAudioPara audiopara = {
        .capture = capture, .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC,
        .path = AUDIO_CAPTURE_FILE.c_str(), .fileSize = FILESIZE
    };

    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)RecordAudio, &audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);
    sleep(1);
    if (audiopara.capture != nullptr) {
        ret = audiopara.capture->Pause(audiopara.capture);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
        ret = audiopara.capture->GetCapturePosition(audiopara.capture, &frames, &timeCount);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
        if (ret == HDF_SUCCESS) {
            EXPECT_GT((timeCount.tvSec) * SECTONSEC + (timeCount.tvNSec), timeExp);
            EXPECT_GT(frames, INITIAL_VALUE);
        }

        ret = audiopara.capture->Resume(audiopara.capture);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
        ret = audiopara.capture->GetCapturePosition(audiopara.capture, &frames, &timeCount);
        ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
        if (ret == HDF_SUCCESS) {
            EXPECT_GT((timeCount.tvSec) * SECTONSEC + (timeCount.tvNSec), timeExp);
            EXPECT_GT(frames, INITIAL_VALUE);
        }
    }

    ret = ThreadRelease(audiopara);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
}
/**
* @tc.name  AudioCaptureGetCapturePosition_003
* @tc.desc  Test GetCapturePosition interface,Returns 0 if get CapturePosition after stop during playing
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureGetCapturePosition_003, TestSize.Level0)
{
    int32_t ret;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    int64_t timeExp = 0;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetCapturePosition(capture, &frames, &time);
    if (ret == HDF_SUCCESS) {
        EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
        EXPECT_GT(frames, INITIAL_VALUE);
    }
}
/**
* @tc.name  AudioCaptureGetCapturePosition_004
* @tc.desc  Test GetCapturePosition interface, return 0 if get CapturePosition after the object is created
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureGetCapturePosition_004, TestSize.Level0)
{
    int32_t ret;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    int64_t timeExp = 0;
    ASSERT_NE(nullptr, capture);
    ret = capture->GetCapturePosition(capture, &frames, &time);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    EXPECT_EQ((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
}
/**
* @tc.name  AudioCaptureGetCapturePositionNull_005
* @tc.desc  Test GetCapturePosition interface, return -3/-4 if setting the parameter Capture is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureGetCapturePositionNull_005, TestSize.Level1)
{
    int32_t ret;
    struct IAudioCapture *captureNull = nullptr;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {};
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetCapturePosition(captureNull, &frames, &time);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
    capture->Stop(capture);
}
/**
* @tc.name  AudioCaptureGetCapturePositionNull_006
* @tc.desc  Test GetCapturePosition interface, return -3 if setting the parameter frames is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureGetCapturePositionNull_006, TestSize.Level1)
{
    int32_t ret;
    uint64_t *framesNull = nullptr;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetCapturePosition(capture, framesNull, &time);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_NOT_SUPPORT);
    capture->Stop(capture);
}
/**
* @tc.name  AudioCaptureGetCapturePositionNull_007
* @tc.desc  Test GetCapturePosition interface, return -3 if setting the parameter time is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureGetCapturePositionNull_007, TestSize.Level1)
{
    int32_t ret;
    uint64_t frames = 0;
    struct AudioTimeStamp *timeNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetCapturePosition(capture, &frames, timeNull);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_NOT_SUPPORT);
    capture->Stop(capture);
}
/**
* @tc.name  AudioCaptureGetCapturePosition_008
* @tc.desc  Test GetCapturePosition interface, return 0 if the GetCapturePosition was called twice
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureGetCapturePosition_008, TestSize.Level0)
{
    int32_t ret;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    struct AudioTimeStamp timeSec = {.tvSec = 0, .tvNSec = 0};
    int64_t timeExp = 0;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetCapturePosition(capture, &frames, &time);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    if (ret == HDF_SUCCESS) {
        EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
        EXPECT_GT(frames, INITIAL_VALUE);
    }
    ret = capture->GetCapturePosition(capture, &frames, &timeSec);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    if (ret == HDF_SUCCESS) {
        EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
        EXPECT_GT(frames, INITIAL_VALUE);
    }
    capture->Stop(capture);
}

/**
* @tc.name  AudioCaptureReqMmapBufferNull_006
* @tc.desc  Test ReqMmapBuffer interface,return -3/-4 if call ReqMmapBuffer interface unsuccessful when setting the
            incoming parameter handle is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureReqMmapBufferNull_006, TestSize.Level1)
{
    int32_t ret;
    bool isRender = false;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescriptor desc = {};
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = InitMmapDesc(AUDIO_LOW_LATENCY_CAPTURE_FILE, desc, reqSize, isRender);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Start(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->ReqMmapBuffer(captureNull, reqSize, &desc);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
    capture->Stop(capture);
}

/**
* @tc.name  AudioCaptureGetMmapPositionNull_003
* @tc.desc  Test GetMmapPosition interface,return -3 if Error in incoming parameter.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureGetMmapPositionNull_003, TestSize.Level1)
{
    int32_t ret;
    uint64_t *frames = nullptr;
    ASSERT_NE(nullptr, capture);
    struct PrepareAudioPara audiopara = {
        .capture = capture, .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC,
        .path = AUDIO_LOW_LATENCY_CAPTURE_FILE.c_str()
    };

    ret = audiopara.capture->GetMmapPosition(audiopara.capture, frames, &(audiopara.time));
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_NOT_SUPPORT);
}
/**
* @tc.name  AudioCaptureGetMmapPositionNull_004
* @tc.desc  Test GetMmapPosition interface,return -3 if Error in incoming parameter.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureGetMmapPositionNull_004, TestSize.Level1)
{
    int32_t ret;
    uint64_t frames = 0;
    struct AudioTimeStamp *time = nullptr;
    ASSERT_NE(nullptr, capture);
    struct PrepareAudioPara audiopara = {
        .capture = capture, .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC,
        .path = AUDIO_LOW_LATENCY_CAPTURE_FILE.c_str()
    };

    ret = audiopara.capture->GetMmapPosition(audiopara.capture, &frames, time);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_NOT_SUPPORT);
}
/**
* @tc.name  AudioCaptureGetMmapPositionNull_005
* @tc.desc  Test GetMmapPosition interface,return -3/-4 if Error in incoming parameter.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureGetMmapPositionNull_005, TestSize.Level1)
{
    int32_t ret;
    uint64_t frames = 0;
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    struct PrepareAudioPara audiopara = {
        .capture = capture, .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC,
        .path = AUDIO_LOW_LATENCY_CAPTURE_FILE.c_str()
    };

    ret = audiopara.capture->GetMmapPosition(captureNull, &frames, &(audiopara.time));
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
}
}
