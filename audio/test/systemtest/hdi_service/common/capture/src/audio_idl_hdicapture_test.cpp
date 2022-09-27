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
const int BUFFER_SIZE = 16384;
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
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

void AudioIdlHdiCaptureTest::TearDown(void)
{
    int32_t ret = ReleaseCaptureSource(manager, adapter, capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

/**
* @tc.name  AudioCaptureFrame_001
* @tc.desc  test AudioCaptureCaptureFrame interface,Returns 0 if the input data is read successfully
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureFrame_001, TestSize.Level1)
{
    int32_t ret;
    uint32_t replyBytes = BUFFER_SIZE;
    uint64_t requestBytes = BUFFER_SIZE;
    ASSERT_NE(nullptr, capture);
    ret = capture->Start(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    int8_t *frame = (int8_t *)calloc(1, BUFFER_SIZE);
    EXPECT_NE(nullptr, frame);
    ret = capture->CaptureFrame(capture, frame, &replyBytes, requestBytes);
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
    uint32_t replyBytes = BUFFER_SIZE;
    uint64_t requestBytes = BUFFER_SIZE;
    int8_t *frame = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = capture->Start(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->CaptureFrame(capture, frame, &replyBytes, requestBytes);
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
    uint64_t requestBytes = BUFFER_SIZE;
    uint32_t *replyBytes = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = capture->Start(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    int8_t *frame = (int8_t *)calloc(1, BUFFER_SIZE);
    EXPECT_NE(nullptr, frame);
    ret = capture->CaptureFrame(capture, frame, replyBytes, requestBytes);
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
    uint64_t requestBytes = BUFFER_SIZE;
    uint32_t replyBytes = BUFFER_SIZE;
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = capture->Start(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    int8_t *frame = (int8_t *)calloc(1, BUFFER_SIZE);
    EXPECT_NE(nullptr, frame);
    ret = capture->CaptureFrame(captureNull, frame, &replyBytes, requestBytes);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);

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
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureFrame_005, TestSize.Level1)
{
    int32_t ret;
    uint64_t requestBytes = BUFFER_SIZE;
    uint32_t replyBytes = BUFFER_SIZE;
    ASSERT_NE(nullptr, capture);
    int8_t *frame = (int8_t *)calloc(1, BUFFER_SIZE);
    EXPECT_NE(nullptr, frame);
    ret = capture->CaptureFrame(capture, frame, &replyBytes, requestBytes);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

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
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureFrame_006, TestSize.Level1)
{
    int32_t ret;
    uint64_t requestBytes = BUFFER_SIZE_LITTLE;
    uint32_t replyBytes = BUFFER_SIZE;

    ASSERT_NE(nullptr, capture);
    ret = capture->Start(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    int8_t *frame = (int8_t *)calloc(1, BUFFER_SIZE);
    EXPECT_NE(nullptr, frame);
    ret = capture->CaptureFrame(capture, frame, &replyBytes, requestBytes);
    EXPECT_EQ(HDF_FAILURE, ret);

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
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureGetCapturePosition_001, TestSize.Level1)
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
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
        EXPECT_GT(frames, INITIAL_VALUE);
    }

    ret = ThreadRelease(audiopara);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioCaptureGetCapturePosition_002
* @tc.desc   Test GetCapturePosition interface,Returns 0 if get Position after Pause and resume during playing
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureGetCapturePosition_002, TestSize.Level1)
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
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.capture->GetCapturePosition(audiopara.capture, &frames, &timeCount);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_GT((timeCount.tvSec) * SECTONSEC + (timeCount.tvNSec), timeExp);
        EXPECT_GT(frames, INITIAL_VALUE);
        ret = audiopara.capture->Resume(audiopara.capture);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.capture->GetCapturePosition(audiopara.capture, &frames, &timeCount);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_GT((timeCount.tvSec) * SECTONSEC + (timeCount.tvNSec), timeExp);
        EXPECT_GT(frames, INITIAL_VALUE);
    }

    ret = ThreadRelease(audiopara);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioCaptureGetCapturePosition_003
* @tc.desc  Test GetCapturePosition interface,Returns 0 if get CapturePosition after stop during playing
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureGetCapturePosition_003, TestSize.Level1)
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
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);
}
/**
* @tc.name  AudioCaptureGetCapturePosition_004
* @tc.desc  Test GetCapturePosition interface, return 0 if get CapturePosition after the object is created
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureGetCapturePosition_004, TestSize.Level1)
{
    int32_t ret;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    int64_t timeExp = 0;
    ASSERT_NE(nullptr, capture);
    ret = capture->GetCapturePosition(capture, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
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
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
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
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
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
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    capture->Stop(capture);
}
/**
* @tc.name  AudioCaptureGetCapturePosition_008
* @tc.desc  Test GetCapturePosition interface, return 0 if the GetCapturePosition was called twice
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureGetCapturePosition_008, TestSize.Level1)
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
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);
    ret = capture->GetCapturePosition(capture, &frames, &timeSec);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);
    capture->Stop(capture);
}
/**
* @tc.name  AudioCaptureReqMmapBuffer_001
* @tc.desc  Test ReqMmapBuffer interface,return 0 if call ReqMmapBuffer interface successfully
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureReqMmapBuffer_001, TestSize.Level1)
{
    bool isRender = false;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc = {};
    ASSERT_NE(nullptr, capture);
    int32_t ret = InitMmapDesc(AUDIO_LOW_LATENCY_CAPTURE_FILE, desc, reqSize, isRender);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Start(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->ReqMmapBuffer(capture, reqSize, &desc);
    EXPECT_EQ(HDF_SUCCESS, ret);
    if (ret == 0) {
        munmap(desc.memoryAddress, reqSize);
    }
    capture->Stop(capture);
}
/**
            the size of actual audio file
* @tc.name  AudioRenderReqMmapBuffer_002
* @tc.desc  Test ReqMmapBuffer interface,return -1 if call ReqMmapBuffer interface unsuccessful when setting the
            incoming parameter reqSize is bigger than the size of actual audio file
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureReqMmapBuffer_002, TestSize.Level1)
{
    int32_t ret;
    bool isRender = false;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc = {};
    ASSERT_NE(nullptr, capture);
    ret = InitMmapDesc(AUDIO_LOW_LATENCY_CAPTURE_FILE, desc, reqSize, isRender);
    EXPECT_EQ(HDF_SUCCESS, ret);
    reqSize = reqSize + BUFFER_LENTH;
    ret = capture->Start(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->ReqMmapBuffer(capture, reqSize, &desc);
    EXPECT_EQ(HDF_FAILURE, ret);
    capture->Stop(capture);
}
/**
            the size of actual audio file
* @tc.name  AudioCaptureReqMmapBuffer_003
* @tc.desc  Test ReqMmapBuffer interface,return 0 if call ReqMmapBuffer interface successfully when setting the
            incoming parameter reqSize is smaller than the size of actual audio file
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureReqMmapBuffer_003, TestSize.Level1)
{
    int32_t ret;
    bool isRender = false;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc = {};
    ASSERT_NE(nullptr, capture);
    ret = InitMmapDesc(AUDIO_LOW_LATENCY_CAPTURE_FILE, desc, reqSize, isRender);
    EXPECT_EQ(HDF_SUCCESS, ret);
    reqSize = reqSize / 2;
    ret = capture->Start(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->ReqMmapBuffer(capture, reqSize, &desc);
    EXPECT_EQ(HDF_SUCCESS, ret);
    if (ret == 0) {
        munmap(desc.memoryAddress, reqSize);
    }
    capture->Stop(capture);
}
/**
* @tc.name  AudioCaptureReqMmapBuffer_004
* @tc.desc  Test ReqMmapBuffer interface,return -1 if call ReqMmapBuffer interface unsuccessful when setting the
            incoming parameter reqSize is zero
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureReqMmapBuffer_004, TestSize.Level1)
{
    int32_t ret;
    bool isRender = false;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc = {};
    ASSERT_NE(nullptr, capture);
    ret = InitMmapDesc(AUDIO_LOW_LATENCY_CAPTURE_FILE, desc, reqSize, isRender);
    EXPECT_EQ(HDF_SUCCESS, ret);
    reqSize = 0;
    ret = capture->Start(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->ReqMmapBuffer(capture, reqSize, &desc);
    EXPECT_EQ(HDF_FAILURE, ret);
    capture->Stop(capture);
}
/**
* @tc.name  AudioCaptureReqMmapBuffer_005
* @tc.desc  Test ReqMmapBuffer interface,return -1 if call ReqMmapBuffer interface unsuccessful when setting the
            incoming parameter memoryFd  of desc is illegal
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureReqMmapBuffer_005, TestSize.Level1)
{
    bool isRender = false;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc = {};
    ASSERT_NE(nullptr, capture);
    int32_t ret = InitMmapDesc(AUDIO_LOW_LATENCY_CAPTURE_FILE, desc, reqSize, isRender);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Start(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(desc.filePath);
    desc.filePath = strdup("/audiotest/audio.wav");
    ret = capture->ReqMmapBuffer(capture, reqSize, &desc);
    EXPECT_EQ(HDF_FAILURE, ret);
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
    struct AudioMmapBufferDescripter desc = {};
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = InitMmapDesc(AUDIO_LOW_LATENCY_CAPTURE_FILE, desc, reqSize, isRender);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Start(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->ReqMmapBuffer(captureNull, reqSize, &desc);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    capture->Stop(capture);
}
/**
* @tc.name  AudioCaptureReqMmapBufferNull_007
* @tc.desc  Test ReqMmapBuffer interface,return -3 if call ReqMmapBuffer interface unsuccessful when setting the
            incoming parameter desc is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureReqMmapBufferNull_007, TestSize.Level1)
{
    int32_t ret;
    uint32_t reqSize = 0;
    struct AudioMmapBufferDescripter *descNull = nullptr;
    ASSERT_NE(nullptr, capture);
    reqSize = FILE_CAPTURE_SIZE;
    ret = capture->Start(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->ReqMmapBuffer(capture, reqSize, descNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    capture->Stop(capture);
}
/**
* @tc.name  AudioCaptureGetMmapPosition_001
* @tc.desc  Test GetMmapPosition interface,return 0 if Getting position successfully.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureTest, AudioCaptureGetMmapPosition_001, TestSize.Level1)
{
    int32_t ret;
    uint64_t frames = 0;
    uint64_t framesCapturing = 0;
    uint64_t framesExpCapture = 0;
    int64_t timeExp = 0;
    int64_t timeExpCaptureing = 0;
    ASSERT_NE(nullptr, capture);
    struct PrepareAudioPara audiopara = {
        .capture = capture, .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC,
        .path = AUDIO_LOW_LATENCY_CAPTURE_FILE.c_str()
    };

    ret = audiopara.capture->GetMmapPosition(audiopara.capture, &frames, &(audiopara.time));
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ((audiopara.time.tvSec) * SECTONSEC + (audiopara.time.tvNSec), timeExp);
    EXPECT_EQ(frames, INITIAL_VALUE);
    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)RecordMapAudio, &audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    sleep(1);
    ret = audiopara.capture->GetMmapPosition(audiopara.capture, &framesCapturing, &(audiopara.time));
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT((audiopara.time.tvSec) * SECTONSEC + (audiopara.time.tvNSec), timeExp);
    EXPECT_GT(framesCapturing, INITIAL_VALUE);
    timeExpCaptureing = (audiopara.time.tvSec) * SECTONSEC + (audiopara.time.tvNSec);
    void *result = nullptr;
    pthread_join(audiopara.tids, &result);
    EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
    ret = audiopara.capture->GetMmapPosition(audiopara.capture, &framesExpCapture, &(audiopara.time));
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT((audiopara.time.tvSec) * SECTONSEC + (audiopara.time.tvNSec), timeExpCaptureing);
    EXPECT_GT(framesExpCapture, framesCapturing);

    audiopara.capture->Stop(audiopara.capture);
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
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
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
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
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
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
}
