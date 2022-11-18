/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
 * @brief Defines audio-related APIs, including custom data types and functions for capture drivers function.
 * accessing a driver adapter, and capturing audios.
 *
 * @since 1.0
 * @version 1.0
 */

/**
 * @file audio_hdi_common.h
 *
 * @brief Declares APIs for operations related to the capturing audio adapter.
 *
 * @since 1.0
 * @version 1.0
 */

#include "audio_hdi_common.h"
#include "audio_hdicapture_test.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
const int BUFFER_SIZE = 16384;
const int BUFFER_SIZE_LITTLE = 0;
const uint64_t FILESIZE = 1024;

class AudioHdiCaptureTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static TestAudioManager *manager;
};

using THREAD_FUNC = void *(*)(void *);
TestAudioManager *AudioHdiCaptureTest::manager = nullptr;

void AudioHdiCaptureTest::SetUpTestCase(void)
{
    manager = GetAudioManagerFuncs();
    ASSERT_NE(nullptr, manager);
}

void AudioHdiCaptureTest::TearDownTestCase(void) {}


void AudioHdiCaptureTest::SetUp(void) {}

void AudioHdiCaptureTest::TearDown(void) {}

/**
* @tc.name  AudioCaptureFrame_001
* @tc.desc  test AudioCaptureCaptureFrame interface,Returns 0 if the input data is read successfully
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureTest, AudioCaptureFrame_001, TestSize.Level1)
{
    uint64_t replyBytes = 0;
    uint64_t requestBytes = BUFFER_SIZE;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Start((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    char *frame = static_cast<char *>(calloc(1, BUFFER_SIZE));
    EXPECT_NE(nullptr, frame);
    ret = capture->CaptureFrame(capture, frame, requestBytes, &replyBytes);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}
/**
* @tc.name  AudioCaptureFrame_002
* @tc.desc  test AudioCaptureCaptureFrame interface,Returns -1 if the incoming parameter frame is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureTest, AudioCaptureFrame_002, TestSize.Level1)
{
    uint64_t replyBytes = 0;
    uint64_t requestBytes = BUFFER_SIZE;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    char *frame = nullptr;

    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Start((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->CaptureFrame(capture, frame, requestBytes, &replyBytes);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioCaptureFrame_003
* @tc.desc  test AudioCaptureCaptureFrame interface,Returns -1 if the incoming parameter replyBytes is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureTest, AudioCaptureFrame_003, TestSize.Level1)
{
    uint64_t requestBytes = BUFFER_SIZE;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    uint64_t *replyBytes = nullptr;

    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Start((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    char *frame = static_cast<char *>(calloc(1, BUFFER_SIZE));
    EXPECT_NE(nullptr, frame);
    ret = capture->CaptureFrame(capture, frame, requestBytes, replyBytes);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}
/**
* @tc.name  AudioCaptureFrame_004
* @tc.desc  test AudioCaptureCaptureFrame interface,Returns -1 if the incoming parameter capture is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureTest, AudioCaptureFrame_004, TestSize.Level1)
{
    uint64_t requestBytes = BUFFER_SIZE;
    uint64_t replyBytes = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;

    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Start((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    char *frame = static_cast<char *>(calloc(1, BUFFER_SIZE));
    EXPECT_NE(nullptr, frame);
    ret = capture->CaptureFrame(captureNull, frame, requestBytes, &replyBytes);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}
/**
* @tc.name  AudioCaptureFrame_005
* @tc.desc  Test AudioCaptureFrame interface,Returns -1 if without calling interface capturestart
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureTest, AudioCaptureFrame_005, TestSize.Level1)
{
    uint64_t requestBytes = BUFFER_SIZE;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    uint64_t replyBytes = 0;

    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    char *frame = static_cast<char *>(calloc(1, BUFFER_SIZE));
    EXPECT_NE(nullptr, frame);
    ret = capture->CaptureFrame(capture, frame, requestBytes, &replyBytes);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
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
HWTEST_F(AudioHdiCaptureTest, AudioCaptureFrame_006, TestSize.Level1)
{
    uint64_t requestBytes = BUFFER_SIZE_LITTLE;
    uint64_t replyBytes = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Start((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    char *frame = static_cast<char *>(calloc(1, BUFFER_SIZE));
    EXPECT_NE(nullptr, frame);
    ret = capture->CaptureFrame(capture, frame, requestBytes, &replyBytes);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
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
HWTEST_F(AudioHdiCaptureTest, AudioCaptureGetCapturePosition_001, TestSize.Level1)
{
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC,
        .path = AUDIO_CAPTURE_FILE.c_str(), .fileSize = FILESIZE
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);

    int32_t ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)RecordAudio, &audiopara);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    sleep(1);
    if (audiopara.capture != nullptr) {
        ret = audiopara.capture->GetCapturePosition(audiopara.capture, &frames, &time);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
        EXPECT_GT(frames, INITIAL_VALUE);
    }

    ret = ThreadRelease(audiopara);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
}
/**
* @tc.name  AudioCaptureGetCapturePosition_002
* @tc.desc   Test GetCapturePosition interface,Returns 0 if get Position after Pause and resume during playing
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureTest, AudioCaptureGetCapturePosition_002, TestSize.Level1)
{
    int64_t timeExp = 0;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC,
        .path = AUDIO_CAPTURE_FILE.c_str(), .fileSize = FILESIZE
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);

    int32_t ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)RecordAudio, &audiopara);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    sleep(1);
    if (audiopara.capture != nullptr) {
        ret = audiopara.capture->control.Pause((AudioHandle)(audiopara.capture));
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        ret = audiopara.capture->GetCapturePosition(audiopara.capture, &frames, &time);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
        EXPECT_GT(frames, INITIAL_VALUE);
        ret = audiopara.capture->control.Resume((AudioHandle)(audiopara.capture));
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        ret = audiopara.capture->GetCapturePosition(audiopara.capture, &frames, &time);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
        EXPECT_GT(frames, INITIAL_VALUE);
    }

    ret = ThreadRelease(audiopara);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
}
/**
* @tc.name  AudioCaptureGetCapturePosition_003
* @tc.desc  Test GetCapturePosition interface,Returns 0 if get CapturePosition after stop during playing
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureTest, AudioCaptureGetCapturePosition_003, TestSize.Level1)
{
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    int64_t timeExp = 0;

    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateStartCapture(manager, &capture, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->GetCapturePosition(capture, &frames, &time);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureGetCapturePosition_004
    * @tc.desc  Test GetCapturePosition interface, return 0 if get CapturePosition after the object is created
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureTest, AudioCaptureGetCapturePosition_004, TestSize.Level1)
{
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    int64_t timeExp = 0;

    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->GetCapturePosition(capture, &frames, &time);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureGetCapturePosition_005
    * @tc.desc  Test GetCapturePosition interface, return -1 if setting the parameter Capture is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureTest, AudioCaptureGetCapturePosition_005, TestSize.Level1)
{
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {};

    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateStartCapture(manager, &capture, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->GetCapturePosition(captureNull, &frames, &time);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureGetCapturePosition_006
    * @tc.desc  Test GetCapturePosition interface, return -1 if setting the parameter frames is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureTest, AudioCaptureGetCapturePosition_006, TestSize.Level1)
{
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    uint64_t *framesNull = nullptr;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};

    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateStartCapture(manager, &capture, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->GetCapturePosition(capture, framesNull, &time);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureGetCapturePosition_007
    * @tc.desc  Test GetCapturePosition interface, return -1 if setting the parameter time is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureTest, AudioCaptureGetCapturePosition_007, TestSize.Level1)
{
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    uint64_t frames = 0;
    struct AudioTimeStamp *timeNull = nullptr;

    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateStartCapture(manager, &capture, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->GetCapturePosition(capture, &frames, timeNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureGetCapturePosition_008
    * @tc.desc  Test GetCapturePosition interface, return 0 if the GetCapturePosition was called twice
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureTest, AudioCaptureGetCapturePosition_008, TestSize.Level1)
{
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    struct AudioTimeStamp timeSec = {.tvSec = 0, .tvNSec = 0};
    int64_t timeExp = 0;

    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateStartCapture(manager, &capture, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->GetCapturePosition(capture, &frames, &time);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);
    ret = capture->GetCapturePosition(capture, &frames, &timeSec);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioCaptureReqMmapBuffer_001
* @tc.desc  Test ReqMmapBuffer interface,return 0 if call ReqMmapBuffer interface successfully
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureTest, AudioCaptureReqMmapBuffer_001, TestSize.Level1)
{
    bool isRender = false;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc = {};
    struct AudioCapture *capture = nullptr;
    struct AudioAdapter *adapter = nullptr;
    ASSERT_NE(nullptr, manager);
    FILE *fp = fopen(AUDIO_LOW_LATENCY_CAPTURE_FILE.c_str(), "wb+");
    ASSERT_NE(nullptr, fp);
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    if (ret < 0 || capture == nullptr) {
        fclose(fp);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ASSERT_EQ(nullptr, capture);
    }
    ret = InitMmapDesc(fp, desc, reqSize, isRender);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret =  capture->control.Start((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret =  capture->attr.ReqMmapBuffer((AudioHandle)capture, reqSize, &desc);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    fclose(fp);
    if (ret == 0) {
        munmap(desc.memoryAddress, reqSize);
    }
    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioRenderReqMmapBuffer_002
* @tc.desc  Test ReqMmapBuffer interface,return -3 if call ReqMmapBuffer interface unsuccessful when setting the
            incoming parameter reqSize is bigger than the size of actual audio file
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureTest, AudioCaptureReqMmapBuffer_002, TestSize.Level1)
{
    bool isRender = false;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc = {};
    struct AudioCapture *capture = nullptr;
    struct AudioAdapter *adapter = nullptr;
    ASSERT_NE(nullptr, manager);
    FILE *fp = fopen(AUDIO_LOW_LATENCY_CAPTURE_FILE.c_str(), "wb+");
    ASSERT_NE(nullptr, fp);
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    if (ret < 0 || capture == nullptr) {
        fclose(fp);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ASSERT_EQ(nullptr, capture);
    }
    ret = InitMmapDesc(fp, desc, reqSize, isRender);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    reqSize = reqSize + BUFFER_LENTH;
    ret =  capture->control.Start((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret =  capture->attr.ReqMmapBuffer((AudioHandle)capture, reqSize, &desc);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    fclose(fp);
    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioCaptureReqMmapBuffer_003
* @tc.desc  Test ReqMmapBuffer interface,return 0 if call ReqMmapBuffer interface successfully when setting the
            incoming parameter reqSize is smaller than the size of actual audio file
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureTest, AudioCaptureReqMmapBuffer_003, TestSize.Level1)
{
    bool isRender = false;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc = {};
    struct AudioCapture *capture = nullptr;
    struct AudioAdapter *adapter = nullptr;
    ASSERT_NE(nullptr, manager);
    FILE *fp = fopen(AUDIO_LOW_LATENCY_CAPTURE_FILE.c_str(), "wb+");
    ASSERT_NE(nullptr, fp);
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    if (ret < 0 || capture == nullptr) {
        fclose(fp);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ASSERT_EQ(nullptr, capture);
    }
    ret = InitMmapDesc(fp, desc, reqSize, isRender);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    reqSize = reqSize / 2;
    ret =  capture->control.Start((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret =  capture->attr.ReqMmapBuffer((AudioHandle)capture, reqSize, &desc);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    fclose(fp);
    if (ret == 0) {
        munmap(desc.memoryAddress, reqSize);
    }
    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioCaptureReqMmapBuffer_004
* @tc.desc  Test ReqMmapBuffer interface,return -1 if call ReqMmapBuffer interface unsuccessful when setting the
            incoming parameter reqSize is zero
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureTest, AudioCaptureReqMmapBuffer_004, TestSize.Level1)
{
    bool isRender = false;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc = {};
    struct AudioCapture *capture = nullptr;
    struct AudioAdapter *adapter = nullptr;
    ASSERT_NE(nullptr, manager);
    FILE *fp = fopen(AUDIO_LOW_LATENCY_CAPTURE_FILE.c_str(), "wb+");
    ASSERT_NE(nullptr, fp);
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    if (ret < 0 || capture == nullptr) {
        fclose(fp);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ASSERT_EQ(nullptr, capture);
    }
    ret = InitMmapDesc(fp, desc, reqSize, isRender);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    reqSize = 0;
    ret =  capture->control.Start((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret =  capture->attr.ReqMmapBuffer((AudioHandle)capture, reqSize, &desc);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
    fclose(fp);
    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioCaptureReqMmapBuffer_005
* @tc.desc  Test ReqMmapBuffer interface,return -3 if call ReqMmapBuffer interface unsuccessful when setting the
            incoming parameter memoryFd  of desc is illegal
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureTest, AudioCaptureReqMmapBuffer_005, TestSize.Level1)
{
    bool isRender = false;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc = {};
    struct AudioCapture *capture = nullptr;
    struct AudioAdapter *adapter = nullptr;
    ASSERT_NE(nullptr, manager);
    FILE *fp = fopen(AUDIO_LOW_LATENCY_CAPTURE_FILE.c_str(), "wb+");
    ASSERT_NE(nullptr, fp);
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    if (ret < 0 || capture == nullptr) {
        fclose(fp);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ASSERT_EQ(nullptr, capture);
    }
    ret = InitMmapDesc(fp, desc, reqSize, isRender);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    desc.memoryFd = -1; // -1 is invalid fd
    ret =  capture->control.Start((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret =  capture->attr.ReqMmapBuffer((AudioHandle)capture, reqSize, &desc);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
    fclose(fp);
    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioCaptureReqMmapBuffer_006
* @tc.desc  Test ReqMmapBuffer interface,return -3 if call ReqMmapBuffer interface unsuccessful when setting the
            incoming parameter handle is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureTest, AudioCaptureReqMmapBuffer_006, TestSize.Level1)
{
    bool isRender = false;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc = {};
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;
    struct AudioAdapter *adapter = nullptr;
    ASSERT_NE(nullptr, manager);
    FILE *fp = fopen(AUDIO_LOW_LATENCY_CAPTURE_FILE.c_str(), "wb+");
    ASSERT_NE(nullptr, fp);
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    if (ret < 0 || capture == nullptr) {
        fclose(fp);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ASSERT_EQ(nullptr, capture);
    }
    ret = InitMmapDesc(fp, desc, reqSize, isRender);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret =  capture->control.Start((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret =  capture->attr.ReqMmapBuffer((AudioHandle)captureNull, reqSize, &desc);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    fclose(fp);
    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioCaptureReqMmapBuffer_007
* @tc.desc  Test ReqMmapBuffer interface,return -3 if call ReqMmapBuffer interface unsuccessful when setting the
            incoming parameter desc is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureTest, AudioCaptureReqMmapBuffer_007, TestSize.Level1)
{
    uint32_t reqSize = 0;
    struct AudioMmapBufferDescripter *descNull = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioAdapter *adapter = nullptr;
    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    if (ret < 0 || capture == nullptr) {
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ASSERT_EQ(nullptr, capture);
    }
    reqSize = FILE_CAPTURE_SIZE;
    ret =  capture->control.Start((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret =  capture->attr.ReqMmapBuffer((AudioHandle)capture, reqSize, descNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioCaptureGetMmapPosition_001
* @tc.desc  Test GetMmapPosition interface,return 0 if Getting position successfully.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureTest, AudioCaptureGetMmapPosition_001, TestSize.Level1)
{
    uint64_t frames = 0;
    uint64_t framesCapturing = 0;
    uint64_t framesExpCapture = 0;
    int64_t timeExp = 0;
    int64_t timeExpCaptureing = 0;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC,
        .path = AUDIO_LOW_LATENCY_CAPTURE_FILE.c_str()
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    int32_t ret = AudioCreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                             &audiopara.capture);
    if (ret < 0 || audiopara.capture == nullptr) {
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ASSERT_EQ(nullptr, audiopara.capture);
    }
    ret = audiopara.capture->attr.GetMmapPosition(audiopara.capture, &frames, &(audiopara.time));
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ((audiopara.time.tvSec) * SECTONSEC + (audiopara.time.tvNSec), timeExp);
    EXPECT_EQ(frames, INITIAL_VALUE);
    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)RecordMapAudio, &audiopara);
    if (ret != 0) {
        audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    sleep(1);
    ret = audiopara.capture->attr.GetMmapPosition(audiopara.capture, &framesCapturing, &(audiopara.time));
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT((audiopara.time.tvSec) * SECTONSEC + (audiopara.time.tvNSec), timeExp);
    EXPECT_GT(framesCapturing, INITIAL_VALUE);
    timeExpCaptureing = (audiopara.time.tvSec) * SECTONSEC + (audiopara.time.tvNSec);
    void *result = nullptr;
    pthread_join(audiopara.tids, &result);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
    ret = audiopara.capture->attr.GetMmapPosition(audiopara.capture, &framesExpCapture, &(audiopara.time));
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT((audiopara.time.tvSec) * SECTONSEC + (audiopara.time.tvNSec), timeExpCaptureing);
    EXPECT_GT(framesExpCapture, framesCapturing);

    audiopara.capture->control.Stop((AudioHandle)audiopara.capture);
    audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  AudioCaptureGetMmapPosition_003
* @tc.desc  Test GetMmapPosition interface,return -3 if Error in incoming parameter.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureTest, AudioCaptureGetMmapPosition_003, TestSize.Level1)
{
    uint64_t *frames = nullptr;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC,
        .path = AUDIO_LOW_LATENCY_CAPTURE_FILE.c_str()
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    int32_t ret = AudioCreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                             &audiopara.capture);
    if (ret < 0 || audiopara.capture == nullptr) {
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ASSERT_EQ(nullptr, audiopara.capture);
    }

    ret = audiopara.capture->attr.GetMmapPosition(audiopara.capture, frames, &(audiopara.time));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  AudioCaptureGetMmapPosition_004
* @tc.desc  Test GetMmapPosition interface,return -3 if Error in incoming parameter.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureTest, AudioCaptureGetMmapPosition_004, TestSize.Level1)
{
    uint64_t frames = 0;
    struct AudioTimeStamp *time = nullptr;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC,
        .path = AUDIO_LOW_LATENCY_CAPTURE_FILE.c_str()
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    int32_t ret = AudioCreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                             &audiopara.capture);
    if (ret < 0 || audiopara.capture == nullptr) {
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ASSERT_EQ(nullptr, audiopara.capture);
    }

    ret = audiopara.capture->attr.GetMmapPosition(audiopara.capture, &frames, time);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  AudioRenderReqMmapBuffer_005
* @tc.desc  Test GetMmapPosition interface,return -3 if Error in incoming parameter.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureTest, AudioCaptureGetMmapPosition_005, TestSize.Level1)
{
    uint64_t frames = 0;
    struct AudioCapture *captureNull = nullptr;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC,
        .path = AUDIO_LOW_LATENCY_CAPTURE_FILE.c_str()
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);
    int32_t ret = AudioCreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                             &audiopara.capture);
    if (ret < 0 || audiopara.capture == nullptr) {
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ASSERT_EQ(nullptr, audiopara.capture);
    }

    ret = audiopara.capture->attr.GetMmapPosition(captureNull, &frames, &(audiopara.time));
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
}
