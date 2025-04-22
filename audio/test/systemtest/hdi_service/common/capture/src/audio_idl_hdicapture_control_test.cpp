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
class AudioIdlHdiCaptureControlTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    struct IAudioCapture *capture = nullptr;
    struct IAudioAdapter *adapter = nullptr;
    static TestAudioManager *manager;
    uint32_t captureId_ = 0;
};

TestAudioManager *AudioIdlHdiCaptureControlTest::manager = nullptr;
using THREAD_FUNC = void *(*)(void *);

void AudioIdlHdiCaptureControlTest::SetUpTestCase(void)
{
    manager = IAudioManagerGet(IS_STUB);
    ASSERT_NE(nullptr, manager);
}

void AudioIdlHdiCaptureControlTest::TearDownTestCase(void)
{
    if (manager != nullptr) {
        (void)IAudioManagerRelease(manager, IS_STUB);
    }
}

void AudioIdlHdiCaptureControlTest::SetUp(void)
{
    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture, &captureId_);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

void AudioIdlHdiCaptureControlTest::TearDown(void)
{
    int32_t ret = ReleaseCaptureSource(manager, adapter, capture, captureId_);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

/**
* @tc.name  AudioStartCapture_001
* @tc.desc  Test AudioCaptureStart interface,return 0 if the audiocapture object is started successfully
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, AudioCaptureStart_001, TestSize.Level0)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);
    ret = capture->Start(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    capture->Stop(capture);
}
/**
* @tc.name  AudioCaptureStartNull_002
* @tc.desc  Test CaptureStart interface,return -3/-4 if the incoming parameter handle is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, AudioCaptureStartNull_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = capture->Start(captureNull);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
    capture->Stop(capture);
}
/**
* @tc.name  AudioCaptureStart_003
* @tc.desc  Test AudioCaptureStart interface,return 0 if the Audiocapturestart was successfully called twice
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, AudioCaptureStart_003, TestSize.Level0)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);
    ret = capture->Start(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Start(capture);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_FAILURE);
    capture->Stop(capture);
}
/**
* @tc.name  AudioCaptureStop_001
* @tc.desc  Test AudioCaptureStop interface,return 0 if the audiocapture object is stopped successfully
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, AudioCaptureStop_001, TestSize.Level0)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioCaptureStop_002
* @tc.desc  Test AudioCaptureStop interface,return -2 if Audiocapturestop was successfully called twice
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, AudioCaptureStop_002, TestSize.Level0)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Stop(capture);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
}
/**
* @tc.name  AudioCaptureStop_003
* @tc.desc  Test AudioCaptureStop interface,return 0 if stop and start an audio capture successfully
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, AudioCaptureStop_003, TestSize.Level0)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Start(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    capture->Stop(capture);
}
/**
* @tc.name  AudioCaptureStop_004
* @tc.desc  Test AudioCaptureStop interface,return -2 if the capture does not start and stop only
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, AudioCaptureStop_004, TestSize.Level0)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);
    ret = capture->Stop(capture);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
}
/**
* @tc.name  AudioCaptureStopNull_005
* @tc.desc  Test CaptureStop interface, return -3/-4 if the incoming parameter handle is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, AudioCaptureStopNull_005, TestSize.Level1)
{
    int32_t ret = -1;
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Stop(captureNull);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
}
/**
* @tc.name  AudioCapturePause_001
* @tc.desc  test HDI CapturePause interface, return 0 if the capture is paused after start
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, AudioCapturePause_001, TestSize.Level0)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_FAILURE);
    ret = capture->Pause(capture);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioCapturePause_002
* @tc.desc  Test CapturePause interface, return -2 the second time if CapturePause is called twice
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, AudioCapturePause_002, TestSize.Level0)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Pause(capture);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = capture->Pause(capture);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioCapturePauseNull_003
* @tc.desc  Test CapturePause interface,return -3/-4 if the incoming parameter handle is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, AudioCapturePauseNull_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Pause(captureNull);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioCapturePause_004
* @tc.desc  Test AudioCapturePause interface,return -1 if the capture is not Started and paused only.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, AudioCapturePause_004, TestSize.Level0)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);
    ret = capture->Pause(capture);
    ASSERT_TRUE(ret == HDF_FAILURE || ret == HDF_ERR_NOT_SUPPORT);
}
/**
* @tc.name  AudioCapturePause_005
* @tc.desc  Test CapturePause interface, return -1 the capture is paused after stopped.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, AudioCapturePause_005, TestSize.Level0)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Pause(capture);
    ASSERT_TRUE(ret == HDF_FAILURE || ret == HDF_ERR_NOT_SUPPORT);
}
/**
* @tc.name  AudioCaptureResume_001
* @tc.desc  Test CaptureResume interface,return 0 if the capture is resumed after paused
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, AudioCaptureResume_001, TestSize.Level0)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Pause(capture);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = capture->Resume(capture);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioCaptureResume_002
* @tc.desc  Test CaptureResume interface,return -2 the second time if the CaptureResume is called twice
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, AudioCaptureResume_002, TestSize.Level0)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Pause(capture);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = capture->Resume(capture);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = capture->Resume(capture);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
* @tc.name  AudioCaptureResume_003
* @tc.desc  test HDI CaptureResume interface,return -2 if the capture is resumed after started
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, AudioCaptureResume_003, TestSize.Level0)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Resume(capture);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioCaptureResumeNull_004
* @tc.desc  Test CaptureResume interface, return -3/-4 if the incoming parameter handle is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, AudioCaptureResumeNull_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Pause(capture);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = capture->Resume(captureNull);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioCaptureResume_005
* @tc.desc  test HDI CaptureResume interface,return -2 if the capture is resumed after stopped
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, AudioCaptureResume_005, TestSize.Level0)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Resume(capture);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
}
/**
* @tc.name  AudioCaptureResume_006
* @tc.desc  test HDI CaptureResume interface,return -1 if the capture Continue to start after resume
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, AudioCaptureResume_006, TestSize.Level0)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Pause(capture);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = capture->Resume(capture);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = capture->Start(capture);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_FAILURE);
    capture->Stop(capture);
}

/**
* @tc.name  AudioCaptureFlush_001
* @tc.desc  Test CaptureFlush interface,return -2 if the data in the buffer is flushed successfully after stop
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, AudioCaptureFlush_001, TestSize.Level0)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Flush(capture);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
}
/**
* @tc.name  AudioCaptureFlushNull_002
* @tc.desc  Test CaptureFlush, return -3/-4 if the data in the buffer is flushed when handle is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, AudioCaptureFlushNull_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Flush(captureNull);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
}
/**
* @tc.name  AudioCaptureTurnStandbyMode_001
* @tc.desc    Test CaptureTurnStandbyMode interface,return 0 if the interface use correctly.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, AudioCaptureTurnStandbyMode_001, TestSize.Level0)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->TurnStandbyMode(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioCaptureTurnStandbyModeNull_002
* @tc.desc    Test CaptureTurnStandbyMode interface,return -3/-4 setting the incoming parameter self is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, AudioCaptureTurnStandbyModeNull_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct IAudioCapture *captureNull = nullptr;

    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_FAILURE);

    ret = capture->TurnStandbyMode(captureNull);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
    capture->Stop(capture);
}

/**
* @tc.name  AudioCaptureAudioDevDump_001
* @tc.desc    Test CaptureAudioDevDump interface,return 0 if the interface use correctly.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, AudioCaptureAudioDevDump_001, TestSize.Level0)
{
    int32_t ret = -1;
    char pathBuf[] = "./DevDump.log";
    ASSERT_NE(nullptr, capture);
    FILE *fp = fopen(pathBuf, "wb+");
    ASSERT_NE(nullptr, fp);
    int fd = fileno(fp);
    if (fd == -1) {
        fclose(fp);
        ASSERT_NE(fd, -1);
    }
    struct PrepareAudioPara audiopara = {
        .capture = capture, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .path = AUDIO_CAPTURE_FILE.c_str()
    };
    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)RecordAudio, &audiopara);
    if (ret < 0) {
        fclose(fp);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    sleep(1);
    ret = audiopara.capture->Pause(audiopara.capture);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = audiopara.capture->AudioDevDump(audiopara.capture, RANGE, fd);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    sleep(1);
    ret = audiopara.capture->Resume(audiopara.capture);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    fclose(fp);
    ret = ThreadRelease(audiopara);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
}
/**
* @tc.name  AudioCaptureAudioDevDump_002
* @tc.desc    Test CaptureAudioDevDump interface,return 0 if the interface use correctly.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, AudioCaptureAudioDevDump_002, TestSize.Level0)
{
    int32_t ret = -1;
    char path[] = "./DevDump.log";
    ASSERT_NE(nullptr, capture);
    FILE *file = fopen(path, "wb+");
    ASSERT_NE(nullptr, file);
    int fd = fileno(file);
    if (fd == -1) {
        fclose(file);
        ASSERT_NE(fd, -1);
    }
    struct PrepareAudioPara audiopara = {
        .capture = capture, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .path = AUDIO_CAPTURE_FILE.c_str()
    };
    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)RecordAudio, &audiopara);
    if (ret < 0) {
        fclose(file);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    sleep(1);
    ret = audiopara.capture->Pause(audiopara.capture);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = audiopara.capture->AudioDevDump(audiopara.capture, OUT_OF_RANGE-1, fd);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    sleep(1);
    ret = audiopara.capture->Resume(audiopara.capture);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    fclose(file);
    ret = ThreadRelease(audiopara);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
}

/**
* @tc.name  AudioCaptureAudioDevDump_003
* @tc.desc    Test CaptureAudioDevDump interface,return -3 if setting the incoming parameter range is out of range
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, AudioCaptureAudioDevDump_003, TestSize.Level0)
{
    int32_t ret = -1;
    char pathBuf[] = "./DevDump.log";
    ASSERT_NE(nullptr, capture);
    FILE *file = fopen(pathBuf, "wb+");
    ASSERT_NE(nullptr, file);
    int fd = fileno(file);
    if (fd == -1) {
        fclose(file);
        ASSERT_NE(fd, -1);
    }
    ret = capture->AudioDevDump(capture, RANGE-1, fd);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = capture->AudioDevDump(capture, OUT_OF_RANGE, fd);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    fclose(file);
}
/**
* @tc.name  AudioCaptureAudioDevDumpNull_004
* @tc.desc    Test CaptureAudioDevDump interface,return -3/-4 if setting the incoming parameter self is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, AudioCaptureAudioDevDumpNull_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct IAudioCapture *captureNull = nullptr;
    char pathBuf[] = "./DevDump.log";
    ASSERT_NE(nullptr, capture);
    FILE *fp = fopen(pathBuf, "wb+");
    ASSERT_NE(nullptr, fp);
    int fd = fileno(fp);
    if (fd == -1) {
        fclose(fp);
        ASSERT_NE(fd, -1);
    }
    ret = capture->AudioDevDump(captureNull, RANGE, fd);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
    fclose(fp);
}
/**
* @tc.name  AudioCaptureAudioDevDump_005
* @tc.desc    Test CaptureAudioDevDump interface,return -3 if setting the incoming parameter fd is illegal
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, AudioCaptureAudioDevDump_005, TestSize.Level0)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, capture);
    int fd = 3;
    ret = capture->AudioDevDump(capture, RANGE, fd);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
}
}
