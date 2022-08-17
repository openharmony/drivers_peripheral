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
class AudioIdlHdiCaptureControlTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    struct IAudioCapture *capture = nullptr;
    struct IAudioAdapter *adapter = nullptr;
    static TestGetAudioManager getAudioManager;
    static void *handle;
    static TestAudioManager *manager;
    static TestAudioManagerRelease managerRelease;
    static TestAudioCaptureRelease captureRelease;
    static TestAudioAdapterRelease adapterRelease;
};

using THREAD_FUNC = void *(*)(void *);
void *AudioIdlHdiCaptureControlTest::handle = nullptr;
TestGetAudioManager AudioIdlHdiCaptureControlTest::getAudioManager = nullptr;
TestAudioManager *AudioIdlHdiCaptureControlTest::manager = nullptr;
TestAudioManagerRelease AudioIdlHdiCaptureControlTest::managerRelease = nullptr;
TestAudioAdapterRelease AudioIdlHdiCaptureControlTest::adapterRelease = nullptr;
TestAudioCaptureRelease AudioIdlHdiCaptureControlTest::captureRelease = nullptr;

void AudioIdlHdiCaptureControlTest::SetUpTestCase(void)
{
    int32_t ret = LoadFuctionSymbol(handle, getAudioManager, managerRelease, adapterRelease);
    ASSERT_EQ(HDF_SUCCESS, ret);
    captureRelease = (TestAudioCaptureRelease)(dlsym(handle, "AudioCaptureRelease"));
    ASSERT_NE(nullptr, captureRelease);
    (void)HdfRemoteGetCallingPid();
    manager = getAudioManager(IDL_SERVER_NAME.c_str());
    ASSERT_NE(nullptr, manager);
}

void AudioIdlHdiCaptureControlTest::TearDownTestCase(void)
{
    if (managerRelease != nullptr && manager != nullptr) {
        (void)managerRelease(manager);
    }
    if (handle != nullptr) {
        (void)dlclose(handle);
    }
}

void AudioIdlHdiCaptureControlTest::SetUp(void)
{
    int32_t ret;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

void AudioIdlHdiCaptureControlTest::TearDown(void)
{
    int32_t ret = ReleaseCaptureSource(manager, adapter, capture, adapterRelease, captureRelease);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

/**
* @tc.name  Test AudioCaptureStart API via legal input
* @tc.number  SUB_Audio_HDI_StartCapture_001
* @tc.desc  Test AudioCaptureStart interface,return 0 if the audiocapture object is started successfully
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, SUB_Audio_HDI_CaptureStart_001, TestSize.Level1)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);
    ret = capture->Start(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    capture->Stop(capture);
}
/**
* @tc.name  Test CaptureStart API via setting the incoming parameter handle is nullptr
* @tc.number  SUB_Audio_HDI_CaptureStart_Null_002
* @tc.desc  Test CaptureStart interface,return -3/-4 if the incoming parameter handle is nullptr
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, SUB_Audio_HDI_CaptureStart_Null_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = capture->Start(captureNull);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    capture->Stop(capture);
}
/**
* @tc.name  Test AudioCaptureStart API via start two capture object continuously
* @tc.number  SUB_Audio_HDI_CaptureStart_003
* @tc.desc  Test AudioCaptureStart interface,return 0 if the Audiocapturestart was successfully called twice
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, SUB_Audio_HDI_CaptureStart_003, TestSize.Level1)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);
    ret = capture->Start(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Start(capture);
    EXPECT_EQ(AUDIO_HAL_ERR_AI_BUSY, ret);
    capture->Stop(capture);
}
/**
* @tc.name  Test AudioCaptureStop API via legal input
* @tc.number  SUB_Audio_HDI_CaptureStop_001
* @tc.desc  Test AudioCaptureStop interface,return 0 if the audiocapture object is stopped successfully
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, SUB_Audio_HDI_CaptureStop_001, TestSize.Level1)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  Test AudioCaptureStop API via stop two capture object continuously
* @tc.number  SUB_Audio_HDI_CaptureStop_002
* @tc.desc  Test AudioCaptureStop interface,return -2 if Audiocapturestop was successfully called twice
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, SUB_Audio_HDI_CaptureStop_002, TestSize.Level1)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
}
/**
* @tc.name  Test AudioCaptureStop API via start an audio capture after stopping
* @tc.number  SUB_Audio_HDI_CaptureStop_003
* @tc.desc  Test AudioCaptureStop interface,return 0 if stop and start an audio capture successfully
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, SUB_Audio_HDI_CaptureStop_003, TestSize.Level1)
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
* @tc.name  Test AudioCaptureStop API via the capture does not start and stop only
* @tc.number  SUB_Audio_HDI_CaptureStop_004
* @tc.desc  Test AudioCaptureStop interface,return -2 if the capture does not start and stop only
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, SUB_Audio_HDI_CaptureStop_004, TestSize.Level1)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);
    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
}
/**
* @tc.name Test CaptureStop API via setting the incoming parameter handle is nullptr
* @tc.number  SUB_Audio_HDI_CaptureStop_Null_005
* @tc.desc  Test CaptureStop interface, return -3/-4 if the incoming parameter handle is nullptr
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, SUB_Audio_HDI_CaptureStop_Null_005, TestSize.Level1)
{
    int32_t ret = -1;
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Stop(captureNull);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
* @tc.name  Test CapturePause API via legal input
* @tc.number  SUB_Audio_HDI_CapturePause_001
* @tc.desc  test HDI CapturePause interface, return 0 if the capture is paused after start
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, SUB_Audio_HDI_CapturePause_001, TestSize.Level1)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Pause(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  Test CapturePause API via the interface is called twice in a row
* @tc.number  SUB_Audio_HDI_CapturePause_002
* @tc.desc  Test CapturePause interface, return -2 the second time if CapturePause is called twice
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, SUB_Audio_HDI_CapturePause_002, TestSize.Level1)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Pause(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Pause(capture);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  Test CapturePause API via setting the incoming parameter handle is nullptr
* @tc.number  SUB_Audio_HDI_CapturePause_Null_003
* @tc.desc  Test CapturePause interface,return -3/-4 if the incoming parameter handle is nullptr
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, SUB_Audio_HDI_CapturePause_Null_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Pause(captureNull);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  Test CapturePause API via the capture is not Started and paused only.
* @tc.number  SUB_Audio_HDI_CapturePause_004
* @tc.desc  Test AudioCapturePause interface,return -1 if the capture is not Started and paused only.
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, SUB_Audio_HDI_CapturePause_004, TestSize.Level1)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);
    ret = capture->Pause(capture);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name  Test CapturePause API via the capture is paused after stopped.
* @tc.number  SUB_Audio_HDI_CapturePause_005
* @tc.desc  Test CapturePause interface, return -1 the capture is paused after stopped.
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, SUB_Audio_HDI_CapturePause_005, TestSize.Level1)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Pause(capture);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name  Test CaptureResume API via legal input
* @tc.number  SUB_Audio_HDI_CaptureResume_001
* @tc.desc  Test CaptureResume interface,return 0 if the capture is resumed after paused
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, SUB_Audio_HDI_CaptureResume_001, TestSize.Level1)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Pause(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Resume(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  Test CaptureResume API via the interface is called twice in a row
* @tc.number  SUB_Audio_HDI_CaptureResume_002
* @tc.desc  Test CaptureResume interface,return -2 the second time if the CaptureResume is called twice
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, SUB_Audio_HDI_CaptureResume_002, TestSize.Level1)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Pause(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Resume(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Resume(capture);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
* @tc.name  Test CaptureResume API via the capture is resumed after started
* @tc.number  SUB_Audio_HDI_CaptureResume_003
* @tc.desc  test HDI CaptureResume interface,return -2 if the capture is resumed after started
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, SUB_Audio_HDI_CaptureResume_003, TestSize.Level1)
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
* @tc.name  Test CaptureResume API via setting the incoming parameter handle is nullptr
* @tc.number  SUB_Audio_HDI_CaptureResume_Null_004
* @tc.desc  Test CaptureResume interface, return -3/-4 if the incoming parameter handle is nullptr
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, SUB_Audio_HDI_CaptureResume_Null_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Pause(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Resume(captureNull);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  Test CaptureResume API via the capture is resumed after stopped
* @tc.number  SUB_Audio_HDI_CaptureResume_005
* @tc.desc  test HDI CaptureResume interface,return -2 if the capture is resumed after stopped
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, SUB_Audio_HDI_CaptureResume_005, TestSize.Level1)
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
* @tc.name  Test CaptureResume API via the capture Continue to start after resume
* @tc.number  SUB_Audio_HDI_CaptureResume_006
* @tc.desc  test HDI CaptureResume interface,return -1 if the capture Continue to start after resume
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, SUB_Audio_HDI_CaptureResume_006, TestSize.Level1)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Pause(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Resume(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Start(capture);
    EXPECT_EQ(AUDIO_HAL_ERR_AI_BUSY, ret);
    capture->Stop(capture);
}

/**
* @tc.name  Test CaptureFlush API via legal input Verify that the data in the buffer is flushed after stop
* @tc.number  SUB_Audio_HDI_CaptureFlush_001
* @tc.desc  Test CaptureFlush interface,return -2 if the data in the buffer is flushed successfully after stop
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, SUB_Audio_HDI_CaptureFlush_001, TestSize.Level1)
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
* @tc.name  Test CaptureFlush that the data in the buffer is flushed when handle is nullptr
* @tc.number  SUB_Audio_HDI_CaptureFlush_Null_002
* @tc.desc  Test CaptureFlush, return -3/-4 if the data in the buffer is flushed when handle is nullptr
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, SUB_Audio_HDI_CaptureFlush_Null_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->Flush(captureNull);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
* @tc.name    Test CaptureTurnStandbyMode API
* @tc.number  SUB_Audio_HDI_CaptureTurnStandbyMode_001
* @tc.desc    Test CaptureTurnStandbyMode interface,return 0 if the interface use correctly.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, SUB_Audio_HDI_CaptureTurnStandbyMode_001, TestSize.Level1)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->TurnStandbyMode(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name    Test CaptureTurnStandbyMode API vai setting the incoming parameter self is nullptr
* @tc.number  SUB_Audio_HDI_CaptureTurnStandbyMode_Null_002
* @tc.desc    Test CaptureTurnStandbyMode interface,return -3/-4 setting the incoming parameter self is nullptr.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, SUB_Audio_HDI_CaptureTurnStandbyMode_Null_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct IAudioCapture *captureNull = nullptr;

    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->TurnStandbyMode(captureNull);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    capture->Stop(capture);
}

/**
* @tc.name    Test CaptureAudioDevDump API via
* @tc.number  SUB_Audio_HDI_CaptureAudioDevDump_001
* @tc.desc    Test CaptureAudioDevDump interface,return 0 if the interface use correctly.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, SUB_Audio_HDI_CaptureAudioDevDump_001, TestSize.Level1)
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
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.capture->AudioDevDump(audiopara.capture, RANGE, fd);
    EXPECT_EQ(HDF_SUCCESS, ret);
    sleep(1);
    ret = audiopara.capture->Resume(audiopara.capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    fclose(fp);
    ret = ThreadRelease(audiopara);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name    Test CaptureAudioDevDump API via
* @tc.number  SUB_Audio_HDI_CaptureAudioDevDump_002
* @tc.desc    Test CaptureAudioDevDump interface,return 0 if the interface use correctly.
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, SUB_Audio_HDI_CaptureAudioDevDump_002, TestSize.Level1)
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
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.capture->AudioDevDump(audiopara.capture, OUT_OF_RANGE-1, fd);
    EXPECT_EQ(HDF_SUCCESS, ret);
    sleep(1);
    ret = audiopara.capture->Resume(audiopara.capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    fclose(file);
    ret = ThreadRelease(audiopara);
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
* @tc.name    Test CaptureAudioDevDump API via setting the incoming parameter range is out of range
* @tc.number  SUB_Audio_HDI_CaptureAudioDevDump_003
* @tc.desc    Test CaptureAudioDevDump interface,return -3 if setting the incoming parameter range is out of range
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, SUB_Audio_HDI_CaptureAudioDevDump_003, TestSize.Level1)
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
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->AudioDevDump(capture, OUT_OF_RANGE, fd);
    EXPECT_EQ(HDF_SUCCESS, ret);
    fclose(file);
}
/**
* @tc.name    Test CaptureAudioDevDump API via setting the incoming parameter self is nullptr
* @tc.number  SUB_Audio_HDI_CaptureAudioDevDump_Null_004
* @tc.desc    Test CaptureAudioDevDump interface,return -3/-4 if setting the incoming parameter self is nullptr
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, SUB_Audio_HDI_CaptureAudioDevDump_Null_004, TestSize.Level1)
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
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    fclose(fp);
}
/**
* @tc.name    Test CaptureAudioDevDump API via setting the incoming parameter fd is illegal
* @tc.number  SUB_Audio_HDI_CaptureAudioDevDump_005
* @tc.desc    Test CaptureAudioDevDump interface,return -3 if setting the incoming parameter fd is illegal
* @tc.author: ZengLiFeng
*/
HWTEST_F(AudioIdlHdiCaptureControlTest, SUB_Audio_HDI_CaptureAudioDevDump_005, TestSize.Level1)
{
    int32_t ret = -1;

    ASSERT_NE(nullptr, capture);
    int fd = 3;
    ret = capture->AudioDevDump(capture, RANGE, fd);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
}
