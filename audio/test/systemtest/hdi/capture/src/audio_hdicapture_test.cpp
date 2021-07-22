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
 * @brief Defines audio-related APIs, including custom data types and functions for capture drivers funtion.
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
using namespace HMOS::Audio;

namespace {
const string AUDIO_CAPTURE_FILE = "//bin/audiocapturetest.wav";
const string ADAPTER_NAME = "hdmi";
const string ADAPTER_NAME2 = "usb";
const string ADAPTER_NAME3 = "internal";
const int BUFFER_SIZE = 16384;
const int BUFFER_SIZE_LITTLE = 0;
const uint64_t FILESIZE = 2048;

class AudioHdiCaptureTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    struct AudioManager *(*GetAudioManager)() = nullptr;
    void *handleSo = nullptr;
    int32_t GetLoadAdapter(struct AudioManager manager, enum AudioPortDirection portType,
                           const string adapterName, struct AudioAdapter **adapter, struct AudioPort& audioPort) const;
    int32_t AudioCreateCapture(enum AudioPortPin pins, struct AudioManager manager,
                               struct AudioPort capturePort, struct AudioAdapter *adapter,
                               struct AudioCapture **capture) const;
    int32_t AudioCaptureStart(const string path, struct AudioCapture *capture) const;
    static int32_t GetLoadAdapterAudioPara(struct PrepareAudioPara& audiopara);
    static int32_t RecordAudio(struct PrepareAudioPara& audiopara);
};

using THREAD_FUNC = void *(*)(void *);

void AudioHdiCaptureTest::SetUpTestCase(void) {}

void AudioHdiCaptureTest::TearDownTestCase(void) {}

void AudioHdiCaptureTest::SetUp(void)
{
    char resolvedPath[] = "//system/lib/libaudio_hdi_proxy_server.z.so";
    handleSo = dlopen(resolvedPath, RTLD_LAZY);
    if (handleSo == nullptr) {
        return;
    }
    GetAudioManager = (struct AudioManager *(*)())(dlsym(handleSo, "GetAudioProxyManagerFuncs"));
    if (GetAudioManager == nullptr) {
        return;
    }
}

void AudioHdiCaptureTest::TearDown(void)
{
    // step 2: input testsuit teardown step
    if (GetAudioManager != nullptr) {
        GetAudioManager = nullptr;
    }
}

int32_t AudioHdiCaptureTest::GetLoadAdapter(struct AudioManager manager, enum AudioPortDirection portType,
    const string adapterName, struct AudioAdapter **adapter, struct AudioPort& audioPort) const
{
    int32_t ret = -1;
    int size = 0;
    struct AudioAdapterDescriptor *desc = nullptr;
    struct AudioAdapterDescriptor *descs = nullptr;
    if (adapter == nullptr) {
        return HDF_FAILURE;
    }
    ret = manager.GetAllAdapters(&manager, &descs, &size);
    if (ret < 0 || descs == nullptr || size == 0) {
        return HDF_FAILURE;
    } else {
        int index = SwitchAdapter(descs, adapterName, portType, audioPort, size);
        if (index < 0) {
            return HDF_FAILURE;
        } else {
            desc = &descs[index];
        }
    }
    if (desc == nullptr) {
        return HDF_FAILURE;
    } else {
        ret = manager.LoadAdapter(&manager, desc, adapter);
    }
    if (ret < 0 || adapter == nullptr) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureTest::AudioCreateCapture(enum AudioPortPin pins, struct AudioManager manager,
    struct AudioPort capturePort, struct AudioAdapter *adapter, struct AudioCapture **capture) const
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    if (adapter == nullptr || capture == nullptr) {
        return HDF_FAILURE;
    }
    ret = InitAttrs(attrs);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    ret = InitDevDesc(devDesc, capturePort.portId, pins);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    ret = adapter->CreateCapture(adapter, &devDesc, &attrs, capture);
    if (ret < 0 || *capture == nullptr) {
        manager.UnloadAdapter(&manager, adapter);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureTest::AudioCaptureStart(const string path, struct AudioCapture *capture) const
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};

    ret = InitAttrs(attrs);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    FILE *file = fopen(path.c_str(), "wb+");
    if (file == nullptr) {
        return HDF_FAILURE;
    }
    ret = FrameStartCapture(capture, file, attrs);
    if (ret < 0) {
        fclose(file);
        return HDF_FAILURE;
    }
    fclose(file);
    return HDF_SUCCESS;
}

struct PrepareAudioPara {
    struct AudioManager *manager;
    enum AudioPortDirection portType;
    const char *adapterName;
    struct AudioAdapter *adapter;
    struct AudioPort audioPort;
    void *self;
    enum AudioPortPin pins;
    const char *path;
    struct AudioRender *render;
    struct AudioCapture *capture;
    struct AudioHeadInfo headInfo;
    struct AudioAdapterDescriptor *desc;
    struct AudioAdapterDescriptor *descs;
    char *frame;
    uint64_t requestBytes;
    uint64_t replyBytes;
    uint64_t fileSize;
    struct AudioSampleAttributes attrs;
};

int32_t AudioHdiCaptureTest::GetLoadAdapterAudioPara(struct PrepareAudioPara& audiopara)
{
    int32_t ret = -1;
    int size = 0;
    auto *inst = (AudioHdiCaptureTest *)audiopara.self;
    if (inst != nullptr && inst->GetAudioManager != nullptr) {
        audiopara.manager = inst->GetAudioManager();
    }
    if (audiopara.manager == nullptr) {
        return HDF_FAILURE;
    }
    ret = audiopara.manager->GetAllAdapters(audiopara.manager, &audiopara.descs, &size);
    if (ret < 0 || audiopara.descs == nullptr || size == 0) {
        return HDF_FAILURE;
    } else {
        int index = SwitchAdapter(audiopara.descs, audiopara.adapterName,
            audiopara.portType, audiopara.audioPort, size);
        if (index < 0) {
            return HDF_FAILURE;
        } else {
            audiopara.desc = &audiopara.descs[index];
        }
    }
    if (audiopara.desc == nullptr) {
        return HDF_FAILURE;
    } else {
        ret = audiopara.manager->LoadAdapter(audiopara.manager, audiopara.desc, &audiopara.adapter);
    }
    if (ret < 0 || audiopara.adapter == nullptr) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureTest::RecordAudio(struct PrepareAudioPara& audiopara)
{
    int32_t ret = -1;
    struct AudioDeviceDescriptor devDesc = {};
    if (audiopara.adapter == nullptr || audiopara.adapter->CreateCapture == nullptr
        || audiopara.manager == nullptr) {
        return HDF_FAILURE;
    }
    ret = InitAttrs(audiopara.attrs);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    ret = InitDevDesc(devDesc, (&audiopara.audioPort)->portId, audiopara.pins);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    ret = audiopara.adapter->CreateCapture(audiopara.adapter, &devDesc, &(audiopara.attrs), &audiopara.capture);
    if (ret < 0 || audiopara.capture == nullptr) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        return HDF_FAILURE;
    }

    FILE *file = fopen(audiopara.path, "wb+");
    if (file == nullptr) {
        audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
        return HDF_FAILURE;
    }
    ret = StartRecord(audiopara.capture, file, audiopara.fileSize);
    if (ret < 0) {
        audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
        fclose(file);
        return HDF_FAILURE;
    }
    fclose(file);
    return HDF_SUCCESS;
}

/**
* @tc.name  Test AudioCaptureCaptureFrame API via legal input
* @tc.number  SUB_Audio_HDI_AudioCaptureFrame_0001
* @tc.desc  test AudioCaptureCaptureFrame interface,Returns 0 if the input data is read successfully
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiCaptureTest, SUB_Audio_HDI_AudioCaptureFrame_0001, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t replyBytes = 0;
    uint64_t requestBytes = BUFFER_SIZE;
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret != 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = capture->control.Start((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    char *frame = (char *)calloc(1, BUFFER_SIZE);
    EXPECT_NE(nullptr, frame);

    ret = capture->CaptureFrame(capture, frame, requestBytes, &replyBytes);
    EXPECT_EQ(HDF_SUCCESS, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}
/**
* @tc.name  Test AudioCaptureCaptureFrame API via setting the incoming parameter frame is nullptr
* @tc.number  SUB_Audio_HDI_AudioCaptureFrame_0002
* @tc.desc  test AudioCaptureCaptureFrame interface,Returns -1 if the incoming parameter frame is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiCaptureTest, SUB_Audio_HDI_AudioCaptureFrame_0002, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t replyBytes = 0;
    uint64_t requestBytes = BUFFER_SIZE;
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    char *frame = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret != 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = capture->control.Start((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->CaptureFrame(capture, frame, requestBytes, &replyBytes);
    EXPECT_EQ(HDF_FAILURE, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioCaptureCaptureFrame API via setting the incoming parameter replyBytes is nullptr
* @tc.number  SUB_Audio_HDI_AudioCaptureFrame_0003
* @tc.desc  test AudioCaptureCaptureFrame interface,Returns -1 if the incoming parameter replyBytes is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiCaptureTest, SUB_Audio_HDI_AudioCaptureFrame_0003, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t requestBytes = BUFFER_SIZE;
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    uint64_t *replyBytes = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret != 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = capture->control.Start((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    char *frame = (char *)calloc(1, BUFFER_SIZE);
    EXPECT_NE(nullptr, frame);
    ret = capture->CaptureFrame(capture, frame, requestBytes, replyBytes);
    EXPECT_EQ(HDF_FAILURE, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}
/**
* @tc.name  Test AudioCaptureCaptureFrame API via setting the incoming parameter capture is nullptr
* @tc.number  SUB_Audio_HDI_AudioCaptureFrame_0004
* @tc.desc  test AudioCaptureCaptureFrame interface,Returns -1 if the incoming parameter capture is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiCaptureTest, SUB_Audio_HDI_AudioCaptureFrame_0004, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t requestBytes = BUFFER_SIZE;
    uint64_t replyBytes = 0;
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret != 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = capture->control.Start((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    char *frame = (char *)calloc(1, BUFFER_SIZE);
    EXPECT_NE(nullptr, frame);
    ret = capture->CaptureFrame(captureNull, frame, requestBytes, &replyBytes);
    EXPECT_EQ(HDF_FAILURE, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}
/**
* @tc.name  Test AudioCaptureFrame API without calling interface capturestart
* @tc.number  SUB_Audio_HDI_AudioCaptureFrame_0005
* @tc.desc  Test AudioCaptureFrame interface,Returns -1 if without calling interface capturestart
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiCaptureTest, SUB_Audio_HDI_AudioCaptureFrame_0005, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t requestBytes = BUFFER_SIZE;
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    uint64_t replyBytes = 0;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret != 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    char *frame = (char *)calloc(1, BUFFER_SIZE);
    EXPECT_NE(nullptr, frame);
    ret = capture->CaptureFrame(capture, frame, requestBytes, &replyBytes);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}
/**
* @tc.name  Test AudioCaptureCaptureFrame API via setting the incoming parameter requestBytes
less than interface requirements
* @tc.number  SUB_Audio_HDI_AudioCaptureFrame_0006
* @tc.desc  test AudioCaptureCaptureFrame interface,Returns -1 if the incoming parameter
requestBytes less than interface requirements
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiCaptureTest, SUB_Audio_HDI_AudioCaptureFrame_0006, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t requestBytes = BUFFER_SIZE_LITTLE;
    uint64_t replyBytes = 0;
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret != 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = capture->control.Start((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    char *frame = (char *)calloc(1, BUFFER_SIZE);
    EXPECT_NE(nullptr, frame);
    ret = capture->CaptureFrame(capture, frame, requestBytes, &replyBytes);
    EXPECT_EQ(HDF_FAILURE, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
}
/**
* @tc.name  Test AudioCaptureGetCapturePosition API via legal input
* @tc.number  SUB_Audio_HDI_AudioCaptureGetCapturePosition_0001
* @tc.desc  Test AudioCaptureGetCapturePosition interface,Returns 0 if get CapturePosition during playing.
* @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureTest, SUB_Audio_HDI_AudioCaptureGetCapturePosition_0001, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvSec = 0};
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME2.c_str(), .self = this, .pins = PIN_IN_MIC,
        .path = AUDIO_CAPTURE_FILE.c_str(), .fileSize = FILESIZE
    };

    ret = GetLoadAdapterAudioPara(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)RecordAudio, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    sleep(3);
    ret = audiopara.capture->GetCapturePosition(audiopara.capture, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(time.tvSec, timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.capture->control.Stop((AudioHandle)(audiopara.capture));
    EXPECT_EQ(HDF_SUCCESS, ret);
    audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Test GetCapturePosition API via get CapturePosition after the audiois Paused and resumed
* @tc.number  SUB_Audio_HDI_AudioCaptureGetCapturePosition_0002
* @tc.desc   Test GetCapturePosition interface,Returns 0 if get Position after Pause and resume during playing
* @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureTest, SUB_Audio_HDI_AudioCaptureGetCapturePosition_0002, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvSec = 0};
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME2.c_str(), .self = this, .pins = PIN_IN_MIC,
        .path = AUDIO_CAPTURE_FILE.c_str(), .fileSize = FILESIZE
    };

    ret = GetLoadAdapterAudioPara(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)RecordAudio, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    sleep(3);
    ret = audiopara.capture->control.Pause((AudioHandle)(audiopara.capture));
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.capture->GetCapturePosition(audiopara.capture, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(time.tvSec, timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);
    ret = audiopara.capture->control.Resume((AudioHandle)(audiopara.capture));
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.capture->GetCapturePosition(audiopara.capture, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(time.tvSec, timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.capture->control.Stop((AudioHandle)(audiopara.capture));
    EXPECT_EQ(HDF_SUCCESS, ret);
    audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Test GetCapturePosition API via get CapturePosition after the audio file is stopped
* @tc.number  SUB_Audio_HDI_AudioCaptureGetCapturePosition_0003
* @tc.desc  Test GetCapturePosition interface,Returns 0 if get CapturePosition after stop during playing
* @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureTest, SUB_Audio_HDI_AudioCaptureGetCapturePosition_0003, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvSec = 0};
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME2.c_str(), .self = this, .pins = PIN_IN_MIC,
        .path = AUDIO_CAPTURE_FILE.c_str(), .fileSize = FILESIZE
    };

    ret = GetLoadAdapterAudioPara(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)RecordAudio, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    sleep(3);
    ret = audiopara.capture->GetCapturePosition(audiopara.capture, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(time.tvSec, timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.capture->control.Stop((AudioHandle)(audiopara.capture));
    EXPECT_EQ(HDF_SUCCESS, ret);
    audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
    * @tc.name  Test GetCapturePosition API via get CapturePosition after the object is created
    * @tc.number  SUB_Audio_HDI_AudioCaptureGetCapturePosition_0004
    * @tc.desc  Test GetCapturePosition interface, return 0 if get CapturePosition after the object is created
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureTest, SUB_Audio_HDI_AudioCaptureGetCapturePosition_0004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioPort capturePort = {};
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {.tvSec = 0};
    int64_t timeExp = 0;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(PIN_IN_MIC, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = capture->GetCapturePosition(capture, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(time.tvSec, timeExp);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test GetCapturePosition API via setting the parameter Capture is nullptr
    * @tc.number  SUB_Audio_HDI_AudioCaptureGetCapturePosition_0005
    * @tc.desc  Test GetCapturePosition interface, return -1 if setting the parameter Capture is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureTest, SUB_Audio_HDI_AudioCaptureGetCapturePosition_0005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioPort capturePort = {};
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {};

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(PIN_IN_MIC, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->GetCapturePosition(captureNull, &frames, &time);
    EXPECT_EQ(HDF_FAILURE, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test GetCapturePosition API via setting the parameter frames is nullptr
    * @tc.number  SUB_Audio_HDI_AudioCaptureGetCapturePosition_0006
    * @tc.desc  Test GetCapturePosition interface, return -1 if setting the parameter frames is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureTest, SUB_Audio_HDI_AudioCaptureGetCapturePosition_0006, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioPort capturePort = {};
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    uint64_t *framesNull = nullptr;
    struct AudioTimeStamp time = {.tvSec = 0};

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(PIN_IN_MIC, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->GetCapturePosition(capture, framesNull, &time);
    EXPECT_EQ(HDF_FAILURE, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test GetCapturePosition API via setting the parameter time is nullptr
    * @tc.number  SUB_Audio_HDI_AudioCaptureGetCapturePosition_0007
    * @tc.desc  Test GetCapturePosition interface, return -1 if setting the parameter time is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureTest, SUB_Audio_HDI_AudioCaptureGetCapturePosition_0007, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioPort capturePort = {};
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    uint64_t frames = 0;
    struct AudioTimeStamp *timeNull = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(PIN_IN_MIC, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->GetCapturePosition(capture, &frames, timeNull);
    EXPECT_EQ(HDF_FAILURE, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test GetCapturePosition API via get CapturePosition continuously
    * @tc.number  SUB_Audio_HDI_AudioCaptureGetCapturePosition_0008
    * @tc.desc  Test GetCapturePosition interface, return 0 if the GetCapturePosition was called twice
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureTest, SUB_Audio_HDI_AudioCaptureGetCapturePosition_0008, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioPort capturePort = {};
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {.tvSec = 0};
    struct AudioTimeStamp timeSec = {.tvNSec = 1};
    int64_t timeExp = 0;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(PIN_IN_MIC, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->GetCapturePosition(capture, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(time.tvSec, timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);
    ret = capture->GetCapturePosition(capture, &frames, &timeSec);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(timeSec.tvNSec, timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test GetCapturePosition API via define format to AUDIO_FORMAT_PCM_16_BIT
    * @tc.number  SUB_Audio_HDI_AudioCaptureGetCapturePosition_0009
    * @tc.desc  Test GetCapturePosition interface,return 0 if get framesize define format to AUDIO_FORMAT_PCM_16_BIT
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureTest, SUB_Audio_HDI_AudioCaptureGetCapturePosition_0009, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort capturePort = {};
    struct AudioCapture *capture = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    uint64_t channelCountExp = 2;
    uint32_t sampleRateExp = 48000;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvNSec = 1};
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(PIN_IN_MIC, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = 48000;
    attrs.channelCount = 2;
    ret = capture->attr.SetSampleAttributes(capture, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->attr.GetSampleAttributes(capture, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(sampleRateExp, attrsValue.sampleRate);
    EXPECT_EQ(channelCountExp, attrsValue.channelCount);

    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetCapturePosition(capture, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(time.tvNSec, timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test GetCapturePosition API via define format to AUDIO_FORMAT_PCM_24_BIT
    * @tc.number  SUB_Audio_HDI_AudioCaptureGetCapturePosition_0010
    * @tc.desc  Test GetCapturePosition interface,return 0 if get framesize define format to AUDIO_FORMAT_PCM_24_BIT
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureTest, SUB_Audio_HDI_AudioCaptureGetCapturePosition_0010, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort capturePort = {};
    struct AudioCapture *capture = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    uint64_t channelCountExp = 2;
    uint32_t sampleRateExp = 48000;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvNSec = 1};
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(PIN_IN_MIC, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
    attrs.sampleRate = 48000;
    attrs.channelCount = 2;
    ret = capture->attr.SetSampleAttributes(capture, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->attr.GetSampleAttributes(capture, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(sampleRateExp, attrsValue.sampleRate);
    EXPECT_EQ(channelCountExp, attrsValue.channelCount);

    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetCapturePosition(capture, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(time.tvNSec, timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test GetCapturePosition API via define sampleRate and channelCount to different value
    * @tc.number  SUB_Audio_HDI_AudioCaptureGetCapturePosition_0011
    * @tc.desc  Test GetCapturePosition interface,return 0 if get framesize define channelCount  as different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureTest, SUB_Audio_HDI_AudioCaptureGetCapturePosition_0011, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort capturePort = {};
    struct AudioCapture *capture = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    uint64_t channelCountExp = 1;
    uint32_t sampleRateExp = 48000;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvNSec = 1};
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(PIN_IN_MIC, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = 48000;
    attrs.channelCount = 1;
    ret = capture->attr.SetSampleAttributes(capture, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->attr.GetSampleAttributes(capture, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(sampleRateExp, attrsValue.sampleRate);
    EXPECT_EQ(channelCountExp, attrsValue.channelCount);

    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetCapturePosition(capture, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(time.tvNSec, timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test GetCapturePosition API via define sampleRate and channelCount to 1
    * @tc.number  SUB_Audio_HDI_AudioCaptureGetCapturePosition_0012
    * @tc.desc  Test GetCapturePosition interface,return 0 if get framesize define channelCount to 1
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureTest, SUB_Audio_HDI_AudioCaptureGetCapturePosition_0012, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort capturePort = {};
    struct AudioCapture *capture = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    uint64_t channelCountExp = 1;
    uint32_t sampleRateExp = 48000;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvNSec = 1};
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(PIN_IN_MIC, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
    attrs.sampleRate = 48000;
    attrs.channelCount = 1;
    ret = capture->attr.SetSampleAttributes(capture, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->attr.GetSampleAttributes(capture, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(sampleRateExp, attrsValue.sampleRate);
    EXPECT_EQ(channelCountExp, attrsValue.channelCount);

    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetCapturePosition(capture, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(time.tvNSec, timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
}