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
const float COUNT = 1000;         // number of interface calls
const long LOWLATENCY = 10000;    // low interface delay:10ms
const long NORMALLATENCY = 30000; // normal interface delay:30ms
const long HIGHLATENCY = 60000;   // high interface delay:60ms
const int BUFFER = 1024 * 4;

class AudioIdlHdiCapturePerformaceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static TestAudioManager *(*GetAudioManager)(const char *);
    static TestAudioManager *manager;
    static void *handle;
    static void (*AudioManagerRelease)(struct IAudioManager *);
    static void (*AudioAdapterRelease)(struct IAudioAdapter *);
    static void (*AudioCaptureRelease)(struct IAudioCapture *);
    static int32_t CreateCapture(TestAudioManager *manager, int pins, const std::string &adapterName,
        struct IAudioAdapter **adapter, struct IAudioCapture **capture);
};

TestAudioManager *(*AudioIdlHdiCapturePerformaceTest::GetAudioManager)(const char *) = nullptr;
TestAudioManager *AudioIdlHdiCapturePerformaceTest::manager = nullptr;
void *AudioIdlHdiCapturePerformaceTest::handle = nullptr;
void (*AudioIdlHdiCapturePerformaceTest::AudioManagerRelease)(struct IAudioManager *) = nullptr;
void (*AudioIdlHdiCapturePerformaceTest::AudioAdapterRelease)(struct IAudioAdapter *) = nullptr;
void (*AudioIdlHdiCapturePerformaceTest::AudioCaptureRelease)(struct IAudioCapture *) = nullptr;
void AudioIdlHdiCapturePerformaceTest::SetUpTestCase(void)
{
    char absPath[PATH_MAX] = {0};
    char *path = realpath(RESOLVED_PATH.c_str(), absPath);
    ASSERT_NE(nullptr, path);
    handle = dlopen(absPath, RTLD_LAZY);
    ASSERT_NE(nullptr, handle);
    GetAudioManager = (TestAudioManager *(*)(const char *))(dlsym(handle, FUNCTION_NAME.c_str()));
    ASSERT_NE(nullptr, GetAudioManager);
    (void)HdfRemoteGetCallingPid();
    manager = GetAudioManager(IDL_SERVER_NAME.c_str());
    ASSERT_NE(nullptr, manager);
    AudioManagerRelease = (void (*)(struct IAudioManager *))(dlsym(handle, "AudioManagerRelease"));
    ASSERT_NE(nullptr, AudioManagerRelease);
    AudioAdapterRelease = (void (*)(struct IAudioAdapter *))(dlsym(handle, "AudioAdapterRelease"));
    ASSERT_NE(nullptr, AudioAdapterRelease);
    AudioCaptureRelease = (void (*)(struct IAudioCapture *))(dlsym(handle, "AudioCaptureRelease"));
    ASSERT_NE(nullptr, AudioCaptureRelease);
}

void AudioIdlHdiCapturePerformaceTest::TearDownTestCase(void)
{
    if (AudioManagerRelease !=nullptr) {
        AudioManagerRelease(manager);
        manager = nullptr;
    }
    if (handle != nullptr) {
        dlclose(handle);
        handle = nullptr;
    }
    if (GetAudioManager != nullptr) {
        GetAudioManager = nullptr;
    }
}

void AudioIdlHdiCapturePerformaceTest::SetUp(void) {}

void AudioIdlHdiCapturePerformaceTest::TearDown(void) {}
int32_t AudioIdlHdiCapturePerformaceTest::CreateCapture(TestAudioManager *manager, int pins,
    const std::string &adapterName, struct IAudioAdapter **adapter, struct IAudioCapture **capture)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioPort audioPort = {};
    if (adapter == nullptr || capture == nullptr) {
        return HDF_ERR_INVALID_PARAM;
    }
    ret = GetLoadAdapter(manager, PORT_IN, adapterName, adapter, audioPort);
    if (ret < 0) {
        if (audioPort.portName != nullptr) {
            free(audioPort.portName);
        }
        return ret;
    }
    if (*adapter == nullptr || (*adapter)->CreateCapture == nullptr) {
        free(audioPort.portName);
        return HDF_FAILURE;
    }
    InitAttrs(attrs);
    attrs.silenceThreshold = BUFFER;
    InitDevDesc(devDesc, audioPort.portId, pins);
    ret = (*adapter)->CreateCapture(*adapter, &devDesc, &attrs, capture);
    if (ret < 0 || *capture == nullptr) {
        manager->UnloadAdapter(manager, adapterName.c_str());
        AudioAdapterRelease(*adapter);
        free(audioPort.portName);
        free(devDesc.desc);
        return HDF_FAILURE;
    }
    free(audioPort.portName);
    free(devDesc.desc);
    return HDF_SUCCESS;
}
/**
* @tc.name  the performace of AudioCreateCapture
* @tc.number  SUB_Audio_HDI_CreateCapture_Performance_001
* @tc.devDesc  tests the performace of AudioCreateCapture interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, SUB_Audio_HDI_CreateCapture_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_IN_MIC, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = GetLoadAdapter(audiopara.manager, audiopara.portType, audiopara.adapterName,
                         &audiopara.adapter, audiopara.audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    InitAttrs(audiopara.attrs);
    InitDevDesc(audiopara.devDesc, audiopara.audioPort.portId, audiopara.pins);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.adapter->CreateCapture(audiopara.adapter, &audiopara.devDesc, &audiopara.attrs,
                                               &audiopara.capture);
        gettimeofday(&audiopara.end, NULL);
        if (ret < 0 || audiopara.capture == nullptr) {
            audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
            AudioAdapterRelease(audiopara.adapter);
            audiopara.adapter = nullptr;
            ASSERT_EQ(HDF_SUCCESS, ret);
        }
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = audiopara.adapter->DestroyCapture(audiopara.adapter);
        AudioCaptureRelease(audiopara.capture);
        audiopara.capture = nullptr;
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    free(audiopara.devDesc.desc);
    free(audiopara.audioPort.portName);
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(HIGHLATENCY, audiopara.averageDelayTime);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performace of AudioDestroyCapture
* @tc.number  SUB_Audio_HDI_DestroyCapture_Performance_001
* @tc.devDesc  tests the performace of AudioDestroyCapture interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, SUB_Audio_HDI_DestroyCapture_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .adapter = nullptr, .capture = nullptr, .portType = PORT_IN,
        .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    for (int i = 0; i < COUNT; ++i) {
        ret = CreateCapture(audiopara.manager, audiopara.pins, ADAPTER_NAME, &audiopara.adapter,
                            &audiopara.capture);
        ASSERT_EQ(HDF_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.adapter->DestroyCapture(audiopara.adapter);
        AudioCaptureRelease(audiopara.capture);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.capture = nullptr;
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
        AudioAdapterRelease(audiopara.adapter);
        audiopara.adapter = nullptr;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  the performace of AudioCaptureStart
* @tc.number  SUB_Audio_HDI_CaptureStart_Performance_001
* @tc.devDesc  tests the performace of AudioCaptureStart interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, SUB_Audio_HDI_CaptureStart_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .adapter = nullptr, .capture = nullptr, .portType = PORT_IN,
        .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    for (int i = 0; i < COUNT; ++i) {
        ret = CreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.capture);
        ASSERT_EQ(HDF_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->Start(audiopara.capture);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = audiopara.capture->Stop(audiopara.capture);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.adapter->DestroyCapture(audiopara.adapter);
        EXPECT_EQ(HDF_SUCCESS, ret);
        AudioCaptureRelease(audiopara.capture);
        audiopara.capture = nullptr;
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
        AudioAdapterRelease(audiopara.adapter);
        audiopara.adapter = nullptr;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}
/**
* @tc.name  the performace of AudioCapturePause
* @tc.number  SUB_Audio_HDI_CapturePause_Performance_001
* @tc.devDesc  tests the performace of AudioCapturePause interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, SUB_Audio_HDI_CapturePause_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .adapter = nullptr, .capture = nullptr, .portType = PORT_IN,
        .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                        &audiopara.capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.capture->Start(audiopara.capture);
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
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioCaptureRelease(audiopara.capture);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
}

/**
* @tc.name  the performace of AudioCaptureResume
* @tc.number  SUB_Audio_HDI_CaptureResume_Performance_001
* @tc.devDesc  tests the performace of AudioCaptureResume interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, SUB_Audio_HDI_CaptureResume_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .adapter = nullptr, .capture = nullptr, .portType = PORT_IN,
        .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                        &audiopara.capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.capture->Start(audiopara.capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        ret = audiopara.capture->Pause(audiopara.capture);
        EXPECT_EQ(HDF_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->Resume(audiopara.capture);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.capture->Stop(audiopara.capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioCaptureRelease(audiopara.capture);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
}

/**
* @tc.name  the performace of AudioCaptureStop
* @tc.number  SUB_Audio_HDI_CaptureStop_Performance_001
* @tc.devDesc  tests the performace of AudioCaptureStop interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, SUB_Audio_HDI_CaptureStop_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .adapter = nullptr, .capture = nullptr, .portType = PORT_IN,
        .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    for (int i = 0; i < COUNT; ++i) {
        ret = CreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.capture);
        ASSERT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.capture->Start(audiopara.capture);
        EXPECT_EQ(HDF_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->Stop(audiopara.capture);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = audiopara.adapter->DestroyCapture(audiopara.adapter);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.capture = nullptr;
        AudioCaptureRelease(audiopara.capture);
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
        AudioAdapterRelease(audiopara.adapter);
        audiopara.adapter = nullptr;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  the performace of AudioCaptureSetSampleAttributes
* @tc.number  SUB_Audio_HDI_CaptureSetSampleAttributes_Performance_001
* @tc.devDesc  tests the performace of AudioCaptureSetSampleAttributes interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, SUB_Audio_HDI_CaptureSetSampleAttributes_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .adapter = nullptr, .capture = nullptr, .portType = PORT_IN,
        .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                        &audiopara.capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    InitAttrs(audiopara.attrs);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->SetSampleAttributes(audiopara.capture, &audiopara.attrs);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioCaptureRelease(audiopara.capture);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
}
/**
* @tc.name  the performace of AudioCaptureCaptureFrame
* @tc.number  SUB_Audio_HDI_CaptureCaptureFrame_Performance_001
* @tc.devDesc  tests the performace of AudioCaptureCaptureFrame interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, SUB_Audio_HDI_CaptureCaptureFrame_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .adapter = nullptr, .audioPort = {}, .capture = nullptr, .portType = PORT_IN,
        .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0,
        .replyBytes = BUFFER, .requestBytes = BUFFER
    };
    ASSERT_NE(nullptr, audiopara.manager);
    audiopara.frame = (char *)calloc(1, BUFFER);
    ASSERT_NE(nullptr, audiopara.frame);
    ret = CreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                        &audiopara.capture);
    if (ret < 0) {
        free(audiopara.frame);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
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
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioCaptureRelease(audiopara.capture);
    audiopara.capture = nullptr;
    free(audiopara.devDesc.desc);
    free(audiopara.audioPort.portName);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(NORMALLATENCY, audiopara.averageDelayTime);
    free(audiopara.frame);
    audiopara.frame = nullptr;
}
/**
* @tc.name  the performace of AudioCaptureGetSampleAttributes
* @tc.number  SUB_Audio_HDI_CaptureGetSampleAttributes_Performance_001
* @tc.devDesc  tests the performace of AudioCaptureGetSampleAttributes interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, SUB_Audio_HDI_CaptureGetSampleAttributes_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .adapter = nullptr, .capture = nullptr, .portType = PORT_IN,
        .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                        &audiopara.capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    InitAttrs(audiopara.attrs);
    ret = audiopara.capture->SetSampleAttributes(audiopara.capture, &audiopara.attrs);
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
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioCaptureRelease(audiopara.capture);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performace of AudioCaptureSetMute
* @tc.number  SUB_Audio_HDI_CaptureSetMute_Performance_001
* @tc.devDesc  tests the performace of AudioCaptureSetMute interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: wengyin
*/

HWTEST_F(AudioIdlHdiCapturePerformaceTest, SUB_Audio_HDI_CaptureSetMute_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .adapter = nullptr, .capture = nullptr, .portType = PORT_IN,
        .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                        &audiopara.capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->SetMute(audiopara.capture, false);
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
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioCaptureRelease(audiopara.capture);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performace of AudioCaptureGetMute
* @tc.number  SUB_Audio_HDI_CaptureGetMute_Performance_001
* @tc.devDesc  tests the performace of AudioCaptureGetMute interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, SUB_Audio_HDI_CaptureGetMute_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .adapter = nullptr, .capture = nullptr, .portType = PORT_IN,
        .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                        &audiopara.capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.capture->SetMute(audiopara.capture, false);
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
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioCaptureRelease(audiopara.capture);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performace of AudioCaptureSetVolume
* @tc.number  SUB_Audio_HDI_CaptureSetVolume_Performance_001
* @tc.devDesc  tests the performace of AudioCaptureSetVolume interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, SUB_Audio_HDI_CaptureSetVolume_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .adapter = nullptr, .capture = nullptr, .portType = PORT_IN,
        .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0,
        .character.setvolume = 0.7
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                        &audiopara.capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->SetVolume(audiopara.capture, audiopara.character.setvolume);
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
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioCaptureRelease(audiopara.capture);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performace of AudioCaptureGetVolume
* @tc.number  SUB_Audio_HDI_CaptureGetVolume_Performance_001
* @tc.devDesc  tests the performace of AudioCaptureGetVolume interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, SUB_Audio_HDI_CaptureGetVolume_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .adapter = nullptr, .capture = nullptr, .portType = PORT_IN,
        .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0, .character.setvolume = 0.8
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                        &audiopara.capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.capture->SetVolume(audiopara.capture, audiopara.character.setvolume);
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
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioCaptureRelease(audiopara.capture);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performace of AudioCaptureGetGain
* @tc.number  SUB_Audio_HDI_CaptureGetGain_Performance_001
* @tc.devDesc  tests the performace of AudioCaptureGetGain interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, SUB_Audio_HDI_CaptureGetGain_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .adapter = nullptr, .capture = nullptr, .portType = PORT_IN,
        .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0, .character.setgain = 7
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                        &audiopara.capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.capture->SetGain(audiopara.capture, audiopara.character.setgain);
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
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioCaptureRelease(audiopara.capture);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performace of AudioCaptureSetGain
* @tc.number  SUB_Audio_HDI_CaptureSetGain_Performance_001
* @tc.devDesc  tests the performace of AudioCaptureSetGain interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, SUB_Audio_HDI_CaptureSetGain_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .adapter = nullptr, .capture = nullptr, .portType = PORT_IN,
        .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0, .character.setgain = 8
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                        &audiopara.capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->SetGain(audiopara.capture, audiopara.character.setgain);
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
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioCaptureRelease(audiopara.capture);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performace of AudioCaptureGetCurrentChannelId
* @tc.number  SUB_Audio_HDI_CaptureGetCurrentChannelId_Performance_001
* @tc.devDesc  tests the performace of AudioCaptureGetCurrentChannelId interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, SUB_Audio_HDI_CaptureGetCurrentChannelId_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .adapter = nullptr, .capture = nullptr, .portType = PORT_IN,
        .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                        &audiopara.capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->GetCurrentChannelId(audiopara.capture, &audiopara.character.getcurrentchannelId);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioCaptureRelease(audiopara.capture);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performace of AudioCaptureGetFrameCount
* @tc.number  SUB_Audio_HDI_CaptureGetFrameCount_Performance_001
* @tc.devDesc  tests the performace of AudioCaptureGetFrameCount interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, SUB_Audio_HDI_CaptureGetFrameCount_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .adapter = nullptr, .capture = nullptr, .portType = PORT_IN,
        .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                        &audiopara.capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->GetFrameCount(audiopara.capture, &audiopara.character.getframecount);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(INITIAL_VALUE, audiopara.character.getframecount);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioCaptureRelease(audiopara.capture);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performace of AudioCaptureGetFrameSize
* @tc.number  SUB_Audio_HDI_CaptureGetFrameSize_Performance_001
* @tc.devDesc  tests the performace of AudioCaptureGetFrameSize interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, SUB_Audio_HDI_CaptureGetFrameSize_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .adapter = nullptr, .capture = nullptr, .portType = PORT_IN,
        .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                        &audiopara.capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->GetFrameSize(audiopara.capture, &audiopara.character.getframesize);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_GT(audiopara.character.getframesize, INITIAL_VALUE);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioCaptureRelease(audiopara.capture);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performace of AudioCaptureFlush
* @tc.number  SUB_Audio_HDI_CaptureFlush_Performance_001
* @tc.devDesc  tests the performace of AudioCaptureFlush interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, SUB_Audio_HDI_CaptureFlush_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .adapter = nullptr, .capture = nullptr, .portType = PORT_IN,
        .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    for (int i = 0; i < COUNT; ++i) {
        ret = CreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.capture);
        ASSERT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.capture->Start(audiopara.capture);
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
        ret = audiopara.adapter->DestroyCapture(audiopara.adapter);
        EXPECT_EQ(HDF_SUCCESS, ret);
        AudioCaptureRelease(audiopara.capture);
        audiopara.capture = nullptr;
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
        AudioAdapterRelease(audiopara.adapter);
        audiopara.adapter = nullptr;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  the performace of AudioCaptureGetGainThreshold
* @tc.number  SUB_Audio_HDI_CaptureGetGainThreshold_Performance_001
* @tc.devDesc  tests the performace of AudioCaptureGetGainThreshold interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, SUB_Audio_HDI_CaptureGetGainThreshold_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .adapter = nullptr, .capture = nullptr, .portType = PORT_IN,
        .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                        &audiopara.capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->GetGainThreshold(audiopara.capture, &audiopara.character.gainthresholdmin,
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
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioCaptureRelease(audiopara.capture);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performace of AudioCaptureCheckSceneCapability
* @tc.number  SUB_Audio_HDI_CaptureCheckSceneCapability_Performance_001
* @tc.devDesc  tests the performace of AudioCaptureCheckSceneCapability interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, SUB_Audio_HDI_CaptureCheckSceneCapability_Performance_001,
         TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .adapter = nullptr, .capture = nullptr, .portType = PORT_IN,
        .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    struct AudioSceneDescriptor scenes = { .scene.id = 0, .desc.pins = PIN_IN_MIC };
    bool supported = false;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateCapture(audiopara.manager, audiopara.pins, ADAPTER_NAME, &audiopara.adapter,
                        &audiopara.capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        scenes.desc.desc = strdup("mic");
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->CheckSceneCapability(audiopara.capture, &scenes, &supported);
        gettimeofday(&audiopara.end, NULL);
        free(scenes.desc.desc);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioCaptureRelease(audiopara.capture);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performace of AudioCaptureSelectScene
* @tc.number  SUB_Audio_HDI_CaptureSelectScene_Performance_001
* @tc.devDesc  tests the performace of AudioCaptureSelectScene interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, SUB_Audio_HDI_CaptureSelectScene_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .adapter = nullptr, .capture = nullptr, .portType = PORT_IN,
        .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    struct AudioSceneDescriptor scenes = { .scene.id = 0, .desc.pins = PIN_IN_MIC };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateCapture(audiopara.manager, audiopara.pins, ADAPTER_NAME, &audiopara.adapter,
                        &audiopara.capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        scenes.desc.desc = strdup("mic");
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->SelectScene(audiopara.capture, &scenes);
        gettimeofday(&audiopara.end, NULL);
        free(scenes.desc.desc);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioCaptureRelease(audiopara.capture);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performace of AudioGetCapturePosition
* @tc.number  SUB_Audio_HDI_GetCapturePosition_Performance_001
* @tc.devDesc  tests the performace of AudioCaptureGetCapturePosition interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, SUB_Audio_HDI_GetCapturePosition_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .adapter = nullptr, .capture = nullptr, .portType = PORT_IN,
        .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                        &audiopara.capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.capture->Start(audiopara.capture);
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
    ret = audiopara.capture->Stop(audiopara.capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioCaptureRelease(audiopara.capture);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performace of AudioCaptureSetExtraParams
* @tc.number  SUB_Audio_HDI_CaptureSetExtraParams_Performance_001
* @tc.desc  tests the performace of AudioCaptureSetExtraParams interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, SUB_Audio_HDI_CaptureSetExtraParams_Performance_001, TestSize.Level1)
{
    int32_t ret;
    char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;attr-frame-count=82;attr-sampling-rate=48000";
    struct PrepareAudioPara audiopara = {
        .manager = manager, .adapter = nullptr, .capture = nullptr, .portType = PORT_IN,
        .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                        &audiopara.capture);
    ASSERT_EQ(HDF_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->SetExtraParams(audiopara.capture, keyValueList);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioCaptureRelease(audiopara.capture);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performace of AudioCaptureGetExtraParams
* @tc.number  SUB_Audio_HDI_CaptureGetExtraParams_Performance_001
* @tc.desc  tests the performace of AudioCaptureGetExtraParams interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, SUB_Audio_HDI_CaptureGetExtraParams_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .adapter = nullptr, .capture = nullptr, .portType = PORT_IN,
        .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    char keyValueList[] = "attr-format=24;attr-frame-count=4096;";
    char keyValueListExp[] = "attr-route=0;attr-format=24;attr-channels=2;\
attr-frame-count=4096;attr-sampling-rate=48000";
    int32_t listLenth = 256;
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                        &audiopara.capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.capture->SetExtraParams(audiopara.capture, keyValueList);
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
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioCaptureRelease(audiopara.capture);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performace of AudioCaptureGetMmapPosition
* @tc.number  SUB_Audio_HDI_CaptureGetMmapPosition_Performance_001
* @tc.desc  tests the performace of AudioCaptureGetMmapPosition interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiCapturePerformaceTest, SUB_Audio_HDI_CaptureGetMmapPosition_Performance_001, TestSize.Level1)
{
    int32_t ret;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .adapter = nullptr, .capture = nullptr, .portType = PORT_IN,
        .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateCapture(audiopara.manager, audiopara.pins, ADAPTER_NAME, &audiopara.adapter,
                        &audiopara.capture);
    if (ret < 0 || audiopara.capture == nullptr) {
        ASSERT_EQ(HDF_SUCCESS, ret);
        ASSERT_EQ(nullptr, audiopara.capture);
    }

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.capture->GetMmapPosition(audiopara.capture, &frames, &(audiopara.time));
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ((audiopara.time.tvSec) * SECTONSEC + (audiopara.time.tvNSec), timeExp);
        EXPECT_EQ(frames, INITIAL_VALUE);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    ret = audiopara.adapter->DestroyCapture(audiopara.adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioCaptureRelease(audiopara.capture);
    audiopara.capture = nullptr;
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;

    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}
}