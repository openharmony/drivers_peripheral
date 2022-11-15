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

#include "audio_lib_common.h"
#include "audio_smartpa_test.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
const string BIND_CONTROL = "control";
const string BIND_RENDER = "render";
const string BIND_NAME_ERROR = "rendeo";

class AudioSmartPaTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static struct DevHandle *(*BindServiceRender)(const char *);
    static int32_t (*InterfaceLibOutputRender)(struct DevHandle *, int32_t, struct AudioHwRenderParam *);
    static int32_t (*InterfaceLibCtlRender)(struct DevHandle *, int32_t, struct AudioHwRenderParam *);
    static void (*CloseServiceRender)(struct DevHandle *);
    static void *ptrHandle;
    static TestAudioManager *manager;
    int32_t BindServiceAndHwRender(struct AudioHwRender *&hwRender, const std::string BindName,
         const std::string adapterNameCase, struct DevHandle *&handle) const;
};

TestAudioManager *AudioSmartPaTest::manager = nullptr;
struct DevHandle *(*AudioSmartPaTest::BindServiceRender)(const char *) = nullptr;
int32_t (*AudioSmartPaTest::InterfaceLibOutputRender)(struct DevHandle *, int, struct AudioHwRenderParam *) = nullptr;
int32_t (*AudioSmartPaTest::InterfaceLibCtlRender)(struct DevHandle *, int, struct AudioHwRenderParam *) = nullptr;
void (*AudioSmartPaTest::CloseServiceRender)(struct DevHandle *) = nullptr;
void *AudioSmartPaTest::ptrHandle = nullptr;
using THREAD_FUNC = void *(*)(void *);

void AudioSmartPaTest::SetUpTestCase(void)
{
    manager = GetAudioManagerFuncs();
    ASSERT_NE(nullptr, manager);
    string resolvedPathOne = HDF_LIBRARY_FULL_PATH("libhdi_audio_interface_lib_render");
    ptrHandle = dlopen(resolvedPathOne.c_str(), RTLD_LAZY);
    ASSERT_NE(nullptr, ptrHandle);
    BindServiceRender = (struct DevHandle* (*)(const char *))dlsym(ptrHandle, "AudioBindServiceRender");
    InterfaceLibOutputRender = (int32_t (*)(struct DevHandle *, int,
        struct AudioHwRenderParam *))dlsym(ptrHandle, "AudioInterfaceLibOutputRender");
    InterfaceLibCtlRender = (int32_t (*)(struct DevHandle *, int,
        struct AudioHwRenderParam *))dlsym(ptrHandle, "AudioInterfaceLibCtlRender");
    CloseServiceRender = reinterpret_cast<void (*)(struct DevHandle *)>(dlsym(ptrHandle, "AudioCloseServiceRender"));
    if (BindServiceRender == nullptr || CloseServiceRender == nullptr ||
        InterfaceLibCtlRender == nullptr || InterfaceLibOutputRender == nullptr) {
        return;
    }
}

void AudioSmartPaTest::TearDownTestCase(void)
{
    if (ptrHandle != nullptr) {
        (void)dlclose(ptrHandle);
    }
    if (BindServiceRender != nullptr) {
        BindServiceRender = nullptr;
    }
    if (CloseServiceRender != nullptr) {
        CloseServiceRender = nullptr;
    }
    if (InterfaceLibOutputRender != nullptr) {
        InterfaceLibOutputRender = nullptr;
    }
    if (InterfaceLibCtlRender != nullptr) {
        InterfaceLibCtlRender = nullptr;
    }
}

void AudioSmartPaTest::SetUp(void) {}

void AudioSmartPaTest::TearDown(void) {}

int32_t AudioSmartPaTest::BindServiceAndHwRender(struct AudioHwRender *&hwRender,
    const std::string BindName, const std::string adapterNameCase, struct DevHandle *&handle) const
{
    handle = BindServiceRender(BindName.c_str());
    if (handle == nullptr) {
        return HDF_FAILURE;
    }
    hwRender = static_cast<struct AudioHwRender *>(calloc(1, sizeof(*hwRender)));
    if (hwRender == nullptr) {
        CloseServiceRender(handle);
        return HDF_FAILURE;
    }
    if (InitHwRender(hwRender, adapterNameCase)) {
        CloseServiceRender(handle);
        free(hwRender);
        hwRender = nullptr;
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
/**
* @tc.name  AudioFunctionSmartpaTest_001
* @tc.desc  test Render interface by playing an audio file based smartPA successfully.
* @tc.type: FUNC
*/
HWTEST_F(AudioSmartPaTest, AudioFunctionSmartpaTest_001, TestSize.Level1)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, manager);
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME_OUT.c_str(), .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };
    uint32_t latencyTime = 0;
    uint32_t expectedValue = 0;

    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);
    sleep(1);
    if (audiopara.render != nullptr) {
        ret = audiopara.render->GetLatency(audiopara.render, &latencyTime);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_LT(expectedValue, latencyTime);
        FrameStatus(0);
        usleep(1000);
        ret = audiopara.render->control.Pause((AudioHandle)(audiopara.render));
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.render->control.Flush((AudioHandle)audiopara.render);
        EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
        sleep(1);
        ret = audiopara.render->control.Resume((AudioHandle)(audiopara.render));
        EXPECT_EQ(HDF_SUCCESS, ret);
        FrameStatus(1);
    }
    ret = ThreadRelease(audiopara);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioFunctionSmartpaTest_002
* @tc.desc  test Render function,set volume when playing audio file based smartPA.
* @tc.type: FUNC
*/
HWTEST_F(AudioSmartPaTest, AudioFunctionSmartpaTest_002, TestSize.Level1)
{
    int32_t ret = -1;
    float volumeMax = 1.0;
    ASSERT_NE(nullptr, manager);
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME_OUT.c_str(), .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };
    float volumeValue[10] = {0};
    float volumeArr[10] = {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0};

    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);
    sleep(1);
    if (audiopara.render != nullptr) {
        ret = audiopara.render->volume.SetVolume(audiopara.render, volumeMax);
        for (int i = 0; i < 10; i++) {
            ret = audiopara.render->volume.SetVolume(audiopara.render, volumeArr[i]);
            EXPECT_EQ(HDF_SUCCESS, ret);
            ret = audiopara.render->volume.GetVolume(audiopara.render, &volumeValue[i]);
            EXPECT_EQ(HDF_SUCCESS, ret);
            EXPECT_EQ(volumeArr[i], volumeValue[i]);
            usleep(30000);
        }
    }
    ret = ThreadRelease(audiopara);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioFunctionSmartpaTest_003
* @tc.desc  test render function by SetMute and GetMute when playing audio file based smartPA.
* @tc.type: FUNC
*/
HWTEST_F(AudioSmartPaTest, AudioFunctionSmartpaTest_003, TestSize.Level1)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, manager);
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME_OUT.c_str(), .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };

    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);
    sleep(1);
    bool muteTrue = true;
    bool muteFalse = false;
    if (audiopara.render != nullptr) {
        ret = audiopara.render->volume.SetMute(audiopara.render, muteTrue);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.render->volume.GetMute(audiopara.render, &muteTrue);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(true, muteTrue);
        sleep(1);
        ret = audiopara.render->volume.SetMute(audiopara.render, muteFalse);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.render->volume.GetMute(audiopara.render, &muteFalse);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(false, muteFalse);
    }
    ret = ThreadRelease(audiopara);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioFunctionSmartpaTest_004
* @tc.desc  test render function by Get render position when playing audio file based smartPA.
* @tc.type: FUNC
*/
HWTEST_F(AudioSmartPaTest, AudioFunctionSmartpaTest_004, TestSize.Level1)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, manager);
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME_OUT.c_str(), .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvSec = 0};

    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);
    sleep(2);
    if (audiopara.render != nullptr) {
        ret = audiopara.render->GetRenderPosition(audiopara.render, &frames, &time);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_GT(time.tvSec, timeExp);
        EXPECT_GT(frames, INITIAL_VALUE);
    }
    ret = ThreadRelease(audiopara);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioFunctionSmartpaTest_005
* @tc.desc  test render function by Get frame count and size when playing audio file based smartPA.
* @tc.type: FUNC
*/
HWTEST_F(AudioSmartPaTest, AudioFunctionSmartpaTest_005, TestSize.Level1)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, manager);
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME_OUT.c_str(), .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };
    uint64_t size = 0;
    uint64_t count = 0;
    uint64_t zero = 0;
    uint64_t sizeExpect = 0;

    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);
    sleep(1);
    if (audiopara.render != nullptr) {
        ret = audiopara.render->attr.GetFrameSize(audiopara.render, &size);
        EXPECT_EQ(HDF_SUCCESS, ret);
        sizeExpect = PcmFramesToBytes(audiopara.attrs);
        EXPECT_EQ(size, sizeExpect);

        ret = audiopara.render->attr.GetFrameCount(audiopara.render, &count);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_GT(count, zero);
    }
    ret = ThreadRelease(audiopara);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioFunctionSmartpaTest_006
* @tc.desc  test render function by SetSampleAttributes when playing audio file based smartPA.
* @tc.type: FUNC
*/
HWTEST_F(AudioSmartPaTest, AudioFunctionSmartpaTest_006, TestSize.Level1)
{
    ASSERT_NE(nullptr, manager);
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME_OUT.c_str(), .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };
    int32_t ret = -1;
    uint32_t samplerateValue = 48000;
    uint32_t channelcountValue = 1;
    struct AudioSampleAttributes attrsValue = {};

    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    sleep(1);
    if (audiopara.render != nullptr) {
        audiopara.attrs.type = AUDIO_IN_MEDIA;
        audiopara.attrs.format = AUDIO_FORMAT_TYPE_PCM_16_BIT;
        audiopara.attrs.period = DEEP_BUFFER_RENDER_PERIOD_SIZE;
        audiopara.attrs.sampleRate = 48000;
        audiopara.attrs.channelCount = 1;
        audiopara.attrs.stopThreshold = INT_32_MAX;

        ret = audiopara.render->attr.SetSampleAttributes(audiopara.render, &(audiopara.attrs));
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.render->attr.GetSampleAttributes(audiopara.render, &attrsValue);
        EXPECT_EQ(HDF_SUCCESS, ret);

        EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
        EXPECT_EQ(AUDIO_FORMAT_TYPE_PCM_16_BIT, attrsValue.format);
        EXPECT_EQ(samplerateValue, attrsValue.sampleRate);
        EXPECT_EQ(channelcountValue, attrsValue.channelCount);
        EXPECT_EQ(INT_32_MAX, attrsValue.stopThreshold);
    }
    ret = ThreadRelease(audiopara);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
*    this value.
* @tc.name  AudioFunctionSmartpaTest_009
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_ELEM_WRITE and AUDIODRV_CTL_IOCTL_ELEM_READ.
* @tc.type: FUNC
*/
HWTEST_F(AudioSmartPaTest, AudioFunctionSmartpaTest_009, TestSize.Level1)
{
    int32_t ret = -1;
    float volumevalue = 0;
    float thresholdValueMaxOut = 0;
    float thresholdValueMinOut = 0;
    float volumeBoundaryValueOut = 127.9;
    struct DevHandle *handle = nullptr;
    struct AudioHwRender *hwRender = nullptr;
    ret = BindServiceAndHwRender(hwRender, BIND_CONTROL.c_str(), ADAPTER_NAME_OUT, handle);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    thresholdValueMaxOut = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMax;
    thresholdValueMinOut = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMin;

    hwRender->renderParam.renderMode.ctlParam.volume = thresholdValueMinOut + 1;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumevalue = hwRender->renderParam.renderMode.ctlParam.volume;
    EXPECT_EQ(41, volumevalue);

    hwRender->renderParam.renderMode.ctlParam.volume = thresholdValueMaxOut - 1;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumevalue = hwRender->renderParam.renderMode.ctlParam.volume;
    EXPECT_EQ(126, volumevalue);

    hwRender->renderParam.renderMode.ctlParam.volume = volumeBoundaryValueOut;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumevalue = hwRender->renderParam.renderMode.ctlParam.volume;
    EXPECT_EQ(127, volumevalue);

    CloseServiceRender(handle);
    free(hwRender);
}
/**
*    this value.
* @tc.name  AudioFunctionSmartpaTest_010
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_ELEM_WRITE and AUDIODRV_CTL_IOCTL_ELEM_READ.
* @tc.type: FUNC
*/
HWTEST_F(AudioSmartPaTest, AudioFunctionSmartpaTest_010, TestSize.Level1)
{
    int32_t ret = -1;
    float thresholdValueMin = 0;
    float thresholdValueMax = 0;
    float volumevalue = 0;
    struct DevHandle *handle = nullptr;
    struct AudioHwRender *hwRender = nullptr;
    ret = BindServiceAndHwRender(hwRender, BIND_CONTROL.c_str(), ADAPTER_NAME_OUT, handle);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    thresholdValueMax = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMax;
    thresholdValueMin = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMin;
    hwRender->renderParam.renderMode.ctlParam.volume = thresholdValueMin;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumevalue = hwRender->renderParam.renderMode.ctlParam.volume;
    EXPECT_EQ(40, volumevalue);

    hwRender->renderParam.renderMode.ctlParam.volume = thresholdValueMax;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumevalue = hwRender->renderParam.renderMode.ctlParam.volume;
    EXPECT_EQ(127, volumevalue);

    CloseServiceRender(handle);
    free(hwRender);
}
/**
* @tc.name  AudioFunctionSmartpaTest_011
* @tc.desc  test InterfaceLibCtlRender ,cmdId is AUDIODRV_CTL_IOCTL_ELEM_WRITE and AUDIODRV_CTL_IOCTL_ELEM_READ.
* @tc.type: FUNC
*/
HWTEST_F(AudioSmartPaTest, AudioFunctionSmartpaTest_011, TestSize.Level1)
{
    int32_t ret = -1;
    float volumeThresholdValueMax = 0;
    float volumeThresholdValueMin = 0;
    struct DevHandle *handle = nullptr;
    struct AudioHwRender *hwRender = nullptr;
    ret = BindServiceAndHwRender(hwRender, BIND_CONTROL.c_str(), ADAPTER_NAME_OUT, handle);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ, &hwRender->renderParam);
    EXPECT_EQ(HDF_SUCCESS, ret);
    volumeThresholdValueMax = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMax;
    volumeThresholdValueMin = hwRender->renderParam.renderMode.ctlParam.volThreshold.volMin;

    hwRender->renderParam.renderMode.ctlParam.volume = volumeThresholdValueMax + 1;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_FAILURE, ret);

    hwRender->renderParam.renderMode.ctlParam.volume = volumeThresholdValueMin - 1;
    ret = InterfaceLibCtlRender(handle, AUDIODRV_CTL_IOCTL_ELEM_WRITE, &hwRender->renderParam);
    EXPECT_EQ(HDF_FAILURE, ret);

    CloseServiceRender(handle);
    free(hwRender);
}
/**
* @tc.name  AudioFunctionSmartpaTest_012
* @tc.desc  Test AudioAdapterInitAllPorts interface, return 0 if the ports are initialized successfully.
* @tc.type: FUNC
*/
HWTEST_F(AudioSmartPaTest, AudioFunctionSmartpaTest_012, TestSize.Level1)
{
    int32_t ret = -1;
    ASSERT_NE(nullptr, manager);
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME_OUT.c_str()
    };
    ret = OHOS::Audio::GetLoadAdapter(audiopara.manager, audiopara.portType, audiopara.adapterName,
                                      &audiopara.adapter, audiopara.audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.adapter->InitAllPorts(audiopara.adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
}
