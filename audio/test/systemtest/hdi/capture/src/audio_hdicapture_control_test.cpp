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
#include "audio_hdicapture_control_test.h"

using namespace std;
using namespace testing::ext;
using namespace HMOS::Audio;

namespace {
const string AUDIO_CAPTURE_FILE = "//bin/audiocapturetest.wav";
const string ADAPTER_NAME = "hdmi";
const string ADAPTER_NAME2 = "usb";
const string ADAPTER_NAME3 = "internal";

class AudioHdiCaptureControlTest : public testing::Test {
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
    int32_t AudioCreateRender(enum AudioPortPin pins, struct AudioManager manager, struct AudioAdapter *adapter,
                              const struct AudioPort renderPort, struct AudioRender **render) const;
    int32_t AudioCaptureStart(const string path, struct AudioCapture *capture) const;
};

void AudioHdiCaptureControlTest::SetUpTestCase(void) {}

void AudioHdiCaptureControlTest::TearDownTestCase(void) {}

void AudioHdiCaptureControlTest::SetUp(void)
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

void AudioHdiCaptureControlTest::TearDown(void)
{
    if (GetAudioManager != nullptr) {
        GetAudioManager = nullptr;
    }
}

int32_t AudioHdiCaptureControlTest::GetLoadAdapter(struct AudioManager manager, enum AudioPortDirection portType,
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

int32_t AudioHdiCaptureControlTest::AudioCreateCapture(enum AudioPortPin pins, struct AudioManager manager,
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

int32_t AudioHdiCaptureControlTest::AudioCreateRender(enum AudioPortPin pins, struct AudioManager manager,
    struct AudioAdapter *adapter, const struct AudioPort renderPort, struct AudioRender **render) const
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    if (adapter == nullptr || adapter->CreateRender == nullptr || render == nullptr) {
        return HDF_FAILURE;
    }
    ret = InitAttrs(attrs);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    ret = InitDevDesc(devDesc, renderPort.portId, pins);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, render);
    if (ret < 0 || *render == nullptr) {
        manager.UnloadAdapter(&manager, adapter);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureControlTest::AudioCaptureStart(const string path, struct AudioCapture *capture) const
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

/**
* @tc.name  Test AudioCreateCapture API via legal input
* @tc.number  SUB_Audio_HDI_AudioCreateCapture_0001
* @tc.desc  Test AudioCreateCapture interface,Returns 0 if the AudioCapture object is created successfully
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_AudioCreateCapture_0001, TestSize.Level1)
{
    int32_t ret = -1;
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
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    EXPECT_EQ(HDF_SUCCESS, ret);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioCreateCapture API via creating a capture object when a render object was created
* @tc.number  SUB_Audio_HDI_AudioCreateCapture_0003
* @tc.desc  test AudioCreateCapture interface,Returns 0 if the AudioCapture object can be created successfully
            when AudioRender was created
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_AudioCreateCapture_0003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort audioPort = {};
    enum AudioPortDirection portType = PORT_OUT_IN;
    enum AudioPortPin pinsRender = PIN_OUT_SPEAKER;
    enum AudioPortPin pinsCapture = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(pinsRender, manager, adapter, audioPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioCreateCapture(pinsCapture, manager, audioPort, adapter, &capture);
    if (ret < 0) {
        adapter->DestroyRender(adapter, render);
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    adapter->DestroyRender(adapter, render);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioCreateCapture API via creating two capture objects
* @tc.number  SUB_Audio_HDI_AudioCreateCapture_0004
* @tc.desc  Test AudioCreateCapture interface,return 0 if the the two audiocapture objects are created successfully
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_AudioCreateCapture_0004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort capturePortFirst = {};
    struct AudioPort capturePortSecond = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapterFirst = nullptr;
    struct AudioAdapter *adapterSecond = nullptr;
    struct AudioCapture *captureFirst = nullptr;
    struct AudioCapture *captureSecond = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapterFirst, capturePortFirst);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME3, &adapterSecond, capturePortSecond);
    if (ret < 0){
        manager.UnloadAdapter(&manager, adapterFirst);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioCreateCapture(pins, manager, capturePortFirst, adapterFirst, &captureFirst);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapterFirst);
        manager.UnloadAdapter(&manager, adapterSecond);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioCreateCapture(pins, manager, capturePortSecond, adapterSecond, &captureSecond);
    if (ret < 0) {
        adapterFirst->DestroyCapture(adapterFirst, captureFirst);
        manager.UnloadAdapter(&manager, adapterFirst);
        manager.UnloadAdapter(&manager, adapterSecond);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    adapterFirst->DestroyCapture(adapterFirst, captureFirst);
    adapterSecond->DestroyCapture(adapterSecond, captureSecond);
    manager.UnloadAdapter(&manager, adapterFirst);
    manager.UnloadAdapter(&manager, adapterSecond);
}
/**
* @tc.name  Test AudioCreateCapture API via setting the incoming parameter adapter is nullptr
* @tc.number  SUB_Audio_HDI_AudioCreateCapture_0005
* @tc.desc  Test AudioCreateCapture interface,Returns -1 if the incoming parameter adapter is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_AudioCreateCapture_0005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort capturePort = {};
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioSampleAttributes attrs = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioAdapter *adapterNull = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InitAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InitDevDesc(devDesc, capturePort.portId, pins);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->CreateCapture(adapterNull, &devDesc, &attrs, &capture);
    EXPECT_EQ(HDF_FAILURE, ret);

    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioCreateCapture API via setting the incoming parameter desc is nullptr
* @tc.number  SUB_Audio_HDI_AudioCreateCapture_0006
* @tc.desc  Test AudioCreateCapture interface,Returns -1 if the incoming parameter desc is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_AudioCreateCapture_0006, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort capturePort = {};
    struct AudioSampleAttributes attrs = {};
    enum AudioPortDirection portType = PORT_IN;
    struct AudioDeviceDescriptor *devDesc = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InitAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->CreateCapture(adapter, devDesc, &attrs, &capture);
    EXPECT_EQ(HDF_FAILURE, ret);

    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioCreateCapture API via setting the incoming parameter attrs is nullptr
* @tc.number  SUB_Audio_HDI_AudioCreateCapture_0007
* @tc.desc  Test AudioCreateCapture interface,Returns -1 if the incoming parameter attrs is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_AudioCreateCapture_0007, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort capturePort = {};
    struct AudioDeviceDescriptor devDesc = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioSampleAttributes *attrs = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InitDevDesc(devDesc, capturePort.portId, pins);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->CreateCapture(adapter, &devDesc, attrs, &capture);
    EXPECT_EQ(HDF_FAILURE, ret);

    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioCreateCapture API via setting the incoming parameter capture is nullptr
* @tc.number  SUB_Audio_HDI_AudioCreateCapture_0008
* @tc.desc  Test AudioCreateCapture interface,Returns -1 if the incoming parameter capture is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_AudioCreateCapture_0008, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort capturePort = {};
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioSampleAttributes attrs = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture **capture = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InitAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InitDevDesc(devDesc, capturePort.portId, pins);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->CreateCapture(adapter, &devDesc, &attrs, capture);
    EXPECT_EQ(HDF_FAILURE, ret);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioCreateCapture API via setting the incoming parameter adapter which port type is PORT_OUT
* @tc.number  SUB_Audio_HDI_AudioCreateCapture_0008
* @tc.desc  Test AudioCreateCapture interface,Returns -1 if the incoming parameter adapter which port type is PORT_OUT
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_AudioCreateCapture_0009, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort capturePort = {};
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioSampleAttributes attrs = {};
    enum AudioPortDirection portType = PORT_OUT;
    enum AudioPortPin pins = PIN_OUT_SPEAKER;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InitAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InitDevDesc(devDesc, capturePort.portId, pins);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->CreateCapture(adapter, &devDesc, &attrs, &capture);
    EXPECT_EQ(HDF_FAILURE, ret);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioDestroyCapture API via legal input
* @tc.number  SUB_Audio_HDI_AudioDestroyCapture_0001
* @tc.desc  Test AudioDestroyCapture interface,Returns 0 if the AudioCapture object is destroyed
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_AudioDestroyCapture_0001, TestSize.Level1)
{
    int32_t ret = -1;
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
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    };
    ret = adapter->DestroyCapture(adapter, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioDestroyCapture API via setting the incoming parameter adapter is nullptr
* @tc.number  SUB_Audio_HDI_AudioDestroyCapture_0002
* @tc.desc  Test AudioDestroyCapture interface,Returns -1 if the incoming parameter adapter is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_AudioDestroyCapture_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioAdapter *adapterNull = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = adapter->DestroyCapture(adapterNull, capture);
    EXPECT_EQ(HDF_FAILURE, ret);
    ret = adapter->DestroyCapture(adapter, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioDestroyCapture API via setting the incoming parameter capture is nullptr
* @tc.number  SUB_Audio_HDI_AudioDestroyCapture_0003
* @tc.desc  Test AudioDestroyCapture interface,Returns -1 if the incoming parameter capture is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_AudioDestroyCapture_0003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = adapter->DestroyCapture(adapter, capture);
    EXPECT_EQ(HDF_FAILURE, ret);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioCaptureStart API via legal input
* @tc.number  SUB_Audio_HDI_StartCapture_0001
* @tc.desc  Test AudioCaptureStart interface,return 0 if the audiocapture object is started successfully
* @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_CaptureStart_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort capturePort = {};
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();

    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME3, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = capture->control.Start((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test CaptureStart API via setting the incoming parameter handle is nullptr
* @tc.number  SUB_Audio_HDI_CaptureStart_0002
* @tc.desc  Test CaptureStart interface,return -1 if the incoming parameter handle is nullptr
* @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_CaptureStart_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort capturePort = {};
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();

    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME3, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = capture->control.Start((AudioHandle)captureNull);
    EXPECT_EQ(HDF_FAILURE, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioCaptureStart API via start two capture object continuously
* @tc.number  SUB_Audio_HDI_CaptureStart_0003
* @tc.desc  Test AudioCaptureStart interface,return 0 if the Audiocapturestart was successfully called twice
* @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_CaptureStart_0003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort capturePort = {};
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();

    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME3, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = capture->control.Start((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->control.Start((AudioHandle)capture);
    EXPECT_EQ(HDF_FAILURE, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test AudioCaptureStop API via legal input
    * @tc.number  SUB_Audio_HDI_CaptureStop_0001
    * @tc.desc  Test AudioCaptureStop interface,return 0 if the audiocapture object is stopped successfully
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_CaptureStop_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort capturePort = {};
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME3, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test AudioCaptureStop API via stop two capture object continuously
    * @tc.number  SUB_Audio_HDI_CaptureStop_0002
    * @tc.desc  Test AudioCaptureStop interface,return -4 if Audiocapturestop was successfully called twice
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_CaptureStop_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort capturePort = {};
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();

    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME3, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, ret);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test AudioCaptureStop API via start an audio capture after stopping
    * @tc.number  SUB_Audio_HDI_CaptureStop_0003
    * @tc.desc  Test AudioCaptureStop interface,return 0 if stop and start an audio capture successfully
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_CaptureStop_0003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort capturePort = {};
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();

    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME3, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->control.Start((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test AudioCaptureStop API via the capture does not start and stop only
    * @tc.number  SUB_Audio_HDI_CaptureStop_0004
    * @tc.desc  Test AudioCaptureStop interface,return -4 if the capture does not start and stop only
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_CaptureStop_0004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort capturePort = {};
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME3, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, ret);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test CapturePause API via legal input
    * @tc.number  SUB_Audio_HDI_CapturePause_0001
    * @tc.desc  test HDI CapturePause interface，return 0 if the capture is paused after start
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_CapturePause_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort capturePort = {};
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME3, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->control.Pause((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test CapturePause API via the interface is called twice in a row
    * @tc.number  SUB_Audio_HDI_CapturePause_0002
    * @tc.desc  Test CapturePause interface, return -1 the second time if CapturePause is called twice
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_CapturePause_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort capturePort = {};
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME3, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->control.Pause((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->control.Pause((AudioHandle)capture);
    EXPECT_EQ(HDF_FAILURE, ret);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test CapturePause API via setting the incoming parameter handle is nullptr
    * @tc.number  SUB_Audio_HDI_CapturePause_0003
    * @tc.desc  Test CapturePause interface,return -1 if the incoming parameter handle is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_CapturePause_0003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort capturePort = {};
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME3, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->control.Pause((AudioHandle)captureNull);
    EXPECT_EQ(HDF_FAILURE, ret);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test CapturePause API via the capture is not Started and paused only.
    * @tc.number  SUB_Audio_HDI_CapturePause_0004
    * @tc.desc  Test AudioRenderPause interface,return -1 if the capture is not Started and paused only.
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_CapturePause_0004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort capturePort = {};
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME3, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = capture->control.Pause((AudioHandle)capture);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test CapturePause API via the capture is paused after stoped.
    * @tc.number  SUB_Audio_HDI_CapturePause_0005
    * @tc.desc  Test CapturePause interface, return -1 the capture is paused after stoped.
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_CapturePause_0005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort capturePort = {};
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();

    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME3, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->control.Pause((AudioHandle)capture);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test CaptureResume API via legal input
    * @tc.number  SUB_Audio_HDI_CaptureResume_0001
    * @tc.desc  Test CaptureResume interface,return 0 if the capture is resumed after paused
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_CaptureResume_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort capturePort = {};
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME3, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->control.Pause((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->control.Resume((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test CaptureResume API via the interface is called twice in a row
    * @tc.number  SUB_Audio_HDI_CaptureResume_0002
    * @tc.desc  Test CaptureResume interface,return -1 the second time if the CaptureResume is called twice
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_CaptureResume_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort capturePort = {};
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME3, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->control.Pause((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->control.Resume((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->control.Resume((AudioHandle)capture);
    EXPECT_EQ(HDF_FAILURE, ret);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test CaptureResume API via the capture is resumed after started
    * @tc.number  SUB_Audio_HDI_CaptureResume_0003
    * @tc.desc  test HDI CaptureResume interface,return -1 if the capture is resumed after started
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_CaptureResume_0003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort capturePort = {};
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME3, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->control.Resume((AudioHandle)capture);
    EXPECT_EQ(HDF_FAILURE, ret);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test CaptureResume API via setting the incoming parameter handle is nullptr
    * @tc.number  SUB_Audio_HDI_CaptureResume_0004
    * @tc.desc  Test CaptureResume interface, return -1 if the incoming parameter handle is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_CaptureResume_0004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort capturePort = {};
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME3, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->control.Pause((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->control.Resume((AudioHandle)captureNull);
    EXPECT_EQ(HDF_FAILURE, ret);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test CaptureResume API via the capture is resumed after stopped
* @tc.number  SUB_Audio_HDI_CaptureResume_0005
* @tc.desc  test HDI CaptureResume interface,return -1 if the capture is resumed after stopped
* @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_CaptureResume_0005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort capturePort = {};
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME3, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->control.Resume((AudioHandle)capture);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test CaptureResume API via the capture Continue to start after resume
* @tc.number  SUB_Audio_HDI_CaptureResume_0006
* @tc.desc  test HDI CaptureResume interface,return -1 if the capture Continue to start after resume
* @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_CaptureResume_0006, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort capturePort = {};
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME3, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->control.Pause((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->control.Resume((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_FAILURE, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test RenderResume API via the different capture objects is started、paused、resumed and stopped.
* @tc.number  SUB_Audio_HDI_CaptureResume_0007
* @tc.desc  test HDI CaptureResume interface,return 0 if the different objects is started、paused、resumed and stopped.
* @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_CaptureResume_0007, TestSize.Level1)
{
    struct AudioManager manager = {};
    struct AudioAdapter *adapterOne = nullptr;
    struct AudioAdapter *adapterSec = nullptr;
    struct AudioPort capturePortOne = {};
    struct AudioPort capturePortSec = {};
    struct AudioCapture *captureOne = nullptr;
    struct AudioCapture *captureSec = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    int32_t ret1 = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME2, &adapterOne, capturePortOne);
    ASSERT_EQ(HDF_SUCCESS, ret1);
    int32_t ret2 = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME3, &adapterSec, capturePortSec);
    ASSERT_EQ(HDF_SUCCESS, ret2);
    ret1 = AudioCreateCapture(PIN_IN_MIC, manager, capturePortOne, adapterOne, &captureOne);
    if (ret1 < 0) {
        manager.UnloadAdapter(&manager, adapterOne);
        manager.UnloadAdapter(&manager, adapterSec);
        ASSERT_EQ(HDF_SUCCESS, ret1);
    }
    ret2 = AudioCreateCapture(PIN_IN_MIC, manager, capturePortSec, adapterSec, &captureSec);
    if (ret2 < 0) {
        adapterOne->DestroyCapture(adapterOne, captureOne);
        manager.UnloadAdapter(&manager, adapterOne);
        manager.UnloadAdapter(&manager, adapterSec);
        ASSERT_EQ(HDF_SUCCESS, ret2);
    }
    ret1 = AudioCaptureStart(AUDIO_CAPTURE_FILE, captureOne);
    EXPECT_EQ(HDF_SUCCESS, ret1);
    ret2 = AudioCaptureStart(AUDIO_CAPTURE_FILE, captureSec);
    EXPECT_EQ(HDF_SUCCESS, ret2);
    ret1 = captureOne->control.Pause((AudioHandle)captureOne);
    EXPECT_EQ(HDF_SUCCESS, ret1);
    ret2 = captureSec->control.Pause((AudioHandle)captureSec);
    EXPECT_EQ(HDF_SUCCESS, ret2);
    ret1 = captureOne->control.Resume((AudioHandle)captureOne);
    EXPECT_EQ(HDF_SUCCESS, ret1);
    ret2 = captureSec->control.Resume((AudioHandle)captureSec);
    EXPECT_EQ(HDF_SUCCESS, ret2);
    ret1 = captureOne->control.Stop((AudioHandle)captureOne);
    EXPECT_EQ(HDF_SUCCESS, ret1);
    ret2 = captureSec->control.Stop((AudioHandle)captureSec);
    EXPECT_EQ(HDF_SUCCESS, ret2);
    adapterOne->DestroyCapture(adapterOne, captureOne);
    adapterSec->DestroyCapture(adapterSec, captureSec);
    manager.UnloadAdapter(&manager, adapterOne);
    manager.UnloadAdapter(&manager, adapterSec);
}
/**
    * @tc.name  Test CaptureFlush API via legal input Verify that the data in the buffer is flushed after stop
    * @tc.number  SUB_Audio_HDI_CaptureFlush_0001
    * @tc.desc  Test CaptureFlush interface,return -2 if the data in the buffer is flushed successfully after stop
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_CaptureFlush_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort capturePort = {};
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME3, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->control.Flush((AudioHandle)capture);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test CaptureFlush that the data in the buffer is flushed when handle is nullptr
    * @tc.number  SUB_Audio_HDI_CaptureFlush_0002
    * @tc.desc  Test CaptureFlush, return -1 if the data in the buffer is flushed when handle is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureControlTest, SUB_Audio_HDI_CaptureFlush_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort capturePort = {};
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME3, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->control.Flush((AudioHandle)captureNull);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
}