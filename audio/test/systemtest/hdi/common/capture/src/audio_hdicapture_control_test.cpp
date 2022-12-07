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
#include "audio_hdicapture_control_test.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
const string ADAPTER_NAME_USB = "USB";

class AudioHdiCaptureControlTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static TestAudioManager *manager;
};

TestAudioManager *AudioHdiCaptureControlTest::manager = nullptr;

void AudioHdiCaptureControlTest::SetUpTestCase(void)
{
    manager = GetAudioManagerFuncs();
    ASSERT_NE(nullptr, manager);
}

void AudioHdiCaptureControlTest::TearDownTestCase(void) {}

void AudioHdiCaptureControlTest::SetUp(void) {}

void AudioHdiCaptureControlTest::TearDown(void) {}

/**
* @tc.name  AudioCreateCapture_001
* @tc.desc  Test AudioCreateCapture interface,Returns 0 if the AudioCapture object is created successfully
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCreateCapture_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioCreateCapture_002
* @tc.desc  test AudioCreateCapture interface:
     (1)service mode:Returns 0,if the AudioCapture object can be created successfully which was created
     (2)passthrough mode: Returns -1,if the AudioCapture object can't be created which was created
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCreateCapture_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *firstCapture = nullptr;
    struct AudioCapture *secondCapture = nullptr;
    struct AudioPort* audioPort = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor DevDesc = {};

    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrs(attrs);
    InitDevDesc(DevDesc, audioPort->portId, PIN_IN_MIC);
    ret = adapter->CreateCapture(adapter, &DevDesc, &attrs, &firstCapture);
    if (ret < 0) {
        manager->UnloadAdapter(manager, adapter);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    ret = adapter->CreateCapture(adapter, &DevDesc, &attrs, &secondCapture);
#if defined (AUDIO_ADM_SERVICE)
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyCapture(adapter, secondCapture);
#endif
#if defined (AUDIO_ADM_SO) || defined (__LITEOS__)
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
    adapter->DestroyCapture(adapter, firstCapture);
#endif
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioCreateCapture_003
* @tc.desc  test AudioCreateCapture interface,Returns 0 if the AudioCapture object can be created successfully
            when AudioRender was created
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCreateCapture_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioPort* audioPort = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor renderDevDesc = {};
    struct AudioDeviceDescriptor captureDevDesc = {};

    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrs(attrs);
    InitDevDesc(renderDevDesc, audioPort->portId, PIN_OUT_SPEAKER);
    InitDevDesc(captureDevDesc, audioPort->portId, PIN_IN_MIC);
    ret = adapter->CreateRender(adapter, &renderDevDesc, &attrs, &render);
    if (ret < 0) {
        manager->UnloadAdapter(manager, adapter);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    ret = adapter->CreateCapture(adapter, &captureDevDesc, &attrs, &capture);
    if (ret < 0) {
        adapter->DestroyRender(adapter, render);
        manager->UnloadAdapter(manager, adapter);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    adapter->DestroyRender(adapter, render);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioCreateCapture_005
* @tc.desc  Test AudioCreateCapture interface,Returns -1 if the incoming parameter adapter is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCreateCapture_005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort* capturePort = nullptr;
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioSampleAttributes attrs = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioAdapter *adapterNull = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME, &adapter, capturePort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrs(attrs);
    ret = InitDevDesc(devDesc, capturePort->portId, PIN_IN_MIC);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = adapter->CreateCapture(adapterNull, &devDesc, &attrs, &capture);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioCreateCapture_006
* @tc.desc  Test AudioCreateCapture interface,Returns -1 if the incoming parameter desc is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCreateCapture_006, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort* capturePort = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor *devDesc = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME, &adapter, capturePort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrs(attrs);
    ret = adapter->CreateCapture(adapter, devDesc, &attrs, &capture);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioCreateCapture_007
* @tc.desc  Test AudioCreateCapture interface,Returns -1 if the incoming parameter attrs is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCreateCapture_007, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort* capturePort = nullptr;
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioSampleAttributes *attrs = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME, &adapter, capturePort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = InitDevDesc(devDesc, capturePort->portId, PIN_IN_MIC);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = adapter->CreateCapture(adapter, &devDesc, attrs, &capture);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioCreateCapture_008
* @tc.desc  Test AudioCreateCapture interface,Returns -1 if the incoming parameter capture is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCreateCapture_008, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort* capturePort = nullptr;
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioSampleAttributes attrs = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture **capture = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME, &adapter, capturePort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrs(attrs);
    ret = InitDevDesc(devDesc, capturePort->portId, PIN_IN_MIC);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = adapter->CreateCapture(adapter, &devDesc, &attrs, capture);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioCreateCapture_008
* @tc.desc  Test AudioCreateCapture interface,Returns -1 if the incoming parameter adapter which port type is PORT_OUT
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCreateCapture_009, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort* capturePort = nullptr;
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioSampleAttributes attrs = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME_OUT, &adapter, capturePort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrs(attrs);
    ret = InitDevDesc(devDesc, capturePort->portId, PIN_OUT_SPEAKER);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = adapter->CreateCapture(adapter, &devDesc, &attrs, &capture);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioCreateCapture_010
* @tc.desc  Test AudioCreateCapture interface,Returns -1 if the incoming parameter desc which portID is not configured
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCreateCapture_010, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort* capturePort = nullptr;
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioSampleAttributes attrs = {};
    uint32_t portID = 12;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME, &adapter, capturePort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrs(attrs);
    ret = InitDevDesc(devDesc, portID, PIN_IN_MIC);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = adapter->CreateCapture(adapter, &devDesc, &attrs, &capture);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioDestroyCapture_001
* @tc.desc  Test AudioDestroyCapture interface,Returns 0 if the AudioCapture object is destroyed
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioDestroyCapture_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = adapter->DestroyCapture(adapter, capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioDestroyCapture_002
* @tc.desc  Test AudioDestroyCapture interface,Returns -1 if the incoming parameter adapter is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioDestroyCapture_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioAdapter *adapterNull = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = adapter->DestroyCapture(adapterNull, capture);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    ret = adapter->DestroyCapture(adapter, capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioDestroyCapture_003
* @tc.desc  Test AudioDestroyCapture interface,Returns -1 if the incoming parameter capture is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioDestroyCapture_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort* capturePort = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME, &adapter, capturePort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = adapter->DestroyCapture(adapter, capture);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioStartCapture_001
* @tc.desc  Test AudioCaptureStart interface,return 0 if the audiocapture object is started successfully
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCaptureStart_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Start((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioCaptureStart_002
* @tc.desc  Test CaptureStart interface,return -1 if the incoming parameter handle is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCaptureStart_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Start((AudioHandle)captureNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioCaptureStart_003
* @tc.desc  Test AudioCaptureStart interface,return 0 if the Audiocapturestart was successfully called twice
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCaptureStart_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Start((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Start((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_ERR_AI_BUSY, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureStop_001
    * @tc.desc  Test AudioCaptureStop interface,return 0 if the audiocapture object is stopped successfully
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCaptureStop_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartCapture(manager, &capture, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureStop_002
    * @tc.desc  Test AudioCaptureStop interface,return -4 if Audiocapturestop was successfully called twice
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCaptureStop_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartCapture(manager, &capture, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureStop_003
    * @tc.desc  Test AudioCaptureStop interface,return 0 if stop and start an audio capture successfully
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCaptureStop_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartCapture(manager, &capture, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Start((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureStop_004
    * @tc.desc  Test AudioCaptureStop interface,return -4 if the capture does not start and stop only
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCaptureStop_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioCaptureStop_005
* @tc.desc  Test CaptureStop interface, return -1 if the incoming parameter handle is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCaptureStop_005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartCapture(manager, &capture, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Stop((AudioHandle)captureNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCapturePause_001
    * @tc.desc  test HDI CapturePause interface，return 0 if the capture is paused after start
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCapturePause_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartCapture(manager, &capture, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Pause((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCapturePause_002
    * @tc.desc  Test CapturePause interface, return -1 the second time if CapturePause is called twice
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCapturePause_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartCapture(manager, &capture, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Pause((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Pause((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, ret);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCapturePause_003
    * @tc.desc  Test CapturePause interface,return -1 if the incoming parameter handle is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCapturePause_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartCapture(manager, &capture, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Pause((AudioHandle)captureNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCapturePause_004
    * @tc.desc  Test AudioRenderPause interface,return -1 if the capture is not Started and paused only.
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCapturePause_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Pause((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCapturePause_005
    * @tc.desc  Test CapturePause interface, return -1 the capture is paused after stopped.
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCapturePause_005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = AudioCreateStartCapture(manager, &capture, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Pause((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureResume_001
    * @tc.desc  Test CaptureResume interface,return 0 if the capture is resumed after paused
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCaptureResume_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartCapture(manager, &capture, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Pause((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Resume((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureResume_002
    * @tc.desc  Test CaptureResume interface,return -1 the second time if the CaptureResume is called twice
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCaptureResume_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartCapture(manager, &capture, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Pause((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Resume((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Resume((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, ret);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}

/**
    * @tc.name  AudioCaptureResume_003
    * @tc.desc  test HDI CaptureResume interface,return -1 if the capture is resumed after started
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCaptureResume_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartCapture(manager, &capture, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Resume((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, ret);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureResume_004
    * @tc.desc  Test CaptureResume interface, return -1 if the incoming parameter handle is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCaptureResume_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartCapture(manager, &capture, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Pause((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Resume((AudioHandle)captureNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioCaptureResume_005
* @tc.desc  test HDI CaptureResume interface,return -1 if the capture is resumed after stopped
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCaptureResume_005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartCapture(manager, &capture, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Resume((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioCaptureResume_006
* @tc.desc  test HDI CaptureResume interface,return -1 if the capture Continue to start after resume
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCaptureResume_006, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartCapture(manager, &capture, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Pause((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Resume((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Start((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_ERR_AI_BUSY, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioCaptureResume_007
* @tc.desc  test HDI CaptureResume interface,return 0 if the different objects is started、paused、resumed and stopped.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCaptureResume_007, TestSize.Level1)
{
    int32_t ret1 = -1;
    int32_t ret2 = -1;
    struct AudioAdapter *adapterOne = nullptr;
    struct AudioAdapter *adapterSec = nullptr;
    struct AudioCapture *captureOne = nullptr;
    struct AudioCapture *captureSec = nullptr;
    ASSERT_NE(nullptr, manager);
    ret1 = AudioCreateStartCapture(manager, &captureOne, &adapterOne, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret1);
    ret1 = captureOne->control.Pause((AudioHandle)captureOne);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret1);
    ret1 = captureOne->control.Resume((AudioHandle)captureOne);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret1);
    ret1 = captureOne->control.Stop((AudioHandle)captureOne);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret1);
    adapterOne->DestroyCapture(adapterOne, captureOne);
    manager->UnloadAdapter(manager, adapterOne);
    ret2 = AudioCreateStartCapture(manager, &captureSec, &adapterSec, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret2);
    ret2 = captureSec->control.Pause((AudioHandle)captureSec);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret2);
    ret2 = captureSec->control.Resume((AudioHandle)captureSec);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret2);
    ret2 = captureSec->control.Stop((AudioHandle)captureSec);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret2);
    adapterSec->DestroyCapture(adapterSec, captureSec);
    manager->UnloadAdapter(manager, adapterSec);
}
/**
    * @tc.name  AudioCaptureFlush_001
    * @tc.desc  Test CaptureFlush interface,return -2 if the data in the buffer is flushed successfully after stop
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCaptureFlush_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartCapture(manager, &capture, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Flush((AudioHandle)capture);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureFlush_002
    * @tc.desc  Test CaptureFlush, return -1 if the data in the buffer is flushed when handle is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureControlTest, AudioCaptureFlush_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartCapture(manager, &capture, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->control.Flush((AudioHandle)captureNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
}
