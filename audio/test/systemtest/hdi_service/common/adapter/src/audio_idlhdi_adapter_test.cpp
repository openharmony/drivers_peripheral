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
#include "osal_mem.h"
#include "hdi_service_common.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
class AudioIdlHdiAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    struct AudioPort audioPort = {};
    static TestAudioManager *manager;
    uint32_t captureId_ = 0;
    uint32_t renderId_ = 0;
};

TestAudioManager *AudioIdlHdiAdapterTest::manager = nullptr;

void AudioIdlHdiAdapterTest::SetUpTestCase(void)
{
    manager = IAudioManagerGet(IS_STUB);
    ASSERT_NE(nullptr, manager);
}

void AudioIdlHdiAdapterTest::TearDownTestCase(void)
{
    if (manager != nullptr) {
        (void)IAudioManagerRelease(manager, IS_STUB);
    }
}

void AudioIdlHdiAdapterTest::SetUp(void) {}
void AudioIdlHdiAdapterTest::TearDown(void)
{
    if (audioPort.portName != nullptr) {
        free(audioPort.portName);
    }
    (void) memset_s(&audioPort, sizeof(struct AudioPort), 0, sizeof(struct AudioPort));
}

/**
* @tc.name  AudioAdapterInitAllPorts_001
* @tc.desc  Test AudioAdapterInitAllPorts interface, return 0 if the ports is initialize successfully.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioAdapterInitAllPorts_001, TestSize.Level0)
{
    int32_t ret;
    struct IAudioAdapter *adapter = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    IAudioAdapterRelease(adapter, IS_STUB);
}
/**
* @tc.name  AudioAdapterInitAllPortsNull_003
* @tc.desc  Test AudioAdapterInitAllPorts API, return -3/-4 if the parameter adapter is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioAdapterInitAllPortsNull_003, TestSize.Level1)
{
    int32_t ret;
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioAdapter *adapterNull = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapterNull);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    IAudioAdapterRelease(adapter, IS_STUB);;
}

/**
* @tc.name  AudioAdapterGetPortCapability_001
* @tc.desc  Test AudioAdapterGetPortCapability,return 0 if PortType is PORT_OUT.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioAdapterGetPortCapability_001, TestSize.Level0)
{
    int32_t ret;
    struct IAudioAdapter *adapter = {};
    struct AudioPortCapability *capability = nullptr;
    capability = (struct AudioPortCapability*)OsalMemCalloc(sizeof(struct AudioPortCapability));
    ASSERT_NE(nullptr, capability);
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->GetPortCapability(adapter, &audioPort, capability);
    EXPECT_EQ(HDF_SUCCESS, ret);
    if (capability->subPorts != nullptr) {
        EXPECT_NE(nullptr, capability->subPorts->desc);
    }
    TestAudioPortCapabilityFree(capability, true);
    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    IAudioAdapterRelease(adapter, IS_STUB);;
}

/**
* @tc.name  AudioAdapterGetPortCapability_002
* @tc.desc  Test AudioAdapterGetPortCapability,return 0 if PortType is PORT_IN.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioAdapterGetPortCapability_002, TestSize.Level1)
{
    int32_t ret;
    struct IAudioAdapter *adapter = {};
    struct AudioPortCapability *capability = nullptr;
    capability = (struct AudioPortCapability*)OsalMemCalloc(sizeof(struct AudioPortCapability));
    ASSERT_NE(nullptr, capability);
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->GetPortCapability(adapter, &audioPort, capability);
    EXPECT_EQ(HDF_SUCCESS, ret);

    TestAudioPortCapabilityFree(capability, true);
    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    IAudioAdapterRelease(adapter, IS_STUB);;
}

/**
* @tc.name  AudioAdapterGetPortCapabilityNull_003
* @tc.desc  Test AudioAdapterGetPortCapability, return -3/-4 if the parameter adapter is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioAdapterGetPortCapabilityNull_003, TestSize.Level1)
{
    int32_t ret;
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioAdapter *adapterNull = nullptr;
    struct AudioPortCapability *capability = nullptr;
    capability = (struct AudioPortCapability*)OsalMemCalloc(sizeof(struct AudioPortCapability));
    ASSERT_NE(nullptr, capability);
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->GetPortCapability(adapterNull, &audioPort, capability);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);

    OsalMemFree(capability);
    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    IAudioAdapterRelease(adapter, IS_STUB);;
}

/**
* @tc.name  AudioAdapterGetPortCapabilityNull_004
* @tc.desc  Test AudioAdapterGetPortCapability, return -3 if the audioPort is nullptr,
            return -1 if the audioPort is not supported.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioAdapterGetPortCapabilityNull_004, TestSize.Level1)
{
    int32_t ret;
    struct AudioPort *audioPortNull = nullptr;
    struct IAudioAdapter *adapter = nullptr;
    struct AudioPortCapability *capability = nullptr;
    capability = (struct AudioPortCapability*)OsalMemCalloc(sizeof(struct AudioPortCapability));
    ASSERT_NE(nullptr, capability);
    struct AudioPort audioPortError = {.dir = PORT_OUT, .portId = 9, .portName = strdup("AIP")};
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->GetPortCapability(adapter, audioPortNull, capability);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    ret = adapter->GetPortCapability(adapter, &audioPortError, capability);
    ASSERT_TRUE(ret == HDF_FAILURE || ret == HDF_ERR_NOT_SUPPORT);
    free(audioPortError.portName);
    OsalMemFree(capability);
    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    IAudioAdapterRelease(adapter, IS_STUB);;
}
#ifdef AUDIO_ADM_PASSTHROUGH
/**
* @tc.name  AudioAdapterGetPortCapabilityNull_005
* @tc.desc  Test AudioAdapterGetPortCapability, return -3 if capability is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioAdapterGetPortCapabilityNull_005, TestSize.Level1)
{
    int32_t ret;
    struct IAudioAdapter *adapter = nullptr;
    struct AudioPortCapability *capabilityNull = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->GetPortCapability(adapter, &audioPort, capabilityNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    IAudioAdapterRelease(adapter, IS_STUB);;
}
#endif
/**
* @tc.name  AudioAdapterSetPassthroughMode_001
* @tc.desc  test AdapterSetPassthroughMode interface, return 0 if PortType is PORT_OUT.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioAdapterSetPassthroughMode_001, TestSize.Level0)
{
    int32_t ret;
    struct IAudioAdapter *adapter = nullptr;
    AudioPortPassthroughMode modeLpcm = PORT_PASSTHROUGH_AUTO;
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->SetPassthroughMode(adapter, &audioPort, PORT_PASSTHROUGH_LPCM);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_FAILURE);
    if (ret == HDF_SUCCESS) {
        ret = adapter->GetPassthroughMode(adapter, &audioPort, &modeLpcm);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(PORT_PASSTHROUGH_LPCM, modeLpcm);
    }

    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    IAudioAdapterRelease(adapter, IS_STUB);;
}

/**
* @tc.name  AudioAdapterSetPassthroughMode_002
* @tc.desc  test AdapterSetPassthroughMode interface, return -1 if PortType is PORT_IN.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioAdapterSetPassthroughMode_002, TestSize.Level1)
{
    int32_t ret;
    struct IAudioAdapter *adapter = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->SetPassthroughMode(adapter, &audioPort, PORT_PASSTHROUGH_LPCM);
    EXPECT_EQ(HDF_FAILURE, ret);

    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    IAudioAdapterRelease(adapter, IS_STUB);;
}

/**
* @tc.name  AudioAdapterSetPassthroughModeNull_003
* @tc.desc  test AdapterSetPassthroughMode interface, return -3/-4 the parameter adapter is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioAdapterSetPassthroughModeNull_003, TestSize.Level1)
{
    int32_t ret;
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioAdapter *adapterNull = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->SetPassthroughMode(adapterNull, &audioPort, PORT_PASSTHROUGH_LPCM);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    IAudioAdapterRelease(adapter, IS_STUB);;
}

/**
* @tc.name  AudioAdapterSetPassthroughModeNull_004
* @tc.desc  test AdapterSetPassthroughMode interface, return -3 if the audioPort is nullptr,
            return -1 if the audioPort is not supported.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioAdapterSetPassthroughModeNull_004, TestSize.Level1)
{
    int32_t ret;
    struct AudioPort *audioPortNull = nullptr;
    AudioPortPassthroughMode mode = PORT_PASSTHROUGH_LPCM;
    struct IAudioAdapter *adapter = nullptr;
    struct AudioPort audioPortError = { .dir = PORT_OUT, .portId = 8, .portName = strdup("AIP1")};
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->SetPassthroughMode(adapter, audioPortNull, mode);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    ret = adapter->SetPassthroughMode(adapter, &audioPortError, mode);
    EXPECT_EQ(HDF_FAILURE, ret);
    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(audioPortError.portName);
    IAudioAdapterRelease(adapter, IS_STUB);;
}

/**
* @tc.name  AudioAdapterSetPassthroughMode_005
* @tc.desc  test AdapterSetPassthroughMode interface, return -1 if the not supported mode.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioAdapterSetPassthroughMode_005, TestSize.Level1)
{
    int32_t ret;
    struct IAudioAdapter *adapter = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->SetPassthroughMode(adapter, &audioPort, PORT_PASSTHROUGH_RAW);
    EXPECT_EQ(HDF_FAILURE, ret);

    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    IAudioAdapterRelease(adapter, IS_STUB);
}

/**
* @tc.name  AudioAdapterGetPassthroughMode_001
* @tc.desc  test AdapterGetPassthroughMode interface, return 0 if is get successfully.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioAdapterGetPassthroughMode_001, TestSize.Level0)
{
    int32_t ret;
    AudioPortPassthroughMode mode = PORT_PASSTHROUGH_AUTO;
    struct IAudioAdapter *adapter = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = adapter->SetPassthroughMode(adapter, &audioPort, PORT_PASSTHROUGH_LPCM);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_FAILURE);
    if (ret == HDF_SUCCESS) {
        ret = adapter->GetPassthroughMode(adapter, &audioPort, &mode);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(PORT_PASSTHROUGH_LPCM, mode);
    }

    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    IAudioAdapterRelease(adapter, IS_STUB);
}

/**
* @tc.name  AudioAdapterGetPassthroughModeNull_002
* @tc.desc  test AdapterGetPassthroughMode interface, return -3/-4 if the parameter adapter is nullptr..
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioAdapterGetPassthroughModeNull_002, TestSize.Level1)
{
    int32_t ret;
    AudioPortPassthroughMode mode = PORT_PASSTHROUGH_LPCM;
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioAdapter *adapterNull = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->GetPassthroughMode(adapterNull, &audioPort, &mode);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);

    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    IAudioAdapterRelease(adapter, IS_STUB);
}

/**
* @tc.name  AudioAdapterGetPassthroughModeNull_003
* @tc.desc  test AdapterGetPassthroughMode interface, return -3 if the audioPort is nullptr,
            return -1 if the audioPort is not supported.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioAdapterGetPassthroughModeNull_003, TestSize.Level1)
{
    int32_t ret;
    struct AudioPort *audioPortNull = nullptr;
    AudioPortPassthroughMode mode = PORT_PASSTHROUGH_LPCM;
    struct IAudioAdapter *adapter = nullptr;
    struct AudioPort audioPortError = { .dir = PORT_OUT, .portId = 8, .portName = strdup("AIP")};
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->GetPassthroughMode(adapter, audioPortNull, &mode);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    ret = adapter->GetPassthroughMode(adapter, &audioPortError, &mode);
    EXPECT_EQ(HDF_FAILURE, ret);
    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(audioPortError.portName);
    IAudioAdapterRelease(adapter, IS_STUB);
}

/**
* @tc.name  AudioAdapterGetPassthroughModeNull_004
* @tc.desc  test AdapterGetPassthroughMode interface, return -3 if the parameter mode is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioAdapterGetPassthroughModeNull_004, TestSize.Level1)
{
    int32_t ret;
    AudioPortPassthroughMode *modeNull = nullptr;
    struct IAudioAdapter *adapter = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->GetPassthroughMode(adapter, &audioPort, modeNull);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_FAILURE);
    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    IAudioAdapterRelease(adapter, IS_STUB);
}
/**
* @tc.name  AudioCreateCapture_001
* @tc.desc  Test AudioCreateCapture interface,Returns 0 if the IAudioCapture object is created successfully
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioCreateCapture_001, TestSize.Level0)
{
    int32_t ret;
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture, &captureId_);
    ASSERT_EQ(HDF_SUCCESS, ret);
    struct AudioDeviceDescriptor devDesc;
    InitDevDesc(devDesc, 0, PIN_IN_MIC);
    adapter->DestroyCapture(adapter, captureId_);
    IAudioCaptureRelease(capture, IS_STUB);
    free(devDesc.desc);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    IAudioAdapterRelease(adapter, IS_STUB);
}

/**
* @tc.name  AudioCreateCapture_002
* @tc.desc  test AudioCreateCapture interface:
     (1)service mode:Returns 0,if the IAudioCapture object can be created successfully which was created
     (2)passthrough mode: Returns -1,if the IAudioCapture object can't be created which was created
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioCreateCapture_002, TestSize.Level0)
{
    int32_t ret;
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioCapture *firstCapture = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    InitAttrs(attrs);
#ifndef AUDIO_SAMPLE_LOW_BITWIDTH
    attrs.format = AUDIO_FORMAT_TYPE_PCM_16_BIT;
    attrs.frameSize = AUDIO_FORMAT_TYPE_PCM_16_BIT * CHANNELCOUNT / MOVE_LEFT_NUM;
    attrs.startThreshold = DEEP_BUFFER_RENDER_PERIOD_SIZE / (attrs.format * attrs.channelCount / MOVE_LEFT_NUM);
#endif
    InitDevDesc(devDesc, audioPort.portId, PIN_IN_MIC);
    ret = adapter->CreateCapture(adapter, &devDesc, &attrs, &firstCapture, &captureId_);
    EXPECT_EQ(HDF_SUCCESS, ret);
    adapter->DestroyCapture(adapter, captureId_);
    IAudioCaptureRelease(firstCapture, IS_STUB);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    IAudioAdapterRelease(adapter, IS_STUB);
    free(devDesc.desc);
}

/**
* @tc.name  AudioCreateCapture_003
* @tc.desc  test AudioCreateCapture interface,Returns 0 if the IAudioCapture object can be created successfully
    when IAudioRender was created
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioCreateCapture_003, TestSize.Level0)
{
    int32_t ret;
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioRender *render = nullptr;
    struct IAudioCapture *capture = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor renderDevDesc = {};
    struct AudioDeviceDescriptor captureDevDesc = {};
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    InitAttrs(attrs);
    InitDevDesc(renderDevDesc, audioPort.portId, PIN_OUT_SPEAKER);
    InitDevDesc(captureDevDesc, audioPort.portId, PIN_IN_MIC);
    ret = adapter->CreateRender(adapter, &renderDevDesc, &attrs, &render, &renderId_);
    EXPECT_EQ(HDF_SUCCESS, ret);
#ifndef AUDIO_SAMPLE_LOW_BITWIDTH
    attrs.format = AUDIO_FORMAT_TYPE_PCM_16_BIT;
    attrs.frameSize = AUDIO_FORMAT_TYPE_PCM_16_BIT * CHANNELCOUNT / MOVE_LEFT_NUM;
    attrs.startThreshold = DEEP_BUFFER_RENDER_PERIOD_SIZE / (attrs.format * attrs.channelCount / MOVE_LEFT_NUM);
    ret = adapter->CreateCapture(adapter, &captureDevDesc, &attrs, &capture, &captureId_);
#endif
    EXPECT_EQ(HDF_SUCCESS, ret);
    adapter->DestroyCapture(adapter, captureId_);
    IAudioCaptureRelease(capture, IS_STUB);
    adapter->DestroyRender(adapter, renderId_);
    IAudioRenderRelease(render, IS_STUB);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    IAudioAdapterRelease(adapter, IS_STUB);
    free(renderDevDesc.desc);
    free(captureDevDesc.desc);
}

/**
* @tc.name  AudioCreateCaptureNull_005
* @tc.desc  Test AudioCreateCapture interface,Returns -3/-4 if the incoming parameter adapter is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioCreateCaptureNull_005, TestSize.Level1)
{
    int32_t ret;
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioSampleAttributes attrs = {};
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioAdapter *adapterNull = nullptr;
    struct IAudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    InitAttrs(attrs);
    ret = InitDevDesc(devDesc, audioPort.portId, PIN_IN_MIC);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->CreateCapture(adapterNull, &devDesc, &attrs, &capture, &captureId_);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    IAudioAdapterRelease(adapter, IS_STUB);
    free(devDesc.desc);
}

/**
* @tc.name  AudioCreateCaptureNull_006
* @tc.desc  Test AudioCreateCapture interface,Returns -3 if the incoming parameter desc is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioCreateCaptureNull_006, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor *devDesc = nullptr;
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    InitAttrs(attrs);
    ret = adapter->CreateCapture(adapter, devDesc, &attrs, &capture, &captureId_);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    IAudioAdapterRelease(adapter, IS_STUB);
}

/**
* @tc.name  AudioCreateCaptureNull_007
* @tc.desc  Test AudioCreateCapture interface,Returns -3 if the incoming parameter attrs is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioCreateCaptureNull_007, TestSize.Level1)
{
    int32_t ret;
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioSampleAttributes *attrs = nullptr;
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InitDevDesc(devDesc, audioPort.portId, PIN_IN_MIC);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->CreateCapture(adapter, &devDesc, attrs, &capture, &captureId_);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    IAudioAdapterRelease(adapter, IS_STUB);
    free(devDesc.desc);
}

#ifdef AUDIO_ADM_PASSTHROUGH
/**
* @tc.name  AudioCreateCaptureNull_008
* @tc.desc  Test AudioCreateCapture interface,Returns -3/-4 if the incoming parameter capture is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioCreateCaptureNull_008, TestSize.Level1)
{
    int32_t ret;
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioSampleAttributes attrs = {};
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioCapture **capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    InitAttrs(attrs);
    ret = InitDevDesc(devDesc, audioPort.portId, PIN_IN_MIC);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->CreateCapture(adapter, &devDesc, &attrs, capture);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    IAudioAdapterRelease(adapter, IS_STUB);
    free(devDesc.desc);
}
#endif
/**
* @tc.name  AudioCreateCapture_009
* @tc.desc  Test AudioCreateCapture interface,Returns -1 if the incoming parameter adapter which devDesc'pin is
* PIN_OUT_SPEAKER
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioCreateCapture_009, TestSize.Level0)
{
    int32_t ret;
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioSampleAttributes attrs = {};
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    InitAttrs(attrs);
    ret = InitDevDesc(devDesc, audioPort.portId, PIN_OUT_SPEAKER);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->CreateCapture(adapter, &devDesc, &attrs, &capture, &captureId_);
    EXPECT_EQ(HDF_FAILURE, ret);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    IAudioAdapterRelease(adapter, IS_STUB);
    free(devDesc.desc);
}

/**
* @tc.name  AudioCreateCapture_010
* @tc.desc  Test AudioCreateCapture interface,Returns -1 if the incoming parameter desc which portID is not configed
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioCreateCapture_010, TestSize.Level0)
{
    int32_t ret;
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioSampleAttributes attrs = {};
    uint32_t portId = 12; // invalid portid
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    InitAttrs(attrs);
    ret = InitDevDesc(devDesc, portId, PIN_IN_MIC);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->CreateCapture(adapter, &devDesc, &attrs, &capture, &captureId_);
    ASSERT_TRUE(ret == HDF_FAILURE || ret == HDF_SUCCESS);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    IAudioAdapterRelease(adapter, IS_STUB);
    free(devDesc.desc);
}
/**
* @tc.name  AudioCreateRender_001
* @tc.desc  test AudioCreateRender interface,return 0 if render is created successful.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioCreateRender_001, TestSize.Level0)
{
    int32_t ret;
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor renderDevDesc = {};
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    InitAttrs(attrs);
    InitDevDesc(renderDevDesc, audioPort.portId, PIN_OUT_SPEAKER);
    ret = adapter->CreateRender(adapter, &renderDevDesc, &attrs, &render, &renderId_);
    EXPECT_EQ(HDF_SUCCESS, ret);
    adapter->DestroyRender(adapter, renderId_);
    IAudioRenderRelease(render, IS_STUB);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    IAudioAdapterRelease(adapter, IS_STUB);
    free(renderDevDesc.desc);
}

/**
    * @tc.name  AudioCreateRender_003
    * @tc.desc  test AudioCreateRender interface,return -1 if the incoming parameter pins is PIN_IN_MIC.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioCreateRender_003, TestSize.Level0)
{
    int32_t ret;
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    InitAttrs(attrs);
    InitDevDesc(devDesc, audioPort.portId, PIN_IN_MIC);

    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render, &renderId_);
    EXPECT_EQ(HDF_FAILURE, ret);

    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    IAudioAdapterRelease(adapter, IS_STUB);
    free(devDesc.desc);
}

/**
* @tc.name  AudioCreateRender_004
* @tc.desc  test AudioCreateRender interface,return -1 if the incoming parameter attr is error.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioCreateRender_004, TestSize.Level0)
{
    int32_t ret;
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    InitAttrs(attrs);
    InitDevDesc(devDesc, audioPort.portId, PIN_OUT_SPEAKER);
    attrs.format = AUDIO_FORMAT_TYPE_AAC_MAIN;
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render, &renderId_);
    ASSERT_TRUE(ret == HDF_FAILURE || ret == HDF_SUCCESS);
    InitAttrs(attrs);
    attrs.type = AUDIO_IN_COMMUNICATION;
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render, &renderId_);
    EXPECT_EQ(HDF_SUCCESS, ret);

    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    IAudioAdapterRelease(adapter, IS_STUB);
    free(devDesc.desc);
}

/**
* @tc.name  AudioCreateRenderNull_005
* @tc.desc  test AudioCreateRender interface,Returns -3/-4 if the incoming parameter adapter is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioCreateRenderNull_005, TestSize.Level1)
{
    int32_t ret;
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioRender *render = nullptr;
    struct IAudioAdapter *adapterNull = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    InitAttrs(attrs);
    InitDevDesc(devDesc, audioPort.portId, PIN_OUT_SPEAKER);

    ret = adapter->CreateRender(adapterNull, &devDesc, &attrs, &render, &renderId_);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);

    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    IAudioAdapterRelease(adapter, IS_STUB);
    free(devDesc.desc);
}

/**
* @tc.name  AudioCreateRenderNull_006
* @tc.desc  test AudioCreateRender interface,Returns -3 if the incoming parameter devDesc is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioCreateRenderNull_006, TestSize.Level1)
{
    int32_t ret;
    struct IAudioRender *render = nullptr;
    struct IAudioAdapter *adapter = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor *devDescNull = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    InitAttrs(attrs);

    ret = adapter->CreateRender(adapter, devDescNull, &attrs, &render, &renderId_);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    IAudioAdapterRelease(adapter, IS_STUB);
}

/**
* @tc.name  AudioCreateRenderNull_007
* @tc.desc  test AudioCreateRender interface,Returns -3 if the incoming parameter attrs is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioCreateRenderNull_007, TestSize.Level1)
{
    int32_t ret;
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioRender *render = nullptr;
    struct AudioSampleAttributes *attrsNull = nullptr;
    struct AudioDeviceDescriptor devDesc = {};
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    InitDevDesc(devDesc, audioPort.portId, PIN_OUT_SPEAKER);

    ret = adapter->CreateRender(adapter, &devDesc, attrsNull, &render, &renderId_);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    IAudioAdapterRelease(adapter, IS_STUB);
    free(devDesc.desc);
}

#ifdef AUDIO_ADM_PASSTHROUGH
/**
* @tc.name  AudioCreateRenderNull_008
* @tc.desc  test AudioCreateRender interface,Returns -3/-4 if the incoming parameter render is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioCreateRenderNull_008, TestSize.Level1)
{
    int32_t ret;
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioRender **renderNull = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    InitAttrs(attrs);
    InitDevDesc(devDesc, audioPort.portId, PIN_OUT_SPEAKER);

    ret = adapter->CreateRender(adapter, &devDesc, &attrs, renderNull, &renderId_);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);

    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    IAudioAdapterRelease(adapter, IS_STUB);
    free(devDesc.desc);
}
#endif

/**
* @tc.name  AudioCreateRender_009
* @tc.desc  test AudioCreateRender interface,Returns -1 if the incoming parameter pins of devDesc is error.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioCreateRender_009, TestSize.Level0)
{
    int32_t ret;
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    InitAttrs(attrs);
    InitDevDesc(devDesc, audioPort.portId, PIN_OUT_SPEAKER);

    devDesc.pins = PIN_NONE;
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render, &renderId_);
    EXPECT_EQ(HDF_FAILURE, ret);

    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    IAudioAdapterRelease(adapter, IS_STUB);
    free(devDesc.desc);
}

/**
* @tc.name  AudioCreateRender_010
* @tc.desc  test AudioCreateRender interface,Returns -1 if the incoming desc which portId is not configed
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioCreateRender_010, TestSize.Level0)
{
    int32_t ret;
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    uint32_t portId = 10; // invalid portId
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    InitAttrs(attrs);
    InitDevDesc(devDesc, portId, PIN_OUT_SPEAKER);

    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render, &renderId_);
    ASSERT_TRUE(ret == HDF_FAILURE || ret == HDF_SUCCESS);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    IAudioAdapterRelease(adapter, IS_STUB);
    free(devDesc.desc);
}

/**
* @tc.name  AudioDestroyCapture_001
* @tc.desc  Test AudioDestroyCapture interface,Returns 0 if the IAudioCapture object is destroyed
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioDestroyCapture_001, TestSize.Level0)
{
    int32_t ret;
    AudioPortPin pins = PIN_IN_MIC;
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, pins, ADAPTER_NAME, &adapter, &capture, &captureId_);
    ASSERT_EQ(HDF_SUCCESS, ret);
    struct AudioDeviceDescriptor devDesc;
    InitDevDesc(devDesc, 0, PIN_IN_MIC);
    ret =adapter->DestroyCapture(adapter, captureId_);
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(devDesc.desc);
    IAudioCaptureRelease(capture, IS_STUB);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    IAudioAdapterRelease(adapter, IS_STUB);
}

/**
* @tc.name  AudioDestroyCaptureNull_002
* @tc.desc  Test AudioDestroyCapture interface,Returns -3/-4 if the incoming parameter adapter is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioDestroyCaptureNull_002, TestSize.Level1)
{
    int32_t ret;
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioAdapter *adapterNull = nullptr;
    struct IAudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture, &captureId_);
    ASSERT_EQ(HDF_SUCCESS, ret);
    struct AudioDeviceDescriptor devDesc;
    InitDevDesc(devDesc, 0, PIN_IN_MIC);
    ret = adapter->DestroyCapture(adapterNull, captureId_);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
    ret = adapter->DestroyCapture(adapter, captureId_);
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(devDesc.desc);
    IAudioCaptureRelease(capture, IS_STUB);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    IAudioAdapterRelease(adapter, IS_STUB);
}

/**
    * @tc.name  AudioDestroyRender_001
    * @tc.desc  Test AudioDestroyRender interface, return 0 if render is destroyed successful.
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioDestroyRender_001, TestSize.Level0)
{
    int32_t ret;
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render, &renderId_);
    ASSERT_EQ(HDF_SUCCESS, ret);
    struct AudioDeviceDescriptor devDesc;
    InitDevDesc(devDesc, 0, PIN_OUT_SPEAKER);
    ret = adapter->DestroyRender(adapter, renderId_);
    EXPECT_EQ(HDF_SUCCESS, ret);
    IAudioRenderRelease(render, IS_STUB);
    free(devDesc.desc);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    IAudioAdapterRelease(adapter, IS_STUB);
}
/**
    * @tc.name  AudioDestroyRenderNull_002
    * @tc.desc  Test AudioDestroyRender interface, return -3/-4 if the parameter render is nullptr.
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiAdapterTest, AudioDestroyRenderNull_002, TestSize.Level1)
{
    int32_t ret;
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioRender *render = nullptr;
    struct IAudioAdapter *adapterNull = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render, &renderId_);
    ASSERT_EQ(HDF_SUCCESS, ret);
    struct AudioDeviceDescriptor devDesc;
    InitDevDesc(devDesc, 0, PIN_OUT_SPEAKER);
    ret = adapter->DestroyRender(adapterNull, renderId_);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
    ret = adapter->DestroyRender(adapter, renderId_);
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(devDesc.desc);
    IAudioRenderRelease(render, IS_STUB);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    IAudioAdapterRelease(adapter, IS_STUB);
}
}
