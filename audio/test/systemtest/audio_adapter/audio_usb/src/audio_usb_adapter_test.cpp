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

/**
 * @addtogroup Audio
 * @{
 *
 * @brief Test audio-related APIs, including custom data types and functions for loading drivers,
 * accessing a driver adapter.
 *
 * @since 1.0
 * @version 1.0
 */

/**
 * @file audio_hdi_common.h
 *
 * @brief Declares APIs for operations related to the audio adapter.
 *
 * @since 1.0
 * @version 1.0
 */

#include "audio_hdi_common.h"
#include "audio_usb_adapter_test.h"

using namespace std;
using namespace testing::ext;
using namespace HMOS::Audio;

namespace {
const string ADAPTER_NAME_USB = "usb";

class AudioUsbAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static TestAudioManager *(*GetAudioManager)();
    static void *handleSo;
#ifdef AUDIO_MPI_SO
    static int32_t (*SdkInit)();
    static void (*SdkExit)();
    static void *sdkSo;
#endif
};

TestAudioManager *(*AudioUsbAdapterTest::GetAudioManager)() = nullptr;
void *AudioUsbAdapterTest::handleSo = nullptr;
#ifdef AUDIO_MPI_SO
    int32_t (*AudioUsbAdapterTest::SdkInit)() = nullptr;
    void (*AudioUsbAdapterTest::SdkExit)() = nullptr;
    void *AudioUsbAdapterTest::sdkSo = nullptr;
#endif

void AudioUsbAdapterTest::SetUpTestCase(void)
{
#ifdef AUDIO_MPI_SO
    char sdkResolvedPath[] = HDF_LIBRARY_FULL_PATH("libhdi_audio_interface_lib_render");
    sdkSo = dlopen(sdkResolvedPath, RTLD_LAZY);
    if (sdkSo == nullptr) {
        return;
    }
    SdkInit = (int32_t (*)())(dlsym(sdkSo, "MpiSdkInit"));
    if (SdkInit == nullptr) {
        return;
    }
    SdkExit = (void (*)())(dlsym(sdkSo, "MpiSdkExit"));
    if (SdkExit == nullptr) {
        return;
    }
    SdkInit();
#endif
    char absPath[PATH_MAX] = {0};
    if (realpath(RESOLVED_PATH.c_str(), absPath) == nullptr) {
        return;
    }
    handleSo = dlopen(absPath, RTLD_LAZY);
    if (handleSo == nullptr) {
        return;
    }
    GetAudioManager = (TestAudioManager *(*)())(dlsym(handleSo, FUNCTION_NAME.c_str()));
    if (GetAudioManager == nullptr) {
        return;
    }
}

void AudioUsbAdapterTest::TearDownTestCase(void)
{
#ifdef AUDIO_MPI_SO
    SdkExit();
    if (sdkSo != nullptr) {
        dlclose(sdkSo);
        sdkSo = nullptr;
    }
    if (SdkInit != nullptr) {
        SdkInit = nullptr;
    }
    if (SdkExit != nullptr) {
        SdkExit = nullptr;
    }
#endif
    if (handleSo != nullptr) {
        dlclose(handleSo);
        handleSo = nullptr;
    }
    if (GetAudioManager != nullptr) {
        GetAudioManager = nullptr;
    }
}

void AudioUsbAdapterTest::SetUp(void) {}

void AudioUsbAdapterTest::TearDown(void) {}

/**
* @tc.name  Test AudioAdapterInitAllPorts API via legal input.
* @tc.number  SUB_Audio_HDI_AdapterInitAllPorts_0001
* @tc.desc  Test AudioAdapterInitAllPorts interface, return 0 if the ports is initialize successfully.
* @tc.author: liutian
*/
HWTEST_F(AudioUsbAdapterTest, SUB_Audio_HDI_AdapterInitAllPorts_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort* renderPort = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME_USB, &adapter, renderPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioAdapterGetPortCapability API when the PortType is PORT_OUT.
* @tc.number  SUB_Audio_HDI_AdapterGetPortCapability_0001
* @tc.desc  Test AudioAdapterGetPortCapability,return 0 if PortType is PORT_OUT.
* @tc.author: liutian
*/
HWTEST_F(AudioUsbAdapterTest, SUB_Audio_HDI_AdapterGetPortCapability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort* audioPort = nullptr;
    struct AudioAdapter *adapter = {};
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    struct AudioPortCapability capability = {};

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME_USB, &adapter, audioPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = adapter->GetPortCapability(adapter, audioPort, &capability);

    if (ret < 0 || capability.formats == nullptr || capability.subPorts == nullptr) {
        manager->UnloadAdapter(manager, adapter);
        ASSERT_NE(AUDIO_HAL_SUCCESS, ret);
        ASSERT_NE(nullptr, capability.formats);
        ASSERT_NE(nullptr, capability.subPorts);
    }

    if (capability.subPorts->desc == nullptr) {
        manager->UnloadAdapter(manager, adapter);
        ASSERT_NE(nullptr, capability.subPorts->desc);
    }

    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioAdapterGetPortCapability API when the PortType is PORT_IN.
* @tc.number  SUB_Audio_HDI_AdapterGetPortCapability_0002
* @tc.desc  Test AudioAdapterGetPortCapability,return 0 if PortType is PORT_IN.
* @tc.author: liutian
*/
HWTEST_F(AudioUsbAdapterTest, SUB_Audio_HDI_AdapterGetPortCapability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort* audioPort = nullptr;
    struct AudioAdapter *adapter = {};
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    struct AudioPortCapability capability = {};

    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME_USB, &adapter, audioPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = adapter->GetPortCapability(adapter, audioPort, &capability);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioAdapterGetPortCapability API when the PortType is PORT_OUT_IN.
* @tc.number  SUB_Audio_HDI_AdapterGetPortCapability_0003
* @tc.desc  Test AudioAdapterGetPortCapability,return 0 if PortType is PORT_OUT_IN.
* @tc.author: liutian
*/
HWTEST_F(AudioUsbAdapterTest, SUB_Audio_HDI_AdapterGetPortCapability_0003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort* audioPort = nullptr;
    struct AudioAdapter *adapter = {};
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    struct AudioPortCapability capability = {};

    ret = GetLoadAdapter(manager, PORT_OUT_IN, ADAPTER_NAME_USB, &adapter, audioPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = adapter->GetPortCapability(adapter, audioPort, &capability);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  Test AdapterSetPassthroughMode API when the PortType is PORT_OUT.
* @tc.number  SUB_Audio_HDI_AdapterSetPassthroughMode_0001
* @tc.desc  test AdapterSetPassthroughMode interface, return 0 if PortType is PORT_OUT.
* @tc.author: liutian
*/
HWTEST_F(AudioUsbAdapterTest, SUB_Audio_HDI_AdapterSetPassthroughMode_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort* audioPort = nullptr;
    struct AudioAdapter *adapter = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    AudioPortPassthroughMode modeLpcm = PORT_PASSTHROUGH_AUTO;

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME_USB, &adapter, audioPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = adapter->SetPassthroughMode(adapter, audioPort, PORT_PASSTHROUGH_LPCM);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = adapter->GetPassthroughMode(adapter, audioPort, &modeLpcm);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(PORT_PASSTHROUGH_LPCM, modeLpcm);

    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name Test AdapterSetPassthroughMode API when the PortType is PORT_IN.
* @tc.number  SUB_Audio_HDI_AdapterSetPassthroughMode_0002
* @tc.desc  test AdapterSetPassthroughMode interface, return -1 if PortType is PORT_IN.
* @tc.author: liutian
*/
HWTEST_F(AudioUsbAdapterTest, SUB_Audio_HDI_AdapterSetPassthroughMode_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort* audioPort = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();

    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME_USB, &adapter, audioPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = adapter->SetPassthroughMode(adapter, audioPort, PORT_PASSTHROUGH_LPCM);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  Test AdapterGetPassthroughMode API via legal input
* @tc.number  SUB_Audio_HDI_AdapterGetPassthroughMode_0001
* @tc.desc  test AdapterGetPassthroughMode interface, return 0 if is get successfully.
* @tc.author: liutian
*/
HWTEST_F(AudioUsbAdapterTest, SUB_Audio_HDI_AdapterGetPassthroughMode_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort* audioPort = nullptr;
    AudioPortPassthroughMode mode = PORT_PASSTHROUGH_AUTO;
    struct AudioAdapter *adapter = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME_USB, &adapter, audioPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = adapter->SetPassthroughMode(adapter, audioPort, PORT_PASSTHROUGH_LPCM);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = adapter->GetPassthroughMode(adapter, audioPort, &mode);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(PORT_PASSTHROUGH_LPCM, mode);

    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  Test AudioCreateCapture API via legal input
* @tc.number  SUB_Audio_HDI_AudioCreateCapture_0001
* @tc.desc  Test AudioCreateCapture interface,Returns 0 if the AudioCapture object is created successfully
* @tc.author: liweiming
*/
HWTEST_F(AudioUsbAdapterTest, SUB_Audio_HDI_AudioCreateCapture_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    TestAudioManager* manager = GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME_USB, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioCreateCapture API via creating a capture object when a render object was created
* @tc.number  SUB_Audio_HDI_AudioCreateCapture_0002
* @tc.desc  test AudioCreateCapture interface:
     (1)service mode:Returns 0,if the AudioCapture object can be created successfully which was created
     (2)passthrough mode: Returns -1,if the AudioCapture object can't be created which was created
*/
HWTEST_F(AudioUsbAdapterTest, SUB_Audio_HDI_AudioCreateCapture_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *firstCapture = nullptr;
    struct AudioCapture *secondCapture = nullptr;
    struct AudioPort* audioPort = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor DevDesc = {};

    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT_IN, ADAPTER_NAME_USB, &adapter, audioPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrs(attrs);
    InitDevDesc(DevDesc, audioPort->portId, PIN_IN_MIC);
    ret = adapter->CreateCapture(adapter, &DevDesc, &attrs, &firstCapture);
    if (ret < 0) {
        manager->UnloadAdapter(manager, adapter);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    }
    ret = adapter->CreateCapture(adapter, &DevDesc, &attrs, &secondCapture);
#if defined (AUDIO_ADM_SERVICE) || defined (AUDIO_MPI_SERVICE)
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyCapture(adapter, secondCapture);
#endif
#if defined (AUDIO_ADM_SO) || defined (AUDIO_MPI_SO) || defined (__LITEOS__)
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
    adapter->DestroyCapture(adapter, firstCapture);
#endif
    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  Test AudioDestroyCapture API via legal input
* @tc.number  SUB_Audio_HDI_AudioDestroyCapture_0001
* @tc.desc  Test AudioDestroyCapture interface,Returns 0 if the AudioCapture object is destroyed
* @tc.author: liweiming
*/
HWTEST_F(AudioUsbAdapterTest, SUB_Audio_HDI_AudioDestroyCapture_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    TestAudioManager* manager = GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME_USB, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = adapter->DestroyCapture(adapter, capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test AudioCreateRender API via legal input.
    * @tc.number  SUB_Audio_HDI_CreateRender_0001
    * @tc.desc  test AudioCreateRender interface,return 0 if render is created successful.
    * @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioUsbAdapterTest, SUB_Audio_HDI_CreateRender_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test AudioDestroyRender API via legal input.
    * @tc.number  SUB_Audio_HDI_DestroyRender_0001
    * @tc.desc  Test AudioDestroyRender interface, return 0 if render is destroyed successful.
    * @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioUsbAdapterTest, SUB_Audio_HDI_DestroyRender_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    TestAudioManager* manager = GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME_USB, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = adapter->DestroyRender(adapter, render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    manager->UnloadAdapter(manager, adapter);
}
}
