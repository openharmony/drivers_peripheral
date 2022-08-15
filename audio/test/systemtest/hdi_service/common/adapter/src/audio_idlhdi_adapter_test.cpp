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
    static TestAudioManager *(*GetAudioManager)(const char *);
    static TestAudioManager *manager;
    static void *handle;
    static void (*AudioManagerRelease)(struct AudioManager *);
    static void (*AudioAdapterRelease)(struct AudioAdapter *);
    static void (*AudioRenderRelease)(struct AudioRender *);
    static void (*AudioCaptureRelease)(struct AudioCapture *);
};

TestAudioManager *(*AudioIdlHdiAdapterTest::GetAudioManager)(const char *) = nullptr;
TestAudioManager *AudioIdlHdiAdapterTest::manager = nullptr;
void *AudioIdlHdiAdapterTest::handle = nullptr;
void (*AudioIdlHdiAdapterTest::AudioManagerRelease)(struct AudioManager *) = nullptr;
void (*AudioIdlHdiAdapterTest::AudioAdapterRelease)(struct AudioAdapter *) = nullptr;
void (*AudioIdlHdiAdapterTest::AudioRenderRelease)(struct AudioRender *) = nullptr;
void (*AudioIdlHdiAdapterTest::AudioCaptureRelease)(struct AudioCapture *) = nullptr;

void AudioIdlHdiAdapterTest::SetUpTestCase(void)
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
    AudioManagerRelease = (void (*)(struct AudioManager *))(dlsym(handle, "AudioManagerRelease"));
    ASSERT_NE(nullptr, AudioManagerRelease);
    AudioAdapterRelease = (void (*)(struct AudioAdapter *))(dlsym(handle, "AudioAdapterRelease"));
    ASSERT_NE(nullptr, AudioAdapterRelease);
    AudioCaptureRelease = (void (*)(struct AudioCapture *))(dlsym(handle, "AudioCaptureRelease"));
    ASSERT_NE(nullptr, AudioCaptureRelease);
    AudioRenderRelease = (void (*)(struct AudioRender *))(dlsym(handle, "AudioRenderRelease"));
    ASSERT_NE(nullptr, AudioRenderRelease);
}

void AudioIdlHdiAdapterTest::TearDownTestCase(void)
{
    if (AudioManagerRelease != nullptr) {
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

void AudioIdlHdiAdapterTest::SetUp(void) {}
void AudioIdlHdiAdapterTest::TearDown(void)
{
    if (audioPort.portName != nullptr) {
        free(audioPort.portName);
    }
    (void) memset_s(&audioPort, sizeof(struct AudioPort), 0, sizeof(struct AudioPort));
}

/**
* @tc.name  Test AudioAdapterInitAllPorts API via legal input.
* @tc.number  SUB_Audio_HDI_AdapterInitAllPorts_001
* @tc.desc  Test AudioAdapterInitAllPorts interface, return 0 if the ports is initialize successfully.
* @tc.author shijie
*/

HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_AdapterInitAllPorts_001, TestSize.Level1)
{
    int32_t ret;
    struct AudioAdapter *adapter = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioAdapterRelease(adapter);
}

/**
* @tc.name  Test AudioAdapterInitAllPorts API when loads two adapters.
* @tc.number  SUB_Audio_HDI_AdapterInitAllPorts_002
* @tc.desc  Test AudioAdapterInitAllPorts interface, return 0 if loads two adapters successfully.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_AdapterInitAllPorts_002, TestSize.Level1)
{
    int32_t ret;
    int32_t ret2 = -1;
    struct AudioPort audioPort2 = {};
    struct AudioAdapter *adapter1 = nullptr;
    struct AudioAdapter *adapter2 = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter1, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter1);
    ret2 = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME_OUT, &adapter2, audioPort2);
    if (ret2 < 0 || adapter2 == nullptr) {
        if (audioPort2.portName != nullptr) {
            free(audioPort2.portName);
        }
        manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
        AudioAdapterRelease(adapter1);
        ASSERT_EQ(HDF_SUCCESS, ret2);
    }
    ret = adapter1->InitAllPorts(adapter1);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret2 = adapter2->InitAllPorts(adapter2);
    EXPECT_EQ(HDF_SUCCESS, ret2);

    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret2 = manager->UnloadAdapter(manager, ADAPTER_NAME_OUT.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret2);

    AudioAdapterRelease(adapter1);
    AudioAdapterRelease(adapter2);
    free(audioPort2.portName);
}

/**
* @tc.name  Test AudioAdapterInitAllPorts API when the parameter adapter is nullptr.
* @tc.number  SUB_Audio_HDI_AdapterInitAllPorts_Null_003
* @tc.desc  Test AudioAdapterInitAllPorts API, return -3/-4 if the parameter adapter is nullptr.
* @tc.author: shijie
*/

HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_AdapterInitAllPorts_Null_003, TestSize.Level1)
{
    int32_t ret;
    struct AudioAdapter *adapter = nullptr;
    struct AudioAdapter *adapterNull = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapterNull);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioAdapterRelease(adapter);
}

/**
* @tc.name  Test AudioAdapterGetPortCapability API when the PortType is PORT_OUT.
* @tc.number  SUB_Audio_HDI_AdapterGetPortCapability_001
* @tc.desc  Test AudioAdapterGetPortCapability,return 0 if PortType is PORT_OUT.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_AdapterGetPortCapability_001, TestSize.Level1)
{
    int32_t ret;
    struct AudioAdapter *adapter = {};
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
    EXPECT_NE(nullptr, capability->formats);
    EXPECT_NE(nullptr, capability->subPorts);
    if (capability->subPorts != nullptr) {
        EXPECT_NE(nullptr, capability->subPorts->desc);
    }
    TestAudioPortCapabilityFree(capability, true);
    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioAdapterRelease(adapter);
}

/**
* @tc.name  Test AudioAdapterGetPortCapability API when the PortType is PORT_IN.
* @tc.number  SUB_Audio_HDI_AdapterGetPortCapability_002
* @tc.desc  Test AudioAdapterGetPortCapability,return 0 if PortType is PORT_IN.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_AdapterGetPortCapability_002, TestSize.Level1)
{
    int32_t ret;
    struct AudioAdapter *adapter = {};
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
    AudioAdapterRelease(adapter);
}

/**
* @tc.name  Test AudioAdapterGetPortCapability API, when the parameter adapter is nullptr.
* @tc.number  SUB_Audio_HDI_AdapterGetPortCapability_Null_003
* @tc.desc  Test AudioAdapterGetPortCapability, return -3/-4 if the parameter adapter is nullptr.
* @tc.author: shjie
*/

HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_AdapterGetPortCapability_Null_003, TestSize.Level1)
{
    int32_t ret;
    struct AudioAdapter *adapter = nullptr;
    struct AudioAdapter *adapterNull = nullptr;
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
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);

    OsalMemFree(capability);
    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioAdapterRelease(adapter);
}

/**
* @tc.name  Test AudioAdapterGetPortCapability API when the audioPort is nullptr or not supported.
* @tc.number  SUB_Audio_HDI_AdapterGetPortCapability_Null_004
* @tc.desc  Test AudioAdapterGetPortCapability, return -3 if the audioPort is nullptr,
            return -1 if the audioPort is not supported.
* @tc.author: shijie
*/

HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_AdapterGetPortCapability_Null_004, TestSize.Level1)
{
    int32_t ret;
    struct AudioPort *audioPortNull = nullptr;
    struct AudioAdapter *adapter = nullptr;
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
    EXPECT_EQ(HDF_FAILURE, ret);
    free(audioPortError.portName);
    OsalMemFree(capability);
    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioAdapterRelease(adapter);
}
#ifdef AUDIO_ADM_PASSTHROUGH
/**
* @tc.name  Test AudioAdapterGetPortCapability API when the capability is nullptr.
* @tc.number  SUB_Audio_HDI_AdapterGetPortCapability_Null_005
* @tc.desc  Test AudioAdapterGetPortCapability, return -3 if capability is nullptr.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_AdapterGetPortCapability_Null_005, TestSize.Level1)
{
    int32_t ret;
    struct AudioAdapter *adapter = nullptr;
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
    AudioAdapterRelease(adapter);
}
#endif
/**
* @tc.name  Test AdapterSetPassthroughMode API when the PortType is PORT_OUT.
* @tc.number  SUB_Audio_HDI_AdapterSetPassthroughMode_001
* @tc.desc  test AdapterSetPassthroughMode interface, return 0 if PortType is PORT_OUT.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_AdapterSetPassthroughMode_001, TestSize.Level1)
{
    int32_t ret;
    struct AudioAdapter *adapter = nullptr;
    AudioPortPassthroughMode modeLpcm = PORT_PASSTHROUGH_AUTO;
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->SetPassthroughMode(adapter, &audioPort, PORT_PASSTHROUGH_LPCM);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->GetPassthroughMode(adapter, &audioPort, &modeLpcm);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(PORT_PASSTHROUGH_LPCM, modeLpcm);

    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioAdapterRelease(adapter);
}

/**
* @tc.name Test AdapterSetPassthroughMode API when the PortType is PORT_IN.
* @tc.number  SUB_Audio_HDI_AdapterSetPassthroughMode_002
* @tc.desc  test AdapterSetPassthroughMode interface, return -1 if PortType is PORT_IN.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_AdapterSetPassthroughMode_002, TestSize.Level1)
{
    int32_t ret;
    struct AudioAdapter *adapter = nullptr;
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
    AudioAdapterRelease(adapter);
}

/**
* @tc.name  Test AdapterSetPassthroughMode API when the parameter adapter is nullptr.
* @tc.number  SUB_Audio_HDI_AdapterSetPassthroughMode_Null_003
* @tc.desc  test AdapterSetPassthroughMode interface, return -3/-4 the parameter adapter is nullptr.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_AdapterSetPassthroughMode_Null_003, TestSize.Level1)
{
    int32_t ret;
    struct AudioAdapter *adapter = nullptr;
    struct AudioAdapter *adapterNull = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->SetPassthroughMode(adapterNull, &audioPort, PORT_PASSTHROUGH_LPCM);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioAdapterRelease(adapter);
}

/**
* @tc.name  Test AdapterSetPassthroughMode API when the parameter audioPort is nullptr or not supported.
* @tc.number  SUB_Audio_HDI_AdapterSetPassthroughMode_Null_004
* @tc.desc  test AdapterSetPassthroughMode interface, return -3 if the audioPort is nullptr,
            return -1 if the audioPort is not supported.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_AdapterSetPassthroughMode_Null_004, TestSize.Level1)
{
    int32_t ret;
    struct AudioPort *audioPortNull = nullptr;
    AudioPortPassthroughMode mode = PORT_PASSTHROUGH_LPCM;
    struct AudioAdapter *adapter = nullptr;
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
    AudioAdapterRelease(adapter);
}

/**
* @tc.name  Test AdapterSetPassthroughMode API when the not supported mode.
* @tc.number  SUB_Audio_HDI_AdapterSetPassthroughMode_005
* @tc.desc  test AdapterSetPassthroughMode interface, return -1 if the not supported mode.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_AdapterSetPassthroughMode_005, TestSize.Level1)
{
    int32_t ret;
    struct AudioAdapter *adapter = nullptr;
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
    AudioAdapterRelease(adapter);
}

/**
* @tc.name  Test AdapterGetPassthroughMode API via legal input
* @tc.number  SUB_Audio_HDI_AdapterGetPassthroughMode_001
* @tc.desc  test AdapterGetPassthroughMode interface, return 0 if is get successfully.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_AdapterGetPassthroughMode_001, TestSize.Level1)
{
    int32_t ret;
    AudioPortPassthroughMode mode = PORT_PASSTHROUGH_AUTO;
    struct AudioAdapter *adapter = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = adapter->SetPassthroughMode(adapter, &audioPort, PORT_PASSTHROUGH_LPCM);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = adapter->GetPassthroughMode(adapter, &audioPort, &mode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(PORT_PASSTHROUGH_LPCM, mode);

    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioAdapterRelease(adapter);
}

/**
* @tc.name  Test AdapterGetPassthroughMode API  when the parameter adapter is nullptr.
* @tc.number  SUB_Audio_HDI_AdapterGetPassthroughMode_Null_002
* @tc.desc  test AdapterGetPassthroughMode interface, return -3/-4 if the parameter adapter is nullptr..
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_AdapterGetPassthroughMode_Null_002, TestSize.Level1)
{
    int32_t ret;
    AudioPortPassthroughMode mode = PORT_PASSTHROUGH_LPCM;
    struct AudioAdapter *adapter = nullptr;
    struct AudioAdapter *adapterNull = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->GetPassthroughMode(adapterNull, &audioPort, &mode);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);

    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioAdapterRelease(adapter);
}

/**
* @tc.name   Test AdapterGetPassthroughMode API when the parameter audioPort is nullptr or not supported.
* @tc.number  SUB_Audio_HDI_AdapterGetPassthroughMode_Null_003
* @tc.desc  test AdapterGetPassthroughMode interface, return -3 if the audioPort is nullptr,
            return -1 if the audioPort is not supported.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_AdapterGetPassthroughMode_Null_003, TestSize.Level1)
{
    int32_t ret;
    struct AudioPort *audioPortNull = nullptr;
    AudioPortPassthroughMode mode = PORT_PASSTHROUGH_LPCM;
    struct AudioAdapter *adapter = nullptr;
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
    AudioAdapterRelease(adapter);
}

/**
* @tc.name  Test AdapterGetPassthroughMode API  when the parameter mode is nullptr.
* @tc.number  SUB_Audio_HDI_AdapterGetPassthroughMode_Null_004
* @tc.desc  test AdapterGetPassthroughMode interface, return -3 if the parameter mode is nullptr.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_AdapterGetPassthroughMode_Null_004, TestSize.Level1)
{
    int32_t ret;
    AudioPortPassthroughMode *modeNull = nullptr;
    struct AudioAdapter *adapter = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->GetPassthroughMode(adapter, &audioPort, modeNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioAdapterRelease(adapter);
}
/**
* @tc.name  Test AudioCreateCapture API via legal input
* @tc.number  SUB_Audio_HDI_CreateCapture_001
* @tc.desc  Test AudioCreateCapture interface,Returns 0 if the AudioCapture object is created successfully
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_CreateCapture_001, TestSize.Level1)
{
    int32_t ret;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    adapter->DestroyCapture(adapter);
    AudioCaptureRelease(capture);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    AudioAdapterRelease(adapter);
}

/**
* @tc.name  Test AudioCreateCapture API via creating a capture object when a render object was created
* @tc.number  SUB_Audio_HDI_CreateCapture_002
* @tc.desc  test AudioCreateCapture interface:
     (1)service mode:Returns 0,if the AudioCapture object can be created successfully which was created
     (2)passthrough mode: Returns -1,if the AudioCapture object can't be created which was created
  @tc.author: wengyin
*/

HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_CreateCapture_002, TestSize.Level1)
{
    int32_t ret;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *firstCapture = nullptr;
    struct AudioCapture *secondCapture = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor DevDesc = {};
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    InitAttrs(attrs);
    InitDevDesc(DevDesc, audioPort.portId, PIN_IN_MIC);
    ret = adapter->CreateCapture(adapter, &DevDesc, &attrs, &firstCapture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->CreateCapture(adapter, &DevDesc, &attrs, &secondCapture);
    EXPECT_EQ(HDF_FAILURE, ret);
    adapter->DestroyCapture(adapter);
    AudioCaptureRelease(firstCapture);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    AudioAdapterRelease(adapter);
    free(DevDesc.desc);
}

/**
* @tc.name  Test AudioCreateCapture API via creating a capture object when a render object was created
* @tc.number  SUB_Audio_HDI_CreateCapture_003
* @tc.desc  test AudioCreateCapture interface,Returns 0 if the AudioCapture object can be created successfully
    when AudioRender was created
  @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_CreateCapture_003, TestSize.Level1)
{
    int32_t ret;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor renderDevDesc = {};
    struct AudioDeviceDescriptor captureDevDesc = {};
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    InitAttrs(attrs);
    InitDevDesc(renderDevDesc, audioPort.portId, PIN_OUT_SPEAKER);
    InitDevDesc(captureDevDesc, audioPort.portId, PIN_IN_MIC);
    ret = adapter->CreateRender(adapter, &renderDevDesc, &attrs, &render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = adapter->CreateCapture(adapter, &captureDevDesc, &attrs, &capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    adapter->DestroyCapture(adapter);
    AudioCaptureRelease(capture);
    adapter->DestroyRender(adapter);
    AudioRenderRelease(render);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    AudioAdapterRelease(adapter);
    free(renderDevDesc.desc);
    free(captureDevDesc.desc);
}

/**
* @tc.name  Test AudioCreateCapture API via setting the incoming parameter adapter is nullptr
* @tc.number  SUB_Audio_HDI_CreateCapture_Null_005
* @tc.desc  Test AudioCreateCapture interface,Returns -3/-4 if the incoming parameter adapter is nullptr
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_CreateCapture_Null_005, TestSize.Level1)
{
    int32_t ret;
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioSampleAttributes attrs = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioAdapter *adapterNull = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InitAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InitDevDesc(devDesc, audioPort.portId, PIN_IN_MIC);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->CreateCapture(adapterNull, &devDesc, &attrs, &capture);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    AudioAdapterRelease(adapter);
    free(devDesc.desc);
}

/**
* @tc.name  Test AudioCreateCapture API via setting the incoming parameter desc is nullptr
* @tc.number  SUB_Audio_HDI_CreateCapture_Null_006
* @tc.desc  Test AudioCreateCapture interface,Returns -3 if the incoming parameter desc is nullptr
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_CreateCapture_Null_006, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor *devDesc = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InitAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->CreateCapture(adapter, devDesc, &attrs, &capture);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    AudioAdapterRelease(adapter);
}

/**
* @tc.name  Test AudioCreateCapture API via setting the incoming parameter attrs is nullptr
* @tc.number  SUB_Audio_HDI_CreateCapture_Null_007
* @tc.desc  Test AudioCreateCapture interface,Returns -3 if the incoming parameter attrs is nullptr
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_CreateCapture_Null_007, TestSize.Level1)
{
    int32_t ret;
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioSampleAttributes *attrs = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InitDevDesc(devDesc, audioPort.portId, PIN_IN_MIC);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->CreateCapture(adapter, &devDesc, attrs, &capture);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    AudioAdapterRelease(adapter);
    free(devDesc.desc);
}

#ifdef AUDIO_ADM_PASSTHROUGH
/**
* @tc.name  Test AudioCreateCapture API via setting the incoming parameter capture is nullptr
* @tc.number  SUB_Audio_HDI_CreateCapture_Null_008
* @tc.desc  Test AudioCreateCapture interface,Returns -3/-4 if the incoming parameter capture is nullptr
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_CreateCapture_Null_008, TestSize.Level1)
{
    int32_t ret;
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioSampleAttributes attrs = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture **capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InitAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InitDevDesc(devDesc, audioPort.portId, PIN_IN_MIC);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->CreateCapture(adapter, &devDesc, &attrs, capture);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    AudioAdapterRelease(adapter);
    free(devDesc.desc);
}
#endif
/**
* @tc.name  Test AudioCreateCapture API via setting the incoming parameter adapter which port type is PORT_OUT
* @tc.number  SUB_Audio_HDI_CreateCapture_009
* @tc.desc  Test AudioCreateCapture interface,Returns -1 if the incoming parameter adapter which port type is PORT_OUT
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_CreateCapture_009, TestSize.Level1)
{
    int32_t ret;
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioSampleAttributes attrs = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME_OUT, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InitAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InitDevDesc(devDesc, audioPort.portId, PIN_OUT_SPEAKER);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->CreateCapture(adapter, &devDesc, &attrs, &capture);
    EXPECT_EQ(HDF_FAILURE, ret);
    manager->UnloadAdapter(manager, ADAPTER_NAME_OUT.c_str());
    AudioAdapterRelease(adapter);
    free(devDesc.desc);
}

/**
* @tc.name  Test AudioCreateCapture API via setting the incoming parameter desc which portID is not configed
* @tc.number  SUB_Audio_HDI_CreateCapture_010
* @tc.desc  Test AudioCreateCapture interface,Returns -1 if the incoming parameter desc which portID is not configed
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_CreateCapture_010, TestSize.Level1)
{
    int32_t ret;
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioSampleAttributes attrs = {};
    uint32_t portId = 12;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = InitAttrs(attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InitDevDesc(devDesc, portId, PIN_IN_MIC);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->CreateCapture(adapter, &devDesc, &attrs, &capture);
    EXPECT_EQ(HDF_FAILURE, ret);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    AudioAdapterRelease(adapter);
    free(devDesc.desc);
}
/**
* @tc.name  Test AudioCreateRender API via legal input.
* @tc.number  SUB_Audio_HDI_CreateRender_001
* @tc.desc  test AudioCreateRender interface,return 0 if render is created successful.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_CreateRender_001, TestSize.Level1)
{
    int32_t ret;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor renderDevDesc = {};
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    InitAttrs(attrs);
    InitDevDesc(renderDevDesc, audioPort.portId, PIN_OUT_SPEAKER);
    ret = adapter->CreateRender(adapter, &renderDevDesc, &attrs, &render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    adapter->DestroyRender(adapter);
    AudioRenderRelease(render);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    AudioAdapterRelease(adapter);
    free(renderDevDesc.desc);
}

/**
    * @tc.name  Test AudioCreateRender API via setting the incoming parameter pins is PIN_IN_MIC.
    * @tc.number  SUB_Audio_HDI_CreateRender_003
    * @tc.desc  test AudioCreateRender interface,return -1 if the incoming parameter pins is PIN_IN_MIC.
    * @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_CreateRender_003, TestSize.Level1)
{
    int32_t ret;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    InitAttrs(attrs);
    InitDevDesc(devDesc, audioPort.portId, PIN_IN_MIC);

    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render);
    EXPECT_EQ(HDF_FAILURE, ret);

    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    AudioAdapterRelease(adapter);
    free(devDesc.desc);
}


/**
* @tc.name  Test AudioCreateRender API via setting the incoming parameter attr is error.
* @tc.number  SUB_Audio_HDI_CreateRender_004
* @tc.desc  test AudioCreateRender interface,return -1 if the incoming parameter attr is error.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_CreateRender_004, TestSize.Level1)
{
    int32_t ret;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    uint32_t channelCountErr = 5;
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    InitAttrs(attrs);
    InitDevDesc(devDesc, audioPort.portId, PIN_OUT_SPEAKER);
    attrs.format = AUDIO_FORMAT_AAC_MAIN;
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render);
    EXPECT_EQ(HDF_FAILURE, ret);
    attrs.channelCount = channelCountErr;
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render);
    EXPECT_EQ(HDF_FAILURE, ret);
    attrs.type = AUDIO_IN_COMMUNICATION;
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render);
    EXPECT_EQ(HDF_FAILURE, ret);

    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    AudioAdapterRelease(adapter);
    free(devDesc.desc);
}

/**
* @tc.name  Test AudioCreateRender API via setting the incoming parameter adapter is nullptr
* @tc.number  SUB_Audio_HDI_CreateRender_Null_005
* @tc.desc  test AudioCreateRender interface,Returns -3/-4 if the incoming parameter adapter is nullptr.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_CreateRender_Null_005, TestSize.Level1)
{
    int32_t ret;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioAdapter *adapterNull = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    InitAttrs(attrs);
    InitDevDesc(devDesc, audioPort.portId, PIN_OUT_SPEAKER);

    ret = adapter->CreateRender(adapterNull, &devDesc, &attrs, &render);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);

    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    AudioAdapterRelease(adapter);
    free(devDesc.desc);
}

/**
* @tc.name  Test AudioCreateRender API via setting the incoming parameter devDesc is nullptr
* @tc.number  SUB_Audio_HDI_CreateRender_Null_006
* @tc.desc  test AudioCreateRender interface,Returns -3 if the incoming parameter devDesc is nullptr.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_CreateRender_Null_006, TestSize.Level1)
{
    int32_t ret;
    struct AudioRender *render = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor *devDescNull = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    InitAttrs(attrs);

    ret = adapter->CreateRender(adapter, devDescNull, &attrs, &render);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    AudioAdapterRelease(adapter);
}

/**
* @tc.name  Test AudioCreateRender API via setting the incoming parameter attrs is nullptr
* @tc.number  SUB_Audio_HDI_CreateRender_Null_007
* @tc.desc  test AudioCreateRender interface,Returns -3 if the incoming parameter attrs is nullptr.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_CreateRender_Null_007, TestSize.Level1)
{
    int32_t ret;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes *attrsNull = nullptr;
    struct AudioDeviceDescriptor devDesc = {};
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    InitDevDesc(devDesc, audioPort.portId, PIN_OUT_SPEAKER);

    ret = adapter->CreateRender(adapter, &devDesc, attrsNull, &render);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    AudioAdapterRelease(adapter);
    free(devDesc.desc);
}

#ifdef AUDIO_ADM_PASSTHROUGH
/**
* @tc.name  Test AudioCreateRender API via setting the incoming parameter render is nullptr
* @tc.number  SUB_Audio_HDI_CreateRender_Null_008
* @tc.desc  test AudioCreateRender interface,Returns -3/-4 if the incoming parameter render is nullptr.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_CreateRender_Null_008, TestSize.Level1)
{
    int32_t ret;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender **renderNull = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    InitAttrs(attrs);
    InitDevDesc(devDesc, audioPort.portId, PIN_OUT_SPEAKER);

    ret = adapter->CreateRender(adapter, &devDesc, &attrs, renderNull);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);

    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    AudioAdapterRelease(adapter);
    free(devDesc.desc);
}
#endif

/**
* @tc.name  Test AudioCreateRender API via setting the incoming parameter devDesc is error
* @tc.number  SUB_Audio_HDI_CreateRender_009
* @tc.desc  test AudioCreateRender interface,Returns -1 if the incoming parameter devDesc is error.
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_CreateRender_009, TestSize.Level1)
{
    int32_t ret;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = InitAttrs(attrs);
    InitDevDesc(devDesc, audioPort.portId, PIN_OUT_SPEAKER);

    devDesc.portId = -5;
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render);
    EXPECT_EQ(HDF_FAILURE, ret);
    devDesc.pins = PIN_NONE;
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render);
    EXPECT_EQ(HDF_FAILURE, ret);
    free(devDesc.desc);
    devDesc.desc = strdup("devtestname");
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render);
    EXPECT_EQ(HDF_FAILURE, ret);

    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    AudioAdapterRelease(adapter);
    free(devDesc.desc);
}

/**
* @tc.name  Test AudioCreateRender API via setting the incoming parameter desc which portID is not configed
* @tc.number  SUB_Audio_HDI_CreateRender_010
* @tc.desc  test AudioCreateRender interface,Returns -1 if the incoming desc which portID is not configed
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_CreateRender_010, TestSize.Level1)
{
    int32_t ret;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    uint32_t portId = 10;
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = InitAttrs(attrs);
    InitDevDesc(devDesc, portId, PIN_OUT_SPEAKER);

    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render);
    EXPECT_EQ(HDF_FAILURE, ret);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    AudioAdapterRelease(adapter);
    free(devDesc.desc);
}

/**
* @tc.name  Test AudioDestroyCapture API via legal input
* @tc.number  SUB_Audio_HDI_DestroyCapture_001
* @tc.desc  Test AudioDestroyCapture interface,Returns 0 if the AudioCapture object is destroyed
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_DestroyCapture_001, TestSize.Level1)
{
    int32_t ret;
    AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, pins, ADAPTER_NAME, &adapter, &capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret =adapter->DestroyCapture(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioCaptureRelease(capture);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    AudioAdapterRelease(adapter);
}

/**
* @tc.name  Test AudioDestroyCapture API via setting the incoming parameter adapter is nullptr
* @tc.number  SUB_Audio_HDI_DestroyCapture_Null_002
* @tc.desc  Test AudioDestroyCapture interface,Returns -3/-4 if the incoming parameter adapter is nullptr
* @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_DestroyCapture_Null_002, TestSize.Level1)
{
    int32_t ret;
    struct AudioAdapter *adapter = nullptr;
    struct AudioAdapter *adapterNull = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->DestroyCapture(adapterNull);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    ret = adapter->DestroyCapture(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioCaptureRelease(capture);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    AudioAdapterRelease(adapter);
}

/**
    * @tc.name  Test AudioDestroyRender API via legal input.
    * @tc.number  SUB_Audio_HDI_DestroyRender_001
    * @tc.desc  Test AudioDestroyRender interface, return 0 if render is destroyed successful.
    * @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_DestroyRender_001, TestSize.Level1)
{
    int32_t ret;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->DestroyRender(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioRenderRelease(render);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    AudioAdapterRelease(adapter);
}
/**
    * @tc.name  Test AudioDestroyRender API,where the parameter render is nullptr.
    * @tc.number  SUB_Audio_HDI_DestroyRender_Null_002
    * @tc.desc  Test AudioDestroyRender interface, return -3/-4 if the parameter render is nullptr.
    * @tc.author: wengyin
*/
HWTEST_F(AudioIdlHdiAdapterTest, SUB_Audio_HDI_DestroyRender_Null_002, TestSize.Level1)
{
    int32_t ret;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioAdapter *adapterNull = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->DestroyRender(adapterNull);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    ret = adapter->DestroyRender(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioRenderRelease(render);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    AudioAdapterRelease(adapter);
}
}