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
#include "audio_hdiadapter_test.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
class AudioHdiAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static TestAudioManager *manager;
};
TestAudioManager *AudioHdiAdapterTest::manager = nullptr;

void AudioHdiAdapterTest::SetUpTestCase(void)
{
    manager = GetAudioManagerFuncs();
    ASSERT_NE(nullptr, manager);
}

void AudioHdiAdapterTest::TearDownTestCase(void) {}

void AudioHdiAdapterTest::SetUp(void) {}

void AudioHdiAdapterTest::TearDown(void) {}

/**
* @tc.name  AudioGetAllAdapters_001
* @tc.desc  test GetAllAdapters interface，Returns 0 if the list is obtained successfully
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioGetAllAdapters_001, TestSize.Level1)
{
    int32_t ret = -1;
    int size = 0;
    struct AudioAdapterDescriptor *descs = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = manager->GetAllAdapters(manager, &descs, &size);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_ADAPTER_MAX_NUM, size);
}

/**
* @tc.name  AudioGetAllAdapters_002
* @tc.desc  test GetAllAdapters interface，Returns -1 if the incoming parameter manager is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioGetAllAdapters_002, TestSize.Level1)
{
    int32_t ret = -1;
    int size = 0;
    struct AudioAdapterDescriptor *descs = nullptr;
    TestAudioManager *manager1 = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = manager->GetAllAdapters(manager1, &descs, &size);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
}

/**
* @tc.name  AudioGetAllAdapters_003
* @tc.desc  test GetAllAdapters interface，Returns -1 if the incoming parameter descs is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioGetAllAdapters_003, TestSize.Level1)
{
    int32_t ret = -1;
    int size = 0;
    struct AudioAdapterDescriptor **descs = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = manager->GetAllAdapters(manager, descs, &size);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
}

/**
* @tc.name  AudioGetAllAdapters_004
* @tc.desc  test GetAllAdapters interface，Returns -1 if the incoming parameter size is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioGetAllAdapters_004, TestSize.Level1)
{
    int32_t ret = -1;
    int *size = nullptr;
    struct AudioAdapterDescriptor *descs = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = manager->GetAllAdapters(manager, &descs, size);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
}
/**
* @tc.name  AudioGetAllAdapters_005
* @tc.desc  test GetAllAdapters interface，Returns -3 if the incoming parameter manager is illagal
* @tc.type: FUNC
*/
#ifdef AUDIO_ADM_SERVICE
HWTEST_F(AudioHdiAdapterTest, AudioGetAllAdapters_005, TestSize.Level1)
{
    int32_t ret = -1;
    int *size = nullptr;
    struct AudioAdapterDescriptor *descs = nullptr;

    ASSERT_NE(nullptr, manager);
    TestAudioManager errorManager;
    ret = manager->GetAllAdapters(&errorManager, &descs, size);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
}
#endif
/**
* @tc.name  AudioLoadAdapter_001
* @tc.desc  test LoadAdapter interface，Returns 0 if the driver is loaded successfully
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioLoadAdapter_001, TestSize.Level1)
{
    int32_t ret = -1;
    int size = 0;
    struct AudioAdapterDescriptor *descs = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = GetAdapters(manager, &descs, size);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    struct AudioAdapterDescriptor *desc = &descs[0];
    ASSERT_TRUE(desc != nullptr);
    struct AudioAdapter *adapter = nullptr;
    ret = manager->LoadAdapter(manager, desc, &adapter);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = -1;
    if (adapter != nullptr) {
        if (adapter->InitAllPorts != nullptr && adapter->CreateRender != nullptr &&
            adapter->DestroyRender != nullptr && adapter->CreateCapture != nullptr &&
            adapter->DestroyCapture != nullptr && adapter->GetPortCapability != nullptr &&
            adapter->SetPassthroughMode != nullptr && adapter->GetPassthroughMode != nullptr) {
            ret = 0;
        }
    }
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioLoadAdapter_002
* @tc.desc  test LoadAdapter interface，Returns -1 if the adapterName of incoming parameter desc is not support
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioLoadAdapter_002, TestSize.Level1)
{
    int32_t ret = -1;
    int size = 0;
    struct AudioAdapterDescriptor *descs = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = GetAdapters(manager, &descs, size);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    struct AudioAdapterDescriptor *desc = &descs[0];
    desc->adapterName = "illegal";
    ASSERT_TRUE(desc != nullptr);
    struct AudioAdapter *adapter = nullptr;

    ret = manager->LoadAdapter(manager, desc, &adapter);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    desc->adapterName = "internal";
    ret = manager->LoadAdapter(manager, desc, &adapter);
    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioLoadAdapter_003
* @tc.desc  test LoadAdapter interface，Returns -1 if the adapterName of incoming parameter desc is illegal
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioLoadAdapter_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioAdapterDescriptor desc = {
        .adapterName = "illegal",
        .portNum = 2,
        .ports = nullptr,
    };

    ASSERT_NE(nullptr, manager);
    ret = manager->LoadAdapter(manager, &desc, &adapter);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioLoadAdapter_004
* @tc.desc  test LoadAdapter interface，Returns -1 if the incoming parameter manager is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioLoadAdapter_004, TestSize.Level1)
{
    int32_t ret = -1;
    int size = 0;
    struct AudioAdapterDescriptor *descs = nullptr;
    TestAudioManager *managerNull = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = GetAdapters(manager, &descs, size);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    struct AudioAdapterDescriptor *desc = &descs[0];
    ASSERT_TRUE(desc != nullptr);
    struct AudioAdapter *adapter = nullptr;

    ret = manager->LoadAdapter(managerNull, desc, &adapter);
    ASSERT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioLoadAdapter_005
* @tc.desc  test LoadAdapter interface，Returns -1 if the incoming parameter desc is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioLoadAdapter_005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapterDescriptor *desc = nullptr;
    struct AudioAdapter *adapter = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = manager->LoadAdapter(manager, desc, &adapter);
    ASSERT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioLoadAdapter_006
* @tc.desc  test LoadAdapter interface，Returns -1 if the incoming parameter adapter is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioLoadAdapter_006, TestSize.Level1)
{
    int32_t ret = -1;
    int size = 0;
    struct AudioAdapterDescriptor *descs = nullptr;
    struct AudioAdapter **adapter = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = GetAdapters(manager, &descs, size);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    struct AudioAdapterDescriptor *desc = &descs[0];
    ASSERT_TRUE(desc != nullptr);

    ret = manager->LoadAdapter(manager, desc, adapter);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
}
/**
* @tc.name  AudioLoadAdapter_007
* @tc.desc  test LoadAdapter interface，Returns -3 if setting the adapterName of incoming parameter manager is illagal
*/
#ifdef AUDIO_ADM_SERVICE
HWTEST_F(AudioHdiAdapterTest, AudioLoadAdapter_007, TestSize.Level1)
{
    int32_t ret = -1;
    int size = 0;
    struct AudioAdapterDescriptor *descs = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = GetAdapters(manager, &descs, size);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    struct AudioAdapterDescriptor *desc = &descs[0];
    ASSERT_TRUE(desc != nullptr);
    struct AudioAdapter *adapter = nullptr;
    TestAudioManager errorManager;
    ret = manager->LoadAdapter(&errorManager, desc, &adapter);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    manager->UnloadAdapter(manager, adapter);
}
#endif
/**
* @tc.name  AudioAdapterInitAllPorts_001
* @tc.desc  Test AudioAdapterInitAllPorts interface, return 0 if the ports is initialize successfully.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterInitAllPorts_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort* renderPort = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioAdapterInitAllPorts_002
* @tc.desc  Test AudioAdapterInitAllPorts interface, return 0 if loads two adapters successfully.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterInitAllPorts_002, TestSize.Level1)
{
    int32_t ret = -1;
    int32_t ret2 = -1;
    struct AudioPort* renderPort = nullptr;
    struct AudioPort* renderPortUsb = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioAdapter *adapter1 = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret2 = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME_OUT, &adapter1, renderPortUsb);
    if (ret2 < 0 || adapter1 == nullptr) {
        manager->UnloadAdapter(manager, adapter);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret2);
    }
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret2 = adapter1->InitAllPorts(adapter1);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret2);

    manager->UnloadAdapter(manager, adapter);
    manager->UnloadAdapter(manager, adapter1);
}

/**
* @tc.name  AudioAdapterInitAllPorts_003
* @tc.desc  Test AudioAdapterInitAllPorts API, return -1 if the parameter adapter is empty.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterInitAllPorts_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort* audioPort = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioAdapter *adapterNull = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapterNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioAdapterGetPortCapability_001
* @tc.desc  Test AudioAdapterGetPortCapability,return 0 if PortType is PORT_OUT.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterGetPortCapability_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort* audioPort = nullptr;
    struct AudioAdapter *adapter = {};
    struct AudioPortCapability capability = {};
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
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
* @tc.name  AudioAdapterGetPortCapability_002
* @tc.desc  Test AudioAdapterGetPortCapability,return 0 if PortType is PORT_IN.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterGetPortCapability_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort* audioPort = nullptr;
    struct AudioAdapter *adapter = {};
    struct AudioPortCapability capability = {};
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = adapter->GetPortCapability(adapter, audioPort, &capability);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioAdapterGetPortCapability_004
* @tc.desc  Test AudioAdapterGetPortCapability, return -1 if the parameter adapter is empty.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterGetPortCapability_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort* audioPort = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioAdapter *adapterNull = nullptr;
    struct AudioPortCapability capability = {};

    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    ret = adapter->GetPortCapability(adapterNull, audioPort, &capability);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioAdapterGetPortCapability_005
* @tc.desc  Test AudioAdapterGetPortCapability, return -1 if the audioPort is nullptr or not supported.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterGetPortCapability_005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort *audioPortNull = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPortCapability capability = {};

    ASSERT_NE(nullptr, manager);
    struct AudioPort* audioPort = nullptr;
    struct AudioPort audioPortError = { .dir = PORT_OUT, .portId = 9, .portName = "AIP" };

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = adapter->GetPortCapability(adapter, audioPortNull, &capability);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    ret = adapter->GetPortCapability(adapter, &audioPortError, &capability);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioAdapterGetPortCapability_006
* @tc.desc  Test AudioAdapterGetPortCapability, return -1 if capability is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterGetPortCapability_006, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort* audioPort = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPortCapability *capabilityNull = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = adapter->GetPortCapability(adapter, audioPort, capabilityNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioAdapterSetPassthroughMode_001
* @tc.desc  test AdapterSetPassthroughMode interface, return 0 if PortType is PORT_OUT.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterSetPassthroughMode_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort* audioPort = nullptr;
    struct AudioAdapter *adapter = nullptr;

    ASSERT_NE(nullptr, manager);
    AudioPortPassthroughMode modeLpcm = PORT_PASSTHROUGH_AUTO;
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
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
* @tc.name  AudioAdapterSetPassthroughMode_002
* @tc.desc  test AdapterSetPassthroughMode interface, return -1 if PortType is PORT_IN.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterSetPassthroughMode_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort* audioPort = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = adapter->SetPassthroughMode(adapter, audioPort, PORT_PASSTHROUGH_LPCM);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioAdapterSetPassthroughMode_003
* @tc.desc  test AdapterSetPassthroughMode interface, return -1 the parameter adapter is empty.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterSetPassthroughMode_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort* audioPort = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioAdapter *adapterNull = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->SetPassthroughMode(adapterNull, audioPort, PORT_PASSTHROUGH_LPCM);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioAdapterSetPassthroughMode_004
* @tc.desc  test AdapterSetPassthroughMode interface, return -1 if the audioPort is nullptr or not supported.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterSetPassthroughMode_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort* audioPort = nullptr;
    struct AudioPort *audioPortNull = nullptr;
    AudioPortPassthroughMode mode = PORT_PASSTHROUGH_LPCM;
    struct AudioAdapter *adapter = nullptr;

    ASSERT_NE(nullptr, manager);
    struct AudioPort audioPortError = { .dir = PORT_OUT, .portId = 8, .portName = "AIP1" };
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = adapter->SetPassthroughMode(adapter, audioPortNull, mode);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    ret = adapter->SetPassthroughMode(adapter, &audioPortError, mode);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioAdapterSetPassthroughMode_005
* @tc.desc  test AdapterSetPassthroughMode interface, return -1 if the not supported mode.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterSetPassthroughMode_005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort* audioPort = nullptr;
    struct AudioAdapter *adapter = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = adapter->SetPassthroughMode(adapter, audioPort, PORT_PASSTHROUGH_RAW);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioAdapterGetPassthroughMode_001
* @tc.desc  test AdapterGetPassthroughMode interface, return 0 if is get successfully.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterGetPassthroughMode_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort* audioPort = nullptr;
    AudioPortPassthroughMode mode = PORT_PASSTHROUGH_AUTO;
    struct AudioAdapter *adapter = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
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
* @tc.name  AudioAdapterGetPassthroughMode_002
* @tc.desc  test AdapterGetPassthroughMode interface, return -1 if the parameter adapter is empty..
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterGetPassthroughMode_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort* audioPort = nullptr;
    AudioPortPassthroughMode mode = PORT_PASSTHROUGH_LPCM;
    struct AudioAdapter *adapter = nullptr;
    struct AudioAdapter *adapterNull = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = adapter->GetPassthroughMode(adapterNull, audioPort, &mode);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioAdapterGetPassthroughMode_003
* @tc.desc  test AdapterGetPassthroughMode interface, return -1 if the audioPort is nullptr or not supported.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterGetPassthroughMode_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort* audioPort = nullptr;
    struct AudioPort *audioPortNull = nullptr;
    AudioPortPassthroughMode mode = PORT_PASSTHROUGH_LPCM;
    struct AudioAdapter *adapter = nullptr;

    ASSERT_NE(nullptr, manager);
    struct AudioPort audioPortError = { .dir = PORT_OUT, .portId = 8, .portName = "AIP" };
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = adapter->GetPassthroughMode(adapter, audioPortNull, &mode);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    ret = adapter->GetPassthroughMode(adapter, &audioPortError, &mode);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioAdapterGetPassthroughMode_004
* @tc.desc  test AdapterGetPassthroughMode interface, return -1 if the parameter mode is empty.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterGetPassthroughMode_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort* audioPort = nullptr;
    AudioPortPassthroughMode *modeNull = nullptr;
    struct AudioAdapter *adapter = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = adapter->GetPassthroughMode(adapter, audioPort, modeNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    manager->UnloadAdapter(manager, adapter);
}
}
