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
* @tc.name  AudioAdapterGetPortCapability_001
* @tc.desc  Test AudioAdapterGetPortCapability,return 0 if PortType is PORT_OUT.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterGetPortCapability_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioPort* audioPort = nullptr;
    struct AudioAdapter *adapter = {};
    struct AudioPortCapability capability = {};
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->GetPortCapability(adapter, audioPort, &capability);
    if (ret < 0 || capability.formats == nullptr || capability.subPorts == nullptr) {
        manager->UnloadAdapter(manager, adapter);
        ASSERT_NE(HDF_SUCCESS, ret);
        ASSERT_EQ(nullptr, capability.formats);
        ASSERT_EQ(nullptr, capability.subPorts);
    }

    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioAdapterGetPortCapability_002
* @tc.desc  Test AudioAdapterGetPortCapability,return 0 if PortType is PORT_IN.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterGetPortCapability_002, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioPort* audioPort = nullptr;
    struct AudioAdapter *adapter = {};
    struct AudioPortCapability capability = {};
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->GetPortCapability(adapter, audioPort, &capability);
    EXPECT_NE(HDF_SUCCESS, ret);

    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioAdapterGetPortCapability_004
* @tc.desc  Test AudioAdapterGetPortCapability, return -1 if the parameter adapter is empty.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterGetPortCapability_004, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioPort* audioPort = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioAdapter *adapterNull = nullptr;
    struct AudioPortCapability capability = {};

    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    ret = adapter->GetPortCapability(adapterNull, audioPort, &capability);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioAdapterGetPortCapability_005
* @tc.desc  Test AudioAdapterGetPortCapability, return -1 if the audioPort is nullptr or not supported.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterGetPortCapability_005, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioPort *audioPortNull = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPortCapability capability = {};

    ASSERT_NE(nullptr, manager);
    struct AudioPort* audioPort = nullptr;
    struct AudioPort audioPortError = {
        .dir = PORT_OUT,
        .portId = 9,
        .portName = "AIP",
    };

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->GetPortCapability(adapter, audioPortNull, &capability);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    ret = adapter->GetPortCapability(adapter, &audioPortError, &capability);
    EXPECT_EQ(HDF_FAILURE, ret);
    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioAdapterGetPortCapability_006
* @tc.desc  Test AudioAdapterGetPortCapability, return -1 if capability is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterGetPortCapability_006, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioPort* audioPort = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPortCapability *capabilityNull = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->GetPortCapability(adapter, audioPort, capabilityNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioAdapterSetPassthroughMode_001
* @tc.desc  test AdapterSetPassthroughMode interface, return 0 if PortType is PORT_OUT.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterSetPassthroughMode_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioPort* audioPort = nullptr;
    struct AudioAdapter *adapter = nullptr;

    ASSERT_NE(nullptr, manager);
    AudioPortPassthroughMode modeLpcm = PORT_PASSTHROUGH_AUTO;
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->SetPassthroughMode(adapter, audioPort, PORT_PASSTHROUGH_LPCM);
    EXPECT_NE(HDF_SUCCESS, ret);
    ret = adapter->GetPassthroughMode(adapter, audioPort, &modeLpcm);
    EXPECT_NE(HDF_SUCCESS, ret);
    EXPECT_NE(PORT_PASSTHROUGH_LPCM, modeLpcm);

    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioAdapterSetPassthroughMode_002
* @tc.desc  test AdapterSetPassthroughMode interface, return -1 if PortType is PORT_IN.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterSetPassthroughMode_002, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort* audioPort = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_IN, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->SetPassthroughMode(adapter, audioPort, PORT_PASSTHROUGH_LPCM);
    EXPECT_EQ(HDF_FAILURE, ret);

    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioAdapterSetPassthroughMode_003
* @tc.desc  test AdapterSetPassthroughMode interface, return -1 the parameter adapter is empty.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterSetPassthroughMode_003, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioPort* audioPort = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioAdapter *adapterNull = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->SetPassthroughMode(adapterNull, audioPort, PORT_PASSTHROUGH_LPCM);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioAdapterSetPassthroughMode_004
* @tc.desc  test AdapterSetPassthroughMode interface, return -1 if the audioPort is nullptr or not supported.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterSetPassthroughMode_004, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioPort* audioPort = nullptr;
    struct AudioPort *audioPortNull = nullptr;
    AudioPortPassthroughMode mode = PORT_PASSTHROUGH_LPCM;
    struct AudioAdapter *adapter = nullptr;

    ASSERT_NE(nullptr, manager);
    struct AudioPort audioPortError = {
        .dir = PORT_OUT,
        .portId = 8,
        .portName = "AIP1",
    };
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->SetPassthroughMode(adapter, audioPortNull, mode);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    ret = adapter->SetPassthroughMode(adapter, &audioPortError, mode);
    EXPECT_EQ(HDF_FAILURE, ret);
    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioAdapterSetPassthroughMode_005
* @tc.desc  test AdapterSetPassthroughMode interface, return -1 if the not supported mode.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterSetPassthroughMode_005, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioPort* audioPort = nullptr;
    struct AudioAdapter *adapter = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->SetPassthroughMode(adapter, audioPort, PORT_PASSTHROUGH_RAW);
    EXPECT_NE(HDF_FAILURE, ret);

    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioAdapterGetPassthroughMode_001
* @tc.desc  test AdapterGetPassthroughMode interface, return 0 if is get successfully.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterGetPassthroughMode_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioPort* audioPort = nullptr;
    AudioPortPassthroughMode mode = PORT_PASSTHROUGH_AUTO;
    struct AudioAdapter *adapter = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = adapter->SetPassthroughMode(adapter, audioPort, PORT_PASSTHROUGH_LPCM);
    EXPECT_NE(HDF_SUCCESS, ret);

    ret = adapter->GetPassthroughMode(adapter, audioPort, &mode);
    EXPECT_NE(HDF_SUCCESS, ret);
    EXPECT_NE(PORT_PASSTHROUGH_LPCM, mode);

    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioAdapterGetPassthroughMode_002
* @tc.desc  test AdapterGetPassthroughMode interface, return -1 if the parameter adapter is empty..
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterGetPassthroughMode_002, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioPort* audioPort = nullptr;
    AudioPortPassthroughMode mode = PORT_PASSTHROUGH_LPCM;
    struct AudioAdapter *adapter = nullptr;
    struct AudioAdapter *adapterNull = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->GetPassthroughMode(adapterNull, audioPort, &mode);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioAdapterGetPassthroughMode_003
* @tc.desc  test AdapterGetPassthroughMode interface, return -1 if the audioPort is nullptr or not supported.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterGetPassthroughMode_003, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioPort* audioPort = nullptr;
    struct AudioPort *audioPortNull = nullptr;
    AudioPortPassthroughMode mode = PORT_PASSTHROUGH_LPCM;
    struct AudioAdapter *adapter = nullptr;

    ASSERT_NE(nullptr, manager);
    struct AudioPort audioPortError = {
        .dir = PORT_OUT,
        .portId = 8,
        .portName = "AIP",
    };
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->GetPassthroughMode(adapter, audioPortNull, &mode);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    ret = adapter->GetPassthroughMode(adapter, &audioPortError, &mode);
    EXPECT_EQ(HDF_FAILURE, ret);
    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioAdapterGetPassthroughMode_004
* @tc.desc  test AdapterGetPassthroughMode interface, return -1 if the parameter mode is empty.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiAdapterTest, AudioAdapterGetPassthroughMode_004, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioPort* audioPort = nullptr;
    AudioPortPassthroughMode *modeNull = nullptr;
    struct AudioAdapter *adapter = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, adapter);
    ret = adapter->InitAllPorts(adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = adapter->GetPassthroughMode(adapter, audioPort, modeNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    manager->UnloadAdapter(manager, adapter);
}
}
