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
#include "audio_usb_manager_test.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
const string ADAPTER_NAME_USB = "usb";

class AudioUsbManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static TestAudioManager *manager;
};

TestAudioManager *AudioUsbManagerTest::manager = nullptr;

void AudioUsbManagerTest::SetUpTestCase(void)
{
    manager = GetAudioManagerFuncs();
    ASSERT_NE(nullptr, manager);
}

void AudioUsbManagerTest::TearDownTestCase(void) {}

void AudioUsbManagerTest::SetUp(void) {}

void AudioUsbManagerTest::TearDown(void) {}

/**
* @tc.name  AudioGetAllAdapters_001
* @tc.desc  test GetAllAdapters interface，Returns 0 if the list is obtained successfully
* @tc.type: FUNC
*/
HWTEST_F(AudioUsbManagerTest, AudioGetAllAdapters_001, TestSize.Level1)
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
* @tc.name  AudioLoadAdapter_001
* @tc.desc  test LoadAdapter interface，Returns 0 if the driver is loaded successfully
* @tc.type: FUNC
*/
HWTEST_F(AudioUsbManagerTest, AudioLoadAdapter_001, TestSize.Level1)
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
}
