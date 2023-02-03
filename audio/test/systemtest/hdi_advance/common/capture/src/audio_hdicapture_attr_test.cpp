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

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
class AudioHdiCaptureAttrTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static TestAudioManager *manager;
};

using THREAD_FUNC = void *(*)(void *);
TestAudioManager *AudioHdiCaptureAttrTest::manager = nullptr;

void AudioHdiCaptureAttrTest::SetUpTestCase(void)
{
    manager = GetAudioManagerFuncs();
    ASSERT_NE(nullptr, manager);
}

void AudioHdiCaptureAttrTest::TearDownTestCase(void) {}

void AudioHdiCaptureAttrTest::SetUp(void) {}
void AudioHdiCaptureAttrTest::TearDown(void) {}

/**
* @tc.name  AudioCaptureGetFrameSize_001
* @tc.desc  test AudioCaptureGetFrameSize interface, return 0 is call successfully.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureAttrTest, AudioCaptureGetFrameSize_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t size = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = capture->attr.GetFrameSize(capture, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioCaptureGetFrameSize_002
* @tc.desc  test AudioCaptureGetFrameSize interface, return -1 if the parameter handle is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureAttrTest, AudioCaptureGetFrameSize_002, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t size = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = capture->attr.GetFrameSize(captureNull, &size);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioCaptureGetFrameSize_003
* @tc.desc  test AudioCaptureGetFrameSize interface, return -1 if the parameter size is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureAttrTest, AudioCaptureGetFrameSize_003, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t *sizeNull = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = capture->attr.GetFrameSize(capture, sizeNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioCaptureGetFrameCount_001
* @tc.desc  test AudioCaptureGetFrameCount interface, return 0 if the FrameCount is called after creating the object.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureAttrTest, AudioCaptureGetFrameCount_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t count = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = capture->attr.GetFrameCount(capture, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_NE(count, INITIAL_VALUE);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioCaptureGetFrameCount_001
* @tc.desc  test AudioCaptureGetFrameCount interface, return 0 if the GetFrameCount is called after started.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureAttrTest, AudioCaptureGetFrameCount_002, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t count = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->attr.GetFrameCount(capture, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  AudioCaptureGetFrameCount_003
* @tc.desc  test AudioCaptureGetFrameCount interface, return -1 if the parameter handle is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureAttrTest, AudioCaptureGetFrameCount_003, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t count = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = capture->attr.GetFrameCount(captureNull, &count);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  AudioCaptureGetFrameCount_004
* @tc.desc  test AudioCaptureGetFrameCount interface, return -1 if the parameter handle is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureAttrTest, AudioCaptureGetFrameCount_004, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t *countNull = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = capture->attr.GetFrameCount(capture, countNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetCurrentChannelId_001
    * @tc.desc  Test GetCurrentChannelId, return 0 if the default CurrentChannelId is obtained successfully
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureAttrTest, AudioCaptureGetCurrentChannelId_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint32_t channelId = 0;
    uint32_t channelIdValue = CHANNELCOUNT;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = capture->attr.GetCurrentChannelId(capture, &channelId);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_NE(channelIdValue, channelId);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureGetCurrentChannelId_003
    * @tc.desc  Test GetCurrentChannelId interface, return 0 if CurrentChannelId is obtained after started
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureAttrTest, AudioCaptureGetCurrentChannelId_003, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint32_t channelId = 0;
    uint32_t channelIdExp = 2;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->attr.GetCurrentChannelId(capture, &channelId);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_NE(channelIdExp, channelId);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetCurrentChannelId_004
    * @tc.desc  Test GetCurrentChannelId interface,return -1 if set the parameter capture is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureAttrTest, AudioCaptureGetCurrentChannelId_004, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint32_t channelId = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = capture->attr.GetCurrentChannelId(captureNull, &channelId);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetCurrentChannelId_005
    * @tc.desc  Test CaptureGetCurrentChannelId interface, return -1 if setting the parameter channelId is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureAttrTest, AudioCaptureGetCurrentChannelId_005, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint32_t *channelIdNull = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = capture->attr.GetCurrentChannelId(capture, channelIdNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
}
