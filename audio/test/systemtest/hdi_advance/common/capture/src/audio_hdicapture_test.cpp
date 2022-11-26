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

class AudioHdiCaptureTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static TestAudioManager *manager;
};

using THREAD_FUNC = void *(*)(void *);
TestAudioManager *AudioHdiCaptureTest::manager = nullptr;

void AudioHdiCaptureTest::SetUpTestCase(void)
{
    manager = GetAudioManagerFuncs();
    ASSERT_NE(nullptr, manager);
}

void AudioHdiCaptureTest::TearDownTestCase(void) {}

void AudioHdiCaptureTest::SetUp(void) {}

void AudioHdiCaptureTest::TearDown(void) {}


/**
* @tc.name  AudioCaptureGetCapturePosition_003
* @tc.desc  Test GetCapturePosition interface,Returns 0 if get CapturePosition after stop during playing
* @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureTest, AudioCaptureGetCapturePosition_003, TestSize.Level1)
{
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {
        .tvSec = 0,
        .tvNSec = 0,
    };
    int64_t timeExp = 0;

    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_NE(HDF_SUCCESS, ret);
    ret = capture->GetCapturePosition(capture, &frames, &time);
    EXPECT_NE(HDF_SUCCESS, ret);
    EXPECT_EQ((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_EQ(frames, INITIAL_VALUE);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureGetCapturePosition_004
    * @tc.desc  Test GetCapturePosition interface, return 0 if get CapturePosition after the object is created
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureTest, AudioCaptureGetCapturePosition_004, TestSize.Level1)
{
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {
        .tvSec = 0,
        .tvNSec = 0,
    };
    int64_t timeExp = 0;

    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetCapturePosition(capture, &frames, &time);
    EXPECT_NE(HDF_SUCCESS, ret);
    EXPECT_EQ((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureGetCapturePosition_005
    * @tc.desc  Test GetCapturePosition interface, return -1 if setting the parameter Capture is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureTest, AudioCaptureGetCapturePosition_005, TestSize.Level1)
{
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {};

    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetCapturePosition(captureNull, &frames, &time);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureGetCapturePosition_006
    * @tc.desc  Test GetCapturePosition interface, return -1 if setting the parameter frames is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureTest, AudioCaptureGetCapturePosition_006, TestSize.Level1)
{
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    uint64_t *framesNull = nullptr;
    struct AudioTimeStamp time = {
        .tvSec = 0,
        .tvNSec = 0,
    };

    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetCapturePosition(capture, framesNull, &time);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureGetCapturePosition_007
    * @tc.desc  Test GetCapturePosition interface, return -1 if setting the parameter time is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureTest, AudioCaptureGetCapturePosition_007, TestSize.Level1)
{
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    uint64_t frames = 0;
    struct AudioTimeStamp *timeNull = nullptr;

    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetCapturePosition(capture, &frames, timeNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureGetCapturePosition_008
    * @tc.desc  Test GetCapturePosition interface, return 0 if the GetCapturePosition was called twice
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureTest, AudioCaptureGetCapturePosition_008, TestSize.Level1)
{
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {
        .tvSec = 0,
        .tvNSec = 0,
    };
    struct AudioTimeStamp timeSec = {
        .tvSec = 0,
        .tvNSec = 0,
    };
    int64_t timeExp = 0;

    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetCapturePosition(capture, &frames, &time);
    EXPECT_NE(HDF_SUCCESS, ret);
    EXPECT_EQ((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_EQ(frames, INITIAL_VALUE);
    ret = capture->GetCapturePosition(capture, &frames, &timeSec);
    EXPECT_NE(HDF_SUCCESS, ret);
    EXPECT_EQ((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_EQ(frames, INITIAL_VALUE);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
}
