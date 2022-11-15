/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "audio_hdicapture_attr_test.h"

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
    int32_t ret = -1;
    uint64_t size = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.GetFrameSize(capture, &size);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
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
    int32_t ret = -1;
    uint64_t size = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = capture->attr.GetFrameSize(captureNull, &size);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

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
    int32_t ret = -1;
    uint64_t *sizeNull = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = capture->attr.GetFrameSize(capture, sizeNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

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
    int32_t ret = -1;
    uint64_t count = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = capture->attr.GetFrameCount(capture, &count);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(count, INITIAL_VALUE);

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
    int32_t ret = -1;
    uint64_t count = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = capture->attr.GetFrameCount(capture, &count);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
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
    int32_t ret = -1;
    uint64_t count = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = capture->attr.GetFrameCount(captureNull, &count);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

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
    int32_t ret = -1;
    uint64_t *countNull = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = capture->attr.GetFrameCount(capture, countNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

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
    int32_t ret = -1;
    uint32_t channelId = 0;
    uint32_t channelIdValue = CHANNELCOUNT;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = capture->attr.GetCurrentChannelId(capture, &channelId);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(channelIdValue, channelId);

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
    int32_t ret = -1;
    uint32_t channelId = 0;
    uint32_t channelIdExp = 2;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = capture->attr.GetCurrentChannelId(capture, &channelId);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(channelIdExp, channelId);

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
    int32_t ret = -1;
    uint32_t channelId = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = capture->attr.GetCurrentChannelId(captureNull, &channelId);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

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
    int32_t ret = -1;
    uint32_t *channelIdNull = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = capture->attr.GetCurrentChannelId(capture, channelIdNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureSetExtraParams_001
    * @tc.desc  Test CaptureSetExtraParams interface,return 0 if the ExtraParams is set during playback
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureAttrTest, AudioCaptureSetExtraParams_001, TestSize.Level1)
{
    int32_t ret = -1;
    char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;attr-frame-count=82;attr-sampling-rate=48000";
    char keyValueListExp[] = "attr-route=1;attr-format=32;attr-channels=2;attr-sampling-rate=48000";
    size_t index = 1;
    char keyValueListValue[256] = {};
    int32_t listLenth = 256;
    uint64_t FILESIZE = 1024;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC,
        .path = AUDIO_CAPTURE_FILE.c_str(), .fileSize = FILESIZE
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);

    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)RecordAudio, &audiopara);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    sleep(1);
    if (audiopara.capture != nullptr) {
        ret = audiopara.capture->attr.SetExtraParams((AudioHandle)audiopara.capture, keyValueList);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        ret = audiopara.capture->attr.GetExtraParams((AudioHandle)audiopara.capture, keyValueListValue, listLenth);
        EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
        string strGetValue = keyValueListValue;
        size_t indexAttr = strGetValue.find("attr-frame-count");
        size_t indexFlag = strGetValue.rfind(";");
        if (indexAttr != string::npos && indexFlag != string::npos) {
            strGetValue.replace(indexAttr, indexFlag - indexAttr + index, "");
        }
        EXPECT_STREQ(keyValueListExp, strGetValue.c_str());
    }

    ret = ThreadRelease(audiopara);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
}
/**
    * @tc.name  AudioCaptureSetExtraParams_002
    * @tc.desc  Test CaptureSetExtraParams interface,return 0 if some parameters is set after playing
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureAttrTest, AudioCaptureSetExtraParams_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    char keyValueListOne[] = "attr-frame-count=4096;";
    char keyValueListOneExp[] = "attr-route=0;attr-format=16;attr-channels=2;attr-frame-count=4096;\
attr-sampling-rate=48000";
    char keyValueListTwo[] = "attr-route=1;attr-frame-count=1024;";
    char keyValueListTwoExp[] = "attr-route=1;attr-format=16;attr-channels=2;attr-frame-count=1024;\
attr-sampling-rate=48000";
    char keyValueListThr[] = "attr-route=0;attr-channels=1;attr-frame-count=4096;";
    char keyValueListThrExp[] = "attr-route=0;attr-format=16;attr-channels=1;attr-frame-count=4096;\
attr-sampling-rate=48000";
    char keyValueListFour[] = "attr-format=32;attr-channels=2;attr-frame-count=4096;attr-sampling-rate=48000";
    char keyValueListFourExp[] = "attr-route=0;attr-format=32;attr-channels=2;attr-frame-count=4096;\
attr-sampling-rate=48000";
    char keyValueListValueOne[256] = {};
    char keyValueListValueTwo[256] = {};
    char keyValueListValueThr[256] = {};
    char keyValueListValueFour[256] = {};
    int32_t listLenth = 256;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartCapture(manager, &capture, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = capture->attr.SetExtraParams((AudioHandle)capture, keyValueListOne);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.GetExtraParams((AudioHandle)capture, keyValueListValueOne, listLenth);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_STREQ(keyValueListOneExp, keyValueListValueOne);
    ret = capture->attr.SetExtraParams((AudioHandle)capture, keyValueListTwo);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.GetExtraParams((AudioHandle)capture, keyValueListValueTwo, listLenth);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_STREQ(keyValueListTwoExp, keyValueListValueTwo);
    ret = capture->attr.SetExtraParams((AudioHandle)capture, keyValueListThr);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.GetExtraParams((AudioHandle)capture, keyValueListValueThr, listLenth);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_STREQ(keyValueListThrExp, keyValueListValueThr);
    ret = capture->attr.SetExtraParams((AudioHandle)capture, keyValueListFour);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.GetExtraParams((AudioHandle)capture, keyValueListValueFour, listLenth);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_STREQ(keyValueListFourExp, keyValueListValueFour);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureSetExtraParams_003
    * @tc.desc  Test CaptureSetExtraParams interface,return -1 if the Keyvaluelist is a value out of range
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureAttrTest, AudioCaptureSetExtraParams_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    char keyValueList[] = "attr-para=abc;";

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = ret = capture->attr.SetExtraParams((AudioHandle)capture, keyValueList);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureSetExtraParams_004
    * @tc.desc  Test CaptureSetExtraParams interface,return -1 if adding parameters to keyvaluelist
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureAttrTest, AudioCaptureSetExtraParams_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;\
attr-frame-count=82;attr-sampling-rate=48000;attr-para=abc";

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.SetExtraParams((AudioHandle)capture, keyValueList);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureSetExtraParams_005
    * @tc.desc  Test CaptureSetExtraParams interface,return 0 if set ExtraParams When the key is the same and the value
    is different
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureAttrTest, AudioCaptureSetExtraParams_005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    char keyValueList[] = "attr-route=1;attr-format=32;attr-frame-count=4096;";
    char keyValueListExp[] = "attr-route=1;attr-format=32;attr-channels=2;attr-frame-count=4096;\
attr-sampling-rate=48000";
    char keyValueListValue[256] = {};
    int32_t listLenth = 256;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartCapture(manager, &capture, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.SetExtraParams((AudioHandle)capture, keyValueList);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.GetExtraParams((AudioHandle)capture, keyValueListValue, listLenth);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_STREQ(keyValueListExp, keyValueListValue);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureSetExtraParams_006
    * @tc.desc  Test CaptureSetExtraParams interface,return -1 if set the parameter in keyvaluelist as an abnormal value
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureAttrTest, AudioCaptureSetExtraParams_006, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    char attrSamplingRateError[] = "attr-sampling-rate=1234567;";
    char attrChannelsError[] = "attr-channels=3;";
    char attrFrameCountError[] = "attr-frame-count=111111111111111111111;";
    char attrRouteError[] = "attr-route=5;";
    char attrFormateError[] = "attr-formate=12;";

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.SetExtraParams((AudioHandle)capture, attrSamplingRateError);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
    ret = capture->attr.SetExtraParams((AudioHandle)capture, attrChannelsError);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
    ret = capture->attr.SetExtraParams((AudioHandle)capture, attrFrameCountError);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
    ret = capture->attr.SetExtraParams((AudioHandle)capture, attrRouteError);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
    ret = capture->attr.SetExtraParams((AudioHandle)capture, attrFormateError);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureSetExtraParams_007
    * @tc.desc  Test CaptureSetExtraParams interface,return -1 if set the parameter render is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureAttrTest, AudioCaptureSetExtraParams_007, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;
    char keyValueList[] = "attr-format=2;";

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.SetExtraParams((AudioHandle)captureNull, keyValueList);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureSetExtraParams_008
    * @tc.desc  Test CaptureSetExtraParams interface,return -1 if set the format of ExtraParams is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureAttrTest, AudioCaptureSetExtraParams_008, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    char keyValueListNull[] = "attr-format=;";

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.SetExtraParams((AudioHandle)capture, keyValueListNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureGetExtraParams_001
    * @tc.desc  Test CaptureGetExtraParams interface,return 0 if the RenderGetExtraParams was obtained successfully
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureAttrTest, AudioCaptureGetExtraParams_001, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t count = 0;
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    struct AudioSampleAttributes attrsValue = {};
    char keyValueList[] = "attr-format=24;attr-frame-count=4096;";
    char keyValueListExp[] = "attr-route=0;attr-format=24;attr-channels=2;attr-frame-count=4096;\
attr-sampling-rate=48000";
    char keyValueListValue[256] = {};
    int32_t listLenth = 256;
    int32_t formatExp = 3;
    uint32_t sampleRateExp = 48000;
    uint32_t channelCountExp = 2;
    uint32_t frameCountExp = 4096;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartCapture(manager, &capture, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.SetExtraParams((AudioHandle)capture, keyValueList);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.GetExtraParams((AudioHandle)capture, keyValueListValue, listLenth);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_STREQ(keyValueListExp, keyValueListValue);

    ret = capture->attr.GetSampleAttributes(capture, &attrsValue);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(formatExp, attrsValue.format);
    EXPECT_EQ(sampleRateExp, attrsValue.sampleRate);
    EXPECT_EQ(channelCountExp, attrsValue.channelCount);
    ret = capture->attr.GetFrameCount(capture, &count);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(count, frameCountExp);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureGetExtraParams_002
    * @tc.desc  Test CaptureGetExtraParams interface,return 0 if set the parameter render is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureAttrTest, AudioCaptureGetExtraParams_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;
    char keyValueList[] = "attr-format=32;";
    char keyValueListValue[256] = {};
    int32_t listLenth = 256;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.SetExtraParams((AudioHandle)capture, keyValueList);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.GetExtraParams((AudioHandle)captureNull, keyValueListValue, listLenth);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureGetExtraParams_003
    * @tc.desc  Test CaptureGetExtraParams interface,return 0 if set listlength to be less than the actual length
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureAttrTest, AudioCaptureGetExtraParams_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;\
attr-frame-count=82;attr-sampling-rate=48000;";
    char keyValueListValue[256] = {};
    int32_t listLenth = 8;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.SetExtraParams((AudioHandle)capture, keyValueList);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.GetExtraParams((AudioHandle)capture, keyValueListValue, listLenth);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureGetExtraParams_004
    * @tc.desc  Test CaptureGetExtraParams interface,return 0 if set listlenth equal to the actual length
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureAttrTest, AudioCaptureGetExtraParams_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;attr-frame-count=11111111111111111111;\
attr-sampling-rate=48000";
    char keyValueListValue[256] = {};
    int32_t listLenth = 107;

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateStartCapture(manager, &capture, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.SetExtraParams((AudioHandle)capture, keyValueList);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.GetExtraParams((AudioHandle)capture, keyValueListValue, listLenth);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_STREQ(keyValueList, keyValueListValue);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureAddAudioEffect_001
    * @tc.desc  Test CaptureAddAudioEffect interface,return 0 if set the legal parameter
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureAttrTest, AudioCaptureAddAudioEffect_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    uint64_t effectid = 14;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.AddAudioEffect((AudioHandle)capture, effectid);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureAddAudioEffect_001
    * @tc.desc  Test CaptureAddAudioEffect interface,return -3 if set the parameter Capture is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureAttrTest, AudioCaptureAddAudioEffect_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;
    uint64_t effectid = 14;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.AddAudioEffect((AudioHandle)captureNull, effectid);
#ifdef AUDIO_ADM_SERVICE
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
#else
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
#endif

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureRemoveAudioEffect_001
    * @tc.desc  Test CaptureAddAudioEffect interface,return 0 if set the legal parameter
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureAttrTest, AudioCaptureRemoveAudioEffect_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    uint64_t effectid = 14;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.AddAudioEffect((AudioHandle)capture, effectid);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.RemoveAudioEffect((AudioHandle)capture, effectid);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioCaptureAddAudioEffect_002
    * @tc.desc  Test CaptureAddAudioEffect interface,return -3 if setting the parameter Capture is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiCaptureAttrTest, AudioCaptureRemoveAudioEffect_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;
    uint64_t effectid = 14;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.RemoveAudioEffect((AudioHandle)captureNull, effectid);
#ifdef AUDIO_ADM_SERVICE
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
#else
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
#endif

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
}
