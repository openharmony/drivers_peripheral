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
#include "hdi_service_common.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
class AudioIdlHdiCaptureAttrTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioCapture *capture = nullptr;
    static TestAudioManager *manager;
    uint32_t captureId_ = 0;
};
    
using THREAD_FUNC = void *(*)(void *);
TestAudioManager *AudioIdlHdiCaptureAttrTest::manager = nullptr;

void AudioIdlHdiCaptureAttrTest::SetUpTestCase(void)
{
    manager = IAudioManagerGet(IS_STUB);
    ASSERT_NE(nullptr, manager);
}

void AudioIdlHdiCaptureAttrTest::TearDownTestCase(void)
{
    if (manager != nullptr) {
        (void)IAudioManagerRelease(manager, IS_STUB);
    }
}

void AudioIdlHdiCaptureAttrTest::SetUp(void)
{
    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture, &captureId_);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

void AudioIdlHdiCaptureAttrTest::TearDown(void)
{
    int32_t ret = ReleaseCaptureSource(manager, adapter, capture, captureId_);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

/**
* @tc.name  AudioCaptureGetFrameSize_001
* @tc.desc  test AudioCaptureGetFrameSize interface, return 0 is call successfully.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, AudioCaptureGetFrameSize_001, TestSize.Level0)
{
    int32_t ret = -1;
    uint64_t size = 0;
    ASSERT_NE(nullptr, capture);
    ret = capture->GetFrameSize(capture, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);
}
/**
* @tc.name  AudioCaptureGetFrameSizeNull_002
* @tc.desc  test AudioCaptureGetFrameSize interface, return -3/-4 if the parameter handle is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, AudioCaptureGetFrameSizeNull_002, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t size = 0;
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = capture->GetFrameSize(captureNull, &size);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
}
/**
* @tc.name  AudioCaptureGetFrameSizeNull_003
* @tc.desc  test AudioCaptureGetFrameSize interface, return -3 if the parameter size is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, AudioCaptureGetFrameSizeNull_003, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t *sizeNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = capture->GetFrameSize(capture, sizeNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**
* @tc.name  AudioCaptureGetFrameCount_001
* @tc.desc  test AudioCaptureGetFrameCount interface, return 0 if the FrameCount is called after creating the object.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, AudioCaptureGetFrameCount_001, TestSize.Level0)
{
    int32_t ret = -1;
    uint64_t count = 0;
    ASSERT_NE(nullptr, capture);
    ret = capture->GetFrameCount(capture, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GE(count, INITIAL_VALUE);
}
/**
* @tc.name  AudioCaptureGetFrameCount_001
* @tc.desc  test AudioCaptureGetFrameCount interface, return 0 if the GetFrameCount is called after started.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, AudioCaptureGetFrameCount_002, TestSize.Level0)
{
    int32_t ret = -1;
    uint64_t count = 0;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_FAILURE);
    ret = capture->GetFrameCount(capture, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);
    capture->Stop(capture);
}
/**
* @tc.name  AudioCaptureGetFrameCountNull_003
* @tc.desc  test AudioCaptureGetFrameCount interface, return -3/-4 if the parameter handle is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, AudioCaptureGetFrameCountNull_003, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t count = 0;
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = capture->GetFrameCount(captureNull, &count);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
}

/**
* @tc.name  AudioCaptureGetFrameCountNull_004
* @tc.desc  test AudioCaptureGetFrameCount interface, return -3 if the parameter handle is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, AudioCaptureGetFrameCountNull_004, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t *countNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = capture->GetFrameCount(capture, countNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**
* @tc.name  AudioRenderGetCurrentChannelId_001
* @tc.desc  Test GetCurrentChannelId, return 0 if the default CurrentChannelId is obtained successfully
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, AudioCaptureGetCurrentChannelId_001, TestSize.Level0)
{
    int32_t ret = -1;
    uint32_t channelId = 0;
    uint32_t channelIdValue = CHANNELCOUNT;
    ASSERT_NE(nullptr, capture);
    ret = capture->GetCurrentChannelId(capture, &channelId);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(channelIdValue, channelId);
}
/**
* @tc.name  AudioCaptureGetCurrentChannelId_003
* @tc.desc  Test GetCurrentChannelId interface, return 0 if CurrentChannelId is obtained after started
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, AudioCaptureGetCurrentChannelId_003, TestSize.Level0)
{
    int32_t ret = -1;
    uint32_t channelId = 0;
    uint32_t channelIdExp = 2;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->GetCurrentChannelId(capture, &channelId);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(channelIdExp, channelId);
    capture->Stop(capture);
}
/**
* @tc.name  AudioCaptureGetCurrentChannelIdNull_004
* @tc.desc  Test GetCurrentChannelId interface,return -3/-4 if set the parameter capture is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, AudioCaptureGetCurrentChannelIdNull_004, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t channelId = 0;
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = capture->GetCurrentChannelId(captureNull, &channelId);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
}
/**
* @tc.name  AudioCaptureGetCurrentChannelIdNull_005
* @tc.desc  Test CaptureGetCurrentChannelId interface, return -3 if setting the parameter channelId is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, AudioCaptureGetCurrentChannelIdNull_005, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t *channelIdNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = capture->GetCurrentChannelId(capture, channelIdNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**
* @tc.name  AudioCaptureSetExtraParams_001
* @tc.desc  Test CaptureSetExtraParams interface,return 0 if the ExtraParams is set during playback
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, AudioCaptureSetExtraParams_001, TestSize.Level0)
{
    int32_t ret = -1;
    char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;attr-frame-count=82;attr-sampling-rate=48000";
    char keyValueListExp[] = "attr-route=1;attr-format=32;attr-channels=2;attr-sampling-rate=48000";
    size_t index = 1;
    char keyValueListValue[256] = {};
    int32_t listLenth = 256;
    uint64_t FILESIZE = 1024;
    ASSERT_NE(nullptr, capture);
    struct PrepareAudioPara audiopara = {
        .capture = capture, .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC,
        .path = AUDIO_CAPTURE_FILE.c_str(), .fileSize = FILESIZE
    };

    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)RecordAudio, &audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);
    sleep(1);
    if (audiopara.capture != nullptr) {
        ret = audiopara.capture->SetExtraParams(audiopara.capture, keyValueList);
        if (ret == HDF_SUCCESS) {
            EXPECT_EQ(HDF_SUCCESS, ret);
            ret = audiopara.capture->GetExtraParams(audiopara.capture, keyValueListValue, listLenth);
            EXPECT_EQ(HDF_SUCCESS, ret);
            string strGetValue = keyValueListValue;
            size_t indexAttr = strGetValue.find("attr-frame-count");
            size_t indexFlag = strGetValue.rfind(";");
            if (indexAttr != string::npos && indexFlag != string::npos) {
                strGetValue.replace(indexAttr, indexFlag - indexAttr + index, "");
            }
            EXPECT_STREQ(keyValueListExp, strGetValue.c_str());
        }
    }

    ret = ThreadRelease(audiopara);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
}
/**
* @tc.name  AudioCaptureSetExtraParams_002
* @tc.desc  Test CaptureSetExtraParams interface,return 0 if some parameters is set after playing
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, AudioCaptureSetExtraParams_002, TestSize.Level0)
{
    int32_t ret = -1;
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

    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = capture->SetExtraParams(capture, keyValueListOne);
    if (ret == HDF_SUCCESS) {
        ret = capture->GetExtraParams(capture, keyValueListValueOne, listLenth);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_STREQ(keyValueListOneExp, keyValueListValueOne);
    }

    ret = capture->SetExtraParams(capture, keyValueListTwo);
    if (ret == HDF_SUCCESS) {
        ret = capture->GetExtraParams(capture, keyValueListValueTwo, listLenth);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_STREQ(keyValueListTwoExp, keyValueListValueTwo);
    }

    ret = capture->SetExtraParams(capture, keyValueListThr);
    if (ret == HDF_SUCCESS) {
        ret = capture->GetExtraParams(capture, keyValueListValueThr, listLenth);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_STREQ(keyValueListThrExp, keyValueListValueThr);
    }

    ret = capture->SetExtraParams(capture, keyValueListFour);
    if (ret == HDF_SUCCESS) {
        ret = capture->GetExtraParams(capture, keyValueListValueFour, listLenth);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_STREQ(keyValueListFourExp, keyValueListValueFour);
    }

    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioCaptureSetExtraParams_003
* @tc.desc  Test CaptureSetExtraParams interface,return -1 if the Keyvaluelist is a value out of range
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, AudioCaptureSetExtraParams_003, TestSize.Level0)
{
    int32_t ret = -1;
    char keyValueList[] = "attr-para=abc;";
    ASSERT_NE(nullptr, capture);
    ret = ret = capture->SetExtraParams(capture, keyValueList);
    ASSERT_TRUE(ret == HDF_FAILURE || ret == HDF_ERR_NOT_SUPPORT);
}
/**
* @tc.name  AudioCaptureSetExtraParams_004
* @tc.desc  Test CaptureSetExtraParams interface,return -1 if adding parameters to keyvaluelist
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, AudioCaptureSetExtraParams_004, TestSize.Level0)
{
    int32_t ret = -1;
    char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;\
attr-frame-count=82;attr-sampling-rate=48000;attr-para=abc";
    ASSERT_NE(nullptr, capture);
    ret = capture->SetExtraParams(capture, keyValueList);
    ASSERT_TRUE(ret == HDF_FAILURE || ret == HDF_ERR_NOT_SUPPORT);
}
/**
* @tc.name  AudioCaptureSetExtraParams_005
* @tc.desc  Test CaptureSetExtraParams interface,return 0 if set ExtraParams When the key is the same and the value
    is different
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, AudioCaptureSetExtraParams_005, TestSize.Level0)
{
    int32_t ret = -1;
    char keyValueList[] = "attr-route=1;attr-format=32;attr-frame-count=4096;";
    char keyValueListExp[] = "attr-route=1;attr-format=32;attr-channels=2;attr-frame-count=4096;\
attr-sampling-rate=48000";
    char keyValueListValue[256] = {};
    int32_t listLenth = 256;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ASSERT_EQ(HDF_SUCCESS, ret);
    ASSERT_NE(nullptr, capture);
    ret = capture->SetExtraParams(capture, keyValueList);
    if (ret == HDF_SUCCESS) {
        ret = capture->GetExtraParams(capture, keyValueListValue, listLenth);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_STREQ(keyValueListExp, keyValueListValue);
    }

    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioCaptureSetExtraParams_006
* @tc.desc  Test CaptureSetExtraParams interface,return -1 if set the parameter in keyvaluelist as an abnormal value
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, AudioCaptureSetExtraParams_006, TestSize.Level0)
{
    int32_t ret = -1;
    char attrSamplingRateError[] = "attr-sampling-rate=1234567;";
    char attrChannelsError[] = "attr-channels=3;";
    char attrFrameCountError[] = "attr-frame-count=111111111111111111111;";
    char attrRouteError[] = "attr-route=5;";
    char attrFormateError[] = "attr-formate=12;";
    ASSERT_NE(nullptr, capture);
    ret = capture->SetExtraParams(capture, attrSamplingRateError);
    ASSERT_TRUE(ret == HDF_FAILURE || ret == HDF_ERR_NOT_SUPPORT);
    ret = capture->SetExtraParams(capture, attrChannelsError);
    ASSERT_TRUE(ret == HDF_FAILURE || ret == HDF_ERR_NOT_SUPPORT);
    ret = capture->SetExtraParams(capture, attrFrameCountError);
    ASSERT_TRUE(ret == HDF_FAILURE || ret == HDF_ERR_NOT_SUPPORT);
    ret = capture->SetExtraParams(capture, attrRouteError);
    ASSERT_TRUE(ret == HDF_FAILURE || ret == HDF_ERR_NOT_SUPPORT);
    ret = capture->SetExtraParams(capture, attrFormateError);
    ASSERT_TRUE(ret == HDF_FAILURE || ret == HDF_ERR_NOT_SUPPORT);
}
/**
* @tc.name  AudioCaptureSetExtraParamsNull_007
* @tc.desc  Test CaptureSetExtraParams interface,return -3/-4 if set the parameter render is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, AudioCaptureSetExtraParamsNull_007, TestSize.Level1)
{
    int32_t ret = -1;
    struct IAudioCapture *captureNull = nullptr;
    char keyValueList[] = "attr-format=2;";
    ASSERT_NE(nullptr, capture);
    ret = capture->SetExtraParams(captureNull, keyValueList);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
}
/**
* @tc.name  AudioCaptureSetExtraParamsNull_008
* @tc.desc  Test CaptureSetExtraParams interface,return -1 if set the format of ExtraParams is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, AudioCaptureSetExtraParamsNull_008, TestSize.Level1)
{
    int32_t ret = -1;
    char keyValueListNull[] = "attr-format=;";
    ASSERT_NE(nullptr, capture);
    ret = capture->SetExtraParams(capture, keyValueListNull);
    ASSERT_TRUE(ret == HDF_FAILURE || ret == HDF_ERR_NOT_SUPPORT);
}
/**
* @tc.name  AudioCaptureGetExtraParams_001
* @tc.desc  Test CaptureGetExtraParams interface,return 0 if the RenderGetExtraParams was obtained successfully
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, AudioCaptureGetExtraParams_001, TestSize.Level0)
{
    int32_t ret = -1;
    uint64_t count = 0;
    struct AudioSampleAttributes attrsValue = {};
    char keyValueList[] = "attr-format=24;attr-frame-count=4096;";
    char keyValueListExp[] = "attr-route=0;attr-format=24;attr-channels=2;attr-frame-count=4096;\
attr-sampling-rate=48000";
    char keyValueListValue[256] = {};
    int32_t listLenth = 256;
    int32_t formatExp = 3;
    uint32_t channelCountExp = 2;
    uint32_t sampleRateExp = 48000;
    uint32_t frameCountExp = 4096;

    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = capture->SetExtraParams(capture, keyValueList);
    if (ret == HDF_SUCCESS) {
        ret = capture->GetExtraParams(capture, keyValueListValue, listLenth);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_STREQ(keyValueListExp, keyValueListValue);

        ret = capture->GetSampleAttributes(capture, &attrsValue);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(formatExp, attrsValue.format);
        EXPECT_EQ(sampleRateExp, attrsValue.sampleRate);
        EXPECT_EQ(channelCountExp, attrsValue.channelCount);
        ret = capture->GetFrameCount(capture, &count);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(count, frameCountExp);
    }

    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioCaptureGetExtraParamsNull_002
* @tc.desc  Test CaptureGetExtraParams interface,return -3/-4 if set the parameter render is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, AudioCaptureGetExtraParamsNull_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct IAudioCapture *captureNull = nullptr;
    char keyValueList[] = "attr-format=32;";
    char keyValueListValue[256] = {};
    int32_t listLenth = 256;

    ASSERT_NE(nullptr, capture);
    ret = capture->SetExtraParams(capture, keyValueList);
    ASSERT_TRUE(ret == HDF_SUCCESS || ret == HDF_ERR_NOT_SUPPORT);
    ret = capture->GetExtraParams(captureNull, keyValueListValue, listLenth);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
}
/**
* @tc.name  AudioCaptureGetExtraParams_003
* @tc.desc  Test CaptureGetExtraParams interface,return -1 if set listlength to be less than the actual length
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, AudioCaptureGetExtraParams_003, TestSize.Level0)
{
    int32_t ret = -1;
    char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;\
attr-frame-count=82;attr-sampling-rate=48000;";
    char keyValueListValue[256] = {};
    int32_t listLenth = 8;
    ASSERT_NE(nullptr, capture);
    ret = capture->SetExtraParams(capture, keyValueList);
    if (ret == HDF_SUCCESS) {
        ret = capture->GetExtraParams(capture, keyValueListValue, listLenth);
        EXPECT_EQ(HDF_FAILURE, ret);
    }
}
/**
* @tc.name  AudioCaptureGetExtraParams_004
* @tc.desc  Test CaptureGetExtraParams interface,return 0 if set listlenth equal to the actual length
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, AudioCaptureGetExtraParams_004, TestSize.Level0)
{
    int32_t ret = -1;
    char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;attr-frame-count=11111111111111111111;\
attr-sampling-rate=48000";
    char keyValueListValue[256] = {};
    int32_t listLenth = 107;

    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = capture->SetExtraParams(capture, keyValueList);
    if (ret == HDF_SUCCESS) {
        ret = capture->GetExtraParams(capture, keyValueListValue, listLenth);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_STREQ(keyValueList, keyValueListValue);
    }

    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  AudioCaptureSetSampleAttributesNull_007
* @tc.desc   Test AudioCaptureSetSampleAttributes interface, return -3/-4 if the capture is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, AudioCaptureSetSampleAttributesNull_007, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_TYPE_PCM_24_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_8000);
    ret = capture->SetSampleAttributes(captureNull, &attrs);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
    ret = capture->SetSampleAttributes(capture, nullptr);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
}
/**
* @tc.name  AudioCaptureGetSampleAttributesNull_002
* @tc.desc   Test AudioCaptureGetSampleAttributes interface, return -3/-4 if the capture is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, AudioCaptureGetSampleAttributesNull_002, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct IAudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_TYPE_PCM_24_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_48000);
    ret = capture->GetSampleAttributes(captureNull, &attrs);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
    ret = capture->GetSampleAttributes(capture, nullptr);
    ASSERT_TRUE(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT);
}
}
