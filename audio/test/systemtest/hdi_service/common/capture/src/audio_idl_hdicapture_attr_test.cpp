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
#include "hdi_service_common.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
class AudioIdlHdiCaptureAttrTest : public testing::Test {
public:
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    static TestAudioManager *(*GetAudioManager)(const char *);
    static TestAudioManager *manager;
    static void *handleSo;
    static void (*AudioManagerRelease)(struct AudioManager *);
    static void (*AudioAdapterRelease)(struct AudioAdapter *);
    static void (*AudioCaptureRelease)(struct AudioCapture *);
    void ReleaseCaptureSource(void);
};

using THREAD_FUNC = void *(*)(void *);

TestAudioManager *(*AudioIdlHdiCaptureAttrTest::GetAudioManager)(const char *) = nullptr;
TestAudioManager *AudioIdlHdiCaptureAttrTest::manager = nullptr;
void *AudioIdlHdiCaptureAttrTest::handleSo = nullptr;
void (*AudioIdlHdiCaptureAttrTest::AudioManagerRelease)(struct AudioManager *) = nullptr;
void (*AudioIdlHdiCaptureAttrTest::AudioAdapterRelease)(struct AudioAdapter *) = nullptr;
void (*AudioIdlHdiCaptureAttrTest::AudioCaptureRelease)(struct AudioCapture *) = nullptr;

void AudioIdlHdiCaptureAttrTest::SetUpTestCase(void)
{
    char absPath[PATH_MAX] = {0};
    char *path = realpath(RESOLVED_PATH.c_str(), absPath);
    ASSERT_NE(nullptr, path);
    handleSo = dlopen(absPath, RTLD_LAZY);
    ASSERT_NE(nullptr, handleSo);
    GetAudioManager = (TestAudioManager *(*)(const char *))(dlsym(handleSo, FUNCTION_NAME.c_str()));
    ASSERT_NE(nullptr, GetAudioManager);
    (void)HdfRemoteGetCallingPid();
    manager = GetAudioManager(IDL_SERVER_NAME.c_str());
    ASSERT_NE(nullptr, manager);
    AudioManagerRelease = (void (*)(struct AudioManager *))(dlsym(handleSo, "AudioManagerRelease"));
    ASSERT_NE(nullptr, AudioManagerRelease);
    AudioAdapterRelease = (void (*)(struct AudioAdapter *))(dlsym(handleSo, "AudioAdapterRelease"));
    ASSERT_NE(nullptr, AudioAdapterRelease);
    AudioCaptureRelease = (void (*)(struct AudioCapture *))(dlsym(handleSo, "AudioCaptureRelease"));
    ASSERT_NE(nullptr, AudioCaptureRelease);
}

void AudioIdlHdiCaptureAttrTest::TearDownTestCase(void)
{
    if (AudioManagerRelease != nullptr) {
        AudioManagerRelease(manager);
        manager = nullptr;
    }
    if (GetAudioManager != nullptr) {
        GetAudioManager = nullptr;
    }
    if (handleSo != nullptr) {
        dlclose(handleSo);
        handleSo = nullptr;
    }
}

void AudioIdlHdiCaptureAttrTest::SetUp(void)
{
    int32_t ret;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

void AudioIdlHdiCaptureAttrTest::TearDown(void)
{
    ReleaseCaptureSource();
}

void AudioIdlHdiCaptureAttrTest::ReleaseCaptureSource(void)
{
    if (capture != nullptr && AudioCaptureRelease != nullptr) {
        adapter->DestroyCapture(adapter);
        AudioCaptureRelease(capture);
        capture = nullptr;
    }
    if (adapter != nullptr && AudioAdapterRelease != nullptr) {
        manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
        AudioAdapterRelease(adapter);
        adapter = nullptr;
    }
}
/**
* @tc.name  Test AudioCaptureGetFrameSize API via legal input
* @tc.number  SUB_Audio_HDI_CaptureGetFrameSize_001
* @tc.desc  test AudioCaptureGetFrameSize interface, return 0 is call successfully.
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, SUB_Audio_HDI_CaptureGetFrameSize_001, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t size = 0;
    ASSERT_NE(nullptr, capture);
    ret = capture->GetFrameSize(capture, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);
}
/**
* @tc.name  Test AudioCaptureGetFrameSize API via setting the parameter handle is nullptr
* @tc.number  SUB_Audio_HDI_CaptureGetFrameSize_Null_002
* @tc.desc  test AudioCaptureGetFrameSize interface, return -3/-4 if the parameter handle is nullptr.
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, SUB_Audio_HDI_CaptureGetFrameSize_Null_002, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t size = 0;
    struct AudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = capture->GetFrameSize(captureNull, &size);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
* @tc.name  Test AudioCaptureGetFrameSize API via setting the parameter size is nullptr
* @tc.number  SUB_Audio_HDI_CaptureGetFrameSize_Null_003
* @tc.desc  test AudioCaptureGetFrameSize interface, return -3 if the parameter size is nullptr.
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, SUB_Audio_HDI_CaptureGetFrameSize_Null_003, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t *sizeNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = capture->GetFrameSize(capture, sizeNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**
* @tc.name  Test AudioCaptureGetFrameCount API via legal input
* @tc.number  SUB_Audio_HDI_CaptureGetFrameCount_001
* @tc.desc  test AudioCaptureGetFrameCount interface, return 0 if the FrameCount is called after creating the object.
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, SUB_Audio_HDI_CaptureGetFrameCount_001, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t count = 0;
    ASSERT_NE(nullptr, capture);
    ret = capture->GetFrameCount(capture, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(count, INITIAL_VALUE);
}
/**
* @tc.name  Test AudioCaptureGetFrameCount API via legal input in the difference scene
* @tc.number  SUB_Audio_HDI_CaptureGetFrameCount_001
* @tc.desc  test AudioCaptureGetFrameCount interface, return 0 if the GetFrameCount is called after started.
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, SUB_Audio_HDI_CaptureGetFrameCount_002, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t count = 0;
    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetFrameCount(capture, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);
    capture->Stop(capture);
}
/**
* @tc.name  Test AudioCaptureGetFrameCount API via setting the parameter handle is nullptr
* @tc.number  SUB_Audio_HDI_CaptureGetFrameCount_Null_003
* @tc.desc  test AudioCaptureGetFrameCount interface, return -3/-4 if the parameter handle is nullptr.
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, SUB_Audio_HDI_CaptureGetFrameCount_Null_003, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t count = 0;
    struct AudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = capture->GetFrameCount(captureNull, &count);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}

/**
* @tc.name  Test AudioCaptureGetFrameCount API via setting the parameter handle is nullptr
* @tc.number  SUB_Audio_HDI_CaptureGetFrameCount_Null_004
* @tc.desc  test AudioCaptureGetFrameCount interface, return -3 if the parameter handle is nullptr.
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, SUB_Audio_HDI_CaptureGetFrameCount_Null_004, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t *countNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = capture->GetFrameCount(capture, countNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**
* @tc.name  Test CaptureGetCurrentChannelId API via legal input
* @tc.number  SUB_Audio_HDI_RenderGetCurrentChannelId_001
* @tc.desc  Test GetCurrentChannelId, return 0 if the default CurrentChannelId is obtained successfully
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, SUB_Audio_HDI_CaptureGetCurrentChannelId_001, TestSize.Level1)
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
* @tc.name  Test GetCurrentChannelId API via CurrentChannelId is obtained after started
* @tc.number  SUB_Audio_HDI_CaptureGetCurrentChannelId_003
* @tc.desc  Test GetCurrentChannelId interface, return 0 if CurrentChannelId is obtained after started
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, SUB_Audio_HDI_CaptureGetCurrentChannelId_003, TestSize.Level1)
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
* @tc.name  Test GetCurrentChannelId API via setting the parameter capture is nullptr
* @tc.number  SUB_Audio_HDI_CaptureGetCurrentChannelId_Null_004
* @tc.desc  Test GetCurrentChannelId interface,return -3/-4 if set the parameter capture is nullptr
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, SUB_Audio_HDI_CaptureGetCurrentChannelId_Null_004, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t channelId = 0;
    struct AudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = capture->GetCurrentChannelId(captureNull, &channelId);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
* @tc.name  Test CaptureGetCurrentChannelId API via setting the parameter channelId is nullptr
* @tc.number  SUB_Audio_HDI_CaptureGetCurrentChannelId_Null_005
* @tc.desc  Test CaptureGetCurrentChannelId interface, return -3 if setting the parameter channelId is nullptr
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, SUB_Audio_HDI_CaptureGetCurrentChannelId_Null_005, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t *channelIdNull = nullptr;
    ASSERT_NE(nullptr, capture);
    ret = capture->GetCurrentChannelId(capture, channelIdNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**
* @tc.name  Test CaptureSetExtraParams API via setting ExtraParams during playback
* @tc.number  SUB_Audio_HDI_CaptureSetExtraParams_001
* @tc.desc  Test CaptureSetExtraParams interface,return 0 if the ExtraParams is set during playback
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, SUB_Audio_HDI_CaptureSetExtraParams_001, TestSize.Level1)
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
        .capture = capture, .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .self = this, .pins = PIN_IN_MIC,
        .path = AUDIO_CAPTURE_FILE.c_str(), .fileSize = FILESIZE
    };

    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)RecordAudio, &audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);
    sleep(1);
    if (audiopara.capture != nullptr) {
        ret = audiopara.capture->SetExtraParams(audiopara.capture, keyValueList);
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

    ret = ThreadRelease(audiopara);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  Test CaptureSetExtraParams API via setting some parameters after playing
* @tc.number  SUB_Audio_HDI_CaptureSetExtraParams_002
* @tc.desc  Test CaptureSetExtraParams interface,return 0 if some parameters is set after playing
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, SUB_Audio_HDI_CaptureSetExtraParams_002, TestSize.Level1)
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
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetExtraParams(capture, keyValueListValueOne, listLenth);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_STREQ(keyValueListOneExp, keyValueListValueOne);
    ret = capture->SetExtraParams(capture, keyValueListTwo);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetExtraParams(capture, keyValueListValueTwo, listLenth);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_STREQ(keyValueListTwoExp, keyValueListValueTwo);
    ret = capture->SetExtraParams(capture, keyValueListThr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetExtraParams(capture, keyValueListValueThr, listLenth);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_STREQ(keyValueListThrExp, keyValueListValueThr);
    ret = capture->SetExtraParams(capture, keyValueListFour);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetExtraParams(capture, keyValueListValueFour, listLenth);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_STREQ(keyValueListFourExp, keyValueListValueFour);

    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  Test CaptureSetExtraParams API via setting keyvaluelist to a value outside the range
* @tc.number  SUB_Audio_HDI_CaptureSetExtraParams_003
* @tc.desc  Test CaptureSetExtraParams interface,return -1 if the Keyvaluelist is a value out of range
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, SUB_Audio_HDI_CaptureSetExtraParams_003, TestSize.Level1)
{
    int32_t ret = -1;
    char keyValueList[] = "attr-para=abc;";
    ASSERT_NE(nullptr, capture);
    ret = ret = capture->SetExtraParams(capture, keyValueList);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name  Test CaptureSetExtraParams API via adding parameters to keyvaluelist
* @tc.number  SUB_Audio_HDI_CaptureSetExtraParams_004
* @tc.desc  Test CaptureSetExtraParams interface,return -1 if adding parameters to keyvaluelist
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, SUB_Audio_HDI_CaptureSetExtraParams_004, TestSize.Level1)
{
    int32_t ret = -1;
    char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;\
attr-frame-count=82;attr-sampling-rate=48000;attr-para=abc";
    ASSERT_NE(nullptr, capture);
    ret = capture->SetExtraParams(capture, keyValueList);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name  Test CaptureSetExtraParams API via setting ExtraParams When the key is the same and the value is
    different
* @tc.number  SUB_Audio_HDI_CaptureSetExtraParams_005
* @tc.desc  Test CaptureSetExtraParams interface,return 0 if set ExtraParams When the key is the same and the value
    is different
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, SUB_Audio_HDI_CaptureSetExtraParams_005, TestSize.Level1)
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
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetExtraParams(capture, keyValueListValue, listLenth);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_STREQ(keyValueListExp, keyValueListValue);
    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  Test CaptureSetExtraParams API via setting the parameter in keyvaluelist as an abnormal value
* @tc.number  SUB_Audio_HDI_CaptureSetExtraParams_006
* @tc.desc  Test CaptureSetExtraParams interface,return -1 if set the parameter in keyvaluelist as an abnormal value
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, SUB_Audio_HDI_CaptureSetExtraParams_006, TestSize.Level1)
{
    int32_t ret = -1;
    char attrSamplingRateError[] = "attr-sampling-rate=1234567;";
    char attrChannelsError[] = "attr-channels=3;";
    char attrFrameCountError[] = "attr-frame-count=111111111111111111111;";
    char attrRouteError[] = "attr-route=5;";
    char attrFormateError[] = "attr-formate=12;";
    ASSERT_NE(nullptr, capture);
    ret = capture->SetExtraParams(capture, attrSamplingRateError);
    EXPECT_EQ(HDF_FAILURE, ret);
    ret = capture->SetExtraParams(capture, attrChannelsError);
    EXPECT_EQ(HDF_FAILURE, ret);
    ret = capture->SetExtraParams(capture, attrFrameCountError);
    EXPECT_EQ(HDF_FAILURE, ret);
    ret = capture->SetExtraParams(capture, attrRouteError);
    EXPECT_EQ(HDF_FAILURE, ret);
    ret = capture->SetExtraParams(capture, attrFormateError);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name  Test CaptureSetExtraParams API via setting the parameter render is nullptr
* @tc.number  SUB_Audio_HDI_CaptureSetExtraParams_Null_007
* @tc.desc  Test CaptureSetExtraParams interface,return -3/-4 if set the parameter render is nullptr
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, SUB_Audio_HDI_CaptureSetExtraParams_Null_007, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioCapture *captureNull = nullptr;
    char keyValueList[] = "attr-format=2;";
    ASSERT_NE(nullptr, capture);
    ret = capture->SetExtraParams(captureNull, keyValueList);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
* @tc.name  Test CaptureSetExtraParams API via setting the format of ExtraParams is nullptr
* @tc.number  SUB_Audio_HDI_CaptureSetExtraParams_Null_008
* @tc.desc  Test CaptureSetExtraParams interface,return -1 if set the format of ExtraParams is nullptr
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, SUB_Audio_HDI_CaptureSetExtraParams_Null_008, TestSize.Level1)
{
    int32_t ret = -1;
    char keyValueListNull[] = "attr-format=;";
    ASSERT_NE(nullptr, capture);
    ret = capture->SetExtraParams(capture, keyValueListNull);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name  Test CaptureGetExtraParams API via legal input
* @tc.number  SUB_Audio_HDI_CaptureGetExtraParams_001
* @tc.desc  Test CaptureGetExtraParams interface,return 0 if the RenderGetExtraParams was obtained successfully
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, SUB_Audio_HDI_CaptureGetExtraParams_001, TestSize.Level1)
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
    uint32_t sampleRateExp = 48000;
    uint32_t channelCountExp = 2;
    uint32_t frameCountExp = 4096;

    ASSERT_NE(nullptr, capture);
    ret = AudioCaptureStartAndOneFrame(capture);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = capture->SetExtraParams(capture, keyValueList);
    EXPECT_EQ(HDF_SUCCESS, ret);
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

    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  Test CaptureGetExtraParams API via setting the parameter render is nullptr
* @tc.number  SUB_Audio_HDI_CaptureGetExtraParams_Null_002
* @tc.desc  Test CaptureGetExtraParams interface,return -3/-4 if set the parameter render is nullptr
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, SUB_Audio_HDI_CaptureGetExtraParams_Null_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioCapture *captureNull = nullptr;
    char keyValueList[] = "attr-format=32;";
    char keyValueListValue[256] = {};
    int32_t listLenth = 256;

    ASSERT_NE(nullptr, capture);
    ret = capture->SetExtraParams(capture, keyValueList);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetExtraParams(captureNull, keyValueListValue, listLenth);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
* @tc.name  Test CaptureGetExtraParams API via setting listlength to be less than the actual length
* @tc.number  SUB_Audio_HDI_CaptureGetExtraParams_003
* @tc.desc  Test CaptureGetExtraParams interface,return -1 if set listlength to be less than the actual length
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, SUB_Audio_HDI_CaptureGetExtraParams_003, TestSize.Level1)
{
    int32_t ret = -1;
    char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;\
attr-frame-count=82;attr-sampling-rate=48000;";
    char keyValueListValue[256] = {};
    int32_t listLenth = 8;
    ASSERT_NE(nullptr, capture);
    ret = capture->SetExtraParams(capture, keyValueList);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetExtraParams(capture, keyValueListValue, listLenth);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name  Test CaptureGetExtraParams API via setting listlenth equal to the actual length
* @tc.number  SUB_Audio_HDI_CaptureGetExtraParams_004
* @tc.desc  Test CaptureGetExtraParams interface,return 0 if set listlenth equal to the actual length
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, SUB_Audio_HDI_CaptureGetExtraParams_004, TestSize.Level1)
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
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->GetExtraParams(capture, keyValueListValue, listLenth);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_STREQ(keyValueList, keyValueListValue);

    ret = capture->Stop(capture);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via setting the capture is nullptr .
* @tc.number  SUB_Audio_HDI_CaptureSetSampleAttributes_Null_007
* @tc.desc   Test AudioCaptureSetSampleAttributes interface, return -3/-4 if the capture is nullptr.
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, SUB_Audio_HDI_CaptureSetSampleAttributes_Null_007, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_8000);
    ret = capture->SetSampleAttributes(captureNull, &attrs);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    ret = capture->SetSampleAttributes(capture, nullptr);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
* @tc.name  Test AudioCaptureGetSampleAttributes API via setting the capture is nullptr .
* @tc.number  SUB_Audio_HDI_CaptureGetSampleAttributes_Null_002
* @tc.desc   Test AudioCaptureGetSampleAttributes interface, return -3/-4 if the capture is nullptr.
* @tc.author: ZengLifeng
*/
HWTEST_F(AudioIdlHdiCaptureAttrTest, SUB_Audio_HDI_CaptureGetSampleAttributes_Null_002, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, capture);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_48000);
    ret = capture->GetSampleAttributes(captureNull, &attrs);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    ret = capture->GetSampleAttributes(capture, nullptr);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
}
