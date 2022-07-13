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
    static TestAudioManager *(*GetAudioManager)();
    static void *handleSo;
#ifdef AUDIO_MPI_SO
    static int32_t (*SdkInit)();
    static void (*SdkExit)();
    static void *sdkSo;
#endif
    int32_t AudioCaptureStart(const string path, struct AudioCapture *capture) const;
};

using THREAD_FUNC = void *(*)(void *);

TestAudioManager *(*AudioHdiCaptureAttrTest::GetAudioManager)() = nullptr;
void *AudioHdiCaptureAttrTest::handleSo = nullptr;
#ifdef AUDIO_MPI_SO
    int32_t (*AudioHdiCaptureAttrTest::SdkInit)() = nullptr;
    void (*AudioHdiCaptureAttrTest::SdkExit)() = nullptr;
    void *AudioHdiCaptureAttrTest::sdkSo = nullptr;
#endif

void AudioHdiCaptureAttrTest::SetUpTestCase(void)
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

void AudioHdiCaptureAttrTest::TearDownTestCase(void)
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

void AudioHdiCaptureAttrTest::SetUp(void) {}
void AudioHdiCaptureAttrTest::TearDown(void) {}

int32_t AudioHdiCaptureAttrTest::AudioCaptureStart(const string path, struct AudioCapture *capture) const
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    if (capture == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    ret = InitAttrs(attrs);
    if (ret < 0) {
        return ret;
    }
    FILE *file = fopen(path.c_str(), "wb+");
    if (file == nullptr) {
        return HDF_FAILURE;
    }
    ret = FrameStartCapture(capture, file, attrs);
    (void)fclose(file);
    return ret;
}
/**
* @tc.name  Test AudioCaptureGetFrameSize API via legal input
* @tc.number  SUB_Audio_hdi_CaptureGetFrameSize_0001
* @tc.desc  test AudioCaptureGetFrameSize interface, return 0 is call successfully.
* @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_hdi_CaptureGetFrameSize_0001, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t size = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.GetFrameSize(capture, &size);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioCaptureGetFrameSize API via setting the parameter handle is nullptr
* @tc.number  SUB_Audio_hdi_CaptureGetFrameSize_0002
* @tc.desc  test AudioCaptureGetFrameSize interface, return -1 if the parameter handle is nullptr.
* @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_hdi_CaptureGetFrameSize_0002, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t size = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = capture->attr.GetFrameSize(captureNull, &size);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioCaptureGetFrameSize API via setting the parameter size is nullptr
* @tc.number  SUB_Audio_hdi_CaptureGetFrameSize_0003
* @tc.desc  test AudioCaptureGetFrameSize interface, return -1 if the parameter size is nullptr.
* @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_hdi_CaptureGetFrameSize_0003, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t *sizeNull = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = capture->attr.GetFrameSize(capture, sizeNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioCaptureGetFrameCount API via legal input
* @tc.number  SUB_Audio_hdi_CaptureGetFrameCount_0001
* @tc.desc  test AudioCaptureGetFrameCount interface, return 0 if the FrameCount is called after creating the object.
* @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_hdi_CaptureGetFrameCount_0001, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t count = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = capture->attr.GetFrameCount(capture, &count);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(count, INITIAL_VALUE);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioCaptureGetFrameCount API via legal input in the difference scene
* @tc.number  SUB_Audio_hdi_CaptureGetFrameCount_0001
* @tc.desc  test AudioCaptureGetFrameCount interface, return 0 if the GetFrameCount is called after started.
* @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_hdi_CaptureGetFrameCount_0002, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t count = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = capture->attr.GetFrameCount(capture, &count);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioCaptureGetFrameCount API via setting the parameter handle is nullptr
* @tc.number  SUB_Audio_hdi_CaptureGetFrameCount_0003
* @tc.desc  test AudioCaptureGetFrameCount interface, return -1 if the parameter handle is nullptr.
* @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_hdi_CaptureGetFrameCount_0003, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t count = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = capture->attr.GetFrameCount(captureNull, &count);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}

/**
* @tc.name  Test AudioCaptureGetFrameCount API via setting the parameter handle is nullptr
* @tc.number  SUB_Audio_hdi_CaptureGetFrameCount_0004
* @tc.desc  test AudioCaptureGetFrameCount interface, return -1 if the parameter handle is nullptr.
* @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_hdi_CaptureGetFrameCount_0004, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t *countNull = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = capture->attr.GetFrameCount(capture, countNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test CaptureGetCurrentChannelId API via legal input
    * @tc.number  SUB_Audio_HDI_RenderGetCurrentChannelId_0001
    * @tc.desc  Test GetCurrentChannelId, return 0 if the default CurrentChannelId is obtained successfully
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_CaptureGetCurrentChannelId_0001, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t channelId = 0;
    uint32_t channelIdValue = CHANNELCOUNT;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = capture->attr.GetCurrentChannelId(capture, &channelId);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(channelIdValue, channelId);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test GetCurrentChannelId API via CurrentChannelId is obtained after started
    * @tc.number  SUB_Audio_HDI_CaptureGetCurrentChannelId_0003
    * @tc.desc  Test GetCurrentChannelId interface, return 0 if CurrentChannelId is obtained after started
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_CaptureGetCurrentChannelId_0003, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t channelId = 0;
    uint32_t channelIdExp = 2;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = capture->attr.GetCurrentChannelId(capture, &channelId);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(channelIdExp, channelId);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test GetCurrentChannelId API via setting the parameter capture is nullptr
    * @tc.number  SUB_Audio_HDI_RenderGetCurrentChannelId_0004
    * @tc.desc  Test GetCurrentChannelId interface,return -1 if set the parameter capture is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_CaptureGetCurrentChannelId_0004, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t channelId = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = capture->attr.GetCurrentChannelId(captureNull, &channelId);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test CaptureGetCurrentChannelId API via setting the parameter channelId is nullptr
    * @tc.number  SUB_Audio_HDI_RenderGetCurrentChannelId_0005
    * @tc.desc  Test CaptureGetCurrentChannelId interface, return -1 if setting the parameter channelId is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_CaptureGetCurrentChannelId_0005, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t *channelIdNull = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = capture->attr.GetCurrentChannelId(capture, channelIdNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test CaptureSetExtraParams API via setting ExtraParams during playback
    * @tc.number  SUB_Audio_HDI_CaptureSetExtraParams_0001
    * @tc.desc  Test CaptureSetExtraParams interface,return 0 if the ExtraParams is set during playback
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_CaptureSetExtraParams_0001, TestSize.Level1)
{
    int32_t ret = -1;
    char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;attr-frame-count=82;attr-sampling-rate=48000";
    char keyValueListExp[] = "attr-route=1;attr-format=32;attr-channels=2;attr-sampling-rate=48000";
    size_t index = 1;
    char keyValueListValue[256] = {};
    int32_t listLenth = 256;
    uint64_t FILESIZE = 1024;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .self = this, .pins = PIN_IN_MIC,
        .path = AUDIO_CAPTURE_FILE.c_str(), .fileSize = FILESIZE
    };
    ASSERT_NE(nullptr, GetAudioManager);
    audiopara.manager = GetAudioManager();
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
    * @tc.name  Test CaptureSetExtraParams API via setting some parameters after playing
    * @tc.number  SUB_Audio_HDI_CaptureSetExtraParams_0002
    * @tc.desc  Test CaptureSetExtraParams interface,return 0 if some parameters is set after playing
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_CaptureSetExtraParams_0002, TestSize.Level1)
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
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
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
    * @tc.name  Test CaptureSetExtraParams API via setting keyvaluelist to a value outside the range
    * @tc.number  SUB_Audio_HDI_CaptureSetExtraParams_0003
    * @tc.desc  Test CaptureSetExtraParams interface,return -1 if the Keyvaluelist is a value out of range
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_CaptureSetExtraParams_0003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    char keyValueList[] = "attr-para=abc;";

    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = ret = capture->attr.SetExtraParams((AudioHandle)capture, keyValueList);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test CaptureSetExtraParams API via adding parameters to keyvaluelist
    * @tc.number  SUB_Audio_HDI_CaptureSetExtraParams_0004
    * @tc.desc  Test CaptureSetExtraParams interface,return -1 if adding parameters to keyvaluelist
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_CaptureSetExtraParams_0004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;\
attr-frame-count=82;attr-sampling-rate=48000;attr-para=abc";

    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.SetExtraParams((AudioHandle)capture, keyValueList);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test CaptureSetExtraParams API via setting ExtraParams When the key is the same and the value is
    different
    * @tc.number  SUB_Audio_HDI_CaptureSetExtraParams_0005
    * @tc.desc  Test CaptureSetExtraParams interface,return 0 if set ExtraParams When the key is the same and the value
    is different
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_CaptureSetExtraParams_0005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    char keyValueList[] = "attr-route=1;attr-format=32;attr-frame-count=4096;";
    char keyValueListExp[] = "attr-route=1;attr-format=32;attr-channels=2;attr-frame-count=4096;\
attr-sampling-rate=48000";
    char keyValueListValue[256] = {};
    int32_t listLenth = 256;

    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
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
    * @tc.name  Test CaptureSetExtraParams API via setting the parameter in keyvaluelist as an abnormal value
    * @tc.number  SUB_Audio_HDI_CaptureSetExtraParams_0006
    * @tc.desc  Test CaptureSetExtraParams interface,return -1 if set the parameter in keyvaluelist as an abnormal value
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_CaptureSetExtraParams_0006, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    char attrSamplingRateError[] = "attr-sampling-rate=1234567;";
    char attrChannelsError[] = "attr-channels=3;";
    char attrFrameCountError[] = "attr-frame-count=111111111111111111111;";
    char attrRouteError[] = "attr-route=5;";
    char attrFormateError[] = "attr-formate=12;";

    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
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
    * @tc.name  Test CaptureSetExtraParams API via setting the parameter render is nullptr
    * @tc.number  SUB_Audio_HDI_CaptureSetExtraParams_0007
    * @tc.desc  Test CaptureSetExtraParams interface,return -1 if set the parameter render is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_CaptureSetExtraParams_0007, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;
    char keyValueList[] = "attr-format=2;";

    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.SetExtraParams((AudioHandle)captureNull, keyValueList);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test CaptureSetExtraParams API via setting the format of ExtraParams is nullptr
    * @tc.number  SUB_Audio_HDI_CaptureSetExtraParams_0008
    * @tc.desc  Test CaptureSetExtraParams interface,return -1 if set the format of ExtraParams is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_CaptureSetExtraParams_0008, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    char keyValueListNull[] = "attr-format=;";

    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.SetExtraParams((AudioHandle)capture, keyValueListNull);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test CaptureGetExtraParams API via legal input
    * @tc.number  SUB_Audio_HDI_CaptureGetExtraParams_0001
    * @tc.desc  Test CaptureGetExtraParams interface,return 0 if the RenderGetExtraParams was obtained successfully
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_CaptureGetExtraParams_0001, TestSize.Level1)
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

    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
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
    * @tc.name  Test CaptureGetExtraParams API via setting the parameter render is nullptr
    * @tc.number  SUB_Audio_HDI_CaptureGetExtraParams_0002
    * @tc.desc  Test CaptureGetExtraParams interface,return 0 if set the parameter render is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_CaptureGetExtraParams_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;
    char keyValueList[] = "attr-format=32;";
    char keyValueListValue[256] = {};
    int32_t listLenth = 256;

    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
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
    * @tc.name  Test CaptureGetExtraParams API via setting listlength to be less than the actual length
    * @tc.number  SUB_Audio_HDI_CaptureGetExtraParams_0003
    * @tc.desc  Test CaptureGetExtraParams interface,return 0 if set listlength to be less than the actual length
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_CaptureGetExtraParams_0003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;\
attr-frame-count=82;attr-sampling-rate=48000;";
    char keyValueListValue[256] = {};
    int32_t listLenth = 8;

    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
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
    * @tc.name  Test CaptureGetExtraParams API via setting listlenth equal to the actual length
    * @tc.number  SUB_Audio_HDI_CaptureGetExtraParams_0004
    * @tc.desc  Test CaptureGetExtraParams interface,return 0 if set listlenth equal to the actual length
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_CaptureGetExtraParams_0004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = {};
    struct AudioCapture *capture = nullptr;
    char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;attr-frame-count=11111111111111111111;\
attr-sampling-rate=48000";
    char keyValueListValue[256] = {};
    int32_t listLenth = 107;

    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
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
    * @tc.name  Test CaptureAddAudioEffect API via legal input
    * @tc.number  SUB_Audio_HDI_CaptureAddAudioEffect_0001
    * @tc.desc  Test CaptureAddAudioEffect interface,return 0 if set the legal parameter
    * @tc.author: liweiming
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_CaptureAddAudioEffect_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    uint64_t effectid = 14;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.AddAudioEffect((AudioHandle)capture, effectid);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test CaptureAddAudioEffect API via setting the parameter Capture is nullptr
    * @tc.number  SUB_Audio_HDI_CaptureAddAudioEffect_0001
    * @tc.desc  Test CaptureAddAudioEffect interface,return -3 if set the parameter Capture is nullptr
    * @tc.author: liweiming
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_CaptureAddAudioEffect_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;
    uint64_t effectid = 14;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
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
    * @tc.name  Test CaptureRemoveAudioEffect API via legal input
    * @tc.number  SUB_Audio_HDI_CaptureRemoveAudioEffect_0001
    * @tc.desc  Test CaptureAddAudioEffect interface,return 0 if set the legal parameter
    * @tc.author: liweiming
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_CaptureRemoveAudioEffect_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    uint64_t effectid = 14;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
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
    * @tc.name  Test CaptureAddAudioEffect API via setting the parameter Capture is nullptr
    * @tc.number  SUB_Audio_HDI_CaptureAddAudioEffect_0002
    * @tc.desc  Test CaptureAddAudioEffect interface,return -3 if setting the parameter Capture is nullptr
    * @tc.author: liweiming
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_CaptureRemoveAudioEffect_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;
    uint64_t effectid = 14;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
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
