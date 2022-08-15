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
class AudioIdlHdiRenderAttrTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioRender *render = nullptr;
    static TestAudioManager *(*GetAudioManager)(const char *);
    static TestAudioManager *manager;
    static void *handle;
    static void (*AudioManagerRelease)(struct IAudioManager *);
    static void (*AudioAdapterRelease)(struct IAudioAdapter *);
    static void (*AudioRenderRelease)(struct IAudioRender *);
    void ReleaseAudioSource(void);
};

using THREAD_FUNC = void *(*)(void *);
TestAudioManager *(*AudioIdlHdiRenderAttrTest::GetAudioManager)(const char *) = nullptr;
TestAudioManager *AudioIdlHdiRenderAttrTest::manager = nullptr;
void *AudioIdlHdiRenderAttrTest::handle = nullptr;
void (*AudioIdlHdiRenderAttrTest::AudioManagerRelease)(struct IAudioManager *) = nullptr;
void (*AudioIdlHdiRenderAttrTest::AudioAdapterRelease)(struct IAudioAdapter *) = nullptr;
void (*AudioIdlHdiRenderAttrTest::AudioRenderRelease)(struct IAudioRender *) = nullptr;

void AudioIdlHdiRenderAttrTest::SetUpTestCase(void)
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
    AudioManagerRelease = (void (*)(struct IAudioManager *))(dlsym(handle, "AudioManagerRelease"));
    ASSERT_NE(nullptr, AudioManagerRelease);
    AudioAdapterRelease = (void (*)(struct IAudioAdapter *))(dlsym(handle, "AudioAdapterRelease"));
    ASSERT_NE(nullptr, AudioAdapterRelease);
    AudioRenderRelease = (void (*)(struct IAudioRender *))(dlsym(handle, "AudioRenderRelease"));
    ASSERT_NE(nullptr, AudioRenderRelease);
}

void AudioIdlHdiRenderAttrTest::TearDownTestCase(void)
{
    if (AudioManagerRelease != nullptr) {
        AudioManagerRelease(manager);
        manager = nullptr;
    }
    if (GetAudioManager != nullptr) {
        GetAudioManager = nullptr;
    }
    if (handle != nullptr) {
        dlclose(handle);
        handle = nullptr;
    }
}

void AudioIdlHdiRenderAttrTest::SetUp(void)
{
    int32_t ret;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

void AudioIdlHdiRenderAttrTest::TearDown(void)
{
    ReleaseAudioSource();
}

void AudioIdlHdiRenderAttrTest::ReleaseAudioSource(void)
{
    int32_t ret;
    if (render != nullptr && AudioRenderRelease != nullptr) {
        ret = adapter->DestroyRender(adapter);
        EXPECT_EQ(HDF_SUCCESS, ret);
        AudioRenderRelease(render);
        render = nullptr;
    }
    if (adapter != nullptr && AudioAdapterRelease != nullptr) {
        ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
        EXPECT_EQ(HDF_SUCCESS, ret);
        AudioAdapterRelease(adapter);
        adapter = nullptr;
    }
}

/**
    * @tc.name  Test RenderGetFrameSize API via legal input
    * @tc.number  SUB_Audio_HDI_RenderGetFrameSize_001
    * @tc.desc  Test RenderGetFrameSize interface,return 0 if the FrameSize was obtained successfully
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderGetFrameSize_001, TestSize.Level1)
{
    int32_t ret;
    uint64_t size = 0;
    uint64_t zero = 0;
    ASSERT_NE(nullptr, render);

    ret = render->GetFrameSize(render, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(size, zero);
}
/**
    * @tc.name  Test AudioCaptureGetFrameSize API via setting the incoming parameter handle is nullptr
    * @tc.number  SUB_Audio_HDI_RenderGetFrameSize_Null_002
    * @tc.desc  Test RenderGetFrameSize interface,return -3/-4 if failed to get the FrameSize when handle is nullptr
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderGetFrameSize_Null_002, TestSize.Level1)
{
    int32_t ret;
    uint64_t size = 0;
    struct IAudioRender *renderNull = nullptr;
    ASSERT_NE(nullptr, render);

    ret = render->GetFrameSize(renderNull, &size);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
    * @tc.name  Test RenderGetFrameCount API via legal
    * @tc.number  SUB_Audio_HDI_RenderGetFrameCount_001
    * @tc.desc  Test RenderGetFrameCount interface, return 0 if the FrameSize was obtained successfully
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderGetFrameCount_001, TestSize.Level1)
{
    int32_t ret;
    uint64_t count = 0;
    uint64_t zero = 0;
    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->GetFrameCount(render, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(count, zero);
    render->Stop(render);
}
/**
    * @tc.name  Test RenderGetFrameCount API via setting the incoming parameter handle is nullptr
    * @tc.number  SUB_Audio_HDI_RenderGetFrameCount_Null_002
    * @tc.desc  Test RenderGetFrameCount interface,return -3/-4 if the incoming parameter handle is nullptr
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderGetFrameCount_Null_002, TestSize.Level1)
{
    int32_t ret;
    uint64_t count = 0;
    struct IAudioRender *renderNull = nullptr;
    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->GetFrameCount(renderNull, &count);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    render->Stop(render);
}
/**
    * @tc.name  Test RenderGetFrameCount API setting the incoming parameter count is nullptr
    * @tc.number  SUB_Audio_HDI_RenderGetFrameCount_Null_003
    * @tc.desc  Test RenderGetFrameCount interface,return -3 if the incoming parameter count is nullptr
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderGetFrameCount_Null_003, TestSize.Level1)
{
    int32_t ret;
    uint64_t *countNull = nullptr;
    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->GetFrameCount(render, countNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    render->Stop(render);
}
/**
    * @tc.name    Test RenderGetCurrentChannelId API via legal input
    * @tc.number  SUB_Audio_HDI_RenderGetCurrentChannelId_001
    * @tc.desc    Test RenderGetCurrentChannelId, return 0 if the default CurrentChannelId is obtained successfully
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderGetCurrentChannelId_001, TestSize.Level1)
{
    int32_t ret;
    uint32_t channelId = 0;
    uint32_t channelIdValue = CHANNELCOUNT;

    ASSERT_NE(nullptr, render);
    ret = render->GetCurrentChannelId(render, &channelId);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(channelIdValue, channelId);
}
/**
    * @tc.name    Test GetCurrentChannelId API via setting the parameter render is nullptr
    * @tc.number  SUB_Audio_HDI_RenderGetCurrentChannelId_Null_003
    * @tc.desc    Test GetCurrentChannelId interface,return -3/-4 if set the parameter render is nullptr
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderGetCurrentChannelId_Null_003, TestSize.Level1)
{
    int32_t ret;
    uint32_t channelId = 0;
    struct IAudioRender *renderNull = nullptr;
    ASSERT_NE(nullptr, render);

    ret = render->GetCurrentChannelId(renderNull, &channelId);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
    * @tc.name    Test RenderGetCurrentChannelId API via setting the parameter channelId is nullptr
    * @tc.number  SUB_Audio_HDI_RenderGetCurrentChannelId_Null_004
    * @tc.desc    Test RenderGetCurrentChannelId interface, return -3 if setting the parameter channelId is nullptr
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderGetCurrentChannelId_Null_004, TestSize.Level1)
{
    int32_t ret;
    uint32_t *channelIdNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->GetCurrentChannelId(render, channelIdNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**
    * @tc.name    Test RenderSetExtraParams API via setting ExtraParams during playback
    * @tc.number  SUB_Audio_HDI_RenderSetExtraParams_001
    * @tc.desc    Test RenderSetExtraParams interface,return 0 if the ExtraParams is set during playback
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderSetExtraParams_001, TestSize.Level1)
{
    int32_t ret;
    char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;attr-frame-count=82;attr-sampling-rate=48000";
    char keyValueListExp[] = "attr-route=1;attr-format=32;attr-channels=2;attr-sampling-rate=48000";
    size_t index = 1;
    char keyValueListValue[256] = {};
    int32_t listLenth = 256;
    ASSERT_NE(nullptr, render);
    struct PrepareAudioPara audiopara = {
        .path = AUDIO_FILE.c_str(), .render = render
    };

    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);
    sleep(1);
    if (audiopara.render != nullptr) {
        ret = audiopara.render->SetExtraParams(audiopara.render, keyValueList);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.render->GetExtraParams(audiopara.render, keyValueListValue, listLenth);
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
    * @tc.name    Test RenderSetExtraParams API via setting some parameters after playing
    * @tc.number  SUB_Audio_HDI_RenderSetExtraParams_002
    * @tc.desc    Test RenderSetExtraParams interface,return 0 if some parameters is set after playing
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderSetExtraParams_002, TestSize.Level1)
{
    int32_t ret;
    char keyValueListOne[] = "attr-frame-count=1024;";
    char keyValueListOneExp[] = "attr-route=0;attr-format=16;attr-channels=2;attr-frame-count=1024;\
attr-sampling-rate=48000";
    char keyValueListTwo[] = "attr-format=16;attr-frame-count=1024;";
    char keyValueListTwoExp[] = "attr-route=0;attr-format=16;attr-channels=2;attr-frame-count=1024;\
attr-sampling-rate=48000";
    char keyValueListThr[] = "attr-route=1;attr-channels=1;attr-frame-count=1024;";
    char keyValueListThrExp[] = "attr-route=1;attr-format=16;attr-channels=1;attr-frame-count=1024;\
attr-sampling-rate=48000";
    char keyValueListFour[] = "attr-format=32;attr-channels=2;attr-frame-count=4096;attr-sampling-rate=48000";
    char keyValueListFourExp[] = "attr-route=1;attr-format=32;attr-channels=2;attr-frame-count=4096;\
attr-sampling-rate=48000";
    char keyValueListValueOne[256] = {};
    char keyValueListValueTwo[256] = {};
    char keyValueListValueThr[256] = {};
    char keyValueListValueFour[256] = {};
    int32_t listLenth = 256;
    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->SetExtraParams(render, keyValueListOne);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetExtraParams(render, keyValueListValueOne, listLenth);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_STREQ(keyValueListOneExp, keyValueListValueOne);
    ret = render->SetExtraParams(render, keyValueListTwo);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetExtraParams(render, keyValueListValueTwo, listLenth);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_STREQ(keyValueListTwoExp, keyValueListValueTwo);
    ret = render->SetExtraParams(render, keyValueListThr);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetExtraParams(render, keyValueListValueThr, listLenth);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_STREQ(keyValueListThrExp, keyValueListValueThr);
    ret = render->SetExtraParams(render, keyValueListFour);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetExtraParams(render, keyValueListValueFour, listLenth);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_STREQ(keyValueListFourExp, keyValueListValueFour);
    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
    * @tc.name    Test RenderSetExtraParams API via setting keyvaluelist to a value outside the range
    * @tc.number  SUB_Audio_HDI_RenderSetExtraParams_003
    * @tc.desc    Test RenderSetExtraParams interface,return -1 if the Keyvaluelist is a value out of range
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderSetExtraParams_003, TestSize.Level1)
{
    int32_t ret;
    char keyValueList[] = "attr-para=abc;";

    ASSERT_NE(nullptr, render);
    ret = ret = render->SetExtraParams(render, keyValueList);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
    * @tc.name    Test RenderSetExtraParams API via adding parameters to keyvaluelist
    * @tc.number  SUB_Audio_HDI_RenderSetExtraParams_004
    * @tc.desc    Test RenderSetExtraParams interface,return -1 if adding parameters to keyvaluelist
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderSetExtraParams_004, TestSize.Level1)
{
    int32_t ret;
    char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;\
attr-frame-count=82;attr-sampling-rate=48000;attr-para=123";

    ASSERT_NE(nullptr, render);
    ret = render->SetExtraParams(render, keyValueList);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
    * @tc.name    Test RenderSetExtraParams API via setting ExtraParams When the key is the same and the value is
    different
    * @tc.number  SUB_Audio_HDI_RenderSetExtraParams_005
    * @tc.desc    Test RenderSetExtraParams interface,return 0 if set ExtraParams When the key is the same and the value
    is different
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderSetExtraParams_005, TestSize.Level1)
{
    int32_t ret;
    char keyValueList[] = "attr-sampling-rate=48000;attr-sampling-rate=96000;attr-frame-count=4096;";
    char keyValueListExp[] = "attr-route=0;attr-format=16;attr-channels=2;attr-frame-count=4096;\
attr-sampling-rate=96000";
    char keyValueListValue[256] = {};
    int32_t listLenth = 256;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->SetExtraParams(render, keyValueList);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetExtraParams(render, keyValueListValue, listLenth);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_STREQ(keyValueListExp, keyValueListValue);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
    * @tc.name    Test RenderSetExtraParams API via setting the parameter in keyvaluelist as an abnormal value
    * @tc.number  SUB_Audio_HDI_RenderSetExtraParams_006
    * @tc.desc    Test RenderSetExtraParams interface,return -1 if Set the parameter in keyvaluelist
                  as an abnormal value
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderSetExtraParams_006, TestSize.Level1)
{
    int32_t ret;
    char attrSamplingRateError[] = "attr-sampling-rate=1234567;";
    char attrChannelsError[] = "attr-channels=3;";
    char attrFrameCountError[] = "attr-frame-count=111111111111111111111;";
    char attrRouteError[] = "attr-route=5;";
    char attrFormateError[] = "attr-formate=12;";

    ASSERT_NE(nullptr, render);
    ret = render->SetExtraParams(render, attrSamplingRateError);
    EXPECT_EQ(HDF_FAILURE, ret);
    ret = render->SetExtraParams(render, attrChannelsError);
    EXPECT_EQ(HDF_FAILURE, ret);
    ret = render->SetExtraParams(render, attrFrameCountError);
    EXPECT_EQ(HDF_FAILURE, ret);
    ret = render->SetExtraParams(render, attrRouteError);
    EXPECT_EQ(HDF_FAILURE, ret);
    ret = render->SetExtraParams(render, attrFormateError);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
    * @tc.name    Test RenderSetExtraParams API via setting the parameter render is nullptr
    * @tc.number  SUB_Audio_HDI_RenderSetExtraParams_Null_007
    * @tc.desc    Test RenderSetExtraParams interface,return -3/-4 if set the parameter render is nullptr
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderSetExtraParams_Null_007, TestSize.Level1)
{
    int32_t ret;
    struct IAudioRender *renderNull = nullptr;
    char keyValueList[] = "attr-format=2;";

    ASSERT_NE(nullptr, render);
    ret = render->SetExtraParams(renderNull, keyValueList);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
    * @tc.name    Test RenderSetExtraParams API via setting the format of ExtraParams is nullptr
    * @tc.number  SUB_Audio_HDI_RenderSetExtraParams_008
    * @tc.desc    Test RenderSetExtraParams interface,return -1 if set the format of ExtraParams is nullptr
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderSetExtraParams_008, TestSize.Level1)
{
    int32_t ret;
    char keyValueLnullptr[] = "attr-format=;";

    ASSERT_NE(nullptr, render);
    ret = render->SetExtraParams(render, keyValueLnullptr);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
    * @tc.name    Test RenderSetExtraParams API via setting the format of ExtraParams is nullptr
    * @tc.number  SUB_Audio_HDI_RenderSetExtraParams_Null_009
    * @tc.desc    Test RenderSetExtraParams interface,return -3 if set the format of ExtraParams is nullptr
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderSetExtraParams_Null_009, TestSize.Level1)
{
    int32_t ret;
    char *keyValueListNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->SetExtraParams(render, keyValueListNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**

* @tc.name    Test RenderGetExtraParams API via legal input
* @tc.number  SUB_Audio_HDI_RenderGetExtraParams_001
* @tc.desc    Test RenderGetExtraParams interface,return 0 if the RenderGetExtraParams was obtained successfully
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderGetExtraParams_001, TestSize.Level1)
{
    int32_t ret;
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

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->SetExtraParams(render, keyValueList);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetExtraParams(render, keyValueListValue, listLenth);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_STREQ(keyValueListExp, keyValueListValue);

    ret = render->GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(formatExp, attrsValue.format);
    EXPECT_EQ(sampleRateExp, attrsValue.sampleRate);
    EXPECT_EQ(channelCountExp, attrsValue.channelCount);
    ret = render->GetFrameCount(render, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(count, frameCountExp);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
    * @tc.name    Test RenderGetExtraParams API via setting the parameter render is nullptr
    * @tc.number  SUB_Audio_HDI_RenderGetExtraParams_Null_002
    * @tc.desc    Test RenderGetExtraParams interface,return -3/-4 if set the parameter render is nullptr
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderGetExtraParams_Null_002, TestSize.Level1)
{
    int32_t ret;
    struct IAudioRender *renderNull = nullptr;
    char keyValueList[] = "attr-format=32;";
    char keyValueListValue[256] = {};
    int32_t listLenth = 256;

    ASSERT_NE(nullptr, render);
    ret = render->SetExtraParams(render, keyValueList);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetExtraParams(renderNull, keyValueListValue, listLenth);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
    * @tc.name    Test RenderGetExtraParams API via setting listlength to be less than the actual length
    * @tc.number  SUB_Audio_HDI_RenderGetExtraParams_003
    * @tc.desc    Test RenderGetExtraParams interface,return -1 if set listlength to be less than the actual length
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderGetExtraParams_003, TestSize.Level1)
{
    int32_t ret;
    char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;attr-frame-count=82;attr-sampling-rate=48000;";
    char keyValueListValue[256] = {};
    int32_t listLenth = 8;

    ASSERT_NE(nullptr, render);
    ret = render->SetExtraParams(render, keyValueList);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetExtraParams(render, keyValueListValue, listLenth);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
    * @tc.name    Test RenderGetExtraParams API via setting listlenth equal to the actual length
    * @tc.number  SUB_Audio_HDI_RenderGetExtraParams_004
    * @tc.desc    Test RenderGetExtraParams interface,return 0 if set listlenth equal to the actual length
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderGetExtraParams_004, TestSize.Level1)
{
    int32_t ret;
    char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;attr-frame-count=11111111111111111111;\
attr-sampling-rate=48000";
    char keyValueListValue[256] = {};
    int32_t listLenth = 107;

    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->SetExtraParams(render, keyValueList);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetExtraParams(render, keyValueListValue, listLenth);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_STREQ(keyValueList, keyValueListValue);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name    Test ReqMmapBuffer API via legal input
* @tc.number  SUB_Audio_HDI_RenderReqMmapBuffer_001
* @tc.desc    Test ReqMmapBuffer interface,return 0 if call ReqMmapBuffer interface successfully
* @tc.author: liweiming
*/

HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderReqMmapBuffer_001, TestSize.Level1)
{
    int32_t ret;
    bool isRender = true;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc = {};
    struct AudioSampleAttributes attrs = {};
    ASSERT_NE(nullptr, render);

    InitAttrs(attrs);
    attrs.startThreshold = 0;
    ret = render->SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = InitMmapDesc(LOW_LATENCY_AUDIO_FILE, desc, reqSize, isRender);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret =  render->Start(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret =  render->ReqMmapBuffer(render, reqSize, &desc);
    EXPECT_EQ(HDF_SUCCESS, ret);
    if (ret == 0) {
        munmap(desc.memoryAddress, reqSize);
    }
    render->Stop(render);
    free(desc.filePath);
}
/**
* @tc.name    Test ReqMmapBuffer API via setting the incoming parameter reqSize is bigger than
            the size of actual audio file
* @tc.number  SUB_Audio_HDI_RenderReqMmapBuffer_002
* @tc.desc    Test ReqMmapBuffer interface,return -1 if call ReqMmapBuffer interface unsuccessfully when setting the
            incoming parameter reqSize is bigger than the size of actual audio file
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderReqMmapBuffer_002, TestSize.Level1)
{
    int32_t ret;
    bool isRender = true;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc = {};
    ASSERT_NE(nullptr, render);

    ret = InitMmapDesc(LOW_LATENCY_AUDIO_FILE, desc, reqSize, isRender);
    EXPECT_EQ(HDF_SUCCESS, ret);
    reqSize = reqSize + BUFFER_LENTH;
    ret =  render->Start(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret =  render->ReqMmapBuffer(render, reqSize, &desc);
    EXPECT_EQ(HDF_FAILURE, ret);
    render->Stop(render);
    free(desc.filePath);
}
/**
* @tc.name    Test ReqMmapBuffer API via setting the incoming parameter reqSize is smaller than
            the size of actual audio file
* @tc.number  SUB_Audio_HDI_RenderReqMmapBuffer_003
* @tc.desc    Test ReqMmapBuffer interface,return 0 if call ReqMmapBuffer interface successfully when setting the
            incoming parameter reqSize is smaller than the size of actual audio file
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderReqMmapBuffer_003, TestSize.Level1)
{
    int32_t ret;
    bool isRender = true;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc = {};
    ASSERT_NE(nullptr, render);

    ret = InitMmapDesc(LOW_LATENCY_AUDIO_FILE, desc, reqSize, isRender);
    EXPECT_EQ(HDF_SUCCESS, ret);
    reqSize = reqSize / 2;
    ret =  render->Start(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret =  render->ReqMmapBuffer(render, reqSize, &desc);
    EXPECT_EQ(HDF_SUCCESS, ret);
    if (ret == 0) {
        munmap(desc.memoryAddress, reqSize);
    }
    render->Stop(render);
    free(desc.filePath);
}
/**
* @tc.name    Test ReqMmapBuffer API via setting the incoming parameter reqSize is zero
* @tc.number  SUB_Audio_HDI_RenderReqMmapBuffer_004
* @tc.desc    Test ReqMmapBuffer interface,return -1 if call ReqMmapBuffer interface unsuccessfully when setting the
            incoming parameter reqSize is zero
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderReqMmapBuffer_004, TestSize.Level1)
{
    int32_t ret;
    bool isRender = true;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc = {};
    ASSERT_NE(nullptr, render);

    ret = InitMmapDesc(LOW_LATENCY_AUDIO_FILE, desc, reqSize, isRender);
    EXPECT_EQ(HDF_SUCCESS, ret);
    reqSize = 0;
    ret =  render->Start(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret =  render->ReqMmapBuffer(render, reqSize, &desc);
    EXPECT_EQ(HDF_FAILURE, ret);
    render->Stop(render);
    free(desc.filePath);
}
/**
* @tc.name    Test ReqMmapBuffer API via setting the incoming parameter memoryFd of desc is illegal
* @tc.number  SUB_Audio_HDI_RenderReqMmapBuffer_005
* @tc.desc    Test ReqMmapBuffer interface,return -3 if call ReqMmapBuffer interface unsuccessfully when setting the
            incoming parameter memoryFd  of desc is illegal
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderReqMmapBuffer_005, TestSize.Level1)
{
    int32_t ret;
    bool isRender = true;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc = {};

    ASSERT_NE(nullptr, render);
    ret = InitMmapDesc(LOW_LATENCY_AUDIO_FILE, desc, reqSize, isRender);
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(desc.filePath);
    desc.filePath = strdup("/bin/audio.wav");
    ret =  render->Start(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret =  render->ReqMmapBuffer(render, reqSize, &desc);
    EXPECT_EQ(HDF_FAILURE, ret);
    render->Stop(render);
    free(desc.filePath);
}
/**
* @tc.name    Test ReqMmapBuffer API via the incoming parameter handle is nullptr
* @tc.number  SUB_Audio_HDI_RenderReqMmapBuffer_Null_006
* @tc.desc    Test ReqMmapBuffer interface,return -3/-4 if call ReqMmapBuffer interface unsuccessfully when setting the
            incoming parameter handle is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderReqMmapBuffer_Null_006, TestSize.Level1)
{
    int32_t ret;
    bool isRender = true;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc = {};
    struct IAudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = InitMmapDesc(LOW_LATENCY_AUDIO_FILE, desc, reqSize, isRender);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret =  render->Start(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret =  render->ReqMmapBuffer(renderNull, reqSize, &desc);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    render->Stop(render);
    free(desc.filePath);
}
/**
* @tc.name    Test ReqMmapBuffer API via the incoming parameter desc is nullptr
* @tc.number  SUB_Audio_HDI_RenderReqMmapBuffer_Null_007
* @tc.desc    Test ReqMmapBuffer interface,return -3 if call ReqMmapBuffer interface unsuccessfully when setting the
            incoming parameter desc is nullptr
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderReqMmapBuffer_Null_007, TestSize.Level1)
{
    int32_t ret;
    bool isRender = true;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc = {};
    struct AudioMmapBufferDescripter *descNull = nullptr;
    ASSERT_NE(nullptr, render);
    ret = InitMmapDesc(LOW_LATENCY_AUDIO_FILE, desc, reqSize, isRender);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret =  render->Start(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret =  render->ReqMmapBuffer(render, reqSize, descNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    render->Stop(render);
    free(desc.filePath);
}
/**
* @tc.name    Test GetMmapPosition API via Getting position is normal in Before playing and Playing.
* @tc.number  SUB_Audio_HDI_RenderGetMmapPosition_001
* @tc.desc    Test GetMmapPosition interface,return 0 if Getting position successfully.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderGetMmapPosition_001, TestSize.Level1)
{
    int32_t ret;
    uint64_t frames = 0;
    uint64_t framesRendering = 0;
    uint64_t framesexpRender = 0;
    int64_t timeExp = 0;
    ASSERT_NE(nullptr, render);
    struct PrepareAudioPara audiopara = {
        .path = LOW_LATENCY_AUDIO_FILE.c_str(), .render = render
    };

    InitAttrs(audiopara.attrs);
    audiopara.attrs.startThreshold = 0;
    ret = audiopara.render->SetSampleAttributes(audiopara.render, &(audiopara.attrs));
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->GetMmapPosition(audiopara.render, &frames, &(audiopara.time));
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ((audiopara.time.tvSec) * SECTONSEC + (audiopara.time.tvNSec), timeExp);
    EXPECT_EQ(frames, INITIAL_VALUE);

    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)PlayMapAudioFile, &audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);
    sleep(1);
    ret = audiopara.render->GetMmapPosition(audiopara.render, &framesRendering, &(audiopara.time));
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT((audiopara.time.tvSec) * SECTONSEC + (audiopara.time.tvNSec), timeExp);
    EXPECT_GT(framesRendering, INITIAL_VALUE);
    int64_t timeExprendering = (audiopara.time.tvSec) * SECTONSEC + (audiopara.time.tvNSec);
    void *result = nullptr;
    pthread_join(audiopara.tids, &result);
    EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
    ret = audiopara.render->GetMmapPosition(audiopara.render, &framesexpRender, &(audiopara.time));
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GE((audiopara.time.tvSec) * SECTONSEC + (audiopara.time.tvNSec), timeExprendering);
    EXPECT_GE(framesexpRender, framesRendering);
    audiopara.render->Stop(audiopara.render);
}

/**
* @tc.name    Test ReqMmapBuffer API via inputtint frame is nullptr.
* @tc.number  SUB_Audio_HDI_RenderGetMmapPosition_Null_003
* @tc.desc    Test GetMmapPosition interface,return -3 if Error in incoming parameter.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderGetMmapPosition_Null_003, TestSize.Level1)
{
    int32_t ret;
    uint64_t *frames = nullptr;
    struct AudioTimeStamp time = {};

    ASSERT_NE(nullptr, render);
    ret = render->GetMmapPosition(render, frames, &time);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**
* @tc.name    Test ReqMmapBuffer API via inputtint time is nullptr.
* @tc.number  SUB_Audio_HDI_RenderGetMmapPosition_Null_004
* @tc.desc    Test GetMmapPosition interface,return -3/-4 if Error in incoming parameter.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderGetMmapPosition_Null_004, TestSize.Level1)
{
    int32_t ret;
    uint64_t frames = 0;
    struct AudioTimeStamp *time = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->GetMmapPosition(render, &frames, time);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
* @tc.name    Test ReqMmapBuffer API via inputtint render is nullptr.
* @tc.number  SUB_Audio_HDI_RenderGetMmapPosition_Null_005
* @tc.desc    Test GetMmapPosition interface,return -3/-4 if Error in incoming parameter.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderGetMmapPosition_Null_005, TestSize.Level1)
{
    int32_t ret;
    uint64_t frames = 0;
    struct AudioTimeStamp time = {};
    struct IAudioRender *renderNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->GetMmapPosition(renderNull, &frames, &time);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
* @tc.name    Test RenderSetSampleAttributes API via setting the render is nullptr .
* @tc.number  SUB_Audio_HDI_RenderSetSampleAttributes_Null_007
* @tc.desc     Test RenderSetSampleAttributes interface, return -3/-4 if the render is nullptr.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderSetSampleAttributes_Null_007, TestSize.Level1)
{
    int32_t ret;
    struct IAudioRender *renderNull = nullptr;
    struct AudioSampleAttributes attrs = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_8000);

    ret = render->SetSampleAttributes(renderNull, &attrs);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    ret = render->SetSampleAttributes(render, nullptr);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
* @tc.name    Test AudioRendereGetSampleAttributes API via setting the render is nullptr .
* @tc.number  SUB_Audio_HDI_RenderGetSampleAttributes_Null_002
* @tc.desc     Test AudioRendereGetSampleAttributes interface, return -3/-4 if the render is nullptr.
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, SUB_Audio_HDI_RenderGetSampleAttributes_Null_002, TestSize.Level1)
{
    int32_t ret;
    struct IAudioRender *renderNull = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes *attrsValue = nullptr;
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_44100);

    ret = render->GetSampleAttributes(renderNull, &attrs);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    ret = render->GetSampleAttributes(render, attrsValue);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
}