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
class AudioIdlHdiRenderAttrTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioRender *render = nullptr;
    static TestAudioManager *manager;
};

TestAudioManager *AudioIdlHdiRenderAttrTest::manager = nullptr;
using THREAD_FUNC = void *(*)(void *);

void AudioIdlHdiRenderAttrTest::SetUpTestCase(void)
{
    manager = IAudioManagerGet(IS_STUB);
    ASSERT_NE(nullptr, manager);
}

void AudioIdlHdiRenderAttrTest::TearDownTestCase(void)
{
    if (manager != nullptr) {
        (void)IAudioManagerRelease(manager, IS_STUB);
    }
}

void AudioIdlHdiRenderAttrTest::SetUp(void)
{
    ASSERT_NE(nullptr, manager);
    int32_t ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

void AudioIdlHdiRenderAttrTest::TearDown(void)
{
    int32_t ret = ReleaseRenderSource(manager, adapter, render);
    ASSERT_EQ(HDF_SUCCESS, ret);
}


/**
    * @tc.name  AudioRenderGetFrameSize_001
    * @tc.desc  Test RenderGetFrameSize interface,return 0 if the FrameSize was obtained successfully
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderGetFrameSize_001, TestSize.Level1)
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
    * @tc.name  AudioRenderGetFrameSizeNull_002
    * @tc.desc  Test RenderGetFrameSize interface,return -3/-4 if failed to get the FrameSize when handle is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderGetFrameSizeNull_002, TestSize.Level1)
{
    int32_t ret;
    uint64_t size = 0;
    struct IAudioRender *renderNull = nullptr;
    ASSERT_NE(nullptr, render);

    ret = render->GetFrameSize(renderNull, &size);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
    * @tc.name  AudioRenderGetFrameCount_001
    * @tc.desc  Test RenderGetFrameCount interface, return 0 if the FrameSize was obtained successfully
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderGetFrameCount_001, TestSize.Level1)
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
    * @tc.name  AudioRenderGetFrameCountNull_002
    * @tc.desc  Test RenderGetFrameCount interface,return -3/-4 if the incoming parameter handle is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderGetFrameCountNull_002, TestSize.Level1)
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
    * @tc.name  AudioRenderGetFrameCountNull_003
    * @tc.desc  Test RenderGetFrameCount interface,return -3 if the incoming parameter count is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderGetFrameCountNull_003, TestSize.Level1)
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
    * @tc.name  AudioRenderGetCurrentChannelId_001
    * @tc.desc    Test RenderGetCurrentChannelId, return 0 if the default CurrentChannelId is obtained successfully
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderGetCurrentChannelId_001, TestSize.Level1)
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
    * @tc.name  AudioRenderGetCurrentChannelIdNull_003
    * @tc.desc    Test GetCurrentChannelId interface,return -3/-4 if set the parameter render is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderGetCurrentChannelIdNull_003, TestSize.Level1)
{
    int32_t ret;
    uint32_t channelId = 0;
    struct IAudioRender *renderNull = nullptr;
    ASSERT_NE(nullptr, render);

    ret = render->GetCurrentChannelId(renderNull, &channelId);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
    * @tc.name  AudioRenderGetCurrentChannelIdNull_004
    * @tc.desc    Test RenderGetCurrentChannelId interface, return -3 if setting the parameter channelId is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderGetCurrentChannelIdNull_004, TestSize.Level1)
{
    int32_t ret;
    uint32_t *channelIdNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->GetCurrentChannelId(render, channelIdNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**
    * @tc.name  AudioRenderSetExtraParams_001
    * @tc.desc    Test RenderSetExtraParams interface,return 0 if the ExtraParams is set during playback
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderSetExtraParams_001, TestSize.Level1)
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
    * @tc.name  AudioRenderSetExtraParams_002
    * @tc.desc    Test RenderSetExtraParams interface,return 0 if some parameters is set after playing
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderSetExtraParams_002, TestSize.Level1)
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
    * @tc.name  AudioRenderSetExtraParams_003
    * @tc.desc    Test RenderSetExtraParams interface,return -1 if the Keyvaluelist is a value out of range
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderSetExtraParams_003, TestSize.Level1)
{
    int32_t ret;
    char keyValueList[] = "attr-para=abc;";

    ASSERT_NE(nullptr, render);
    ret = ret = render->SetExtraParams(render, keyValueList);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
    * @tc.name  AudioRenderSetExtraParams_004
    * @tc.desc    Test RenderSetExtraParams interface,return -1 if adding parameters to keyvaluelist
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderSetExtraParams_004, TestSize.Level1)
{
    int32_t ret;
    char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;\
attr-frame-count=82;attr-sampling-rate=48000;attr-para=123";

    ASSERT_NE(nullptr, render);
    ret = render->SetExtraParams(render, keyValueList);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
    * @tc.name  AudioRenderSetExtraParams_005
    * @tc.desc   Test RenderSetExtraParams interface,return 0 if set ExtraParams When the key is the same and the value
    is different
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderSetExtraParams_005, TestSize.Level1)
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
    * @tc.name  AudioRenderSetExtraParams_006
    * @tc.desc    Test RenderSetExtraParams interface,return -1 if Set the parameter in keyvaluelist
                  as an abnormal value
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderSetExtraParams_006, TestSize.Level1)
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
    * @tc.name  AudioRenderSetExtraParamsNull_007
    * @tc.desc    Test RenderSetExtraParams interface,return -3/-4 if set the parameter render is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderSetExtraParamsNull_007, TestSize.Level1)
{
    int32_t ret;
    struct IAudioRender *renderNull = nullptr;
    char keyValueList[] = "attr-format=2;";

    ASSERT_NE(nullptr, render);
    ret = render->SetExtraParams(renderNull, keyValueList);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
    * @tc.name  AudioRenderSetExtraParams_008
    * @tc.desc    Test RenderSetExtraParams interface,return -1 if set the format of ExtraParams is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderSetExtraParams_008, TestSize.Level1)
{
    int32_t ret;
    char keyValueLnullptr[] = "attr-format=;";

    ASSERT_NE(nullptr, render);
    ret = render->SetExtraParams(render, keyValueLnullptr);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
    * @tc.name  AudioRenderSetExtraParamsNull_009
    * @tc.desc    Test RenderSetExtraParams interface,return -3 if set the format of ExtraParams is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderSetExtraParamsNull_009, TestSize.Level1)
{
    int32_t ret;
    char *keyValueListNull = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->SetExtraParams(render, keyValueListNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**

* @tc.name  AudioRenderGetExtraParams_001
* @tc.desc    Test RenderGetExtraParams interface,return 0 if the RenderGetExtraParams was obtained successfully
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderGetExtraParams_001, TestSize.Level1)
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
    * @tc.name  AudioRenderGetExtraParamsNull_002
    * @tc.desc    Test RenderGetExtraParams interface,return -3/-4 if set the parameter render is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderGetExtraParamsNull_002, TestSize.Level1)
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
    * @tc.name  AudioRenderGetExtraParams_003
    * @tc.desc    Test RenderGetExtraParams interface,return -1 if set listlength to be less than the actual length
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderGetExtraParams_003, TestSize.Level1)
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
    * @tc.name  AudioRenderGetExtraParams_004
    * @tc.desc    Test RenderGetExtraParams interface,return 0 if set listlenth equal to the actual length
    * @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderGetExtraParams_004, TestSize.Level1)
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
* @tc.name  AudioRenderReqMmapBuffer_001
* @tc.desc    Test ReqMmapBuffer interface,return 0 if call ReqMmapBuffer interface successfully
* @tc.type: FUNC
*/

HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderReqMmapBuffer_001, TestSize.Level1)
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
* @tc.name  AudioRenderReqMmapBuffer_002
* @tc.desc    Test ReqMmapBuffer interface,return -1 if call ReqMmapBuffer interface unsuccessfully when setting the
            incoming parameter reqSize is bigger than the size of actual audio file
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderReqMmapBuffer_002, TestSize.Level1)
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
* @tc.name  AudioRenderReqMmapBuffer_003
* @tc.desc    Test ReqMmapBuffer interface,return 0 if call ReqMmapBuffer interface successfully when setting the
            incoming parameter reqSize is smaller than the size of actual audio file
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderReqMmapBuffer_003, TestSize.Level1)
{
    int32_t ret;
    bool isRender = true;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc = {};
    ASSERT_NE(nullptr, render);

    ret = InitMmapDesc(LOW_LATENCY_AUDIO_FILE, desc, reqSize, isRender);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret =  render->Start(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    reqSize = reqSize / 2; // change reqSize less than the size of actual audio file
    ret =  render->ReqMmapBuffer(render, reqSize, &desc);
    EXPECT_EQ(HDF_SUCCESS, ret);
    if (ret == 0) {
        munmap(desc.memoryAddress, reqSize);
    }
    render->Stop(render);
    free(desc.filePath);
}
/**
* @tc.name  AudioRenderReqMmapBuffer_004
* @tc.desc    Test ReqMmapBuffer interface,return -1 if call ReqMmapBuffer interface unsuccessfully when setting the
            incoming parameter reqSize is zero
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderReqMmapBuffer_004, TestSize.Level1)
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
* @tc.name  AudioRenderReqMmapBuffer_005
* @tc.desc    Test ReqMmapBuffer interface,return -3 if call ReqMmapBuffer interface unsuccessfully when setting the
            incoming parameter memoryFd  of desc is illegal
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderReqMmapBuffer_005, TestSize.Level1)
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
* @tc.name  AudioRenderReqMmapBufferNull_006
* @tc.desc    Test ReqMmapBuffer interface,return -3/-4 if call ReqMmapBuffer interface unsuccessfully when setting the
            incoming parameter handle is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderReqMmapBufferNull_006, TestSize.Level1)
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
* @tc.name  AudioRenderReqMmapBufferNull_007
* @tc.desc    Test ReqMmapBuffer interface,return -3 if call ReqMmapBuffer interface unsuccessfully when setting the
            incoming parameter desc is nullptr
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderReqMmapBufferNull_007, TestSize.Level1)
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
* @tc.name  AudioRenderGetMmapPosition_001
* @tc.desc    Test GetMmapPosition interface,return 0 if Getting position successfully.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderGetMmapPosition_001, TestSize.Level1)
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
* @tc.name  AudioRenderGetMmapPositionNull_003
* @tc.desc    Test GetMmapPosition interface,return -3 if Error in incoming parameter.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderGetMmapPositionNull_003, TestSize.Level1)
{
    int32_t ret;
    uint64_t *frames = nullptr;
    struct AudioTimeStamp time = {};

    ASSERT_NE(nullptr, render);
    ret = render->GetMmapPosition(render, frames, &time);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**
* @tc.name  AudioRenderGetMmapPositionNull_004
* @tc.desc    Test GetMmapPosition interface,return -3/-4 if Error in incoming parameter.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderGetMmapPositionNull_004, TestSize.Level1)
{
    int32_t ret;
    uint64_t frames = 0;
    struct AudioTimeStamp *time = nullptr;

    ASSERT_NE(nullptr, render);
    ret = render->GetMmapPosition(render, &frames, time);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
}
/**
* @tc.name  AudioRenderGetMmapPositionNull_005
* @tc.desc    Test GetMmapPosition interface,return -3/-4 if Error in incoming parameter.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderGetMmapPositionNull_005, TestSize.Level1)
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
* @tc.name  AudioRenderSetSampleAttributesNull_007
* @tc.desc     Test RenderSetSampleAttributes interface, return -3/-4 if the render is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderSetSampleAttributesNull_007, TestSize.Level1)
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
* @tc.name  AudioRenderGetSampleAttributesNull_002
* @tc.desc     Test AudioRendereGetSampleAttributes interface, return -3/-4 if the render is nullptr.
* @tc.type: FUNC
*/
HWTEST_F(AudioIdlHdiRenderAttrTest, AudioRenderGetSampleAttributesNull_002, TestSize.Level1)
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