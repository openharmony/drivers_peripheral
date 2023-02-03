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
 * @brief Defines audio-related APIs, including custom data types and functions for loading drivers,
 * accessing a driver adapter, and rendering audios.
 *
 * @since 1.0
 * @version 1.0
 */

/**
 * @file audio_hdi_common.h
 *
 * @brief Declares APIs for operations related to the audio render adapter.
 *
 * @since 1.0
 * @version 1.0
 */

#include "audio_hdi_common.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
class AudioHdiRenderAttrTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static TestAudioManager *manager;
};

using THREAD_FUNC = void *(*)(void *);
TestAudioManager *AudioHdiRenderAttrTest::manager = nullptr;

void AudioHdiRenderAttrTest::SetUpTestCase(void)
{
    manager = GetAudioManagerFuncs();
    ASSERT_NE(nullptr, manager);
}

void AudioHdiRenderAttrTest::TearDownTestCase(void) {}
void AudioHdiRenderAttrTest::SetUp(void) {}
void AudioHdiRenderAttrTest::TearDown(void) {}
/**
    * @tc.name  AudioRenderGetFrameSize_001
    * @tc.desc  Test RenderGetFrameSize interface,return 0 if the FrameSize was obtained successfully
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderAttrTest, AudioRenderGetFrameSize_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t size = 0;
    uint64_t zero = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = render->attr.GetFrameSize(render, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(size, zero);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetFrameSize_002
    * @tc.desc  Test RenderGetFrameSize interface,return -1 if failed to get the FrameSize when handle is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderAttrTest, AudioRenderGetFrameSize_002, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t size = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = render->attr.GetFrameSize(renderNull, &size);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetFrameSize_003
    * @tc.desc  Test RenderGetFrameSize interface,return -1 if failed to get the FrameSize when size is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderAttrTest, AudioRenderGetFrameSize_003, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t *sizeNull = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = render->attr.GetFrameSize(render, sizeNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetFrameCount_001
    * @tc.desc  Test RenderGetFrameCount interface, return 0 if the FrameSize was obtained successfully
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderAttrTest, AudioRenderGetFrameCount_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t count = 0;
    uint64_t zero = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = render->attr.GetFrameCount(render, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(count, zero);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetFrameCount_002
    * @tc.desc  Test RenderGetFrameCount interface,return -1 if the incoming parameter handle is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderAttrTest, AudioRenderGetFrameCount_002, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t count = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = render->attr.GetFrameCount(renderNull, &count);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetFrameCount_003
    * @tc.desc  Test RenderGetFrameCount interface,return -1 if the incoming parameter count is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderAttrTest, AudioRenderGetFrameCount_003, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint64_t *countNull = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = render->attr.GetFrameCount(render, countNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetCurrentChannelId_001
    * @tc.desc  Test RenderGetCurrentChannelId, return 0 if the default CurrentChannelId is obtained successfully
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderAttrTest, AudioRenderGetCurrentChannelId_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint32_t channelId = 0;
    uint32_t channelIdValue = CHANNELCOUNT;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = render->attr.GetCurrentChannelId(render, &channelId);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(channelIdValue, channelId);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetCurrentChannelId_003
    * @tc.desc  Test RenderGetCurrentChannelId interface, return 0 if CurrentChannelId is obtained after created
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderAttrTest, AudioRenderGetCurrentChannelId_003, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint32_t channelId = 0;
    uint32_t channelIdExp = 2;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = render->attr.GetCurrentChannelId(render, &channelId);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(channelIdExp, channelId);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetCurrentChannelId_004
    * @tc.desc  Test GetCurrentChannelId interface,return -1 if set the parameter render is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderAttrTest, AudioRenderGetCurrentChannelId_004, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint32_t channelId = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = render->attr.GetCurrentChannelId(renderNull, &channelId);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderGetCurrentChannelId_005
    * @tc.desc  Test RenderGetCurrentChannelId interface, return -1 if setting the parameter channelId is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderAttrTest, AudioRenderGetCurrentChannelId_005, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    uint32_t *channelIdNull = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = render->attr.GetCurrentChannelId(render, channelIdNull);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderSetExtraParams_001
    * @tc.desc  Test RenderSetExtraParams interface,return 0 if the ExtraParams is set during playback
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderAttrTest, AudioRenderSetExtraParams_001, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;attr-frame-count=82;attr-sampling-rate=48000";
    char keyValueListExp[] = "attr-route=1;attr-format=32;attr-channels=2;attr-sampling-rate=48000";
    size_t index = 1;
    char keyValueListValue[256] = {};
    int32_t listLenth = 256;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };
    audiopara.manager = manager;
    ASSERT_NE(nullptr, audiopara.manager);

    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);
    sleep(1);
    if (audiopara.render != nullptr) {
        ret = audiopara.render->attr.SetExtraParams((AudioHandle)audiopara.render, keyValueList);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.render->attr.GetExtraParams((AudioHandle)audiopara.render, keyValueListValue, listLenth);
        EXPECT_NE(HDF_SUCCESS, ret);
        string strGetValue = keyValueListValue;
        size_t indexAttr = strGetValue.find("attr-frame-count");
        size_t indexFlag = strGetValue.rfind(";");
        if (indexAttr != string::npos && indexFlag != string::npos) {
            strGetValue.replace(indexAttr, indexFlag - indexAttr + index, "");
        }
        EXPECT_STRNE(keyValueListExp, strGetValue.c_str());
    }

    ret = ThreadRelease(audiopara);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
    * @tc.name  AudioRenderSetExtraParams_002
    * @tc.desc  Test RenderSetExtraParams interface,return 0 if some parameters is set after playing
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderAttrTest, AudioRenderSetExtraParams_002, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
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
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = render->attr.SetExtraParams((AudioHandle)render, keyValueListOne);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->attr.GetExtraParams((AudioHandle)render, keyValueListValueOne, listLenth);
    EXPECT_NE(HDF_SUCCESS, ret);
    EXPECT_STRNE(keyValueListOneExp, keyValueListValueOne);

    ret = render->attr.SetExtraParams((AudioHandle)render, keyValueListTwo);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->attr.GetExtraParams((AudioHandle)render, keyValueListValueTwo, listLenth);
    EXPECT_NE(HDF_SUCCESS, ret);
    EXPECT_STRNE(keyValueListTwoExp, keyValueListValueTwo);

    ret = render->attr.SetExtraParams((AudioHandle)render, keyValueListThr);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->attr.GetExtraParams((AudioHandle)render, keyValueListValueThr, listLenth);
    EXPECT_NE(HDF_SUCCESS, ret);
    EXPECT_STRNE(keyValueListThrExp, keyValueListValueThr);
    
    ret = render->attr.SetExtraParams((AudioHandle)render, keyValueListFour);
    EXPECT_EQ(HDF_SUCCESS, ret);
    
    ret = render->attr.GetExtraParams((AudioHandle)render, keyValueListValueFour, listLenth);
    EXPECT_NE(HDF_SUCCESS, ret);
    EXPECT_STRNE(keyValueListFourExp, keyValueListValueFour);
    
    ret = render->control.Stop((AudioHandle)render);
    EXPECT_NE(HDF_SUCCESS, ret);
    
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderSetExtraParams_003
    * @tc.desc  Test RenderSetExtraParams interface,return -1 if the Keyvaluelist is a value out of range
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderAttrTest, AudioRenderSetExtraParams_003, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    char keyValueList[] = "attr-para=abc;";

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = ret = render->attr.SetExtraParams((AudioHandle)render, keyValueList);
    EXPECT_NE(HDF_FAILURE, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderSetExtraParams_004
    * @tc.desc  Test RenderSetExtraParams interface,return -1 if adding parameters to keyvaluelist
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderAttrTest, AudioRenderSetExtraParams_004, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;\
attr-frame-count=82;attr-sampling-rate=48000;attr-para=123";

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.SetExtraParams((AudioHandle)render, keyValueList);
    EXPECT_NE(HDF_FAILURE, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderSetExtraParams_005
    * @tc.desc  Test RenderSetExtraParams interface,return 0 if set ExtraParams When the key is the same and the value
    is different
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderAttrTest, AudioRenderSetExtraParams_005, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, manager);
    char keyValueList[] = "attr-sampling-rate=48000;attr-sampling-rate=96000;attr-frame-count=4096;";
    char keyValueListExp[] = "attr-route=0;attr-format=16;attr-channels=2;attr-frame-count=4096;\
        attr-sampling-rate=96000";
    char keyValueListValue[256] = {};
    int32_t listLenth = 256;

    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.SetExtraParams((AudioHandle)render, keyValueList);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetExtraParams((AudioHandle)render, keyValueListValue, listLenth);
    EXPECT_NE(HDF_SUCCESS, ret);
    EXPECT_STRNE(keyValueListExp, keyValueListValue);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_NE(HDF_SUCCESS, ret);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderSetExtraParams_006
    * @tc.desc  Test RenderSetExtraParams interface,return -1 if Set the parameter in keyvaluelist as an abnormal value
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderAttrTest, AudioRenderSetExtraParams_006, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    char attrSamplingRateError[] = "attr-sampling-rate=1234567;";
    char attrChannelsError[] = "attr-channels=3;";
    char attrFrameCountError[] = "attr-frame-count=111111111111111111111;";
    char attrRouteError[] = "attr-route=5;";
    char attrFormateError[] = "attr-formate=12;";

    ASSERT_NE(nullptr, manager);
    
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    
    ret = render->attr.SetExtraParams((AudioHandle)render, attrSamplingRateError);
    EXPECT_NE(HDF_FAILURE, ret);
    
    ret = render->attr.SetExtraParams((AudioHandle)render, attrChannelsError);
    EXPECT_NE(HDF_FAILURE, ret);
    
    ret = render->attr.SetExtraParams((AudioHandle)render, attrFrameCountError);
    EXPECT_NE(HDF_FAILURE, ret);
    
    ret = render->attr.SetExtraParams((AudioHandle)render, attrRouteError);
    EXPECT_NE(HDF_FAILURE, ret);
    
    ret = render->attr.SetExtraParams((AudioHandle)render, attrFormateError);
    EXPECT_NE(HDF_FAILURE, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderSetExtraParams_007
    * @tc.desc  Test RenderSetExtraParams interface,return -1 if set the parameter render is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderAttrTest, AudioRenderSetExtraParams_007, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    char keyValueList[] = "attr-format=2;";

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.SetExtraParams((AudioHandle)renderNull, keyValueList);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  AudioRenderSetExtraParams_008
    * @tc.desc  Test RenderSetExtraParams interface,return -1 if set the format of ExtraParams is nullptr
    * @tc.type: FUNC
*/
HWTEST_F(AudioHdiRenderAttrTest, AudioRenderSetExtraParams_008, TestSize.Level1)
{
    int32_t ret = HDF_FAILURE;
    struct AudioAdapter *adapter = {};
    struct AudioRender *render = nullptr;
    char keyValueListNull[] = "attr-format=;";

    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.SetExtraParams((AudioHandle)render, keyValueListNull);
    EXPECT_NE(HDF_FAILURE, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
}
