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

#include "audio_hdi_common.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
class AudioHdiRenderHardwareDependenceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static TestAudioManager *(*GetAudioManager)();
    static void *handleSo;
};

using THREAD_FUNC = void *(*)(void *);

TestAudioManager *(*AudioHdiRenderHardwareDependenceTest::GetAudioManager)() = nullptr;
void *AudioHdiRenderHardwareDependenceTest::handleSo = nullptr;

void AudioHdiRenderHardwareDependenceTest::SetUpTestCase(void)
{
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

void AudioHdiRenderHardwareDependenceTest::TearDownTestCase(void)
{
    if (handleSo != nullptr) {
        dlclose(handleSo);
        handleSo = nullptr;
    }
    if (GetAudioManager != nullptr) {
        GetAudioManager = nullptr;
    }
}
void AudioHdiRenderHardwareDependenceTest::SetUp(void) {}
void AudioHdiRenderHardwareDependenceTest::TearDown(void) {}

/**
* @tc.name  Test AudioRenderSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_001
* @tc.desc  Test AudioRenderSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = AUDIO_SAMPLE_RATE_MASK_8000;
*    attrs.channelCount = 1;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_8000);

    ret = render->attr.SetSampleAttributes(render, &attrs);
#ifdef PRODUCT_RK3568
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
#else
    struct AudioSampleAttributes attrsValue = {};
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->attr.GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_8000, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);
#endif
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioRenderSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_002
* @tc.desc  Test AudioRenderSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*    attrs.sampleRate = 11025;
*    attrs.channelCount = 2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_11025);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_11025, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioRenderSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_003
* @tc.desc  Test AudioRenderSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = 22050;
*    attrs.channelCount = 1;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_22050);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_22050, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioRenderSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_004
* @tc.desc  Test AudioRenderSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*    attrs.sampleRate = 32000;
*    attrs.channelCount = 2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_32000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_32000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioRenderSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_005
* @tc.desc  Test AudioRenderSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = 44100;
*    attrs.channelCount = 1;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_44100);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
#ifdef PRODUCT_RK3568
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
#else
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_44100, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);
#endif
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioRenderSetSampleAttributes API via legal input.
* @tc.desc  Test AudioRenderSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_COMMUNICATION;
*    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*    attrs.sampleRate = 48000;
*    attrs.channelCount = 2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_006, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_48000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioRenderSetSampleAttributes API via setting the render is empty .
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_007
* @tc.desc   Test AudioRenderSetSampleAttributes interface, return -1 if the render is empty.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_007, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    struct AudioSampleAttributes attrs = {};
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_8000);

    ret = render->attr.SetSampleAttributes(renderNull, &attrs);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    ret = render->attr.SetSampleAttributes(render, nullptr);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioRenderSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_008
* @tc.desc  Test AudioRenderSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = 12000;
*    attrs.channelCount = 1;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_008, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_12000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
#ifdef PRODUCT_RK3568
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
#else
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_12000, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);
#endif
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioRenderSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_009
* @tc.desc  Test AudioRenderSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*    attrs.sampleRate = 16000;
*    attrs.channelCount = 1;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_009, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_16000);
    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
#ifdef PRODUCT_RK3568
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
#else
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_16000, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);
#endif
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioRenderSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_010
* @tc.desc  Test AudioRenderSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = 24000;
*    attrs.channelCount = 2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_010, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_24000);
    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_24000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioRenderSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_011
* @tc.desc  Test AudioRenderSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = 64000;
*    attrs.channelCount = 2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_011, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_64000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_64000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioRenderSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_012
* @tc.desc  Test AudioRenderSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*    attrs.sampleRate = 96000;
*    attrs.channelCount = 1;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_012, TestSize.Level1)
{
    int32_t ret = -1;

    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_96000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
#ifdef PRODUCT_RK3568
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
#else
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_96000, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);
#endif
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioRenderSetSampleAttributes API via illegal input.
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_013
* @tc.desc  Test AudioRenderSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = 0xFFFFFFFFu;
*    attrs.channelCount = 2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_013, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, 2, 0xFFFFFFFFu);

    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioRenderSetSampleAttributes API via illegal input.
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_014
* @tc.desc  Test AudioRenderSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_8/32_BIT/AAC_MAIN;
*    attrs.sampleRate = 8000/11025/22050;
*    attrs.channelCount = 1/2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_014, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs1 = {};
    struct AudioSampleAttributes attrs2 = {};
    struct AudioSampleAttributes attrs3 = {};
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();

    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    InitAttrsUpdate(attrs1, AUDIO_FORMAT_PCM_8_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_8000);
    ret = render->attr.SetSampleAttributes(render, &attrs1);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    InitAttrsUpdate(attrs2, AUDIO_FORMAT_PCM_32_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_11025);
    ret = render->attr.SetSampleAttributes(render, &attrs2);
#ifdef ALSA_LIB_MODE
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
#else
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
#endif
    InitAttrsUpdate(attrs3, AUDIO_FORMAT_AAC_MAIN, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_22050);
    ret = render->attr.SetSampleAttributes(render, &attrs3);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioRenderSetSampleAttributes API via illegal input.
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_015
* @tc.desc  Test AudioRenderSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_AAC_LC/LD/ELD;
*    attrs.sampleRate = 32000/44100/48000;
*    attrs.channelCount = 1/2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_015, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs1 = {};
    struct AudioSampleAttributes attrs2 = {};
    struct AudioSampleAttributes attrs3 = {};
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();

    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs1, AUDIO_FORMAT_AAC_LC, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_32000);
    ret = render->attr.SetSampleAttributes(render, &attrs1);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    InitAttrsUpdate(attrs2, AUDIO_FORMAT_AAC_LD, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_44100);
    ret = render->attr.SetSampleAttributes(render, &attrs2);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    InitAttrsUpdate(attrs3, AUDIO_FORMAT_AAC_ELD, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_48000);
    ret = render->attr.SetSampleAttributes(render, &attrs3);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioRenderSetSampleAttributes API via illegal input.
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_016
* @tc.desc  Test AudioRenderSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_AAC_HE_V1/V2
*    attrs.sampleRate = 8000/44100;
*    attrs.channelCount = 1/2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_016, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs1 = {};
    struct AudioSampleAttributes attrs2 = {};
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    InitAttrsUpdate(attrs1, AUDIO_FORMAT_AAC_HE_V1, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_8000);
    ret = render->attr.SetSampleAttributes(render, &attrs1);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    InitAttrsUpdate(attrs2, AUDIO_FORMAT_AAC_HE_V2, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_44100);
    ret = render->attr.SetSampleAttributes(render, &attrs2);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioRenderSetSampleAttributes API via illegal input.
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_017
* @tc.desc  Test AudioRenderSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT
*    attrs.sampleRate = 8000;
*    attrs.channelCount = 5;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_017, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, 5, SAMPLE_RATE_8000);
    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioRenderGetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioRenderGetSampleAttributes_001
* @tc.desc  Test AudioRenderGetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = 8000;
*    attrs.channelCount = 1;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderGetSampleAttributes_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_8000);
    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
#ifdef PRODUCT_RK3568
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
#else
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_8000, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);
#endif
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioRendereGetSampleAttributes API via setting the render is empty .
* @tc.number  SUB_Audio_HDI_AudioRenderGetSampleAttributes_002
* @tc.desc   Test AudioRendereGetSampleAttributes interface, return -1 if the render is empty.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderGetSampleAttributes_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes *attrsValue = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_44100);

    ret = render->attr.GetSampleAttributes(renderNull, &attrs);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    ret = render->attr.GetSampleAttributes(render, attrsValue);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test RenderGetFrameSize API via define format to different values
    * @tc.number  SUB_Audio_HDI_RenderGetFrameSize_004
    * @tc.desc  Test RenderGetFrameSize interface,return 0 if get framesize define format as different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderGetFrameSize_004, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t size = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_48000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = render->attr.GetFrameSize(render, &size);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
#ifndef PRODUCT_RK3568
/**
    * @tc.name  Test RenderGetFrameSize API via define sampleRate to different values
    * @tc.number  SUB_Audio_HDI_RenderGetFrameSize_005
    * @tc.desc  Test RenderGetFrameSize interface,return 0 if get framesize define sampleRate as different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderGetFrameSize_005, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t size = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_48000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = render->attr.GetFrameSize(render, &size);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
#endif
/**
    * @tc.name  Test RenderGetFrameSize API via define channelCount to different values
    * @tc.number  SUB_Audio_HDI_RenderGetFrameSize_006
    * @tc.desc  Test RenderGetFrameSize interface,return 0 if get framesize define channelCount as different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderGetFrameSize_006, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t size = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_44100);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_44100, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = render->attr.GetFrameSize(render, &size);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
#ifndef PRODUCT_RK3568
/**
    * @tc.name  Test RenderGetFrameSize API via define sampleRate to different value
    * @tc.number  SUB_Audio_HDI_RenderGetFrameSize_007
    * @tc.desc  Test RenderGetFrameSize interface,return 0 if get framesize define sampleRate as different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderGetFrameSize_007, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t size = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_48000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = render->attr.GetFrameSize(render, &size);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
#endif
/**
    * @tc.name  Test RenderGetFrameCount API via define channelCount to different value
    * @tc.number  SUB_Audio_HDI_RenderGetFrameCount_004
    * @tc.desc  Test RenderGetFrameCount interface,return 0 if get framesize define channelCount as different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderGetFrameCount_004, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t count = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_8000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_8000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->attr.GetFrameCount(render, &count);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test RenderGetFrameCount API via define format to different value
    * @tc.number  SUB_Audio_HDI_RenderGetFrameCount_005
    * @tc.desc  Test RenderGetFrameCount interface,return 0 if get framesize define format as different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderGetFrameCount_005, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t count = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_8000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_8000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->attr.GetFrameCount(render, &count);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
#ifndef PRODUCT_RK3568
/**
    * @tc.name  Test RenderGetFrameCount API via define channelCount to different value
    * @tc.number  SUB_Audio_HDI_RenderGetFrameCount_006
    * @tc.desc  Test RenderGetFrameCount interface,return 0 if get framesize define channelCount to different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderGetFrameCount_006, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t count = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_44100);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_44100, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->attr.GetFrameCount(render, &count);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test RenderGetFrameCount API via define format to different value
    * @tc.number  SUB_Audio_HDI_RenderGetFrameCount_007
    * @tc.desc  Test RenderGetFrameCount interface,return 0 if get framesize define format as different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderGetFrameCount_007, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t count = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_32000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_32000, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->attr.GetFrameCount(render, &count);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
#endif
#ifndef PRODUCT_RK3568
/**
    * @tc.name  Test GetCurrentChannelId API via get channelId to 1 and set channelCount to 1
    * @tc.number  SUB_Audio_HDI_RenderGetCurrentChannelId_003
    * @tc.desc  Test GetCurrentChannelId interface,return 0 if get channelId to 1 and set channelCount to 1
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderGetCurrentChannelId_002, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t channelId = 0;
    uint32_t channelIdExp = 1;
    uint32_t channelCountExp = 1;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_32000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(channelCountExp, attrs.channelCount);

    ret = render->attr.GetCurrentChannelId(render, &channelId);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(channelIdExp, channelId);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
#endif
/**
    * @tc.name  Test GetRenderPosition API via define format to AUDIO_FORMAT_PCM_16_BIT
    * @tc.number  SUB_Audio_HDI_AudioRenderGetRenderPosition_009
    * @tc.desc  Test GetRenderPosition interface,return 0 if get framesize define format to AUDIO_FORMAT_PCM_16_BIT
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderGetRenderPosition_009, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    TestAudioManager* manager = GetAudioManager();
    ASSERT_NE(GetAudioManager, nullptr);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrs(attrs);
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = SAMPLE_RATE_48000;
    attrs.channelCount = DOUBLE_CHANNEL_COUNT;
    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->attr.GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);
    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
#ifndef ALSA_LIB_MODE
/**
    * @tc.name  Test GetRenderPosition API via define format to AUDIO_FORMAT_PCM_24_BIT
    * @tc.number  SUB_Audio_HDI_AudioRenderGetRenderPosition_010
    * @tc.desc  Test GetRenderPosition interface,return 0 if get framesize define format to AUDIO_FORMAT_PCM_24_BIT
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderGetRenderPosition_010, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    ASSERT_NE(GetAudioManager, nullptr);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrs(attrs);
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
    attrs.sampleRate = SAMPLE_RATE_48000;
    attrs.channelCount = DOUBLE_CHANNEL_COUNT;
    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->attr.GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);
    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
#endif
#ifndef PRODUCT_RK3568
/**
    * @tc.name  Test GetRenderPosition API via define sampleRate and channelCount to different value
    * @tc.number  SUB_Audio_HDI_AudioRenderGetRenderPosition_011
    * @tc.desc  Test GetRenderPosition interface,return 0 if get framesize define channelCount  as different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderGetRenderPosition_011, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    ASSERT_NE(GetAudioManager, nullptr);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrs(attrs);
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = SAMPLE_RATE_48000;
    attrs.channelCount = SINGLE_CHANNEL_COUNT;
    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->attr.GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);
    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test GetRenderPosition API via define sampleRate and channelCount to 1
    * @tc.number  SUB_Audio_HDI_AudioRenderGetRenderPosition_012
    * @tc.desc  Test GetRenderPosition interface,return 0 if get framesize define channelCount to 1
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderGetRenderPosition_012, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioRender *render = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    ASSERT_NE(GetAudioManager, nullptr);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrs(attrs);
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
    attrs.sampleRate = SAMPLE_RATE_48000;
    attrs.channelCount = SINGLE_CHANNEL_COUNT;
    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->attr.GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);
    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test GetMmapPosition API via SetSampleAttributes and Getting position is normal.
* @tc.number  SUB_Audio_HDI_RenderGetMmapPosition_002
* @tc.desc  Test GetMmapPosition interface,return 0 if Getting position successfully.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderGetMmapPosition_002, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .self = this, .pins = PIN_OUT_SPEAKER,
        .path = LOW_LATENCY_AUDIO_FILE.c_str()
    };
    ASSERT_NE(GetAudioManager, nullptr);
    audiopara.manager = GetAudioManager();
    ASSERT_NE(audiopara.manager, nullptr);
    ret = AudioCreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                            &audiopara.render);
    if (ret < 0 || audiopara.render == nullptr) {
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ASSERT_EQ(nullptr, audiopara.render);
    }
    InitAttrs(audiopara.attrs);
    audiopara.attrs.format = AUDIO_FORMAT_PCM_24_BIT;
    audiopara.attrs.channelCount = SINGLE_CHANNEL_COUNT;
    ret = audiopara.render->attr.SetSampleAttributes(audiopara.render, &(audiopara.attrs));
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)PlayMapAudioFile, &audiopara);
    if (ret != 0) {
        audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    }

    void *result = nullptr;
    pthread_join(audiopara.tids, &result);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);
    ret = audiopara.render->attr.GetMmapPosition(audiopara.render, &frames, &(audiopara.time));
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT((audiopara.time.tvSec) * SECTONSEC + (audiopara.time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);
    audiopara.render->control.Stop((AudioHandle)audiopara.render);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
#endif
/**
    * @tc.name  Test SetChannelMode API via setting channel mode to different enumeration values
    * @tc.number  SUB_Audio_HDI_AudioRenderSetChannelMode_001
    * @tc.desc  Test SetChannelMode interface,return 0 if set channel mode to different enumeration values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderSetChannelMode_001, TestSize.Level1)
{
    int32_t ret = -1;
    TestAudioManager* manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;
    ASSERT_NE(GetAudioManager, nullptr);
    manager = GetAudioManager();
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->SetChannelMode(render, mode);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetChannelMode(render, &mode);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
#ifndef ALSA_LIB_MODE
    EXPECT_EQ(AUDIO_CHANNEL_NORMAL, mode);
    AudioChannelMode modeOne = AUDIO_CHANNEL_BOTH_LEFT;
    AudioChannelMode modeSec = AUDIO_CHANNEL_BOTH_RIGHT;
    AudioChannelMode modeTrd = AUDIO_CHANNEL_EXCHANGE;
    ret = render->SetChannelMode(render, modeOne);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetChannelMode(render, &modeOne);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_BOTH_LEFT, modeOne);
    ret = render->SetChannelMode(render, modeSec);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetChannelMode(render, &modeSec);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_BOTH_RIGHT, modeSec);
    ret = render->SetChannelMode(render, modeTrd);
#ifdef PRODUCT_RK3568
    EXPECT_EQ(HDF_FAILURE, ret);
#else
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetChannelMode(render, &modeTrd);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_EXCHANGE, modeTrd);
#endif
#endif
    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
#ifndef ALSA_LIB_MODE
/**
    * @tc.name  Test SetChannelMode API via setting channel mode to different values
    * @tc.number  SUB_Audio_HDI_AudioRenderSetChannelMode_002
    * @tc.desc  Test SetChannelMode interface,return 0 if set channel mode to different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderSetChannelMode_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    AudioChannelMode mode = AUDIO_CHANNEL_MIX;
    AudioChannelMode modeOne = AUDIO_CHANNEL_LEFT_MUTE;
    ASSERT_NE(GetAudioManager, nullptr);
    TestAudioManager *manager = GetAudioManager();
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->SetChannelMode(render, mode);
#ifdef PRODUCT_RK3568
    EXPECT_EQ(HDF_FAILURE, ret);
#else
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetChannelMode(render, &mode);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_MIX, mode);
#endif
    ret = render->SetChannelMode(render, modeOne);
#ifdef PRODUCT_RK3568
    EXPECT_EQ(HDF_FAILURE, ret);
#else
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetChannelMode(render, &modeOne);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_LEFT_MUTE, modeOne);
#endif
    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test SetChannelMode API via setting channel mode to different values
    * @tc.number  SUB_Audio_HDI_AudioRenderSetChannelMode_003
    * @tc.desc  Test SetChannelMode interface,return 0 if set channel mode to different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderSetChannelMode_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    AudioChannelMode mode = AUDIO_CHANNEL_RIGHT_MUTE;
    AudioChannelMode modeOne = AUDIO_CHANNEL_BOTH_MUTE;
    ASSERT_NE(GetAudioManager, nullptr);
    TestAudioManager *manager = GetAudioManager();
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->SetChannelMode(render, mode);
#ifdef PRODUCT_RK3568
    EXPECT_EQ(HDF_FAILURE, ret);
#else
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetChannelMode(render, &mode);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_RIGHT_MUTE, mode);
#endif
    ret = render->SetChannelMode(render, modeOne);
#ifdef PRODUCT_RK3568
    EXPECT_EQ(HDF_FAILURE, ret);
#else
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetChannelMode(render, &modeOne);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_BOTH_MUTE, modeOne);
#endif
    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
#endif
/**
    * @tc.name  Test SetChannelMode API via setting channel mode after render object is created
    * @tc.number  SUB_Audio_HDI_AudioRenderSetChannelMode_004
    * @tc.desc  Test SetChannelMode interface,return 0 if set channel mode after render object is created
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderSetChannelMode_004, TestSize.Level1)
{
    int32_t ret = -1;
    TestAudioManager* manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;
    ASSERT_NE(GetAudioManager, nullptr);
    manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->SetChannelMode(render, mode);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetChannelMode(render, &mode);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_NORMAL, mode);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test SetChannelMode API via setting the parameter render is nullptr
    * @tc.number  SUB_Audio_HDI_AudioRenderSetChannelMode_005
    * @tc.desc  Test SetChannelMode interface,return -1 if set the parameter render is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderSetChannelMode_005, TestSize.Level1)
{
    int32_t ret = -1;
    TestAudioManager* manager = {};
    struct AudioRender *render = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *renderNull = nullptr;
    AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;
    ASSERT_NE(GetAudioManager, nullptr);
    manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->SetChannelMode(renderNull, mode);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test GetChannelMode API via getting the channel mode after setting
    * @tc.number  SUB_Audio_HDI_AudioRenderGetChannelMode_001
    * @tc.desc  Test GetChannelMode interface,return 0 if getting the channel mode after setting
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderGetChannelMode_001, TestSize.Level1)
{
    int32_t ret = -1;
    TestAudioManager* manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;
    ASSERT_NE(GetAudioManager, nullptr);
    manager = GetAudioManager();
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->GetChannelMode(render, &mode);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->SetChannelMode(render, mode);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetChannelMode(render, &mode);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_NORMAL, mode);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test GetChannelMode API via getting the parameter render is nullptr
    * @tc.number  SUB_Audio_HDI_AudioRenderGetChannelMode_002
    * @tc.desc  Test GetChannelMode interface,return -1 if getting the parameter render is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderGetChannelMode_002, TestSize.Level1)
{
    int32_t ret = -1;
    TestAudioManager* manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *renderNull = nullptr;
    struct AudioRender *render = nullptr;
    AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;

    ASSERT_NE(GetAudioManager, nullptr);
    manager = GetAudioManager();
    ret = AudioCreateStartRender(manager, &render, &adapter, ADAPTER_NAME);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = render->GetChannelMode(renderNull, &mode);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test GetChannelMode API via getting the channel mode after the render object is created
    * @tc.number  SUB_Audio_HDI_AudioRenderGetChannelMode_003
    * @tc.desc  Test GetChannelMode interface,return 0 if getting the channel mode after the object is created
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderHardwareDependenceTest, SUB_Audio_HDI_AudioRenderGetChannelMode_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    TestAudioManager* manager = {};
    AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;
    ASSERT_NE(GetAudioManager, nullptr);
    manager = GetAudioManager();
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = render->GetChannelMode(render, &mode);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_NORMAL, mode);

    adapter->DestroyRender(adapter, render);
    manager->UnloadAdapter(manager, adapter);
}
}