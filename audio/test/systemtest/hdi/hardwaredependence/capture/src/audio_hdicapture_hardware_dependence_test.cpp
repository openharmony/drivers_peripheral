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
class AudioHdiCaptureHardwareDependenceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static TestAudioManager *(*GetAudioManager)();
    static void *handleSo;
    int32_t AudioCaptureStart(const string path, struct AudioCapture *capture) const;
};

using THREAD_FUNC = void *(*)(void *);

TestAudioManager *(*AudioHdiCaptureHardwareDependenceTest::GetAudioManager)() = nullptr;
void *AudioHdiCaptureHardwareDependenceTest::handleSo = nullptr;

void AudioHdiCaptureHardwareDependenceTest::SetUpTestCase(void)
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

void AudioHdiCaptureHardwareDependenceTest::TearDownTestCase(void)
{
    if (handleSo != nullptr) {
        dlclose(handleSo);
        handleSo = nullptr;
    }
    if (GetAudioManager != nullptr) {
        GetAudioManager = nullptr;
    }
}

void AudioHdiCaptureHardwareDependenceTest::SetUp(void) {}
void AudioHdiCaptureHardwareDependenceTest::TearDown(void) {}

int32_t AudioHdiCaptureHardwareDependenceTest::AudioCaptureStart(const string path, struct AudioCapture *capture) const
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
* @tc.name  Test AudioCaptureSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_001
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = SAMPLE_RATE_8000;
*    attrs.channelCount = 1;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, 1, SAMPLE_RATE_8000);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
#ifdef PRODUCT_RK3568
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
#else
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_8000, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);
#endif
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_002
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*    attrs.sampleRate = SAMPLE_RATE_11025;
*    attrs.channelCount = 2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_11025);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_11025, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_003
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = BROADCAST_FM_RATE;
*    attrs.channelCount = 1;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, 1, BROADCAST_FM_RATE);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
#ifdef PRODUCT_RK3568
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
#else
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(BROADCAST_FM_RATE, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);
#endif

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_004
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*    attrs.sampleRate = SAMPLE_RATE_32000;
*    attrs.channelCount = 2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_32000);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_32000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_005
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = SAMPLE_RATE_44100;
*    attrs.channelCount = 1;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_44100);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
#ifdef PRODUCT_RK3568
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
#else
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_44100, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);
#endif

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_006
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_COMMUNICATION;
*    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*    attrs.sampleRate = SAMPLE_RATE_48000;
*    attrs.channelCount = 2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_006, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_48000);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via setting the capture is empty .
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_007
* @tc.desc   Test AudioCaptureSetSampleAttributes interface, return -1 if the capture is empty.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_007, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_8000);

    ret = capture->attr.SetSampleAttributes(captureNull, &attrs);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    ret = capture->attr.SetSampleAttributes(capture, nullptr);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_008
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = SAMPLE_RATE_12000;
*    attrs.channelCount = 1;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_008, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_12000);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
#ifdef PRODUCT_RK3568
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
#else
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_12000, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);
#endif

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_009
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*    attrs.sampleRate = SAMPLE_RATE_16000;
*    attrs.channelCount = 1;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_009, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_16000);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
#ifdef PRODUCT_RK3568
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
#else
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_16000, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);
#endif

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0010
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = SAMPLE_RATE_24000;
*    attrs.channelCount = 2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_010, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_24000);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_24000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0011
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = SAMPLE_RATE_64000;
*    attrs.channelCount = 1;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0011, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_64000);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
#ifdef PRODUCT_RK3568
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
#else
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_64000, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);
#endif
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0012
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*    attrs.sampleRate = SAMPLE_RATE_96000;
*    attrs.channelCount = 1;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0012, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, 1, SAMPLE_RATE_96000);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
#ifdef PRODUCT_RK3568
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
#else
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_96000, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);
#endif

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via illegal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0013
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16;
*    attrs.sampleRate = 0xFFFFFFFFu;
*    attrs.channelCount = 2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0013, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, DOUBLE_CHANNEL_COUNT, 0xFFFFFFFFu);

    ret = capture->attr.SetSampleAttributes(capture, &attrs);
    EXPECT_EQ(AUDIO_HAL_ERR_NOT_SUPPORT, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via illegal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0014
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_8/32_BIT/AAC_MAIN;
*    attrs.sampleRate = SAMPLE_RATE_8000/SAMPLE_RATE_11025/BROADCAST_FM_RATE;
*    attrs.channelCount = 1/2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_014, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs1 = {};
    struct AudioSampleAttributes attrs2 = {};
    struct AudioSampleAttributes attrs3 = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    InitAttrsUpdate(attrs1, AUDIO_FORMAT_PCM_8_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_8000);
    ret = capture->attr.SetSampleAttributes(capture, &attrs1);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    InitAttrsUpdate(attrs2, AUDIO_FORMAT_PCM_32_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_11025);
    ret = capture->attr.SetSampleAttributes(capture, &attrs2);
#ifdef ALSA_LIB_MODE
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
#else
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
#endif
    InitAttrsUpdate(attrs3, AUDIO_FORMAT_AAC_MAIN, SINGLE_CHANNEL_COUNT, BROADCAST_FM_RATE);
    ret = capture->attr.SetSampleAttributes(capture, &attrs3);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via illegal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0015
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_AAC_LC/LD/ELD;
*    attrs.sampleRate = SAMPLE_RATE_32000/SAMPLE_RATE_44100/SAMPLE_RATE_48000;
*    attrs.channelCount = 1/2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_015, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs1 = {};
    struct AudioSampleAttributes attrs2 = {};
    struct AudioSampleAttributes attrs3 = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    InitAttrsUpdate(attrs1, AUDIO_FORMAT_AAC_LC, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_32000);
    ret = capture->attr.SetSampleAttributes(capture, &attrs1);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    InitAttrsUpdate(attrs2, AUDIO_FORMAT_AAC_LD, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_44100);
    ret = capture->attr.SetSampleAttributes(capture, &attrs2);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    InitAttrsUpdate(attrs3, AUDIO_FORMAT_AAC_ELD, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_48000);
    ret = capture->attr.SetSampleAttributes(capture, &attrs3);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via illegal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0016
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_AAC_HE_V1/V2
*    attrs.sampleRate = SAMPLE_RATE_8000/SAMPLE_RATE_44100;
*    attrs.channelCount = 1/2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_016, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs1 = {};
    struct AudioSampleAttributes attrs2 = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    InitAttrsUpdate(attrs1, AUDIO_FORMAT_AAC_HE_V1, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_8000);
    ret = capture->attr.SetSampleAttributes(capture, &attrs1);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    InitAttrsUpdate(attrs2, AUDIO_FORMAT_AAC_HE_V2, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_44100);
    ret = capture->attr.SetSampleAttributes(capture, &attrs2);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via illegal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0017
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT
*    attrs.sampleRate = SAMPLE_RATE_8000;
*    attrs.channelCount = 5;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_017, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, 5, SAMPLE_RATE_8000);
    ret = capture->attr.SetSampleAttributes(capture, &attrs);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
#ifndef ALSA_LIB_MODE
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via illegal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0018
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT
*    attrs.sampleRate = SAMPLE_RATE_8000;
*    attrs.channelCount = 2;
*    silenceThreshold = 32*1024 "the value of silenceThreshold is greater than requested";
* @tc.author: ZENG LIFENG
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_018, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    int32_t silenceThreshold = 32*1024;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_8000, silenceThreshold);
    ret = capture->attr.SetSampleAttributes(capture, &attrs);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via illegal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0019
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT
*    attrs.sampleRate = SAMPLE_RATE_8000;
*    attrs.channelCount = 5;
*    silenceThreshold = 4*1024 "the value of silenceThreshold is less than requested";
* @tc.author: ZENG LIFENG
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_019, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    int32_t silenceThreshold = 2*1024;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_8000, silenceThreshold);
    ret = capture->attr.SetSampleAttributes(capture, &attrs);
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
#endif
/**
* @tc.name  Test AudioCaptureGetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureGetSampleAttributes_001
* @tc.desc  Test AudioCaptureGetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = SAMPLE_RATE_8000;
*    attrs.channelCount = 1;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_HDI_AudioCaptureGetSampleAttributes_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.GetSampleAttributes(capture, &attrsValue);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_32000);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
#ifdef PRODUCT_RK3568
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
#else
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.sampleRate);
    EXPECT_EQ(SAMPLE_RATE_32000, attrsValue.channelCount);
#endif

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test AudioCaptureGetSampleAttributes API via setting the capture is empty .
* @tc.number  SUB_Audio_HDI_AudioCaptureGetSampleAttributes_002
* @tc.desc   Test AudioCaptureGetSampleAttributes interface, return -1 if the capture is empty.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_HDI_AudioCaptureGetSampleAttributes_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_48000);

    ret = capture->attr.GetSampleAttributes(captureNull, &attrs);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);
    ret = capture->attr.GetSampleAttributes(capture, nullptr);
    EXPECT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, ret);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test CaptureGetFrameSize API via define format to different values
    * @tc.number  SUB_Audio_hdi_CaptureGetFrameSize_004
    * @tc.desc  Test CaptureGetFrameSize interface,return 0 if get framesize define format as different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_hdi_CaptureGetFrameSize_004, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t size = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_48000);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = capture->attr.GetFrameSize(capture, &size);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
#ifndef PRODUCT_RK3568
/**
    * @tc.name  Test CaptureGetFrameSize API via define sampleRate to different values
    * @tc.number  SUB_Audio_hdi_CaptureGetFrameSize_005
    * @tc.desc  Test CaptureGetFrameSize interface,return 0 if get framesize define sampleRate as different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_hdi_CaptureGetFrameSize_005, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t size = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_48000);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = capture->attr.GetFrameSize(capture, &size);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
#endif
/**
    * @tc.name  Test CaptureGetFrameSize API via define channelCount to different values
    * @tc.number  SUB_Audio_hdi_CaptureGetFrameSize_006
    * @tc.desc  Test CaptureGetFrameSize interface,return 0 if get framesize define channelCount as different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_hdi_CaptureGetFrameSize_006, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t size = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_44100);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_44100, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = capture->attr.GetFrameSize(capture, &size);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
#ifndef PRODUCT_RK3568
/**
    * @tc.name  Test CaptureGetFrameSize API via define sampleRate to different value
    * @tc.number  SUB_Audio_hdi_CaptureGetFrameSize_007
    * @tc.desc  Test CaptureGetFrameSize interface,return 0 if get framesize define sampleRate as different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_hdi_CaptureGetFrameSize_007, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t size = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_48000);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = capture->attr.GetFrameSize(capture, &size);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
#endif
/**
    * @tc.name  Test CaptureGetFrameCount API via define channelCount to different value
    * @tc.number  SUB_Audio_hdi_CaptureGetFrameCount_005
    * @tc.desc  Test CaptureGetFrameCount interface,return 0 if get framesize define channelCount as different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_hdi_CaptureGetFrameCount_005, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t count = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_8000);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_8000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.GetFrameCount(capture, &count);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test CaptureGetFrameCount API via define format to different value
    * @tc.number  SUB_Audio_hdi_CaptureGetFrameCount_006
    * @tc.desc  Test CaptureGetFrameCount interface,return 0 if get framesize define format as different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_hdi_CaptureGetFrameCount_006, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t count = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_8000);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_8000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.GetFrameCount(capture, &count);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
#ifndef PRODUCT_RK3568
/**
    * @tc.name  Test CaptureGetFrameCount API via define channelCount to different value
    * @tc.number  SUB_Audio_hdi_CaptureGetFrameCount_007
    * @tc.desc  Test CaptureGetFrameCount interface,return 0 if get framesize define channelCount to different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_hdi_CaptureGetFrameCount_007, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t count = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_44100);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_44100, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.GetFrameCount(capture, &count);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test CaptureGetFrameCount API via define format to different value
    * @tc.number  SUB_Audio_hdi_CaptureGetFrameCount_008
    * @tc.desc  Test CaptureGetFrameCount interface,return 0 if get framesize define format as different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_hdi_CaptureGetFrameCount_008, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t count = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_32000);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_32000, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.GetFrameCount(capture, &count);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    ret = capture->control.Stop((AudioHandle)capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
#endif
#ifndef PRODUCT_RK3568
/**
    * @tc.name  Test GetCurrentChannelId API via getting channelId to 1 and set channelCount to 1
    * @tc.number  SUB_Audio_HDI_CaptureGetCurrentChannelId_002
    * @tc.desc  Test GetCurrentChannelId interface,return 0 if get channelId to 1 and set channelCount to 1
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_HDI_CaptureGetCurrentChannelId_002, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t channelId = 0;
    uint32_t channelIdExp = 1;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    ASSERT_NE(nullptr, GetAudioManager);
    TestAudioManager* manager = GetAudioManager();
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);

    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_48000);

    ret = AudioCaptureSetGetSampleAttributes(attrs, attrsValue, capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = capture->attr.GetCurrentChannelId(capture, &channelId);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(channelIdExp, channelId);

    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
#endif
/**
    * @tc.name  Test GetCapturePosition API via define format to AUDIO_FORMAT_PCM_16_BIT
    * @tc.number  SUB_Audio_HDI_AudioCaptureGetCapturePosition_009
    * @tc.desc  Test GetCapturePosition interface,return 0 if get framesize define format to AUDIO_FORMAT_PCM_16_BIT
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_HDI_AudioCaptureGetCapturePosition_009, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    TestAudioManager* manager = GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrs(attrs);
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = SAMPLE_RATE_48000;
    attrs.channelCount = 2;
    ret = capture->attr.SetSampleAttributes(capture, &attrs);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.GetSampleAttributes(capture, &attrsValue);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->GetCapturePosition(capture, &frames, &time);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test GetCapturePosition API via define format to AUDIO_FORMAT_PCM_24_BIT
    * @tc.number  SUB_Audio_HDI_AudioCaptureGetCapturePosition_0010
    * @tc.desc  Test GetCapturePosition interface,return 0 if get framesize define format to AUDIO_FORMAT_PCM_24_BIT
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_HDI_AudioCaptureGetCapturePosition_010, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    TestAudioManager* manager = GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrs(attrs);
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
    attrs.sampleRate = SAMPLE_RATE_48000;
    attrs.channelCount = 2;
    ret = capture->attr.SetSampleAttributes(capture, &attrs);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.GetSampleAttributes(capture, &attrsValue);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);

    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->GetCapturePosition(capture, &frames, &time);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
#ifndef PRODUCT_RK3568
/**
    * @tc.name  Test GetCapturePosition API via define sampleRate and channelCount to different value
    * @tc.number  SUB_Audio_HDI_AudioCaptureGetCapturePosition_0011
    * @tc.desc  Test GetCapturePosition interface,return 0 if get framesize define channelCount  as different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_HDI_AudioCaptureGetCapturePosition_011, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioCapture *capture = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    TestAudioManager* manager = GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrs(attrs);
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = SAMPLE_RATE_48000;
    attrs.channelCount = 1;
    ret = capture->attr.SetSampleAttributes(capture, &attrs);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.GetSampleAttributes(capture, &attrsValue);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->GetCapturePosition(capture, &frames, &time);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
    * @tc.name  Test GetCapturePosition API via define sampleRate and channelCount to 1
    * @tc.number  SUB_Audio_HDI_AudioCaptureGetCapturePosition_0012
    * @tc.desc  Test GetCapturePosition interface,return 0 if get framesize define channelCount to 1
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_HDI_AudioCaptureGetCapturePosition_012, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    TestAudioManager* manager = GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);
    ret = AudioCreateCapture(manager, PIN_IN_MIC, ADAPTER_NAME, &adapter, &capture);
    ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    InitAttrs(attrs);
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
    attrs.sampleRate = SAMPLE_RATE_48000;
    attrs.channelCount = 1;
    ret = capture->attr.SetSampleAttributes(capture, &attrs);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->attr.GetSampleAttributes(capture, &attrsValue);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_EQ(SINGLE_CHANNEL_COUNT, attrsValue.channelCount);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);

    ret = AudioCaptureStartAndOneFrame(capture);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    ret = capture->GetCapturePosition(capture, &frames, &time);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
}
/**
* @tc.name  Test GetMmapPosition API via SetSampleAttributes and Getting position is normal.
* @tc.number  SUB_Audio_HDI_CaptureGetMmapPosition_002
* @tc.desc  Test GetMmapPosition interface,return 0 if Getting position successfully.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiCaptureHardwareDependenceTest, SUB_Audio_HDI_CaptureGetMmapPosition_002, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME.c_str(), .pins = PIN_IN_MIC,
        .path = AUDIO_LOW_LATENCY_CAPTURE_FILE.c_str()
    };
    ASSERT_NE(nullptr, GetAudioManager);
    audiopara.manager = GetAudioManager();
    ASSERT_NE(nullptr, audiopara.manager);
    ret = AudioCreateCapture(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                             &audiopara.capture);
    if (ret < 0 || audiopara.capture == nullptr) {
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
        ASSERT_EQ(nullptr, audiopara.capture);
    }
    InitAttrs(audiopara.attrs);
    audiopara.attrs.format = AUDIO_FORMAT_PCM_24_BIT;
    audiopara.attrs.channelCount = 1;
    ret = audiopara.capture->attr.SetSampleAttributes(audiopara.capture, &(audiopara.attrs));
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);

    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)RecordMapAudio, &audiopara);
    if (ret != 0) {
        audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(AUDIO_HAL_SUCCESS, ret);
    }

    void *result = nullptr;
    pthread_join(audiopara.tids, &result);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, (intptr_t)result);

    ret = audiopara.capture->attr.GetMmapPosition(audiopara.capture, &frames, &(audiopara.time));
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
    EXPECT_GT((audiopara.time.tvSec) * SECTONSEC + (audiopara.time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);

    audiopara.capture->control.Stop((AudioHandle)audiopara.capture);
    audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
}
#endif
}
