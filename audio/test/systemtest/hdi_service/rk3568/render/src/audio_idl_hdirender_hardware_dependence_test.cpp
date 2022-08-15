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
class AudioIdlHdiRenderHardwareDependenceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    struct AudioAdapter *adapter = nullptr;
    struct AudioRender *render = nullptr;
    static TestAudioManager *(*GetAudioManager)(const char *);
    static TestAudioManager *manager;
    static void *handle;
    static void (*AudioManagerRelease)(struct AudioManager *);
    static void (*AudioAdapterRelease)(struct AudioAdapter *);
    static void (*AudioRenderRelease)(struct AudioRender *);
    void ReleaseAudioSource(void);
};

using THREAD_FUNC = void *(*)(void *);
TestAudioManager *(*AudioIdlHdiRenderHardwareDependenceTest::GetAudioManager)(const char *) = nullptr;
TestAudioManager *AudioIdlHdiRenderHardwareDependenceTest::manager = nullptr;
void *AudioIdlHdiRenderHardwareDependenceTest::handle = nullptr;
void (*AudioIdlHdiRenderHardwareDependenceTest::AudioManagerRelease)(struct AudioManager *) = nullptr;
void (*AudioIdlHdiRenderHardwareDependenceTest::AudioAdapterRelease)(struct AudioAdapter *) = nullptr;
void (*AudioIdlHdiRenderHardwareDependenceTest::AudioRenderRelease)(struct AudioRender *) = nullptr;

void AudioIdlHdiRenderHardwareDependenceTest::SetUpTestCase(void)
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
    AudioManagerRelease = (void (*)(struct AudioManager *))(dlsym(handle, "AudioManagerRelease"));
    ASSERT_NE(nullptr, AudioManagerRelease);
    AudioAdapterRelease = (void (*)(struct AudioAdapter *))(dlsym(handle, "AudioAdapterRelease"));
    ASSERT_NE(nullptr, AudioAdapterRelease);
    AudioRenderRelease = (void (*)(struct AudioRender *))(dlsym(handle, "AudioRenderRelease"));
    ASSERT_NE(nullptr, AudioRenderRelease);
}

void AudioIdlHdiRenderHardwareDependenceTest::TearDownTestCase(void)
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

void AudioIdlHdiRenderHardwareDependenceTest::SetUp(void)
{
    int32_t ret;
    ASSERT_NE(nullptr, manager);
    ret = AudioCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

void AudioIdlHdiRenderHardwareDependenceTest::TearDown(void)
{
    ReleaseAudioSource();
}

void AudioIdlHdiRenderHardwareDependenceTest::ReleaseAudioSource(void)
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
    * @tc.name  Test RenderGetFrameSize API via define format to different values
    * @tc.number  SUB_Audio_HDI_RenderGetFrameSize_004
    * @tc.desc  Test RenderGetFrameSize interface,return 0 if get framesize define format as different values
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderGetFrameSize_004, TestSize.Level1)
{
    int32_t ret;
    uint64_t size = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);

    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_48000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = render->GetFrameSize(render, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);
}
/**
    * @tc.name  Test RenderGetFrameSize API via define channelCount to different values
    * @tc.number  SUB_Audio_HDI_RenderGetFrameSize_006
    * @tc.desc  Test RenderGetFrameSize interface,return 0 if get framesize define channelCount as different values
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderGetFrameSize_006, TestSize.Level1)
{
    int32_t ret;
    uint64_t size = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_44100);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_44100, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = render->GetFrameSize(render, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);
}
/**
    * @tc.name  Test RenderGetFrameCount API via define channelCount to different value
    * @tc.number  SUB_Audio_HDI_RenderGetFrameCount_004
    * @tc.desc  Test RenderGetFrameCount interface,return 0 if get framesize define channelCount as different values
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderGetFrameCount_004, TestSize.Level1)
{
    int32_t ret;
    uint64_t count = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_8000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_8000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetFrameCount(render, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
    * @tc.name  Test RenderGetFrameCount API via define format to different value
    * @tc.number  SUB_Audio_HDI_RenderGetFrameCount_005
    * @tc.desc  Test RenderGetFrameCount interface,return 0 if get framesize define format as different values
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderGetFrameCount_005, TestSize.Level1)
{
    int32_t ret;
    uint64_t count = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_8000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_8000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);

    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetFrameCount(render, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    ret = render->Stop(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name    Test RenderSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_RenderSetSampleAttributes_001
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*     attrs.sampleRate = AUDIO_SAMPLE_RATE_MASK_8000;
*     attrs.channelCount = 1;
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderSetSampleAttributes_001, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_8000);

    ret = render->SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name    Test RenderSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_RenderSetSampleAttributes_002
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*     attrs.sampleRate = SAMPLE_RATE_11025;
*     attrs.channelCount = 2;
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderSetSampleAttributes_002, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_11025);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_11025, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);
}
/**
* @tc.name    Test RenderSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_RenderSetSampleAttributes_003
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*     attrs.sampleRate = SAMPLE_RATE_22050;
*     attrs.channelCount = 1;
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderSetSampleAttributes_003, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_22050);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_22050, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);
}
/**
* @tc.name    Test RenderSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_RenderSetSampleAttributes_004
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*     attrs.sampleRate = SAMPLE_RATE_32000;
*     attrs.channelCount = 2;
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderSetSampleAttributes_004, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_32000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_32000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);
}
/**
* @tc.name    Test RenderSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_RenderSetSampleAttributes_005
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*     attrs.sampleRate = SAMPLE_RATE_44100;
*     attrs.channelCount = 1;
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderSetSampleAttributes_005, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_44100);

    ret = render->SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name    Test RenderSetSampleAttributes API via legal input.
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_COMMUNICATION;
*     attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*     attrs.sampleRate = SAMPLE_RATE_48000;
*     attrs.channelCount = 2;
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderSetSampleAttributes_006, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_48000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);
}
/**
* @tc.name    Test RenderSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_RenderSetSampleAttributes_008
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*     attrs.sampleRate = SAMPLE_RATE_12000;
*     attrs.channelCount = 1;
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderSetSampleAttributes_008, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_12000);

    ret = render->SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name    Test RenderSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_RenderSetSampleAttributes_009
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*     attrs.sampleRate = SAMPLE_RATE_16000;
*     attrs.channelCount = 1;
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderSetSampleAttributes_009, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_16000);
    ret = render->SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name    Test RenderSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_RenderSetSampleAttributes_010
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*     attrs.sampleRate = SAMPLE_RATE_24000;
*     attrs.channelCount = 2;
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderSetSampleAttributes_010, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);

    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_24000);
    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_24000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);
}
/**
* @tc.name    Test RenderSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_RenderSetSampleAttributes_011
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*     attrs.sampleRate = SAMPLE_RATE_64000;
*     attrs.channelCount = 2;
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderSetSampleAttributes_011, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_64000);

    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_64000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);
}
/**
* @tc.name    Test RenderSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_RenderSetSampleAttributes_012
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*     attrs.sampleRate = SAMPLE_RATE_96000;
*     attrs.channelCount = 1;
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderSetSampleAttributes_012, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_96000);
    ret = render->SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name    Test RenderSetSampleAttributes API via illegal input.
* @tc.number  SUB_Audio_HDI_RenderSetSampleAttributes_013
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*     attrs.sampleRate = 0xFFFFFFFFu;
*     attrs.channelCount = 2;
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderSetSampleAttributes_013, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    ASSERT_NE(nullptr, render);
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, DOUBLE_CHANNEL_COUNT, 0xFFFFFFFFu);

    ret = render->SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
}
/**
* @tc.name    Test RenderSetSampleAttributes API via illegal input.
* @tc.number  SUB_Audio_HDI_RenderSetSampleAttributes_014
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_PCM_8/32_BIT/AAC_MAIN;
*     attrs.sampleRate = SAMPLE_RATE_8000/SAMPLE_RATE_11025/SAMPLE_RATE_22050;
*     attrs.channelCount = 1/2;
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderSetSampleAttributes_014, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs1 = {};
    struct AudioSampleAttributes attrs2 = {};
    struct AudioSampleAttributes attrs3 = {};
    ASSERT_NE(nullptr, render);

    InitAttrsUpdate(attrs1, AUDIO_FORMAT_PCM_8_BIT, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_8000);
    ret = render->SetSampleAttributes(render, &attrs1);
    EXPECT_EQ(HDF_FAILURE, ret);

    InitAttrsUpdate(attrs2, AUDIO_FORMAT_PCM_32_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_11025);
    ret = render->SetSampleAttributes(render, &attrs2);
#ifdef ALSA_LIB_MODE
    EXPECT_EQ(HDF_SUCCESS, ret);
#else
    EXPECT_EQ(HDF_FAILURE, ret);
#endif
    InitAttrsUpdate(attrs3, AUDIO_FORMAT_AAC_MAIN, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_22050);
    ret = render->SetSampleAttributes(render, &attrs3);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name    Test RenderSetSampleAttributes API via illegal input.
* @tc.number  SUB_Audio_HDI_RenderSetSampleAttributes_015
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_AAC_LC/LD/ELD;
*     attrs.sampleRate = SAMPLE_RATE_32000/SAMPLE_RATE_44100/SAMPLE_RATE_48000;
*     attrs.channelCount = 1/2;
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderSetSampleAttributes_015, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs1 = {};
    struct AudioSampleAttributes attrs2 = {};
    struct AudioSampleAttributes attrs3 = {};
    ASSERT_NE(nullptr, render);

    InitAttrsUpdate(attrs1, AUDIO_FORMAT_AAC_LC, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_32000);
    ret = render->SetSampleAttributes(render, &attrs1);
    EXPECT_EQ(HDF_FAILURE, ret);

    InitAttrsUpdate(attrs2, AUDIO_FORMAT_AAC_LD, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_44100);
    ret = render->SetSampleAttributes(render, &attrs2);
    EXPECT_EQ(HDF_FAILURE, ret);

    InitAttrsUpdate(attrs3, AUDIO_FORMAT_AAC_ELD, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_48000);
    ret = render->SetSampleAttributes(render, &attrs3);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name    Test RenderSetSampleAttributes API via illegal input.
* @tc.number  SUB_Audio_HDI_RenderSetSampleAttributes_016
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_AAC_HE_V1/V2
*     attrs.sampleRate = SAMPLE_RATE_8000/SAMPLE_RATE_44100;
*     attrs.channelCount = 1/2;
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderSetSampleAttributes_016, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs1 = {};
    struct AudioSampleAttributes attrs2 = {};
    ASSERT_NE(nullptr, render);

    InitAttrsUpdate(attrs1, AUDIO_FORMAT_AAC_HE_V1, SINGLE_CHANNEL_COUNT, SAMPLE_RATE_8000);
    ret = render->SetSampleAttributes(render, &attrs1);
    EXPECT_EQ(HDF_FAILURE, ret);

    InitAttrsUpdate(attrs2, AUDIO_FORMAT_AAC_HE_V2, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_44100);
    ret = render->SetSampleAttributes(render, &attrs2);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name    Test RenderSetSampleAttributes API via illegal input.
* @tc.number  SUB_Audio_HDI_RenderSetSampleAttributes_017
* @tc.desc    Test RenderSetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_PCM_16_BIT
*     attrs.sampleRate = SAMPLE_RATE_8000;
*     attrs.channelCount = 5;
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderSetSampleAttributes_017, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    ASSERT_NE(nullptr, render);
    uint32_t channelCount = 5;
    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_16_BIT, channelCount, SAMPLE_RATE_8000);
    ret = render->SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_FAILURE, ret);
}
/**
* @tc.name    Test RenderGetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_RenderGetSampleAttributes_001
* @tc.desc    Test RenderGetSampleAttributes ,the setting parameters are as follows.
*     attrs.type = AUDIO_IN_MEDIA;
*     attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*     attrs.sampleRate = SAMPLE_RATE_8000;
*     attrs.channelCount = 1;
* @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderGetSampleAttributes_001, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    ASSERT_NE(nullptr, render);

    InitAttrsUpdate(attrs, AUDIO_FORMAT_PCM_24_BIT, DOUBLE_CHANNEL_COUNT, SAMPLE_RATE_8000);
    ret = AudioRenderSetGetSampleAttributes(attrs, attrsValue, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_8000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);
}
/**
    * @tc.name    Test AudioRenderGetRenderPosition API via define format to AUDIO_FORMAT_PCM_16_BIT
    * @tc.number  SUB_Audio_HDI_RenderGetRenderPosition_009
    * @tc.desc    Test GetRenderPosition interface,return 0 if get framesize define format to AUDIO_FORMAT_PCM_16_BIT
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderGetRenderPosition_009, TestSize.Level1)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};

    ASSERT_NE(nullptr, render);
    InitAttrs(attrs);
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = SAMPLE_RATE_48000;
    attrs.channelCount = 2;
    ret = render->SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);
    render->Stop(render);
}
/**
    * @tc.name    Test AudioRenderGetRenderPosition API via define format to AUDIO_FORMAT_PCM_24_BIT
    * @tc.number  SUB_Audio_HDI_RenderGetRenderPosition_010
    * @tc.desc    Test GetRenderPosition interface,return 0 if get framesize define format to AUDIO_FORMAT_PCM_24_BIT
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderGetRenderPosition_010, TestSize.Level1)
{
    int32_t ret;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};

    ASSERT_NE(nullptr, render);
    InitAttrs(attrs);
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
    attrs.sampleRate = SAMPLE_RATE_48000;
    attrs.channelCount = 2;
    ret = render->SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(SAMPLE_RATE_48000, attrsValue.sampleRate);
    EXPECT_EQ(DOUBLE_CHANNEL_COUNT, attrsValue.channelCount);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetRenderPosition(render, &frames, &time);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT((time.tvSec) * SECTONSEC + (time.tvNSec), timeExp);
    EXPECT_GT(frames, INITIAL_VALUE);
    render->Stop(render);
}
/**
    * @tc.name    Test SetChannelMode API via setting channel mode to different enumeration values
    * @tc.number  SUB_Audio_HDI_RenderSetChannelMode_001
    * @tc.desc    Test SetChannelMode interface,return 0 if set channel mode to different enumeration values
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderSetChannelMode_001, TestSize.Level1)
{
    int32_t ret;
    AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;
    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->SetChannelMode(render, mode);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetChannelMode(render, &mode);
    EXPECT_EQ(HDF_SUCCESS, ret);
#ifndef ALSA_LIB_MODE
    EXPECT_EQ(AUDIO_CHANNEL_NORMAL, mode);
    AudioChannelMode modeOne = AUDIO_CHANNEL_BOTH_LEFT;
    AudioChannelMode modeSec = AUDIO_CHANNEL_BOTH_RIGHT;
    AudioChannelMode modeTrd = AUDIO_CHANNEL_EXCHANGE;
    ret = render->SetChannelMode(render, modeOne);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetChannelMode(render, &modeOne);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_BOTH_LEFT, modeOne);
    ret = render->SetChannelMode(render, modeSec);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->GetChannelMode(render, &modeSec);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_CHANNEL_BOTH_RIGHT, modeSec);
    ret = render->SetChannelMode(render, modeTrd);
    EXPECT_EQ(HDF_FAILURE, ret);
#endif
    render->Stop(render);
}
#ifndef ALSA_LIB_MODE
/**
    * @tc.name    Test SetChannelMode API via setting channel mode to different values
    * @tc.number  SUB_Audio_HDI_RenderSetChannelMode_002
    * @tc.desc    Test SetChannelMode interface,return 0 if set channel mode to different values
    * @tc.author: liweiming
*/
HWTEST_F(AudioIdlHdiRenderHardwareDependenceTest, SUB_Audio_HDI_RenderSetChannelMode_002, TestSize.Level1)
{
    int32_t ret;
    AudioChannelMode mode = AUDIO_CHANNEL_MIX;
    AudioChannelMode modeOne = AUDIO_CHANNEL_LEFT_MUTE;
    AudioChannelMode modeSec = AUDIO_CHANNEL_RIGHT_MUTE;
    AudioChannelMode modeTrd = AUDIO_CHANNEL_BOTH_MUTE;
    ASSERT_NE(nullptr, render);
    ret = AudioRenderStartAndOneFrame(render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->SetChannelMode(render, mode);
    EXPECT_EQ(HDF_FAILURE, ret);
    ret = render->SetChannelMode(render, modeOne);
    EXPECT_EQ(HDF_FAILURE, ret);
    ret = render->SetChannelMode(render, modeSec);
    EXPECT_EQ(HDF_FAILURE, ret);
    ret = render->SetChannelMode(render, modeTrd);
    EXPECT_EQ(HDF_FAILURE, ret);
    render->Stop(render);
}
#endif
}
