/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "audio_hdirender_attr_test.h"

using namespace std;
using namespace testing::ext;
using namespace HMOS::Audio;

namespace {
const string AUDIO_FILE = "//bin/audiorendertest.wav";
const string ADAPTER_NAME = "hdmi";
const string ADAPTER_NAME2 = "usb";
const string ADAPTER_NAME3 = "internal";

class AudioHdiRenderAttrTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    struct AudioManager *(*GetAudioManager)() = nullptr;
    void *handleSo = nullptr;
    int32_t GetLoadAdapter(struct AudioManager manager, enum AudioPortDirection portType,
                           const string adapterName, struct AudioAdapter **adapter, struct AudioPort& audioPort) const;
    int32_t AudioCreateRender(enum AudioPortPin pins, struct AudioManager manager, struct AudioAdapter *adapter,
                              const struct AudioPort renderPort, struct AudioRender **render) const;
    int32_t AudioRenderStart(const string path, struct AudioRender *render) const;
};

void AudioHdiRenderAttrTest::SetUpTestCase(void) {}

void AudioHdiRenderAttrTest::TearDownTestCase(void) {}

void AudioHdiRenderAttrTest::SetUp(void)
{
    char resolvedPath[] = "//system/lib/libaudio_hdi_proxy_server.z.so";
    handleSo = dlopen(resolvedPath, RTLD_LAZY);
    if (handleSo == nullptr) {
        return;
    }
    GetAudioManager = (struct AudioManager* (*)())(dlsym(handleSo, "GetAudioProxyManagerFuncs"));
    if (GetAudioManager == nullptr) {
        return;
    }
}

void AudioHdiRenderAttrTest::TearDown(void)
{
    if (GetAudioManager != nullptr) {
        GetAudioManager = nullptr;
    }
}

int32_t AudioHdiRenderAttrTest::GetLoadAdapter(struct AudioManager manager, enum AudioPortDirection portType,
    const string adapterName, struct AudioAdapter **adapter, struct AudioPort& audioPort) const
{
    int32_t ret = -1;
    int size = 0;
    struct AudioAdapterDescriptor *desc = nullptr;
    struct AudioAdapterDescriptor *descs = nullptr;
    if (adapter == nullptr) {
        return HDF_FAILURE;
    }
    ret = manager.GetAllAdapters(&manager, &descs, &size);
    if (ret < 0 || descs == nullptr || size == 0) {
        return HDF_FAILURE;
    } else {
        int index = SwitchAdapter(descs, adapterName, portType, audioPort, size);
        if (index < 0) {
            return HDF_FAILURE;
        } else {
            desc = &descs[index];
        }
    }
    if (desc == nullptr) {
        return HDF_FAILURE;
    } else {
        ret = manager.LoadAdapter(&manager, desc, adapter);
    }
    if (ret < 0 || adapter == nullptr) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiRenderAttrTest::AudioCreateRender(enum AudioPortPin pins, struct AudioManager manager,
    struct AudioAdapter *adapter, const struct AudioPort renderPort, struct AudioRender **render) const
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    if (adapter == nullptr || adapter->CreateRender == nullptr || render == nullptr) {
        return HDF_FAILURE;
    }
    ret = InitAttrs(attrs);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    ret = InitDevDesc(devDesc, renderPort.portId, pins);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, render);
    if (ret < 0 || *render == nullptr) {
        manager.UnloadAdapter(&manager, adapter);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiRenderAttrTest::AudioRenderStart(const string path, struct AudioRender *render) const
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioHeadInfo headInfo = {};
    if (render == nullptr) {
        return HDF_FAILURE;
    }
    ret = InitAttrs(attrs);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    char absPath[PATH_MAX] = {0};
    if (realpath(path.c_str(), absPath) == nullptr) {
        printf("path is not exist");
        return HDF_FAILURE;
    }
    FILE *file = fopen(absPath, "rb");
    if (file == nullptr) {
        return HDF_FAILURE;
    }
    ret = WavHeadAnalysis(headInfo, file, attrs);
    if (ret < 0) {
        fclose(file);
        return HDF_FAILURE;
    }
    ret = FrameStart(headInfo, render, file, attrs);
    if (ret < 0) {
        fclose(file);
        return HDF_FAILURE;
    }
    fclose(file);
    return HDF_SUCCESS;
}

/**
* @tc.name  Test AudioRenderSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_0001
* @tc.desc  Test AudioRenderSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = AUDIO_SAMPLE_RATE_MASK_8000;
*    attrs.channelCount = 1;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_0001, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t ret1 = 1;
    uint32_t ret2 = 8000;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    attrs.type = AUDIO_IN_MEDIA;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = 8000;
    attrs.channelCount = 1;

    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);

    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(ret2, attrsValue.sampleRate);
    EXPECT_EQ(ret1, attrsValue.channelCount);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioRenderSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_0002
* @tc.desc  Test AudioRenderSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*    attrs.sampleRate = 11025;
*    attrs.channelCount = 2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_0002, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t ret1 = 11025;
    uint32_t ret2 = 2;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    attrs.type = AUDIO_IN_MEDIA;
    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
    attrs.sampleRate = 11025;
    attrs.channelCount = 2;

    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);

    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(ret1, attrsValue.sampleRate);
    EXPECT_EQ(ret2, attrsValue.channelCount);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioRenderSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_0003
* @tc.desc  Test AudioRenderSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = 22050;
*    attrs.channelCount = 1;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_0003, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t ret1 = 22050;
    uint32_t ret2 = 2;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    attrs.type = AUDIO_IN_MEDIA;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = 22050;
    attrs.channelCount = 2;

    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);

    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(ret1, attrsValue.sampleRate);
    EXPECT_EQ(ret2, attrsValue.channelCount);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioRenderSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_0004
* @tc.desc  Test AudioRenderSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*    attrs.sampleRate = 32000;
*    attrs.channelCount = 2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_0004, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t ret1 = 32000;
    uint32_t ret2 = 2;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    attrs.type = AUDIO_IN_MEDIA;
    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
    attrs.sampleRate = 32000;
    attrs.channelCount = 2;

    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);

    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(ret1, attrsValue.sampleRate);
    EXPECT_EQ(ret2, attrsValue.channelCount);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioRenderSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_0005
* @tc.desc  Test AudioRenderSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = 44100;
*    attrs.channelCount = 1;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_0005, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t ret1 = 44100;
    uint32_t ret2 = 1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    attrs.type = AUDIO_IN_MEDIA;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = 44100;
    attrs.channelCount = 1;

    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);

    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(ret1, attrsValue.sampleRate);
    EXPECT_EQ(ret2, attrsValue.channelCount);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
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
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_0006, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t ret1 = 48000;
    uint32_t ret2 = 2;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    attrs.type = AUDIO_IN_MEDIA;
    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
    attrs.sampleRate = 48000;
    attrs.channelCount = 2;

    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);

    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(ret1, attrsValue.sampleRate);
    EXPECT_EQ(ret2, attrsValue.channelCount);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioRenderSetSampleAttributes API via setting the render is empty .
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_0007
* @tc.desc   Test AudioRenderSetSampleAttributes interface, return -1 if the render is empty.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_0007, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    attrs.type = AUDIO_IN_MEDIA;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = AUDIO_SAMPLE_RATE_MASK_8000;
    attrs.channelCount = 1;

    ret = render->attr.SetSampleAttributes(renderNull, &attrs);
    EXPECT_EQ(HDF_FAILURE, ret);
    ret = render->attr.SetSampleAttributes(render, nullptr);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioRenderSetSampleAttributes API via illegal input.
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_0008
* @tc.desc  Test AudioRenderSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16/24_BIT;
*    attrs.sampleRate = 12000/16000/24000;
*    attrs.channelCount = 1/2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_0008, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs1 = {};
    struct AudioSampleAttributes attrs2 = {};
    struct AudioSampleAttributes attrs3 = {};
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    attrs1.type = AUDIO_IN_MEDIA;
    attrs1.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs1.sampleRate = 12000;
    attrs1.channelCount = 1;
    ret = render->attr.SetSampleAttributes(render, &attrs1);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);

    attrs2.type = AUDIO_IN_MEDIA;
    attrs2.format = AUDIO_FORMAT_PCM_24_BIT;
    attrs2.sampleRate = 16000;
    attrs2.channelCount = 1;
    ret = render->attr.SetSampleAttributes(render, &attrs2);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);

    attrs3.type = AUDIO_IN_MEDIA;
    attrs3.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs3.sampleRate = 24000;
    attrs3.channelCount = 2;
    ret = render->attr.SetSampleAttributes(render, &attrs3);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioRenderSetSampleAttributes API via illegal input.
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_0009
* @tc.desc  Test AudioRenderSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16/24_BIT;
*    attrs.sampleRate = 64000/96000/0xFFFFFFFFu;
*    attrs.channelCount = 1/2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_0009, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs1 = {};
    struct AudioSampleAttributes attrs2 = {};
    struct AudioSampleAttributes attrs3 = {};
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    attrs1.type = AUDIO_IN_MEDIA;
    attrs1.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs1.sampleRate = 64000;
    attrs1.channelCount = 1;
    ret = render->attr.SetSampleAttributes(render, &attrs1);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);

    attrs2.type = AUDIO_IN_MEDIA;
    attrs2.format = AUDIO_FORMAT_PCM_24_BIT;
    attrs2.sampleRate = 96000;
    attrs2.channelCount = 1;
    ret = render->attr.SetSampleAttributes(render, &attrs2);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);

    attrs3.type = AUDIO_IN_MEDIA;
    attrs3.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs3.sampleRate = 0xFFFFFFFFu;
    attrs3.channelCount = 2;
    ret = render->attr.SetSampleAttributes(render, &attrs3);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioRenderSetSampleAttributes API via illegal input.
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_0010
* @tc.desc  Test AudioRenderSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_8/32_BIT/AAC_MAIN;
*    attrs.sampleRate = 8000/11025/22050;
*    attrs.channelCount = 1/2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_0010, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs1 = {};
    struct AudioSampleAttributes attrs2 = {};
    struct AudioSampleAttributes attrs3 = {};
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    attrs1.type = AUDIO_IN_MEDIA;
    attrs1.format = AUDIO_FORMAT_PCM_8_BIT;
    attrs1.sampleRate = 8000;
    attrs1.channelCount = 1;
    ret = render->attr.SetSampleAttributes(render, &attrs1);
    EXPECT_EQ(HDF_FAILURE, ret);

    attrs2.type = AUDIO_IN_MEDIA;
    attrs2.format = AUDIO_FORMAT_PCM_32_BIT;
    attrs2.sampleRate = 11025;
    attrs2.channelCount = 2;
    ret = render->attr.SetSampleAttributes(render, &attrs2);
    EXPECT_EQ(HDF_FAILURE, ret);

    attrs3.type = AUDIO_IN_MEDIA;
    attrs3.format = AUDIO_FORMAT_AAC_MAIN;
    attrs3.sampleRate = 22050;
    attrs3.channelCount = 1;
    ret = render->attr.SetSampleAttributes(render, &attrs3);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioRenderSetSampleAttributes API via illegal input.
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_0011
* @tc.desc  Test AudioRenderSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_AAC_LC/LD/ELD;
*    attrs.sampleRate = 32000/44100/48000;
*    attrs.channelCount = 1/2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_0011, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs1 = {};
    struct AudioSampleAttributes attrs2 = {};
    struct AudioSampleAttributes attrs3 = {};
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    attrs1.type = AUDIO_IN_MEDIA;
    attrs1.format = AUDIO_FORMAT_AAC_LC;
    attrs1.sampleRate = 32000;
    attrs1.channelCount = 2;
    ret = render->attr.SetSampleAttributes(render, &attrs1);
    EXPECT_EQ(HDF_FAILURE, ret);

    attrs2.type = AUDIO_IN_MEDIA;
    attrs2.format = AUDIO_FORMAT_AAC_LD;
    attrs2.sampleRate = 44100;
    attrs2.channelCount = 1;
    ret = render->attr.SetSampleAttributes(render, &attrs2);
    EXPECT_EQ(HDF_FAILURE, ret);

    attrs3.type = AUDIO_IN_MEDIA;
    attrs3.format = AUDIO_FORMAT_AAC_ELD;
    attrs3.sampleRate = 48000;
    attrs3.channelCount = 2;
    ret = render->attr.SetSampleAttributes(render, &attrs3);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioRenderSetSampleAttributes API via illegal input.
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_0012
* @tc.desc  Test AudioRenderSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_AAC_HE_V1/V2
*    attrs.sampleRate = 8000/44100;
*    attrs.channelCount = 1/2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_0012, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs1 = {};
    struct AudioSampleAttributes attrs2 = {};
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    attrs1.type = AUDIO_IN_MEDIA;
    attrs1.format = AUDIO_FORMAT_AAC_HE_V1;
    attrs1.sampleRate = 8000;
    attrs1.channelCount = 1;
    ret = render->attr.SetSampleAttributes(render, &attrs1);
    EXPECT_EQ(HDF_FAILURE, ret);

    attrs2.type = AUDIO_IN_MEDIA;
    attrs2.format = AUDIO_FORMAT_AAC_HE_V2;
    attrs2.sampleRate = 44100;
    attrs2.channelCount = 2;
    ret = render->attr.SetSampleAttributes(render, &attrs2);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioRenderSetSampleAttributes API via illegal input.
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_0013
* @tc.desc  Test AudioRenderSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT
*    attrs.sampleRate = 8000;
*    attrs.channelCount = 5;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_0013, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    attrs.type = AUDIO_IN_MEDIA;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = 8000;
    attrs.channelCount = 5;
    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioRenderGetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioRenderGetSampleAttributes_0001
* @tc.desc  Test AudioRenderGetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = 8000;
*    attrs.channelCount = 1;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_AudioRenderGetSampleAttributes_0001, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t ret1 = 8000;
    uint32_t ret2 = 1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    attrs.type = AUDIO_IN_MEDIA;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = 8000;
    attrs.channelCount = 1;

    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);

    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(ret1, attrsValue.sampleRate);
    EXPECT_EQ(ret2, attrsValue.channelCount);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioRendereGetSampleAttributes API via setting the render is empty .
* @tc.number  SUB_Audio_HDI_AudioRenderGetSampleAttributes_0002
* @tc.desc   Test AudioRendereGetSampleAttributes interface, return -1 if the render is empty.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_AudioRenderGetSampleAttributes_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes *attrsValue = nullptr;
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    attrs.type = AUDIO_IN_MEDIA;
    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
    attrs.sampleRate = 48000;
    attrs.channelCount = 1;

    ret = render->attr.GetSampleAttributes(renderNull, &attrs);
    EXPECT_EQ(HDF_FAILURE, ret);
    ret = render->attr.GetSampleAttributes(render, attrsValue);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test RenderGetFrameSize API via legal input
    * @tc.number  SUB_Audio_HDI_RenderGetFrameSize_0001
    * @tc.desc  Test RenderGetFrameSize interface,return 0 if the FrameSize was obtained successfully
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_RenderGetFrameSize_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    uint64_t size = 0;
    uint64_t zero = 0;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = render->attr.GetFrameSize(render, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(size, zero);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test AudioCaptureGetFrameSize API via setting the incoming parameter handle is nullptr
    * @tc.number  SUB_Audio_HDI_RenderGetFrameSize_0002
    * @tc.desc  Test RenderGetFrameSize interface,return -1 if failed to get the FrameSize when handle is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_RenderGetFrameSize_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    uint64_t size = 0;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = render->attr.GetFrameSize(renderNull, &size);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test RenderGetFrameSize API setting the incoming parameter FrameSize is nullptr
    * @tc.number  SUB_Audio_HDI_RenderGetFrameSize_0003
    * @tc.desc  Test RenderGetFrameSize interface,return -1 if failed to get the FrameSize when size is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_RenderGetFrameSize_0003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    uint64_t *sizeNull = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = render->attr.GetFrameSize(render, sizeNull);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test RenderGetFrameSize API via define format to different values
    * @tc.number  SUB_Audio_HDI_RenderGetFrameSize_0004
    * @tc.desc  Test RenderGetFrameSize interface,return 0 if get framesize define format as different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_RenderGetFrameSize_0004, TestSize.Level1)
{
        int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    uint64_t size = 0;
    uint64_t channelCountExp = 2;
    uint32_t sampleRateExp = 48000;
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = 48000;
    attrs.channelCount = 2;
    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(sampleRateExp, attrsValue.sampleRate);
    EXPECT_EQ(channelCountExp, attrsValue.channelCount);

    ret = render->attr.GetFrameSize(render, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test RenderGetFrameSize API via define sampleRate to different values
    * @tc.number  SUB_Audio_HDI_RenderGetFrameSize_0005
    * @tc.desc  Test RenderGetFrameSize interface,return 0 if get framesize define sampleRate as different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_RenderGetFrameSize_0005, TestSize.Level1)
{
        int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    uint64_t size = 0;
    uint64_t channelCountExp = 1;
    uint32_t sampleRateExp = 48000;
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = 48000;
    attrs.channelCount = 1;
    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(sampleRateExp, attrsValue.sampleRate);
    EXPECT_EQ(channelCountExp, attrsValue.channelCount);

    ret = render->attr.GetFrameSize(render, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test RenderGetFrameSize API via define channelCount to different values
    * @tc.number  SUB_Audio_HDI_RenderGetFrameSize_0006
    * @tc.desc  Test RenderGetFrameSize interface,return 0 if get framesize define channelCount as different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_RenderGetFrameSize_0006, TestSize.Level1)
{
        int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    uint64_t size = 0;
    uint64_t channelCountExp = 2;
    uint32_t sampleRateExp = 48000;
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
    attrs.sampleRate = 48000;
    attrs.channelCount = 2;
    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(sampleRateExp, attrsValue.sampleRate);
    EXPECT_EQ(channelCountExp, attrsValue.channelCount);

    ret = render->attr.GetFrameSize(render, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test RenderGetFrameSize API via define sampleRate to different value
    * @tc.number  SUB_Audio_HDI_RenderGetFrameSize_0007
    * @tc.desc  Test RenderGetFrameSize interface,return 0 if get framesize define sampleRate as different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_RenderGetFrameSize_0007, TestSize.Level1)
{
        int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    uint64_t size = 0;
    uint64_t channelCountExp = 1;
    uint32_t sampleRateExp = 44100;
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
    attrs.sampleRate = 44100;
    attrs.channelCount = 1;
    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(sampleRateExp, attrsValue.sampleRate);
    EXPECT_EQ(channelCountExp, attrsValue.channelCount);

    ret = render->attr.GetFrameSize(render, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test RenderGetFrameCount API via legal
    * @tc.number  SUB_Audio_HDI_RenderGetFrameCount_0001
    * @tc.desc  Test RenderGetFrameCount interface, return 0 if the FrameSize was obtained successfully
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_RenderGetFrameCount_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    uint64_t count = 0;
    uint64_t zero = 0;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->attr.GetFrameCount(render, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(count, zero);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test RenderGetFrameCount API via setting the incoming parameter handle is nullptr
    * @tc.number  SUB_Audio_HDI_RenderGetFrameCount_0002
    * @tc.desc  Test RenderGetFrameCount interface,return -1 if the incoming parameter handle is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_RenderGetFrameCount_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    uint64_t count = 0;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->attr.GetFrameCount(renderNull, &count);
    EXPECT_EQ(HDF_FAILURE, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test RenderGetFrameCount API setting the incoming parameter count is nullptr
    * @tc.number  SUB_Audio_HDI_RenderGetFrameCount_0003
    * @tc.desc  Test RenderGetFrameCount interface,return -1 if the incoming parameter count is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_RenderGetFrameCount_0003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    uint64_t *countNull = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = render->attr.GetFrameCount(render, countNull);
    EXPECT_EQ(HDF_FAILURE, ret);

    render->control.Stop((AudioHandle)render);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test RenderGetFrameCount API via define channelCount to different value
    * @tc.number  SUB_Audio_HDI_RenderGetFrameCount_0004
    * @tc.desc  Test RenderGetFrameCount interface,return 0 if get framesize define channelCount as different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_RenderGetFrameCount_0004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    uint64_t count = 0;
    uint64_t channelCountExp = 2;
    uint32_t sampleRateExp = 48000;
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = 48000;
    attrs.channelCount = 2;
    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(sampleRateExp, attrsValue.sampleRate);
    EXPECT_EQ(channelCountExp, attrsValue.channelCount);

    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetFrameCount(render, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test RenderGetFrameCount API via define format to different value
    * @tc.number  SUB_Audio_HDI_RenderGetFrameCount_0005
    * @tc.desc  Test RenderGetFrameCount interface,return 0 if get framesize define format as different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_RenderGetFrameCount_0005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    uint64_t count = 0;
    uint64_t channelCountExp = 2;
    uint32_t sampleRateExp = 48000;
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
    attrs.sampleRate = 48000;
    attrs.channelCount = 2;
    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(sampleRateExp, attrsValue.sampleRate);
    EXPECT_EQ(channelCountExp, attrsValue.channelCount);

    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetFrameCount(render, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test RenderGetFrameCount API via define channelCount to different value
    * @tc.number  SUB_Audio_HDI_RenderGetFrameCount_0006
    * @tc.desc  Test RenderGetFrameCount interface,return 0 if get framesize define channelCount to different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_RenderGetFrameCount_0006, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    uint64_t count = 0;
    uint64_t channelCountExp = 1;
    uint32_t sampleRateExp = 48000;
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = 48000;
    attrs.channelCount = 1;
    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(sampleRateExp, attrsValue.sampleRate);
    EXPECT_EQ(channelCountExp, attrsValue.channelCount);

    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetFrameCount(render, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test RenderGetFrameCount API via define format to different value
    * @tc.number  SUB_Audio_HDI_RenderGetFrameCount_0007
    * @tc.desc  Test RenderGetFrameCount interface,return 0 if get framesize define format as different values
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_RenderGetFrameCount_0007, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    uint64_t count = 0;
    uint64_t channelCountExp = 1;
    uint32_t sampleRateExp = 48000;
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    attrs.type = AUDIO_IN_MEDIA;
    attrs.interleaved = false;
    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
    attrs.sampleRate = 48000;
    attrs.channelCount = 1;
    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetSampleAttributes(render, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(sampleRateExp, attrsValue.sampleRate);
    EXPECT_EQ(channelCountExp, attrsValue.channelCount);

    ret = AudioRenderStart(AUDIO_FILE, render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetFrameCount(render, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    ret = render->control.Stop((AudioHandle)render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test RenderGetCurrentChannelId API via legal input
    * @tc.number  SUB_Audio_HDI_RenderGetCurrentChannelId_0001
    * @tc.desc  Test RenderGetCurrentChannelId, return 0 if the default CurrentChannelId is obtained successfully
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_RenderGetCurrentChannelId_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    uint32_t channelId = 0;
    uint32_t channelIdValue = CHANNELCOUNT;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = render->attr.GetCurrentChannelId(render, &channelId);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(channelIdValue, channelId);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test GetCurrentChannelId API via get channelId to 1 and set channelCount to 1
    * @tc.number  SUB_Audio_HDI_RenderGetCurrentChannelId_0003
    * @tc.desc  Test GetCurrentChannelId interface,return 0 if get channelId to 1 and set channelCount to 1
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_RenderGetCurrentChannelId_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    uint32_t channelId = 0;
    uint32_t channelIdExp = 1;
    uint32_t channelCountExp = 1;
    struct AudioSampleAttributes attrs = {};

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    attrs.type = AUDIO_IN_MEDIA;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = 48000;
    attrs.channelCount = 1;
    ret = render->attr.SetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = render->attr.GetSampleAttributes(render, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(channelCountExp, attrs.channelCount);

    ret = render->attr.GetCurrentChannelId(render, &channelId);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(channelIdExp, channelId);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test RenderGetCurrentChannelId API via CurrentChannelId is obtained after created
    * @tc.number  SUB_Audio_HDI_RenderGetCurrentChannelId_0003
    * @tc.desc  Test RenderGetCurrentChannelId interface, return 0 if CurrentChannelId is obtained after created
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_RenderGetCurrentChannelId_0003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    uint32_t channelId = 0;
    uint32_t channelIdExp = 2;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = render->attr.GetCurrentChannelId(render, &channelId);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(channelIdExp, channelId);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test GetCurrentChannelId API via setting the parameter render is nullptr
    * @tc.number  SUB_Audio_HDI_RenderGetCurrentChannelId_0004
    * @tc.desc  Test GetCurrentChannelId interface,return -1 if set the parameter render is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_RenderGetCurrentChannelId_0004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    struct AudioRender *renderNull = nullptr;
    uint32_t channelId = 0;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = render->attr.GetCurrentChannelId(renderNull, &channelId);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test RenderGetCurrentChannelId API via setting the parameter channelId is nullptr
    * @tc.number  SUB_Audio_HDI_RenderGetCurrentChannelId_0005
    * @tc.desc  Test RenderGetCurrentChannelId interface, return -1 if setting the parameter channelId is nullptr
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiRenderAttrTest, SUB_Audio_HDI_RenderGetCurrentChannelId_0005, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioManager manager = {};
    struct AudioAdapter *adapter = nullptr;
    struct AudioPort renderPort = {};
    struct AudioRender *render = nullptr;
    uint32_t *channelIdNull = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, renderPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateRender(PIN_OUT_SPEAKER, manager, adapter, renderPort, &render);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = render->attr.GetCurrentChannelId(render, channelIdNull);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyRender(adapter, render);
    manager.UnloadAdapter(&manager, adapter);
}
}