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
 * @brief Defines audio-related APIs, including custom data types and functions for capture drivers funtion.
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
using namespace HMOS::Audio;

namespace {
const string AUDIO_CAPTURE_FILE = "//bin/audiocapturetest.wav";
const string ADAPTER_NAME = "hdmi";
const string ADAPTER_NAME2 = "usb";
const string ADAPTER_NAME3 = "internal";

class AudioHdiCaptureAttrTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    struct AudioManager *(*GetAudioManager)() = nullptr;
    void *handleSo = nullptr;
    int32_t GetLoadAdapter(struct AudioManager manager, enum AudioPortDirection portType,
                           const string adapterName, struct AudioAdapter **adapter, struct AudioPort& audioPort) const;
    int32_t AudioCreateCapture(enum AudioPortPin pins, struct AudioManager manager,
                               struct AudioPort capturePort, struct AudioAdapter *adapter,
                               struct AudioCapture **capture) const;
    int32_t AudioCaptureStart(const string path, struct AudioCapture *capture) const;
};

void AudioHdiCaptureAttrTest::SetUpTestCase(void) {}

void AudioHdiCaptureAttrTest::TearDownTestCase(void) {}

void AudioHdiCaptureAttrTest::SetUp(void)
{
    char resolvedPath[] = "//system/lib/libaudio_hdi_proxy_server.z.so";
    handleSo = dlopen(resolvedPath, RTLD_LAZY);
    if (handleSo == nullptr) {
        return;
    }
    GetAudioManager = (struct AudioManager *(*)())(dlsym(handleSo, "GetAudioProxyManagerFuncs"));
    if (GetAudioManager == nullptr) {
        return;
    }
}

void AudioHdiCaptureAttrTest::TearDown(void)
{
    if (GetAudioManager != nullptr) {
        GetAudioManager = nullptr;
    }
}

int32_t AudioHdiCaptureAttrTest::GetLoadAdapter(struct AudioManager manager, enum AudioPortDirection portType,
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

int32_t AudioHdiCaptureAttrTest::AudioCreateCapture(enum AudioPortPin pins, struct AudioManager manager,
    struct AudioPort capturePort, struct AudioAdapter *adapter, struct AudioCapture **capture) const
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    if (adapter == nullptr || adapter->CreateCapture == nullptr || capture == nullptr) {
        return HDF_FAILURE;
    }
    ret = InitAttrs(attrs);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    ret = InitDevDesc(devDesc, capturePort.portId, pins);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    ret = adapter->CreateCapture(adapter, &devDesc, &attrs, capture);
    if (ret < 0 || *capture == nullptr) {
        manager.UnloadAdapter(&manager, adapter);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureAttrTest::AudioCaptureStart(const string path, struct AudioCapture *capture) const
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    if (capture == nullptr) {
        return HDF_FAILURE;
    }
    ret = InitAttrs(attrs);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    FILE *file = fopen(path.c_str(), "wb+");
    if (file == nullptr) {
        return HDF_FAILURE;
    }
    ret = FrameStartCapture(capture, file, attrs);
    if (ret < 0) {
        fclose(file);
        return HDF_FAILURE;
    }
    fclose(file);
    return HDF_SUCCESS;
}

/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0001
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = 8000;
*    attrs.channelCount = 1;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0001, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t ret1 = 1;
    uint32_t ret2 = 8000;
    struct AudioPort capturePort = {};
    struct AudioAdapter *adapter = {};
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioCapture *capture = nullptr;
    struct AudioManager manager = *GetAudioManager();
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    attrs.type = AUDIO_IN_MEDIA;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = 8000;
    attrs.channelCount = 1;

    ret = capture->attr.SetSampleAttributes(capture, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->attr.GetSampleAttributes(capture, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(ret2, attrsValue.sampleRate);
    EXPECT_EQ(ret1, attrsValue.channelCount);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0002
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*    attrs.sampleRate = 11025;
*    attrs.channelCount = 2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0002, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t ret1 = 2;
    uint32_t ret2 = 11025;
    struct AudioPort capturePort = {};
    struct AudioAdapter *adapter = {};
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioCapture *capture = nullptr;
    struct AudioManager manager = *GetAudioManager();
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    attrs.type = AUDIO_IN_MEDIA;
    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
    attrs.sampleRate = 11025;
    attrs.channelCount = 2;

    ret = capture->attr.SetSampleAttributes(capture, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->attr.GetSampleAttributes(capture, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(ret2, attrsValue.sampleRate);
    EXPECT_EQ(ret1, attrsValue.channelCount);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0003
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = 22050;
*    attrs.channelCount = 1;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0003, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t ret1 = 1;
    uint32_t ret2 = 22050;
    struct AudioPort capturePort = {};
    struct AudioAdapter *adapter = {};
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioCapture *capture = nullptr;
    struct AudioManager manager = *GetAudioManager();
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    attrs.type = AUDIO_IN_MEDIA;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = 22050;
    attrs.channelCount = 1;

    ret = capture->attr.SetSampleAttributes(capture, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->attr.GetSampleAttributes(capture, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(ret2, attrsValue.sampleRate);
    EXPECT_EQ(ret1, attrsValue.channelCount);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0004
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*    attrs.sampleRate = 32000;
*    attrs.channelCount = 2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0004, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t ret1 = 2;
    uint32_t ret2 = 32000;
    struct AudioPort capturePort = {};
    struct AudioAdapter *adapter = {};
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioCapture *capture = nullptr;
    struct AudioManager manager = *GetAudioManager();
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    attrs.type = AUDIO_IN_MEDIA;
    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
    attrs.sampleRate = 32000;
    attrs.channelCount = 2;

    ret = capture->attr.SetSampleAttributes(capture, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->attr.GetSampleAttributes(capture, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(ret2, attrsValue.sampleRate);
    EXPECT_EQ(ret1, attrsValue.channelCount);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0005
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = 44100;
*    attrs.channelCount = 1;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0005, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t ret1 = 1;
    uint32_t ret2 = 44100;
    struct AudioPort capturePort = {};
    struct AudioAdapter *adapter = {};
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioCapture *capture = nullptr;
    struct AudioManager manager = *GetAudioManager();
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    attrs.type = AUDIO_IN_MEDIA;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = 44100;
    attrs.channelCount = 1;

    ret = capture->attr.SetSampleAttributes(capture, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->attr.GetSampleAttributes(capture, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(ret2, attrsValue.sampleRate);
    EXPECT_EQ(ret1, attrsValue.channelCount);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0006
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_COMMUNICATION;
*    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
*    attrs.sampleRate = 48000;
*    attrs.channelCount = 2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0006, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t ret1 = 2;
    uint32_t ret2 = 48000;
    struct AudioPort capturePort = {};
    struct AudioAdapter *adapter = {};
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioCapture *capture = nullptr;
    struct AudioManager manager = *GetAudioManager();
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    attrs.type = AUDIO_IN_COMMUNICATION;
    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
    attrs.sampleRate = 48000;
    attrs.channelCount = 2;

    ret = capture->attr.SetSampleAttributes(capture, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->attr.GetSampleAttributes(capture, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(AUDIO_IN_COMMUNICATION, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, attrsValue.format);
    EXPECT_EQ(ret2, attrsValue.sampleRate);
    EXPECT_EQ(ret1, attrsValue.channelCount);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via setting the capture is empty .
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0007
* @tc.desc   Test AudioCaptureSetSampleAttributes interface, return -1 if the capture is empty.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0007, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort capturePort = {};
    struct AudioAdapter *adapter = {};
    struct AudioSampleAttributes attrs = {};
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;
    struct AudioManager manager = *GetAudioManager();
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    attrs.type = AUDIO_IN_MEDIA;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = AUDIO_SAMPLE_RATE_MASK_8000;
    attrs.channelCount = 1;

    ret = capture->attr.SetSampleAttributes(captureNull, &attrs);
    EXPECT_EQ(HDF_FAILURE, ret);
    ret = capture->attr.SetSampleAttributes(capture, nullptr);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via illegal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0008
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16/24_BIT;
*    attrs.sampleRate = 12000/16000/24000;
*    attrs.channelCount = 1/2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0008, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort capturePort = {};
    struct AudioAdapter *adapter = {};
    struct AudioSampleAttributes attrs1 = {};
    struct AudioSampleAttributes attrs2 = {};
    struct AudioSampleAttributes attrs3 = {};
    struct AudioCapture *capture = nullptr;
    struct AudioManager manager = *GetAudioManager();
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    attrs1.type = AUDIO_IN_MEDIA;
    attrs1.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs1.sampleRate = 12000;
    attrs1.channelCount = 1;
    ret = capture->attr.SetSampleAttributes(capture, &attrs1);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);

    attrs2.type = AUDIO_IN_MEDIA;
    attrs2.format = AUDIO_FORMAT_PCM_24_BIT;
    attrs2.sampleRate = 16000;
    attrs2.channelCount = 1;
    ret = capture->attr.SetSampleAttributes(capture, &attrs2);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);

    attrs3.type = AUDIO_IN_MEDIA;
    attrs3.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs3.sampleRate = 24000;
    attrs3.channelCount = 2;
    ret = capture->attr.SetSampleAttributes(capture, &attrs3);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via illegal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0009
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16/24_BIT;
*    attrs.sampleRate = 64000/96000/0xFFFFFFFFu;
*    attrs.channelCount = 1/2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0009, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort capturePort = {};
    struct AudioAdapter *adapter = {};
    struct AudioSampleAttributes attrs1 = {};
    struct AudioSampleAttributes attrs2 = {};
    struct AudioSampleAttributes attrs3 = {};
    struct AudioCapture *capture = nullptr;
    struct AudioManager manager = *GetAudioManager();
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    attrs1.type = AUDIO_IN_MEDIA;
    attrs1.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs1.sampleRate = 64000;
    attrs1.channelCount = 1;
    ret = capture->attr.SetSampleAttributes(capture, &attrs1);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);

    attrs2.type = AUDIO_IN_MEDIA;
    attrs2.format = AUDIO_FORMAT_PCM_24_BIT;
    attrs2.sampleRate = 96000;
    attrs2.channelCount = 1;
    ret = capture->attr.SetSampleAttributes(capture, &attrs2);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);

    attrs3.type = AUDIO_IN_MEDIA;
    attrs3.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs3.sampleRate = 0xFFFFFFFFu;
    attrs3.channelCount = 2;
    ret = capture->attr.SetSampleAttributes(capture, &attrs3);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via illegal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0010
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_8/32_BIT/AAC_MAIN;
*    attrs.sampleRate = 8000/11025/22050;
*    attrs.channelCount = 1/2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0010, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort capturePort = {};
    struct AudioAdapter *adapter = {};
    struct AudioSampleAttributes attrs1 = {};
    struct AudioSampleAttributes attrs2 = {};
    struct AudioSampleAttributes attrs3 = {};
    struct AudioCapture *capture = nullptr;
    struct AudioManager manager = *GetAudioManager();
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    attrs1.type = AUDIO_IN_MEDIA;
    attrs1.format = AUDIO_FORMAT_PCM_8_BIT;
    attrs1.sampleRate = 8000;
    attrs1.channelCount = 1;
    ret = capture->attr.SetSampleAttributes(capture, &attrs1);
    EXPECT_EQ(HDF_FAILURE, ret);

    attrs2.type = AUDIO_IN_MEDIA;
    attrs2.format = AUDIO_FORMAT_PCM_32_BIT;
    attrs2.sampleRate = 11025;
    attrs2.channelCount = 2;
    ret = capture->attr.SetSampleAttributes(capture, &attrs2);
    EXPECT_EQ(HDF_FAILURE, ret);

    attrs3.type = AUDIO_IN_MEDIA;
    attrs3.format = AUDIO_FORMAT_AAC_MAIN;
    attrs3.sampleRate = 22050;
    attrs3.channelCount = 1;
    ret = capture->attr.SetSampleAttributes(capture, &attrs3);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via illegal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0011
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_AAC_LC/LD/ELD;
*    attrs.sampleRate = 32000/44100/48000;
*    attrs.channelCount = 1/2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0011, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort capturePort = {};
    struct AudioAdapter *adapter = {};
    struct AudioSampleAttributes attrs1 = {};
    struct AudioSampleAttributes attrs2 = {};
    struct AudioSampleAttributes attrs3 = {};
    struct AudioCapture *capture = nullptr;
    struct AudioManager manager = *GetAudioManager();
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    attrs1.type = AUDIO_IN_MEDIA;
    attrs1.format = AUDIO_FORMAT_AAC_LC;
    attrs1.sampleRate = 32000;
    attrs1.channelCount = 2;
    ret = capture->attr.SetSampleAttributes(capture, &attrs1);
    EXPECT_EQ(HDF_FAILURE, ret);

    attrs2.type = AUDIO_IN_MEDIA;
    attrs2.format = AUDIO_FORMAT_AAC_LD;
    attrs2.sampleRate = 44100;
    attrs2.channelCount = 1;
    ret = capture->attr.SetSampleAttributes(capture, &attrs2);
    EXPECT_EQ(HDF_FAILURE, ret);

    attrs3.type = AUDIO_IN_MEDIA;
    attrs3.format = AUDIO_FORMAT_AAC_ELD;
    attrs3.sampleRate = 48000;
    attrs3.channelCount = 2;
    ret = capture->attr.SetSampleAttributes(capture, &attrs3);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via illegal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0012
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_AAC_HE_V1/V2
*    attrs.sampleRate = 8000/44100;
*    attrs.channelCount = 1/2;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0012, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort capturePort = {};
    struct AudioAdapter *adapter = {};
    struct AudioSampleAttributes attrs1 = {};
    struct AudioSampleAttributes attrs2 = {};
    struct AudioCapture *capture = nullptr;
    struct AudioManager manager = *GetAudioManager();
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    attrs1.type = AUDIO_IN_MEDIA;
    attrs1.format = AUDIO_FORMAT_AAC_HE_V1;
    attrs1.sampleRate = 8000;
    attrs1.channelCount = 1;
    ret = capture->attr.SetSampleAttributes(capture, &attrs1);
    EXPECT_EQ(HDF_FAILURE, ret);

    attrs2.type = AUDIO_IN_MEDIA;
    attrs2.format = AUDIO_FORMAT_AAC_HE_V2;
    attrs2.sampleRate = 44100;
    attrs2.channelCount = 2;
    ret = capture->attr.SetSampleAttributes(capture, &attrs2);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioCaptureSetSampleAttributes API via illegal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0013
* @tc.desc  Test AudioCaptureSetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT
*    attrs.sampleRate = 8000;
*    attrs.channelCount = 5;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_0013, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort capturePort = {};
    struct AudioAdapter *adapter = {};
    struct AudioSampleAttributes attrs = {};
    struct AudioCapture *capture = nullptr;
    struct AudioManager manager = *GetAudioManager();
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    attrs.type = AUDIO_IN_MEDIA;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = 8000;
    attrs.channelCount = 5;
    ret = capture->attr.SetSampleAttributes(capture, &attrs);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioCaptureGetSampleAttributes API via legal input.
* @tc.number  SUB_Audio_HDI_AudioCaptureGetSampleAttributes_0001
* @tc.desc  Test AudioCaptureGetSampleAttributes ,the setting parameters are as follows.
*    attrs.type = AUDIO_IN_MEDIA;
*    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
*    attrs.sampleRate = 8000;
*    attrs.channelCount = 1;
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_AudioCaptureGetSampleAttributes_0001, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t ret1 = 8000;
    uint32_t ret2 = 1;
    struct AudioPort capturePort = {};
    struct AudioAdapter *adapter = {};
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};
    struct AudioCapture *capture = nullptr;
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioManager manager = *GetAudioManager();
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = capture->attr.GetSampleAttributes(capture, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);

    attrs.type = AUDIO_IN_MEDIA;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = 8000;
    attrs.channelCount = 1;

    ret = capture->attr.SetSampleAttributes(capture, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->attr.GetSampleAttributes(capture, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);

    EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
    EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
    EXPECT_EQ(ret1, attrsValue.sampleRate);
    EXPECT_EQ(ret2, attrsValue.channelCount);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
* @tc.name  Test AudioCaptureGetSampleAttributes API via setting the capture is empty .
* @tc.number  SUB_Audio_HDI_AudioCaptureGetSampleAttributes_0002
* @tc.desc   Test AudioCaptureGetSampleAttributes interface, return -1 if the capture is empty.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_AudioCaptureGetSampleAttributes_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort capturePort = {};
    struct AudioAdapter *adapter = {};
    struct AudioSampleAttributes attrs = {};
    struct AudioCapture *capture = nullptr;
    struct AudioCapture *captureNull = nullptr;
    struct AudioManager manager = *GetAudioManager();
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    ASSERT_NE(nullptr, GetAudioManager);

    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (ret < 0 || capture == nullptr) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
        ASSERT_NE(nullptr, capture);
    }

    attrs.type = AUDIO_IN_MEDIA;
    attrs.format = AUDIO_FORMAT_PCM_24_BIT;
    attrs.sampleRate = 48000;
    attrs.channelCount = 1;

    ret = capture->attr.GetSampleAttributes(captureNull, &attrs);
    EXPECT_EQ(HDF_FAILURE, ret);
    ret = capture->attr.GetSampleAttributes(capture, nullptr);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
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
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter* adapter = nullptr;
    struct AudioCapture* capture = nullptr;
    uint64_t size = 0;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (capture == nullptr || ret != 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = capture->attr.GetFrameSize((AudioHandle)capture, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(size, INITIAL_VALUE);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
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
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter* adapter = nullptr;
    struct AudioCapture* capture = nullptr;
    struct AudioCapture* captureNull = nullptr;
    uint64_t size = 0;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (capture == nullptr || ret != 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = capture->attr.GetFrameSize((AudioHandle)captureNull, &size);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
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
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter* adapter = nullptr;
    struct AudioCapture* capture = nullptr;
    uint64_t* sizeNull = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (capture == nullptr || ret != 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = capture->attr.GetFrameSize((AudioHandle)capture, sizeNull);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
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
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter* adapter = nullptr;
    struct AudioCapture* capture = nullptr;
    uint64_t count = 0;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (capture == nullptr || ret != 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = capture->attr.GetFrameCount((AudioHandle)capture, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(count, INITIAL_VALUE);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
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
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter* adapter = nullptr;
    struct AudioCapture* capture = nullptr;
    uint64_t count = 0;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (capture == nullptr || ret != 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->attr.GetFrameCount((AudioHandle)capture, &count);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_GT(count, INITIAL_VALUE);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
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
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter* adapter = nullptr;
    struct AudioCapture* capture = nullptr;
    struct AudioCapture* captureNull = nullptr;
    uint64_t count = 0;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (capture == nullptr || ret != 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->attr.GetFrameCount((AudioHandle)captureNull, &count);
    EXPECT_EQ(HDF_FAILURE, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
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
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter* adapter = nullptr;
    struct AudioCapture* capture = nullptr;
    uint64_t* countNull = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();

    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (capture == nullptr || ret != 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->attr.GetFrameCount((AudioHandle)capture, countNull);
    EXPECT_EQ(HDF_FAILURE, ret);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
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
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter* adapter = nullptr;
    struct AudioCapture* capture = nullptr;
    uint32_t channelId = 0;
    uint32_t channelIdValue = CHANNELCOUNT;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (capture == nullptr || ret != 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = capture->attr.GetCurrentChannelId(capture, &channelId);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(channelIdValue, channelId);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
/**
    * @tc.name  Test GetCurrentChannelId API via getting channelId to 1 and set channelCount to 1
    * @tc.number  SUB_Audio_HDI_CaptureGetCurrentChannelId_0002
    * @tc.desc  Test GetCurrentChannelId interface,return 0 if get channelId to 1 and set channelCount to 1
    * @tc.author: tiansuli
*/
HWTEST_F(AudioHdiCaptureAttrTest, SUB_Audio_HDI_CaptureGetCurrentChannelId_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter* adapter = nullptr;
    struct AudioCapture* capture = nullptr;
    uint32_t channelId = 0;
    uint32_t channelIdExp = 1;
    uint32_t channelCountExp = 1;
    struct AudioSampleAttributes attrs = {};
    struct AudioSampleAttributes attrsValue = {};

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (capture == nullptr || ret != 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    attrs.type = AUDIO_IN_MEDIA;
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.sampleRate = 48000;
    attrs.channelCount = 1;

    ret = capture->attr.SetSampleAttributes(capture, &attrs);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = capture->attr.GetSampleAttributes(capture, &attrsValue);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(channelCountExp, attrsValue.channelCount);

    ret = capture->attr.GetCurrentChannelId(capture, &channelId);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(channelIdExp, channelId);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
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
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter* adapter = nullptr;
    struct AudioCapture* capture = nullptr;
    uint32_t channelId = 0;
    uint32_t channelIdExp = 2;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (capture == nullptr || ret != 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = AudioCaptureStart(AUDIO_CAPTURE_FILE, capture);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = capture->attr.GetCurrentChannelId(capture, &channelId);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ(channelIdExp, channelId);

    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
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
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter* adapter = nullptr;
    struct AudioCapture* capture = nullptr;
    struct AudioCapture* captureNull = nullptr;
    uint32_t channelId = 0;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (capture == nullptr || ret != 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = capture->attr.GetCurrentChannelId(captureNull, &channelId);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
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
    struct AudioPort capturePort = {};
    enum AudioPortDirection portType = PORT_IN;
    enum AudioPortPin pins = PIN_IN_MIC;
    struct AudioAdapter* adapter = nullptr;
    struct AudioCapture* capture = nullptr;
    struct AudioCapture* captureNull = nullptr;
    uint32_t *channelIdNull = nullptr;

    ASSERT_NE(nullptr, GetAudioManager);
    struct AudioManager manager = *GetAudioManager();
    ret = GetLoadAdapter(manager, portType, ADAPTER_NAME2, &adapter, capturePort);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioCreateCapture(pins, manager, capturePort, adapter, &capture);
    if (capture == nullptr || ret != 0) {
        manager.UnloadAdapter(&manager, adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    ret = capture->attr.GetCurrentChannelId(captureNull, channelIdNull);
    EXPECT_EQ(HDF_FAILURE, ret);

    adapter->DestroyCapture(adapter, capture);
    manager.UnloadAdapter(&manager, adapter);
}
}
