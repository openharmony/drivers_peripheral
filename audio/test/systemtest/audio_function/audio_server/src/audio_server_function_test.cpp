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

#include "audio_hdi_common.h"
#include "audio_server_function_test.h"

using namespace std;
using namespace testing::ext;
using namespace HMOS::Audio;

namespace {
const string AUDIO_FILE = "//bin/audiorendertest.wav";
const string AUDIO_CAPTURE_FILE = "//bin/audiocapture.wav";
const string ADAPTER_NAME = "hdmi";
const string ADAPTER_NAME2 = "usb";
const string ADAPTER_NAME3 = "internal";
const uint64_t FILESIZE = 2048;
const uint32_t CHANNELCOUNTEXOECT = 2;
const uint32_t SAMPLERATEEXOECT = 32000;

class AudioServerFunctionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    struct AudioManager *(*GetAudioManager)() = nullptr;
    void *handleSo = nullptr;
    static int32_t GetLoadAdapter(struct PrepareAudioPara& audiopara);
    static int32_t PlayAudioFile(struct PrepareAudioPara& audiopara);
    static int32_t RecordAudio(struct PrepareAudioPara& audiopara);
    uint32_t FrameSizeExpect(const struct AudioSampleAttributes attrs);
};

using THREAD_FUNC = void *(*)(void *);

void AudioServerFunctionTest::SetUpTestCase(void) {}

void AudioServerFunctionTest::TearDownTestCase(void) {}

void AudioServerFunctionTest::SetUp(void)
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

void AudioServerFunctionTest::TearDown(void)
{
    if (GetAudioManager != nullptr) {
        GetAudioManager = nullptr;
    }
}

struct PrepareAudioPara {
    struct AudioManager *manager;
    enum AudioPortDirection portType;
    const char *adapterName;
    struct AudioAdapter *adapter;
    struct AudioPort audioPort;
    void *self;
    enum AudioPortPin pins;
    const char *path;
    struct AudioRender *render;
    struct AudioCapture *capture;
    struct AudioHeadInfo headInfo;
    struct AudioAdapterDescriptor *desc;
    struct AudioAdapterDescriptor *descs;
    char *frame;
    uint64_t requestBytes;
    uint64_t replyBytes;
    uint64_t fileSize;
    struct AudioSampleAttributes attrs;
};

int32_t AudioServerFunctionTest::GetLoadAdapter(struct PrepareAudioPara& audiopara)
{
    int32_t ret = -1;
    int size = 0;
    auto *inst = (AudioServerFunctionTest *)audiopara.self;
    if (inst != nullptr && inst->GetAudioManager != nullptr) {
        audiopara.manager = inst->GetAudioManager();
    }
    if (audiopara.manager == nullptr) {
        return HDF_FAILURE;
    }
    ret = audiopara.manager->GetAllAdapters(audiopara.manager, &audiopara.descs, &size);
    if (ret < 0 || audiopara.descs == nullptr || size == 0) {
        return HDF_FAILURE;
    } else {
        int index = SwitchAdapter(audiopara.descs, audiopara.adapterName,
            audiopara.portType, audiopara.audioPort, size);
        if (index < 0) {
            return HDF_FAILURE;
        } else {
            audiopara.desc = &audiopara.descs[index];
        }
    }
    if (audiopara.desc == nullptr) {
        return HDF_FAILURE;
    } else {
        ret = audiopara.manager->LoadAdapter(audiopara.manager, audiopara.desc, &audiopara.adapter);
    }
    if (ret < 0 || audiopara.adapter == nullptr) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioServerFunctionTest::PlayAudioFile(struct PrepareAudioPara& audiopara)
{
    int32_t ret = -1;
    struct AudioDeviceDescriptor devDesc = {};
    char absPath[PATH_MAX] = {0};
    if (audiopara.adapter == nullptr  || audiopara.manager == nullptr) {
        return HDF_FAILURE;
    }
    if (realpath(audiopara.path, absPath) == nullptr) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        return HDF_FAILURE;
    }
    FILE *file = fopen(absPath, "rb");
    if (file == nullptr) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        return HDF_FAILURE;
    }

    ret = HMOS::Audio::InitAttrs(audiopara.attrs);

    if (WavHeadAnalysis(audiopara.headInfo, file, audiopara.attrs) < 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        fclose(file);
        return HDF_FAILURE;
    }

    ret = HMOS::Audio::InitDevDesc(devDesc, (&audiopara.audioPort)->portId, audiopara.pins);

    ret = audiopara.adapter->CreateRender(audiopara.adapter, &devDesc, &(audiopara.attrs), &audiopara.render);
    if (ret < 0 || audiopara.render == nullptr) {
        fclose(file);
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        return HDF_FAILURE;
    }
    ret = HMOS::Audio::FrameStart(audiopara.headInfo, audiopara.render, file, audiopara.attrs);
    if (ret == HDF_SUCCESS) {
        fclose(file);
    } else {
        audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        fclose(file);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioServerFunctionTest::RecordAudio(struct PrepareAudioPara& audiopara)
{
    int32_t ret = -1;
    struct AudioDeviceDescriptor devDesc = {};
    if (audiopara.adapter == nullptr  || audiopara.manager == nullptr) {
        return HDF_FAILURE;
    }
    ret = InitAttrs(audiopara.attrs);

    ret = InitDevDesc(devDesc, (&audiopara.audioPort)->portId, audiopara.pins);

    ret = audiopara.adapter->CreateCapture(audiopara.adapter, &devDesc, &(audiopara.attrs), &audiopara.capture);
    if (ret < 0 || audiopara.capture == nullptr) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        return HDF_FAILURE;
    }
    bool isMute = false;
    ret = audiopara.capture->volume.SetMute(audiopara.capture, isMute);
    if (ret < 0) {
        audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        return HDF_FAILURE;
    }

    FILE *file = fopen(audiopara.path, "wb+");
    if (file == nullptr) {
        audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        return HDF_FAILURE;
    }
    ret = StartRecord(audiopara.capture, file, audiopara.fileSize);
    if (ret < 0) {
        audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        fclose(file);
        return HDF_FAILURE;
    }
    fclose(file);
    return HDF_SUCCESS;
}

uint32_t AudioServerFunctionTest::FrameSizeExpect(const struct AudioSampleAttributes attrs)
{
    uint32_t sizeExpect = FRAME_SIZE * (attrs.channelCount) * (PcmFormatToBits(attrs.format) >> 3);
    return sizeExpect;
}

/**
* @tc.name  Playing an audio file
* @tc.number  SUB_Audio_Function_Render_Test_0001
* @tc.desc  test StartRender interface,The audio file is played successfully.
* @tc.author: wangkang
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Render_Test_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .self = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };

    ret = GetLoadAdapter(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->control.Stop((AudioHandle)(audiopara.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Set audio file volume
* @tc.number  SUB_Audio_Function_Render_Test_0002
* @tc.desc  test Render function,set volume when the audio file is playing.
* @tc.author: wangkang
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Render_Test_0002, TestSize.Level1)
{
    int32_t ret = -1;
    float volumeMax = 1.0;
    bool muteFalse = false;
    float volumeValue[10] = {0};
    float volumeArr[10] = {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0};
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .self = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };

    ret = GetLoadAdapter(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    sleep(1);
    if (audiopara.render != nullptr) {
        ret = audiopara.render->volume.SetMute(audiopara.render, muteFalse);
        EXPECT_EQ(HDF_SUCCESS, ret);
        sleep(1);
        ret = audiopara.render->volume.SetVolume(audiopara.render, volumeMax);
        EXPECT_EQ(HDF_SUCCESS, ret);
        for (int i = 0; i < 10; i++) {
            ret = audiopara.render->volume.SetVolume(audiopara.render, volumeArr[i]);
            EXPECT_EQ(HDF_SUCCESS, ret);
            ret = audiopara.render->volume.GetVolume(audiopara.render, &volumeValue[i]);
            EXPECT_EQ(HDF_SUCCESS, ret);
            EXPECT_EQ(volumeArr[i], volumeValue[i]);
            sleep(1);
    }
    }

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->control.Stop((AudioHandle)(audiopara.render));
    EXPECT_EQ(HDF_SUCCESS, ret);

    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Mute audio files
* @tc.number  SUB_Audio_Function_Render_Test_0003
* @tc.desc  test Render function,set mute when the audio file is playing.
* @tc.author: wangkang
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Render_Test_0003, TestSize.Level1)
{
    int32_t ret = -1;
    bool muteTrue = true;
    bool muteFalse = false;
    float volume = 0.8;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .self = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };

    ret = GetLoadAdapter(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    sleep(1);
    if (audiopara.render != nullptr) {
        ret = audiopara.render->volume.SetVolume(audiopara.render, volume);
        EXPECT_EQ(HDF_SUCCESS, ret);
        sleep(1);
        ret = audiopara.render->volume.SetMute(audiopara.render, muteTrue);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.render->volume.GetMute(audiopara.render, &muteTrue);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(true, muteTrue);
        sleep(1);
        ret = audiopara.render->volume.SetMute(audiopara.render, muteFalse);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.render->volume.GetMute(audiopara.render, &muteFalse);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(false, muteFalse);
    }

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = audiopara.render->control.Stop((AudioHandle)(audiopara.render));
    EXPECT_EQ(HDF_SUCCESS, ret);

    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Pause ��Resume and Stop audio file
* @tc.number  SUB_Audio_Function_Render_Test_0004
* @tc.desc  test Render function,call pause,resume and stop interface when the audio file is playing.
* @tc.author: wangkang
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Render_Test_0004, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .self = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };

    ret = GetLoadAdapter(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    sleep(1);
    if (audiopara.render != nullptr) {
        ret = audiopara.render->control.Pause((AudioHandle)(audiopara.render));
        EXPECT_EQ(HDF_SUCCESS, ret);
        sleep(1);
        ret = audiopara.render->control.Resume((AudioHandle)(audiopara.render));
        EXPECT_EQ(HDF_SUCCESS, ret);
    }


    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->control.Stop((AudioHandle)(audiopara.render));
    EXPECT_EQ(HDF_SUCCESS, ret);

    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Get audio gainthreshold and set gain value
* @tc.number  SUB_Audio_Function_Render_Test_0005
* @tc.desc  test Render function,Call interface GetGainThreshold,SetGain and GetGain when playing.
* @tc.author: wangkang
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Render_Test_0005, TestSize.Level1)
{
    int32_t ret = -1;
    float gain = 0;
    float gainMax = 0;
    float gainMin = 0;
    float gainMinValue = 1;
    float gainMaxValue = 14;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .self = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };

    ret = GetLoadAdapter(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    sleep(1);
    if (audiopara.render != nullptr) {
        ret = audiopara.render->volume.GetGainThreshold(audiopara.render, &gainMin, &gainMax);
        EXPECT_EQ(HDF_SUCCESS, ret);
    
        ret = audiopara.render->volume.SetGain(audiopara.render, gainMax-1);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.render->volume.GetGain(audiopara.render, &gain);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(gainMaxValue, gain);
    
        sleep(1);
        ret = audiopara.render->volume.SetGain(audiopara.render, gainMin+1);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.render->volume.GetGain(audiopara.render, &gain);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(gainMinValue, gain);
    }

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->control.Stop((AudioHandle)(audiopara.render));
    EXPECT_EQ(HDF_SUCCESS, ret);

    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  set volume after the audio file is Paused and set mute after the audio file is resumed
* @tc.number  SUB_Audio_Function_Render_Test_0006
* @tc.desc  test Render function,set volume after pause and set mute after resume during playing.
* @tc.author: tiansuli
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Render_Test_0006, TestSize.Level1)
{
    int32_t ret = -1;
    bool muteTrue = true;
    float volumeValue[10] = {0};
    float volumeArr[10] = {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0};
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .self = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };
    ret = GetLoadAdapter(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);
    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    sleep(1);
    if (audiopara.render != nullptr) {
        ret = audiopara.render->control.Pause((AudioHandle)(audiopara.render));
        EXPECT_EQ(HDF_SUCCESS, ret);
        sleep(1);
        for (int i = 0; i < 10; i++) {
            ret = audiopara.render->volume.SetVolume(audiopara.render, volumeArr[i]);
            EXPECT_EQ(HDF_SUCCESS, ret);
            ret = audiopara.render->volume.GetVolume(audiopara.render, &volumeValue[i]);
            EXPECT_EQ(HDF_SUCCESS, ret);
            EXPECT_EQ(volumeArr[i], volumeValue[i]);
            sleep(1);
        }
        ret = audiopara.render->control.Resume((AudioHandle)(audiopara.render));
        EXPECT_EQ(HDF_SUCCESS, ret);
        sleep(1);
        ret = audiopara.render->volume.SetMute(audiopara.render, muteTrue);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.render->volume.GetMute(audiopara.render, &muteTrue);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(true, muteTrue);
    }
    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->control.Stop((AudioHandle)(audiopara.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  set mute after the audio file is Paused and set volume after the audio file is resumed
* @tc.number  SUB_Audio_Function_Render_Test_0007
* @tc.desc  test Render function,set mute after pause and set volume after resume during playing.
* @tc.author: tiansuli
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Render_Test_0007, TestSize.Level1)
{
    int32_t ret = -1;
    float volumeMax = 1.0;
    bool muteTrue = true;
    bool muteFalse = false;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .self = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };
    ret = GetLoadAdapter(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);
    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    sleep(1);
    if (audiopara.render != nullptr) {
        ret = audiopara.render->control.Pause((AudioHandle)(audiopara.render));
        EXPECT_EQ(HDF_SUCCESS, ret);
        sleep(1);
        ret = audiopara.render->volume.SetMute(audiopara.render, muteTrue);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.render->volume.GetMute(audiopara.render, &muteTrue);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(true, muteTrue);
        ret = audiopara.render->volume.SetMute(audiopara.render, muteFalse);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.render->volume.GetMute(audiopara.render, &muteFalse);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(false, muteFalse);
        sleep(1);
        ret = audiopara.render->control.Resume((AudioHandle)(audiopara.render));
        EXPECT_EQ(HDF_SUCCESS, ret);
        sleep(1);
        ret = audiopara.render->volume.SetVolume(audiopara.render, volumeMax);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->control.Stop((AudioHandle)(audiopara.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Get Current ChannelId during playing.
* @tc.number  SUB_Audio_Function_Render_Test_0008
* @tc.desc  test StartRender interface,The audio file is played out normally and Get Current ChannelId as expected.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Render_Test_0008, TestSize.Level1)
{
    int32_t ret = -1;
    float speed = 3;
    uint32_t channelId = 0;
    uint32_t channelIdValue = CHANNELCOUNT;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .self = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };

    ret = GetLoadAdapter(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
    sleep(1);
    if (audiopara.render != nullptr) {
        ret = audiopara.render->SetRenderSpeed(audiopara.render, speed);
        EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
        ret = audiopara.render->GetRenderSpeed(audiopara.render, &speed);
        EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
        ret = audiopara.render->attr.GetCurrentChannelId(audiopara.render, &channelId);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(channelId, channelIdValue);
    }

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->control.Stop((AudioHandle)(audiopara.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Get Frame Size during playing
* @tc.number  SUB_Audio_Function_Render_Test_0009
* @tc.desc  test StartRender interface,The audio file is played out normally and Get Frame Sizeas expected.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Render_Test_0009, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t size = 0;
    uint64_t sizeExpect = 0;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .self = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };

    ret = GetLoadAdapter(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
    sleep(1);
    if (audiopara.render != nullptr) {
        ret = audiopara.render->attr.GetFrameSize(audiopara.render, &size);
        EXPECT_EQ(HDF_SUCCESS, ret);
        sizeExpect = FrameSizeExpect(audiopara.attrs);
        EXPECT_EQ(size, sizeExpect);
    }

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->control.Stop((AudioHandle)(audiopara.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Get Frame Count during playing
* @tc.number  SUB_Audio_Function_Render_Test_0010
* @tc.desc  test StartRender interface,The audio file is played out normally and Get Frame Count as expected.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Render_Test_0010, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t count = 0;
    uint64_t zero = 0;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .self = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };

    ret = GetLoadAdapter(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
    sleep(1);
    if (audiopara.render != nullptr) {
        ret = audiopara.render->attr.GetFrameCount(audiopara.render, &count);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_GT(count, zero);
    }

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->control.Stop((AudioHandle)(audiopara.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Get render position when playing audio file
* @tc.number  SUB_Audio_Function_Render_Test_0011
* @tc.desc  test render functio by Get render position when playing audio file.
* @tc.author: wangkang
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Render_Test_0011, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvSec = 0};
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .self = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };

    ret = GetLoadAdapter(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    sleep(1);
    if (audiopara.render != nullptr) {
        ret = audiopara.render->GetRenderPosition(audiopara.render, &frames, &time);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_GT(time.tvSec, timeExp);
        EXPECT_GT(frames, INITIAL_VALUE);
    }

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->control.Stop((AudioHandle)(audiopara.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Check Scene Capability during playing
* @tc.number  SUB_Audio_Function_Render_Test_0012
* @tc.desc  test StartRender interface,The audio file is played out normally and Check Scene Capability as expected.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Render_Test_0012, TestSize.Level1)
{
    int32_t ret = -1;
    bool supported = false;
    struct AudioSceneDescriptor scenes = {};
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .self = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };
    scenes.scene.id = 0;
    scenes.desc.pins = PIN_OUT_SPEAKER;

    ret = GetLoadAdapter(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
    sleep(1);
    if (audiopara.render != nullptr) {
        ret = audiopara.render->scene.CheckSceneCapability(audiopara.render, &scenes, &supported);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_TRUE(supported);
    }

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->control.Stop((AudioHandle)(audiopara.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  when audio file playing SetSampleAttributes
* @tc.number  SUB_Audio_Function_Render_Test_0013
* @tc.desc  test StartRender interface,After setting SetSampleAttributes,
*           the playback will reset SetSampleAttributes.
* @tc.author: wangkang
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Render_Test_0013, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t samplerateValue = 48000;
    uint32_t channelcountValue = 1;
    struct AudioSampleAttributes attrsValue = {};
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .self = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };

    ret = GetLoadAdapter(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
    sleep(1);
    if (audiopara.render != nullptr) {
        audiopara.attrs.type = AUDIO_IN_MEDIA;
        audiopara.attrs.interleaved = false;
        audiopara.attrs.format = AUDIO_FORMAT_PCM_16_BIT;
        audiopara.attrs.sampleRate = 48000;
        audiopara.attrs.channelCount = 1;
    
        ret = audiopara.render->attr.SetSampleAttributes(audiopara.render, &(audiopara.attrs));
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.render->attr.GetSampleAttributes(audiopara.render, &attrsValue);
        EXPECT_EQ(HDF_SUCCESS, ret);
    
        EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
        EXPECT_FALSE(attrsValue.interleaved);
        EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
        EXPECT_EQ(samplerateValue, attrsValue.sampleRate);
        EXPECT_EQ(channelcountValue, attrsValue.channelCount);
    }

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->control.Stop((AudioHandle)(audiopara.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Record audio file
* @tc.number  SUB_Audio_Function_Capture_Test_0001
* @tc.desc  test capture function, The audio file is recorded successfully.
* @tc.author: liutian
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Capture_Test_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME3.c_str(), .self = this, .pins = PIN_IN_MIC,
        .path = AUDIO_CAPTURE_FILE.c_str(), .fileSize = FILESIZE
    };

    ret = GetLoadAdapter(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)RecordAudio, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.capture->control.Stop((AudioHandle)(audiopara.capture));
    ASSERT_EQ(HDF_SUCCESS, ret);
    audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Pause,resume and stop when recording.
* @tc.number  SUB_Audio_Function_Capture_Test_0002
* @tc.desc  test capture function,Pause,resume and stop when recording.
* @tc.author: liutian
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Capture_Test_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME3.c_str(), .self = this, .pins = PIN_IN_MIC,
        .path = AUDIO_CAPTURE_FILE.c_str(), .fileSize = FILESIZE
    };

    ret = GetLoadAdapter(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    CaptureFrameStatus(1);
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)RecordAudio, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
    sleep(1);
    if (audiopara.capture != nullptr) {
        CaptureFrameStatus(0);
        sleep(1);
        ret = audiopara.capture->control.Pause((AudioHandle)(audiopara.capture));
        EXPECT_EQ(HDF_SUCCESS, ret);
        sleep(1);
        ret = audiopara.capture->control.Resume((AudioHandle)(audiopara.capture));
        EXPECT_EQ(HDF_SUCCESS, ret);
        CaptureFrameStatus(1);
    }

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.capture->control.Stop((AudioHandle)(audiopara.capture));
    EXPECT_EQ(HDF_SUCCESS, ret);
    audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Set volume when recording audio file
* @tc.number  SUB_Audio_Function_Capture_Test_0003
* @tc.desc  Test capture function,set volume when recording audio file.
* @tc.author: liutian
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Capture_Test_0003, TestSize.Level1)
{
    int32_t ret = -1;
    float val = 0.9;
    float getVal = 0;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME3.c_str(), .self = this, .pins = PIN_IN_MIC,
        .path = AUDIO_CAPTURE_FILE.c_str(), .fileSize = FILESIZE
    };

    ret = GetLoadAdapter(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)RecordAudio, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
    sleep(1);
    if (audiopara.capture != nullptr) {
        ret = audiopara.capture->volume.SetVolume((AudioHandle)(audiopara.capture), val);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.capture->volume.GetVolume((AudioHandle)(audiopara.capture), &getVal);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_FLOAT_EQ(val, getVal);
    }

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.capture->control.Stop((AudioHandle)(audiopara.capture));
    EXPECT_EQ(HDF_SUCCESS, ret);
    audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Set Mute when recording audio file
* @tc.number  SUB_Audio_Function_Capture_Test_0004
* @tc.desc  Test capture function, Set mute when recording audio file.
* @tc.author: liutian
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Capture_Test_0004, TestSize.Level1)
{
    int32_t ret = -1;
    bool isMute = false;
    bool mute = true;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME3.c_str(), .self = this, .pins = PIN_IN_MIC,
        .path = AUDIO_CAPTURE_FILE.c_str(), .fileSize = FILESIZE
    };

    ret = GetLoadAdapter(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)RecordAudio, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
    sleep(1);
    if (audiopara.capture != nullptr) {
        ret = audiopara.capture->volume.SetMute((AudioHandle)(audiopara.capture), mute);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.capture->volume.GetMute((AudioHandle)(audiopara.capture), &isMute);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_TRUE(isMute);
        isMute = false;
        sleep(1);
        ret = audiopara.capture->volume.SetMute((AudioHandle)(audiopara.capture), isMute);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.capture->volume.GetMute((AudioHandle)(audiopara.capture), &isMute);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_FALSE(isMute);
    }

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.capture->control.Stop((AudioHandle)(audiopara.capture));
    EXPECT_EQ(HDF_SUCCESS, ret);
    audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Set Gain when recording audio file
* @tc.number  SUB_Audio_Function_Capture_Test_0005
* @tc.desc  Test capture function, Set gain when recording audio file.
* @tc.author: liutian
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Capture_Test_0005, TestSize.Level1)
{
    int32_t ret = -1;
    float gainMin = 0;
    float gainMax = 0;
    float gainValue = 0;
    float gain = 0;
    struct PrepareAudioPara para = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME3.c_str(), .self = this, .pins = PIN_IN_MIC,
        .path = AUDIO_CAPTURE_FILE.c_str(), .fileSize = FILESIZE
    };

    ret = GetLoadAdapter(para);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)RecordAudio, &para);
    if (ret != 0) {
        para.manager->UnloadAdapter(para.manager, para.adapter);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }

    sleep(1);
    if (para.capture != nullptr) {
        ret = para.capture->volume.GetGainThreshold(para.capture, &gainMin, &gainMax);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = para.capture->volume.SetGain((AudioHandle)(para.capture), gainMax - 1);
        EXPECT_EQ(HDF_SUCCESS, ret);
        gainValue = gainMax - 1;
        ret = para.capture->volume.GetGain((AudioHandle)(para.capture), &gain);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_FLOAT_EQ(gainValue, gain);
        sleep(1);
        ret = para.capture->volume.SetGain((AudioHandle)(para.capture), gainMin + 1);
        EXPECT_EQ(HDF_SUCCESS, ret);
        gainValue = gainMin + 1;
        ret = para.capture->volume.GetGain((AudioHandle)(para.capture), &gain);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_FLOAT_EQ(gainValue, gain);
    }

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = para.capture->control.Stop((AudioHandle)(para.capture));
    EXPECT_EQ(HDF_SUCCESS, ret);
    para.adapter->DestroyCapture(para.adapter, para.capture);
    para.manager->UnloadAdapter(para.manager, para.adapter);
}
/**
* @tc.name  Set SampleAttributes during recording.
* @tc.number  SUB_Audio_Function_Capture_Test_0006
* @tc.desc  test capture function,the sampleattributes were setted success,and the audio file is recorded successfully.
* @tc.author: liutian
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Capture_Test_0006, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrsValue = {};
    struct AudioSampleAttributes attrs = {
        .format = AUDIO_FORMAT_PCM_16_BIT, .channelCount = CHANNELCOUNTEXOECT, .sampleRate = SAMPLERATEEXOECT,
        .type = AUDIO_IN_MEDIA, .interleaved = 0
    };
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME3.c_str(), .self = this, .pins = PIN_IN_MIC,
        .path = AUDIO_CAPTURE_FILE.c_str(), .fileSize = FILESIZE
    };

    ret = GetLoadAdapter(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);
    CaptureFrameStatus(1);
    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)RecordAudio, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }

    sleep(1);
    if (audiopara.capture != nullptr) {
        CaptureFrameStatus(0);
        usleep(300000);
        ret = audiopara.capture->attr.SetSampleAttributes(audiopara.capture, &attrs);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(300000);
        CaptureFrameStatus(1);
        sleep(1);
        ret = audiopara.capture->attr.GetSampleAttributes(audiopara.capture, &attrsValue);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
        EXPECT_FALSE(attrsValue.interleaved);
        EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
        EXPECT_EQ(SAMPLERATEEXOECT, attrsValue.sampleRate);
        EXPECT_EQ(CHANNELCOUNTEXOECT, attrsValue.channelCount);
    }

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.capture->control.Stop((AudioHandle)(audiopara.capture));
    EXPECT_EQ(HDF_SUCCESS, ret);
    audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Get CurrentChannel Id during recording.
* @tc.number  SUB_Audio_Function_Capture_Test_0007
* @tc.desc  test capture function,the CurrentChannel Id were get success,and the audio file is recorded successfully.
* @tc.author: tiansuli
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Capture_Test_0007, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t channelId = 0;
    uint32_t channelIdValue = CHANNELCOUNT;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME3.c_str(), .self = this, .pins = PIN_IN_MIC,
        .path = AUDIO_CAPTURE_FILE.c_str(), .fileSize = FILESIZE
    };

    ret = GetLoadAdapter(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)RecordAudio, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
    sleep(1);
    if (audiopara.capture != nullptr) {
        ret = audiopara.capture->attr.GetCurrentChannelId(audiopara.capture, &channelId);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(channelId, channelIdValue);
    }

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.capture->control.Stop((AudioHandle)(audiopara.capture));
    EXPECT_EQ(HDF_SUCCESS, ret);

    audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Get Frame Size during recording.
* @tc.number  SUB_Audio_Function_Capture_Test_0008
* @tc.desc  test capture function, the Frame Size were get success,and the audio file is recorded successfully.
* @tc.author: tiansuli
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Capture_Test_0008, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t size = 0;
    uint64_t sizeExpect = 0;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME3.c_str(), .self = this, .pins = PIN_IN_MIC,
        .path = AUDIO_CAPTURE_FILE.c_str(), .fileSize = FILESIZE
    };

    ret = GetLoadAdapter(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)RecordAudio, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
    sleep(1);
    if (audiopara.capture != nullptr) {
        ret = audiopara.capture->attr.GetFrameSize(audiopara.capture, &size);
        EXPECT_EQ(HDF_SUCCESS, ret);
        sizeExpect = FrameSizeExpect(audiopara.attrs);
        EXPECT_EQ(size, sizeExpect);
    }

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.capture->control.Stop((AudioHandle)(audiopara.capture));
    EXPECT_EQ(HDF_SUCCESS, ret);
    audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Get Frame Count during recording.
* @tc.number  SUB_Audio_Function_Capture_Test_0009
* @tc.desc  test capture function, the Frame Count were get success,and the audio file is recorded successfully.
* @tc.author: tiansuli
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Capture_Test_0009, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t count = 0;
    uint64_t zero = 0;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME3.c_str(), .self = this, .pins = PIN_IN_MIC,
        .path = AUDIO_CAPTURE_FILE.c_str(), .fileSize = FILESIZE
    };

    ret = GetLoadAdapter(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)RecordAudio, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
    sleep(1);
    if (audiopara.capture != nullptr) {
        ret = audiopara.capture->attr.GetFrameCount(audiopara.capture, &count);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_GT(count, zero);
    }

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.capture->control.Stop((AudioHandle)(audiopara.capture));
    EXPECT_EQ(HDF_SUCCESS, ret);
    audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Get Gain during recording.
* @tc.number  SUB_Audio_Function_Capture_Test_0010
* @tc.desc  test capture function, the Gain were get success,and the audio file is recorded successfully.
* @tc.author: tiansuli
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Capture_Test_0010, TestSize.Level1)
{
    int32_t ret = -1;
    float min = 0;
    float max = 0;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME3.c_str(), .self = this, .pins = PIN_IN_MIC,
        .path = AUDIO_CAPTURE_FILE.c_str(), .fileSize = FILESIZE
    };

    ret = GetLoadAdapter(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)RecordAudio, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
    sleep(1);
    if (audiopara.capture != nullptr) {
        ret = audiopara.capture->volume.GetGainThreshold((AudioHandle)(audiopara.capture), &min, &max);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(min, GAIN_MIN);
        EXPECT_EQ(max, GAIN_MAX);
    }

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.capture->control.Stop((AudioHandle)(audiopara.capture));
    EXPECT_EQ(HDF_SUCCESS, ret);

    audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Check Scene Capability during recording.
* @tc.number  SUB_Audio_Function_Capture_Test_0011
* @tc.desc  test capture function, the Check Scene Capability success,and the audio file is recorded successfully.
* @tc.author: tiansuli
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Capture_Test_0011, TestSize.Level1)
{
    int32_t ret = -1;
    bool supported = false;
    struct AudioSceneDescriptor scenes = {};
    scenes.scene.id = 0;
    scenes.desc.pins = PIN_IN_MIC;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME3.c_str(), .self = this, .pins = PIN_IN_MIC,
        .path = AUDIO_CAPTURE_FILE.c_str(), .fileSize = FILESIZE
    };

    ret = GetLoadAdapter(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)RecordAudio, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
    sleep(1);
    if (audiopara.capture != nullptr) {
        ret = audiopara.capture->scene.CheckSceneCapability(audiopara.capture, &scenes, &supported);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_TRUE(supported);
    }

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.capture->control.Stop((AudioHandle)(audiopara.capture));
    EXPECT_EQ(HDF_SUCCESS, ret);
    audiopara.adapter->DestroyCapture(audiopara.adapter, audiopara.capture);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Pause,Flush,Resume and Stop when playing audio file based smartPA
* @tc.number  SUB_Audio_Function_Smartpa_Test_0001
* @tc.desc  test Render interface by playing an audio file based smartPA successfully.
* @tc.author: wangkang
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Smartpa_Test_0001, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t latencyTime = 0;
    uint32_t expectedValue = 0;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .self = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };

    ret = GetLoadAdapter(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
    sleep(1);
    if (audiopara.render != nullptr) {
        ret = audiopara.render->GetLatency(audiopara.render, &latencyTime);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_LT(expectedValue, latencyTime);
        ret = audiopara.render->control.Pause((AudioHandle)(audiopara.render));
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.render->control.Flush((AudioHandle)audiopara.render);
        EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
        sleep(3);
        ret = audiopara.render->control.Resume((AudioHandle)(audiopara.render));
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->control.Stop((AudioHandle)(audiopara.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->control.Flush((AudioHandle)audiopara.render);
    EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Setting audio file volume based smartPA
* @tc.number  SUB_Audio_Function_Smartpa_Test_0002
* @tc.desc  test Render function,set volume when playing audio file based smartPA.
* @tc.author: wangkang
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Smartpa_Test_0002, TestSize.Level1)
{
    int32_t ret = -1;
    float volumeMax = 1.0;
    float volumeValue[10] = {0};
    float volumeArr[10] = {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0};
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .self = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };

    ret = GetLoadAdapter(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(ret, HDF_SUCCESS);
    }
    sleep(1);
    if (audiopara.render != nullptr) {
        ret = audiopara.render->volume.SetVolume(audiopara.render, volumeMax);
        for (int i = 0; i < 10; i++) {
            ret = audiopara.render->volume.SetVolume(audiopara.render, volumeArr[i]);
            EXPECT_EQ(HDF_SUCCESS, ret);
            ret = audiopara.render->volume.GetVolume(audiopara.render, &volumeValue[i]);
            EXPECT_EQ(HDF_SUCCESS, ret);
            EXPECT_EQ(volumeArr[i], volumeValue[i]);
            sleep(1);
        }
    }

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->control.Stop((AudioHandle)(audiopara.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  SetMute audio files when playing audio file based smartPA
* @tc.number  SUB_Audio_Function_Smartpa_Test_0003
* @tc.desc  test render function by SetMute and GetMute when playing audio file based smartPA.
* @tc.author: wangkang
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Smartpa_Test_0003, TestSize.Level1)
{
    int32_t ret = -1;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .self = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };

    ret = GetLoadAdapter(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    sleep(1);
    if (audiopara.render != nullptr) {
        bool muteTrue = true;
        bool muteFalse = false;
        ret = audiopara.render->volume.SetMute(audiopara.render, muteTrue);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.render->volume.GetMute(audiopara.render, &muteTrue);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(true, muteTrue);
        sleep(1);
        ret = audiopara.render->volume.SetMute(audiopara.render, muteFalse);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.render->volume.GetMute(audiopara.render, &muteFalse);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(false, muteFalse);
    }

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->control.Stop((AudioHandle)(audiopara.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Get render position when playing audio file based smartPA
* @tc.number  SUB_Audio_Function_Smartpa_Test_0004
* @tc.desc  test render functio by Get render position when playing audio file based smartPA.
* @tc.author: wangkang
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Smartpa_Test_0004, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct AudioTimeStamp time = {.tvSec = 0};
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .self = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };

    ret = GetLoadAdapter(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    sleep(1);
    if (audiopara.render != nullptr) {
        ret = audiopara.render->GetRenderPosition(audiopara.render, &frames, &time);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_GT(time.tvSec, timeExp);
        EXPECT_GT(frames, INITIAL_VALUE);
    }

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->control.Stop((AudioHandle)(audiopara.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  Get frame count and size when playing audio file based smartPA
* @tc.number  SUB_Audio_Function_Smartpa_Test_0005
* @tc.desc  test render functio by Get frame count and size when playing audio file based smartPA.
* @tc.author: wangkang
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Smartpa_Test_0005, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t size = 0;
    uint64_t count = 0;
    uint64_t zero = 0;
    uint64_t sizeExpect = 0;
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .self = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };

    ret = GetLoadAdapter(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    sleep(1);
    if (audiopara.render != nullptr) {
        ret = audiopara.render->attr.GetFrameSize(audiopara.render, &size);
        EXPECT_EQ(HDF_SUCCESS, ret);
        sizeExpect = FrameSizeExpect(audiopara.attrs);
        EXPECT_EQ(size, sizeExpect);
    
        ret = audiopara.render->attr.GetFrameCount(audiopara.render, &count);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_GT(count, zero);
    }

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->control.Stop((AudioHandle)(audiopara.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
/**
* @tc.name  SetSampleAttributes when playing audio file based smartPA
* @tc.number  SUB_Audio_Function_Smartpa_Test_0006
* @tc.desc  test render functio by SetSampleAttributes when playing audio file based smartPA.
* @tc.author: wangkang
*/
HWTEST_F(AudioServerFunctionTest, SUB_Audio_Function_Smartpa_Test_0006, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t samplerateValue = 48000;
    uint32_t channelcountValue = 1;
    struct AudioSampleAttributes attrsValue = {};
    struct PrepareAudioPara audiopara = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .self = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };

    ret = GetLoadAdapter(audiopara);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids;
    ret = pthread_create(&tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    if (ret != 0) {
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    sleep(1);
    if (audiopara.render != nullptr) {
        audiopara.attrs.type = AUDIO_IN_MEDIA;
        audiopara.attrs.format = AUDIO_FORMAT_PCM_16_BIT;
        audiopara.attrs.sampleRate = 48000;
        audiopara.attrs.channelCount = 1;
        audiopara.attrs.stopThreshold = INT_32_MAX;
    
        ret = audiopara.render->attr.SetSampleAttributes(audiopara.render, &(audiopara.attrs));
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.render->attr.GetSampleAttributes(audiopara.render, &attrsValue);
        EXPECT_EQ(HDF_SUCCESS, ret);
    
        EXPECT_EQ(AUDIO_IN_MEDIA, attrsValue.type);
        EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, attrsValue.format);
        EXPECT_EQ(samplerateValue, attrsValue.sampleRate);
        EXPECT_EQ(channelcountValue, attrsValue.channelCount);
        EXPECT_EQ(INT_32_MAX, attrsValue.stopThreshold);
    }

    void *result = nullptr;
    pthread_join(tids, &result);
    ret = (intptr_t)result;
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->control.Stop((AudioHandle)(audiopara.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    audiopara.adapter->DestroyRender(audiopara.adapter, audiopara.render);
    audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapter);
}
}