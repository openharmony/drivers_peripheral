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
#include <pthread.h>
#include "audio_hdicapture_reliability_test.h"

using namespace std;
using namespace testing::ext;
using namespace HMOS::Audio;

namespace {
const string AUDIO_FILE = "//bin/audiocapturetest.wav";
const string ADAPTER_NAME = "hdmi";
const string ADAPTER_NAME2 = "usb";
const string ADAPTER_NAME3 = "internal";
const int PTHREAD_SAMEADA_COUNT = 3;
const int PTHREAD_DIFFADA_COUNT = 2;
const uint32_t SAMPLERATEVALUE = 48000;

class AudioHdiCaptureReliabilityTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    struct AudioManager *(*GetAudioManager)() = nullptr;
    void *handleSo = nullptr;
    static int32_t RelAudioCreateCapture(struct RelCaptureAdapterPara& ptr);
    static int32_t RelGetAllAdapter(struct RelCaptureAdapterPara& ptr);
    static int32_t RelLoadAdapter(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioDestroyCapture(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioCaptureSetMute(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioCaptureGetMute(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioCaptureSetVolume(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioCaptureGetVolume(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioCaptureProcedure(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioCaptureStartAndCaputreFrame(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioCaptureSetGain(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioCaptureGetGain(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioCaptureGetGainThreshold(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioCaptureGetFrameSize(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioCaptureGetFrameCount(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioCaptureGetCurrentChannelId(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioCaptureSetSampleAttributes(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioCaptureGetSampleAttributes(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioCaptureSelectScene(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioCaptureCheckSceneCapability(struct RelCaptureAdapterPara& ptr);
};

using THREAD_FUNC = void *(*)(void *);

void AudioHdiCaptureReliabilityTest::SetUpTestCase(void) {}

void AudioHdiCaptureReliabilityTest::TearDownTestCase(void) {}

void AudioHdiCaptureReliabilityTest::SetUp(void)
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

void AudioHdiCaptureReliabilityTest::TearDown(void)
{
    if (GetAudioManager != nullptr) {
        GetAudioManager = nullptr;
    }
}

struct CaptureCharacteristic {
    bool setmute;
    bool getmute;
    float setvolume;
    float getvolume;
    float setgain;
    float getgain;
    float gainthresholdmin;
    float gainthresholdmax;
    uint64_t getframesize;
    uint64_t getframecount;
    uint32_t getcurrentchannelId;
    bool supported;
};

struct RelCaptureAdapterPara {
    struct AudioManager *manager;
    enum AudioPortDirection portType;
    const char *adapterName;
    struct AudioAdapter *adapter;
    struct AudioPort capturePort;
    void *param;
    enum AudioPortPin pins;
    const char *path;
    struct AudioCapture *capture;
    struct AudioHeadInfo headInfo;
    struct AudioAdapterDescriptor *desc;
    struct AudioAdapterDescriptor *descs;
    struct CaptureCharacteristic character;
    struct AudioSampleAttributes attrs;
    struct AudioSampleAttributes attrsValue;
    struct AudioSceneDescriptor scenes;
};

int32_t AudioHdiCaptureReliabilityTest::RelGetAllAdapter(struct RelCaptureAdapterPara& ptr)
{
    int size = 0;
    auto *inst = (AudioHdiCaptureReliabilityTest *)ptr.param;
    if (inst != nullptr && inst->GetAudioManager != nullptr) {
        ptr.manager = inst->GetAudioManager();
    }
    if (ptr.manager == nullptr) {
        return HDF_FAILURE;
    }
    ptr.manager->GetAllAdapters(ptr.manager, &ptr.descs, &size);
    if (ptr.descs == nullptr || size == 0) {
        return HDF_FAILURE;
    } else {
        int index = SwitchAdapter(ptr.descs, ptr.adapterName, ptr.portType, ptr.capturePort, size);
        if (index < 0) {
            return HDF_FAILURE;
        } else {
            ptr.desc = &ptr.descs[index];
        }
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureReliabilityTest::RelLoadAdapter(struct RelCaptureAdapterPara& ptr)
{
    if (ptr.desc == nullptr) {
        return HDF_FAILURE;
    } else {
        ptr.manager->LoadAdapter(ptr.manager, ptr.desc, &ptr.adapter);
    }
    if (ptr.adapter == nullptr) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureReliabilityTest::RelAudioCreateCapture(struct RelCaptureAdapterPara& ptr)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    if (ptr.adapter == nullptr  || ptr.manager == nullptr) {
        return HDF_FAILURE;
    }
    InitAttrs(attrs);
    InitDevDesc(devDesc, (&ptr.capturePort)->portId, ptr.pins);
    ret = ptr.adapter->CreateCapture(ptr.adapter, &devDesc, &attrs, &ptr.capture);
    if (ret < 0 || ptr.capture == nullptr) {
        ptr.manager->UnloadAdapter(ptr.manager, ptr.adapter);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureReliabilityTest::RelAudioDestroyCapture(struct RelCaptureAdapterPara& ptr)
{
    int32_t ret = -1;
    if (ptr.adapter == nullptr  || ptr.manager == nullptr) {
        return HDF_FAILURE;
    }
    ret = ptr.adapter->DestroyCapture(ptr.adapter, ptr.capture);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureReliabilityTest::RelAudioCaptureStartAndCaputreFrame(struct RelCaptureAdapterPara& ptr)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    FILE *file = fopen(ptr.path, "wb+");
    if (file == nullptr) {
        return HDF_FAILURE;
    }
    ret = InitAttrs(attrs);
    if (ret < 0) {
        fclose(file);
        return HDF_FAILURE;
    }

    ret = FrameStartCapture(ptr.capture, file, attrs);
    if (ret < 0) {
        fclose(file);
        return HDF_FAILURE;
    }
    fclose(file);
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureReliabilityTest::RelAudioCaptureSetMute(struct RelCaptureAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.capture->volume.SetMute(ptr.capture, ptr.character.setmute);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureReliabilityTest::RelAudioCaptureGetMute(struct RelCaptureAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.capture->volume.GetMute(ptr.capture, &(ptr.character.getmute));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureReliabilityTest::RelAudioCaptureSetVolume(struct RelCaptureAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.capture->volume.SetVolume(ptr.capture, ptr.character.setvolume);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureReliabilityTest::RelAudioCaptureGetVolume(struct RelCaptureAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.capture->volume.GetVolume(ptr.capture, &(ptr.character.getvolume));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureReliabilityTest::RelAudioCaptureProcedure(struct RelCaptureAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = RelGetAllAdapter(ptr);
    if (ret < 0) {
        return HDF_FAILURE;
    }

    ret = RelLoadAdapter(ptr);
    if (ret < 0) {
        return HDF_FAILURE;
    }

    ret = RelAudioCreateCapture(ptr);
    if (ret < 0) {
        return HDF_FAILURE;
    }

    ret = RelAudioCaptureStartAndCaputreFrame(ptr);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureReliabilityTest::RelAudioCaptureGetGainThreshold(struct RelCaptureAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.capture->volume.GetGainThreshold(ptr.capture, &(ptr.character.gainthresholdmin),
        &(ptr.character.gainthresholdmax));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureReliabilityTest::RelAudioCaptureSetGain(struct RelCaptureAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.capture->volume.SetGain(ptr.capture, ptr.character.setgain);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureReliabilityTest::RelAudioCaptureGetGain(struct RelCaptureAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.capture->volume.GetGain(ptr.capture, &(ptr.character.getgain));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureReliabilityTest::RelAudioCaptureGetFrameSize(struct RelCaptureAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.capture->attr.GetFrameSize(ptr.capture, &(ptr.character.getframesize));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureReliabilityTest::RelAudioCaptureGetFrameCount(struct RelCaptureAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.capture->attr.GetFrameCount(ptr.capture, &(ptr.character.getframecount));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureReliabilityTest::RelAudioCaptureGetCurrentChannelId(struct RelCaptureAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.capture->attr.GetCurrentChannelId(ptr.capture, &(ptr.character.getcurrentchannelId));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureReliabilityTest::RelAudioCaptureSetSampleAttributes(struct RelCaptureAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.capture->attr.SetSampleAttributes(ptr.capture, &(ptr.attrs));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureReliabilityTest::RelAudioCaptureGetSampleAttributes(struct RelCaptureAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.capture->attr.GetSampleAttributes(ptr.capture, &(ptr.attrsValue));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureReliabilityTest::RelAudioCaptureSelectScene(struct RelCaptureAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.capture->scene.SelectScene(ptr.capture, &(ptr.scenes));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureReliabilityTest::RelAudioCaptureCheckSceneCapability(struct RelCaptureAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.capture->scene.CheckSceneCapability(ptr.capture, &ptr.scenes, &(ptr.character.supported));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/**
* @tc.name  RelAudioCreateCapture API via The passed in adaptername is the differentt
* @tc.number  SUB_Audio_HDI_AudioCreateCapture_Reliability_0002
* @tc.desc  test AudioCreateCapture interface, return 0 if the the capture objects are created successfully
* @tc.author: wangkang
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioCreateCapture_Reliability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelCaptureAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_IN, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_IN, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }
    };
    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelGetAllAdapter(para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = RelLoadAdapter(para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCreateCapture, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
    }
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        ret = (intptr_t)result;
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyCapture(para[i].adapter, para[i].capture);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}

/**
* @tc.name  RelAudioDestroyCapture API via The passed in adaptername is the different
* @tc.number  SUB_Audio_HDI_AudioCaptureStart_Reliability_0002
* @tc.desc  test AudioCaptureStart interface,Returns 0 if the AudioCapture object is destroyed
* @tc.author: wangkang
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioDestroyCapture_Reliability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelCaptureAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_IN, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_IN, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }
    };
    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelGetAllAdapter(para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = RelLoadAdapter(para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = RelAudioCreateCapture(para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioDestroyCapture, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}

/**
* @tc.name  test AudioCaptureSetGain API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetGain_Reliability_0001
* @tc.desc  test AudioCaptureSetGain interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioCaptureSetGain_Reliability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelCaptureAdapterPara para = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_IN_MIC,
        .path = AUDIO_FILE.c_str()
    };
    struct RelCaptureAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    ret = RelAudioCaptureProcedure(para);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(RelCaptureAdapterPara), &para, sizeof(RelCaptureAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        arrpara[i].character.setgain = 2;
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureSetGain, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        ret = arrpara[i].capture->volume.GetGain(arrpara[i].capture, &(arrpara[i].character.getgain));
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(arrpara[i].character.setgain, arrpara[i].character.getgain);
    }
    ret = para.capture->control.Stop((AudioHandle)(para.capture));
    EXPECT_EQ(HDF_SUCCESS, ret);
    para.adapter->DestroyCapture(para.adapter, para.capture);
    para.manager->UnloadAdapter(para.manager, para.adapter);
}
/**
* @tc.name  test AudioCaptureSetVolume API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetGain_Reliability_0002
* @tc.desc  test SetGain interface Reliability pass through pthread_create fun and adapterName is different.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioCaptureSetGain_Reliability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelCaptureAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_IN, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_IN, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }
    };
    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelAudioCaptureProcedure(para[i]);
        ASSERT_EQ(HDF_SUCCESS, ret);
        para[i].character.setgain = 15;
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureSetGain, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
    }
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        ret = (intptr_t)result;
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = para[i].capture->volume.GetGain(para[i].capture, &(para[i].character.getgain));
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_LT(INITIAL_VALUE, para[i].character.getgain);

        ret = para[i].capture->control.Stop((AudioHandle)(para[i].capture));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyCapture(para[i].adapter, para[i].capture);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}
/**
* @tc.name  test AudioCaptureGetGain API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioCaptureGetGain_Reliability_0001
* @tc.desc  test AudioCaptureGetGain interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioCaptureGetGain_Reliability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelCaptureAdapterPara para = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_IN_MIC,
        .path = AUDIO_FILE.c_str()
    };
    struct RelCaptureAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    ret = RelAudioCaptureProcedure(para);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(RelCaptureAdapterPara), &para, sizeof(RelCaptureAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        arrpara[i].character.setgain = 8;
        ret = arrpara[i].capture->volume.SetGain(arrpara[i].capture, arrpara[i].character.setgain);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureGetGain, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_EQ(8, arrpara[i].character.getgain);
    }
    ret = para.capture->control.Stop((AudioHandle)(para.capture));
    EXPECT_EQ(HDF_SUCCESS, ret);
    para.adapter->DestroyCapture(para.adapter, para.capture);
    para.manager->UnloadAdapter(para.manager, para.adapter);
}
/**
* @tc.name  test AudioCaptureGetGain API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioCaptureGetGain_Reliability_0002
* @tc.desc  test GetGain interface Reliability pass through pthread_create fun and adapterName is different.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioCaptureGetGain_Reliability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelCaptureAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_IN, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_IN, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }
    };
    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelAudioCaptureProcedure(para[i]);
        ASSERT_EQ(HDF_SUCCESS, ret);
        para[i].character.setgain = 15;
        ret = para[i].capture->volume.SetGain(para[i].capture, para[i].character.setgain);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureGetGain, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
    }

    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_LT(INITIAL_VALUE, para[i].character.getgain);
        ret = para[i].capture->control.Stop((AudioHandle)(para[i].capture));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyCapture(para[i].adapter, para[i].capture);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}
/**
* @tc.name  test AudioCaptureGetGainThreshold API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioCaptureGetGainThreshold_Reliability_0001
* @tc.desc  test GetGainThreshold interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioCaptureGetGainThreshold_Reliability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelCaptureAdapterPara para = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_IN_MIC,
        .path = AUDIO_FILE.c_str()
    };
    struct RelCaptureAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    ret = RelAudioCaptureProcedure(para);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(RelCaptureAdapterPara), &para, sizeof(RelCaptureAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureGetGainThreshold, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_EQ(0, arrpara[i].character.gainthresholdmin);
        EXPECT_EQ(15, arrpara[i].character.gainthresholdmax);
    }
    ret = para.capture->control.Stop((AudioHandle)(para.capture));
    EXPECT_EQ(HDF_SUCCESS, ret);
    para.adapter->DestroyCapture(para.adapter, para.capture);
    para.manager->UnloadAdapter(para.manager, para.adapter);
}
/**
* @tc.name  test AudioCaptureGetGainThreshold API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioCaptureGetGainThreshold_Reliability_0002
* @tc.desc  test GetGainThreshold interface Reliability pass through pthread_create fun and adapterName is different.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioCaptureGetGainThreshold_Reliability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelCaptureAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_IN, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_IN, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }
    };

    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelAudioCaptureProcedure(para[i]);
        ASSERT_EQ(HDF_SUCCESS, ret);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureGetGainThreshold, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_EQ(0, para[i].character.gainthresholdmin);
        EXPECT_EQ(15, para[i].character.gainthresholdmax);
        ret = para[i].capture->control.Stop((AudioHandle)(para[i].capture));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyCapture(para[i].adapter, para[i].capture);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}
/**
* @tc.name  test AudioCaptureGetFrameSize API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioCaptureGetFrameSize_Reliability_0001
* @tc.desc  test AudioCaptureGetFrameSize interface Reliability pass through pthread_create fun and adapterName is same
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioCaptureGetFrameSize_Reliability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    uint64_t sizeValue = 4096;
    struct RelCaptureAdapterPara para = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_IN_MIC,
        .path = AUDIO_FILE.c_str()
    };
    struct RelCaptureAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    ret = RelAudioCaptureProcedure(para);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(RelCaptureAdapterPara), &para, sizeof(RelCaptureAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureGetFrameSize, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_EQ(sizeValue, arrpara[i].character.getframesize);
    }
    ret = para.capture->control.Stop((AudioHandle)(para.capture));
    EXPECT_EQ(HDF_SUCCESS, ret);
    para.adapter->DestroyCapture(para.adapter, para.capture);
    para.manager->UnloadAdapter(para.manager, para.adapter);
}
/**
* @tc.name  test AudioCaptureGetFrameSize API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioCaptureGetFrameSize_Reliability_0002
* @tc.desc  test GetFrameSize interface Reliability pass through pthread_create fun and adapterName is different.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioCaptureGetFrameSize_Reliability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelCaptureAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_IN, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_IN, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }

    };
    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelAudioCaptureProcedure(para[i]);
        ASSERT_EQ(HDF_SUCCESS, ret);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureGetFrameSize, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_LT(INITIAL_VALUE, para[i].character.getframesize);
        ret = para[i].capture->control.Stop((AudioHandle)(para[i].capture));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyCapture(para[i].adapter, para[i].capture);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}
/**
* @tc.name  test AudioCaptureGetFrameCount API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioCaptureGetFrameCount_Reliability_0001
* @tc.desc  test CaptureGetFrameCount interface Reliability pass through pthread_create fun and adapterName is same
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioCaptureGetFrameCount_Reliability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelCaptureAdapterPara para = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_IN_MIC,
        .path = AUDIO_FILE.c_str()
    };
    struct RelCaptureAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    ret = RelAudioCaptureProcedure(para);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(RelCaptureAdapterPara), &para, sizeof(RelCaptureAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureGetFrameCount, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_LT(INITIAL_VALUE, arrpara[i].character.getframecount);
    }
    ret = para.capture->control.Stop((AudioHandle)(para.capture));
    EXPECT_EQ(HDF_SUCCESS, ret);
    para.adapter->DestroyCapture(para.adapter, para.capture);
    para.manager->UnloadAdapter(para.manager, para.adapter);
}
/**
* @tc.name  test AudioCaptureGetFrameCount API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioCaptureGetFrameCount_Reliability_0002
* @tc.desc  test GetFrameCount interface Reliability pass through pthread_create fun and adapterName is different.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioCaptureGetFrameCount_Reliability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelCaptureAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_IN, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_IN, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }

    };
    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelAudioCaptureProcedure(para[i]);
        ASSERT_EQ(HDF_SUCCESS, ret);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureGetFrameCount, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_LT(INITIAL_VALUE, para[i].character.getframecount);
        ret = para[i].capture->control.Stop((AudioHandle)(para[i].capture));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyCapture(para[i].adapter, para[i].capture);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}

/**
* @tc.name  test AudioGetCurrentChannelId API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioGetCurrentChannelId_Reliability_0001
* @tc.desc  test AudioGetCurrentChannelId interface Reliability pass through pthread_create fun and adapterName is same
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioGetCurrentChannelId_Reliability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t channelIdValue = 2;
    struct RelCaptureAdapterPara para = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_IN_MIC,
        .path = AUDIO_FILE.c_str()
    };
    struct RelCaptureAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    ret = RelAudioCaptureProcedure(para);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(RelCaptureAdapterPara), &para, sizeof(RelCaptureAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        arrpara[i].character.getcurrentchannelId = 0;
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureGetCurrentChannelId, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_EQ(channelIdValue, arrpara[i].character.getcurrentchannelId);
    }
    ret = para.capture->control.Stop((AudioHandle)(para.capture));
    EXPECT_EQ(HDF_SUCCESS, ret);
    para.adapter->DestroyCapture(para.adapter, para.capture);
    para.manager->UnloadAdapter(para.manager, para.adapter);
}
/**
* @tc.name  test AudioCaptureGetCurrentChannelId API via Multithread call.
* @tc.number  SUB_Audio_HDI_CaptureGetCurrentChannelId_Reliability_0002
* @tc.desc test GetCurrentChannelId interface Reliability pass through pthread_create fun and adapterName is different
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_CaptureGetCurrentChannelId_Reliability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t channelIdValue = 2;
    struct RelCaptureAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_IN, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_IN, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }

    };
    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelAudioCaptureProcedure(para[i]);
        ASSERT_EQ(HDF_SUCCESS, ret);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureGetCurrentChannelId, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_EQ(channelIdValue, para[i].character.getcurrentchannelId);
        ret = para[i].capture->control.Stop((AudioHandle)(para[i].capture));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyCapture(para[i].adapter, para[i].capture);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}

/**
* @tc.name  AudioCapturesetMute
* @tc.number  SUB_Audio_HDI_AudioCaptureSetMute_0001
* @tc.desc  test AudioCaptureSetMute interface Reliability pass through pthread_create(adapterName is same)
* @tc.author: wangkang
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioCaptureSetMute_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelCaptureAdapterPara para = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_IN_MIC,
        .path = AUDIO_FILE.c_str()
    };
    struct RelCaptureAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    ret = RelAudioCaptureProcedure(para);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(RelCaptureAdapterPara), &para, sizeof(RelCaptureAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = arrpara[i].capture->volume.GetMute(arrpara[i].capture, &(arrpara[i].character.getmute));
        EXPECT_EQ(HDF_SUCCESS, ret);
        if (arrpara[i].character.getmute == false) {
            arrpara[i].character.setmute = true;
        } else {
            arrpara[i].character.setmute = false;
        }
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureSetMute, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
        ret = arrpara[i].capture->volume.GetMute(arrpara[i].capture, &(arrpara[i].character.getmute));
        EXPECT_EQ(HDF_SUCCESS, ret);
        if (arrpara[i].character.setmute == true) {
            EXPECT_TRUE(arrpara[i].character.getmute);
        } else {
            EXPECT_FALSE(arrpara[i].character.getmute);
        }
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
    }
    ret = para.capture->control.Stop((AudioHandle)(para.capture));
    EXPECT_EQ(HDF_SUCCESS, ret);
    para.adapter->DestroyCapture(para.adapter, para.capture);
    para.manager->UnloadAdapter(para.manager, para.adapter);
}
/**
* @tc.name  RelAudioCaptureSetMute
* @tc.number  SUB_Audio_HDI_AudioCaptureSetMute_0002
* @tc.desc  test AudioCaptureSetMute interface Reliability pass through pthread_create(adapterName is different)
* @tc.author: wangkang
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioCaptureSetMute_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelCaptureAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_IN, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_IN, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }
    };

    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelAudioCaptureProcedure(para[i]);
        ASSERT_EQ(HDF_SUCCESS, ret);
        ret = para[i].capture->volume.GetMute(para[i].capture, &(para[i].character.getmute));
        EXPECT_EQ(HDF_SUCCESS, ret);
        if (para[i].character.getmute == false) {
            para[i].character.setmute = true;
        } else {
            para[i].character.setmute = false;
        }
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureSetMute, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
        ret = para[i].capture->volume.GetMute(para[i].capture, &(para[i].character.getmute));
        EXPECT_EQ(HDF_SUCCESS, ret);
        if (para[i].character.setmute == true) {
            EXPECT_TRUE(para[i].character.getmute);
        } else {
            EXPECT_FALSE(para[i].character.getmute);
        }
    }

    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        ret = para[i].capture->control.Stop((AudioHandle)(para[i].capture));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyCapture(para[i].adapter, para[i].capture);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}
/**
* @tc.name  RelAudioCaptureGetMute
* @tc.number  SUB_Audio_HDI_RelAudioCaptureGetMute_0001
* @tc.desc  test RelAudioCaptureGetMute interface Reliability pass through pthread_create(adapterName is same)
* @tc.author: wangkang
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioCaptureGetMute_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelCaptureAdapterPara para = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_IN_MIC,
        .path = AUDIO_FILE.c_str()
    };
    struct RelCaptureAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    ret = RelAudioCaptureProcedure(para);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(RelCaptureAdapterPara), &para, sizeof(RelCaptureAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        arrpara[i].character.setmute = true;
        ret = arrpara[i].capture->volume.SetMute(arrpara[i].capture, false);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureGetMute, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_FALSE(arrpara[i].character.getmute);
    }
    ret = para.capture->control.Stop((AudioHandle)(para.capture));
    EXPECT_EQ(HDF_SUCCESS, ret);
    para.adapter->DestroyCapture(para.adapter, para.capture);
    para.manager->UnloadAdapter(para.manager, para.adapter);
}
/**
* @tc.name  AudioCaptureGetMute
* @tc.number  SUB_Audio_HDI_AudioCaptureGetMute_0002
* @tc.desc  test AudioCaptureGetMute interface Reliability pass through pthread_create(adapterName is different)
* @tc.author: wangkang
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioCaptureGetMute_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelCaptureAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_IN, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_IN, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }

    };

    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelAudioCaptureProcedure(para[i]);
        ASSERT_EQ(HDF_SUCCESS, ret);
        para[i].character.setmute = true;
        ret = para[i].capture->volume.SetMute(para[i].capture, false);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureGetMute, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
    }

    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_FALSE(para[i].character.getmute);
        ret = para[i].capture->control.Stop((AudioHandle)(para[i].capture));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyCapture(para[i].adapter, para[i].capture);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}
/**
* @tc.name  test AudioCaptureSetSampleAttributes API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_Reliability_0001
* @tc.desc  test AudioCaptureSetSampleAttributes interface Reliability pass through pthread_create fun and adapterName
            is same.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_Reliability_0001,
         TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t count = 2;
    struct RelCaptureAdapterPara para = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_IN_MIC,
        .path = AUDIO_FILE.c_str()
    };
    struct RelCaptureAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    ret = RelAudioCaptureProcedure(para);
    ASSERT_EQ(HDF_SUCCESS, ret);
    InitAttrs(para.attrs);
    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(RelCaptureAdapterPara), &para, sizeof(RelCaptureAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureSetSampleAttributes, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
        ret = arrpara[i].capture->attr.GetSampleAttributes(arrpara[i].capture, &(arrpara[i].attrsValue));
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(AUDIO_IN_MEDIA, arrpara[i].attrsValue.type);
        EXPECT_FALSE(arrpara[i].attrsValue.interleaved);
        EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, arrpara[i].attrsValue.format);
        EXPECT_EQ(SAMPLERATEVALUE, arrpara[i].attrsValue.sampleRate);
        EXPECT_EQ(count, arrpara[i].attrsValue.channelCount);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
    }
    ret = para.capture->control.Stop((AudioHandle)(para.capture));
    EXPECT_EQ(HDF_SUCCESS, ret);
    para.adapter->DestroyCapture(para.adapter, para.capture);
    para.manager->UnloadAdapter(para.manager, para.adapter);
}
/**
* @tc.name  test AudioCaptureSetSampleAttributes API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioCaptureSetSampleAttributes_Reliability_0002
* @tc.desc  test AudioCaptureSetSampleAttributes interface Reliability pass through pthread_create fun and adapterName
            is different.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioCaptureSetSampleAttributes_Reliability_0002,
         TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t count = 2;
    struct RelCaptureAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_IN, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_IN, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }
    };

    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelAudioCaptureProcedure(para[i]);
        if (ret < 0) {
            para[i].adapter->DestroyCapture(para[i].adapter, para[i].capture);
            para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
            ASSERT_EQ(HDF_SUCCESS, ret);
        }
        InitAttrs(para[i].attrs);
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureSetSampleAttributes, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
        ret = para[i].capture->attr.GetSampleAttributes(para[i].capture, &(para[i].attrsValue));
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(AUDIO_IN_MEDIA, para[i].attrsValue.type);
        EXPECT_FALSE(para[i].attrsValue.interleaved);
        EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, para[i].attrsValue.format);
        EXPECT_EQ(SAMPLERATEVALUE, para[i].attrsValue.sampleRate);
        EXPECT_EQ(count, para[i].attrsValue.channelCount);
    }

    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        ret = para[i].capture->control.Stop((AudioHandle)(para[i].capture));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyCapture(para[i].adapter, para[i].capture);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}
/**
* @tc.name  test AudioCaptureGetSampleAttributes API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioCaptureGetSampleAttributes_Reliability_0001
* @tc.desc  test AudioCaptureGetSampleAttributes interface Reliability pass through pthread_create fun and adapterName
            is same.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioCaptureGetSampleAttributes_Reliability_0001,
         TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t count = 2;
    struct RelCaptureAdapterPara para = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_IN_MIC,
        .path = AUDIO_FILE.c_str()
    };
    struct RelCaptureAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    ret = RelAudioCaptureProcedure(para);
    ASSERT_EQ(HDF_SUCCESS, ret);
    InitAttrs(para.attrs);
    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(RelCaptureAdapterPara), &para, sizeof(RelCaptureAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = arrpara[i].capture->attr.SetSampleAttributes(arrpara[i].capture, &(arrpara[i].attrs));
        EXPECT_EQ(HDF_SUCCESS, ret);

        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureGetSampleAttributes, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
        EXPECT_EQ(AUDIO_IN_MEDIA, arrpara[i].attrsValue.type);
        EXPECT_FALSE(arrpara[i].attrsValue.interleaved);
        EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, arrpara[i].attrsValue.format);
        EXPECT_EQ(SAMPLERATEVALUE, arrpara[i].attrsValue.sampleRate);
        EXPECT_EQ(count, arrpara[i].attrsValue.channelCount);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
    }
    ret = para.capture->control.Stop((AudioHandle)(para.capture));
    EXPECT_EQ(HDF_SUCCESS, ret);
    para.adapter->DestroyCapture(para.adapter, para.capture);
    para.manager->UnloadAdapter(para.manager, para.adapter);
}
/**
* @tc.name  test AudioCaptureGetSampleAttributes API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioCaptureGetSampleAttributes_Reliability_0002
* @tc.desc  test AudioCaptureGetSampleAttributes interface Reliability pass through pthread_create fun and adapterName
            is different.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioCaptureGetSampleAttributes_Reliability_0002,
         TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t count = 2;
    struct RelCaptureAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_IN, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_IN, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }
    };

    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelAudioCaptureProcedure(para[i]);
        ASSERT_EQ(HDF_SUCCESS, ret);
        InitAttrs(para[i].attrs);
        ret = para[i].capture->attr.SetSampleAttributes(para[i].capture, &(para[i].attrs));
        EXPECT_EQ(HDF_SUCCESS, ret);

        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureGetSampleAttributes, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
        EXPECT_EQ(AUDIO_IN_MEDIA, para[i].attrsValue.type);
        EXPECT_FALSE(para[i].attrsValue.interleaved);
        EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, para[i].attrsValue.format);
        EXPECT_EQ(SAMPLERATEVALUE, para[i].attrsValue.sampleRate);
        EXPECT_EQ(count, para[i].attrsValue.channelCount);
    }

    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        ret = para[i].capture->control.Stop((AudioHandle)(para[i].capture));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyCapture(para[i].adapter, para[i].capture);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}

/**
* @tc.name  test AudioCaptureSelectScene API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioCaptureSelectScene_Reliability_0001
* @tc.desc  test AudioCaptureSelectScene interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioCaptureSelectScene_Reliability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelCaptureAdapterPara para = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_IN_MIC,
        .path = AUDIO_FILE.c_str()
    };
    struct RelCaptureAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    ret = RelAudioCaptureProcedure(para);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(RelCaptureAdapterPara), &para, sizeof(RelCaptureAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        arrpara[i].scenes.scene.id = 0;
        arrpara[i].scenes.desc.pins = PIN_IN_MIC;
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureSelectScene, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
    }
    ret = para.capture->control.Stop((AudioHandle)(para.capture));
    EXPECT_EQ(HDF_SUCCESS, ret);
    para.adapter->DestroyCapture(para.adapter, para.capture);
    para.manager->UnloadAdapter(para.manager, para.adapter);
}

/**
* @tc.name  test AudioCaptureSelectScene API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioCaptureSelectScene_Reliability_0002
* @tc.desc  test AudioCaptureSelectScene interface Reliability pass through pthread_create fun and adapterName
            is different.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioCaptureSelectScene_Reliability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelCaptureAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_IN, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_IN, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }
    };

    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelAudioCaptureProcedure(para[i]);
        ASSERT_EQ(HDF_SUCCESS, ret);
        para[i].scenes.scene.id = 0;
        para[i].scenes.desc.pins = PIN_IN_MIC;
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureSelectScene, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        ret = para[i].capture->control.Stop((AudioHandle)(para[i].capture));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyCapture(para[i].adapter, para[i].capture);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}
/**
* @tc.name  test AudioCaptureCheckSceneCapability API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioCaptureCheckSceneCapability_Reliability_0001
* @tc.desc  test AudioCaptureCheckSceneCapability interface Reliability pass through pthread_create fun and adapterName
            is same.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioCaptureCheckSceneCapability_Reliability_0001,
         TestSize.Level1)
{
    int32_t ret = -1;
    struct RelCaptureAdapterPara para = {
        .portType = PORT_IN, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_IN_MIC,
        .path = AUDIO_FILE.c_str()
    };
    struct RelCaptureAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    ret = RelAudioCaptureProcedure(para);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(RelCaptureAdapterPara), &para, sizeof(RelCaptureAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        arrpara[i].scenes.scene.id = 0;
        arrpara[i].scenes.desc.pins = PIN_IN_MIC;
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureCheckSceneCapability, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
    }
    ret = para.capture->control.Stop((AudioHandle)(para.capture));
    EXPECT_EQ(HDF_SUCCESS, ret);
    para.adapter->DestroyCapture(para.adapter, para.capture);
    para.manager->UnloadAdapter(para.manager, para.adapter);
}

/**
* @tc.name  test AudioCaptureCheckSceneCapability API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioCaptureCheckSceneCapability_Reliability_0002
* @tc.desc  test AudioCaptureCheckSceneCapability interface Reliability pass through pthread_create fun and adapterName
            is different.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioCaptureCheckSceneCapability_Reliability_0002,
         TestSize.Level1)
{
    int32_t ret = -1;
    struct RelCaptureAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_IN, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_IN, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }
    };

    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelAudioCaptureProcedure(para[i]);
        ASSERT_EQ(HDF_SUCCESS, ret);
        para[i].scenes.scene.id = 0;
        para[i].scenes.desc.pins = PIN_IN_MIC;
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureCheckSceneCapability, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        ret = para[i].capture->control.Stop((AudioHandle)(para[i].capture));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyCapture(para[i].adapter, para[i].capture);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}
}