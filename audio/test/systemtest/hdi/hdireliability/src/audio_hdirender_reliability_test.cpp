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
#include "audio_hdirender_reliability_test.h"

using namespace std;
using namespace testing::ext;
using namespace HMOS::Audio;

namespace {
const string AUDIO_FILE = "//bin/audiorendertest.wav";
const string ADAPTER_NAME = "hdmi";
const string ADAPTER_NAME2 = "usb";
const string ADAPTER_NAME3 = "internal";
const int PTHREAD_SAMEADA_COUNT = 10;
const int PTHREAD_DIFFADA_COUNT = 3;

class AudioHdiRenderReliabilityTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    struct AudioManager *(*GetAudioManager)() = nullptr;
    void *handleSo = nullptr;
    static int32_t RelGetAllAdapter(struct RelRenderAdapterPara& ptr);
    static int32_t RelLoadAdapter(struct RelRenderAdapterPara& ptr);
    static int32_t RelUnloadAdapter(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioCreateRender(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioDestroyRender(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderStartAndFrame(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderProcedure(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderSetGain(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderGetGain(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderGetGainThreshold(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderSetMute(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderGetMute(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderSetVolume(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderGetVolume(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderGetFrameSize(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderGetFrameCount(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderGetCurrentChannelId(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderSetChannelMode(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderGetChannelMode(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderSetSampleAttributes(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderGetSampleAttributes(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderSelectScene(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderCheckSceneCapability(struct RelRenderAdapterPara& ptr);
};

using THREAD_FUNC = void *(*)(void *);

void AudioHdiRenderReliabilityTest::SetUpTestCase(void) {}

void AudioHdiRenderReliabilityTest::TearDownTestCase(void) {}

void AudioHdiRenderReliabilityTest::SetUp(void)
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

void AudioHdiRenderReliabilityTest::TearDown(void)
{
    if (GetAudioManager != nullptr) {
        GetAudioManager = nullptr;
    }
}

struct RenderCharacteristic {
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
    enum AudioChannelMode setmode;
    enum AudioChannelMode getmode;
    bool supported;
};

struct RelRenderAdapterPara {
    struct AudioManager *manager;
    enum AudioPortDirection portType;
    const char *adapterName;
    struct AudioAdapter *adapter;
    struct AudioPort renderPort;
    void *param;
    enum AudioPortPin pins;
    const char *path;
    struct AudioRender *render;
    struct AudioHeadInfo headInfo;
    struct AudioAdapterDescriptor *desc;
    struct AudioAdapterDescriptor *descs;
    struct RenderCharacteristic character;
    struct AudioSampleAttributes attrs;
    struct AudioSampleAttributes attrsValue;
    struct AudioSceneDescriptor scenes;
};

int32_t AudioHdiRenderReliabilityTest::RelGetAllAdapter(struct RelRenderAdapterPara& ptr)
{
    int size = 0;
    auto *inst = (AudioHdiRenderReliabilityTest *)ptr.param;
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
        int index = SwitchAdapter(ptr.descs, ptr.adapterName, ptr.portType, ptr.renderPort, size);
        if (index < 0) {
            return HDF_FAILURE;
        } else {
            ptr.desc = &ptr.descs[index];
        }
    }
    if (ptr.desc == nullptr) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiRenderReliabilityTest::RelLoadAdapter(struct RelRenderAdapterPara& ptr)
{
    ptr.manager->LoadAdapter(ptr.manager, ptr.desc, &ptr.adapter);

    if (ptr.adapter == nullptr) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioCreateRender(struct RelRenderAdapterPara& ptr)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    if (ptr.adapter == nullptr  || ptr.manager == nullptr) {
        return HDF_FAILURE;
    }
    InitAttrs(attrs);
    InitDevDesc(devDesc, (&ptr.renderPort)->portId, ptr.pins);
    ret = ptr.adapter->CreateRender(ptr.adapter, &devDesc, &attrs, &ptr.render);
    if (ret < 0 || ptr.render == nullptr) {
        ptr.manager->UnloadAdapter(ptr.manager, ptr.adapter);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioDestroyRender(struct RelRenderAdapterPara& ptr)
{
    int32_t ret = -1;
    if (ptr.adapter == nullptr  || ptr.render == nullptr) {
        return HDF_FAILURE;
    }
    ret = ptr.adapter->DestroyRender(ptr.adapter, ptr.render);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderStartAndFrame(struct RelRenderAdapterPara& ptr)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    char absPath[PATH_MAX] = {0};
    if (realpath(ptr.path, absPath) == nullptr) {
        return HDF_FAILURE;
    }
    FILE *file = fopen(absPath, "rb");
    if (file == nullptr) {
        return HDF_FAILURE;
    }
    ret = InitAttrs(attrs);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    if (HMOS::Audio::WavHeadAnalysis(ptr.headInfo, file, attrs) < 0) {
        return HDF_FAILURE;
    } else {
        ret = HMOS::Audio::FrameStart(ptr.headInfo, ptr.render, file, attrs);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    if (ret == 0) {
        fclose(file);
    } else {
        fclose(file);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderGetGainThreshold(struct RelRenderAdapterPara& ptr)
{
    int32_t ret = -1;

    ret = ptr.render->volume.GetGainThreshold(ptr.render, &(ptr.character.gainthresholdmin),
                                              &(ptr.character.gainthresholdmax));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderSetGain(struct RelRenderAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.render->volume.SetGain(ptr.render, ptr.character.setgain);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderGetGain(struct RelRenderAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.render->volume.GetGain(ptr.render, &(ptr.character.getgain));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderProcedure(struct RelRenderAdapterPara& ptr)
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

    ret = RelAudioCreateRender(ptr);
    if (ret < 0) {
        return HDF_FAILURE;
    }

    ret = RelAudioRenderStartAndFrame(ptr);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderSetMute(struct RelRenderAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.render->volume.SetMute(ptr.render, ptr.character.setmute);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderGetMute(struct RelRenderAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.render->volume.GetMute(ptr.render, &(ptr.character.getmute));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderSetVolume(struct RelRenderAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.render->volume.SetVolume(ptr.render, ptr.character.setvolume);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderGetVolume(struct RelRenderAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.render->volume.GetVolume(ptr.render, &(ptr.character.getvolume));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderGetFrameSize(struct RelRenderAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.render->attr.GetFrameSize(ptr.render, &(ptr.character.getframesize));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderGetFrameCount(struct RelRenderAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.render->attr.GetFrameCount(ptr.render, &(ptr.character.getframecount));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderGetCurrentChannelId(struct RelRenderAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.render->attr.GetCurrentChannelId(ptr.render, &(ptr.character.getcurrentchannelId));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderSetSampleAttributes(struct RelRenderAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.render->attr.SetSampleAttributes(ptr.render, &(ptr.attrs));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderGetSampleAttributes(struct RelRenderAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.render->attr.GetSampleAttributes(ptr.render, &(ptr.attrsValue));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderSelectScene(struct RelRenderAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.render->scene.SelectScene(ptr.render, &(ptr.scenes));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiRenderReliabilityTest::RelAudioRenderCheckSceneCapability(struct RelRenderAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.render->scene.CheckSceneCapability(ptr.render, &ptr.scenes, &(ptr.character.supported));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/**
* @tc.name  test AudioCreateRender API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioCreateRender_Reliability_0001
* @tc.desc  test CreateRender interface Reliability pass through pthread_create fun and adapterName is different.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudioCreateRender_Reliability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelRenderAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }
    };
    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelGetAllAdapter(para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = RelLoadAdapter(para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCreateRender, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        ret = (intptr_t)result;
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyRender(para[i].adapter, para[i].render);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}

/**
* @tc.name  test AudioDestroyRender API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioDestroyRender_Reliability_0002
* @tc.desc  test DestroyRender interface Reliability pass through pthread_create fun and adapterName is different.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudioDestroyRender_Reliability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelRenderAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }
    };
    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelGetAllAdapter(para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = RelLoadAdapter(para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = RelAudioCreateRender(para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioDestroyRender, &para[i]);
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
* @tc.name  test AudioRenderGetFrameSize API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudiorenderGetVolume_Reliability_0001
* @tc.desc  test GetFrameSize interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudioRenderGetFrameSize_Reliability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelRenderAdapterPara para = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };
    struct RelRenderAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    ret = RelAudioRenderProcedure(para);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(RelRenderAdapterPara), &para, sizeof(RelRenderAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderGetFrameSize, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_LT(INITIAL_VALUE, arrpara[i].character.getframesize);
    }
    ret = para.render->control.Stop((AudioHandle)(para.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    para.adapter->DestroyRender(para.adapter, para.render);
    para.manager->UnloadAdapter(para.manager, para.adapter);
}

/**
* @tc.name  test AudioRenderGetFrameSize API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioRenderGetFrameSize_Reliability_0002
* @tc.desc  test GetFrameSize interface Reliability pass through pthread_create fun and adapterName is different.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudioRenderGetFrameSize_Reliability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelRenderAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }
    };
    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelAudioRenderProcedure(para[i]);
        ASSERT_EQ(HDF_SUCCESS, ret);
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderGetFrameSize, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_LT(INITIAL_VALUE, para[i].character.getframesize);

        ret = para[i].render->control.Stop((AudioHandle)(para[i].render));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyRender(para[i].adapter, para[i].render);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}

/**
* @tc.name  test AudioRenderGetFrameCount API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudiorenderGetVolume_Reliability_0001
* @tc.desc  test GetFrameCount interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudioRenderGetFrameCount_Reliability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelRenderAdapterPara para = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };
    struct RelRenderAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    ret = RelAudioRenderProcedure(para);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(RelRenderAdapterPara), &para, sizeof(RelRenderAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderGetFrameCount, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_LT(INITIAL_VALUE, arrpara[i].character.getframecount);
    }
    ret = para.render->control.Stop((AudioHandle)(para.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    para.adapter->DestroyRender(para.adapter, para.render);
    para.manager->UnloadAdapter(para.manager, para.adapter);
}

/**
* @tc.name  test AudioRenderGetFrameCount API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioRenderGetFrameCount_Reliability_0002
* @tc.desc  test GetFrameCount interface Reliability pass through pthread_create fun and adapterName is different.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudioRenderGetFrameCount_Reliability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelRenderAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }
    };
    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelAudioRenderProcedure(para[i]);
        ASSERT_EQ(HDF_SUCCESS, ret);
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderGetFrameCount, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_LT(INITIAL_VALUE, para[i].character.getframecount);

        ret = para[i].render->control.Stop((AudioHandle)(para[i].render));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyRender(para[i].adapter, para[i].render);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}

/**
* @tc.name  test AudioRenderGetVolume API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudiorenderGetVolume_Reliability_0001
* @tc.desc  test GetCurrentChannelId interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudioRenderGetCurrentChannelId_Reliability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t channelIdValue = 2;
    struct RelRenderAdapterPara para = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };
    struct RelRenderAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    ret = RelAudioRenderProcedure(para);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(RelRenderAdapterPara), &para, sizeof(RelRenderAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        arrpara[i].character.getcurrentchannelId = 0;
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderGetCurrentChannelId, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_EQ(channelIdValue, arrpara[i].character.getcurrentchannelId);
    }
    ret = para.render->control.Stop((AudioHandle)(para.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    para.adapter->DestroyRender(para.adapter, para.render);
    para.manager->UnloadAdapter(para.manager, para.adapter);
}

/**
* @tc.name  test AudioRenderGetCurrentChannelId API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioRenderGetCurrentChannelId_Reliability_0002
* @tc.desc test GetCurrentChannelId interface Reliability pass through pthread_create fun and adapterName is different
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudioRenderGetCurrentChannelId_Reliability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t channelIdValue = 2;
    struct RelRenderAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }
    };
    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelAudioRenderProcedure(para[i]);
        ASSERT_EQ(HDF_SUCCESS, ret);
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderGetCurrentChannelId, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_EQ(channelIdValue, para[i].character.getcurrentchannelId);

        ret = para[i].render->control.Stop((AudioHandle)(para[i].render));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyRender(para[i].adapter, para[i].render);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}

/**
* @tc.name  test AudioRenderSetMute API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudiorenderSetMute_Reliability_0001
* @tc.desc  test AudioRenderSetMute interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudiorenderSetMute_Reliability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelRenderAdapterPara para = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };
    struct RelRenderAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    ret = RelAudioRenderProcedure(para);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(RelRenderAdapterPara), &para, sizeof(RelRenderAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = arrpara[i].render->volume.GetMute(arrpara[i].render, &(arrpara[i].character.getmute));
        EXPECT_EQ(HDF_SUCCESS, ret);
        if (arrpara[i].character.getmute == false) {
            arrpara[i].character.setmute = true;
        } else {
            arrpara[i].character.setmute = false;
        }
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderSetMute, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
        ret = arrpara[i].render->volume.GetMute(arrpara[i].render, &(arrpara[i].character.getmute));
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
    ret = para.render->control.Stop((AudioHandle)(para.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    para.adapter->DestroyRender(para.adapter, para.render);
    para.manager->UnloadAdapter(para.manager, para.adapter);
}

/**
* @tc.name  test AudioRenderSetMute API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudiorenderSetMute_Reliability_0002
* @tc.desc  test AudioRenderSetMute interface Reliability pass through pthread_create fun and adapterName is different.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudiorenderSetMute_Reliability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelRenderAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }
    };
    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelAudioRenderProcedure(para[i]);
        ASSERT_EQ(HDF_SUCCESS, ret);
        ret = para[i].render->volume.GetMute(para[i].render, &(para[i].character.getmute));
        EXPECT_EQ(HDF_SUCCESS, ret);
        if (para[i].character.getmute == false) {
            para[i].character.setmute = true;
        } else {
            para[i].character.setmute = false;
        }
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderSetMute, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
        ret = para[i].render->volume.GetMute(para[i].render, &(para[i].character.getmute));
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
        ret = para[i].render->control.Stop((AudioHandle)(para[i].render));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyRender(para[i].adapter, para[i].render);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}

/**
* @tc.name  test AudioRenderGetMute API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudiorenderGetMute_Reliability_0001
* @tc.desc  test AudioRenderGetMute interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudiorenderGetMute_Reliability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelRenderAdapterPara para = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };
    struct RelRenderAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    ret = RelAudioRenderProcedure(para);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(RelRenderAdapterPara), &para, sizeof(RelRenderAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        arrpara[i].character.setmute = true;
        ret = arrpara[i].render->volume.SetMute(arrpara[i].render, false);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderGetMute, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_FALSE(arrpara[i].character.getmute);
    }
    ret = para.render->control.Stop((AudioHandle)(para.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    para.adapter->DestroyRender(para.adapter, para.render);
    para.manager->UnloadAdapter(para.manager, para.adapter);
}

/**
* @tc.name  test AudioRenderGetMute API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudiorenderGetMute_Reliability_0002
* @tc.desc  test AudioRenderGetMute interface Reliability pass through pthread_create fun and adapterName is different.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudiorenderGetMute_Reliability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelRenderAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }
    };

    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelAudioRenderProcedure(para[i]);
        ASSERT_EQ(HDF_SUCCESS, ret);
        para[i].character.setmute = true;
        ret = para[i].render->volume.SetMute(para[i].render, false);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderGetMute, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
    }

    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_FALSE(para[i].character.getmute);
        ret = para[i].render->control.Stop((AudioHandle)(para[i].render));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyRender(para[i].adapter, para[i].render);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}
/**
* @tc.name  test AudioRenderSetVolume API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudiorenderSetVolume_Reliability_0001
* @tc.desc  test AudioRenderSetVolume interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudiorenderSetVolume_Reliability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    float volumeHighExpc = 0.70;
    struct RelRenderAdapterPara para = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };
    struct RelRenderAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    ret = RelAudioRenderProcedure(para);
    ASSERT_EQ(HDF_SUCCESS, ret);
    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(RelRenderAdapterPara), &para, sizeof(RelRenderAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = arrpara[i].render->volume.GetVolume(arrpara[i].render, &(arrpara[i].character.getvolume));
        EXPECT_EQ(HDF_SUCCESS, ret);
        arrpara[i].character.setvolume = 0.70;
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderSetVolume, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        ret = arrpara[i].render->volume.GetVolume(arrpara[i].render, &(arrpara[i].character.getvolume));
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(volumeHighExpc, arrpara[i].character.getvolume);
    }
    ret = para.render->control.Stop((AudioHandle)(para.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    para.adapter->DestroyRender(para.adapter, para.render);
    para.manager->UnloadAdapter(para.manager, para.adapter);
}

/**
* @tc.name  test AudioRenderSetVolume API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudiorenderSetVolume_Reliability_0002
* @tc.desc  test RenderSetVolume interface Reliability pass through pthread_create fun and adapterName is different
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudiorenderSetVolume_Reliability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    float volumeHighExpc = 0.6;
    struct RelRenderAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }
    };
    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelAudioRenderProcedure(para[i]);
        ASSERT_EQ(HDF_SUCCESS, ret);
        para[i].character.setvolume = 0.6;
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderSetVolume, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
    }
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        ret = para[i].render->volume.GetVolume(para[i].render, &(para[i].character.getvolume));
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(volumeHighExpc, para[i].character.getvolume);
        ret = para[i].render->control.Stop((AudioHandle)(para[i].render));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyRender(para[i].adapter, para[i].render);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}

/**
* @tc.name  test AudioRenderGetVolume API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudiorenderGetVolume_Reliability_0001
* @tc.desc  test AudioRenderGetMute interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudiorenderGetVolume_Reliability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    float volumeHighExpc = 0.7;
    struct RelRenderAdapterPara para = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };
    struct RelRenderAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    ret = RelAudioRenderProcedure(para);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(RelRenderAdapterPara), &para, sizeof(RelRenderAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        arrpara[i].character.setvolume = 0.7;
        ret = arrpara[i].render->volume.SetVolume(arrpara[i].render, arrpara[i].character.setvolume);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderGetVolume, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_EQ(volumeHighExpc, arrpara[i].character.getvolume);
    }
    ret = para.render->control.Stop((AudioHandle)(para.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    para.adapter->DestroyRender(para.adapter, para.render);
    para.manager->UnloadAdapter(para.manager, para.adapter);
}

/**
* @tc.name  test AudioRenderGetVolume API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudiorenderGetVolume_Reliability_0002
* @tc.desc  test AudioRenderGetMute interface Reliability pass through pthread_create fun and adapterName is different.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudiorenderGetVolume_Reliability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    float volumeHighExpc = 0.6;
    struct RelRenderAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }
    };

    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelAudioRenderProcedure(para[i]);
        ASSERT_EQ(HDF_SUCCESS, ret);
        para[i].character.setvolume = 0.6;
        ret = para[i].render->volume.SetVolume(para[i].render, para[i].character.setvolume);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderGetVolume, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
    }
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_EQ(volumeHighExpc, para[i].character.getvolume);
        ret = para[i].render->control.Stop((AudioHandle)(para[i].render));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyRender(para[i].adapter, para[i].render);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}

/**
* @tc.name  test AudioRenderSetSampleAttributes API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_Reliability_0001
* @tc.desc  test AudioRenderSetSampleAttributes interface Reliability pass through pthread_create fun and adapterName
            is same.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_Reliability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t count = 2;
    uint32_t rateExpc = 48000;
    struct RelRenderAdapterPara para = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };
    struct RelRenderAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    ret = RelAudioRenderProcedure(para);
    ASSERT_EQ(HDF_SUCCESS, ret);
    InitAttrs(para.attrs);
    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(RelRenderAdapterPara), &para, sizeof(RelRenderAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderSetSampleAttributes, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
        ret = arrpara[i].render->attr.GetSampleAttributes(arrpara[i].render, &(arrpara[i].attrsValue));
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(AUDIO_IN_MEDIA, arrpara[i].attrsValue.type);
        EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, arrpara[i].attrsValue.format);
        EXPECT_EQ(rateExpc, arrpara[i].attrsValue.sampleRate);
        EXPECT_EQ(count, arrpara[i].attrsValue.channelCount);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
    }
    ret = para.render->control.Stop((AudioHandle)(para.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    para.adapter->DestroyRender(para.adapter, para.render);
    para.manager->UnloadAdapter(para.manager, para.adapter);
}

/**
* @tc.name  test AudioRenderSetSampleAttributes API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioRenderSetSampleAttributes_Reliability_0002
* @tc.desc  test AudioRenderSetSampleAttributes interface Reliability pass through pthread_create fun and adapterName
            is different.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudioRenderSetSampleAttributes_Reliability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t count = 2;
    uint32_t rateExpc = 48000;
    struct RelRenderAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }
    };

    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelAudioRenderProcedure(para[i]);
        ASSERT_EQ(HDF_SUCCESS, ret);
        InitAttrs(para[i].attrs);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderSetSampleAttributes, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
        ret = para[i].render->attr.GetSampleAttributes(para[i].render, &(para[i].attrsValue));
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(AUDIO_IN_MEDIA, para[i].attrsValue.type);
        EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, para[i].attrsValue.format);
        EXPECT_EQ(rateExpc, para[i].attrsValue.sampleRate);
        EXPECT_EQ(count, para[i].attrsValue.channelCount);
    }

    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        ret = para[i].render->control.Stop((AudioHandle)(para[i].render));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyRender(para[i].adapter, para[i].render);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}

/**
* @tc.name  test AudioRenderGetSampleAttributes API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioRenderGetSampleAttributes_Reliability_0001
* @tc.desc  test AudioRenderGetSampleAttributes interface Reliability pass through pthread_create fun and adapterName
            is same.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudioRenderGetSampleAttributes_Reliability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t count = 2;
    uint32_t rateExpc = 48000;
    struct RelRenderAdapterPara para = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };
    struct RelRenderAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    ret = RelAudioRenderProcedure(para);
    ASSERT_EQ(HDF_SUCCESS, ret);
    InitAttrs(para.attrs);
    ret = para.render->attr.SetSampleAttributes(para.render, &(para.attrs));
    EXPECT_EQ(HDF_SUCCESS, ret);
    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(RelRenderAdapterPara), &para, sizeof(RelRenderAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderGetSampleAttributes, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_EQ(AUDIO_IN_MEDIA, arrpara[i].attrsValue.type);
        EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, arrpara[i].attrsValue.format);
        EXPECT_EQ(rateExpc, arrpara[i].attrsValue.sampleRate);
        EXPECT_EQ(count, arrpara[i].attrsValue.channelCount);
    }
    ret = para.render->control.Stop((AudioHandle)(para.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    para.adapter->DestroyRender(para.adapter, para.render);
    para.manager->UnloadAdapter(para.manager, para.adapter);
}

/**
* @tc.name  test AudioRenderGetSampleAttributes API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioRenderGetSampleAttributes_Reliability_0002
* @tc.desc  test AudioRenderGetSampleAttributes interface Reliability pass through pthread_create fun and adapterName
            is different.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudioRenderGetSampleAttributes_Reliability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t count = 2;
    uint32_t rateExpc = 48000;
    struct RelRenderAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }
    };

    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelAudioRenderProcedure(para[i]);
        ASSERT_EQ(HDF_SUCCESS, ret);
        InitAttrs(para[i].attrs);
        ret = para[i].render->attr.SetSampleAttributes(para[i].render, &(para[i].attrs));
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderGetSampleAttributes, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
    }

    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_EQ(AUDIO_IN_MEDIA, para[i].attrsValue.type);
        EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, para[i].attrsValue.format);
        EXPECT_EQ(rateExpc, para[i].attrsValue.sampleRate);
        EXPECT_EQ(count, para[i].attrsValue.channelCount);
        ret = para[i].render->control.Stop((AudioHandle)(para[i].render));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyRender(para[i].adapter, para[i].render);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}

/**
* @tc.name  test AudioRenderSelectScene API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioRenderSelectScene_Reliability_0001
* @tc.desc  test AudioRenderSelectScene interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudioRenderSelectScene_Reliability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelRenderAdapterPara para = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };
    struct RelRenderAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    ret = RelAudioRenderProcedure(para);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(RelRenderAdapterPara), &para, sizeof(RelRenderAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        arrpara[i].scenes.scene.id = 0;
        arrpara[i].scenes.desc.pins = PIN_OUT_SPEAKER;
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderSelectScene, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
    }
    ret = para.render->control.Stop((AudioHandle)(para.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    para.adapter->DestroyRender(para.adapter, para.render);
    para.manager->UnloadAdapter(para.manager, para.adapter);
}

/**
* @tc.name  test AudioRenderSelectScene API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioRenderSelectScene_Reliability_0002
* @tc.desc  test AudioRenderSelectScene interface Reliability pass through pthread_create fun and adapterName
            is different.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudioRenderSelectScene_Reliability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelRenderAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }
    };

    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT - 1; ++i) {
        ret = RelAudioRenderProcedure(para[i]);
        ASSERT_EQ(HDF_SUCCESS, ret);
        para[i].scenes.scene.id = 0;
        para[i].scenes.desc.pins = PIN_OUT_SPEAKER;
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderSelectScene, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
    }

    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT - 1; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        ret = para[i].render->control.Stop((AudioHandle)(para[i].render));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyRender(para[i].adapter, para[i].render);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}

/**
* @tc.name  test AudioRenderCheckSceneCapability API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioRenderCheckSceneCapability_Reliability_0001
* @tc.desc  test AudioRenderCheckSceneCapability interface Reliability pass through pthread_create fun and adapterName
            is same.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudioRenderCheckSceneCapability_Reliability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelRenderAdapterPara para = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };
    struct RelRenderAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    ret = RelAudioRenderProcedure(para);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(RelRenderAdapterPara), &para, sizeof(RelRenderAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        arrpara[i].scenes.scene.id = 0;
        arrpara[i].scenes.desc.pins = PIN_OUT_SPEAKER;
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderCheckSceneCapability, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
    }
    ret = para.render->control.Stop((AudioHandle)(para.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    para.adapter->DestroyRender(para.adapter, para.render);
    para.manager->UnloadAdapter(para.manager, para.adapter);
}

/**
* @tc.name  test AudioRenderCheckSceneCapability API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioRenderCheckSceneCapability_Reliability_0002
* @tc.desc  test AudioRenderCheckSceneCapability interface Reliability pass through pthread_create fun and adapterName
            is different.
* @tc.author: ZHANGHAILIN
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudioRenderCheckSceneCapability_Reliability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelRenderAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()
        }
    };

    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelAudioRenderProcedure(para[i]);
        ASSERT_EQ(HDF_SUCCESS, ret);
        para[i].scenes.scene.id = 0;
        para[i].scenes.desc.pins = PIN_OUT_SPEAKER;
        ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderCheckSceneCapability, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(50000);
    }

    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        ret = para[i].render->control.Stop((AudioHandle)(para[i].render));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyRender(para[i].adapter, para[i].render);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}
}