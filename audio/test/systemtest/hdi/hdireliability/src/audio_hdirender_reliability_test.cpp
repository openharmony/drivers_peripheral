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
const string AUDIO_FILE_LOG = "//bin/14031.wav";
const string AUDIO_FILE_ERR = "//bin/test.txt";
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
    static int32_t RelAudioRenderStart(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderFrame(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderStop(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderStartAndFrame(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderProcedure(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderPause(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderResume(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderSetGain(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderGetGain(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderGetGainThreshold(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderSetMute(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderGetMute(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderSetVolume(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderGetVolume(struct RelRenderAdapterPara& ptr);
    static int32_t RelAudioRenderGetFrameSize(struct RelRenderAdapterPara &ptr);
    static int32_t RelAudioRenderGetFrameCount(struct RelRenderAdapterPara &ptr);
    static int32_t RelAudioRenderGetCurrentChannelId(struct RelRenderAdapterPara &ptr);
    static int32_t RelAudioRenderGetRenderPosition(struct RelRenderAdapterPara &ptr);
    static int32_t RelAudioRenderSetChannelMode(struct RelRenderAdapterPara &ptr);
    static int32_t RelAudioRenderGetChannelMode(struct RelRenderAdapterPara &ptr);
};

using THREAD_FUNC = void *(*)(void *);

void AudioHdiRenderReliabilityTest::SetUpTestCase(void) {}

void AudioHdiRenderReliabilityTest::TearDownTestCase(void) {}

void AudioHdiRenderReliabilityTest::SetUp(void)
{
    char resolvedPath[] = "//system/lib/libhdi_audio.z.so";
    handleSo = dlopen(resolvedPath, RTLD_LAZY);
    if (handleSo == nullptr) {
        return;
    }
    GetAudioManager = (struct AudioManager* (*)())(dlsym(handleSo, "GetAudioManagerFuncs"));
    if (GetAudioManager == nullptr) {
        return;
    }
}

void AudioHdiRenderReliabilityTest::TearDown(void)
{
    // step 2: input testsuit teardown step
    if (handleSo != nullptr) {
        dlclose(handleSo);
        handleSo = nullptr;
    }
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
    uint64_t getframes;
    uint32_t getcurrentchannelId;
    enum AudioChannelMode setmode;
    enum AudioChannelMode getmode;
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
    struct AudioTimeStamp time = {.tvNSec = 1};
};

/**
 * @brief Obtains the list of all adapters supported by an audio driver and Switch appropriate Adapter.
 *
 * @param struct RelRenderAdapterPara
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise
 */
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
        int index = HMOS::Audio::SwitchAdapter(ptr.descs, ptr.adapterName, ptr.portType, ptr.renderPort, size);
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

/**
 * @brief Loads the driver for an audio adapter which is GetAllAdapters Switch appropriate Adapter.
 *
 * @param struct RelRenderAdapterPara
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise.
 */
int32_t AudioHdiRenderReliabilityTest::RelLoadAdapter(struct RelRenderAdapterPara& ptr)
{
    ptr.manager->LoadAdapter(ptr.manager, ptr.desc, &ptr.adapter);

    if (ptr.adapter == nullptr) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/**
 * @brief Creates an <b>AudioRender</b> object.
 *
 * @param struct RelRenderAdapterPara
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise.
 */
int32_t AudioHdiRenderReliabilityTest::RelAudioCreateRender(struct RelRenderAdapterPara& ptr)
{
    int32_t ret = -1;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    if (ptr.adapter == nullptr  || ptr.manager == nullptr) {
        return HDF_FAILURE;
    }
    ret = HMOS::Audio::InitAttrs(attrs);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    ret = HMOS::Audio::InitDevDesc(devDesc, (&ptr.renderPort)->portId, ptr.pins);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    ret = ptr.adapter->CreateRender(ptr.adapter, &devDesc, &attrs, &ptr.render);
    if (ret < 0 || ptr.render == nullptr) {
        ptr.manager->UnloadAdapter(ptr.manager, ptr.adapter);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/**
 * @brief Destroy an <b>AudioRender</b> object.
 *
 * @param struct RelRenderAdapterPara
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise.
 */
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


/**
 * @brief Starts audio rendering.
 *
 * @param struct RelRenderAdapterPara
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise.
 */
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

/**
 * @brief Stops audio rendering.
 *
 * @param struct RelRenderAdapterPara
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise.
 */
int32_t AudioHdiRenderReliabilityTest::RelAudioRenderStart(struct RelRenderAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.render->control.Start((AudioHandle)(ptr.render));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/**
 * @brief  audio send Frame.
 *
 * @param struct RelRenderAdapterPara
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise.
 */
int32_t AudioHdiRenderReliabilityTest::RelAudioRenderFrame(struct RelRenderAdapterPara& ptr)
{
    int32_t ret = -1;
    uint64_t requestBytes = 0;
    uint64_t replyBytes = 0;
    char *frame = nullptr;

    ret = HMOS::Audio::RenderFramePrepare(ptr.path, frame, requestBytes);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    ret = ptr.render->RenderFrame(ptr.render, frame, requestBytes, &replyBytes);
    if (ret < 0) {
        if (frame != nullptr) {
            free(frame);
            frame = nullptr;
        }
        return HDF_FAILURE;
    }
    if (frame != nullptr) {
        free(frame);
        frame = nullptr;
    }
    return HDF_SUCCESS;
}

/**
 * @brief Stops audio rendering.
 *
 * @param struct RelRenderAdapterPara
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise.
 */
int32_t AudioHdiRenderReliabilityTest::RelAudioRenderStop(struct RelRenderAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.render->control.Stop((AudioHandle)(ptr.render));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/**
 * @brief Pause audio rendering.
 *
 * @param struct RelRenderAdapterPara
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise.
 */
int32_t AudioHdiRenderReliabilityTest::RelAudioRenderPause(struct RelRenderAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.render->control.Pause((AudioHandle)(ptr.render));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/**
 * @brief Resume audio rendering.
 *
 * @param struct RelRenderAdapterPara
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise.
 */
int32_t AudioHdiRenderReliabilityTest::RelAudioRenderResume(struct RelRenderAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.render->control.Resume((AudioHandle)(ptr.render));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/**
 * @brief Resume audio rendering.
 *
 * @param struct RelRenderAdapterPara
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise.
 */
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

/**
 * @brief Resume audio rendering.
 *
 * @param struct RelRenderAdapterPara
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise.
 */
int32_t AudioHdiRenderReliabilityTest::RelAudioRenderSetGain(struct RelRenderAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.render->volume.SetGain(ptr.render, ptr.character.setgain);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/**
 * @brief Resume audio rendering.
 *
 * @param struct RelRenderAdapterPara
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise.
 */
int32_t AudioHdiRenderReliabilityTest::RelAudioRenderGetGain(struct RelRenderAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.render->volume.GetGain(ptr.render, &(ptr.character.getgain));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/**
 * @brief Render procedure include RelGetAllAdapter,RelLoadAdapter.RelAudioCreateRender,RelAudioRenderStartAndFrame.
 *
 * @param struct RelRenderAdapterPara
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise.
 */
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

/**
 * @brief Set audio mute.
 *
 * @param struct RelRenderAdapterPara
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise.
 */
int32_t AudioHdiRenderReliabilityTest::RelAudioRenderSetMute(struct RelRenderAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.render->volume.SetMute(ptr.render, ptr.character.setmute);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/**
 * @brief Get audio mute.
 *
 * @param struct RelRenderAdapterPara
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise.
 */
int32_t AudioHdiRenderReliabilityTest::RelAudioRenderGetMute(struct RelRenderAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.render->volume.GetMute(ptr.render, &(ptr.character.getmute));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/**
 * @brief Set audio mute.
 *
 * @param struct RelRenderAdapterPara
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise.
 */
int32_t AudioHdiRenderReliabilityTest::RelAudioRenderSetVolume(struct RelRenderAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.render->volume.SetVolume(ptr.render, ptr.character.setvolume);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/**
 * @brief Get audio mute.
 *
 * @param struct RelRenderAdapterPara
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise.
 */
int32_t AudioHdiRenderReliabilityTest::RelAudioRenderGetVolume(struct RelRenderAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.render->volume.GetVolume(ptr.render, &(ptr.character.getvolume));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/**
 * @brief Resume audio rendering.
 *
 * @param struct RelRenderAdapterPara
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise.
 */
int32_t AudioHdiRenderReliabilityTest::RelAudioRenderGetFrameSize(struct RelRenderAdapterPara &ptr)
{
    int32_t ret = -1;
    ret = ptr.render->attr.GetFrameSize(ptr.render, &(ptr.character.getframesize));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/**
 * @brief Resume audio rendering.
 *
 * @param struct RelRenderAdapterPara
 *
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise.
 */
int32_t AudioHdiRenderReliabilityTest::RelAudioRenderGetFrameCount(struct RelRenderAdapterPara &ptr)
{
    int32_t ret = -1;
    ret = ptr.render->attr.GetFrameCount(ptr.render, &(ptr.character.getframecount));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/**
 * @brief Resume audio rendering.
 *
 * @param struct RelRenderAdapterPara
 *
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise.
 */
int32_t AudioHdiRenderReliabilityTest::RelAudioRenderGetCurrentChannelId(struct RelRenderAdapterPara &ptr)
{
    int32_t ret = -1;
    ret = ptr.render->attr.GetCurrentChannelId(ptr.render, &(ptr.character.getcurrentchannelId));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/**
 * @brief Resume audio rendering.
 *
 * @param struct RelRenderAdapterPara
 *
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise.
 */
int32_t AudioHdiRenderReliabilityTest::RelAudioRenderGetRenderPosition(struct RelRenderAdapterPara &ptr)
{
    int32_t ret = -1;
    ret = ptr.render->GetRenderPosition(ptr.render, &(ptr.character.getframes), &(ptr.time));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/**
* @tc.name  test GetAllAdapter API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioGetAllAdapter_Reliability_0001
* @tc.desc  test Reliability GetAllAdapters interface pass through pthread_create fun and adapterName is same.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudioGetAllAdapter_Reliability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelRenderAdapterPara para = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };
    struct RelRenderAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(RelRenderAdapterPara), &para, sizeof(RelRenderAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelGetAllAdapter, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = 0;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
    }
}

/**
* @tc.name  test LoadAdapter API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioLoadlAdapter_Reliability_0002
* @tc.desc  test LoadAdapter interface Reliability pass through pthread_create fun and adapterName is different.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudioLoadlAdapter_Reliability_0002, TestSize.Level1)
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
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelLoadAdapter, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        int32_t ret = -1;
        pthread_join(tids[i], &result);
        ret = (intptr_t)result;
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}

/**
* @tc.name  test LoadAdapter API via Multithread call but desc is nullptr.
* @tc.number  SUB_Audio_HDI_AudioLoadlAdapter_Reliability_0003
* @tc.desc  test LoadAdapter interface Reliability pass through pthread_create fun.
*           adapterName is different and desc is nullptr.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudioLoadlAdapter_Reliability_0003, TestSize.Level1)
{
    int32_t ret = -1;
    int32_t failcount = 0;
    int32_t succeedcount = 0;
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
        para[i].desc = nullptr;
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelLoadAdapter, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        int32_t ret = -1;
        pthread_join(tids[i], &result);
        ret = (intptr_t)result;
        if (ret == 0) {
            EXPECT_EQ(HDF_SUCCESS, ret);
            succeedcount = succeedcount + 1;
            para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
        } else {
            EXPECT_EQ(HDF_FAILURE, ret);
            failcount = failcount + 1;
        }
    }
    EXPECT_EQ(failcount, PTHREAD_DIFFADA_COUNT);
    EXPECT_EQ(succeedcount, 0);
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
        int32_t ret = -1;
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
* @tc.name  test AudioRenderStart API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioRenderStart_Reliability_0002
* @tc.desc  test AudioRenderStart interface Reliability pass through pthread_create fun.adapterName is different.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudioRenderStart_Reliability_0002, TestSize.Level1)
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
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderStart, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        int32_t ret = -1;
        pthread_join(tids[i], &result);
        ret = (intptr_t)result;
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = para[i].render->control.Stop((AudioHandle)(para[i].render));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyRender(para[i].adapter, para[i].render);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}

/**
* @tc.name  test AudioRenderFrame API via Multithread call.
* @tc.number  SUB_Audio_HDI_RelAudioRenderFrame_Reliability_0002
* @tc.desc  test AudioRenderFrame interface Reliability pass through pthread_create fun.adapterName is different.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudioRenderFrame_Reliability_0002, TestSize.Level1)
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
        ret = RelAudioRenderStart(para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderFrame, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        int32_t ret = -1;
        pthread_join(tids[i], &result);
        ret = (intptr_t)result;
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = para[i].render->control.Stop((AudioHandle)(para[i].render));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyRender(para[i].adapter, para[i].render);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}

/**
* @tc.name  test AudioRenderStop API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioRenderStop_Reliability_0001
* @tc.desc  test AudioRenderStop interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudioRenderStop_Reliability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    int32_t failcount = 0;
    int32_t succeedcount = 0;
    struct RelRenderAdapterPara para = {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()};
    struct RelRenderAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    ret = RelAudioRenderProcedure(para);
    ASSERT_EQ(HDF_SUCCESS, ret);
    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(RelRenderAdapterPara), &para, sizeof(RelRenderAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderStop, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        int32_t ret = -1;
        pthread_join(tids[i], &result);
        ret = (intptr_t)result;
        if (ret == 0) {
            EXPECT_EQ(HDF_SUCCESS, ret);
            succeedcount = succeedcount + 1;
        } else {
            EXPECT_EQ(HDF_FAILURE, ret);
            failcount = failcount + 1;
        }
    }

    para.adapter->DestroyRender(para.adapter, para.render);
    para.manager->UnloadAdapter(para.manager, para.adapter);
    EXPECT_EQ(failcount, PTHREAD_SAMEADA_COUNT-1);
    EXPECT_EQ(succeedcount, 1);
}

/**
* @tc.name  test AudioRenderStop API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioRenderStop_Reliability_0002
* @tc.desc  test AudioRenderStop interface Reliability pass through pthread_create fun and adapterName is different.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudioRenderStop_Reliability_0002, TestSize.Level1)
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
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderStop, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        int32_t ret = -1;
        pthread_join(tids[i], &result);
        ret = (intptr_t)result;
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyRender(para[i].adapter, para[i].render);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}
/**
* @tc.name  test AudioRenderPause API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioRenderPause_Reliability_0001
* @tc.desc  test AudioRenderPause interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudioRenderPause_Reliability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    int32_t failcount = 0;
    int32_t succeedcount = 0;
    struct RelRenderAdapterPara para = {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()};
    struct RelRenderAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    ret = RelAudioRenderProcedure(para);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(RelRenderAdapterPara), &para, sizeof(RelRenderAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderPause, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        ret = (intptr_t)result;
        if (ret == 0) {
            EXPECT_EQ(HDF_SUCCESS, ret);
            succeedcount = succeedcount + 1;
        } else {
            EXPECT_EQ(HDF_FAILURE, ret);
            failcount = failcount + 1;
        }
    }
    para.render->control.Stop((AudioHandle)(para.render));
    para.adapter->DestroyRender(para.adapter, para.render);
    para.manager->UnloadAdapter(para.manager, para.adapter);
    EXPECT_EQ(failcount, PTHREAD_SAMEADA_COUNT-1);
    EXPECT_EQ(succeedcount, 1);
}

/**
* @tc.name  test AudioRenderPause API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioRenderPause_Reliability_0002
* @tc.desc  test AudioRenderPause interface Reliability pass through pthread_create fun and adapterName is different
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudioRenderPause_Reliability_0002, TestSize.Level1)
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
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderPause, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        int32_t ret = -1;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);

        ret = para[i].render->control.Stop((AudioHandle)(para[i].render));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyRender(para[i].adapter, para[i].render);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}

/**
* @tc.name  test AudioRenderResume API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioRenderResume_Reliability_0001
* @tc.desc  test RelAudioRenderResume interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudioRenderResume_Reliability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    int32_t failcount = 0;
    int32_t succeedcount = 0;
    struct RelRenderAdapterPara para = {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()};
    struct RelRenderAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    ret = RelAudioRenderProcedure(para);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = RelAudioRenderPause(para);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(RelRenderAdapterPara), &para, sizeof(RelRenderAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderResume, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        ret = (intptr_t)result;
        if (ret == 0) {
            EXPECT_EQ(HDF_SUCCESS, ret);
            succeedcount = succeedcount + 1;
        } else {
            EXPECT_EQ(HDF_FAILURE, ret);
            failcount = failcount + 1;
        }
    }
    para.render->control.Stop((AudioHandle)(para.render));
    para.adapter->DestroyRender(para.adapter, para.render);
    para.manager->UnloadAdapter(para.manager, para.adapter);
}
/**
* @tc.name  test AudioRenderResume API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioRenderResume_Reliability_0002
* @tc.desc  test AudioRenderResume interface Reliability pass through pthread_create fun and adapterName is different.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudioRenderResume_Reliability_0002, TestSize.Level1)
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
        ret = RelAudioRenderPause(para[i]);
        ASSERT_EQ(HDF_SUCCESS, ret);
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderResume, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        int32_t ret = -1;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);

        ret = para[i].render->control.Stop((AudioHandle)(para[i].render));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyRender(para[i].adapter, para[i].render);
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
            .path = AUDIO_FILE.c_str()};
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
        int32_t ret = -1;
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
            .path = AUDIO_FILE.c_str()};
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
        int32_t ret = -1;
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
* @tc.name  test AudioRenderGetRenderPosition API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudiorenderGetVolume_Reliability_0001
* @tc.desc  test GetRenderPosition interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudioRenderGetRenderPosition_Reliability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    int64_t timeExp = 0;
    struct RelRenderAdapterPara para = {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
            .path = AUDIO_FILE.c_str()};
    struct RelRenderAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    ret = RelAudioRenderProcedure(para);
    ASSERT_EQ(HDF_SUCCESS, ret);

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = memcpy_s(&arrpara[i], sizeof(RelRenderAdapterPara), &para, sizeof(RelRenderAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderGetRenderPosition, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_LT(INITIAL_VALUE, arrpara[i].character.getframes);
        EXPECT_LT(timeExp, arrpara[i].time.tvNSec);
    }
    ret = para.render->control.Stop((AudioHandle)(para.render));
    EXPECT_EQ(HDF_SUCCESS, ret);
    para.adapter->DestroyRender(para.adapter, para.render);
    para.manager->UnloadAdapter(para.manager, para.adapter);
}

/**
* @tc.name  test AudioRenderGetRenderPosition API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioRenderGetRenderPosition_Reliability_0002
* @tc.desc  test GetRenderPosition interface Reliability pass through pthread_create fun and adapterName is different.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiRenderReliabilityTest, SUB_Audio_HDI_AudioRenderGetRenderPosition_Reliability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    int64_t timeExp = 0;
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
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioRenderGetRenderPosition, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        int32_t ret = -1;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_LT(INITIAL_VALUE, para[i].character.getframes);
        EXPECT_LT(timeExp, para[i].time.tvNSec);

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
            .path = AUDIO_FILE.c_str()};
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
        int32_t ret = -1;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_EQ(channelIdValue, para[i].character.getcurrentchannelId);

        ret = para[i].render->control.Stop((AudioHandle)(para[i].render));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyRender(para[i].adapter, para[i].render);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}
}
