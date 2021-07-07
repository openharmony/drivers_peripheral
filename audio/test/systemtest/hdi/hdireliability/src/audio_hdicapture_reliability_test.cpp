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
const string AUDIO_FILE_LOG = "//bin/14031.wav";
const string AUDIO_FILE_ERR = "//bin/test.txt";
const string ADAPTER_NAME = "hdmi";
const string ADAPTER_NAME2 = "usb";
const string ADAPTER_NAME3 = "internal";
const int PTHREAD_SAMEADA_COUNT = 3;
const int PTHREAD_DIFFADA_COUNT = 2;
const int BUFFER_SIZE = 16384;

class AudioHdiCaptureReliabilityTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    struct AudioManager *(*GetAudioManager)() = nullptr;
    void *handleSo = nullptr;
    static int32_t RelAudioCreateCapture(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioCaptureStart(struct RelCaptureAdapterPara& ptr);
    static int32_t RelGetAllAdapter(struct RelCaptureAdapterPara& ptr);
    static int32_t RelLoadAdapter(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioDestroyCapture(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioCaptureStop(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioCaptureResume(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioCapturePause(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioCaptureSetMute(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioCaptureGetMute(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioCaptureSetVolume(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioCaptureGetVolume(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioCaptureProcedure(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioCaptureFrame(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioCaptureStartAndCaputreFrame(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioAdapterInitAllPorts(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioAdapterGetPortCapability(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioAdapterSetPassthroughMode(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioAdapterGetPassthroughMode(struct RelCaptureAdapterPara& ptr);
    static int32_t RelAudioCaptureSetGain(struct RelCaptureAdapterPara &ptr);
    static int32_t RelAudioCaptureGetGain(struct RelCaptureAdapterPara &ptr);
    static int32_t RelAudioCaptureGetGainThreshold(struct RelCaptureAdapterPara &ptr);
    static int32_t RelAudioCaptureGetFrameSize(struct RelCaptureAdapterPara &ptr);
    static int32_t RelAudioCaptureGetFrameCount(struct RelCaptureAdapterPara &ptr);
    static int32_t RelAudioCaptureGetCurrentChannelId(struct RelCaptureAdapterPara &ptr);
    static int32_t RelAudioCaptureGetCapturePosition(struct RelCaptureAdapterPara &ptr);
};

using THREAD_FUNC = void *(*)(void *);

void AudioHdiCaptureReliabilityTest::SetUpTestCase(void) {}

void AudioHdiCaptureReliabilityTest::TearDownTestCase(void) {}

void AudioHdiCaptureReliabilityTest::SetUp(void)
{
    char resolvedPath[] = "//system/lib/libhdi_audio.z.so";
    handleSo = dlopen(resolvedPath, RTLD_LAZY);
    if (handleSo == nullptr) {
        cout << "Open Error:" << dlerror() << endl;
        return;
    }
    GetAudioManager = (struct AudioManager* (*)())(dlsym(handleSo, "GetAudioManagerFuncs"));
    if (GetAudioManager == nullptr) {
        cout << "Dlsym Error: " << dlerror() << endl;
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
    uint64_t getframes;
    uint32_t getcurrentchannelId;
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
    struct AudioPortCapability capability;
    enum AudioPortPassthroughMode mode;
    struct AudioTimeStamp time = {.tvNSec = 1};
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
        int index = HMOS::Audio::SwitchAdapter(ptr.descs, ptr.adapterName, ptr.portType, ptr.capturePort, size);
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
    ret = HMOS::Audio::InitAttrs(attrs);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    ret = HMOS::Audio::InitDevDesc(devDesc, (&ptr.capturePort)->portId, ptr.pins);
    if (ret < 0) {
        return HDF_FAILURE;
    }
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

int32_t AudioHdiCaptureReliabilityTest::RelAudioCaptureStart(struct RelCaptureAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.capture->control.Start((AudioHandle)(ptr.capture));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureReliabilityTest::RelAudioCaptureFrame(struct RelCaptureAdapterPara& ptr)
{
    int32_t ret = -1;
    uint64_t requestBytes = BUFFER_SIZE;
    uint64_t replyBytes = 0;

    char *frame = (char *)calloc(1, BUFFER_SIZE);
    if (frame == nullptr) {
        return HDF_FAILURE;
    }

    ret = ptr.capture->CaptureFrame(ptr.capture, frame, requestBytes, &replyBytes);
    if (ret < 0) {
        free(frame);
        frame = nullptr;
        return HDF_FAILURE;
    }
    free(frame);
    frame = nullptr;
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

int32_t AudioHdiCaptureReliabilityTest::RelAudioCaptureStop(struct RelCaptureAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.capture->control.Stop((AudioHandle)(ptr.capture));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureReliabilityTest::RelAudioCapturePause(struct RelCaptureAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.capture->control.Pause((AudioHandle)(ptr.capture));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureReliabilityTest::RelAudioCaptureResume(struct RelCaptureAdapterPara& ptr)
{
    int32_t ret = -1;
    ret = ptr.capture->control.Resume((AudioHandle)(ptr.capture));
    if (ret < 0) {
        return HDF_FAILURE;
    }
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

int32_t AudioHdiCaptureReliabilityTest::RelAudioAdapterInitAllPorts(struct RelCaptureAdapterPara& ptr)
{
    int32_t ret = -1;
    if (ptr.adapter == nullptr) {
        return HDF_FAILURE;
    }
    ret = ptr.adapter->InitAllPorts(ptr.adapter);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureReliabilityTest::RelAudioAdapterGetPortCapability(struct RelCaptureAdapterPara& ptr)
{
    int32_t ret = -1;
    if (ptr.adapter == nullptr) {
        return HDF_FAILURE;
    }
    ret = ptr.adapter->GetPortCapability(ptr.adapter, &(ptr.capturePort), &(ptr.capability));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureReliabilityTest::RelAudioAdapterSetPassthroughMode(struct RelCaptureAdapterPara& ptr)
{
    int32_t ret = -1;
    if (ptr.adapter == nullptr) {
        return HDF_FAILURE;
    }
    ret = ptr.adapter->SetPassthroughMode(ptr.adapter, &(ptr.capturePort), ptr.mode);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioHdiCaptureReliabilityTest::RelAudioAdapterGetPassthroughMode(struct RelCaptureAdapterPara& ptr)
{
    int32_t ret = -1;
    if (ptr.adapter == nullptr) {
        return HDF_FAILURE;
    }
    ret = ptr.adapter->GetPassthroughMode(ptr.adapter, &(ptr.capturePort), &(ptr.mode));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/**
 * @brief Resume audio Captureing.
 *
 * @param struct RelCaptureAdapterPara
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise
 */
int32_t AudioHdiCaptureReliabilityTest::RelAudioCaptureGetGainThreshold(struct RelCaptureAdapterPara &ptr)
{
    int32_t ret = -1;
    ret = ptr.capture->volume.GetGainThreshold(ptr.capture, &(ptr.character.gainthresholdmin),
        &(ptr.character.gainthresholdmax));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/**
 * @brief Resume audio Captureing.
 *
 * @param struct RelCaptureAdapterPara
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise
 */
int32_t AudioHdiCaptureReliabilityTest::RelAudioCaptureSetGain(struct RelCaptureAdapterPara &ptr)
{
    int32_t ret = -1;
    ret = ptr.capture->volume.SetGain(ptr.capture, ptr.character.setgain);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/**
 * @brief Resume audio Captureing.
 *
 * @param struct RelCaptureAdapterPara
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise
 */
int32_t AudioHdiCaptureReliabilityTest::RelAudioCaptureGetGain(struct RelCaptureAdapterPara &ptr)
{
    int32_t ret = -1;
    ret = ptr.capture->volume.GetGain(ptr.capture, &(ptr.character.getgain));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/**
 * @brief Resume audio Captureing.
 *
 * @param struct RelCaptureAdapterPara
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise
 */
int32_t AudioHdiCaptureReliabilityTest::RelAudioCaptureGetFrameSize(struct RelCaptureAdapterPara &ptr)
{
    int32_t ret = -1;
    ret = ptr.capture->attr.GetFrameSize(ptr.capture, &(ptr.character.getframesize));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/**
 * @brief Resume audio Captureing.
 *
 * @param struct RelCaptureAdapterPara
 *
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise
 */
int32_t AudioHdiCaptureReliabilityTest::RelAudioCaptureGetFrameCount(struct RelCaptureAdapterPara &ptr)
{
    int32_t ret = -1;
    ret = ptr.capture->attr.GetFrameCount(ptr.capture, &(ptr.character.getframecount));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/**
 * @brief Resume audio Captureing.
 *
 * @param struct RelCaptureAdapterPara
 *
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise
 */
int32_t AudioHdiCaptureReliabilityTest::RelAudioCaptureGetCurrentChannelId(struct RelCaptureAdapterPara &ptr)
{
    int32_t ret = -1;
    ret = ptr.capture->attr.GetCurrentChannelId(ptr.capture, &(ptr.character.getcurrentchannelId));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

/**
 * @brief Resume audio Captureing.
 *
 * @param struct RelCaptureAdapterPara
 *
 *
 * @return Returns <b>0</b> if the initialization is successful; returns a negative value otherwise
 */
int32_t AudioHdiCaptureReliabilityTest::RelAudioCaptureGetCapturePosition(struct RelCaptureAdapterPara &ptr)
{
    int32_t ret = -1;
    ret = ptr.capture->GetCapturePosition(ptr.capture, &(ptr.character.getframes), &(ptr.time));
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
    }
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        int32_t ret = -1;
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
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioDestroyCapture, &para[i]);
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
* @tc.name  RelAudioCaptureFrame API via The passed in adaptername is the different
* @tc.number  SUB_Audio_HDI_RelAudioCaptureFrame_Reliability_0002
* @tc.desc  test AudioCaptureStop interface, Returns 0 if the input data is read successfully
* @tc.author: wangkang
*/

HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioCaptureFrame_Reliability_0002, TestSize.Level1)
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
        ret = RelAudioCreateCapture(para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = RelAudioCaptureStart(para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureFrame, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        int32_t ret = -1;
        pthread_join(tids[i], &result);
        ret = (intptr_t)result;
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = para[i].capture->control.Stop((AudioHandle)(para[i].capture));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyCapture(para[i].adapter, para[i].capture);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}

/**
* @tc.name  RelAudioCaptureStart API via The passed in adaptername is the differentt
* @tc.number  SUB_Audio_HDI_RelAudioCaptureStart_Reliability_0002
* @tc.desc  test AudioCaptureStart interface, return 0 if the the AudioCapture objects are Start successfully
* @tc.author: wangkang
*/

HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioCaptureStart_Reliability_0002, TestSize.Level1)
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
        ret = RelAudioCreateCapture(para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureStart, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        int32_t ret = -1;
        pthread_join(tids[i], &result);
        ret = (intptr_t)result;
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = para[i].capture->control.Stop((AudioHandle)(para[i].capture));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyCapture(para[i].adapter, para[i].capture);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}

/**
* @tc.name  RelAudioCaptureStop API via The passed in adaptername is the differentt
* @tc.number  SUB_Audio_HDI_RelAudioCaptureStop_Reliability_0002
* @tc.desc  test AudioCaptureStop interface, return 0 if the the AudioCapture objects are Stop successfully
* @tc.author: wangkang
*/

HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioCaptureStop_Reliability_0002, TestSize.Level1)
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
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureStop, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        int32_t ret = -1;
        pthread_join(tids[i], &result);
        ret = (intptr_t)result;
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyCapture(para[i].adapter, para[i].capture);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}

/**
* @tc.name  RelAudioCapturePause API via The passed in adaptername is the differentt
* @tc.number  SUB_Audio_HDI_RelAudioCapturePause_Reliability_0002
* @tc.desc  test AudioCapturePause interface, return 0 if the the AudioCapture objects are Pause successfully
* @tc.author: wangkang
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioCapturePause_Reliability_0002, TestSize.Level1)
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
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCapturePause, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        int32_t ret = -1;
        pthread_join(tids[i], &result);
        ret = (intptr_t)result;
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].capture->control.Stop((AudioHandle)(para[i].capture));
        para[i].adapter->DestroyCapture(para[i].adapter, para[i].capture);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}

/**
* @tc.name  test RelAudioAdapterInitAllPorts API via Multi thread calling multi sound card
* @tc.number  SUB_Audio_HDI_AudioInitAllPorts_Reliability_0001
* @tc.desc  test InitAllPorts interface, return 0 if the ports is initialize successfully.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioInitAllPorts_Reliability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelCaptureAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }
    };
    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelGetAllAdapter(para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = RelLoadAdapter(para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioAdapterInitAllPorts, &para[i]);
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
* @tc.name  test RelAudioAdapterInitAllPorts API via Multi thread calling mono card
* @tc.number  SUB_Audio_HDI_AudioInitAllPorts_Reliability_0002
* @tc.desc  test InitAllPorts interface, return 0 if the ports is initialize successfully.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioInitAllPorts_Reliability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelCaptureAdapterPara para = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str()
    };
    struct RelCaptureAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = RelGetAllAdapter(para);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = RelLoadAdapter(para);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = memcpy_s(&arrpara[i], sizeof(RelCaptureAdapterPara), &para, sizeof(RelCaptureAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioAdapterInitAllPorts, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        int32_t ret = -1;
        pthread_join(tids[i], &result);
        ret = (intptr_t)result;
        EXPECT_EQ(HDF_SUCCESS, ret);
        arrpara[i].manager->UnloadAdapter(arrpara[i].manager, arrpara[i].adapter);
    }
}

/**
* @tc.name  test RelAudioAdapterGetPortCapability API via Multi thread calling multi sound card
* @tc.number  SUB_Audio_HDI_AudioGetPortCapability_Reliability_0001
* @tc.desc  test GetPortCapability interface,return 0 if the Get Port capability successfully.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioGetPortCapability_Reliability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelCaptureAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }, {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str()
        }
    };
    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelGetAllAdapter(para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = RelLoadAdapter(para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = RelAudioAdapterInitAllPorts(para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioAdapterGetPortCapability, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        ret = (intptr_t)result;
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}

/**
* @tc.name  test RelAudioAdapterGetPortCapability API via Multi thread calling mono card
* @tc.number  SUB_Audio_HDI_AudioGetPortCapability_Reliability_0002
* @tc.desc  test GetPortCapability interface,return 0 if the Get Port capability successfully.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioGetPortCapability_Reliability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelCaptureAdapterPara para = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_IN_MIC,
        .path = AUDIO_FILE.c_str()
    };

    struct RelCaptureAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];

    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = RelGetAllAdapter(para);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = RelLoadAdapter(para);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = RelAudioAdapterInitAllPorts(para);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = memcpy_s(&arrpara[i], sizeof(RelCaptureAdapterPara), &para, sizeof(RelCaptureAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioAdapterGetPortCapability, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        arrpara[i].manager->UnloadAdapter(arrpara[i].manager, arrpara[i].adapter);
    }
}

/**
* @tc.name  test RelAudioAdapterSetPassthroughMode API via Multi thread calling multi sound card
* @tc.number  SUB_Audio_HDI_AudioSetPassthroughMode_Reliability_0001
* @tc.desc  test SetPassthroughMode interface,return 0 if the Set Passthrough Mode successfully.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioSetPassthroughMode_Reliability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelCaptureAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str(), .mode = PORT_PASSTHROUGH_LPCM
        }, {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str(), .mode = PORT_PASSTHROUGH_LPCM
        }
    };

    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelGetAllAdapter(para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = RelLoadAdapter(para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = RelAudioAdapterInitAllPorts(para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioAdapterSetPassthroughMode, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        int32_t ret = -1;
        pthread_join(tids[i], &result);
        ret = (intptr_t)result;
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = para[i].adapter->GetPassthroughMode(para[i].adapter, &(para[i].capturePort), &(para[i].mode));
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(PORT_PASSTHROUGH_LPCM, para[i].mode);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}

/**
* @tc.name  test RelAudioAdapterSetPassthroughMode API via Multi thread calling mono card
* @tc.number  SUB_Audio_HDI_AudioSetPassthroughMode_Reliability_0002
* @tc.desc  test SetPassthroughMode interface,return 0 if the Set Passthrough Mode successfully.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioSetPassthroughMode_Reliability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelCaptureAdapterPara para = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str(), .mode = PORT_PASSTHROUGH_LPCM
    };

    struct RelCaptureAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];
    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = RelGetAllAdapter(para);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = RelLoadAdapter(para);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = RelAudioAdapterInitAllPorts(para);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = memcpy_s(&arrpara[i], sizeof(RelCaptureAdapterPara), &para, sizeof(RelCaptureAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioAdapterSetPassthroughMode, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        int32_t ret = -1;
        pthread_join(tids[i], &result);
        ret = (intptr_t)result;
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = arrpara[i].adapter->GetPassthroughMode(arrpara[i].adapter, &(arrpara[i].capturePort), &(arrpara[i].mode));
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(PORT_PASSTHROUGH_LPCM, arrpara[i].mode);
        arrpara[i].manager->UnloadAdapter(arrpara[i].manager, arrpara[i].adapter);
    }
}

/**
* @tc.name  test RelAudioAdapterGetPassthroughMode API via Multi thread calling multi sound card
* @tc.number  SUB_Audio_HDI_AudioGetPassthroughMode_Reliability_0001
* @tc.desc  test GetPassthroughMode interface,return 0 if the Get Passthrough Mode successfully.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioGetPassthroughMode_Reliability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelCaptureAdapterPara para[PTHREAD_DIFFADA_COUNT] = {
        {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME3.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str(), .mode = PORT_PASSTHROUGH_LPCM
        }, {
            .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_IN_MIC,
            .path = AUDIO_FILE.c_str(), .mode = PORT_PASSTHROUGH_LPCM
        }
    };
    pthread_t tids[PTHREAD_DIFFADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        ret = RelGetAllAdapter(para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = RelLoadAdapter(para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = RelAudioAdapterInitAllPorts(para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = RelAudioAdapterSetPassthroughMode(para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioAdapterGetPassthroughMode, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        int32_t ret = -1;
        pthread_join(tids[i], &result);
        ret = (intptr_t)result;
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(PORT_PASSTHROUGH_LPCM, para[i].mode);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}

/**
* @tc.name  test RelAudioAdapterGetPassthroughMode API via Multi thread calling mono card
* @tc.number  SUB_Audio_HDI_AudioGetPassthroughMode_Reliability_0002
* @tc.desc  test GetPassthroughMode interface,return 0 if the Get Passthrough Mode successfully.
* @tc.author: liutian
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioGetPassthroughMode_Reliability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    struct RelCaptureAdapterPara para = {
        .portType = PORT_OUT, .adapterName = ADAPTER_NAME2.c_str(), .param = this, .pins = PIN_OUT_SPEAKER,
        .path = AUDIO_FILE.c_str(), .mode = PORT_PASSTHROUGH_LPCM
    };

    struct RelCaptureAdapterPara arrpara[PTHREAD_SAMEADA_COUNT];
    pthread_t tids[PTHREAD_SAMEADA_COUNT];
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        ret = RelGetAllAdapter(para);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = RelLoadAdapter(para);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = RelAudioAdapterInitAllPorts(para);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = memcpy_s(&arrpara[i], sizeof(RelCaptureAdapterPara), &para, sizeof(RelCaptureAdapterPara));
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = RelAudioAdapterSetPassthroughMode(arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioAdapterGetPassthroughMode, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        int32_t ret = -1;
        pthread_join(tids[i], &result);
        ret = (intptr_t)result;
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(PORT_PASSTHROUGH_LPCM, arrpara[i].mode);
        arrpara[i].manager->UnloadAdapter(arrpara[i].manager, arrpara[i].adapter);
    }
}

/**
* @tc.name  test AudioCaptureResume API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioCaptureResume_Reliability_0002
* @tc.desc  test CaptureResume interface Reliability pass through pthread_create fun and adapterName is different.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioCaptureResume_Reliability_0002, TestSize.Level1)
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
        ret = RelAudioCapturePause(para[i]);
        ASSERT_EQ(HDF_SUCCESS, ret);
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureResume, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        int32_t ret = -1;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);

        ret = para[i].capture->control.Stop((AudioHandle)(para[i].capture));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyCapture(para[i].adapter, para[i].capture);
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
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureSetGain, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        ret = arrpara[i].capture->volume.GetGain(arrpara[i].capture, &(arrpara[i].character.getgain));
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(2, arrpara[i].character.getgain);
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
    }
    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        int32_t ret = -1;
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
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureGetGain, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
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
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureGetGain, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        int32_t ret = -1;
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
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureGetGainThreshold, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
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
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureGetGainThreshold, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        int32_t ret = -1;
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
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureGetFrameSize, &arrpara[i]);
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
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureGetFrameSize, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        int32_t ret = -1;
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
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureGetFrameCount, &arrpara[i]);
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
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureGetFrameCount, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        int32_t ret = -1;
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
* @tc.name  test AudioGetCapturePosition API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioGetCapturePosition_Reliability_0001
* @tc.desc  test AudioGetCapturePosition interface Reliability pass through pthread_create fun and adapterName is same.
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioGetCapturePosition_Reliability_0001, TestSize.Level1)
{
    int32_t ret = -1;
    int64_t timeExp = 0;
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
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureGetCapturePosition, &arrpara[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_SAMEADA_COUNT; ++i) {
        void *result = nullptr;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_LT(INITIAL_VALUE, arrpara[i].character.getframes);
        EXPECT_LT(timeExp, arrpara[i].time.tvNSec);
    }
    ret = para.capture->control.Stop((AudioHandle)(para.capture));
    EXPECT_EQ(HDF_SUCCESS, ret);
    para.adapter->DestroyCapture(para.adapter, para.capture);
    para.manager->UnloadAdapter(para.manager, para.adapter);
}
/**
* @tc.name  test AudioCaptureGetCapturePosition API via Multithread call.
* @tc.number  SUB_Audio_HDI_AudioCaptureGetCapturePosition_Reliability_0002
* @tc.desc test GetCapturePosition interface Reliability pass through pthread_create fun and adapterName is different
* @tc.author: zhouyongxiao
*/
HWTEST_F(AudioHdiCaptureReliabilityTest, SUB_Audio_HDI_AudioCaptureGetCapturePosition_Reliability_0002, TestSize.Level1)
{
    int32_t ret = -1;
    int64_t timeExp = 0;
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
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureGetCapturePosition, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        int32_t ret = -1;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_LT(INITIAL_VALUE, para[i].character.getframes);
        EXPECT_LT(timeExp, para[i].time.tvNSec);

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
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureGetCurrentChannelId, &arrpara[i]);
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
        int32_t ret = pthread_create(&tids[i], NULL, (THREAD_FUNC)RelAudioCaptureGetCurrentChannelId, &para[i]);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (int32_t i = 0; i < PTHREAD_DIFFADA_COUNT; ++i) {
        void *result = nullptr;
        int32_t ret = -1;
        pthread_join(tids[i], &result);
        EXPECT_EQ(HDF_SUCCESS, (intptr_t)result);
        EXPECT_EQ(channelIdValue, para[i].character.getcurrentchannelId);

        ret = para[i].capture->control.Stop((AudioHandle)(para[i].capture));
        EXPECT_EQ(HDF_SUCCESS, ret);
        para[i].adapter->DestroyCapture(para[i].adapter, para[i].capture);
        para[i].manager->UnloadAdapter(para[i].manager, para[i].adapter);
    }
}
}