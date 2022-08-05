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
#include "osal_mem.h"
#include "hdi_service_common.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
const float COUNT = 1000;             // number of interface calls
const int32_t LOWLATENCY = 10000;     // low interface delay:10ms
const int32_t NORMALLATENCY = 30000;  // normal interface delay:30ms
const int32_t HIGHLATENCY = 60000;    // high interface delay:60ms

class AudioIdlHdiRenderPerformaceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static TestAudioManager *(*GetAudioManager)(const char *);
    static TestAudioManager *manager;
    static void *handle;
    static void (*AudioManagerRelease)(struct AudioManager *);
    static void (*AudioAdapterRelease)(struct AudioAdapter *);
    static void (*AudioRenderRelease)(struct AudioRender *);
    static int32_t CreateRender(TestAudioManager *manager, int pins, const std::string &adapterName,
        struct AudioAdapter **adapter, struct AudioRender **render);
};
using THREAD_FUNC = void *(*)(void *);
TestAudioManager *(*AudioIdlHdiRenderPerformaceTest::GetAudioManager)(const char *) = nullptr;
TestAudioManager *AudioIdlHdiRenderPerformaceTest::manager = nullptr;
void *AudioIdlHdiRenderPerformaceTest::handle = nullptr;
void (*AudioIdlHdiRenderPerformaceTest::AudioManagerRelease)(struct AudioManager *) = nullptr;
void (*AudioIdlHdiRenderPerformaceTest::AudioAdapterRelease)(struct AudioAdapter *) = nullptr;
void (*AudioIdlHdiRenderPerformaceTest::AudioRenderRelease)(struct AudioRender *) = nullptr;

void AudioIdlHdiRenderPerformaceTest::SetUpTestCase(void)
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

void AudioIdlHdiRenderPerformaceTest::TearDownTestCase(void)
{
    if (AudioManagerRelease !=nullptr) {
        AudioManagerRelease(manager);
        manager = nullptr;
    }
    if (handle != nullptr) {
        dlclose(handle);
        handle = nullptr;
    }
    if (GetAudioManager != nullptr) {
        GetAudioManager = nullptr;
    }
}

void AudioIdlHdiRenderPerformaceTest::SetUp(void) {}

void AudioIdlHdiRenderPerformaceTest::TearDown(void) {}

int32_t AudioIdlHdiRenderPerformaceTest::CreateRender(TestAudioManager *manager, int pins,
    const std::string &adapterName, struct AudioAdapter **adapter, struct AudioRender **render)
{
    int32_t ret;
    struct AudioSampleAttributes attrs = {};
    struct AudioDeviceDescriptor devDesc = {};
    struct AudioPort audioPort = {};
    if (adapter == nullptr || render == nullptr) {
        return HDF_ERR_INVALID_PARAM;
    }
    ret = GetLoadAdapter(manager, PORT_IN, adapterName, adapter, audioPort);
    if (ret < 0) {
        if (audioPort.portName != nullptr) {
            free(audioPort.portName);
        }
        return ret;
    }
    if (*adapter == nullptr || (*adapter)->CreateRender == nullptr) {
        free(audioPort.portName);
        return HDF_FAILURE;
    }
    InitAttrs(attrs);
    attrs.startThreshold = 0;
    InitDevDesc(devDesc, audioPort.portId, pins);
    ret = (*adapter)->CreateRender(*adapter, &devDesc, &attrs, render);
    if (ret < 0 || *render == nullptr) {
        manager->UnloadAdapter(manager, adapterName.c_str());
        AudioAdapterRelease(*adapter);
        free(audioPort.portName);
        free(devDesc.desc);
        return HDF_FAILURE;
    }
    free(audioPort.portName);
    free(devDesc.desc);
    return HDF_SUCCESS;
}

/**
* @tc.name  the performace of ManagerGetAllAdapters
* @tc.number  SUB_Audio_HDI_ManagerGetAllAdapter_Performance_001
* @tc.desc  tests the performace of ManagerGetAllAdapters interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_ManagerGetAllAdapters_Performance_001, TestSize.Level1)
{
    int32_t ret;
    uint32_t descsLen = AUDIO_ADAPTER_MAX_NUM;
    struct PrepareAudioPara audiopara = { .manager = manager, .totalTime = 0 };
    ASSERT_NE(nullptr, audiopara.manager);

    for (int i = 0; i < COUNT; ++i) {
        audiopara.descs = (struct AudioAdapterDescriptor*)OsalMemCalloc(
                              sizeof(struct AudioAdapterDescriptor) * (AUDIO_ADAPTER_MAX_NUM));
        ASSERT_NE(nullptr, audiopara.descs);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.manager->GetAllAdapters(audiopara.manager, audiopara.descs, &descsLen);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        TestReleaseAdapterDescs(&audiopara.descs, descsLen);
        audiopara.descs = nullptr;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  the performace of ManagerLoadAdapter
* @tc.number  SUB_Audio_HDI_ManagerLoadAdapter_Performance_001
* @tc.desc  tests the performace of ManagerLoadAdapter interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_ManagerLoadAdapter_Performance_001, TestSize.Level1)
{
    int32_t ret;
    uint32_t descsLen = AUDIO_ADAPTER_MAX_NUM;
    struct PrepareAudioPara audiopara = { .manager = manager, .totalTime = 0 };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = GetAdapters(audiopara.manager, audiopara.descs, descsLen);
    ASSERT_EQ(HDF_SUCCESS, ret);
    audiopara.desc = &audiopara.descs[0];
    EXPECT_NE(nullptr, audiopara.desc);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.manager->LoadAdapter(audiopara.manager, audiopara.desc, &audiopara.adapter);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);

        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.desc->adapterName);
        EXPECT_EQ(HDF_SUCCESS, ret);
        AudioAdapterRelease(audiopara.adapter);
        audiopara.adapter = nullptr;
    }
    TestReleaseAdapterDescs(&audiopara.descs, descsLen);
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  the performace of ManagerUnLoadAdapter
* @tc.number  SUB_Audio_HDI_ManagerUnLoadAdapter_Performance_001
* @tc.desc  tests the performace of ManagerLoadAdapter interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_ManagerUnLoadAdapter_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);

    for (int i = 0; i < COUNT; ++i) {
        ret = GetLoadAdapter(audiopara.manager, audiopara.portType, audiopara.adapterName, &audiopara.adapter,
                             audiopara.audioPort);
        EXPECT_EQ(HDF_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        AudioAdapterRelease(audiopara.adapter);
        audiopara.adapter = nullptr;
        if (audiopara.audioPort.portName != nullptr) {
            free(audiopara.audioPort.portName);
        }
    }

    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  the performace of InitAllPorts
* @tc.number  SUB_Audio_HDI_ManagerInitAllPorts_Performance_001
* @tc.desc  tests the performace of InitAllPorts interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_ManagerInitAllPorts_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = GetLoadAdapter(audiopara.manager, audiopara.portType, audiopara.adapterName,
                         &audiopara.adapter, audiopara.audioPort);
    if (ret < 0) {
        if (audiopara.audioPort.portName != nullptr) {
            free(audiopara.audioPort.portName);
        }
        ASSERT_EQ(HDF_SUCCESS, ret);
    }

    for (int i = 0; i < COUNT; ++i) {
        EXPECT_NE(nullptr, audiopara.adapter);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.adapter->InitAllPorts(audiopara.adapter);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    free(audiopara.audioPort.portName);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performace of GetPortCapability
* @tc.number  SUB_Audio_HDI_GetPortCapability_Performance_001
* @tc.desc  tests the performace of GetPortCapability interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_GetPortCapability_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = GetLoadAdapter(audiopara.manager, audiopara.portType, audiopara.adapterName, &audiopara.adapter,
                         audiopara.audioPort);
    if (ret < 0) {
        if (audiopara.audioPort.portName != nullptr) {
            free(audiopara.audioPort.portName);
        }
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = audiopara.adapter->InitAllPorts(audiopara.adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        struct AudioPortCapability *capability = nullptr;
        capability = (struct AudioPortCapability*)OsalMemCalloc(sizeof(struct AudioPortCapability));
        if (capability == nullptr) {
            audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
            AudioAdapterRelease(audiopara.adapter);
            free(audiopara.audioPort.portName);
            ASSERT_NE(nullptr, capability);
        }
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.adapter->GetPortCapability(audiopara.adapter, &audiopara.audioPort, capability);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_NE(nullptr, capability->formats);
        EXPECT_NE(nullptr, capability->subPorts);
        if (capability->subPorts != nullptr) {
            EXPECT_NE(nullptr, capability->subPorts->desc);
        }
        TestAudioPortCapabilityFree(capability, true);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    free(audiopara.audioPort.portName);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performace of SetPassthroughMode
* @tc.number  SUB_Audio_HDI_SetPassthroughMode_Performance_001
* @tc.desc  tests the performace of SetPassthroughMode interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_SetPassthroughMode_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .mode = PORT_PASSTHROUGH_LPCM, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = GetLoadAdapter(audiopara.manager, audiopara.portType, audiopara.adapterName, &audiopara.adapter,
                         audiopara.audioPort);
    if (ret < 0) {
        if (audiopara.audioPort.portName != nullptr) {
            free(audiopara.audioPort.portName);
        }
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = audiopara.adapter->InitAllPorts(audiopara.adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.adapter->SetPassthroughMode(audiopara.adapter, &audiopara.audioPort, audiopara.mode);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = audiopara.adapter->GetPassthroughMode(audiopara.adapter, &audiopara.audioPort, &audiopara.mode);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(PORT_PASSTHROUGH_LPCM, audiopara.mode);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    free(audiopara.audioPort.portName);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performace of GetPassthroughMode
* @tc.number  SUB_Audio_HDI_GetPassthroughMode_Performance_001
* @tc.desc  tests the performace of GetPassthroughMode interface by executing 1000 times,
* and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_GetPassthroughMode_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .mode = PORT_PASSTHROUGH_LPCM, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = GetLoadAdapter(audiopara.manager, audiopara.portType, audiopara.adapterName, &audiopara.adapter,
                         audiopara.audioPort);
    if (ret < 0) {
        if (audiopara.audioPort.portName != nullptr) {
            free(audiopara.audioPort.portName);
        }
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    ret = audiopara.adapter->InitAllPorts(audiopara.adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.adapter->SetPassthroughMode(audiopara.adapter, &audiopara.audioPort, audiopara.mode);
    EXPECT_EQ(HDF_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.adapter->GetPassthroughMode(audiopara.adapter, &audiopara.audioPort, &audiopara.mode);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(PORT_PASSTHROUGH_LPCM, audiopara.mode);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    free(audiopara.audioPort.portName);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
}

/**
* @tc.name  the performace of RenderGetLatency
* @tc.number  SUB_Audio_HDI_RenderGetLatency_Performance_001
* @tc.desc  tests the performace of RenderGetLatency interface by executing 1000 times,
* and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_RenderGetLatency_Performance_001, TestSize.Level1)
{
    int32_t ret;
    uint32_t latencyTime = 0;
    uint32_t expectLatency = 0;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                       &audiopara.render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioRenderStartAndOneFrame(audiopara.render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        if (audiopara.render != nullptr) {
            gettimeofday(&audiopara.start, NULL);
            ret = audiopara.render->GetLatency(audiopara.render, &latencyTime);
            gettimeofday(&audiopara.end, NULL);
            EXPECT_EQ(HDF_SUCCESS, ret);
            EXPECT_LT(expectLatency, latencyTime);
            audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                                  (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
            audiopara.totalTime += audiopara.delayTime;
        }
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.render->Stop(audiopara.render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = audiopara.adapter->DestroyRender(audiopara.adapter);
    AudioRenderRelease(audiopara.render);
    audiopara.render = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  the performace of CreateRender
* @tc.number  SUB_Audio_HDI_CreateRender_Performance_001
* @tc.desc  tests the performace of CreateRender interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_CreateRender_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = GetLoadAdapter(audiopara.manager, audiopara.portType, audiopara.adapterName, &audiopara.adapter,
                         audiopara.audioPort);
    if (ret < 0) {
        if (audiopara.audioPort.portName != nullptr) {
            free(audiopara.audioPort.portName);
        }
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    InitAttrs(audiopara.attrs);
    InitDevDesc(audiopara.devDesc, audiopara.audioPort.portId, audiopara.pins);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.adapter->CreateRender(audiopara.adapter, &audiopara.devDesc, &audiopara.attrs,
                                              &audiopara.render);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = audiopara.adapter->DestroyRender(audiopara.adapter);
        AudioRenderRelease(audiopara.render);
        audiopara.render = nullptr;
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(HIGHLATENCY, audiopara.averageDelayTime);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(audiopara.devDesc.desc);
    free(audiopara.audioPort.portName);
}

/**
* @tc.name  the performace of DestroyRender
* @tc.number  SUB_Audio_HDI_DestroyRender_Performance_001
* @tc.desc  tests the performace of DestroyRender interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_DestroyRender_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = GetLoadAdapter(audiopara.manager, audiopara.portType, audiopara.adapterName, &audiopara.adapter,
                         audiopara.audioPort);
    if (ret < 0) {
        if (audiopara.audioPort.portName != nullptr) {
            free(audiopara.audioPort.portName);
        }
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    InitAttrs(audiopara.attrs);
    InitDevDesc(audiopara.devDesc, audiopara.audioPort.portId, audiopara.pins);

    for (int i = 0; i < COUNT; ++i) {
        ret = audiopara.adapter->CreateRender(audiopara.adapter, &audiopara.devDesc, &audiopara.attrs,
                                              &audiopara.render);
        EXPECT_EQ(HDF_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        audiopara.adapter->DestroyRender(audiopara.adapter);
        gettimeofday(&audiopara.end, NULL);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(audiopara.devDesc.desc);
    free(audiopara.audioPort.portName);
}
/**
* @tc.name  the performace of RenderGetRenderPosition
* @tc.number  SUB_Audio_HDI_RenderGetRenderPosition_Performance_001
* @tc.desc  tests the performace of RenderGetRenderPosition interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_RenderGetRenderPosition_Performance_001, TestSize.Level1)
{
    int32_t ret;
    uint64_t frames = 0;
    int64_t timeExp = 0;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .path = AUDIO_FILE.c_str(), .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                       &audiopara.render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = pthread_create(&audiopara.tids, NULL, (THREAD_FUNC)PlayAudioFile, &audiopara);
    EXPECT_EQ(HDF_SUCCESS, ret);
    sleep(1);
    for (int i = 0; i < COUNT; ++i) {
        if (audiopara.render != nullptr) {
            gettimeofday(&audiopara.start, NULL);
            ret = audiopara.render->GetRenderPosition(audiopara.render, &frames, &audiopara.time);
            gettimeofday(&audiopara.end, NULL);
            EXPECT_EQ(HDF_SUCCESS, ret);
            EXPECT_GT((audiopara.time.tvSec) * SECTONSEC + (audiopara.time.tvNSec), timeExp);
            EXPECT_GT(frames, INITIAL_VALUE);
            audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                                  (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
            audiopara.totalTime += audiopara.delayTime;
        }
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = ThreadRelease(audiopara);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.adapter->DestroyRender(audiopara.adapter);
    AudioRenderRelease(audiopara.render);
    audiopara.render = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  the performace of RenderSetRenderSpeed
* @tc.number  SUB_Audio_HDI_RenderSetRenderSpeed_Performance_001
* @tc.desc  tests the performace of RenderSetRenderSpeed interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_RenderSetRenderSpeed_Performance_001, TestSize.Level1)
{
    int32_t ret;
    float speed = 0;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                       &audiopara.render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioRenderStartAndOneFrame(audiopara.render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->SetRenderSpeed(audiopara.render, speed);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
        ret = audiopara.render->GetRenderSpeed(audiopara.render, &speed);
        EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.render->Stop(audiopara.render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.adapter->DestroyRender(audiopara.adapter);
    AudioRenderRelease(audiopara.render);
    audiopara.render = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  the performace of RenderGetRenderSpeed
* @tc.number  SUB_Audio_HDI_RenderGetRenderSpeed_Performance_001
* @tc.desc  tests the performace of RenderGetRenderSpeed interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_AudioRenderGetRenderSpeed_Performance_001, TestSize.Level1)
{
    int32_t ret;
    float speed = 0;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                       &audiopara.render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioRenderStartAndOneFrame(audiopara.render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->GetRenderSpeed(audiopara.render, &speed);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.render->Stop(audiopara.render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.adapter->DestroyRender(audiopara.adapter);
    AudioRenderRelease(audiopara.render);
    audiopara.render = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  the performace of RenderSetChannelMode
* @tc.number  SUB_Audio_HDI_RenderSetChannelMode_Performance_001
* @tc.desc  tests the performace of RenderSetChannelMode interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_RenderSetChannelMode_Performance_001, TestSize.Level1)
{
    int32_t ret;
    AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                       &audiopara.render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioRenderStartAndOneFrame(audiopara.render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->SetChannelMode(audiopara.render, mode);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = audiopara.render->GetChannelMode(audiopara.render, &mode);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(AUDIO_CHANNEL_NORMAL, mode);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.render->Stop(audiopara.render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.adapter->DestroyRender(audiopara.adapter);
    AudioRenderRelease(audiopara.render);
    audiopara.render = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  the performace of RenderGetChannelMode
* @tc.number  SUB_Audio_HDI_RenderGetChannelMode_Performance_001
* @tc.desc  tests the performace of RenderGetChannelMode interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_RenderGetChannelMode_Performance_001, TestSize.Level1)
{
    int32_t ret;
    AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                       &audiopara.render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioRenderStartAndOneFrame(audiopara.render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->SetChannelMode(audiopara.render, mode);
    EXPECT_EQ(HDF_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->GetChannelMode(audiopara.render, &mode);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(AUDIO_CHANNEL_NORMAL, mode);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.render->Stop(audiopara.render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.adapter->DestroyRender(audiopara.adapter);
    AudioRenderRelease(audiopara.render);
    audiopara.render = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  the performace of RenderGetFrameCount
* @tc.number  SUB_Audio_HDI_RenderGetFrameCount_Performance_001
* @tc.desc  tests the performace of RenderGetFrameCount interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_RenderGetFrameCount_Performance_001, TestSize.Level1)
{
    int32_t ret;
    uint64_t count = 0;
    uint64_t zero = 0;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                       &audiopara.render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioRenderStartAndOneFrame(audiopara.render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->GetFrameCount(audiopara.render, &count);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_GT(count, zero);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.render->Stop(audiopara.render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.adapter->DestroyRender(audiopara.adapter);
    AudioRenderRelease(audiopara.render);
    audiopara.render = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  the performace of RenderGetCurrentChannelId
* @tc.number  SUB_Audio_HDI_RenderGetCurrentChannelId_Performance_001
* @tc.desc  tests the performace of RenderGetCurrentChannelId interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_RenderGetCurrentChannelId_Performance_001, TestSize.Level1)
{
    int32_t ret;
    uint32_t channelId = 0;
    uint32_t channelIdValue = CHANNELCOUNT;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                       &audiopara.render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->GetCurrentChannelId(audiopara.render, &channelId);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(channelIdValue, channelId);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyRender(audiopara.adapter);
    AudioRenderRelease(audiopara.render);
    audiopara.render = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  the performace of RenderFlush
* @tc.number  SUB_Audio_HDI_RenderFlush_Performance_001
* @tc.desc  tests the performace of RenderFlush interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_RenderFlush_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);

    for (int i = 0; i < COUNT; ++i) {
        ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                           &audiopara.render);
        ASSERT_EQ(HDF_SUCCESS, ret);
        ret = AudioRenderStartAndOneFrame(audiopara.render);
        EXPECT_EQ(HDF_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->Flush(audiopara.render);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_ERR_NOT_SUPPORT, ret);
        ret = audiopara.render->Stop(audiopara.render);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = audiopara.adapter->DestroyRender(audiopara.adapter);
        AudioRenderRelease(audiopara.render);
        audiopara.render = nullptr;
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
        AudioAdapterRelease(audiopara.adapter);
        audiopara.adapter = nullptr;
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}
/**
* @tc.name  the performace of RenderGetFrameSize
* @tc.number  SUB_Audio_HDI_RenderGetFrameSize_Performance_001
* @tc.desc  tests the performace of RenderGetFrameSize interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_RenderGetFrameSize_Performance_001, TestSize.Level1)
{
    int32_t ret;
    uint64_t size = 0;
    uint64_t zero = 0;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                       &audiopara.render);
    ASSERT_EQ(HDF_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        ret = AudioRenderStartAndOneFrame(audiopara.render);
        EXPECT_EQ(HDF_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->GetFrameSize(audiopara.render, &size);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_GT(size, zero);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = audiopara.render->Stop(audiopara.render);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyRender(audiopara.adapter);
    AudioRenderRelease(audiopara.render);
    audiopara.render = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
}

/**
* @tc.name  the performace of RenderCheckSceneCapability
* @tc.number  SUB_Audio_HDI_RenderCheckSceneCapability_Performance_001
* @tc.desc  tests the performace of RenderCheckSceneCapability interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_RenderCheckSceneCapability_Performance_001, TestSize.Level1)
{
    int32_t ret;
    bool supported = false;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                       &audiopara.render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    struct AudioSceneDescriptor scenes = {.scene.id = 0, .desc.pins = PIN_OUT_SPEAKER, .desc.desc = strdup("mic") };
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->CheckSceneCapability(audiopara.render, &scenes, &supported);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_TRUE(supported);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyRender(audiopara.adapter);
    AudioRenderRelease(audiopara.render);
    audiopara.render = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(scenes.desc.desc);
}
/**
* @tc.name  the performace of RenderSelectScene
* @tc.number  SUB_Audio_HDI_RenderSelectScene_Performance_001
* @tc.desc  tests the performace of RenderSelectScene interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_RenderSelectScene_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                       &audiopara.render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    struct AudioSceneDescriptor scenes = {.scene.id = 0, .desc.pins = PIN_OUT_SPEAKER, .desc.desc = strdup("mic") };

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->SelectScene(audiopara.render, &scenes);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = AudioRenderStartAndOneFrame(audiopara.render);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.render->Stop(audiopara.render);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyRender(audiopara.adapter);
    AudioRenderRelease(audiopara.render);
    audiopara.render = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    free(scenes.desc.desc);
}
/**
* @tc.name  the performace of renderSetMute
* @tc.number  SUB_Audio_HDI_renderSetMute_Performance_001
* @tc.desc  tests the performace of renderSetMute interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_renderSetMute_Performance_001, TestSize.Level1)
{
    int32_t ret;
    bool muteFalse = false;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                       &audiopara.render);
    ASSERT_EQ(HDF_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->SetMute(audiopara.render, muteFalse);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = audiopara.render->GetMute(audiopara.render, &muteFalse);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(false, muteFalse);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyRender(audiopara.adapter);
    AudioRenderRelease(audiopara.render);
    audiopara.render = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  the performace of renderGetMute
* @tc.number  SUB_Audio_HDI_enderGetMute_Performance_001
* @tc.desc  tests the performace of renderGetMute interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_renderGetMute_Performance_001, TestSize.Level1)
{
    int32_t ret;
    bool muteFalse = false;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                       &audiopara.render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->SetMute(audiopara.render, muteFalse);
    EXPECT_EQ(HDF_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->GetMute(audiopara.render, &muteFalse);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyRender(audiopara.adapter);
    AudioRenderRelease(audiopara.render);
    audiopara.render = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  the performace of renderSetVolume
* @tc.number  SUB_Audio_HDI_renderSetVolume_Performance_001
* @tc.desc  tests the performace of renderSetVolume interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_renderSetVolume_Performance_001, TestSize.Level1)
{
    int32_t ret;
    float volume = 0.80;
    float volumeExpc = 0.80;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                       &audiopara.render);
    ASSERT_EQ(HDF_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->SetVolume(audiopara.render, volume);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = audiopara.render->GetVolume(audiopara.render, &volume);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(volumeExpc, volume);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyRender(audiopara.adapter);
    AudioRenderRelease(audiopara.render);
    audiopara.render = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  the performace of renderGetVolume
* @tc.number  SUB_Audio_HDI_renderGetVolume_Performance_001
* @tc.desc  tests the performace of renderGetVolume interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_renderGetVolume_Performance_001, TestSize.Level1)
{
    int32_t ret;
    float volume = 0.30;
    float volumeDefault = 0.30;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                       &audiopara.render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->SetVolume(audiopara.render, volume);
    EXPECT_EQ(HDF_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->GetVolume(audiopara.render, &volume);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(volumeDefault, volume);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyRender(audiopara.adapter);
    AudioRenderRelease(audiopara.render);
    audiopara.render = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  the performace of renderGetGainThreshold
* @tc.number  SUB_Audio_HDI_renderGetGainThreshold_Performance_001
* @tc.desc  tests the performace of renderGetGainThreshold interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_renderGetGainThreshold_Performance_001, TestSize.Level1)
{
    int32_t ret;
    float min = 0;
    float max = 0;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                       &audiopara.render);
    ASSERT_EQ(HDF_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->GetGainThreshold(audiopara.render, &min, &max);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(min, GAIN_MIN);
        EXPECT_EQ(max, GAIN_MAX);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyRender(audiopara.adapter);
    AudioRenderRelease(audiopara.render);
    audiopara.render = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  the performace of renderSetGain
* @tc.number  SUB_Audio_HDI_renderSetGain_Performance_001
* @tc.desc  tests the performace of renderSetGain interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_renderSetGain_Performance_001, TestSize.Level1)
{
    int32_t ret;
    float gain = 10;
    float gainExpc = 10;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                       &audiopara.render);
    ASSERT_EQ(HDF_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->SetGain(audiopara.render, gain);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = audiopara.render->GetGain(audiopara.render, &gain);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(gainExpc, gain);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyRender(audiopara.adapter);
    AudioRenderRelease(audiopara.render);
    audiopara.render = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  the performace of renderGetGain
* @tc.number  SUB_Audio_HDI_renderGetGain_Performance_001
* @tc.desc  tests the performace of renderGetGain interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: liutian
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_renderGetGain_Performance_001, TestSize.Level1)
{
    int32_t ret;
    float min = 0;
    float max = 0;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                       &audiopara.render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->GetGainThreshold(audiopara.render, &min, &max);
    EXPECT_EQ(HDF_SUCCESS, ret);
    float gain = min+1;
    float gainValue = min+1;

    for (int i = 0; i < COUNT; ++i) {
        ret = audiopara.render->SetGain(audiopara.render, gain);
        EXPECT_EQ(HDF_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->GetGain(audiopara.render, &gain);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(gainValue, gain);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyRender(audiopara.adapter);
    AudioRenderRelease(audiopara.render);
    audiopara.render = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  the performace of RenderFrame
* @tc.number  SUB_Audio_HDI_RenderFrame_Performance_001
* @tc.desc  tests the performace of RenderFrame interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_RenderFrame_Performance_001, TestSize.Level1)
{
    int32_t ret;
    uint64_t requestBytes = 0;
    uint64_t replyBytes = 0;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .path = AUDIO_FILE.c_str(), .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                       &audiopara.render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->Start(audiopara.render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = RenderFramePrepare(AUDIO_FILE, audiopara.frame, requestBytes);
    EXPECT_EQ(HDF_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->RenderFrame(audiopara.render, (int8_t *)audiopara.frame, requestBytes,
                                            &replyBytes);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.render->Stop(audiopara.render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    if (audiopara.frame != nullptr) {
        free(audiopara.frame);
        audiopara.frame = nullptr;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(NORMALLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyRender(audiopara.adapter);
    AudioRenderRelease(audiopara.render);
    audiopara.render = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  the performace of RenderStart
* @tc.number  SUB_Audio_HDI_RenderStart_Performance_001
* @tc.desc  tests the performace of RenderStart interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_RenderStart_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);

    for (int i = 0; i < COUNT; ++i) {
        ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                           &audiopara.render);
        ASSERT_EQ(HDF_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->Start(audiopara.render);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = audiopara.render->Stop(audiopara.render);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.adapter->DestroyRender(audiopara.adapter);
        AudioRenderRelease(audiopara.render);
        audiopara.render = nullptr;
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
        AudioAdapterRelease(audiopara.adapter);
        audiopara.adapter = nullptr;
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}
/**
* @tc.name  the performace of RenderStop
* @tc.number  SUB_Audio_HDI_RenderStop_Performance_001
* @tc.desc  tests the performace of RenderStop interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_RenderStop_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);

    for (int i = 0; i < COUNT; ++i) {
        ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                           &audiopara.render);
        ASSERT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.render->Start(audiopara.render);
        EXPECT_EQ(HDF_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->Stop(audiopara.render);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = audiopara.adapter->DestroyRender(audiopara.adapter);
        AudioRenderRelease(audiopara.render);
        audiopara.render = nullptr;
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
        AudioAdapterRelease(audiopara.adapter);
        audiopara.adapter = nullptr;
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}
/**
* @tc.name  the performace of RenderPause
* @tc.number  SUB_Audio_HDI_RenderPause_Performance_001
* @tc.desc  tests the performace of RenderPause interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_RenderPause_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                       &audiopara.render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioRenderStartAndOneFrame(audiopara.render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->Pause(audiopara.render);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.render->Resume(audiopara.render);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.render->Stop(audiopara.render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.adapter->DestroyRender(audiopara.adapter);
    AudioRenderRelease(audiopara.render);
    audiopara.render = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  the performace of AudioRenderResume
* @tc.number  SUB_Audio_HDI_AudioRenderResume_Performance_001
* @tc.desc  tests the performace of AudioRenderResume interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_AudioRenderResume_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                       &audiopara.render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = AudioRenderStartAndOneFrame(audiopara.render);
    EXPECT_EQ(HDF_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        ret = audiopara.render->Pause(audiopara.render);
        EXPECT_EQ(HDF_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->Resume(audiopara.render);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.render->Stop(audiopara.render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.adapter->DestroyRender(audiopara.adapter);
    AudioRenderRelease(audiopara.render);
    audiopara.render = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  the performace of RenderSetSampleAttributes
* @tc.number  SUB_Audio_HDI_RenderSetSampleAttributes_Performance_001
* @tc.desc  tests the performace of RenderSetSampleAttributes interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_RenderSetSampleAttributes_Performance_001, TestSize.Level1)
{
    int32_t ret;
    uint32_t expChannelCount = 2;
    uint32_t expSampleRate = 8000;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                       &audiopara.render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    InitAttrsUpdate(audiopara.attrs, AUDIO_FORMAT_PCM_16_BIT, 2, 8000);

    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->SetSampleAttributes(audiopara.render, &audiopara.attrs);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.render->GetSampleAttributes(audiopara.render, &audiopara.attrsValue);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(AUDIO_IN_MEDIA, audiopara.attrsValue.type);
        EXPECT_EQ(AUDIO_FORMAT_PCM_16_BIT, audiopara.attrsValue.format);
        EXPECT_EQ(expSampleRate, audiopara.attrsValue.sampleRate);
        EXPECT_EQ(expChannelCount, audiopara.attrsValue.channelCount);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyRender(audiopara.adapter);
    AudioRenderRelease(audiopara.render);
    audiopara.render = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  the performace of RenderGetSampleAttributes
* @tc.number  SUB_Audio_HDI_RenderGetSampleAttributes_Performance_001
* @tc.desc  tests the performace of RenderGetSampleAttributes interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_RenderGetSampleAttributes_Performance_001, TestSize.Level1)
{
    int32_t ret;
    uint32_t expChannelCount = 2;
    uint32_t expSampleRate = 8000;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                       &audiopara.render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    InitAttrsUpdate(audiopara.attrs, AUDIO_FORMAT_PCM_24_BIT, 2, 8000);

    for (int i = 0; i < COUNT; ++i) {
        ret = audiopara.render->SetSampleAttributes(audiopara.render, &audiopara.attrs);
        EXPECT_EQ(HDF_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->GetSampleAttributes(audiopara.render, &audiopara.attrsValue);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(AUDIO_IN_MEDIA, audiopara.attrsValue.type);
        EXPECT_EQ(AUDIO_FORMAT_PCM_24_BIT, audiopara.attrsValue.format);
        EXPECT_EQ(expSampleRate, audiopara.attrsValue.sampleRate);
        EXPECT_EQ(expChannelCount, audiopara.attrsValue.channelCount);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyRender(audiopara.adapter);
    AudioRenderRelease(audiopara.render);
    audiopara.render = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  the performace of RenderReqMmapBuffer
* @tc.number  SUB_Audio_HDI_RenderReqMmapBuffer_Performance_001
* @tc.desc  tests the performace of RenderReqMmapBuffer interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_RenderReqMmapBuffer_Performance_001, TestSize.Level1)
{
    int32_t ret;
    bool isRender = true;
    int32_t reqSize = 0;
    struct AudioMmapBufferDescripter desc = {};
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);

    for (int i = 0; i < COUNT; ++i) {
        audiopara.render = nullptr;
        ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                           &audiopara.render);
        ASSERT_EQ(HDF_SUCCESS, ret);
        ret = InitMmapDesc(LOW_LATENCY_AUDIO_FILE, desc, reqSize, isRender);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.render->Start(audiopara.render);
        EXPECT_EQ(HDF_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->ReqMmapBuffer(audiopara.render, reqSize, &desc);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        if (ret == 0) {
            munmap(desc.memoryAddress, reqSize);
        }
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = audiopara.render->Stop(audiopara.render);
        EXPECT_EQ(HDF_SUCCESS, ret);
        free(desc.filePath);
        ret = audiopara.adapter->DestroyRender(audiopara.adapter);
        AudioRenderRelease(audiopara.render);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
        AudioAdapterRelease(audiopara.adapter);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(500);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}
/**
* @tc.name  the performace of RenderGetMmapPosition
* @tc.number  SUB_Audio_HDI_RenderGetMmapPosition_Performance_001
* @tc.desc  tests the performace of RenderRenderGetMmapPosition interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_RenderGetMmapPosition_Performance_001, TestSize.Level1)
{
    int32_t ret;
    uint64_t framesRendering = 0;
    int64_t timeExp = 0;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .path = LOW_LATENCY_AUDIO_FILE.c_str(), .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                       &audiopara.render);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = PlayMapAudioFile(audiopara);
    if (ret != 0) {
        audiopara.adapter->DestroyRender(audiopara.adapter);
        AudioRenderRelease(audiopara.render);
        audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
        AudioAdapterRelease(audiopara.adapter);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->GetMmapPosition(audiopara.render, &framesRendering, &(audiopara.time));
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_GT((audiopara.time.tvSec) * SECTONSEC + (audiopara.time.tvNSec), timeExp);
        EXPECT_GT(framesRendering, INITIAL_VALUE);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.render->Stop(audiopara.render);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.adapter->DestroyRender(audiopara.adapter);
    AudioRenderRelease(audiopara.render);
    audiopara.render = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  the performace of RenderSetExtraParams
* @tc.number  SUB_Audio_HDI_RenderSetExtraParams_Performance_001
* @tc.desc  tests the performace of RenderSetExtraParams interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_RenderSetExtraParams_Performance_001, TestSize.Level1)
{
    int32_t ret;
    const char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;attr-frame-count=82;\
attr-sampling-rate=48000";
    const char keyValueListExp[] = "attr-route=1;attr-format=32;attr-channels=2;attr-sampling-rate=48000";
    size_t index = 1;
    int32_t listLenth = 256;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                       &audiopara.render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->SetExtraParams(audiopara.render, keyValueList);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        usleep(10000);
        char keyValueListValue[256] = {0};
        ret = audiopara.render->GetExtraParams(audiopara.render, keyValueListValue, listLenth);
        EXPECT_EQ(HDF_SUCCESS, ret);
        string strGetValue = keyValueListValue;
        size_t indexAttr = strGetValue.find("attr-frame-count");
        size_t indexFlag = strGetValue.rfind(";");
        if (indexAttr != string::npos && indexFlag != string::npos) {
            strGetValue.replace(indexAttr, indexFlag - indexAttr + index, "");
        }
        EXPECT_STREQ(keyValueListExp, strGetValue.c_str());
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyRender(audiopara.adapter);
    AudioRenderRelease(audiopara.render);
    audiopara.render = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
}
/**
* @tc.name  the performace of RenderGetExtraParams
* @tc.number  SUB_Audio_HDI_RenderGetExtraParams_Performance_001
* @tc.desc  tests the performace of RenderGetExtraParams interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiRenderPerformaceTest, SUB_Audio_HDI_RenderGetExtraParams_Performance_001, TestSize.Level1)
{
    int32_t ret;
    char keyValueList[] = "attr-format=24;attr-frame-count=4096;";
    char keyValueListExp[] = "attr-route=0;attr-format=24;attr-channels=2;attr-frame-count=4096;\
attr-sampling-rate=48000";
    int32_t listLenth = 256;
    struct PrepareAudioPara audiopara = {
        .manager = manager, .portType = PORT_OUT, .adapterName = ADAPTER_NAME.c_str(),
        .pins = PIN_OUT_SPEAKER, .path = AUDIO_FILE.c_str(), .totalTime = 0
    };
    ASSERT_NE(nullptr, audiopara.manager);
    ret = CreateRender(audiopara.manager, audiopara.pins, audiopara.adapterName, &audiopara.adapter,
                       &audiopara.render);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.render->SetExtraParams(audiopara.render, keyValueList);
    EXPECT_EQ(HDF_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        char keyValueListValue[256] = {};
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.render->GetExtraParams(audiopara.render, keyValueListValue, listLenth);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_STREQ(keyValueListExp, keyValueListValue);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
    ret = audiopara.adapter->DestroyRender(audiopara.adapter);
    AudioRenderRelease(audiopara.render);
    audiopara.render = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.manager->UnloadAdapter(audiopara.manager, audiopara.adapterName);
    AudioAdapterRelease(audiopara.adapter);
    audiopara.adapter = nullptr;
    EXPECT_EQ(HDF_SUCCESS, ret);
}
}
