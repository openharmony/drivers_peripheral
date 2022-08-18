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
#include "osal_mem.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Audio;

namespace {
const float COUNT = 1000;             // number of interface calls
const int32_t LOWLATENCY = 10000;     // low interface delay:10ms
const int32_t HIGHLATENCY = 60000;    // high interface delay:60ms

class AudioIdlHdiAdapterPerformaceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static struct IAudioAdapter *adapter;
    static struct AudioPort audioPort;
    static void *handle;
    static TestAudioManager *manager;
    static TestAudioManagerRelease managerRelease;
    static TestGetAudioManager getAudioManager;
    static TestAudioAdapterRelease adapterRelease;
    static TestAudioRenderRelease renderRelease;
    static TestAudioCaptureRelease captureRelease;
};
using THREAD_FUNC = void *(*)(void *);
TestGetAudioManager AudioIdlHdiAdapterPerformaceTest::getAudioManager = nullptr;
TestAudioManager *AudioIdlHdiAdapterPerformaceTest::manager = nullptr;
void *AudioIdlHdiAdapterPerformaceTest::handle = nullptr;
TestAudioManagerRelease AudioIdlHdiAdapterPerformaceTest::managerRelease = nullptr;
TestAudioAdapterRelease AudioIdlHdiAdapterPerformaceTest::adapterRelease = nullptr;
TestAudioRenderRelease AudioIdlHdiAdapterPerformaceTest::renderRelease = nullptr;
TestAudioCaptureRelease AudioIdlHdiAdapterPerformaceTest::captureRelease = nullptr;
struct IAudioAdapter *AudioIdlHdiAdapterPerformaceTest::adapter = nullptr;
struct AudioPort AudioIdlHdiAdapterPerformaceTest::audioPort = {};

void AudioIdlHdiAdapterPerformaceTest::SetUpTestCase(void)
{
    int32_t ret = LoadFuctionSymbol(handle, getAudioManager, managerRelease, adapterRelease);
    ASSERT_EQ(HDF_SUCCESS, ret);
    renderRelease = (TestAudioRenderRelease)(dlsym(handle, "AudioRenderRelease"));
    ASSERT_NE(nullptr, renderRelease);
    captureRelease = (TestAudioCaptureRelease)(dlsym(handle, "AudioCaptureRelease"));
    ASSERT_NE(nullptr, captureRelease);
    (void)HdfRemoteGetCallingPid();
    manager = getAudioManager(IDL_SERVER_NAME.c_str());
    ASSERT_NE(nullptr, manager);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    ASSERT_EQ(HDF_SUCCESS, ret);
}

void AudioIdlHdiAdapterPerformaceTest::TearDownTestCase(void)
{
    if (manager != nullptr || manager->UnloadAdapter != nullptr || adapter != nullptr) {
        int32_t ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
        EXPECT_EQ(HDF_SUCCESS, ret);
        adapterRelease(adapter);
        free(audioPort.portName);
    }
    if (managerRelease != nullptr && manager != nullptr) {
        (void)managerRelease(manager);
    }
    if (handle != nullptr) {
        (void)dlclose(handle);
    }
}

void AudioIdlHdiAdapterPerformaceTest::SetUp(void) {}

void AudioIdlHdiAdapterPerformaceTest::TearDown(void) {}
/**
* @tc.name  Audio_HDI_ManagerInitAllPorts_Performance_001
* @tc.desc  tests the performace of InitAllPorts interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiAdapterPerformaceTest, Audio_HDI_ManagerInitAllPorts_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .adapter = adapter, .delayTime = 0, .totalTime = 0, .averageDelayTime =0,
    };
    ASSERT_NE(nullptr, audiopara.adapter);

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
}
/**
* @tc.name  Audio_HDI_GetPortCapability_Performance_001
* @tc.desc  tests the performace of GetPortCapability interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiAdapterPerformaceTest, Audio_HDI_GetPortCapability_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .adapter = adapter, .delayTime = 0, .totalTime = 0, .averageDelayTime =0,
    };
    ASSERT_NE(nullptr, audiopara.adapter);
    ret = audiopara.adapter->InitAllPorts(audiopara.adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        struct AudioPortCapability *capability = nullptr;
        capability = (struct AudioPortCapability*)OsalMemCalloc(sizeof(struct AudioPortCapability));
        ASSERT_NE(nullptr, capability);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.adapter->GetPortCapability(audiopara.adapter, &audioPort, capability);
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
}
/**
* @tc.name  Audio_HDI_SetPassthroughMode_Performance_001
* @tc.desc  tests the performace of SetPassthroughMode interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiAdapterPerformaceTest, Audio_HDI_SetPassthroughMode_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .adapter = adapter, .mode = PORT_PASSTHROUGH_LPCM, .delayTime = 0, .totalTime = 0, .averageDelayTime =0,
    };
    ASSERT_NE(nullptr, audiopara.adapter);
    ret = audiopara.adapter->InitAllPorts(audiopara.adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    for (int i = 0; i < COUNT; ++i) {
        AudioPortPassthroughMode mode = PORT_PASSTHROUGH_AUTO;
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.adapter->SetPassthroughMode(audiopara.adapter, &audioPort, audiopara.mode);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = audiopara.adapter->GetPassthroughMode(audiopara.adapter, &audioPort, &mode);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(PORT_PASSTHROUGH_LPCM, mode);
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}
/**
* @tc.name  Audio_HDI_GetPassthroughMode_Performance_001
* @tc.desc  tests the performace of GetPassthroughMode interface by executing 1000 times,
* and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiAdapterPerformaceTest, Audio_HDI_GetPassthroughMode_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .adapter = adapter, .mode = PORT_PASSTHROUGH_LPCM, .delayTime = 0, .totalTime = 0, .averageDelayTime =0,
    };
    ASSERT_NE(nullptr, audiopara.adapter);
    ret = audiopara.adapter->InitAllPorts(audiopara.adapter);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = audiopara.adapter->SetPassthroughMode(audiopara.adapter, &audioPort, audiopara.mode);
    EXPECT_EQ(HDF_SUCCESS, ret);

    for (int i = 0; i < COUNT; ++i) {
        AudioPortPassthroughMode mode = PORT_PASSTHROUGH_AUTO;
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.adapter->GetPassthroughMode(audiopara.adapter, &audioPort, &mode);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        EXPECT_EQ(PORT_PASSTHROUGH_LPCM, mode);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}
/**
* @tc.name  Audio_HDI_CreateRender_Performance_001
* @tc.desc  tests the performace of CreateRender interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiAdapterPerformaceTest, Audio_HDI_CreateRender_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .adapter = adapter, .delayTime = 0, .totalTime = 0, .averageDelayTime =0, .pins = PIN_OUT_SPEAKER
    };
    ASSERT_NE(nullptr, audiopara.adapter);
    InitAttrs(audiopara.attrs);
    InitDevDesc(audiopara.devDesc, audioPort.portId, audiopara.pins);

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
        renderRelease(audiopara.render);
        audiopara.render = nullptr;
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    free(audiopara.devDesc.desc);
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(HIGHLATENCY, audiopara.averageDelayTime);
}
/**
* @tc.name  Audio_HDI_DestroyRender_Performance_001
* @tc.desc  tests the performace of DestroyRender interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiAdapterPerformaceTest, Audio_HDI_DestroyRender_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .adapter = adapter, .delayTime = 0, .totalTime = 0, .averageDelayTime =0, .pins = PIN_OUT_SPEAKER
    };
    ASSERT_NE(nullptr, audiopara.adapter);
    InitAttrs(audiopara.attrs);
    InitDevDesc(audiopara.devDesc, audioPort.portId, audiopara.pins);

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
    free(audiopara.devDesc.desc);
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}
/**
* @tc.name  Audio_HDI_CreateCapture_Performance_001
* @tc.desc  tests the performace of AudioCreateCapture interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiAdapterPerformaceTest, Audio_HDI_CreateCapture_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .adapter = adapter, .delayTime = 0, .averageDelayTime =0, .totalTime = 0, .pins = PIN_IN_MIC
    };
    ASSERT_NE(nullptr, audiopara.adapter);
    InitAttrs(audiopara.attrs);
    InitDevDesc(audiopara.devDesc, audioPort.portId, audiopara.pins);
    for (int i = 0; i < COUNT; ++i) {
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.adapter->CreateCapture(audiopara.adapter, &audiopara.devDesc, &audiopara.attrs,
                                               &audiopara.capture);
        gettimeofday(&audiopara.end, NULL);
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
        ret = audiopara.adapter->DestroyCapture(audiopara.adapter);
        captureRelease(audiopara.capture);
        audiopara.capture = nullptr;
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    free(audiopara.devDesc.desc);
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(HIGHLATENCY, audiopara.averageDelayTime);
}
/**
* @tc.name  Audio_HDI_DestroyCapture_Performance_001
* @tc.desc  tests the performace of AudioDestroyCapture interface by executing 1000 times,
*              and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiAdapterPerformaceTest, Audio_HDI_DestroyCapture_Performance_001, TestSize.Level1)
{
    int32_t ret;
    struct PrepareAudioPara audiopara = {
        .adapter = adapter, .delayTime = 0, .totalTime = 0, .averageDelayTime =0, .pins = PIN_IN_MIC
    };
    ASSERT_NE(nullptr, audiopara.adapter);
    InitAttrs(audiopara.attrs);
    InitDevDesc(audiopara.devDesc, audioPort.portId, audiopara.pins);
    for (int i = 0; i < COUNT; ++i) {
        ret = audiopara.adapter->CreateCapture(audiopara.adapter, &audiopara.devDesc, &audiopara.attrs,
                                               &audiopara.capture);
        ASSERT_EQ(HDF_SUCCESS, ret);
        gettimeofday(&audiopara.start, NULL);
        ret = audiopara.adapter->DestroyCapture(audiopara.adapter);
        captureRelease(audiopara.capture);
        gettimeofday(&audiopara.end, NULL);
        EXPECT_EQ(HDF_SUCCESS, ret);
        audiopara.capture = nullptr;
        audiopara.delayTime = (audiopara.end.tv_sec * MICROSECOND + audiopara.end.tv_usec) -
                              (audiopara.start.tv_sec * MICROSECOND + audiopara.start.tv_usec);
        audiopara.totalTime += audiopara.delayTime;
    }
    free(audiopara.devDesc.desc);
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}
}
