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

class AudioIdlHdiManagerPerformaceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static void *handle;
    static TestAudioManager *manager;
    static TestAudioManagerRelease managerRelease;
    static TestGetAudioManager getAudioManager;
    static TestAudioAdapterRelease adapterRelease;
};
using THREAD_FUNC = void *(*)(void *);
TestGetAudioManager AudioIdlHdiManagerPerformaceTest::getAudioManager = nullptr;
TestAudioManager *AudioIdlHdiManagerPerformaceTest::manager = nullptr;
void *AudioIdlHdiManagerPerformaceTest::handle = nullptr;
TestAudioManagerRelease AudioIdlHdiManagerPerformaceTest::managerRelease = nullptr;
TestAudioAdapterRelease AudioIdlHdiManagerPerformaceTest::adapterRelease = nullptr;

void AudioIdlHdiManagerPerformaceTest::SetUpTestCase(void)
{
    int32_t ret = LoadFuctionSymbol(handle, getAudioManager, managerRelease, adapterRelease);
    ASSERT_EQ(HDF_SUCCESS, ret);
    (void)HdfRemoteGetCallingPid();
    manager = getAudioManager(IDL_SERVER_NAME.c_str());
    ASSERT_NE(nullptr, manager);
}

void AudioIdlHdiManagerPerformaceTest::TearDownTestCase(void)
{
    if (managerRelease != nullptr && manager != nullptr) {
        (void)managerRelease(manager);
    }
    if (handle != nullptr) {
        (void)dlclose(handle);
    }
}

void AudioIdlHdiManagerPerformaceTest::SetUp(void) {}

void AudioIdlHdiManagerPerformaceTest::TearDown(void) {}

/**
* @tc.name  Audio_HDI_ManagerGetAllAdapter_Performance_001
* @tc.desc  tests the performace of ManagerGetAllAdapters interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiManagerPerformaceTest, Audio_HDI_ManagerGetAllAdapters_Performance_001, TestSize.Level1)
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
* @tc.name  Audio_HDI_ManagerLoadAdapter_Performance_001
* @tc.desc  tests the performace of ManagerLoadAdapter interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiManagerPerformaceTest, Audio_HDI_ManagerLoadAdapter_Performance_001, TestSize.Level1)
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
        adapterRelease(audiopara.adapter);
        audiopara.adapter = nullptr;
    }
    TestReleaseAdapterDescs(&audiopara.descs, descsLen);
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}

/**
* @tc.name  Audio_HDI_ManagerUnLoadAdapter_Performance_001
* @tc.desc  tests the performace of ManagerLoadAdapter interface by executing 1000 times,
*           and calculates the delay time and average of Delay Time.
* @tc.type: PERF
*/
HWTEST_F(AudioIdlHdiManagerPerformaceTest, Audio_HDI_ManagerUnLoadAdapter_Performance_001, TestSize.Level1)
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
        adapterRelease(audiopara.adapter);
        audiopara.adapter = nullptr;
        if (audiopara.audioPort.portName != nullptr) {
            free(audiopara.audioPort.portName);
        }
    }
    audiopara.averageDelayTime = (float)audiopara.totalTime / COUNT;
    EXPECT_GT(LOWLATENCY, audiopara.averageDelayTime);
}
}
