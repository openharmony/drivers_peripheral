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
class AudioIdlHdiManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static TestAudioManager *(*GetAudioManager)(const char *);
    static TestAudioManager *manager;
    static void *handleSo;
    static void (*AudioManagerRelease)(struct AudioManager *);
    static void (*AudioAdapterRelease)(struct AudioAdapter *);
};

TestAudioManager *(*AudioIdlHdiManagerTest::GetAudioManager)(const char *) = nullptr;
TestAudioManager *AudioIdlHdiManagerTest::manager = nullptr;
void *AudioIdlHdiManagerTest::handleSo = nullptr;
void (*AudioIdlHdiManagerTest::AudioManagerRelease)(struct AudioManager *) = nullptr;
void (*AudioIdlHdiManagerTest::AudioAdapterRelease)(struct AudioAdapter *) = nullptr;

void AudioIdlHdiManagerTest::SetUpTestCase(void)
{
    char absPath[PATH_MAX] = {0};
    char *path = realpath(RESOLVED_PATH.c_str(), absPath);
    ASSERT_NE(nullptr, path);
    handleSo = dlopen(absPath, RTLD_LAZY);
    ASSERT_NE(nullptr, handleSo);
    GetAudioManager = (TestAudioManager *(*)(const char *))(dlsym(handleSo, FUNCTION_NAME.c_str()));
    ASSERT_NE(nullptr, GetAudioManager);
    (void)HdfRemoteGetCallingPid();
    manager = GetAudioManager(IDL_SERVER_NAME.c_str());
    ASSERT_NE(nullptr, manager);
    AudioManagerRelease = (void (*)(struct AudioManager *))(dlsym(handleSo, "AudioManagerRelease"));
    ASSERT_NE(nullptr, AudioManagerRelease);
    AudioAdapterRelease = (void (*)(struct AudioAdapter *))(dlsym(handleSo, "AudioAdapterRelease"));
    ASSERT_NE(nullptr, AudioAdapterRelease);
}

void AudioIdlHdiManagerTest::TearDownTestCase(void)
{
    if (AudioManagerRelease !=nullptr) {
        AudioManagerRelease(manager);
        manager = nullptr;
    }
    if (GetAudioManager != nullptr) {
        GetAudioManager = nullptr;
    }
    if (handleSo != nullptr) {
        dlclose(handleSo);
        handleSo = nullptr;
    }
}

void AudioIdlHdiManagerTest::SetUp(void) {}
void AudioIdlHdiManagerTest::TearDown(void) {}

/**
* @tc.name  Test GetAllAdapters API via legal input
* @tc.number  SUB_Audio_HDI_GetAllAdapters_001
* @tc.desc  test GetAllAdapters interface，Returns 0 if the list is obtained successfully
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiManagerTest, SUB_Audio_HDI_GetAllAdapters_001, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t descsLen = AUDIO_ADAPTER_MAX_NUM;
    struct AudioAdapterDescriptor *descs = nullptr;
    descs = (struct AudioAdapterDescriptor*)OsalMemCalloc(
        sizeof(struct AudioAdapterDescriptor) * (AUDIO_ADAPTER_MAX_NUM));
    ASSERT_NE(nullptr, descs);
    ASSERT_NE(nullptr, manager);

    ret = manager->GetAllAdapters(manager, descs, &descsLen);
    EXPECT_EQ(HDF_SUCCESS, ret);
    EXPECT_EQ((uint32_t)AUDIO_ADAPTER_MAX_NUM, descsLen);

    TestReleaseAdapterDescs(&descs, descsLen);
}

/**
* @tc.name  Test GetAllAdapters API via setting the incoming parameter manager is nullptr
* @tc.number  SUB_Audio_HDI_GetAllAdapters_Null_002
* @tc.desc  test GetAllAdapters interface，Returns -3/-4 if the incoming parameter manager is nullptr
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiManagerTest, SUB_Audio_HDI_GetAllAdapters_Null_002, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t descsLen = AUDIO_ADAPTER_MAX_NUM;
    struct AudioAdapterDescriptor *descs = nullptr;
    descs = (struct AudioAdapterDescriptor*)OsalMemCalloc(
        sizeof(struct AudioAdapterDescriptor) * (AUDIO_ADAPTER_MAX_NUM));
    TestAudioManager *managerNull = nullptr;
    ASSERT_NE(nullptr, descs);
    ASSERT_NE(nullptr, manager);

    ret = manager->GetAllAdapters(managerNull, descs, &descsLen);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    OsalMemFree(descs);
    descs = nullptr;
}
#ifdef AUDIO_ADM_PASSTHROUGH
/**
* @tc.name  Test GetAllAdapters API via setting the incoming parameter descs is nullptr
* @tc.number  SUB_Audio_HDI_GetAllAdapters_003
* @tc.desc  test GetAllAdapters interface，Returns -3 if the incoming parameter descs is nullptr
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiManagerTest, SUB_Audio_HDI_GetAllAdapters_Null_003, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t descsLen = AUDIO_ADAPTER_MAX_NUM;
    struct AudioAdapterDescriptor *descs = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = manager->GetAllAdapters(manager, descs, &descsLen);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
}
/**
* @tc.name  Test GetAllAdapters API via setting the incoming parameter descsLen is nullptr
* @tc.number  SUB_Audio_HDI_GetAllAdapters_Null_004
* @tc.desc  test GetAllAdapters interface，Returns -3/-4 if the incoming parameter descsLen is nullptr
* @tc.author: shijie
*/

HWTEST_F(AudioIdlHdiManagerTest, SUB_Audio_HDI_GetAllAdapters_Null_004, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t* descsLen = nullptr;
    struct AudioAdapterDescriptor *descs = nullptr;
    descs = (struct AudioAdapterDescriptor*)OsalMemCalloc(
        sizeof(struct AudioAdapterDescriptor) * (AUDIO_ADAPTER_MAX_NUM));
    ASSERT_NE(nullptr, descs);
    ASSERT_NE(nullptr, manager);

    ret = manager->GetAllAdapters(manager, descs, descsLen);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    OsalMemFree(descs);
    descs = nullptr;
}
#endif
/**
* @tc.name  Test GetAllAdapters API in server module via setting the incoming descsLen is too small
* @tc.number  SUB_Audio_HDI_GetAllAdapters_005
* @tc.desc  test GetAllAdapters interface，Returns -7001 if the incoming parameter descsLen is too small
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiManagerTest, SUB_Audio_HDI_GetAllAdapters_005, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t descsLen = AUDIO_ADAPTER_MAX_NUM;
    struct AudioAdapterDescriptor *descs = nullptr;
    descs = (struct AudioAdapterDescriptor*)OsalMemCalloc(
        sizeof(struct AudioAdapterDescriptor) * (AUDIO_ADAPTER_MAX_NUM));
    ASSERT_NE(nullptr, descs);
    ASSERT_NE(nullptr, manager);

    descsLen = 2;
    ret = manager->GetAllAdapters(manager, descs, &descsLen);
    EXPECT_EQ(AUDIO_HAL_ERR_NOTREADY, ret);
    OsalMemFree(descs);
    descs = nullptr;
}

/**
* @tc.name  Test LoadAdapter API via legal input
* @tc.number  SUB_Audio_HDI_LoadAdapter_001
* @tc.desc  test LoadAdapter interface，Returns 0 if the driver is loaded successfully
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiManagerTest, SUB_Audio_HDI_LoadAdapter_001, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t descsLen = AUDIO_ADAPTER_MAX_NUM;
    struct AudioAdapterDescriptor *descs = nullptr;
    struct AudioAdapter *adapter = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = GetAdapters(manager, descs, descsLen);
    ASSERT_EQ(HDF_SUCCESS, ret);
    struct AudioAdapterDescriptor *desc = &descs[0];
    ASSERT_TRUE(desc != nullptr);
    ret = manager->LoadAdapter(manager, desc, &adapter);
    ASSERT_EQ(HDF_SUCCESS, ret);
    ret = -1;
    if (adapter != nullptr) {
        if (adapter->InitAllPorts != nullptr && adapter->CreateRender != nullptr &&
            adapter->DestroyRender != nullptr && adapter->CreateCapture != nullptr &&
            adapter->DestroyCapture != nullptr && adapter->GetPortCapability != nullptr &&
            adapter->SetPassthroughMode != nullptr && adapter->GetPassthroughMode != nullptr) {
            ret = 0;
        }
    }
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = manager->UnloadAdapter(manager, desc->adapterName);
    EXPECT_EQ(HDF_SUCCESS, ret);
    TestReleaseAdapterDescs(&descs, descsLen);
    AudioAdapterRelease(adapter);
}

/**
* @tc.name  Test LoadAdapter API via setting the adapterName of incoming parameter manager is nullptr
* @tc.number  SUB_Audio_HDI_LoadAdapter_Null_002
* @tc.desc  test LoadAdapter interface，Returns -3/-4 if the incoming parameter manager is nullptr
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiManagerTest, SUB_Audio_HDI_LoadAdapter_Null_002, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t descsLen = AUDIO_ADAPTER_MAX_NUM;
    struct AudioAdapterDescriptor *descs = nullptr;
    TestAudioManager *managerNull = nullptr;
    struct AudioAdapter *adapter = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = GetAdapters(manager, descs, descsLen);
    ASSERT_EQ(HDF_SUCCESS, ret);
    struct AudioAdapterDescriptor *desc = &descs[0];
    ASSERT_TRUE(desc != nullptr);
    ret = manager->LoadAdapter(managerNull, desc, &adapter);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    TestReleaseAdapterDescs(&descs, descsLen);
}
#ifdef AUDIO_ADM_PASSTHROUGH
/**
* @tc.name  Test LoadAdapter API via setting the adapterName of incoming parameter desc is nullptr
* @tc.number  SUB_Audio_HDI_LoadAdapter_Null_003
* @tc.desc  test LoadAdapter interface，Returns -3 if the incoming parameter desc is nullptr
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiManagerTest, SUB_Audio_HDI_LoadAdapter_Null_003, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t descsLen = AUDIO_ADAPTER_MAX_NUM;
    struct AudioAdapterDescriptor *desc = nullptr;
    struct AudioAdapterDescriptor *descs = nullptr;
    struct AudioAdapter *adapter = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = GetAdapters(manager, descs, descsLen);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ret = manager->LoadAdapter(manager, desc, &adapter);
    ASSERT_EQ(HDF_ERR_INVALID_PARAM, ret);
    TestReleaseAdapterDescs(&descs, descsLen);
}
/**
* @tc.name  Test LoadAdapter API via setting the adapterName of incoming parameter adapter is nullptr
* @tc.number  SUB_Audio_HDI_LoadAdapter_Null_004
* @tc.desc  test LoadAdapter interface，Returns -3/-4 if the incoming parameter adapter is nullptr
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiManagerTest, SUB_Audio_HDI_LoadAdapter_Null_004, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t descsLen = AUDIO_ADAPTER_MAX_NUM;
    struct AudioAdapterDescriptor *descs = nullptr;
    struct AudioAdapter **adapter = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = GetAdapters(manager, descs, descsLen);
    ASSERT_EQ(HDF_SUCCESS, ret);
    struct AudioAdapterDescriptor *desc = &descs[0];
    ASSERT_TRUE(desc != nullptr);

    ret = manager->LoadAdapter(manager, desc, adapter);
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    TestReleaseAdapterDescs(&descs, descsLen);
}
#endif
/**
* @tc.name  Test LoadAdapter API via changing the adapterName of incoming parameter desc
* @tc.number  SUB_Audio_HDI_LoadAdapter_005
* @tc.desc  test LoadAdapter interface，Returns -3 if the adapterName of incoming parameter desc is not support
* @tc.author: shijie
*/

HWTEST_F(AudioIdlHdiManagerTest, SUB_Audio_HDI_LoadAdapter_005, TestSize.Level1)
{
    int32_t ret = -1;
    uint32_t descsLen = AUDIO_ADAPTER_MAX_NUM;
    struct AudioAdapterDescriptor *descs = nullptr;
    struct AudioAdapter *adapter = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = GetAdapters(manager, descs, descsLen);
    ASSERT_EQ(HDF_SUCCESS, ret);
    struct AudioAdapterDescriptor *desc = &descs[0];
    ASSERT_TRUE(desc != nullptr);
    desc->adapterName = strdup("illegal");
    ret = manager->LoadAdapter(manager, desc, &adapter);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    TestReleaseAdapterDescs(&descs, descsLen);
}

/**
* @tc.name  Test LoadAdapter API via setting the adapterName of incoming parameter desc  is illegal
* @tc.number  SUB_Audio_HDI_LoadAdapter_006
* @tc.desc  test LoadAdapter interface，Returns -3 if the adapterName of incoming parameter desc is illegal
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiManagerTest, SUB_Audio_HDI_LoadAdapter_006, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioAdapterDescriptor desc = {
        .adapterName = strdup("illegal"),
        .ports = nullptr,
        .portsLen = 0,
    };
    struct AudioAdapter *adapter = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = manager->LoadAdapter(manager, &desc, &adapter);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    free(desc.adapterName);
}

/**
* @tc.name  Test LoadAdapter API via changing the adapterName of incoming parameter desc
* @tc.number  SUB_Audio_HDI_LoadAdapter_007
* @tc.desc  test LoadAdapter interface，Returns 0 if If two different sound cards are loaded at the same time
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiManagerTest, SUB_Audio_HDI_LoadAdapter_007, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort audioPort = {};
    struct AudioPort audioPort2 = {};
    struct AudioAdapter *adapter1 = nullptr;
    struct AudioAdapter *adapter2 = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter1, audioPort);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME_OUT, &adapter2, audioPort2);
    EXPECT_EQ(HDF_SUCCESS, ret);

    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = manager->UnloadAdapter(manager, ADAPTER_NAME_OUT.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioAdapterRelease(adapter1);
    AudioAdapterRelease(adapter2);
    if (audioPort.portName != nullptr) {
        free(audioPort.portName);
    }
    if (audioPort2.portName != nullptr) {
        free(audioPort2.portName);
    }
}
/**
* @tc.name  Test LoadAdapter API via changing the adapterName of incoming parameter desc
* @tc.number  SUB_Audio_HDI_LoadAdapter_008
* @tc.desc  test LoadAdapter interface，Load two sound cards at the same time, Returns 0 If the loading is successful,
            Return - 1 If the loading fails.
*/
HWTEST_F(AudioIdlHdiManagerTest, SUB_Audio_HDI_LoadAdapter_008, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort audioPort = {};
    struct AudioPort audioPort2 = {};
    struct AudioAdapter *adapter1 = nullptr;
    struct AudioAdapter *adapter2 = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter1, audioPort);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter2, audioPort2);
    EXPECT_EQ(HDF_FAILURE, ret);

    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioAdapterRelease(adapter1);
    if (audioPort.portName != nullptr) {
        free(audioPort.portName);
    }
    if (audioPort2.portName != nullptr) {
        free(audioPort2.portName);
    }
}
/**
* @tc.name  Test UnloadAdapter API via legal input
* @tc.number  SUB_Audio_HDI_UnloadAdapter_001
* @tc.desc  test UnloadAdapter interface，Returns 0 if If the sound card can be successfully uninstalled
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiManagerTest, SUB_Audio_HDI_UnloadAdapter_001, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort audioPort = {};
    struct AudioAdapter *adapter = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioAdapterRelease(adapter);
    if (audioPort.portName != nullptr) {
        free(audioPort.portName);
    }
}
/**
* @tc.name  Test UnloadAdapter API via setting the adapterName of incoming parameter manager is nullptr
* @tc.number  SUB_Audio_HDI_UnloadAdapter_Null_002
* @tc.desc  test UnloadAdapter interface，Returns -3/-4 if the incoming parameter manager is nullptr
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiManagerTest, SUB_Audio_HDI_UnloadAdapter_Null_002, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort audioPort = {};
    struct AudioAdapter *adapter = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    EXPECT_EQ(HDF_SUCCESS, ret);
    TestAudioManager *managerNull = nullptr;
    ret = manager->UnloadAdapter(managerNull, ADAPTER_NAME.c_str());
    EXPECT_EQ(ret == HDF_ERR_INVALID_PARAM || ret == HDF_ERR_INVALID_OBJECT, true);
    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioAdapterRelease(adapter);
    if (audioPort.portName != nullptr) {
        free(audioPort.portName);
    }
}

/**
* @tc.name  Test UnloadAdapter API via setting the adapterName of incoming parameter adapterName is nullptr
* @tc.number  SUB_Audio_HDI_UnloadAdapter_Null_003
* @tc.desc  test UnloadAdapter interface，Returns -3 if the incoming parameter adapterName is nullptr
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiManagerTest, SUB_Audio_HDI_UnloadAdapter_Null_003, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort audioPort = {};
    struct AudioAdapter *adapter = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    EXPECT_EQ(HDF_SUCCESS, ret);
    char *adapterName = nullptr;
    ret = manager->UnloadAdapter(manager, adapterName);
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioAdapterRelease(adapter);
    if (audioPort.portName != nullptr) {
        free(audioPort.portName);
    }
}

/**
* @tc.name  Test UnloadAdapter API via changing the adapterName of incoming parameter desc
* @tc.number  SUB_Audio_HDI_UnloadAdapter_004
* @tc.desc  test UnloadAdapter interface，Returns -1 if The name of the adapterName is not supported
* @tc.author: shijie
*/
HWTEST_F(AudioIdlHdiManagerTest, SUB_Audio_HDI_UnloadAdapter_004, TestSize.Level1)
{
    int32_t ret = -1;
    struct AudioPort audioPort = {};
    struct AudioAdapter *adapter = nullptr;
    ASSERT_NE(nullptr, manager);

    ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    EXPECT_EQ(HDF_SUCCESS, ret);
    ret = manager->UnloadAdapter(manager, ADAPTER_NAME_OUT.c_str());
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, ret);
    ret = manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
    EXPECT_EQ(HDF_SUCCESS, ret);
    AudioAdapterRelease(adapter);
    if (audioPort.portName != nullptr) {
        free(audioPort.portName);
    }
}
}