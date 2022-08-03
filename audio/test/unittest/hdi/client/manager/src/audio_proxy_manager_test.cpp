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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "hdf_dlist.h"
#include "audio_proxy_common_fun_test.h"

using namespace std;
using namespace comfun;
using namespace testing::ext;
namespace {
class AudioProxyManagerTest : public testing::Test {
public:
    uint32_t audioCheck = 0xAAAAAAAA;
    struct AudioManager *manager = nullptr;
    struct AudioManager *(*getAudioManager)(void) = NULL;
    struct AudioAdapterDescriptor *descs = nullptr;
    struct AudioAdapterDescriptor *desc = nullptr;
    struct AudioAdapter *adapter = nullptr;
    void *clientHandle = nullptr;
    virtual void SetUp();
    virtual void TearDown();
};

void AudioProxyManagerTest::SetUp()
{
    clientHandle = GetDynamicLibHandle(RESOLVED_PATH);
    ASSERT_NE(clientHandle, nullptr);
    getAudioManager = (struct AudioManager *(*)())(dlsym(clientHandle, FUNCTION_NAME.c_str()));
    ASSERT_NE(getAudioManager, nullptr);
    manager = getAudioManager();
    ASSERT_NE(manager, nullptr);
    int32_t size = 0;
    ASSERT_EQ(HDF_SUCCESS, manager->GetAllAdapters(manager, &descs, &size));
    desc = &descs[0];
    ASSERT_EQ(HDF_SUCCESS, manager->LoadAdapter(manager, desc, &adapter));
}

void AudioProxyManagerTest::TearDown()
{
    if (manager != nullptr) {
        manager->UnloadAdapter(manager, adapter);
        adapter = nullptr;
        manager->ReleaseAudioManagerObject(manager);
        manager = nullptr;
    }
    if (clientHandle != nullptr) {
        dlclose(clientHandle);
        clientHandle = nullptr;
    }
}

HWTEST_F(AudioProxyManagerTest, ManagerGetAllAdapters_001, TestSize.Level1)
{
    struct AudioManager managerFuncs;
    struct AudioAdapterDescriptor *descs = nullptr;
    int size = 0;
    ASSERT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyManagerGetAllAdapters(nullptr, &descs, &size));
    ASSERT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyManagerGetAllAdapters(&managerFuncs, nullptr, &size));
    ASSERT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyManagerGetAllAdapters(&managerFuncs, &descs, nullptr));
}

HWTEST_F(AudioProxyManagerTest, ManagerGetAllAdapters_002, TestSize.Level1)
{
    struct AudioProxyManager proxyMgr;
    struct AudioManager *managerFuncs = &proxyMgr.impl;
    struct AudioAdapterDescriptor *descs = nullptr;
    int size = 0;
    ASSERT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyManagerGetAllAdapters(managerFuncs, &descs, &size));
}

HWTEST_F(AudioProxyManagerTest, ManagerGetAllAdapters_003, TestSize.Level1)
{
    ASSERT_NE(manager, nullptr);
    int size = 0;
    struct HdfRemoteService *remoteService = nullptr;
    struct HdfRemoteService *usbRemoteService = nullptr;
    struct HdfRemoteService *a2dpRemoteService = nullptr;
    struct AudioProxyManager *proxyManager = CONTAINER_OF(manager, struct AudioProxyManager, impl);
    remoteService = proxyManager->remote;
    usbRemoteService = proxyManager->usbRemote;
    a2dpRemoteService = proxyManager->a2dpRemote;
    proxyManager->remote = nullptr;
    proxyManager->usbRemote = nullptr;
    proxyManager->a2dpRemote = nullptr;
    ASSERT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyManagerGetAllAdapters(manager, &descs, &size));
    proxyManager->remote = remoteService;
    proxyManager->usbRemote = usbRemoteService;
    proxyManager->a2dpRemote = a2dpRemoteService;

    uint32_t audioMagic = proxyManager->audioMagic;
    proxyManager->audioMagic = audioCheck - 1;
    ASSERT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyManagerGetAllAdapters(manager, &descs, &size));
    proxyManager->audioMagic = audioMagic;

    remoteService = nullptr;
    audioMagic = 0;
}

HWTEST_F(AudioProxyManagerTest, ManagerLoadAdapter_001, TestSize.Level1)
{
    struct AudioManager managerFuncs;
    struct AudioAdapterDescriptor descObject;
    const struct AudioAdapterDescriptor *desc = &descObject;
    struct AudioAdapter adapterObject;
    struct AudioAdapter *adapter = &adapterObject;
    ASSERT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyManagerLoadAdapter(nullptr, desc, &adapter));
    ASSERT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyManagerLoadAdapter(&managerFuncs, nullptr, &adapter));
    ASSERT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyManagerLoadAdapter(&managerFuncs, desc, nullptr));
}

HWTEST_F(AudioProxyManagerTest, ManagerLoadAdapter_002, TestSize.Level1)
{
    ASSERT_NE(manager, nullptr);
    struct AudioManager managerFuncs;
    struct AudioAdapterDescriptor descObject;
    const struct AudioAdapterDescriptor *desc = &descObject;
    struct AudioAdapter adapterObject;
    struct AudioAdapter *adapter = &adapterObject;

    struct HdfRemoteService *remoteService = nullptr;
    struct AudioProxyManager *proxyManager = CONTAINER_OF(manager, struct AudioProxyManager, impl);

    ASSERT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyManagerLoadAdapter(&managerFuncs, desc, &adapter));

    remoteService = proxyManager->remote;
    proxyManager->remote = nullptr;
    ASSERT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyManagerLoadAdapter(manager, desc, &adapter));
    proxyManager->remote = remoteService;

    uint32_t audioMagic = proxyManager->audioMagic;
    proxyManager->audioMagic = audioCheck - 1;
    ASSERT_EQ(AUDIO_HAL_ERR_INVALID_PARAM, AudioProxyManagerLoadAdapter(manager, desc, &adapter));
    proxyManager->audioMagic = audioMagic;

    remoteService = nullptr;
    audioMagic = 0;
}
}

