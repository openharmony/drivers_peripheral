/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <climits>
#include <gtest/gtest.h>

#include "hdf_dlist.h"
#include "osal_mem.h"
#include "v5_0/iaudio_manager.h"

using namespace std;
using namespace testing::ext;
namespace {
static const uint32_t g_audioAdapterNumMax = 5;
struct IAudioManager *g_manager = nullptr;

class HdfAudioUtManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void AudioAdapterDescriptorFree(struct AudioAdapterDescriptor *dataBlock, bool freeSelf);
    void ReleaseAdapterDescs(struct AudioAdapterDescriptor **descs, uint32_t descsLen);
};

void HdfAudioUtManagerTest::AudioAdapterDescriptorFree(struct AudioAdapterDescriptor *dataBlock, bool freeSelf)
{
    if (dataBlock == nullptr) {
        return;
    }

    if (dataBlock->adapterName != nullptr) {
        OsalMemFree(dataBlock->adapterName);
        dataBlock->adapterName = nullptr;
    }

    if (dataBlock->ports != nullptr) {
        OsalMemFree(dataBlock->ports);
    }

    if (freeSelf) {
        OsalMemFree(dataBlock);
    }
}

void HdfAudioUtManagerTest::ReleaseAdapterDescs(struct AudioAdapterDescriptor **descs, uint32_t descsLen)
{
    if ((descsLen > 0) && (descs != nullptr) && ((*descs) != nullptr)) {
        for (uint32_t i = 0; i < descsLen; i++) {
            AudioAdapterDescriptorFree(&(*descs)[i], false);
        }
        OsalMemFree(*descs);
        *descs = nullptr;
    }
}

void HdfAudioUtManagerTest::SetUp()
{
}

void HdfAudioUtManagerTest::TearDown()
{
}

void HdfAudioUtManagerTest::SetUpTestCase()
{
    g_manager = IAudioManagerGet(false);
    ASSERT_NE(g_manager, nullptr);
}

void HdfAudioUtManagerTest::TearDownTestCase()
{
    IAudioManagerRelease(g_manager, false);
}

HWTEST_F(HdfAudioUtManagerTest, HdfAudioManagerGetVersionNull001, TestSize.Level1)
{
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, g_manager->GetVersion(nullptr, nullptr, nullptr));
}

HWTEST_F(HdfAudioUtManagerTest, HdfAudioManagerGetVersionNull002, TestSize.Level1)
{
    uint32_t version;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, g_manager->GetVersion(nullptr, &version, &version));
}

HWTEST_F(HdfAudioUtManagerTest, HdfAudioManagerGetVersionNull003, TestSize.Level1)
{
    uint32_t version;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, g_manager->GetVersion(g_manager, nullptr, &version));
}

HWTEST_F(HdfAudioUtManagerTest, HdfAudioManagerGetVersionNull004, TestSize.Level1)
{
    uint32_t version;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, g_manager->GetVersion(g_manager, &version, nullptr));
}

HWTEST_F(HdfAudioUtManagerTest, HdfAudioManagerGetVersionIsValid001, TestSize.Level1)
{
    uint32_t majorVer;
    uint32_t minorVer;
    ASSERT_EQ(HDF_SUCCESS, g_manager->GetVersion(g_manager, &majorVer, &minorVer));
    EXPECT_EQ(IAUDIO_MANAGER_MAJOR_VERSION, majorVer);
    EXPECT_EQ(IAUDIO_MANAGER_MINOR_VERSION, minorVer);
}

HWTEST_F(HdfAudioUtManagerTest, HdfAudioManagerGetAllAdaptersNull001, TestSize.Level1)
{
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, g_manager->GetAllAdapters(nullptr, nullptr, nullptr));
}

HWTEST_F(HdfAudioUtManagerTest, HdfAudioManagerGetAllAdaptersNull002, TestSize.Level1)
{
    uint32_t size = 0;
    struct AudioAdapterDescriptor descs;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, g_manager->GetAllAdapters(nullptr, &descs, &size));
}

HWTEST_F(HdfAudioUtManagerTest, HdfAudioManagerGetAllAdaptersNull003, TestSize.Level1)
{
    uint32_t size = 0;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, g_manager->GetAllAdapters(g_manager, nullptr, &size));
}

HWTEST_F(HdfAudioUtManagerTest, HdfAudioManagerGetAllAdaptersParaInvalid001, TestSize.Level1)
{
    uint32_t size = 0;
    struct AudioAdapterDescriptor descs;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, g_manager->GetAllAdapters(g_manager, &descs, &size));
}

HWTEST_F(HdfAudioUtManagerTest, HdfAudioManagerGetAllAdaptersParaInvalid002, TestSize.Level1)
{
    uint32_t size = UINT_MAX;
    struct AudioAdapterDescriptor descs;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, g_manager->GetAllAdapters(g_manager, &descs, &size));
}

HWTEST_F(HdfAudioUtManagerTest, HdfAudioManagerGetAllAdaptersSizeIsValid_001, TestSize.Level0)
{
    uint32_t size = g_audioAdapterNumMax;
    struct AudioAdapterDescriptor *descs = (struct AudioAdapterDescriptor *)OsalMemCalloc(
        sizeof(struct AudioAdapterDescriptor) * (g_audioAdapterNumMax));
    ASSERT_NE(nullptr, descs);
    ASSERT_EQ(HDF_SUCCESS, g_manager->GetAllAdapters(g_manager, descs, &size));
    EXPECT_GE(g_audioAdapterNumMax, size);
    ReleaseAdapterDescs(&descs, g_audioAdapterNumMax);
}

HWTEST_F(HdfAudioUtManagerTest, HdfAudioManagerGetAllAdaptersDescsIsValid_001, TestSize.Level0)
{
    uint32_t size = g_audioAdapterNumMax;
    struct AudioAdapterDescriptor *descs = (struct AudioAdapterDescriptor *)OsalMemCalloc(
        sizeof(struct AudioAdapterDescriptor) * (g_audioAdapterNumMax));
    ASSERT_NE(nullptr, descs);

    ASSERT_EQ(HDF_SUCCESS, g_manager->GetAllAdapters(g_manager, descs, &size));
    EXPECT_GE(g_audioAdapterNumMax, size);

    for (uint32_t i = 0; i < size; i++) {
        EXPECT_NE(nullptr, descs[i].adapterName);
    }

    ReleaseAdapterDescs(&descs, g_audioAdapterNumMax);
}

HWTEST_F(HdfAudioUtManagerTest, HdfAudioManagerLoadAdapterNull_001, TestSize.Level1)
{
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, g_manager->LoadAdapter(nullptr, nullptr, nullptr));
}

HWTEST_F(HdfAudioUtManagerTest, HdfAudioManagerLoadAdapterNull_002, TestSize.Level1)
{
    struct AudioAdapterDescriptor descs;
    struct IAudioAdapter *adapter = nullptr;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, g_manager->LoadAdapter(nullptr, &descs, &adapter));
}

HWTEST_F(HdfAudioUtManagerTest, HdfAudioManagerLoadAdapterNull_003, TestSize.Level1)
{
    struct IAudioAdapter *adapter = nullptr;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, g_manager->LoadAdapter(g_manager, nullptr, &adapter));
}

HWTEST_F(HdfAudioUtManagerTest, HdfAudioManagerLoadAdapterNull_004, TestSize.Level1)
{
    struct AudioAdapterDescriptor descs;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, g_manager->LoadAdapter(g_manager, &descs, nullptr));
}

HWTEST_F(HdfAudioUtManagerTest, HdfAudioManagerLoadAdapterSuccess_001, TestSize.Level0)
{
    uint32_t size = g_audioAdapterNumMax;
    struct IAudioAdapter *adapter = nullptr;

    struct AudioAdapterDescriptor *descs = (struct AudioAdapterDescriptor *)OsalMemCalloc(
        sizeof(struct AudioAdapterDescriptor) * (g_audioAdapterNumMax));
    ASSERT_NE(nullptr, descs);
    ASSERT_EQ(HDF_SUCCESS, g_manager->GetAllAdapters(g_manager, descs, &size));
    if (size > g_audioAdapterNumMax) {
        ReleaseAdapterDescs(&descs, g_audioAdapterNumMax);
        ASSERT_GE(g_audioAdapterNumMax, size);
    }

    ASSERT_EQ(HDF_SUCCESS, g_manager->LoadAdapter(g_manager, &descs[0], &adapter));
    EXPECT_TRUE(adapter != nullptr);
    EXPECT_EQ(HDF_SUCCESS, g_manager->UnloadAdapter(g_manager, descs[0].adapterName));
    ReleaseAdapterDescs(&descs, g_audioAdapterNumMax);
}

HWTEST_F(HdfAudioUtManagerTest, HdfAudioManagerLoadAdapterSuccess_002, TestSize.Level0)
{
    uint32_t size = g_audioAdapterNumMax;
    struct IAudioAdapter *firstAdapter = nullptr;
    struct IAudioAdapter *secondAdapter = nullptr;

    struct AudioAdapterDescriptor *descs = (struct AudioAdapterDescriptor *)OsalMemCalloc(
        sizeof(struct AudioAdapterDescriptor) * (g_audioAdapterNumMax));
    ASSERT_NE(nullptr, descs);
    EXPECT_EQ(HDF_SUCCESS, g_manager->GetAllAdapters(g_manager, descs, &size));

    if (size > g_audioAdapterNumMax) {
        ReleaseAdapterDescs(&descs, g_audioAdapterNumMax);
        ASSERT_GE(g_audioAdapterNumMax, size);
    }

    EXPECT_EQ(HDF_SUCCESS, g_manager->LoadAdapter(g_manager, &descs[0], &firstAdapter));
    EXPECT_TRUE(firstAdapter != nullptr);
    EXPECT_EQ(HDF_SUCCESS, g_manager->LoadAdapter(g_manager, &descs[0], &secondAdapter));
    EXPECT_TRUE(secondAdapter != nullptr);
    EXPECT_EQ(HDF_SUCCESS, g_manager->UnloadAdapter(g_manager, descs[0].adapterName));
    EXPECT_EQ(HDF_SUCCESS, g_manager->UnloadAdapter(g_manager, descs[0].adapterName));

    ReleaseAdapterDescs(&descs, g_audioAdapterNumMax);
}

HWTEST_F(HdfAudioUtManagerTest, HdfAudioManagerReleaseAudioManagerObjectNull_001, TestSize.Level1)
{
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, g_manager->ReleaseAudioManagerObject(nullptr));
}
}