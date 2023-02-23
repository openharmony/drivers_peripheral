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

#include <gtest/gtest.h>
#include <climits>
#include "hdf_dlist.h"
#include "osal_mem.h"
#include "v1_0/iaudio_manager.h"

using namespace std;
using namespace testing::ext;
namespace {
static const uint32_t g_audioAdapterNumMax = 5;

class AudioUtManagerTest : public testing::Test {
public:
    struct IAudioManager *manager_ = nullptr;
    virtual void SetUp();
    virtual void TearDown();
    void AudioAdapterDescriptorFree(struct AudioAdapterDescriptor *dataBlock, bool freeSelf);
    void ReleaseAdapterDescs(struct AudioAdapterDescriptor **descs, uint32_t descsLen);
};

void AudioUtManagerTest::AudioAdapterDescriptorFree(struct AudioAdapterDescriptor *dataBlock, bool freeSelf)
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

void AudioUtManagerTest::ReleaseAdapterDescs(struct AudioAdapterDescriptor **descs, uint32_t descsLen)
{
    if ((descsLen > 0) && (descs != nullptr) && ((*descs) != nullptr)) {
        for (uint32_t i = 0; i < descsLen; i++) {
            AudioAdapterDescriptorFree(&(*descs)[i], false);
        }
        OsalMemFree(*descs);
        *descs = nullptr;
    }
}
void AudioUtManagerTest::SetUp()
{
    manager_ = IAudioManagerGet(false);
    ASSERT_NE(manager_, nullptr);
}

void AudioUtManagerTest::TearDown()
{
}

HWTEST_F(AudioUtManagerTest, ManagerGetAllAdaptersNull001, TestSize.Level1)
{
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, manager_->GetAllAdapters(nullptr, nullptr, nullptr));
}

HWTEST_F(AudioUtManagerTest, ManagerGetAllAdaptersNull002, TestSize.Level1)
{
    uint32_t size = 0;
    struct AudioAdapterDescriptor descs;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, manager_->GetAllAdapters(nullptr, &descs, &size));
}

HWTEST_F(AudioUtManagerTest, ManagerGetAllAdaptersNull003, TestSize.Level1)
{
    uint32_t size = 0;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, manager_->GetAllAdapters(manager_, nullptr, &size));
}

HWTEST_F(AudioUtManagerTest, ManagerGetAllAdaptersNull004, TestSize.Level1)
{
    struct AudioAdapterDescriptor descs;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, manager_->GetAllAdapters(manager_, &descs, nullptr));
}

HWTEST_F(AudioUtManagerTest, ManagerGetAllAdaptersParaInvalid001, TestSize.Level1)
{
    uint32_t size = 0;
    struct AudioAdapterDescriptor descs;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, manager_->GetAllAdapters(manager_, &descs, &size));
}

HWTEST_F(AudioUtManagerTest, ManagerGetAllAdaptersParaInvalid002, TestSize.Level1)
{
    uint32_t size = UINT_MAX;
    struct AudioAdapterDescriptor descs;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, manager_->GetAllAdapters(manager_, &descs, &size));
}

HWTEST_F(AudioUtManagerTest, ManagerGetAllAdaptersSizeIsValid_001, TestSize.Level1)
{
    uint32_t size = g_audioAdapterNumMax;
    struct AudioAdapterDescriptor *descs = (struct AudioAdapterDescriptor *)OsalMemCalloc(
        sizeof(struct AudioAdapterDescriptor) * (g_audioAdapterNumMax));
    if (descs == nullptr) {
        ASSERT_NE(nullptr, descs);
    }
    ASSERT_EQ(HDF_SUCCESS, manager_->GetAllAdapters(manager_, descs, &size));
    EXPECT_GE(g_audioAdapterNumMax, size);
    ReleaseAdapterDescs(&descs, g_audioAdapterNumMax);
}

HWTEST_F(AudioUtManagerTest, ManagerGetAllAdaptersDescsIsValid_001, TestSize.Level1)
{
    uint32_t size = g_audioAdapterNumMax;
    struct AudioAdapterDescriptor *descs = (struct AudioAdapterDescriptor *)OsalMemCalloc(
        sizeof(struct AudioAdapterDescriptor) * (g_audioAdapterNumMax));
    if (descs == nullptr) {
        ASSERT_NE(nullptr, descs);
    }

    EXPECT_EQ(HDF_SUCCESS, manager_->GetAllAdapters(manager_, descs, &size));
    EXPECT_GE(g_audioAdapterNumMax, size);

    for (uint32_t i = 0; i < size; i++) {
        EXPECT_NE(nullptr, descs[i].adapterName);
    }

    ReleaseAdapterDescs(&descs, g_audioAdapterNumMax);
}

HWTEST_F(AudioUtManagerTest, ManagerLoadAdapterNull_001, TestSize.Level1)
{
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, manager_->LoadAdapter(nullptr, nullptr, nullptr));
}

HWTEST_F(AudioUtManagerTest, ManagerLoadAdapterNull_002, TestSize.Level1)
{
    struct AudioAdapterDescriptor descs;
    struct IAudioAdapter *adapter = nullptr;
    EXPECT_EQ(HDF_ERR_INVALID_OBJECT, manager_->LoadAdapter(nullptr, &descs, &adapter));
}

HWTEST_F(AudioUtManagerTest, ManagerLoadAdapterNull_003, TestSize.Level1)
{
    struct IAudioAdapter *adapter = nullptr;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, manager_->LoadAdapter(manager_, nullptr, &adapter));
}

HWTEST_F(AudioUtManagerTest, ManagerLoadAdapterNull_004, TestSize.Level1)
{
    struct AudioAdapterDescriptor descs;
    EXPECT_EQ(HDF_ERR_INVALID_PARAM, manager_->LoadAdapter(manager_, &descs, nullptr));
}

HWTEST_F(AudioUtManagerTest, ManagerLoadAdapterSuccess_001, TestSize.Level1)
{
    uint32_t size = g_audioAdapterNumMax;
    struct IAudioAdapter *adapter = nullptr;

    struct AudioAdapterDescriptor *descs = (struct AudioAdapterDescriptor *)OsalMemCalloc(
        sizeof(struct AudioAdapterDescriptor) * (g_audioAdapterNumMax));
    if (descs == nullptr) {
        ASSERT_NE(nullptr, descs);
    }
    EXPECT_EQ(HDF_SUCCESS, manager_->GetAllAdapters(manager_, descs, &size));

    if (size > g_audioAdapterNumMax) {
        ASSERT_GE(g_audioAdapterNumMax, size);
        ReleaseAdapterDescs(&descs, g_audioAdapterNumMax);
    }

    EXPECT_EQ(HDF_SUCCESS, manager_->LoadAdapter(manager_, &descs[0], &adapter));
    EXPECT_TRUE(adapter != nullptr);
    EXPECT_EQ(HDF_SUCCESS, manager_->UnloadAdapter(manager_, descs[0].adapterName));
    ReleaseAdapterDescs(&descs, g_audioAdapterNumMax);
}

HWTEST_F(AudioUtManagerTest, ManagerLoadAdapterSuccess_002, TestSize.Level1)
{
    uint32_t size = g_audioAdapterNumMax;
    struct IAudioAdapter *firstAdapter = nullptr;
    struct IAudioAdapter *secondAdapter = nullptr;

    struct AudioAdapterDescriptor *descs = (struct AudioAdapterDescriptor *)OsalMemCalloc(
        sizeof(struct AudioAdapterDescriptor) * (g_audioAdapterNumMax));
    if (descs == nullptr) {
        ASSERT_NE(nullptr, descs);
    }
    EXPECT_EQ(HDF_SUCCESS, manager_->GetAllAdapters(manager_, descs, &size));

    if (size > g_audioAdapterNumMax) {
        ASSERT_GE(g_audioAdapterNumMax, size);
        ReleaseAdapterDescs(&descs, g_audioAdapterNumMax);
    }

    EXPECT_EQ(HDF_SUCCESS, manager_->LoadAdapter(manager_, &descs[0], &firstAdapter));
    ASSERT_TRUE(firstAdapter != nullptr);
    EXPECT_EQ(HDF_SUCCESS, manager_->LoadAdapter(manager_, &descs[0], &secondAdapter));
    ASSERT_TRUE(secondAdapter != nullptr);
    EXPECT_EQ(HDF_SUCCESS, manager_->UnloadAdapter(manager_, descs[0].adapterName));
    EXPECT_EQ(HDF_SUCCESS, manager_->UnloadAdapter(manager_, descs[0].adapterName));
    ReleaseAdapterDescs(&descs, g_audioAdapterNumMax);
}
}