/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <atomic>
#include <climits>
#include <cstring>
#include <gtest/gtest.h>
#include <thread>
#include <vector>

#include "hdf_dlist.h"
#include "osal_mem.h"
#include "v6_1/audio_types.h"
#include "v6_1/iaudio_adapter.h"
#include "v6_1/iaudio_manager.h"

using namespace std;
using namespace testing::ext;

#define AUDIO_ADAPTER_NUM_MAX 5
#define AUDIO_THREAD_NUM      4

namespace {
static void ReleaseAdapterDescs(struct AudioAdapterDescriptor **descs, uint32_t descsLen)
{
    if ((descsLen > 0) && (descs != nullptr) && ((*descs) != nullptr)) {
        for (uint32_t i = 0; i < descsLen; i++) {
            AudioAdapterDescriptorFree(&(*descs)[i], false);
        }
        OsalMemFree(*descs);
        *descs = nullptr;
    }
}

class HdfAudioConcManagerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
};

HWTEST_F(HdfAudioConcManagerTest, HdfAudioManagerConcGetAllAdaptersMutiThread001, TestSize.Level1)
{
    std::atomic<int32_t> successCnt(0);
    std::vector<std::thread> threads;
    for (uint32_t i = 0; i < AUDIO_THREAD_NUM; i++) {
        threads.push_back(std::thread([&successCnt]() {
            struct IAudioManager *manager = IAudioManagerGet(false);
            if (manager == nullptr) {
                return;
            }
            uint32_t size = AUDIO_ADAPTER_NUM_MAX;
            struct AudioAdapterDescriptor *descs = (struct AudioAdapterDescriptor *)OsalMemCalloc(
                sizeof(struct AudioAdapterDescriptor) * (AUDIO_ADAPTER_NUM_MAX));
            if (descs == nullptr) {
                IAudioManagerRelease(manager, false);
                return;
            }
            if (manager->GetAllAdapters(manager, descs, &size) == HDF_SUCCESS) {
                successCnt++;
            }
            ReleaseAdapterDescs(&descs, AUDIO_ADAPTER_NUM_MAX);
            IAudioManagerRelease(manager, false);
        }));
    }
    for (auto &thread : threads) {
        thread.join();
    }
    EXPECT_EQ(AUDIO_THREAD_NUM, successCnt.load());
}

HWTEST_F(HdfAudioConcManagerTest, HdfAudioManagerConcLoadAdapterMutiThread001, TestSize.Level1)
{
    struct IAudioManager *manager = IAudioManagerGet(false);
    ASSERT_NE(manager, nullptr);

    uint32_t size = AUDIO_ADAPTER_NUM_MAX;
    struct AudioAdapterDescriptor *descs = (struct AudioAdapterDescriptor *)OsalMemCalloc(
        sizeof(struct AudioAdapterDescriptor) * (AUDIO_ADAPTER_NUM_MAX));
    ASSERT_NE(descs, nullptr);
    ASSERT_EQ(HDF_SUCCESS, manager->GetAllAdapters(manager, descs, &size));
    ASSERT_GT(size, 0);

    std::atomic<int32_t> loadCnt(0);
    std::atomic<int32_t> unloadCnt(0);
    std::vector<std::thread> threads;
    for (uint32_t i = 0; i < AUDIO_THREAD_NUM; i++) {
        threads.push_back(std::thread([&loadCnt, &unloadCnt, manager, descs]() {
            struct IAudioAdapter *adapter = nullptr;
            if (manager->LoadAdapter(manager, &descs[0], &adapter) != HDF_SUCCESS) {
                return;
            }
            loadCnt++;
            if (manager->UnloadAdapter(manager, descs[0].adapterName) == HDF_SUCCESS) {
                unloadCnt++;
            }
        }));
    }
    for (auto &thread : threads) {
        thread.join();
    }

    ReleaseAdapterDescs(&descs, AUDIO_ADAPTER_NUM_MAX);
    IAudioManagerRelease(manager, false);

    EXPECT_EQ(AUDIO_THREAD_NUM, loadCnt.load());
    EXPECT_EQ(AUDIO_THREAD_NUM, unloadCnt.load());
}

} // namespace
