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

#include <benchmark/benchmark.h>
#include <climits>
#include <gtest/gtest.h>
#include "hdf_base.h"
#include "osal_mem.h"
#include "v5_0/iaudio_manager.h"

using namespace testing::ext;
using namespace std;

namespace {
static const uint32_t g_audioAdapterNumMax = 5;
const int32_t ITERATION_FREQUENCY = 100;
const int32_t REPETITION_FREQUENCY = 3;

class AudioManagerBenchmarkTest : public benchmark::Fixture {
public:
    struct IAudioManager *manager_ = nullptr;
    struct AudioAdapterDescriptor *adapterDescs_ = nullptr;
    void SetUp(const ::benchmark::State &state);
    void TearDown(const ::benchmark::State &state);
    void AudioAdapterDescriptorFree(struct AudioAdapterDescriptor *dataBlock, bool freeSelf);
    void ReleaseAdapterDescs(struct AudioAdapterDescriptor *descs, uint32_t descsLen);
};

void AudioManagerBenchmarkTest::AudioAdapterDescriptorFree(struct AudioAdapterDescriptor *dataBlock, bool freeSelf)
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

void AudioManagerBenchmarkTest::ReleaseAdapterDescs(struct AudioAdapterDescriptor *descs, uint32_t descsLen)
{
    if ((descs == nullptr) || (descsLen == 0)) {
        return;
    }

    for (uint32_t i = 0; i < descsLen; i++) {
        AudioAdapterDescriptorFree(&descs[i], false);
    }
}

void AudioManagerBenchmarkTest::SetUp(const ::benchmark::State &state)
{
    manager_ = IAudioManagerGet(false);
    ASSERT_NE(manager_, nullptr);
}

void AudioManagerBenchmarkTest::TearDown(const ::benchmark::State &state)
{
    IAudioManagerRelease(manager_, false);
}

BENCHMARK_F(AudioManagerBenchmarkTest, GetAllAdapters)(benchmark::State &state)
{
    ASSERT_NE(manager_, nullptr);
    int32_t ret;
    uint32_t size = g_audioAdapterNumMax;
    adapterDescs_ = (struct AudioAdapterDescriptor *)OsalMemCalloc(
        sizeof(struct AudioAdapterDescriptor) * (g_audioAdapterNumMax));
    ASSERT_NE(adapterDescs_, nullptr);

    for (auto _ : state) {
        ret = manager_->GetAllAdapters(manager_, adapterDescs_, &size);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    ReleaseAdapterDescs(adapterDescs_, g_audioAdapterNumMax);
}

BENCHMARK_REGISTER_F(AudioManagerBenchmarkTest, GetAllAdapters)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_F(AudioManagerBenchmarkTest, LoadAdapterAndUnloadAdapter)(benchmark::State &state)
{
    ASSERT_NE(manager_, nullptr);
    int32_t ret;
    uint32_t size = g_audioAdapterNumMax;
    struct IAudioAdapter *adapter = nullptr;
    adapterDescs_ = (struct AudioAdapterDescriptor *)OsalMemCalloc(
        sizeof(struct AudioAdapterDescriptor) * (g_audioAdapterNumMax));
    ASSERT_NE(adapterDescs_, nullptr);
    ret = manager_->GetAllAdapters(manager_, adapterDescs_, &size);
    EXPECT_EQ(HDF_SUCCESS, ret);

    for (auto _ : state) {
        ret = manager_->LoadAdapter(manager_, &adapterDescs_[0], &adapter);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (auto _ : state) {
        ret = manager_->UnloadAdapter(manager_, adapterDescs_[0].adapterName);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
    ReleaseAdapterDescs(adapterDescs_, g_audioAdapterNumMax);
}

BENCHMARK_REGISTER_F(AudioManagerBenchmarkTest, LoadAdapterAndUnloadAdapter)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();
}

BENCHMARK_MAIN();
