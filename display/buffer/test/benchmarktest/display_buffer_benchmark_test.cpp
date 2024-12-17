/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include <mutex>
#include <chrono>
#include <cinttypes>
#include <algorithm>
#include <condition_variable>
#include <benchmark/benchmark.h>
#include "gtest/gtest.h"
#include "hdf_base.h"
#include "hdf_log.h"
#include "v1_2/display_composer_type.h"
#include "v1_2/display_buffer_type.h"
#include "v1_2/include/idisplay_buffer.h"
using namespace OHOS::HDI::Display::Buffer;
using namespace OHOS::HDI::Display::Buffer::V1_2;
using namespace OHOS::HDI::Display::Composer::V1_0;
using namespace testing::ext;
using OHOS::HDI::Display::Buffer::V1_0::AllocInfo;

const uint32_t ALLOC_SIZE_1080 = 1080; // alloc size 1080
const uint32_t ALLOC_SIZE_1920 = 1920; // alloc size 1920

static std::shared_ptr<V1_2::IDisplayBuffer> g_gralloc = nullptr;
static BufferHandle* g_bufferHandle = nullptr;
static AllocInfo g_allocInfo = {
    .width = ALLOC_SIZE_1920,
    .height = ALLOC_SIZE_1080,
    .usage = HBM_USE_MEM_DMA | HBM_USE_CPU_READ | HBM_USE_CPU_WRITE,
    .format = PIXEL_FMT_RGBX_8888
};

namespace {
class DisplayBenchmarkTest : public benchmark::Fixture {
public:
    void SetUp(const ::benchmark::State &state);
    void TearDown(const ::benchmark::State &state);
};

void DisplayBenchmarkTest::SetUp(const ::benchmark::State &state)
{
    g_gralloc.reset(V1_2::IDisplayBuffer::Get());
    if (g_gralloc == nullptr) {
        HDF_LOGE("IDisplayBuffer get failed");
        ASSERT_TRUE(0);
    }

    int32_t ret = g_gralloc->AllocMem(g_allocInfo, g_bufferHandle);
    if (ret != DISPLAY_SUCCESS || g_bufferHandle == nullptr) {
        HDF_LOGE("AllocMem failed");
        ASSERT_TRUE(ret == DISPLAY_SUCCESS && g_bufferHandle != nullptr);
    }

    ret = g_gralloc->RegisterBuffer(*g_bufferHandle);
    ASSERT_TRUE(ret == DISPLAY_SUCCESS || ret == DISPLAY_NOT_SUPPORT);
}

void DisplayBenchmarkTest::TearDown(const ::benchmark::State &state)
{
    if (g_bufferHandle != nullptr) {
        g_gralloc->FreeMem(*g_bufferHandle);
    }
}

/**
  * @tc.name: SetMetadataTest
  * @tc.desc: Benchmarktest for interface SetMetadata.
  */
BENCHMARK_F(DisplayBenchmarkTest, SetMetadataTest)(benchmark::State &state)
{
    int32_t ret;
    int32_t key = 0;
    for (auto _ : state) {
        std::vector<uint8_t> values(2880, 0);
        ret = g_gralloc->SetMetadata(*g_bufferHandle, key, values);
        EXPECT_TRUE(ret == DISPLAY_SUCCESS || ret == DISPLAY_NOT_SUPPORT);
    }
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, SetMetadataTest)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: GetMetadataTest
  * @tc.desc: Benchmarktest for interface GetMetadata.
  */
BENCHMARK_F(DisplayBenchmarkTest, GetMetadataTest)(benchmark::State &state)
{
    int32_t ret;
    int32_t key = 0;
    for (auto _ : state) {
        std::vector<uint8_t> values(2880, 0);
        ret = g_gralloc->SetMetadata(*g_bufferHandle, key, values);
        EXPECT_TRUE(ret == DISPLAY_SUCCESS || ret == DISPLAY_NOT_SUPPORT);
        std::vector<uint8_t> rets;
        ret = g_gralloc->GetMetadata(*g_bufferHandle, key, rets);
        EXPECT_TRUE(ret == DISPLAY_SUCCESS || ret == DISPLAY_NOT_SUPPORT);
    }
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, GetMetadataTest)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: ListMetadataKeysTest
  * @tc.desc: Benchmarktest for interface ListMetadataKeys.
  */
BENCHMARK_F(DisplayBenchmarkTest, ListMetadataKeysTest)(benchmark::State &state)
{
    int32_t ret;
    int32_t key = 0;
    for (auto _ : state) {
        std::vector<uint32_t> keys;
        std::vector<uint8_t> values(2880, 0);
        ret = g_gralloc->SetMetadata(*g_bufferHandle, key, values);
        EXPECT_TRUE(ret == DISPLAY_SUCCESS || ret == DISPLAY_NOT_SUPPORT);
        ret = g_gralloc->ListMetadataKeys(*g_bufferHandle, keys);
        EXPECT_TRUE(ret == DISPLAY_SUCCESS || ret == DISPLAY_NOT_SUPPORT);
    }
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, ListMetadataKeysTest)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: EraseMetadataKeyTest
  * @tc.desc: Benchmarktest for interface EraseMetadataKey.
  */
BENCHMARK_F(DisplayBenchmarkTest, EraseMetadataKeyTest)(benchmark::State &state)
{
    int32_t ret;
    int32_t key = 0;
    for (auto _ : state) {
        std::vector<uint8_t> values(2880, 0);
        ret = g_gralloc->SetMetadata(*g_bufferHandle, key, values);
        EXPECT_TRUE(ret == DISPLAY_SUCCESS || ret == DISPLAY_NOT_SUPPORT);
        ret = g_gralloc->EraseMetadataKey(*g_bufferHandle, key);
        EXPECT_TRUE(ret == DISPLAY_SUCCESS || ret == DISPLAY_NOT_SUPPORT);
    }
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, EraseMetadataKeyTest)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: SetAllocFreeTest
  * @tc.desc: Benchmarktest for interface AllocMem and FreeMem.
  */
BENCHMARK_F(DisplayBenchmarkTest, SetAllocFreeTest)(benchmark::State &state)
{
    int32_t ret;
    BufferHandle* bufferHandle = nullptr;
    for (auto _ : state) {
        ret = g_gralloc->AllocMem(g_allocInfo, bufferHandle);
        EXPECT_TRUE(ret == DISPLAY_SUCCESS || ret == DISPLAY_NOT_SUPPORT);
        g_gralloc->FreeMem(*bufferHandle);
    }
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, SetAllocFreeTest)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: MmapTest
  * @tc.desc: Benchmarktest for interface Mmap.
  */
BENCHMARK_F(DisplayBenchmarkTest, MmapTest)(benchmark::State &state)
{
    for (auto _ : state) {
        g_gralloc->Mmap(*g_bufferHandle);
    }
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, MmapTest)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: UnmapTest
  * @tc.desc: Benchmarktest for interface Unmap.
  */
BENCHMARK_F(DisplayBenchmarkTest, UnmapTest)(benchmark::State &state)
{
    for (auto _ : state) {
        g_gralloc->Unmap(*g_bufferHandle);
    }
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, UnmapTest)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: FlushCacheTest
  * @tc.desc: Benchmarktest for interface FlushCache.
  */
BENCHMARK_F(DisplayBenchmarkTest, FlushCacheTest)(benchmark::State &state)
{
    for (auto _ : state) {
        g_gralloc->FlushCache(*g_bufferHandle);
    }
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, FlushCacheTest)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: InvalidateCacheTest
  * @tc.desc: Benchmarktest for interface InvalidateCache.
  */
BENCHMARK_F(DisplayBenchmarkTest, InvalidateCacheTest)(benchmark::State &state)
{
    for (auto _ : state) {
        g_gralloc->InvalidateCache(*g_bufferHandle);
    }
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, InvalidateCacheTest)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: GetImageLayoutTest
  * @tc.desc: Benchmarktest for interface GetImageLayout.
  */
BENCHMARK_F(DisplayBenchmarkTest, GetImageLayoutTest)(benchmark::State &state)
{
    V1_2::ImageLayout layout = {0};
    for (auto _ : state) {
        g_gralloc->GetImageLayout(*g_bufferHandle, layout);
    }
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, GetImageLayoutTest)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

} // namespace
BENCHMARK_MAIN();

