/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>
#include <vector>
#include "v1_0/icamera_vendor_tag.h"

using namespace testing::ext;
using namespace OHOS;

constexpr int32_t ITERATION_FREQUENCY = 100;
constexpr int32_t REPETITION_FREQUENCY = 3;

static sptr<OHOS::HDI::Camera::Metadata::V1_0::ICameraVendorTag> g_cameraVendorTagService = nullptr;

class CameraVendorTagBenchmarkTest : public benchmark::Fixture {
public:
    void SetUp(const ::benchmark::State &state);
    void TearDown(const ::benchmark::State &state);
};

void CameraVendorTagBenchmarkTest::SetUp(const ::benchmark::State &state)
{
    g_cameraVendorTagService = OHOS::HDI::Camera::Metadata::V1_0::ICameraVendorTag::Get(true);
}

void CameraVendorTagBenchmarkTest::TearDown(const ::benchmark::State &state)
{
}

/**
  * @tc.name: DriverSystem_CameraVendorTagBenchmarkTest_GetVendorTagName
  * @tc.desc: Benchmarktest for interface GetVendorTagName
  * @tc.type: FUNC
  */
BENCHMARK_F(CameraVendorTagBenchmarkTest, GetVendorTagName)(benchmark::State &state)
{
    ASSERT_NE(nullptr, g_cameraVendorTagService);
    std::vector<OHOS::HDI::Camera::Metadata::V1_0::VendorTag> g_hdiTagVec;
    auto ret = g_cameraVendorTagService->GetAllVendorTags(g_hdiTagVec);
    for (auto _ : state) {
        auto item = g_hdiTagVec.front();
        void* tagName = nullptr;
        ret = g_cameraVendorTagService->GetVendorTagName(item.tagId, tagName);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(CameraVendorTagBenchmarkTest, GetVendorTagName)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: DriverSystem_CameraVendorTagBenchmarkTest_GetVendorTagType
  * @tc.desc: Benchmarktest for interface GetVendorTagType
  * @tc.type: FUNC
  */
BENCHMARK_F(CameraVendorTagBenchmarkTest, GetVendorTagType)(benchmark::State &state)
{
    ASSERT_NE(nullptr, g_cameraVendorTagService);
    std::vector<OHOS::HDI::Camera::Metadata::V1_0::VendorTag> g_hdiTagVec;
    auto ret = g_cameraVendorTagService->GetAllVendorTags(g_hdiTagVec);
    for (auto _ : state) {
        auto item = g_hdiTagVec.front();
        int8_t hdiDataType = -1;
        ret = g_cameraVendorTagService->GetVendorTagType(item.tagId, hdiDataType);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(CameraVendorTagBenchmarkTest, GetVendorTagType)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: DriverSystem_CameraVendorTagBenchmarkTest_GetAllVendorTags
  * @tc.desc: Benchmarktest for interface GetAllVendorTags
  * @tc.type: FUNC
  */
BENCHMARK_F(CameraVendorTagBenchmarkTest, GetAllVendorTags)(benchmark::State &state)
{
    ASSERT_NE(nullptr, g_cameraVendorTagService);
    std::vector<OHOS::HDI::Camera::Metadata::V1_0::VendorTag> g_hdiTagVec;
    for (auto _ : state) {
        auto ret = g_cameraVendorTagService->GetAllVendorTags(g_hdiTagVec);
        ASSERT_EQ(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(CameraVendorTagBenchmarkTest, GetAllVendorTags)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();
BENCHMARK_MAIN();
