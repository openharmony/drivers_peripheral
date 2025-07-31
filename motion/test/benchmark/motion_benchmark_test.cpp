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
#include <cmath>
#include <cstdio>
#include <gtest/gtest.h>
#include <securec.h>
#include <string>
#include <unistd.h>
#include <vector>
#include "hdf_base.h"
#include "osal_time.h"
#include "v1_1/imotion_interface.h"
#include "motion_callback_impl.h"

using namespace OHOS::HDI::Motion::V1_1;
using namespace testing::ext;
using namespace std;

#define DATA_NUM 12
#define DATA_VALUE 6

namespace {
    sptr<OHOS::HDI::Motion::V1_1::IMotionInterface> g_motionInterface = nullptr;
    sptr<IMotionCallback> g_motionCallback = new MotionCallbackImpl();
    sptr<IMotionCallback> g_motionCallbackUnregistered = new MotionCallbackImpl();
    std::vector<uint8_t> g_motionConfigData(DATA_NUM, DATA_VALUE);


class MotionBenchmarkTest : public benchmark::Fixture {
public:
    void SetUp(const ::benchmark::State &state);
    void TearDown(const ::benchmark::State &state);
};

void MotionBenchmarkTest::SetUp(const ::benchmark::State &state)
{
    g_motionInterface = OHOS::HDI::Motion::V1_1::IMotionInterface::Get();
}

void MotionBenchmarkTest::TearDown(const ::benchmark::State &state)
{
}

/**
  * @tc.name: DriverSystem_MotionBenchmark_EnableMotion
  * @tc.desc: Benchmarktest for interface EnableMotion
  * Obtains information about all motion in the system
  * @tc.type: FUNC
  */
BENCHMARK_F(MotionBenchmarkTest, EnableMotion)(benchmark::State &state)
{
    ASSERT_NE(nullptr, g_motionInterface);

    for (auto _ : state) {
        int32_t motionType = OHOS::HDI::Motion::V1_1::HDF_MOTION_TYPE_WRIST_DOWN;
        int32_t ret = g_motionInterface->EnableMotion(motionType);
        EXPECT_NE(HDF_SUCCESS, ret);
        ret = g_motionInterface->DisableMotion(motionType);
        EXPECT_NE(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(MotionBenchmarkTest, EnableMotion)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();


/**
  * @tc.name: DriverSystem_MotionBenchmark_Register
  * @tc.desc: Benchmarktest for interface Register
  * Obtains information about all motion in the system
  * @tc.type: FUNC
  */
BENCHMARK_F(MotionBenchmarkTest, Register)(benchmark::State &state)
{
    ASSERT_NE(nullptr, g_motionInterface);

    for (auto _ : state) {
        int32_t ret = g_motionInterface->Register(g_motionCallback);
        EXPECT_EQ(HDF_SUCCESS, ret);
        ret = g_motionInterface->Unregister(g_motionCallback);
        EXPECT_EQ(0, ret);
    }
}

BENCHMARK_REGISTER_F(MotionBenchmarkTest, Register)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: DriverSystem_MotionBenchmark_SetMotionConfig
  * @tc.desc: Benchmarktest for interface SetMotionConfig
  * Obtains information about all motion in the system
  * @tc.type: FUNC
  */
BENCHMARK_F(MotionBenchmarkTest, SetMotionConfig)(benchmark::State &state)
{
    ASSERT_NE(nullptr, g_motionInterface);

    for (auto _ : state) {
        int32_t motionType = -1;
        int32_t ret = g_motionInterface->SetMotionConfig(motionType, g_motionConfigData);
        EXPECT_NE(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(MotionBenchmarkTest, SetMotionConfig)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();
}
BENCHMARK_MAIN();
