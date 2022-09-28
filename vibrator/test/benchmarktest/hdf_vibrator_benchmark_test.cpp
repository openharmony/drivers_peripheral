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

#include <benchmark/benchmark.h>
#include <cmath>
#include <cstdio>
#include <gtest/gtest.h>
#include <securec.h>
#include <string>
#include <vector>
#include "hdf_base.h"
#include "osal_time.h"
#include "v1_1/ivibrator_interface.h"

using namespace OHOS::HDI::Vibrator::V1_1;
using namespace testing::ext;
using namespace std;

namespace {
    uint32_t g_duration = 100;
    int32_t g_intensity1 = 30;
    int32_t g_frequency1 = 200;
    uint32_t g_sleepTime1 = 200;
    std::string g_timeSequence = "haptic.clock.timer";
    std::string g_builtIn = "haptic.default.effect";
    sptr<IVibratorInterface> g_vibratorInterface = nullptr;

class VibratorBenchmarkTest : public benchmark::Fixture {
public:
    void SetUp(const ::benchmark::State &state);
    void TearDown(const ::benchmark::State &state);
};

void VibratorBenchmarkTest::SetUp(const ::benchmark::State &state)
{
    g_vibratorInterface = IVibratorInterface::Get();
}

void VibratorBenchmarkTest::TearDown(const ::benchmark::State &state)
{
}

/**
  * @tc.name: DriverSystem_VibratorBenchmark_001
  * @tc.desc: Benchmarktest for interface StartOnce
  * Controls this vibrator to perform a one-shot vibrator at a given duration.
  * @tc.type: FUNC
  */
BENCHMARK_F(VibratorBenchmarkTest, DriverSystem_VibratorBenchmark_001)(benchmark::State &state)
{
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet;
    int32_t endRet;
    for (auto _ : state) {
        startRet = g_vibratorInterface->StartOnce(g_duration);
        EXPECT_EQ(startRet, HDF_SUCCESS);

        endRet = g_vibratorInterface->Stop(HDF_VIBRATOR_MODE_ONCE);
        EXPECT_EQ(endRet, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(VibratorBenchmarkTest, DriverSystem_VibratorBenchmark_001)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: DriverSystem_VibratorBenchmark_002
  * @tc.desc: Benchmarktest for interface Start
  * Controls this Performing Time Series Vibrator Effects.
  * @tc.type: FUNC
  */
BENCHMARK_F(VibratorBenchmarkTest, DriverSystem_VibratorBenchmark_002)(benchmark::State &state)
{
    ASSERT_NE(nullptr, g_vibratorInterface);

    int32_t startRet;
    int32_t endRet;
    for (auto _ : state) {
        startRet = g_vibratorInterface->Start(g_timeSequence);
        EXPECT_EQ(startRet, HDF_SUCCESS);

        endRet = g_vibratorInterface->Stop(HDF_VIBRATOR_MODE_PRESET);
        EXPECT_EQ(endRet, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(VibratorBenchmarkTest, DriverSystem_VibratorBenchmark_002)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: DriverSystem_VibratorBenchmark_003
  * @tc.desc: Benchmarktest for interface Stop
  * Controls this Performing built-in Vibrator Effects.
  * @tc.type: FUNC
  */
BENCHMARK_F(VibratorBenchmarkTest, DriverSystem_VibratorBenchmark_003)(benchmark::State &state)
{
    ASSERT_NE(nullptr, g_vibratorInterface);
    int32_t startRet;
    int32_t endRet;

    for (auto _ : state) {
        startRet = g_vibratorInterface->Start(g_builtIn);
        EXPECT_EQ(startRet, HDF_SUCCESS);

        endRet = g_vibratorInterface->Stop(HDF_VIBRATOR_MODE_PRESET);
        EXPECT_EQ(endRet, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(VibratorBenchmarkTest, DriverSystem_VibratorBenchmark_003)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: DriverSystem_VibratorBenchmark_004
  * @tc.desc: Benchmarktest for interface GetVibratorInfo.
  * Controls this Performing Time Series Vibrator Effects.
  * @tc.type: FUNC
  */
BENCHMARK_F(VibratorBenchmarkTest, DriverSystem_VibratorBenchmark_004)(benchmark::State &state)
{
    uint32_t majorVer;
    uint32_t minorVer;
    uint32_t ret;

    ASSERT_NE(nullptr, g_vibratorInterface);

    ret = g_vibratorInterface->GetVersion(majorVer, minorVer);
    ASSERT_EQ(HDF_SUCCESS, ret);

    ASSERT_LT(0, minorVer);
    ASSERT_LT(0, majorVer);

    std::vector<HdfVibratorInfo> info;

    for (auto _ : state) {
        int32_t startRet = g_vibratorInterface->GetVibratorInfo(info);
        EXPECT_EQ(startRet, HDF_SUCCESS);
    }
}

BENCHMARK_REGISTER_F(VibratorBenchmarkTest, DriverSystem_VibratorBenchmark_004)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: DriverSystem_VibratorBenchmark_005
  * @tc.desc: Benchmarktest for interface EnableVibratorModulation.
  * Controls this Performing built-in Vibrator Effects.
  * @tc.type: FUNC
  */
BENCHMARK_F(VibratorBenchmarkTest, DriverSystem_VibratorBenchmark_005)(benchmark::State &state)
{
    uint32_t majorVer;
    uint32_t minorVer;
    if (g_vibratorInterface->GetVersion(majorVer, minorVer) != HDF_SUCCESS) {
        return;
    }

    if (majorVer > 0 && minorVer <= 0) {
        return;
    }
    ASSERT_NE(nullptr, g_vibratorInterface);

    std::vector<HdfVibratorInfo> info;

    int32_t startRet = g_vibratorInterface->GetVibratorInfo(info);
    EXPECT_EQ(startRet, HDF_SUCCESS);

    for (auto _ : state) {
        if ((info[0].isSupportIntensity == 1) || (info[0].isSupportFrequency == 1)) {
            printf("vibratot benchmarktest successed!\n\t");
            EXPECT_GT(g_duration, 0);
            EXPECT_GE(g_intensity1, info[0].intensityMinValue);
            EXPECT_LE(g_intensity1, info[0].intensityMaxValue);
            EXPECT_GE(g_frequency1, info[0].frequencyMinValue);
            EXPECT_LE(g_frequency1, info[0].frequencyMaxValue);
            printf("vibratot benchmark test successed!\n\t");
            startRet = g_vibratorInterface->EnableVibratorModulation(g_duration, g_intensity1, g_frequency1);
            EXPECT_EQ(startRet, HDF_SUCCESS);
            OsalMSleep(g_sleepTime1);
            startRet = g_vibratorInterface->Stop(HDF_VIBRATOR_MODE_ONCE);
            EXPECT_EQ(startRet, HDF_SUCCESS);
        }
    }
}

BENCHMARK_REGISTER_F(VibratorBenchmarkTest, DriverSystem_VibratorBenchmark_005)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();
}

BENCHMARK_MAIN();
