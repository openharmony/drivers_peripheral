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
#include "light_type.h"
#include "osal_time.h"
#include "v1_0/ilight_interface.h"

using namespace OHOS::HDI::Light::V1_0;
using namespace testing::ext;
using namespace std;

namespace {
    constexpr int32_t ITERATION_FREQUENCY = 100;
    constexpr int32_t REPETITION_FREQUENCY = 3;
    constexpr int32_t COLORVALUE_RED = 255;
    constexpr int32_t COLORVALUE_GREEN = 0;
    constexpr int32_t COLORVALUE_BLUE = 0;
    constexpr uint32_t SLEEP_TIME = 3;
    constexpr int32_t MIN_LIGHT_ID = HDF_LIGHT_ID_BATTERY;
    constexpr int32_t MAX_LIGHT_ID = HDF_LIGHT_ID_ATTENTION;
    constexpr int32_t ON_TIME = 500;
    constexpr int32_t OFF_TIME = 500;
    sptr<ILightInterface> g_lightInterface = nullptr;

class LightBenchmarkTest : public benchmark::Fixture {
public:
    void SetUp(const ::benchmark::State &state);
    void TearDown(const ::benchmark::State &state);
};

void LightBenchmarkTest::SetUp(const ::benchmark::State &state)
{
    g_lightInterface = ILightInterface::Get();
}

void LightBenchmarkTest::TearDown(const ::benchmark::State &state)
{
}

/**
  * @tc.name: SUB_DriverSystem_LightBenchmark_GetLightInfo
  * @tc.desc: Benchmarktest for interface GetLightInfo
  * @tc.type: FUNC
  */
BENCHMARK_F(LightBenchmarkTest, GetLightInfo)(benchmark::State &st)
{
    ASSERT_NE(nullptr, g_lightInterface);

    std::vector<HdfLightInfo> info;
    int32_t ret;

    for (auto _ : st) {
        ret = g_lightInterface->GetLightInfo(info);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }

    for (auto iter : info) {
        EXPECT_GE(iter.lightId, MIN_LIGHT_ID);
        EXPECT_LE(iter.lightId, MAX_LIGHT_ID);
    }
}

BENCHMARK_REGISTER_F(LightBenchmarkTest, GetLightInfo)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: SUB_DriverSystem_LightBenchmark_TurnOnLight
  * @tc.desc: Benchmarktest for interface TurnOnLight
  * @tc.type: FUNC
  */
BENCHMARK_F(LightBenchmarkTest, TurnOnLight)(benchmark::State &st)
{
    ASSERT_NE(nullptr, g_lightInterface);

    std::vector<HdfLightInfo> info;
    int32_t ret;

    ret = g_lightInterface->GetLightInfo(info);
    EXPECT_EQ(HDF_SUCCESS, ret);

    for (auto iter : info) {
        EXPECT_GE(iter.lightId, MIN_LIGHT_ID);
        EXPECT_LE(iter.lightId, MAX_LIGHT_ID);

        HdfLightEffect effect;
        effect.lightColor.colorValue.rgbColor.r = COLORVALUE_RED;
        effect.lightColor.colorValue.rgbColor.g = COLORVALUE_GREEN;
        effect.lightColor.colorValue.rgbColor.b = COLORVALUE_BLUE;
        effect.flashEffect.flashMode = LIGHT_FLASH_NONE;

        for (auto _ : st) {
            ret = g_lightInterface->TurnOnLight(iter.lightId, effect);
            EXPECT_EQ(HDF_SUCCESS, ret);
        }
        OsalMSleep(SLEEP_TIME);
        ret = g_lightInterface->TurnOffLight(iter.lightId);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(LightBenchmarkTest, TurnOnLight)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: SUB_DriverSystem_LightBenchmark_TurnOffLight
  * @tc.desc: Benchmarktest for interface TurnOffLight
  * @tc.type: FUNC
  */
BENCHMARK_F(LightBenchmarkTest, TurnOffLight)(benchmark::State &st)
{
    ASSERT_NE(nullptr, g_lightInterface);

    std::vector<HdfLightInfo> info;
    int32_t ret;

    ret = g_lightInterface->GetLightInfo(info);
    EXPECT_EQ(HDF_SUCCESS, ret);

    for (auto iter : info) {
        EXPECT_GE(iter.lightId, MIN_LIGHT_ID);
        EXPECT_LE(iter.lightId, MAX_LIGHT_ID);

        HdfLightEffect effect;
        effect.lightColor.colorValue.rgbColor.r = COLORVALUE_RED;
        effect.lightColor.colorValue.rgbColor.g = COLORVALUE_GREEN;
        effect.lightColor.colorValue.rgbColor.b = COLORVALUE_BLUE;
        effect.flashEffect.flashMode = LIGHT_FLASH_BLINK;
        effect.flashEffect.onTime = ON_TIME;
        effect.flashEffect.offTime = OFF_TIME;
        ret = g_lightInterface->TurnOnLight(iter.lightId, effect);
        EXPECT_EQ(HDF_SUCCESS, ret);
        OsalMSleep(SLEEP_TIME);
        for (auto _ : st) {
            ret = g_lightInterface->TurnOffLight(iter.lightId);
            EXPECT_EQ(HDF_SUCCESS, ret);
        }
    }
}

BENCHMARK_REGISTER_F(LightBenchmarkTest, TurnOffLight)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: SUB_DriverSystem_LightBenchmark_TurnOnMultiLights
  * @tc.desc: Benchmarktest for interface TurnOnMultiLights
  * @tc.type: FUNC
  */
BENCHMARK_F(LightBenchmarkTest, TurnOnMultiLights)(benchmark::State &st)
{
    ASSERT_NE(nullptr, g_lightInterface);

    std::vector<HdfLightInfo> info;
    int32_t ret;

    ret = g_lightInterface->GetLightInfo(info);
    EXPECT_EQ(0, ret);

    for (auto iter : info) {
        EXPECT_GE(iter.lightId, MIN_LIGHT_ID);
        EXPECT_LE(iter.lightId, MAX_LIGHT_ID);
        std::vector<HdfLightColor> lightColor;
        struct HdfLightColor light;
        light.colorValue.rgbColor.b = COLORVALUE_BLUE;
        lightColor.push_back(light);
        for (auto _ : st) {
            ret = g_lightInterface->TurnOnMultiLights(iter.lightId, lightColor);
            EXPECT_EQ(HDF_SUCCESS, ret);
        }
    }
}

BENCHMARK_REGISTER_F(LightBenchmarkTest, TurnOnMultiLights)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();
}

BENCHMARK_MAIN();
