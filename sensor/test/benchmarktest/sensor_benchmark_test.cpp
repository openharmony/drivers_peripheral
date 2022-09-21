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
#include <unistd.h>
#include <vector>
#include "hdf_base.h"
#include "osal_time.h"
#include "sensor_callback_impl.h"
#include "sensor_type.h"
#include "v1_0/isensor_interface.h"

using namespace OHOS::HDI::Sensor::V1_0;
using namespace testing::ext;
using namespace std;

namespace {
    sptr<ISensorInterface>  g_sensorInterface = nullptr;
    sptr<ISensorCallback> g_traditionalCallback = new SensorCallbackImpl();
    sptr<ISensorCallback> g_medicalCallback = new SensorCallbackImpl();
    std::vector<HdfSensorInformation> g_info;

    constexpr int32_t SENSOR_INTERVAL1 = 20;
    constexpr int32_t SENSOR_INTERVAL2 = 2;
    constexpr int32_t SENSOR_POLL_TIME = 1;
    constexpr int32_t SENSOR_WAIT_TIME = 10;

class SensorBenchmarkTest : public benchmark::Fixture {
public:
    void SetUp(const ::benchmark::State &state);
    void TearDown(const ::benchmark::State &state);
};

void SensorBenchmarkTest::SetUp(const ::benchmark::State &state)
{
    g_sensorInterface = ISensorInterface::Get();
}

void SensorBenchmarkTest::TearDown(const ::benchmark::State &state)
{
}

/**
  * @tc.name: DriverSystem_SensorBenchmark_001
  * @tc.desc: Benchmarktest for interface GetAllSensorInfo.
  * Obtains information about all sensors in the system.
  * @tc.type: FUNC
  */
BENCHMARK_F(SensorBenchmarkTest, DriverSystem_SensorBenchmark_001)(benchmark::State &state)
{
    if (g_sensorInterface == nullptr) {
        ASSERT_NE(nullptr, g_sensorInterface);
        return;
    }
    int32_t ret;
    for (auto _ : state) {
        ret = g_sensorInterface->GetAllSensorInfo(g_info);
    }
    EXPECT_EQ(SENSOR_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(SensorBenchmarkTest, DriverSystem_SensorBenchmark_001)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: DriverSystem_SensorBenchmark_002
  * @tc.desc: Benchmarktest for interface register.
  * Returns 0 if the callback is successfully registered; returns a negative value otherwise.
  * @tc.type: FUNC
  */
BENCHMARK_F(SensorBenchmarkTest, DriverSystem_SensorBenchmark_002)(benchmark::State &state)
{
    if (g_sensorInterface == nullptr) {
        ASSERT_NE(nullptr, g_sensorInterface);
    }
    int32_t ret;
    for (auto _ : state) {
        ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
    }
    EXPECT_EQ(SENSOR_SUCCESS, ret);
    ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
    EXPECT_EQ(SENSOR_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(SensorBenchmarkTest, DriverSystem_SensorBenchmark_002)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: DriverSystem_SensorBenchmark_003
  * @tc.desc: Benchmarktest for interface Unregister.
  * Returns 0 if the callback is successfully registered; returns a negative value otherwise.
  * @tc.type: FUNC
  */
BENCHMARK_F(SensorBenchmarkTest, DriverSystem_SensorBenchmark_003)(benchmark::State &state)
{
    if (g_sensorInterface == nullptr) {
        ASSERT_NE(nullptr, g_sensorInterface);
    }
    int32_t ret;
    for (auto _ : state) {
        ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
        EXPECT_EQ(SENSOR_SUCCESS, ret);
        ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
    }
    EXPECT_EQ(SENSOR_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(SensorBenchmarkTest, DriverSystem_SensorBenchmark_003)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: DriverSystem_SensorBenchmark_004
  * @tc.desc: Benchmarktest for interface Enable.
  * Enables the sensor unavailable in the sensor list based on the specified sensor ID.
  * @tc.type: FUNC
  */
BENCHMARK_F(SensorBenchmarkTest, DriverSystem_SensorBenchmark_004)(benchmark::State &state)
{
    if (g_sensorInterface == nullptr) {
        ASSERT_NE(nullptr, g_sensorInterface);
    }
    int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
    EXPECT_EQ(SENSOR_SUCCESS, ret);

    EXPECT_GT(g_info.size(), 0);

    ret = g_sensorInterface->SetBatch(0, SENSOR_INTERVAL1, SENSOR_POLL_TIME);
    EXPECT_EQ(SENSOR_SUCCESS, ret);
    for (auto _ : state) {
        ret = g_sensorInterface->Enable(0);
    }
    EXPECT_EQ(SENSOR_SUCCESS, ret);
    OsalMSleep(SENSOR_POLL_TIME);
    ret = g_sensorInterface->Disable(0);
    EXPECT_EQ(SENSOR_SUCCESS, ret);
    ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
    EXPECT_EQ(SensorCallbackImpl::sensorDataFlag, 1);
    SensorCallbackImpl::sensorDataFlag = 1;
}

BENCHMARK_REGISTER_F(SensorBenchmarkTest, DriverSystem_SensorBenchmark_004)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: DriverSystem_SensorBenchmark_005
  * @tc.desc: Benchmarktest for interface Disable.
  * Enables the sensor unavailable in the sensor list based on the specified sensor ID.
  * @tc.type: FUNC
  */
BENCHMARK_F(SensorBenchmarkTest, DriverSystem_SensorBenchmark_005)(benchmark::State &state)
{
    if (g_sensorInterface == nullptr) {
        ASSERT_NE(nullptr, g_sensorInterface);
    }
    int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
    EXPECT_EQ(SENSOR_SUCCESS, ret);

    EXPECT_GT(g_info.size(), 0);

    ret = g_sensorInterface->SetBatch(0, SENSOR_INTERVAL1, SENSOR_POLL_TIME);
    EXPECT_EQ(SENSOR_SUCCESS, ret);
    ret = g_sensorInterface->Enable(0);
    EXPECT_EQ(SENSOR_SUCCESS, ret);
    OsalMSleep(SENSOR_POLL_TIME);
    for (auto _ : state) {
        ret = g_sensorInterface->Disable(0);
    }
    EXPECT_EQ(SENSOR_SUCCESS, ret);
    ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
    EXPECT_EQ(SensorCallbackImpl::sensorDataFlag, 1);
    SensorCallbackImpl::sensorDataFlag = 1;
}

BENCHMARK_REGISTER_F(SensorBenchmarkTest, DriverSystem_SensorBenchmark_005)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: DriverSystem_SensorBenchmark_006
  * @tc.desc: Benchmarktest for interface SetBatch.
  * Sets the sampling time and data report interval for sensors in batches.
  * @tc.type: FUNC
  */
BENCHMARK_F(SensorBenchmarkTest, DriverSystem_SensorBenchmark_006)(benchmark::State &state)
{
    if (g_sensorInterface == nullptr) {
        ASSERT_NE(nullptr, g_sensorInterface);
    }
    int32_t ret = g_sensorInterface->Register(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
    EXPECT_EQ(SENSOR_SUCCESS, ret);

    for (auto _ : state) {
        ret = g_sensorInterface->SetBatch(0, SENSOR_INTERVAL2, SENSOR_POLL_TIME);
    }
    EXPECT_EQ(SENSOR_SUCCESS, ret);
    ret = g_sensorInterface->Enable(0);
    EXPECT_EQ(SENSOR_SUCCESS, ret);
    OsalMSleep(SENSOR_WAIT_TIME);
    ret = g_sensorInterface->Disable(0);
    EXPECT_EQ(SENSOR_SUCCESS, ret);

    ret = g_sensorInterface->Unregister(TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
    EXPECT_EQ(SENSOR_SUCCESS, ret);
    EXPECT_EQ(SensorCallbackImpl::sensorDataFlag, 1);
    SensorCallbackImpl::sensorDataFlag = 1;
}

BENCHMARK_REGISTER_F(SensorBenchmarkTest, DriverSystem_SensorBenchmark_006)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: DriverSystem_SensorBenchmark_007
  * @tc.desc: Benchmarktest for interface SetMode.
  * Sets the data reporting mode for the specified sensor.
  * @tc.type: FUNC
  */
BENCHMARK_F(SensorBenchmarkTest, DriverSystem_SensorBenchmark_007)(benchmark::State &state)
{
    if (g_sensorInterface == nullptr) {
        ASSERT_NE(nullptr, g_sensorInterface);
    }
    EXPECT_GT(g_info.size(), 0);
    int32_t ret ;
    ret = g_sensorInterface->SetBatch(0, SENSOR_INTERVAL1, SENSOR_POLL_TIME);
    EXPECT_EQ(SENSOR_SUCCESS, ret);
    for (auto _ : state) {
        if (0 == SENSOR_TYPE_HALL) {
            ret = g_sensorInterface->SetMode(0, SENSOR_MODE_ON_CHANGE);
        } else {
                ret = g_sensorInterface->SetMode(0, SENSOR_MODE_REALTIME);
        }
    }
    EXPECT_EQ(SENSOR_SUCCESS, ret);
    ret = g_sensorInterface->Enable(0);
    EXPECT_EQ(SENSOR_SUCCESS, ret);
    OsalMSleep(SENSOR_WAIT_TIME);
    ret = g_sensorInterface->Disable(0);
    EXPECT_EQ(SENSOR_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(SensorBenchmarkTest, DriverSystem_SensorBenchmark_007)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: DriverSystem_SensorBenchmark_008
  * @tc.desc: Benchmarktest for interface SetOption.
  * Sets options for the specified sensor, including its measurement range and accuracy.
  * @tc.type: FUNC
  */
BENCHMARK_F(SensorBenchmarkTest, DriverSystem_SensorBenchmark_008)(benchmark::State &state)
{
    if (g_sensorInterface == nullptr) {
        ASSERT_NE(nullptr, g_sensorInterface);
    }
    EXPECT_GT(g_info.size(), 0);
    int32_t ret;

    for (auto _ : state) {
        ret = g_sensorInterface->SetOption(0, 0);
    }
    EXPECT_EQ(SENSOR_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(SensorBenchmarkTest, DriverSystem_SensorBenchmark_008)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();
}

BENCHMARK_MAIN();
