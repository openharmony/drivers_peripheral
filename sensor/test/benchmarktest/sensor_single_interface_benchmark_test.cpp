/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include "sensor_plug_callback_impl.h"
#include "sensor_uhdf_log.h"
#include "v3_0/isensor_interface.h"

using namespace OHOS::HDI::Sensor::V3_0;
using namespace OHOS::HDI::Sensor;
using namespace testing::ext;
using namespace std;

namespace {
    sptr<ISensorInterface>  g_sensorInterface = nullptr;
    sptr<V3_0::ISensorCallback> g_traditionalCallback = new SensorCallbackImpl();
    sptr<V3_0::ISensorPlugCallback> g_sensorPlugCallback = new SensorPlugCallbackImpl();
    std::vector<HdfSensorInformation> g_info;
    std::vector<HdfSensorEvents> g_events;
    std::vector<SdcSensorInfo> g_sdcSensorInfo;

    constexpr int32_t ITERATION_FREQUENCY = 100;
    constexpr int32_t REPETITION_FREQUENCY = 3;
    constexpr int32_t SENSOR_INTERVAL1 = 20;
    constexpr int32_t SENSOR_POLL_TIME = 3;
    constexpr uint32_t OPTION = 0;
    constexpr DeviceSensorInfo SENSOR_HANDLE = {-1, 1, 0, 1};
    constexpr int32_t RATE_LEVEL = 50;

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
  * @tc.name: DriverSystem_SensorBenchmark_GetAllSensorInfo
  * @tc.desc: Benchmarktest for interface GetAllSensorInfo
  * Obtains information about all sensors in the system
  * @tc.type: FUNC
  */
BENCHMARK_F(SensorBenchmarkTest, GetAllSensorInfo)(benchmark::State &state)
{
    for (auto _ : state) {
        int32_t ret = g_sensorInterface->GetAllSensorInfo(g_info);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(SensorBenchmarkTest, GetAllSensorInfo)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: DriverSystem_SensorBenchmark_register
  * @tc.desc: Benchmarktest for interface register
  * Returns 0 if the callback is successfully registered; returns a negative value otherwise
  * @tc.type: FUNC
  */
BENCHMARK_F(SensorBenchmarkTest, Register)(benchmark::State &state)
{
    for (auto _ : state) {
        int32_t ret = g_sensorInterface->Register(HDF_TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(SensorBenchmarkTest, Register)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: DriverSystem_SensorBenchmark_RegisterAsync
  * @tc.desc: Benchmarktest for interface RegisterAsync
  * Returns 0 if the callback is successfully registered; returns a negative value otherwise
  * @tc.type: FUNC
  */
BENCHMARK_F(SensorBenchmarkTest, RegisterAsync)(benchmark::State &state)
{
    for (auto _ : state) {
        int32_t ret = g_sensorInterface->RegisterAsync(HDF_TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(SensorBenchmarkTest, RegisterAsync)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: DriverSystem_SensorBenchmark_SetBatch
  * @tc.desc: Benchmarktest for interface SetBatch
  * Sets the sampling time and data report interval for sensors in batches
  * @tc.type: FUNC
  */
BENCHMARK_F(SensorBenchmarkTest, SetBatch)(benchmark::State &state)
{
    for (auto _ : state) {
        int32_t ret = g_sensorInterface->SetBatch(SENSOR_HANDLE, SENSOR_INTERVAL1, SENSOR_POLL_TIME);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(SensorBenchmarkTest, SetBatch)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: DriverSystem_SensorBenchmark_SetMode
  * @tc.desc: Benchmarktest for interface SetMode
  * Sets the data reporting mode for the specified sensor
  * @tc.type: FUNC
  */
BENCHMARK_F(SensorBenchmarkTest, SetMode)(benchmark::State &state)
{
    for (auto _ : state) {
        int32_t ret = g_sensorInterface->SetMode(SENSOR_HANDLE, SENSOR_MODE_ON_CHANGE);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(SensorBenchmarkTest, SetMode)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: DriverSystem_SensorBenchmark_SetOption
  * @tc.desc: Benchmarktest for interface SetOption
  * Sets options for the specified sensor, including its measurement range and accuracy
  * @tc.type: FUNC
  */
BENCHMARK_F(SensorBenchmarkTest, SetOption)(benchmark::State &state)
{
    for (auto _ : state) {
        int32_t ret = g_sensorInterface->SetOption(SENSOR_HANDLE, OPTION);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(SensorBenchmarkTest, SetOption)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: DriverSystem_SensorBenchmark_Unregister
  * @tc.desc: Benchmarktest for interface Unregister
  * Returns 0 if the callback is successfully registered; returns a negative value otherwise
  * @tc.type: FUNC
  */
BENCHMARK_F(SensorBenchmarkTest, Unregister)(benchmark::State &state)
{
    for (auto _ : state) {
        int32_t ret = g_sensorInterface->Unregister(HDF_TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(SensorBenchmarkTest, Unregister)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: DriverSystem_SensorBenchmark_UnregisterAsync
  * @tc.desc: Benchmarktest for interface UnregisterAsync
  * Returns 0 if the callback is successfully registered; returns a negative value otherwise
  * @tc.type: FUNC
  */
BENCHMARK_F(SensorBenchmarkTest, UnregisterAsync)(benchmark::State &state)
{
    for (auto _ : state) {
        int32_t ret = g_sensorInterface->UnregisterAsync(HDF_TRADITIONAL_SENSOR_TYPE, g_traditionalCallback);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(SensorBenchmarkTest, UnregisterAsync)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: DriverSystem_SensorBenchmark_Enable
  * @tc.desc: Benchmarktest for interface Enable
  * Enables the sensor unavailable in the sensor list based on the specified sensor ID
  * @tc.type: FUNC
  */
BENCHMARK_F(SensorBenchmarkTest, Enable)(benchmark::State &state)
{
    for (auto _ : state) {
        int32_t ret = g_sensorInterface->Enable(SENSOR_HANDLE);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(SensorBenchmarkTest, Enable)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: DriverSystem_SensorBenchmark_Disable
  * @tc.desc: Benchmarktest for interface Disable
  * Disables the sensor unavailable in the sensor list based on the specified sensor ID
  * @tc.type: FUNC
  */
BENCHMARK_F(SensorBenchmarkTest, Disable)(benchmark::State &state)
{
    for (auto _ : state) {
        int32_t ret = g_sensorInterface->Disable(SENSOR_HANDLE);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(SensorBenchmarkTest, Disable)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: DriverSystem_SensorBenchmark_GetDeviceSensorInfo
  * @tc.desc: Benchmarktest for interface GetDeviceSensorInfo
  * Gets the information of the specified sensor device
  * @tc.type: FUNC
  */
BENCHMARK_F(SensorBenchmarkTest, GetDeviceSensorInfo)(benchmark::State &state)
{
    for (auto _ : state) {
        int32_t ret = g_sensorInterface->GetDeviceSensorInfo(SENSOR_HANDLE.deviceId, g_info);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(SensorBenchmarkTest, GetDeviceSensorInfo)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: DriverSystem_SensorBenchmark_ReadData
  * @tc.desc: Benchmarktest for interface ReadData
  * Reads data from the specified sensor device
  * @tc.type: FUNC
  */
BENCHMARK_F(SensorBenchmarkTest, ReadData)(benchmark::State &state)
{
    for (auto _ : state) {
        int32_t ret = g_sensorInterface->ReadData(SENSOR_HANDLE, g_events);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(SensorBenchmarkTest, ReadData)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: DriverSystem_SensorBenchmark_SetSdcSensor
  * @tc.desc: Benchmarktest for interface SetSdcSensor
  * Sets the SDC sensor with the specified parameters
  * @tc.type: FUNC
  */
BENCHMARK_F(SensorBenchmarkTest, SetSdcSensor)(benchmark::State &state)
{
    for (auto _ : state) {
        int32_t ret = g_sensorInterface->SetSdcSensor(SENSOR_HANDLE, true, RATE_LEVEL);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(SensorBenchmarkTest, SetSdcSensor)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: DriverSystem_SensorBenchmark_GetSdcSensorInfo
  * @tc.desc: Benchmarktest for interface GetSdcSensorInfo
  * Gets the SDC sensor information
  * @tc.type: FUNC
  */
BENCHMARK_F(SensorBenchmarkTest, GetSdcSensorInfo)(benchmark::State &state)
{
    for (auto _ : state) {
        int32_t ret = g_sensorInterface->GetSdcSensorInfo(g_sdcSensorInfo);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(SensorBenchmarkTest, GetSdcSensorInfo)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: DriverSystem_SensorBenchmark_RegSensorPlugCallBack
  * @tc.desc: Benchmarktest for interface RegSensorPlugCallBack
  * Registers a callback function for sensor plug events
  * @tc.type: FUNC
  */
BENCHMARK_F(SensorBenchmarkTest, RegSensorPlugCallBack)(benchmark::State &state)
{
    for (auto _ : state) {
        int32_t ret = g_sensorInterface->RegSensorPlugCallBack(g_sensorPlugCallback);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(SensorBenchmarkTest, RegSensorPlugCallBack)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: DriverSystem_SensorBenchmark_UnRegSensorPlugCallBack
  * @tc.desc: Benchmarktest for interface UnRegSensorPlugCallBack
  * Unregisters a callback function for sensor plug events
  * @tc.type: FUNC
  */
BENCHMARK_F(SensorBenchmarkTest, UnRegSensorPlugCallBack)(benchmark::State &state)
{
    for (auto _ : state) {
        int32_t ret = g_sensorInterface->UnRegSensorPlugCallBack(g_sensorPlugCallback);
        EXPECT_EQ(HDF_SUCCESS, ret);
    }
}

BENCHMARK_REGISTER_F(SensorBenchmarkTest, UnRegSensorPlugCallBack)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();
}

BENCHMARK_MAIN();
