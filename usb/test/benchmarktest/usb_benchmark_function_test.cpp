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

#include "hdf_log.h"
#include "usbd_function.h"
#include "usbd_port.h"
#include <benchmark/benchmark.h>
#include <gtest/gtest.h>

using namespace benchmark::internal;
using namespace OHOS;
using namespace std;
using namespace OHOS::HDI::Usb::V1_0;

namespace {
sptr<IUsbInterface> g_usbInterface = nullptr;

constexpr int32_t SLEEP_TIME = 3;
constexpr int32_t ITERATION_FREQUENCY = 100;
constexpr int32_t REPETITION_FREQUENCY = 3;

class UsbBenchmarkFunctionTest : public benchmark::Fixture {
public:
    void SetUp(const ::benchmark::State &state);
    void TearDown(const ::benchmark::State &state);
};

int32_t SwitchErrCode(int32_t ret)
{
    return ret == HDF_ERR_NOT_SUPPORT ? HDF_SUCCESS : ret;
}

void UsbBenchmarkFunctionTest::SetUp(const ::benchmark::State &state)
{
    g_usbInterface = IUsbInterface::Get();
    ASSERT_NE(g_usbInterface, nullptr);
    auto ret = g_usbInterface->SetPortRole(DEFAULT_PORT_ID, POWER_ROLE_SINK, DATA_ROLE_DEVICE);
    sleep(SLEEP_TIME);
    ret = SwitchErrCode(ret);
    ASSERT_EQ(0, ret);
}

void UsbBenchmarkFunctionTest::TearDown(const ::benchmark::State& state) {}

/**
 * @tc.name: GetCurrentFunctions
 * @tc.desc: Test functions to GetCurrentFunctions benchmark test
 * @tc.desc: int32_t GetCurrentFunctions(int32_t &funcs);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(UsbBenchmarkFunctionTest, GetCurrentFunctions)(benchmark::State &state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    auto ret = 0;
    int32_t funcs = USB_FUNCTION_NONE;
    for (auto _ : state) {
        ret = g_usbInterface->GetCurrentFunctions(funcs);
    }
    ASSERT_EQ(0, ret);
}

BENCHMARK_REGISTER_F(UsbBenchmarkFunctionTest, GetCurrentFunctions)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: SetCurrentFunctions
 * @tc.desc: Test functions to SetCurrentFunctions benchmark test
 * @tc.desc: int32_t SetCurrentFunctions(int32_t funcs)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(UsbBenchmarkFunctionTest, SetCurrentFunctions)(benchmark::State &state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    auto ret = 0;
    for (auto _ : state) {
        ret = g_usbInterface->SetCurrentFunctions(USB_FUNCTION_ACM);
    }
    ASSERT_EQ(0, ret);
}

BENCHMARK_REGISTER_F(UsbBenchmarkFunctionTest, SetCurrentFunctions)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: SetPortRole
 * @tc.desc: Test functions to SetPortRole benchmark test
 * @tc.desc: int32_t SetPortRole(int32_t portId,int32_t powerRole,int32_t dataRole)
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(UsbBenchmarkFunctionTest, SetPortRole)(benchmark::State &state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    auto ret = 0;
    for (auto _ : state) {
        ret = g_usbInterface->SetPortRole(DEFAULT_PORT_ID, POWER_ROLE_SOURCE, DATA_ROLE_HOST);
    }
    ret = SwitchErrCode(ret);
    ASSERT_EQ(0, ret);
}

BENCHMARK_REGISTER_F(UsbBenchmarkFunctionTest, SetPortRole)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: QueryPort
 * @tc.desc: Test functions to QueryPort benchmark test
 * @tc.desc: int32_t QueryPort(int32_t &portId, int32_t &powerRole, int32_t &dataRole, int32_t &mode);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */

BENCHMARK_F(UsbBenchmarkFunctionTest, QueryPort)(benchmark::State &state)
{
    ASSERT_TRUE(g_usbInterface != nullptr);
    int32_t portId = DEFAULT_PORT_ID;
    int32_t powerRole = POWER_ROLE_NONE;
    int32_t dataRole = DATA_ROLE_NONE;
    int32_t mode = PORT_MODE_NONE;
    auto ret = 0;
    for (auto _ : state) {
        ret = g_usbInterface->QueryPort(portId, powerRole, dataRole, mode);
    }
    ASSERT_EQ(0, ret);
}

BENCHMARK_REGISTER_F(UsbBenchmarkFunctionTest, QueryPort)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: QueryPorts
 * @tc.desc: Test functions to QueryPorts benchmark test
 * @tc.desc: int32_t QueryPorts(std::vector<UsbPort>& portList);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
 
BENCHMARK_F(UsbBenchmarkFunctionTest, QueryPorts)(benchmark::State &state)
{
    sptr<HDI::Usb::V2_0::IUsbPortInterface> usbPortInterface_ = nullptr;
    usbPortInterface_ = HDI::Usb::V2_0::IUsbPortInterface::Get();
    ASSERT_TRUE(usbPortInterface_ != nullptr);
    std::vector<HDI::Usb::V2_0::UsbPort> portList;
    auto ret = 0;
    for (auto _ : state) {
        ret = usbPortInterface_->QueryPorts(portList);
    }
    ASSERT_EQ(0, ret);
}

BENCHMARK_REGISTER_F(UsbBenchmarkFunctionTest, QueryPorts)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();
}

BENCHMARK_MAIN();
