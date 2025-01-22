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
#include "hdf_log.h"
#include "v1_1/iusb_ddk.h"
#include "usbd_wrapper.h"

using namespace OHOS::HDI::Usb::Ddk;
using namespace testing::ext;
using namespace std;

namespace {
    V1_1::DriverAbilityInfo g_driverInfo;
    OHOS::sptr<V1_1::IUsbDdk> g_usbDdk = nullptr;

    constexpr int32_t ITERATION_FREQUENCY = 100;
    constexpr int32_t REPETITION_FREQUENCY = 3;

class UsbBenchmarkDriverTest : public benchmark::Fixture {
public:
    void SetUp(const ::benchmark::State &state);
    void TearDown(const ::benchmark::State &state);
};

void UsbBenchmarkDriverTest::SetUp(const ::benchmark::State &state)
{
    g_usbDdk = V1_1::IUsbDdk::Get();
    ASSERT_NE(g_usbDdk, nullptr);
}

void UsbBenchmarkDriverTest::TearDown(const ::benchmark::State &state) {}

/**
 * @tc.name: UpdateDriverInfo
 * @tc.desc: Test functions to UpdateDriverInfo benchmark test
 * @tc.desc: int32_t UpdateDriverInfo(const DriverAbilityInfo &driverInfo);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(UsbBenchmarkDriverTest, UpdateDriverInfo)(benchmark::State &state)
{
    ASSERT_NE(g_usbDdk, nullptr);
    g_driverInfo.driverUid = "driverName-10001";
    g_driverInfo.vids = { 1001, 1002 };
    int32_t ret = 0;
    for (auto _ : state) {
        ret = g_usbDdk->UpdateDriverInfo(g_driverInfo);
        EXPECT_EQ(0, ret);
    }
}
BENCHMARK_REGISTER_F(UsbBenchmarkDriverTest, UpdateDriverInfo)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: RemoveDriverInfo
 * @tc.desc: Test functions to RemoveDriverInfo benchmark test
 * @tc.desc: int32_t RemoveDriverInfo(const std::string &driverUid);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(UsbBenchmarkDriverTest, RemoveDriverInfo)(benchmark::State &state)
{
    ASSERT_NE(g_usbDdk, nullptr);
    g_driverInfo.driverUid = "driverName-10001";
    g_driverInfo.vids = { 1001, 1002 };
    int32_t ret = 0;
    for (auto _ : state) {
        ret = g_usbDdk->UpdateDriverInfo(g_driverInfo);
        EXPECT_EQ(0, ret);
        ret = g_usbDdk->RemoveDriverInfo(g_driverInfo.driverUid);
        EXPECT_EQ(0, ret);
    }
}
BENCHMARK_REGISTER_F(UsbBenchmarkDriverTest, RemoveDriverInfo)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();
} // namespace
BENCHMARK_MAIN();
