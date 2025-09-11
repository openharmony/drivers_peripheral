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
#include "UsbSubscriberV2Test.h"
#include "v2_0/iusb_device_interface.h"
#include "v2_0/iusb_host_interface.h"
#include "v2_0/usb_types.h"

using namespace OHOS;
using namespace OHOS::HDI::Usb::V2_0;
using namespace testing::ext;
using namespace std;

namespace {
struct UsbDev g_dev = {0, 0};
sptr<IUsbDeviceInterface> g_usbDeviceInterface = nullptr;
sptr<IUsbHostInterface> g_usbHostInterface = nullptr;
sptr<OHOS::USB::UsbSubscriberTest> g_subscriber = nullptr;

constexpr int32_t ITERATION_FREQUENCY = 100;
constexpr int32_t REPETITION_FREQUENCY = 3;
const uint8_t CONFIG_ID_OK = 1;
const uint8_t INTERFACEID_OK_NEW = 0;
const int SLEEP_TIME = 1;

class UsbBenchmarkAuthorizeTest : public benchmark::Fixture {
public:
    void SetUp(const ::benchmark::State &state);
    void TearDown(const ::benchmark::State &state);
};

void UsbBenchmarkAuthorizeTest::SetUp(const ::benchmark::State &state)
{
    g_usbDeviceInterface = IUsbDeviceInterface::Get();
    ASSERT_NE(g_usbDeviceInterface, nullptr);
    g_usbHostInterface = IUsbHostInterface::Get();
    ASSERT_NE(g_usbHostInterface, nullptr);
    g_subscriber = new OHOS::USB::UsbSubscriberTest();
    ASSERT_NE(g_subscriber, nullptr);
    auto ret = g_usbHostInterface->BindUsbdHostSubscriber(g_subscriber);
    ASSERT_EQ(ret, HDF_SUCCESS);
    sleep(SLEEP_TIME);
    g_dev = {g_subscriber->busNum_, g_subscriber->devAddr_};
}

void UsbBenchmarkAuthorizeTest::TearDown(const ::benchmark::State &state)
{
    auto ret = g_usbHostInterface->UnbindUsbdHostSubscriber(g_subscriber);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: UsbDeviceAuthorize01
 * @tc.desc: Test functions to UsbDeviceAuthorize benchmark test
 * @tc.desc: int32_t UsbDeviceAuthorize(uint8_t busNum, uint8_t devAddr, bool authorized);
 * @tc.desc: Positive test: parameters correctly, with authorized = false
 * @tc.type: FUNC
 */
BENCHMARK_F(UsbBenchmarkAuthorizeTest, UsbDeviceAuthorize01)(benchmark::State &state)
{
    int32_t ret;
    for (auto _ : state) {
        ret = g_usbDeviceInterface->UsbDeviceAuthorize(g_dev.busNum, g_dev.devAddr, false);
    }
    EXPECT_EQ(0, ret);
    ret = g_usbDeviceInterface->UsbDeviceAuthorize(g_dev.busNum, g_dev.devAddr, true);
    EXPECT_EQ(0, ret);
}
BENCHMARK_REGISTER_F(UsbBenchmarkAuthorizeTest, UsbDeviceAuthorize01)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: UsbDeviceAuthorize02
 * @tc.desc: Test functions to UsbDeviceAuthorize benchmark test
 * @tc.desc: int32_t UsbDeviceAuthorize(uint8_t busNum, uint8_t devAddr, bool authorized);
 * @tc.desc: Positive test: parameters correctly, with authorized false & true
 * @tc.type: FUNC
 */
BENCHMARK_F(UsbBenchmarkAuthorizeTest, UsbDeviceAuthorize02)(benchmark::State &state)
{
    int32_t ret;
    for (auto _ : state) {
        ret = g_usbDeviceInterface->UsbDeviceAuthorize(g_dev.busNum, g_dev.devAddr, false);
        EXPECT_EQ(0, ret);
        ret = g_usbDeviceInterface->UsbDeviceAuthorize(g_dev.busNum, g_dev.devAddr, true);
        EXPECT_EQ(0, ret);
    }
}
BENCHMARK_REGISTER_F(UsbBenchmarkAuthorizeTest, UsbDeviceAuthorize02)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: UsbInterfaceAuthorize01
 * @tc.desc: Test functions to UsbInterfaceAuthorize benchmark test
 * @tc.desc: int32_t UsbInterfaceAuthorize(
 *      const UsbDev &dev, uint8_t configId, uint8_t interfaceId, bool authorized);
 * @tc.desc: Positive test: parameters correctly, with authorized = false
 * @tc.type: FUNC
 */
BENCHMARK_F(UsbBenchmarkAuthorizeTest, UsbInterfaceAuthorize01)(benchmark::State &state)
{
    int32_t ret;
    for (auto _ : state) {
        ret = g_usbDeviceInterface->UsbInterfaceAuthorize(g_dev, CONFIG_ID_OK, INTERFACEID_OK_NEW, false);
    }
    EXPECT_EQ(0, ret);
    ret = g_usbDeviceInterface->UsbInterfaceAuthorize(g_dev, CONFIG_ID_OK, INTERFACEID_OK_NEW, true);
    EXPECT_EQ(0, ret);
}
BENCHMARK_REGISTER_F(UsbBenchmarkAuthorizeTest, UsbInterfaceAuthorize01)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: UsbInterfaceAuthorize02
 * @tc.desc: Test functions to UsbInterfaceAuthorize benchmark test
 * @tc.desc: int32_t UsbInterfaceAuthorize(
 *      const UsbDev &dev, uint8_t configId, uint8_t interfaceId, bool authorized);
 * @tc.desc: Positive test: parameters correctly, with authorized false & true
 * @tc.type: FUNC
 */
BENCHMARK_F(UsbBenchmarkAuthorizeTest, UsbInterfaceAuthorize02)(benchmark::State &state)
{
    int32_t ret;
    for (auto _ : state) {
        ret = g_usbDeviceInterface->UsbInterfaceAuthorize(g_dev, CONFIG_ID_OK, INTERFACEID_OK_NEW, false);
        EXPECT_EQ(0, ret);
        ret = g_usbDeviceInterface->UsbInterfaceAuthorize(g_dev, CONFIG_ID_OK, INTERFACEID_OK_NEW, true);
        EXPECT_EQ(0, ret);
    }
}
BENCHMARK_REGISTER_F(UsbBenchmarkAuthorizeTest, UsbInterfaceAuthorize02)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

} // namespace
BENCHMARK_MAIN();