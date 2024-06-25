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

#include <benchmark/benchmark.h>
#include <gtest/gtest.h>
#include "hdf_log.h"
#include "usbd_port.h"
#include "UsbSubscriberTest.h"
#include "v1_0/iusb_interface.h"

using namespace OHOS::HDI::Usb::V1_0;
using namespace testing::ext;
using namespace OHOS::USB;
using namespace std;

namespace {
    struct UsbDev g_dev = {0, 0};
    sptr<IUsbInterface> g_usbInterface = nullptr;

    const int SLEEP_TIME = 3;
    constexpr int32_t ITERATION_FREQUENCY = 100;
    constexpr int32_t REPETITION_FREQUENCY = 3;

class UsbBenchmarkDeviceTest : public benchmark::Fixture {
public:
    void SetUp(const ::benchmark::State &state);
    void TearDown(const ::benchmark::State &state);
};

int32_t SwitchErrCode(int32_t ret)
{
    return ret == HDF_ERR_NOT_SUPPORT ? HDF_SUCCESS : ret;
}

void UsbBenchmarkDeviceTest::SetUp(const ::benchmark::State &state)
{
    g_usbInterface = IUsbInterface::Get();
    ASSERT_NE(g_usbInterface, nullptr);
    auto ret = g_usbInterface->SetPortRole(DEFAULT_PORT_ID, POWER_ROLE_SINK, DATA_ROLE_DEVICE);
    sleep(SLEEP_TIME);
    ret = SwitchErrCode(ret);
    ASSERT_EQ(0, ret);
}

void UsbBenchmarkDeviceTest::TearDown(const ::benchmark::State &state) {}

/**
 * @tc.name: OpenDevice
 * @tc.desc: Test functions to OpenDevice benchmark test
 * @tc.desc: int32_t OpenDevice(const UsbDev &dev);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(UsbBenchmarkDeviceTest, OpenDevice)(benchmark::State &state)
{
    ASSERT_NE(g_usbInterface, nullptr);
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_NE(subscriber, nullptr);
    if (g_usbInterface->BindUsbdSubscriber(subscriber) != HDF_SUCCESS) {
        HDF_LOGW("%{public}s: bind usbd subscriber failed", __func__);
    }
    g_dev = {subscriber->busNum_, subscriber->devAddr_};
    int32_t ret;
    for (auto _ : state) {
        ret = g_usbInterface->OpenDevice(g_dev);
    }
    EXPECT_EQ(0, ret);
    ret = g_usbInterface->UnbindUsbdSubscriber(subscriber);
    EXPECT_EQ(0, ret);
}
BENCHMARK_REGISTER_F(UsbBenchmarkDeviceTest, OpenDevice)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
 * @tc.name: CloseDevice
 * @tc.desc: Test functions to CloseDevice benchmark test
 * @tc.desc: int32_t CloseDevice(const UsbDev &dev);
 * @tc.desc: Positive test: parameters correctly
 * @tc.type: FUNC
 */
BENCHMARK_F(UsbBenchmarkDeviceTest, CloseDevice)(benchmark::State &state)
{
    ASSERT_NE(g_usbInterface, nullptr);
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    ASSERT_NE(subscriber, nullptr);
    if (g_usbInterface->BindUsbdSubscriber(subscriber) != HDF_SUCCESS) {
        HDF_LOGW("%{public}s: bind usbd subscriber failed", __func__);
    }
    g_dev = {subscriber->busNum_, subscriber->devAddr_};
    int32_t ret;
    for (auto _ : state) {
        ret = g_usbInterface->OpenDevice(g_dev);
        EXPECT_EQ(0, ret);
        ret = g_usbInterface->CloseDevice(g_dev);
        EXPECT_EQ(0, ret);
    }
    ret = g_usbInterface->UnbindUsbdSubscriber(subscriber);
    EXPECT_EQ(0, ret);
}
BENCHMARK_REGISTER_F(UsbBenchmarkDeviceTest, CloseDevice)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();
} // namespace
BENCHMARK_MAIN();
