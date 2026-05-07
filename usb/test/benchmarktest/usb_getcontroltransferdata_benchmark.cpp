/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <vector>
#include <gtest/gtest.h>
#include "hdf_log.h"
#include "v2_1/iusb_device_interface.h"
#include "v2_0/usb_types.h"
#include "usbd_type.h"

using namespace OHOS;
using namespace OHOS::HDI::Usb::V2_1;
using namespace testing::ext;
using namespace std;

namespace {
sptr<OHOS::HDI::Usb::V2_1::IUsbDeviceInterface> g_usbDeviceInterface = nullptr;
constexpr int32_t ITERATION_FREQUENCY = 100;
constexpr int32_t REPETITION_FREQUENCY = 3;

class UsbBenchmarkGetControlTransferDataTest : public benchmark::Fixture {
public:
    void SetUp(const ::benchmark::State &state);
    void TearDown(const ::benchmark::State &state) {};
};

void UsbBenchmarkGetControlTransferDataTest::SetUp(const ::benchmark::State &state)
{
    g_usbDeviceInterface = HDI::Usb::V2_1::IUsbDeviceInterface::Get();
    ASSERT_NE(g_usbDeviceInterface, nullptr);
}

/**
 * @tc.name: UsbGetControlTransferData01
 * @tc.desc: Test functions to GetControlTransferData benchmark test
 * @tc.desc: int32_t GetControlTransferData(int32_t eventId, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, with eventId = ACT_CUSTOMCONTROLREQUEST
 * @tc.type: FUNC
 */
BENCHMARK_F(UsbBenchmarkGetControlTransferDataTest, UsbGetControlTransferData01)(benchmark::State &state)
{
    int32_t ret;
    std::vector<uint8_t> data;
    for (auto _ : state) {
        ret = g_usbDeviceInterface->GetControlTransferData(ACT_CUSTOMCONTROLREQUEST, data);
    }
    EXPECT_EQ(0, ret);
    ret = g_usbDeviceInterface->GetControlTransferData(ACT_CUSTOMCONTROLREQUEST, data);
    EXPECT_EQ(0, ret);
}
BENCHMARK_REGISTER_F(UsbBenchmarkGetControlTransferDataTest, UsbGetControlTransferData01)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();


/**
 * @tc.name: UsbGetControlTransferData02
 * @tc.desc: Test functions to GetControlTransferData benchmark test
 * @tc.desc: int32_t GetControlTransferData(int32_t eventId, std::vector<uint8_t> &data);
 * @tc.desc: Positive test: parameters correctly, with eventId != ACT_CUSTOMCONTROLREQUEST
 * @tc.type: FUNC
 */
BENCHMARK_F(UsbBenchmarkGetControlTransferDataTest, UsbGetControlTransferData02)(benchmark::State &state)
{
    int32_t ret;
    std::vector<uint8_t> data;
    for (auto _ : state) {
        ret = g_usbDeviceInterface->GetControlTransferData(ACT_ACCESSORYSEND, data);
    }
    EXPECT_EQ(0, ret);
    ret = g_usbDeviceInterface->GetControlTransferData(ACT_ACCESSORYSEND, data);
    EXPECT_EQ(0, ret);
}
BENCHMARK_REGISTER_F(UsbBenchmarkGetControlTransferDataTest, UsbGetControlTransferData02)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

} // namespace
BENCHMARK_MAIN();