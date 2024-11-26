/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <benchmark/benchmark.h>
#include <gtest/gtest.h>
#include "hdf_base.h"
#include <linux/uinput.h>
#include <vector>
#include "v1_0/ihid_ddk.h"
#include "accesstoken_kit.h"


using namespace OHOS::HDI::Input::Ddk::V1_0;

namespace {
    constexpr int32_t ITERATION_FREQUENCY = 100;
    constexpr int32_t REPETITION_FREQUENCY = 3;

    sptr<IHidDdk>  g_hidDdk = nullptr;
}

class HidDdkBenchmarkTest : public benchmark::Fixture {
public:
    void SetUp(const ::benchmark::State &state);
    void TearDown(const ::benchmark::State &state);
};

void HidDdkBenchmarkTest::SetUp(const ::benchmark::State &state)
{
    g_hidDdk = IHidDdk::Get();
}

void HidDdkBenchmarkTest::TearDown(const ::benchmark::State &state)
{
    g_hidDdk = nullptr;
}

/**
  * @tc.name: CreateDevice_benchmark
  * @tc.desc: Benchmarktest for interface CreateDevice and DestroyDevice.
  * @tc.type: FUNC
  */
BENCHMARK_F(HidDdkBenchmarkTest, CreateDevice_benchmark)(benchmark::State &state)
{
    ASSERT_TRUE(g_hidDdk != nullptr);

    auto ret = 0;
    uint32_t deviceId = 0;
    struct Hid_Device hidDevice = {
        .deviceName = "VSoC keyboard",
        .vendorId = 0x6006,
        .productId = 0x6008,
        .version = 1,
        .bustype = BUS_USB
    };
    struct Hid_EventProperties hidEventProp = {
        .hidEventTypes = {HID_EV_KEY},
        .hidKeys = {HID_KEY_1, HID_KEY_SPACE, HID_KEY_BACKSPACE, HID_KEY_ENTER}
    };

    for (auto _ : state) {
        ret = g_hidDdk->CreateDevice(hidDevice, hidEventProp, deviceId);
        ret = g_hidDdk->DestroyDevice(deviceId);
    }
    ASSERT_EQ(0, ret);
}

BENCHMARK_REGISTER_F(HidDdkBenchmarkTest, CreateDevice_benchmark)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: EmitEvent_benchmark
  * @tc.desc: Benchmarktest for interface EmitEvent.
  * @tc.type: FUNC
  */
BENCHMARK_F(HidDdkBenchmarkTest, EmitEvent_benchmark)(benchmark::State &state)
{
    ASSERT_TRUE(g_hidDdk != nullptr);

    auto ret = 0;
    uint32_t deviceId = 0;
    struct Hid_Device hidDevice = {
        .deviceName = "VSoC keyboard",
        .vendorId = 0x6006,
        .productId = 0x6008,
        .version = 1,
        .bustype = BUS_USB
    };
    struct Hid_EventProperties hidEventProp = {
        .hidEventTypes = {HID_EV_KEY},
        .hidKeys = {HID_KEY_1, HID_KEY_SPACE, HID_KEY_BACKSPACE, HID_KEY_ENTER}
    };
    ret = g_hidDdk->CreateDevice(hidDevice, hidEventProp, deviceId);
    ASSERT_EQ(0, ret);

    std::vector<struct Hid_EmitItem> items = {
        {1, 0x14a, 108},
        {3, 0,     50 },
        {3, 1,     50 }
    };

    for (auto _ : state) {
        ret = g_hidDdk->EmitEvent(deviceId, items);
    }
    ASSERT_EQ(0, ret);
}

BENCHMARK_REGISTER_F(HidDdkBenchmarkTest, EmitEvent_benchmark)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_MAIN();