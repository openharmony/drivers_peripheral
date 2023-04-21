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

#include <mutex>
#include <chrono>
#include <cinttypes>
#include <algorithm>
#include <condition_variable>
#include <benchmark/benchmark.h>
#include "gtest/gtest.h"
#include "v1_0/include/idisplay_composer_interface.h"
#include "v1_0/display_composer_type.h"
#include "v1_0/display_buffer_type.h"
#include "display_test.h"
#include "display_test_utils.h"
#include "hdi_composition_check.h"
#include "hdi_test_device.h"
#include "hdi_test_device_common.h"
#include "hdi_test_display.h"
#include "hdi_test_render_utils.h"

using namespace OHOS::HDI::Display::Buffer::V1_0;
using namespace OHOS::HDI::Display::Composer::V1_0;
using namespace OHOS::HDI::Display::TEST;
using namespace testing::ext;

std::shared_ptr<IDisplayComposerInterface> g_composerDevice {};
std::shared_ptr<IDisplayBuffer> g_gralloc = nullptr;
std::vector<uint32_t> g_displayIds;

namespace {
class DisplayBenchmarkTest : public benchmark::Fixture {
public:
    void TearDown(const ::benchmark::State &state);
};

void DisplayBenchmarkTest::TearDown(const ::benchmark::State &state)
{
    HdiTestDevice::GetInstance().Clear();
}

/**
  * @tc.name: GetDisplayCapabilityTest
  * @tc.desc: Benchmarktest for interface GetDisplayCapability.
  */
BENCHMARK_F(DisplayBenchmarkTest, GetDisplayCapabilityTest)(benchmark::State &state)
{
    int32_t ret;
    DisplayCapability info;
    for (auto _ : state) {
        ret = g_composerDevice->GetDisplayCapability(g_displayIds[0], info);
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, GetDisplayCapabilityTest)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: GetDisplaySupportedModesTest
  * @tc.desc: Benchmarktest for interface GetDisplaySupportedModes.
  */
BENCHMARK_F(DisplayBenchmarkTest, GetDisplaySupportedModesTest)(benchmark::State &state)
{
    int32_t ret;
    std::vector<DisplayModeInfo> modes;
    for (auto _ : state) {
        ret = g_composerDevice->GetDisplaySupportedModes(g_displayIds[0], modes);
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, GetDisplaySupportedModesTest)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: GetDisplayModeTest
  * @tc.desc: Benchmarktest for interface GetDisplayMode.
  */
BENCHMARK_F(DisplayBenchmarkTest, GetDisplayModeTest)(benchmark::State &state)
{
    int32_t ret;
    uint32_t modeId = 0;
    for (auto _ : state) {
        ret = g_composerDevice->GetDisplayMode(modeId, modeId);
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, GetDisplayModeTest)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: SetDisplayModeTest
  * @tc.desc: Benchmarktest for interface SetDisplayMode.
  */
BENCHMARK_F(DisplayBenchmarkTest, SetDisplayModeTest)(benchmark::State &state)
{
    int32_t ret;
    const uint32_t modeId = 0;
    for (auto _ : state) {
        ret = g_composerDevice->SetDisplayMode(g_displayIds[0], modeId);
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, SetDisplayModeTest)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: GetDisplayPowerStatusTest
  * @tc.desc: Benchmarktest for interface GetDisplayPowerStatus.
  */
BENCHMARK_F(DisplayBenchmarkTest, GetDisplayPowerStatusTest)(benchmark::State &state)
{
    int32_t ret;
    DispPowerStatus powerStatus = DispPowerStatus::POWER_STATUS_OFF;
    for (auto _ : state) {
        ret = g_composerDevice->GetDisplayPowerStatus(g_displayIds[0], powerStatus);
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, GetDisplayPowerStatusTest)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: SetDisplayPowerStatusTest
  * @tc.desc: Benchmarktest for interface SetDisplayPowerStatus.
  */
BENCHMARK_F(DisplayBenchmarkTest, SetDisplayPowerStatusTest)(benchmark::State &state)
{
    int32_t ret;
    for (auto _ : state) {
        ret = g_composerDevice->SetDisplayPowerStatus(g_displayIds[0], DispPowerStatus::POWER_STATUS_ON);
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, SetDisplayPowerStatusTest)->
    Iterations(30)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: GetDisplayBacklightTest
  * @tc.desc: Benchmarktest for interface GetDisplayBacklight.
  */
BENCHMARK_F(DisplayBenchmarkTest, GetDisplayBacklightTest)(benchmark::State &state)
{
    int32_t ret;
    uint32_t level;
    for (auto _ : state) {
        ret = g_composerDevice->GetDisplayBacklight(g_displayIds[0], level);
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, GetDisplayBacklightTest)->
    Iterations(30)->Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: SetDisplayBacklightTest
  * @tc.desc: Benchmarktest for interface SetDisplayBacklight.
  */
BENCHMARK_F(DisplayBenchmarkTest, SetDisplayBacklightTest)(benchmark::State &state)
{
    int32_t ret;
    const uint32_t level = 10;
    for (auto _ : state) {
        ret = g_composerDevice->SetDisplayBacklight(g_displayIds[0], level);
    }
    EXPECT_EQ(DISPLAY_SUCCESS, ret);
}

BENCHMARK_REGISTER_F(DisplayBenchmarkTest, SetDisplayBacklightTest)->
    Iterations(30)->Repetitions(3)->ReportAggregatesOnly();

} // namespace

int main(int argc, char** argv)
{
    int ret = HdiTestDevice::GetInstance().InitDevice();
    DISPLAY_TEST_CHK_RETURN((ret != DISPLAY_SUCCESS), DISPLAY_FAILURE, DISPLAY_TEST_LOGE("Init Device Failed"));
    ::testing::InitGoogleTest(&argc, argv);
    ::benchmark::Initialize(&argc, argv);
    if (::benchmark::ReportUnrecognizedArguments(argc, argv)) {
        return 1;
    }
    g_composerDevice = HdiTestDevice::GetInstance().GetDeviceInterface();
    g_gralloc.reset(IDisplayBuffer::Get());
    auto display = HdiTestDevice::GetInstance().GetFirstDisplay();
    if (display != nullptr) {
        g_displayIds = HdiTestDevice::GetInstance().GetDevIds();
        display->SetDisplayVsyncEnabled(false);
    }
    ::benchmark::RunSpecifiedBenchmarks();
    ::benchmark::Shutdown();
    HdiTestDevice::GetInstance().GetFirstDisplay()->ResetClientLayer();
    return ret;
}