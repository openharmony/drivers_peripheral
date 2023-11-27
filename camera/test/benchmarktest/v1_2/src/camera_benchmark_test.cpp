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

#include "camera_benchmark_test.h"

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;

constexpr int32_t ITERATION_FREQUENCY = 100;
constexpr int32_t REPETITION_FREQUENCY = 3;

void CameraBenchmarkTest::SetUp(const ::benchmark::State &state)
{
    cameraTest = std::make_shared<OHOS::Camera::Test>();
    cameraTest->Init();
    cameraTest->Open();
}

void CameraBenchmarkTest::TearDown(const ::benchmark::State &state)
{
    cameraTest->Close();
}

/**
  * @tc.name: NotifyDeviceStateChangeInfo
  * @tc.desc: benchmark
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkTest, NotifyDeviceStateChangeInfo_benchmark_001)(
    benchmark::State &st)
{
    EXPECT_EQ(false, cameraTest->serviceV1_2 == nullptr);
    int notifyType = 1;
    int deviceState = 1008;
    for (auto _ : st) {
        cameraTest->rc = cameraTest->serviceV1_2->NotifyDeviceStateChangeInfo(notifyType, deviceState);
    }
}
BENCHMARK_REGISTER_F(CameraBenchmarkTest, NotifyDeviceStateChangeInfo_benchmark_001)->Iterations(ITERATION_FREQUENCY)->
    Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: PreCameraSwitch
  * @tc.desc: benchmark
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkTest, PreCameraSwitch_benchmark_001)(
    benchmark::State &st)
{
    EXPECT_EQ(false, cameraTest->serviceV1_2 == nullptr);
    cameraTest->serviceV1_2->GetCameraIds(cameraTest->cameraIds);
    for (auto _ : st) {
        cameraTest->rc = cameraTest->serviceV1_2->PreCameraSwitch(cameraTest->cameraIds.front());
    }
}
BENCHMARK_REGISTER_F(CameraBenchmarkTest, PreCameraSwitch_benchmark_001)->Iterations(ITERATION_FREQUENCY)->
    Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: PrelaunchWithOpMode
  * @tc.desc: Prelaunch, benchmark.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkTest, PrelaunchWithOpMode_benchmark_001)(
    benchmark::State &st)
{
    EXPECT_EQ(false, cameraTest->serviceV1_2 == nullptr);
    cameraTest->serviceV1_2->GetCameraIds(cameraTest->cameraIds);

    cameraTest->prelaunchConfig = std::make_shared<OHOS::HDI::Camera::V1_1::PrelaunchConfig>();
    cameraTest->prelaunchConfig->cameraId = cameraTest->cameraIds.front();
    cameraTest->prelaunchConfig->streamInfos_V1_1 = {};
    cameraTest->prelaunchConfig->setting = {};
    for (auto _ : st) {
        cameraTest->rc = cameraTest->serviceV1_2->PrelaunchWithOpMode(
            *cameraTest->prelaunchConfig, OHOS::HDI::Camera::V1_2::NORMAL);
    }
}
BENCHMARK_REGISTER_F(CameraBenchmarkTest, PrelaunchWithOpMode_benchmark_001)->Iterations(ITERATION_FREQUENCY)->
    Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_MAIN();

