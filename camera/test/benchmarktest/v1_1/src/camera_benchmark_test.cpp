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
    cameraTest = std::make_shared<OHOS::Camera::HdiCommonV1_1>();
    cameraTest->Init();
    cameraTest->Open(DEVICE_0);
}

void CameraBenchmarkTest::TearDown(const ::benchmark::State &state)
{
    cameraTest->Close();
}

/**
  * @tc.name: Prelaunch
  * @tc.desc: Prelaunch, benchmark.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkTest, SUB_Prelaunch_benchmark_001)(
    benchmark::State &st)
{
    EXPECT_EQ(false, cameraTest->serviceV1_1 == nullptr);
    cameraTest->prelaunchConfig = std::make_shared<OHOS::HDI::Camera::V1_1::PrelaunchConfig>();
    cameraTest->prelaunchConfig->cameraId = {};
    cameraTest->prelaunchConfig->streamInfos_V1_1 = {};
    cameraTest->prelaunchConfig->setting = {};
    for (auto _ : st) {
        cameraTest->rc = cameraTest->serviceV1_1->Prelaunch(*cameraTest->prelaunchConfig);
    }
}
BENCHMARK_REGISTER_F(CameraBenchmarkTest, SUB_Prelaunch_benchmark_001)->Iterations(ITERATION_FREQUENCY)->
    Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: GetStreamOperator_V1_1
  * @tc.desc: GetStreamOperator_V1_1, benchmark.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkTest, SUB_GetStreamOperator_V1_1_benchmark_002)(
    benchmark::State &st)
{
    EXPECT_EQ(false, cameraTest->cameraDeviceV1_1 == nullptr);
    cameraTest->streamOperatorCallback = new OHOS::Camera::HdiCommon::TestStreamOperatorCallback();
    for (auto _ : st) {
        cameraTest->rc = cameraTest->cameraDeviceV1_1->GetStreamOperator_V1_1(cameraTest->streamOperatorCallback,
            cameraTest->streamOperator_V1_1);
    }
}

BENCHMARK_REGISTER_F(CameraBenchmarkTest, SUB_GetStreamOperator_V1_1_benchmark_002)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: GetDefaultSettings
  * @tc.desc: GetDefaultSettings, benchmark.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkTest, SUB_GetDefaultSettings_benchmark_003)(
    benchmark::State &st)
{
    EXPECT_EQ(false, cameraTest->cameraDeviceV1_1 == nullptr);
    cameraTest->streamOperatorCallback = new OHOS::Camera::HdiCommon::TestStreamOperatorCallback();
    for (auto _ : st) {
        cameraTest->rc = cameraTest->cameraDeviceV1_1->GetDefaultSettings(cameraTest->abilityVec);
    }
}
BENCHMARK_REGISTER_F(CameraBenchmarkTest, SUB_GetDefaultSettings_benchmark_003)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_MAIN();

