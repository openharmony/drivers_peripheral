/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "camera_benchmark_securestream_test.h"

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;
constexpr int32_t ITERATION_FREQUENCY = 100;
constexpr int32_t REPETITION_FREQUENCY = 3;

void CameraBenchmarkSecureStreamTest::SetUp(const ::benchmark::State &state)
{
    cameraTest = std::make_shared<OHOS::Camera::HdiCommonV1_3>();
    cameraTest->Init();
    cameraTest->OpenSecureCamera(DEVICE_0);
}

void CameraBenchmarkSecureStreamTest::TearDown(const ::benchmark::State &state)
{
    cameraTest->Close();
}

/**
  * @tc.name: OpenSecureCamera
  * @tc.desc: benchmark
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkSecureStreamTest, OpenSecureCamera_benchmark_001)(
    benchmark::State &st)
{
    for (auto _ : st) {
    }
}
BENCHMARK_REGISTER_F(CameraBenchmarkSecureStreamTest, OpenSecureCamera_benchmark_001)->\
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: GetSecureCameraSeq
  * @tc.desc: benchmark
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkSecureStreamTest, GetSecureCameraSeq_benchmark_002)(
    benchmark::State &st)
{
    EXPECT_NE(cameraTest, nullptr);
    EXPECT_NE(cameraTest->cameraDeviceV1_3, nullptr);
    uint64_t SeqId;
    for (auto _ : st) {
        cameraTest->cameraDeviceV1_3->GetSecureCameraSeq(SeqId);
    }
}
BENCHMARK_REGISTER_F(CameraBenchmarkSecureStreamTest, GetSecureCameraSeq_benchmark_002)->\
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: EnableResult_benchmark_001
  * @tc.desc: benchmark
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkSecureStreamTest, EnableResult_benchmark_001)(
    benchmark::State &st)
{
    cameraTest->streamOperatorCallbackV1_3 = new OHOS::Camera::HdiCommonV1_3::TestStreamOperatorCallbackV1_3();
    cameraTest->cameraDeviceV1_3->GetStreamOperator_V1_3(cameraTest->streamOperatorCallbackV1_3,
        cameraTest->streamOperator_V1_3);
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(
        cameraTest->itemCapacity, cameraTest->dataCapacity);
    std::vector<uint8_t> detectTypes;
    detectTypes.push_back(static_cast<uint8_t>(OHOS_CAMERA_HUMAN_FACE_DETECT));
    uint8_t* typesToEnable = detectTypes.data();
    meta->addEntry(OHOS_CONTROL_STATISTICS_DETECT_SETTING, typesToEnable, detectTypes.size());
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    for (auto _ : st) {
        cameraTest->streamOperator_V1_3->EnableResult(cameraTest->streamIdVideo, setting);
    }
}
BENCHMARK_REGISTER_F(CameraBenchmarkSecureStreamTest, EnableResult_benchmark_001)->\
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: DisableResult_benchmark_001
  * @tc.desc: benchmark
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkSecureStreamTest, DisableResult_benchmark_001)(
    benchmark::State &st)
{
    cameraTest->streamOperatorCallbackV1_3 = new OHOS::Camera::HdiCommonV1_3::TestStreamOperatorCallbackV1_3();
    cameraTest->cameraDeviceV1_3->GetStreamOperator_V1_3(cameraTest->streamOperatorCallbackV1_3,
        cameraTest->streamOperator_V1_3);
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(
        cameraTest->itemCapacity, cameraTest->dataCapacity);
    std::vector<uint8_t> detectTypes;
    detectTypes.push_back(static_cast<uint8_t>(OHOS_CAMERA_HUMAN_FACE_DETECT));
    uint8_t* typesToEnable = detectTypes.data();
    meta->addEntry(OHOS_CONTROL_STATISTICS_DETECT_SETTING, typesToEnable, detectTypes.size());
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    for (auto _ : st) {
        cameraTest->streamOperator_V1_3->DisableResult(cameraTest->streamIdVideo, setting);
    }
}
BENCHMARK_REGISTER_F(CameraBenchmarkSecureStreamTest, DisableResult_benchmark_001)->\
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();


BENCHMARK_MAIN();

