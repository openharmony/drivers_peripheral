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
}

void CameraBenchmarkTest::TearDown(const ::benchmark::State &state)
{
    cameraTest->Close();
}

/**
  * @tc.name: OpenCamera
  * @tc.desc: OpenCamera, benchmark.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkTest, SUB_OpenCamera_benchmark_001)(
    benchmark::State &st)
{
    EXPECT_EQ(true, cameraTest->cameraDevice == nullptr);
    if (cameraTest->cameraDevice == nullptr) {
        cameraTest->service->GetCameraIds(cameraTest->cameraIds);
        cameraTest->deviceCallback = new OHOS::Camera::Test::DemoCameraDeviceCallback();
        for (auto _ : st) {
            cameraTest->rc = cameraTest->service->OpenCamera(cameraTest->cameraIds.front(),
                cameraTest->deviceCallback, cameraTest->cameraDevice);
        }
        EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
    }
}
BENCHMARK_REGISTER_F(CameraBenchmarkTest, SUB_OpenCamera_benchmark_001)->Iterations(ITERATION_FREQUENCY)->
    Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: GetCameraIds
  * @tc.desc: GetCameraIds, benchmark.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkTest, SUB_GetCameraIds_benchmark_002)(
    benchmark::State &st)
{
    //std::cout << "==========[test log] GetCameraIds, success."<< std::endl;
    for (auto _ : st) {
        cameraTest->rc = cameraTest->service->GetCameraIds(cameraTest->cameraIds);
    }
}
BENCHMARK_REGISTER_F(CameraBenchmarkTest, SUB_GetCameraIds_benchmark_002)->Iterations(ITERATION_FREQUENCY)->
    Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: GetStreamOperator
  * @tc.desc: GetStreamOperator, benchmark.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkTest, SUB_GetStreamOperator_benchmark_003)(
    benchmark::State &st)
{
    cameraTest->Open();
    cameraTest->streamOperatorCallback = new OHOS::Camera::Test::TestStreamOperatorCallback();
    for (auto _ : st) {
        cameraTest->rc = cameraTest->cameraDevice->GetStreamOperator(cameraTest->streamOperatorCallback,
            cameraTest->streamOperator);
    }
}

BENCHMARK_REGISTER_F(CameraBenchmarkTest, SUB_GetStreamOperator_benchmark_003)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: GetCameraAbility
  * @tc.desc: GetCameraAbility, benchmark.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkTest, SUB_GetCameraAbility_benchmark_004)(
    benchmark::State &st)
{
    cameraTest->rc = cameraTest->service->GetCameraIds(cameraTest->cameraIds);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
    for (auto _ : st) {
        cameraTest->rc = cameraTest->service->GetCameraAbility(cameraTest->cameraIds.front(), cameraTest->abilityVec);
    }
}
BENCHMARK_REGISTER_F(CameraBenchmarkTest, SUB_GetCameraAbility_benchmark_004)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: SetFlashlight
  * @tc.desc: SetFlashlight, benchmark.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkTest, SUB_SetFlashlight_benchmark_005)(
    benchmark::State &st)
{
    cameraTest->service->GetCameraIds(cameraTest->cameraIds);
    cameraTest->status = true;
    for (auto _ : st) {
        cameraTest->rc = cameraTest->service->SetFlashlight(cameraTest->cameraIds.front(), cameraTest->status);
    }
}
BENCHMARK_REGISTER_F(CameraBenchmarkTest, SUB_SetFlashlight_benchmark_005)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();


/**
  * @tc.name: SetResultMode
  * @tc.desc: SetResultMode, benchmark.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkTest, SUB_SetResultMode_benchmark_006)(
    benchmark::State &st)
{
    cameraTest->Open();
    for (auto _ : st) {
        cameraTest->rc = cameraTest->cameraDevice->SetResultMode(PER_FRAME);
    }
}
BENCHMARK_REGISTER_F(CameraBenchmarkTest, SUB_SetResultMode_benchmark_006)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: CreateStreams
  * @tc.desc: CreateStreams, benchmark.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkTest, SUB_CreateStreams_benchmark_007)(
    benchmark::State &st)
{
    cameraTest->Open();
    cameraTest->streamOperatorCallback = new OHOS::Camera::Test::TestStreamOperatorCallback();
    cameraTest->rc = cameraTest->cameraDevice->GetStreamOperator(cameraTest->streamOperatorCallback,
        cameraTest->streamOperator);
    EXPECT_EQ(false, cameraTest->rc != HDI::Camera::V1_0::NO_ERROR || cameraTest->streamOperator == nullptr);
    std::shared_ptr<StreamInfo> streamInfoPre = std::make_shared<StreamInfo>();
    streamInfoPre->streamId_ = cameraTest->streamIdPreview;
    streamInfoPre->width_ = cameraTest->previewWidth;
    streamInfoPre->height_ = cameraTest->previewHeight;
    streamInfoPre->format_ = cameraTest->previewFormat;
    streamInfoPre->dataspace_ = OHOS::Camera::UT_DATA_SIZE;
    streamInfoPre->intent_ = PREVIEW;
    streamInfoPre->tunneledMode_ = OHOS::Camera::UT_TUNNEL_MODE;
    std::shared_ptr<OHOS::Camera::Test::StreamConsumer> consumer_pre =
        std::make_shared<OHOS::Camera::Test::StreamConsumer>();
    if (streamInfoPre->bufferQueue_ == nullptr) {
        streamInfoPre->bufferQueue_ = consumer_pre->CreateProducerSeq([this](void* addr, uint32_t size) {
            CAMERA_LOGD("On Buffer Available: size = %{public}u", size);
        });
    }
    streamInfoPre->bufferQueue_->producer_->SetQueueSize(OHOS::Camera::UT_DATA_SIZE);
    std::vector<StreamInfo> streamInfos;
    streamInfos.push_back(*streamInfoPre);
    for (auto _ : st) {
        cameraTest->rc = cameraTest->streamOperator->CreateStreams(streamInfos);
    }
}
BENCHMARK_REGISTER_F(CameraBenchmarkTest, SUB_CreateStreams_benchmark_007)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: CommitStreams
  * @tc.desc: CommitStreams, benchmark.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkTest, SUB_CommitStreams_benchmark_008)(
    benchmark::State &st)
{
    cameraTest->Open();
    cameraTest->streamOperatorCallback = new OHOS::Camera::Test::TestStreamOperatorCallback();
    cameraTest->rc = cameraTest->cameraDevice->GetStreamOperator(cameraTest->streamOperatorCallback,
        cameraTest->streamOperator);
    EXPECT_EQ(false, cameraTest->rc != HDI::Camera::V1_0::NO_ERROR || cameraTest->streamOperator == nullptr);
    std::shared_ptr<StreamInfo> streamInfoPre = std::make_shared<StreamInfo>();
    streamInfoPre->streamId_ = cameraTest->streamIdPreview;
    streamInfoPre->width_ = cameraTest->previewWidth;
    streamInfoPre->height_ = cameraTest->previewHeight;
    streamInfoPre->format_ = cameraTest->previewFormat;
    streamInfoPre->dataspace_ = OHOS::Camera::UT_DATA_SIZE;
    streamInfoPre->intent_ = PREVIEW;
    streamInfoPre->tunneledMode_ = OHOS::Camera::UT_TUNNEL_MODE;
    std::shared_ptr<OHOS::Camera::Test::StreamConsumer> consumer_pre =
        std::make_shared<OHOS::Camera::Test::StreamConsumer>();
    streamInfoPre->bufferQueue_ = consumer_pre->CreateProducerSeq([this](void* addr, uint32_t size) {
        CAMERA_LOGD("On Buffer Available: size = %{public}u", size);
    });
    streamInfoPre->bufferQueue_->producer_->SetQueueSize(OHOS::Camera::UT_DATA_SIZE);
    std::vector<StreamInfo> streamInfos;
    streamInfos.push_back(*streamInfoPre);
    cameraTest->rc = cameraTest->streamOperator->CreateStreams(streamInfos);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);

    for (auto _ : st) {
        cameraTest->rc = cameraTest->streamOperator->CommitStreams(OperationMode::NORMAL, cameraTest->abilityVec);
    }
}
BENCHMARK_REGISTER_F(CameraBenchmarkTest, SUB_CommitStreams_benchmark_008)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: GetStreamAttributes
  * @tc.desc: GetStreamAttributes, benchmark.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkTest, SUB_GetStreamAttributes_benchmark_009)(
    benchmark::State &st)
{
    cameraTest->Open();
    cameraTest->intents = {PREVIEW};
    cameraTest->StartStream(cameraTest->intents);
    std::vector<StreamAttribute> attributes;
    for (auto _ : st) {
        cameraTest->rc = cameraTest->streamOperator->GetStreamAttributes(attributes);
    }
}
BENCHMARK_REGISTER_F(CameraBenchmarkTest, SUB_GetStreamAttributes_benchmark_009)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: ReleaseStreams
  * @tc.desc: ReleaseStreams, benchmark.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkTest, SUB_ReleaseStreams_benchmark_0010)(
    benchmark::State &st)
{
    cameraTest->Open();
    cameraTest->intents = {PREVIEW};
    cameraTest->StartStream(cameraTest->intents);
    for (auto _ : st) {
        cameraTest->rc = cameraTest->streamOperator->ReleaseStreams({cameraTest->streamIdPreview});
    }
}
BENCHMARK_REGISTER_F(CameraBenchmarkTest, SUB_ReleaseStreams_benchmark_0010)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: Capture
  * @tc.desc: Capture, benchmark.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkTest, SUB_Capture_benchmark_0011)(
    benchmark::State &st)
{
    cameraTest->Open();
    cameraTest->intents = {PREVIEW};
    cameraTest->StartStream(cameraTest->intents);
    int captureId = 2001;
    cameraTest->captureInfo = std::make_shared<CaptureInfo>();
    cameraTest->captureInfo->streamIds_ = {-1};
    cameraTest->captureInfo->captureSetting_ = cameraTest->abilityVec;
    cameraTest->captureInfo->enableShutterCallback_ = true;
    for (auto _ : st) {
        cameraTest->rc = cameraTest->streamOperator->Capture(captureId, *cameraTest->captureInfo, true);
    }
}
BENCHMARK_REGISTER_F(CameraBenchmarkTest, SUB_Capture_benchmark_0011)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: Close
  * @tc.desc: Close, benchmark.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkTest, SUB_Close_benchmark_0012)(
    benchmark::State &st)
{
    cameraTest->Open();
    for (auto _ : st) {
        cameraTest->cameraDevice->Close();
    }
}
BENCHMARK_REGISTER_F(CameraBenchmarkTest, SUB_Close_benchmark_0012)->
    Iterations(ITERATION_FREQUENCY)->Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

/**
  * @tc.name: CancelCapture
  * @tc.desc: CancelCapture, benchmark.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkTest, SUB_CancelCapture_benchmark_0013)(
    benchmark::State &st)
{
    cameraTest->Open();
    cameraTest->intents = {PREVIEW};
    cameraTest->StartStream(cameraTest->intents);
    int captureId = 2001;
    cameraTest->captureInfo = std::make_shared<CaptureInfo>();
    cameraTest->captureInfo->streamIds_ = {-1};
    cameraTest->captureInfo->captureSetting_ = cameraTest->abilityVec;
    cameraTest->captureInfo->enableShutterCallback_ = true;
    cameraTest->rc = cameraTest->streamOperator->Capture(captureId, *cameraTest->captureInfo, true);
    for (auto _ : st) {
        cameraTest->streamOperator->CancelCapture(captureId);
    }
}
BENCHMARK_REGISTER_F(CameraBenchmarkTest, SUB_CancelCapture_benchmark_0013)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: EnableResult
  * @tc.desc: EnableResult, benchmark.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkTest, SUB_EnableResult_benchmark_0014)(
    benchmark::State &st)
{
    cameraTest->Open();
    std::vector<int32_t> resultsList;
    resultsList.push_back(OHOS_CAMERA_STREAM_ID);
    resultsList.push_back(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION);
    for (auto _ : st) {
        cameraTest->cameraDevice->EnableResult(resultsList);
    }
}
BENCHMARK_REGISTER_F(CameraBenchmarkTest, SUB_EnableResult_benchmark_0014)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: DisableResult
  * @tc.desc: DisableResult, benchmark.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkTest, SUB_DisableResult_benchmark_0015)(
    benchmark::State &st)
{
    cameraTest->Open();
    std::vector<OHOS::Camera::MetaType> resultsOriginal;
    for (auto _ : st) {
        cameraTest->cameraDevice->DisableResult(resultsOriginal);
    }
}
BENCHMARK_REGISTER_F(CameraBenchmarkTest, SUB_DisableResult_benchmark_0015)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: UpdateSettings
  * @tc.desc: UpdateSettings, benchmark.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkTest, SUB_UpdateSettings_benchmark_0016)(
    benchmark::State &st)
{
    cameraTest->Open();
    cameraTest->intents = {PREVIEW};
    cameraTest->StartStream(cameraTest->intents);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    std::shared_ptr<OHOS::Camera::CameraMetadata> meta = std::make_shared<OHOS::Camera::CameraSetting>(100, 200);
    int32_t expo = 0xa0;
    meta->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &expo, 1);
    std::vector<uint8_t> metaVec;
    OHOS::Camera::MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    for (auto _ : st) {
        cameraTest->cameraDevice->UpdateSettings(metaVec);
    }
}
BENCHMARK_REGISTER_F(CameraBenchmarkTest, SUB_UpdateSettings_benchmark_0016)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: GetEnabledResults
  * @tc.desc: GetEnabledResults, benchmark.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkTest, SUB_GetEnabledResults_benchmark_0017)(
    benchmark::State &st)
{
    cameraTest->Open();
    std::vector<OHOS::Camera::MetaType> enableTypes;
    for (auto _ : st) {
        cameraTest->cameraDevice->GetEnabledResults(enableTypes);
    }
}
BENCHMARK_REGISTER_F(CameraBenchmarkTest, SUB_GetEnabledResults_benchmark_0017)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: IsStreamsSupported
  * @tc.desc: IsStreamsSupported, benchmark.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkTest, SUB_IsStreamsSupported_benchmark_0018)(
    benchmark::State &st)
{
    cameraTest->Open();
    EXPECT_EQ(false, cameraTest->cameraDevice == nullptr);
    cameraTest->streamOperatorCallback = new OHOS::Camera::Test::TestStreamOperatorCallback();
    cameraTest->rc = cameraTest->cameraDevice->GetStreamOperator(cameraTest->streamOperatorCallback,
        cameraTest->streamOperator);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
    std::shared_ptr<OHOS::Camera::CameraMetadata> modeSetting = std::make_shared<OHOS::Camera::CameraMetadata>(2, 128);
    int64_t expoTime = 0;
    modeSetting->addEntry(OHOS_SENSOR_EXPOSURE_TIME, &expoTime, 1);
    int64_t colorGains[4] = {0};
    modeSetting->addEntry(OHOS_SENSOR_COLOR_CORRECTION_GAINS, &colorGains, 4);

    cameraTest->streamInfo = std::make_shared<StreamInfo>();
    cameraTest->streamInfo->streamId_ = 1001;
    cameraTest->streamInfo->format_ = PIXEL_FMT_YCRCB_420_SP;
    cameraTest->streamInfo->height_ = 480;
    cameraTest->streamInfo->width_ = 640;
    cameraTest->streamInfo->dataspace_ = 8;

    std::shared_ptr<OHOS::Camera::Test::StreamConsumer> consumer =
        std::make_shared<OHOS::Camera::Test::StreamConsumer>();
    cameraTest->streamInfo->bufferQueue_ =  consumer->CreateProducerSeq([this](void* addr, uint32_t size) {
        cameraTest->DumpImageFile(cameraTest->streamIdPreview, "yuv", addr, size);
    });

    cameraTest->streamInfo->bufferQueue_->producer_->SetQueueSize(8);
    cameraTest->consumerMap_[cameraTest->streamInfo->intent_] = consumer;
    cameraTest->streamInfo->intent_ = PREVIEW;
    cameraTest->streamInfo->tunneledMode_ = 5;
    StreamSupportType pType;
    std::vector<StreamInfo> streams;
    streams.push_back(*cameraTest->streamInfo);
    std::vector<uint8_t> modeSettingVec;
    OHOS::Camera::MetadataUtils::ConvertMetadataToVec(modeSetting, modeSettingVec);
    for (auto _ : st) {
        cameraTest->streamOperator->IsStreamsSupported(OperationMode::NORMAL, modeSettingVec,
        streams, pType);
    }
}
BENCHMARK_REGISTER_F(CameraBenchmarkTest, SUB_IsStreamsSupported_benchmark_0018)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: AttachBufferQueue
  * @tc.desc: AttachBufferQueue, benchmark.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkTest, SUB_AttachBufferQueue_benchmark_0019)(
    benchmark::State &st)
{
    cameraTest->Open();
    cameraTest->streamOperatorCallback = new OHOS::Camera::Test::TestStreamOperatorCallback();
    cameraTest->rc = cameraTest->cameraDevice->GetStreamOperator(cameraTest->streamOperatorCallback,
        cameraTest->streamOperator);

    cameraTest->streamInfo = std::make_shared<StreamInfo>();
    cameraTest->streamInfo->streamId_ = 1201; // PREVIEW streamId
    cameraTest->streamInfo->width_ = 720; // Pixel Width
    cameraTest->streamInfo->height_ = 480; // Pixel height
    cameraTest->streamInfo->format_ = PIXEL_FMT_YCRCB_420_SP;
    cameraTest->streamInfo->dataspace_ = UT_DATA_SIZE;
    cameraTest->streamInfo->intent_ = PREVIEW;
    cameraTest->streamInfo->tunneledMode_ = UT_TUNNEL_MODE;
    std::shared_ptr<OHOS::Camera::Test::StreamConsumer> consumer =
        std::make_shared<OHOS::Camera::Test::StreamConsumer>();
    cameraTest->streamInfo->bufferQueue_ = consumer->CreateProducerSeq([this](void* addr, uint32_t size) {
        cameraTest->DumpImageFile(cameraTest->streamIdPreview, "yuv", addr, size);
    });

    cameraTest->streamInfo->bufferQueue_->producer_->SetQueueSize(UT_DATA_SIZE);
    cameraTest->consumerMap_[cameraTest->streamInfo->intent_] = consumer;
    cameraTest->streamInfos.push_back(*cameraTest->streamInfo);

    cameraTest->streamInfoSnapshot = std::make_shared<StreamInfo>();
    cameraTest->streamInfoSnapshot->streamId_ = 1202; // STILL_CAPTURE streamId
    cameraTest->streamInfoSnapshot->width_ = 720; // Pixel Width
    cameraTest->streamInfoSnapshot->height_ = 480; // Pixel height
    cameraTest->streamInfoSnapshot->format_ = PIXEL_FMT_YCRCB_420_SP;
    cameraTest->streamInfoSnapshot->dataspace_ = UT_DATA_SIZE;
    cameraTest->streamInfoSnapshot->intent_ = STILL_CAPTURE;
    cameraTest->streamInfoSnapshot->tunneledMode_ = UT_TUNNEL_MODE;
    std::shared_ptr<OHOS::Camera::Test::StreamConsumer> snapshotConsumer =
        std::make_shared<OHOS::Camera::Test::StreamConsumer>();
    cameraTest->streamInfoSnapshot->bufferQueue_ = snapshotConsumer->CreateProducerSeq([this](void* addr,
        uint32_t size) {
        cameraTest->DumpImageFile(cameraTest->streamIdPreview, "yuv", addr, size);
    });

    cameraTest->streamInfoSnapshot->bufferQueue_->producer_->SetQueueSize(UT_DATA_SIZE);
    cameraTest->consumerMap_[cameraTest->streamInfoSnapshot->intent_] = snapshotConsumer;
    cameraTest->streamInfos.push_back(*cameraTest->streamInfoSnapshot);

    cameraTest->rc = cameraTest->streamOperator->CreateStreams(cameraTest->streamInfos);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);

    std::shared_ptr<OHOS::Camera::Test::StreamConsumer> preview_consumer =
        std::make_shared<OHOS::Camera::Test::StreamConsumer>();
    OHOS::sptr<OHOS::IBufferProducer> producerTemp = preview_consumer->CreateProducer([this](void* addr,
        uint32_t size) {
        cameraTest->DumpImageFile(cameraTest->streamIdPreview, "yuv", addr, size);
    });

    OHOS::sptr<BufferProducerSequenceable> bufferQueue = new BufferProducerSequenceable(producerTemp);
    for (auto _ : st) {
        cameraTest->streamOperator->AttachBufferQueue(cameraTest->streamInfoSnapshot->streamId_,
            bufferQueue);
    }
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);

    cameraTest->rc = cameraTest->streamOperator->DetachBufferQueue(cameraTest->streamInfoSnapshot->streamId_);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);

    std::vector<int> streamIds = {cameraTest->streamInfo->streamId_, cameraTest->streamInfoSnapshot->streamId_};
    cameraTest->rc = cameraTest->streamOperator->ReleaseStreams(streamIds);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
}
BENCHMARK_REGISTER_F(CameraBenchmarkTest, SUB_AttachBufferQueue_benchmark_0019)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: DetachBufferQueue
  * @tc.desc: DetachBufferQueue, benchmark.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkTest, SUB_DetachBufferQueue_benchmark_0020)(
    benchmark::State &st)
{
    cameraTest->Open();
    cameraTest->streamOperatorCallback = new OHOS::Camera::Test::TestStreamOperatorCallback();
    cameraTest->rc = cameraTest->cameraDevice->GetStreamOperator(cameraTest->streamOperatorCallback,
        cameraTest->streamOperator);

    cameraTest->streamInfo = std::make_shared<StreamInfo>();
    cameraTest->streamInfo->streamId_ = 1201; // PREVIEW streamId
    cameraTest->streamInfo->width_ = 720; // Pixel Width
    cameraTest->streamInfo->height_ = 480; // Pixel height
    cameraTest->streamInfo->format_ = PIXEL_FMT_YCRCB_420_SP;
    cameraTest->streamInfo->dataspace_ = UT_DATA_SIZE;
    cameraTest->streamInfo->intent_ = PREVIEW;
    cameraTest->streamInfo->tunneledMode_ = UT_TUNNEL_MODE;
    std::shared_ptr<OHOS::Camera::Test::StreamConsumer> consumer =
        std::make_shared<OHOS::Camera::Test::StreamConsumer>();
    cameraTest->streamInfo->bufferQueue_ = consumer->CreateProducerSeq([this](void* addr, uint32_t size) {
        cameraTest->DumpImageFile(cameraTest->streamIdPreview, "yuv", addr, size);
    });

    cameraTest->streamInfo->bufferQueue_->producer_->SetQueueSize(UT_DATA_SIZE);
    cameraTest->consumerMap_[cameraTest->streamInfo->intent_] = consumer;
    cameraTest->streamInfos.push_back(*cameraTest->streamInfo);

    cameraTest->streamInfoSnapshot = std::make_shared<StreamInfo>();
    cameraTest->streamInfoSnapshot->streamId_ = 1202; // STILL_CAPTURE streamId
    cameraTest->streamInfoSnapshot->width_ = 720; // Pixel Width
    cameraTest->streamInfoSnapshot->height_ = 480; // Pixel height
    cameraTest->streamInfoSnapshot->format_ = PIXEL_FMT_YCRCB_420_SP;
    cameraTest->streamInfoSnapshot->dataspace_ = UT_DATA_SIZE;
    cameraTest->streamInfoSnapshot->intent_ = STILL_CAPTURE;
    cameraTest->streamInfoSnapshot->tunneledMode_ = UT_TUNNEL_MODE;
    std::shared_ptr<OHOS::Camera::Test::StreamConsumer> snapshotConsumer =
        std::make_shared<OHOS::Camera::Test::StreamConsumer>();
    cameraTest->streamInfoSnapshot->bufferQueue_ = snapshotConsumer->CreateProducerSeq([this](void* addr,
        uint32_t size) {
        cameraTest->DumpImageFile(cameraTest->streamIdPreview, "yuv", addr, size);
    });

    cameraTest->streamInfoSnapshot->bufferQueue_->producer_->SetQueueSize(UT_DATA_SIZE);
    cameraTest->consumerMap_[cameraTest->streamInfoSnapshot->intent_] = snapshotConsumer;
    cameraTest->streamInfos.push_back(*cameraTest->streamInfoSnapshot);

    cameraTest->rc = cameraTest->streamOperator->CreateStreams(cameraTest->streamInfos);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);

    std::shared_ptr<OHOS::Camera::Test::StreamConsumer> preview_consumer =
        std::make_shared<OHOS::Camera::Test::StreamConsumer>();
    OHOS::sptr<OHOS::IBufferProducer> producerTemp = preview_consumer->CreateProducer([this](void* addr,
        uint32_t size) {
        cameraTest->DumpImageFile(cameraTest->streamIdPreview, "yuv", addr, size);
    });

    OHOS::sptr<BufferProducerSequenceable> bufferQueue = new BufferProducerSequenceable(producerTemp);

    cameraTest->rc = cameraTest->streamOperator->AttachBufferQueue(cameraTest->streamInfoSnapshot->streamId_,
        bufferQueue);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);

    for (auto _ : st) {
        cameraTest->streamOperator->DetachBufferQueue(cameraTest->streamInfoSnapshot->streamId_);
    }

    std::vector<int> streamIds = {cameraTest->streamInfo->streamId_, cameraTest->streamInfoSnapshot->streamId_};
    cameraTest->rc = cameraTest->streamOperator->ReleaseStreams(streamIds);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
}
BENCHMARK_REGISTER_F(CameraBenchmarkTest, SUB_DetachBufferQueue_benchmark_0020)->Iterations(100)->
    Repetitions(3)->ReportAggregatesOnly();

/**
  * @tc.name: ChangeToOfflineStream
  * @tc.desc: ChangeToOfflineStream, benchmark.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
BENCHMARK_F(CameraBenchmarkTest, SUB_ChangeToOfflineStream_benchmark_021)(
    benchmark::State &st)
{
    cameraTest->Open();
    cameraTest->streamOperatorCallback = new OHOS::Camera::Test::TestStreamOperatorCallback();
    cameraTest->rc = cameraTest->cameraDevice->GetStreamOperator(cameraTest->streamOperatorCallback,
        cameraTest->streamOperator);

    cameraTest->streamInfo = std::make_shared<StreamInfo>();
    cameraTest->streamInfo->streamId_ = 1201;
    cameraTest->streamInfo->width_ = 720;
    cameraTest->streamInfo->height_ = 480;
    cameraTest->streamInfo->format_ = PIXEL_FMT_YCRCB_420_SP;
    cameraTest->streamInfo->dataspace_ = UT_DATA_SIZE;
    cameraTest->streamInfo->intent_ = PREVIEW;
    cameraTest->streamInfo->tunneledMode_ = UT_TUNNEL_MODE;
    std::shared_ptr<OHOS::Camera::Test::StreamConsumer> consumer =
        std::make_shared<OHOS::Camera::Test::StreamConsumer>();
    cameraTest->streamInfo->bufferQueue_ = consumer->CreateProducerSeq([this](void* addr, uint32_t size) {
        cameraTest->DumpImageFile(cameraTest->streamIdPreview, "yuv", addr, size);
    });
    cameraTest->streamInfo->bufferQueue_->producer_->SetQueueSize(UT_DATA_SIZE);
    cameraTest->consumerMap_[cameraTest->streamInfo->intent_] = consumer;
    cameraTest->streamInfos.push_back(*cameraTest->streamInfo);

    cameraTest->streamInfoSnapshot = std::make_shared<StreamInfo>();
    cameraTest->streamInfoSnapshot->streamId_ = 1202;
    cameraTest->streamInfoSnapshot->width_ = 720;
    cameraTest->streamInfoSnapshot->height_ = 480;
    cameraTest->streamInfoSnapshot->format_ = PIXEL_FMT_YCRCB_420_SP;
    cameraTest->streamInfoSnapshot->dataspace_ = UT_DATA_SIZE;
    cameraTest->streamInfoSnapshot->intent_ = STILL_CAPTURE;
    cameraTest->streamInfoSnapshot->tunneledMode_ = UT_TUNNEL_MODE;
    std::shared_ptr<OHOS::Camera::Test::StreamConsumer> snapshotConsumer =
        std::make_shared<OHOS::Camera::Test::StreamConsumer>();
    cameraTest->streamInfoSnapshot->bufferQueue_ = snapshotConsumer->CreateProducerSeq([this](void* addr,
        uint32_t size) {
        cameraTest->DumpImageFile(cameraTest->streamIdPreview, "yuv", addr, size);
    });
    cameraTest->streamInfoSnapshot->bufferQueue_->producer_->SetQueueSize(UT_DATA_SIZE);
    cameraTest->consumerMap_[cameraTest->streamInfoSnapshot->intent_] = snapshotConsumer;
    cameraTest->streamInfos.push_back(*cameraTest->streamInfoSnapshot);

    cameraTest->rc = (CamRetCode)cameraTest->streamOperator->CreateStreams(cameraTest->streamInfos);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    cameraTest->rc = (CamRetCode)cameraTest->streamOperator->CommitStreams(OperationMode::NORMAL,
        cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    int captureId = 2001;
    cameraTest->captureInfo = std::make_shared<CaptureInfo>();
    cameraTest->captureInfo->streamIds_ = {1202};
    cameraTest->captureInfo->captureSetting_ = cameraTest->abilityVec;
    cameraTest->captureInfo->enableShutterCallback_ = true;
    bool isStreaming = true;
    cameraTest->rc = (CamRetCode)cameraTest->streamOperator->Capture(captureId, *cameraTest->captureInfo, isStreaming);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    sleep(UT_SECOND_TIMES);

    OHOS::sptr<IStreamOperatorCallback> streamOperatorCallback = new OHOS::Camera::Test::TestStreamOperatorCallback();
    OHOS::sptr<IOfflineStreamOperator> offlineStreamOperator = nullptr;
    for (auto _ : st) {
        cameraTest->streamOperator->ChangeToOfflineStream({cameraTest->streamInfoSnapshot->streamId_},
            streamOperatorCallback, offlineStreamOperator);
    }

    sleep(UT_SECOND_TIMES);
    cameraTest->rc = (CamRetCode)offlineStreamOperator->CancelCapture(2020);
    EXPECT_EQ(true, cameraTest->rc == HDI::Camera::V1_0::NO_ERROR
        || cameraTest->rc == HDI::Camera::V1_0::METHOD_NOT_SUPPORTED);

    std::vector<int> streamIds = {1202};
    cameraTest->rc = (CamRetCode)offlineStreamOperator->ReleaseStreams(streamIds);
    EXPECT_EQ(true, cameraTest->rc == HDI::Camera::V1_0::NO_ERROR
        || cameraTest->rc == HDI::Camera::V1_0::METHOD_NOT_SUPPORTED);
    cameraTest->rc = (CamRetCode)offlineStreamOperator->Release();
    EXPECT_EQ(true, cameraTest->rc == HDI::Camera::V1_0::NO_ERROR
        || cameraTest->rc == HDI::Camera::V1_0::METHOD_NOT_SUPPORTED);
    cameraTest->rc = (CamRetCode)cameraTest->streamOperator->ReleaseStreams({1201});
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    sleep(UT_SECOND_TIMES);
}
BENCHMARK_REGISTER_F(CameraBenchmarkTest, SUB_ChangeToOfflineStream_benchmark_021)->Iterations(ITERATION_FREQUENCY)->
    Repetitions(REPETITION_FREQUENCY)->ReportAggregatesOnly();

BENCHMARK_MAIN();

