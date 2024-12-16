/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file expected in compliance with the License.
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
#include "meta_data_test.h"

using namespace testing::ext;

constexpr uint32_t SLEEP_SECOND_ONE = 1;
constexpr uint32_t SLEEP_SECOND_TWO = 2;
constexpr uint32_t DATA_COUNT = 1;
constexpr uint32_t ENTRY_CAPACITY = 30;
constexpr uint32_t DATA_CAPACITY = 2000;
constexpr int32_t FPS_RANGE = 20;
constexpr int32_t FPS_RANGE_CHANGE = 30;

const std::vector<int32_t> DATA_BASE = {
    OHOS_CAMERA_STREAM_ID,
    OHOS_SENSOR_COLOR_CORRECTION_GAINS,
    OHOS_SENSOR_EXPOSURE_TIME,
    OHOS_CONTROL_EXPOSURE_MODE,
    OHOS_CONTROL_AE_EXPOSURE_COMPENSATION,
    OHOS_CONTROL_FOCUS_MODE,
    OHOS_CONTROL_METER_MODE,
    OHOS_CONTROL_FLASH_MODE,
    OHOS_CONTROL_FPS_RANGES,
    OHOS_CONTROL_AWB_MODE,
    OHOS_CONTROL_AF_REGIONS,
    OHOS_CONTROL_METER_POINT,
    OHOS_CONTROL_VIDEO_STABILIZATION_MODE,
    OHOS_CONTROL_FOCUS_STATE,
    OHOS_CONTROL_EXPOSURE_STATE,
};

void MetaDataTest::SetUpTestCase(void) {}
void MetaDataTest::TearDownTestCase(void) {}
void MetaDataTest::SetUp(void)
{
    if (cameraBase_ == nullptr) {
        cameraBase_ = std::make_shared<TestCameraBase>();
    }
    cameraBase_->Init();
}
void MetaDataTest::TearDown(void)
{
    cameraBase_->Close();
}

void MetaDataTest::SetStreamInfo(StreamInfo &streamInfo, const std::shared_ptr<StreamCustomer> &streamCustomer,
    const int streamId, const StreamIntent intent)
{
    sptr<OHOS::IBufferProducer> producer;
    constexpr uint32_t dataSpace = 8;
    constexpr uint32_t tunnelMode = 5;
    constexpr uint32_t bufferQueueSize = 8;
    if (intent == STILL_CAPTURE) {
        streamInfo.encodeType_ = ENCODE_TYPE_JPEG;
    } else if (intent == VIDEO) {
        streamInfo.encodeType_ = ENCODE_TYPE_H264;
    }
    streamInfo.width_ = PREVIEW_WIDTH;
    streamInfo.height_ = PREVIEW_HEIGHT;
    streamInfo.format_ = PIXEL_FMT_RGBA_8888;
    streamInfo.streamId_ = streamId;
    streamInfo.dataspace_ = dataSpace;
    streamInfo.intent_ = intent;
    streamInfo.tunneledMode_ = tunnelMode;
    producer = streamCustomer->CreateProducer();
    streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    CHECK_IF_PTR_NULL_RETURN_VOID(streamInfo.bufferQueue_);
    streamInfo.bufferQueue_->producer_->SetQueueSize(bufferQueueSize);
}

void MetaDataTest::CreateStream(int streamId, StreamIntent intent)
{
    StreamInfo streamInfo = {};

    if (intent == PREVIEW) {
        if (streamId == cameraBase_->STREAM_ID_PREVIEW) {
            if (streamCustomerPreview_ == nullptr) {
                streamCustomerPreview_ = std::make_shared<StreamCustomer>();
                SetStreamInfo(streamInfo, streamCustomerPreview_, streamId, intent);
            }
        }
    } else if (intent == STILL_CAPTURE) {
        if (streamCustomerSnapshot_ == nullptr) {
            streamCustomerSnapshot_ = std::make_shared<StreamCustomer>();
            SetStreamInfo(streamInfo, streamCustomerSnapshot_, streamId, intent);
        }
    } else if (intent == VIDEO) {
        if (streamCustomerVideo_ == nullptr) {
            streamCustomerVideo_ = std::make_shared<StreamCustomer>();
            SetStreamInfo(streamInfo, streamCustomerVideo_, streamId, intent);
        }
    }

    std::vector<StreamInfo>().swap(streamInfos_);
    streamInfos_.push_back(streamInfo);
    result_ = static_cast<CamRetCode>(cameraBase_->streamOperator->CreateStreams(streamInfos_));
    EXPECT_EQ(result_, HDI::Camera::V1_0::NO_ERROR);

    if (result_ == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("CreateStreams success.");
    } else {
        CAMERA_LOGE("CreateStreams fail, result_ = %{public}d", result_);
    }
}

void MetaDataTest::CommitStream()
{
    result_ = static_cast<CamRetCode>(cameraBase_->streamOperator->CommitStreams(NORMAL, cameraBase_->ability_));
    EXPECT_EQ(result_, HDI::Camera::V1_0::NO_ERROR);
    if (result_ == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("CommitStreams preview success.");
    } else {
        CAMERA_LOGE("CommitStreams preview fail, result_ = %{public}d", result_);
    }
}

void MetaDataTest::StartCapture(
    int streamId, int captureId, bool shutterCallback, bool isStreaming, const CaptureInfo captureInfo)
{
    captureInfo_.streamIds_ = {streamId};
    captureInfo_.captureSetting_ = cameraBase_->ability_;
    captureInfo_.enableShutterCallback_ = shutterCallback;
    if (captureInfo.captureSetting_.size() != 0) {
        result_ = static_cast<CamRetCode>(cameraBase_->streamOperator->Capture(captureId, captureInfo, isStreaming));
    } else {
        result_ = static_cast<CamRetCode>(cameraBase_->streamOperator->Capture(captureId, captureInfo_, isStreaming));
    }
    EXPECT_EQ(result_, HDI::Camera::V1_0::NO_ERROR);
    if (result_ == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("Capture success, captureId = %{public}d", captureId);
    } else {
        CAMERA_LOGE("check Capture: Capture fail, captureId = %{public}d, result_ = %{public}d", captureId, result_);
    }
    if (captureId == cameraBase_->CAPTURE_ID_PREVIEW) {
        streamCustomerPreview_->ReceiveFrameOn([this](const unsigned char *addr, const uint32_t size) {
            CAMERA_LOGI("preview size = %{public}u", size);
        });
    } else if (captureId == cameraBase_->CAPTURE_ID_CAPTURE) {
        streamCustomerSnapshot_->ReceiveFrameOn([this](const unsigned char *addr, const uint32_t size) {
            CAMERA_LOGI("snapshot size = %{public}u", size);
        });
    } else if (captureId == cameraBase_->CAPTURE_ID_VIDEO) {
        streamCustomerVideo_->ReceiveFrameOn([this](const unsigned char *addr, const uint32_t size) {
            CAMERA_LOGI("video size = %{public}u", size);
        });
    } else {
        CAMERA_LOGE("StartCapture ignore command ");
    }
}

void MetaDataTest::StopStream(std::vector<int> &captureIds, std::vector<int> &streamIds)
{
    sleep(SLEEP_SECOND_TWO);
    if (captureIds.size() == 0) {
        return;
    }
    for (const auto &captureId : captureIds) {
        if (captureId == cameraBase_->CAPTURE_ID_PREVIEW) {
            streamCustomerPreview_->ReceiveFrameOff();
        } else if (captureId == cameraBase_->CAPTURE_ID_CAPTURE) {
            streamCustomerSnapshot_->ReceiveFrameOff();
        } else if (captureId == cameraBase_->CAPTURE_ID_VIDEO) {
            streamCustomerVideo_->ReceiveFrameOff();
            sleep(SLEEP_SECOND_ONE);
        } else {
            CAMERA_LOGE("StopStream ignore command ");
        }
    }
    for (auto &captureId : captureIds) {
        result_ = static_cast<CamRetCode>(cameraBase_->streamOperator->CancelCapture(captureId));
        sleep(SLEEP_SECOND_TWO);
        EXPECT_EQ(result_, HDI::Camera::V1_0::NO_ERROR);
        if (result_ == HDI::Camera::V1_0::NO_ERROR) {
            CAMERA_LOGI("check Capture: CancelCapture success, captureId = %{public}d", captureId);
        } else {
            CAMERA_LOGE("check Capture: CancelCapture fail, captureId = %{public}d, result_ = %{public}d",
                captureId, result_);
        }
    }
    sleep(SLEEP_SECOND_ONE);
}

void MetaDataTest::StartCustomCapture()
{
    CaptureInfo captureInfo = {};
    StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true, captureInfo);
    constexpr double latitude = 27.987500;  // dummy data: Qomolangma latitde
    constexpr double longitude = 86.927500; // dummy data: Qomolangma longituude
    constexpr double altitude = 8848.86;    // dummy data: Qomolangma altitude
    std::shared_ptr<CameraSetting> captureSetting = std::make_shared<CameraSetting>(ENTRY_CAPACITY, DATA_CAPACITY);
    std::vector<double> gps;
    gps.push_back(latitude);
    gps.push_back(longitude);
    gps.push_back(altitude);
    captureSetting->addEntry(OHOS_JPEG_GPS_COORDINATES, gps.data(), gps.size());

    captureInfo.streamIds_ = {cameraBase_->STREAM_ID_CAPTURE};
    std::vector<uint8_t> snapshotSetting;
    MetadataUtils::ConvertMetadataToVec(captureSetting, snapshotSetting);
    captureInfo.captureSetting_ = snapshotSetting;
    captureInfo.enableShutterCallback_ = false;
    StartCapture(cameraBase_->STREAM_ID_CAPTURE, cameraBase_->CAPTURE_ID_CAPTURE, false, true, captureInfo);
}

void MetaDataTest::StartPreviewVideoStream()
{
    CreateStream(cameraBase_->STREAM_ID_PREVIEW, PREVIEW);
    CreateStream(cameraBase_->STREAM_ID_VIDEO, VIDEO);
    CommitStream();
}

void MetaDataTest::StartPreviewCaptureStream()
{
    CreateStream(cameraBase_->STREAM_ID_PREVIEW, PREVIEW);
    CreateStream(cameraBase_->STREAM_ID_CAPTURE, STILL_CAPTURE);
    CommitStream();
}

void MetaDataTest::StopPreviewVideoStream()
{
    sleep(SLEEP_SECOND_TWO);
    std::vector<int> captureIds = {cameraBase_->CAPTURE_ID_PREVIEW, cameraBase_->CAPTURE_ID_VIDEO};
    std::vector<int> streamIds = {cameraBase_->STREAM_ID_PREVIEW, cameraBase_->STREAM_ID_VIDEO};
    StopStream(captureIds, streamIds);
}

void MetaDataTest::StopPreviewCaptureStream()
{
    sleep(SLEEP_SECOND_TWO);
    std::vector<int> captureIds = {cameraBase_->CAPTURE_ID_PREVIEW, cameraBase_->CAPTURE_ID_CAPTURE};
    std::vector<int> streamIds = {cameraBase_->STREAM_ID_PREVIEW, cameraBase_->STREAM_ID_CAPTURE};
    StopStream(captureIds, streamIds);
}

void MetaDataTest::SetFps(std::shared_ptr<CameraSetting> &metaData, int32_t fps, bool isUpdate)
{
    std::vector<int32_t> fpsRange;
    fpsRange.push_back(fps);
    fpsRange.push_back(fps);

    if (isUpdate) {
        metaData->updateEntry(OHOS_CONTROL_FPS_RANGES, fpsRange.data(), fpsRange.size());
    } else {
        metaData->addEntry(OHOS_CONTROL_FPS_RANGES, fpsRange.data(), fpsRange.size());
    }
}

void MetaDataTest::Prepare(ResultCallbackMode mode, std::vector<MetaType> &results)
{
    cameraBase_->AchieveStreamOperator();
    cameraBase_->cameraDevice->SetResultMode(mode);

    if (results.size() == 0) {
        CAMERA_LOGE("results size is null");
        return;
    }
    cameraBase_->cameraDevice->EnableResult(results);
}

void MetaDataTest::UpdateSettings(std::shared_ptr<CameraSetting> &metaData)
{
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(metaData, setting);
    cameraBase_->rc = static_cast<CamRetCode>(cameraBase_->cameraDevice->UpdateSettings(setting));
    if (cameraBase_->rc != HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGE("UpdateSettings error, rc = %{public}d", cameraBase_->rc);
        return;
    } else {
        CAMERA_LOGI("UpdateSettings ok, rc = %{public}d", cameraBase_->rc);
    }
}

void MetaDataTest::StartPreviewVideoCapture()
{
    CaptureInfo captureInfo = {};
    StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true, captureInfo);
    StartCapture(cameraBase_->STREAM_ID_VIDEO, cameraBase_->CAPTURE_ID_VIDEO, false, true, captureInfo);
}

/**
 * @tc.name: double preview
 * @tc.desc: Commit 2 streams together, preview and video streams, isStreaming is true.
 * CallbackMode is PER_FRAME, set device stream fps range value.
 * @tc.level: Level1
 * @tc.size: MediumTest
 * @tc.type: Function
 */
static HWTEST_F(MetaDataTest, meta_data_001, TestSize.Level1)
{
    std::vector<MetaType> results;
    results.push_back(OHOS_CAMERA_STREAM_ID);
    results.push_back(OHOS_CONTROL_FPS_RANGES);
    Prepare(ResultCallbackMode::PER_FRAME, results);

    std::shared_ptr<CameraSetting> metaData = std::make_shared<CameraSetting>(ENTRY_CAPACITY, DATA_CAPACITY);
    const int32_t deviceStreamId = 0;
    metaData->addEntry(OHOS_CAMERA_STREAM_ID, &deviceStreamId, DATA_COUNT);

    SetFps(metaData, FPS_RANGE, false);

    StartPreviewVideoStream();

    UpdateSettings(metaData);

    StartPreviewVideoCapture();

    StopPreviewVideoStream();
}

/**
 * @tc.name: double preview
 * @tc.desc: Commit 2 streams together, preview and video streams, isStreaming is true.
 * CallbackMode is ON_CHANGED, but the device stream fps range value has not changed.
 * @tc.level: Level1
 * @tc.size: MediumTest
 * @tc.type: Function
 */
static HWTEST_F(MetaDataTest, meta_data_002, TestSize.Level1)
{
    std::vector<MetaType> results;
    results.push_back(OHOS_CAMERA_STREAM_ID);
    results.push_back(OHOS_CONTROL_FPS_RANGES);
    Prepare(ResultCallbackMode::ON_CHANGED, results);

    std::shared_ptr<CameraSetting> metaData = std::make_shared<CameraSetting>(ENTRY_CAPACITY, DATA_CAPACITY);
    const int32_t deviceStreamId = 0;
    metaData->addEntry(OHOS_CAMERA_STREAM_ID, &deviceStreamId, DATA_COUNT);

    SetFps(metaData, FPS_RANGE, false);

    StartPreviewVideoStream();

    UpdateSettings(metaData);

    StartPreviewVideoCapture();
    sleep(SLEEP_SECOND_TWO);

    SetFps(metaData, FPS_RANGE, true);

    UpdateSettings(metaData);

    StopPreviewVideoStream();
}

/**
 * @tc.name: double preview
 * @tc.desc: Commit 2 streams together, preview and video streams, isStreaming is true.
 * CallbackMode is ON_CHANGED, set device stream fps range different value.
 * @tc.level: Level1
 * @tc.size: MediumTest
 * @tc.type: Function
 */
static HWTEST_F(MetaDataTest, meta_data_003, TestSize.Level1)
{
    std::vector<MetaType> results;
    results.push_back(OHOS_CAMERA_STREAM_ID);
    results.push_back(OHOS_CONTROL_FPS_RANGES);
    Prepare(ResultCallbackMode::ON_CHANGED, results);

    std::shared_ptr<CameraSetting> metaData = std::make_shared<CameraSetting>(ENTRY_CAPACITY, DATA_CAPACITY);
    const int32_t deviceStreamId = 0;
    metaData->addEntry(OHOS_CAMERA_STREAM_ID, &deviceStreamId, DATA_COUNT);

    SetFps(metaData, FPS_RANGE, false);

    StartPreviewVideoStream();

    UpdateSettings(metaData);

    StartPreviewVideoCapture();
    sleep(SLEEP_SECOND_TWO);

    SetFps(metaData, FPS_RANGE_CHANGE, true);

    UpdateSettings(metaData);

    StopPreviewVideoStream();
}

/**
 * @tc.name: double preview
 * @tc.desc: Commit 2 streams together, preview and video streams, isStreaming is true.
 * CallbackMode is PER_FRAME,set video stream stability mode value.
 * @tc.level: Level1
 * @tc.size: MediumTest
 * @tc.type: Function
 */
static HWTEST_F(MetaDataTest, meta_data_004, TestSize.Level1)
{
    std::vector<MetaType> results;
    results.push_back(OHOS_CAMERA_STREAM_ID);
    Prepare(ResultCallbackMode::PER_FRAME, results);

    std::shared_ptr<CameraSetting> metaData = std::make_shared<CameraSetting>(ENTRY_CAPACITY, DATA_CAPACITY);
    const int32_t streamId = cameraBase_->STREAM_ID_VIDEO;
    metaData->addEntry(OHOS_CAMERA_STREAM_ID, &streamId, DATA_COUNT);

    uint8_t videoStabilizationMode = OHOS_CAMERA_VIDEO_STABILIZATION_LOW;
    metaData->addEntry(OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &videoStabilizationMode, sizeof(videoStabilizationMode));

    StartPreviewVideoStream();

    UpdateSettings(metaData);

    StartPreviewVideoCapture();

    StopPreviewVideoStream();
}

/**
 * @tc.name: double preview
 * @tc.desc: Commit 2 streams together, preview and video streams, isStreaming is true.
 * CallbackMode is ON_CHANGED, set video stream stability mode different value.
 * @tc.level: Level1
 * @tc.size: MediumTest
 * @tc.type: Function
 */
static HWTEST_F(MetaDataTest, meta_data_005, TestSize.Level1)
{
    std::vector<MetaType> results;
    results.push_back(OHOS_CAMERA_STREAM_ID);
    Prepare(ResultCallbackMode::ON_CHANGED, results);

    std::shared_ptr<CameraSetting> metaData = std::make_shared<CameraSetting>(ENTRY_CAPACITY, DATA_CAPACITY);
    const int32_t streamId = cameraBase_->STREAM_ID_VIDEO;
    metaData->addEntry(OHOS_CAMERA_STREAM_ID, &streamId, DATA_COUNT);

    uint8_t videoStabilizationMode = OHOS_CAMERA_VIDEO_STABILIZATION_LOW;
    metaData->addEntry(OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &videoStabilizationMode, sizeof(videoStabilizationMode));

    StartPreviewVideoStream();

    UpdateSettings(metaData);

    StartPreviewVideoCapture();
    sleep(SLEEP_SECOND_TWO);

    uint8_t videoStabilizationModeChange = OHOS_CAMERA_VIDEO_STABILIZATION_MIDDLE;
    metaData->updateEntry(
        OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &videoStabilizationModeChange, sizeof(videoStabilizationModeChange));
    UpdateSettings(metaData);

    StopPreviewVideoStream();
}

/**
 * @tc.name: double preview
 * @tc.desc: Commit 2 streams together, preview and video streams, isStreaming is true.
 * CallbackMode is PER_FRAME, set device stream fps range value and exposure time value.
 * @tc.level: Level1
 * @tc.size: MediumTest
 * @tc.type: Function
 */
static HWTEST_F(MetaDataTest, meta_data_006, TestSize.Level1)
{
    std::vector<MetaType> results;
    results.push_back(OHOS_CAMERA_STREAM_ID);
    results.push_back(OHOS_CONTROL_FPS_RANGES);
    results.push_back(OHOS_SENSOR_EXPOSURE_TIME);
    Prepare(ResultCallbackMode::PER_FRAME, results);

    std::shared_ptr<CameraSetting> metaData = std::make_shared<CameraSetting>(ENTRY_CAPACITY, DATA_CAPACITY);
    const int32_t deviceStreamId = 0;
    metaData->addEntry(OHOS_CAMERA_STREAM_ID, &deviceStreamId, DATA_COUNT);

    SetFps(metaData, FPS_RANGE, false);

    StartPreviewVideoStream();

    UpdateSettings(metaData);

    StartPreviewVideoCapture();
    sleep(SLEEP_SECOND_TWO);

    int64_t exposureTime = 10;
    metaData->addEntry(OHOS_SENSOR_EXPOSURE_TIME, &exposureTime, DATA_COUNT);

    UpdateSettings(metaData);

    StopPreviewVideoStream();
}

/**
 * @tc.name: double preview
 * @tc.desc: Commit 2 streams together, preview and video streams, isStreaming is true.
 * CallbackMode is PER_FRAME, set device stream fps range different value and exposure time value.
 * @tc.level: Level1
 * @tc.size: MediumTest
 * @tc.type: Function
 */
static HWTEST_F(MetaDataTest, meta_data_007, TestSize.Level1)
{
    std::vector<MetaType> results;
    results.push_back(OHOS_CAMERA_STREAM_ID);
    results.push_back(OHOS_CONTROL_FPS_RANGES);
    results.push_back(OHOS_SENSOR_EXPOSURE_TIME);
    Prepare(ResultCallbackMode::PER_FRAME, results);

    std::shared_ptr<CameraSetting> metaData = std::make_shared<CameraSetting>(ENTRY_CAPACITY, DATA_CAPACITY);
    const int32_t deviceStreamId = 0;
    metaData->addEntry(OHOS_CAMERA_STREAM_ID, &deviceStreamId, DATA_COUNT);

    SetFps(metaData, FPS_RANGE, false);

    StartPreviewVideoStream();

    UpdateSettings(metaData);

    StartPreviewVideoCapture();
    sleep(SLEEP_SECOND_TWO);

    SetFps(metaData, FPS_RANGE_CHANGE, true);

    UpdateSettings(metaData);
    sleep(SLEEP_SECOND_TWO);

    int64_t exposureTime = 10;
    metaData->addEntry(OHOS_SENSOR_EXPOSURE_TIME, &exposureTime, DATA_COUNT);

    UpdateSettings(metaData);

    StopPreviewVideoStream();
}

/**
 * @tc.name: double preview
 * @tc.desc: Commit 2 streams together, preview and still picture streams, isStreaming is true.
 * CallbackMode is ON_CHANGED, set still picture stream exposure mode different value.
 * @tc.level: Level1
 * @tc.size: MediumTest
 * @tc.type: Function
 */
static HWTEST_F(MetaDataTest, meta_data_008, TestSize.Level1)
{
    std::vector<MetaType> results;
    results.push_back(OHOS_CAMERA_STREAM_ID);
    Prepare(ResultCallbackMode::ON_CHANGED, results);

    std::shared_ptr<CameraSetting> metaData = std::make_shared<CameraSetting>(ENTRY_CAPACITY, DATA_CAPACITY);
    const int32_t deviceStreamId = cameraBase_->STREAM_ID_CAPTURE;
    metaData->addEntry(OHOS_CAMERA_STREAM_ID, &deviceStreamId, DATA_COUNT);

    uint8_t aeMode = OHOS_CAMERA_EXPOSURE_MODE_CONTINUOUS_AUTO;
    metaData->addEntry(OHOS_CONTROL_EXPOSURE_MODE, &aeMode, sizeof(aeMode));

    StartPreviewCaptureStream();

    UpdateSettings(metaData);

    StartCustomCapture();
    sleep(SLEEP_SECOND_TWO);

    uint8_t aeModeChangeValue = OHOS_CAMERA_EXPOSURE_MODE_LOCKED;
    metaData->updateEntry(OHOS_CONTROL_EXPOSURE_MODE, &aeModeChangeValue, sizeof(aeModeChangeValue));

    UpdateSettings(metaData);

    StopPreviewCaptureStream();
}

/**
 * @tc.name: double preview
 * @tc.desc: Commit 2 streams together, preview and still picture streams, isStreaming is true.
 * CallbackMode is ON_CHANGED, set still picture stream exposure mode/time different value and device stream fps range
 * different value.
 * @tc.level: Level1
 * @tc.size: MediumTest
 * @tc.type: Function
 */
static HWTEST_F(MetaDataTest, meta_data_009, TestSize.Level1)
{
    std::vector<MetaType> results;
    results.push_back(OHOS_CAMERA_STREAM_ID);
    results.push_back(OHOS_CONTROL_FPS_RANGES);
    Prepare(ResultCallbackMode::ON_CHANGED, results);

    std::shared_ptr<CameraSetting> metaDataDevice = std::make_shared<CameraSetting>(ENTRY_CAPACITY, DATA_CAPACITY);
    const int32_t deviceStreamId = 0;
    metaDataDevice->addEntry(OHOS_CAMERA_STREAM_ID, &deviceStreamId, DATA_COUNT);

    SetFps(metaDataDevice, FPS_RANGE, false);

    std::shared_ptr<CameraSetting> metaDataStream = std::make_shared<CameraSetting>(ENTRY_CAPACITY, DATA_CAPACITY);
    const int32_t streamId = cameraBase_->STREAM_ID_CAPTURE;
    metaDataStream->addEntry(OHOS_CAMERA_STREAM_ID, &streamId, DATA_COUNT);

    uint8_t aeMode = OHOS_CAMERA_EXPOSURE_MODE_CONTINUOUS_AUTO;
    metaDataStream->addEntry(OHOS_CONTROL_EXPOSURE_MODE, &aeMode, sizeof(aeMode));

    int64_t exposureTime = 10;
    metaDataStream->addEntry(OHOS_SENSOR_EXPOSURE_TIME, &exposureTime, DATA_COUNT);

    StartPreviewCaptureStream();

    UpdateSettings(metaDataDevice);
    sleep(SLEEP_SECOND_TWO);
    UpdateSettings(metaDataStream);
    StartCustomCapture();
    sleep(SLEEP_SECOND_TWO);

    uint8_t aeModeChangeValue = OHOS_CAMERA_EXPOSURE_MODE_LOCKED;
    metaDataStream->updateEntry(OHOS_CONTROL_EXPOSURE_MODE, &aeModeChangeValue, sizeof(aeModeChangeValue));

    UpdateSettings(metaDataStream);
    sleep(SLEEP_SECOND_TWO);
    SetFps(metaDataDevice, FPS_RANGE_CHANGE, true);
    UpdateSettings(metaDataDevice);

    StopPreviewCaptureStream();
}
