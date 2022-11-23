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
    if (display_ == nullptr) {
        display_ = std::make_shared<TestDisplay>();
    }
    display_->Init();
}
void MetaDataTest::TearDown(void)
{
    display_->Close();
}

void MetaDataTest::SetStreamInfo(StreamInfo &streamInfo, const std::shared_ptr<StreamCustomer> &streamCustomer,
    const int streamId, const StreamIntent intent)
{
    sptr<OHOS::IBufferProducer> producer;
    constexpr uint32_t DATA_SPACE = 8;
    constexpr uint32_t TUNNEL_MODE = 5;
    constexpr uint32_t BUFFER_QUEUE_SIZE = 8;
    if (intent == STILL_CAPTURE) {
        streamInfo.encodeType_ = ENCODE_TYPE_JPEG;
    } else if (intent == VIDEO) {
        streamInfo.encodeType_ = ENCODE_TYPE_H264;
    }
    streamInfo.width_ = PREVIEW_WIDTH;
    streamInfo.height_ = PREVIEW_HEIGHT;
    streamInfo.format_ = PIXEL_FMT_RGBA_8888;
    streamInfo.streamId_ = streamId;
    streamInfo.dataspace_ = DATA_SPACE;
    streamInfo.intent_ = intent;
    streamInfo.tunneledMode_ = TUNNEL_MODE;
    producer = streamCustomer->CreateProducer();
    streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    streamInfo.bufferQueue_->producer_->SetQueueSize(BUFFER_QUEUE_SIZE);
}

void MetaDataTest::CreateStream(int streamId, StreamIntent intent)
{
    StreamInfo streamInfo = {};

    if (intent == PREVIEW) {
        if (streamId == display_->STREAM_ID_PREVIEW) {
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
    result_ = static_cast<CamRetCode>(display_->streamOperator->CreateStreams(streamInfos_));
    EXPECT_EQ(result_, HDI::Camera::V1_0::NO_ERROR);

    if (result_ == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log]CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log]CreateStreams fail, result_ = " << result_ << std::endl;
    }
}

void MetaDataTest::CommitStream()
{
    result_ = static_cast<CamRetCode>(display_->streamOperator->CommitStreams(NORMAL, display_->ability_));
    EXPECT_EQ(result_, HDI::Camera::V1_0::NO_ERROR);
    if (result_ == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log]CommitStreams preview success." << std::endl;
    } else {
        std::cout << "==========[test log]CommitStreams preview  fail, result_ = " << result_ << std::endl;
    }
}

void MetaDataTest::StartCapture(
    int streamId, int captureId, bool shutterCallback, bool isStreaming, const CaptureInfo captureInfo)
{
    captureInfo_.streamIds_ = {streamId};
    captureInfo_.captureSetting_ = display_->ability_;
    captureInfo_.enableShutterCallback_ = shutterCallback;
    if (captureInfo.captureSetting_.size() != 0) {
        result_ = static_cast<CamRetCode>(display_->streamOperator->Capture(captureId, captureInfo, isStreaming));
    } else {
        result_ = static_cast<CamRetCode>(display_->streamOperator->Capture(captureId, captureInfo_, isStreaming));
    }
    EXPECT_EQ(result_, HDI::Camera::V1_0::NO_ERROR);
    if (result_ == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log]check Capture: Capture success, " << captureId << std::endl;
    } else {
        std::cout << "==========[test log]check Capture: Capture fail, result_ = " << result_ << captureId << std::endl;
    }
    if (captureId == display_->CAPTURE_ID_PREVIEW) {
        streamCustomerPreview_->ReceiveFrameOn([this](const unsigned char *addr, const uint32_t size) {
            std::cout << "==========[test log]preview size= " << size << std::endl;
        });
    } else if (captureId == display_->CAPTURE_ID_CAPTURE) {
        streamCustomerSnapshot_->ReceiveFrameOn([this](const unsigned char *addr, const uint32_t size) {
            std::cout << "==========[test log]snapshot size= " << size << std::endl;
        });
    } else if (captureId == display_->CAPTURE_ID_VIDEO) {
        streamCustomerVideo_->ReceiveFrameOn([this](const unsigned char *addr, const uint32_t size) {
            std::cout << "==========[test log]videosize= " << size << std::endl;
        });
    } else {
        std::cout << "==========[test log]StartCapture ignore command " << std::endl;
    }
}

void MetaDataTest::StopStream(std::vector<int> &captureIds, std::vector<int> &streamIds)
{
    sleep(SLEEP_SECOND_TWO);
    if (sizeof(captureIds) == 0) {
        return;
    }
    for (auto &captureId : captureIds) {
        if (captureId == display_->CAPTURE_ID_PREVIEW) {
            streamCustomerPreview_->ReceiveFrameOff();
        } else if (captureId == display_->CAPTURE_ID_CAPTURE) {
            streamCustomerSnapshot_->ReceiveFrameOff();
        } else if (captureId == display_->CAPTURE_ID_VIDEO) {
            streamCustomerVideo_->ReceiveFrameOff();
            sleep(SLEEP_SECOND_ONE);
        } else {
            std::cout << "==========[test log]StopStream ignore command. " << std::endl;
        }
    }
    for (auto &captureId : captureIds) {
        result_ = static_cast<CamRetCode>(display_->streamOperator->CancelCapture(captureId));
        sleep(SLEEP_SECOND_TWO);
        EXPECT_EQ(result_, HDI::Camera::V1_0::NO_ERROR);
        if (result_ == HDI::Camera::V1_0::NO_ERROR) {
            std::cout << "==========[test log]check Capture: CancelCapture success," << captureId << std::endl;
        } else {
            std::cout << "==========[test log]check Capture: CancelCapture fail, result_ = " << result_;
            std::cout << "captureId = " << captureId << std::endl;
        }
    }
    sleep(SLEEP_SECOND_ONE);
}

void MetaDataTest::StartCustomCapture()
{
    CaptureInfo captureInfo = {};
    StartCapture(display_->STREAM_ID_PREVIEW, display_->CAPTURE_ID_PREVIEW, false, true, captureInfo);
    constexpr double latitude = 27.987500;  // dummy data: Qomolangma latitde
    constexpr double longitude = 86.927500; // dummy data: Qomolangma longituude
    constexpr double altitude = 8848.86;    // dummy data: Qomolangma altitude
    std::shared_ptr<CameraSetting> captureSetting = std::make_shared<CameraSetting>(ENTRY_CAPACITY, DATA_CAPACITY);
    std::vector<double> gps;
    gps.push_back(latitude);
    gps.push_back(longitude);
    gps.push_back(altitude);
    captureSetting->addEntry(OHOS_JPEG_GPS_COORDINATES, gps.data(), gps.size());

    captureInfo.streamIds_ = {display_->STREAM_ID_CAPTURE};
    std::vector<uint8_t> snapshotSetting;
    MetadataUtils::ConvertMetadataToVec(captureSetting, snapshotSetting);
    captureInfo.captureSetting_ = snapshotSetting;
    captureInfo.enableShutterCallback_ = false;
    StartCapture(display_->STREAM_ID_CAPTURE, display_->CAPTURE_ID_CAPTURE, false, true, captureInfo);
}

void MetaDataTest::StartPreviewVideoStream()
{
    CreateStream(display_->STREAM_ID_PREVIEW, PREVIEW);
    CreateStream(display_->STREAM_ID_VIDEO, VIDEO);
    CommitStream();
}

void MetaDataTest::StartPreviewCaptureStream()
{
    CreateStream(display_->STREAM_ID_PREVIEW, PREVIEW);
    CreateStream(display_->STREAM_ID_CAPTURE, STILL_CAPTURE);
    CommitStream();
}

void MetaDataTest::StopPreviewVideoStream()
{
    sleep(SLEEP_SECOND_TWO);
    std::vector<int> captureIds = {display_->CAPTURE_ID_PREVIEW, display_->CAPTURE_ID_VIDEO};
    std::vector<int> streamIds = {display_->STREAM_ID_PREVIEW, display_->STREAM_ID_VIDEO};
    StopStream(captureIds, streamIds);
}

void MetaDataTest::StopPreviewCaptureStream()
{
    sleep(SLEEP_SECOND_TWO);
    std::vector<int> captureIds = {display_->CAPTURE_ID_PREVIEW, display_->CAPTURE_ID_CAPTURE};
    std::vector<int> streamIds = {display_->STREAM_ID_PREVIEW, display_->STREAM_ID_CAPTURE};
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
    display_->AchieveStreamOperator();
    display_->cameraDevice->SetResultMode(mode);

    if (results.size() == 0) {
        std::cout << "results size is null" << std::endl;
        return;
    }
    display_->cameraDevice->EnableResult(results);
}

void MetaDataTest::UpdateSettings(std::shared_ptr<CameraSetting> &metaData)
{
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(metaData, setting);
    display_->rc = static_cast<CamRetCode>(display_->cameraDevice->UpdateSettings(setting));
    if (display_->rc != HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] UpdateSettings error." << display_->rc << std::endl;
        return;
    } else {
        std::cout << "==========[test log] UpdateSettings ok." << display_->rc << std::endl;
    }
}

void MetaDataTest::StartPreviewVideoCapture()
{
    CaptureInfo captureInfo = {};
    StartCapture(display_->STREAM_ID_PREVIEW, display_->CAPTURE_ID_PREVIEW, false, true, captureInfo);
    StartCapture(display_->STREAM_ID_VIDEO, display_->CAPTURE_ID_VIDEO, false, true, captureInfo);
}

void MetaDataTest::PrintCameraMetadata(const std::vector<uint8_t> &settings)
{
    std::shared_ptr<CameraMetadata> result;
    MetadataUtils::ConvertVecToMetadata(settings, result);
    if (result == nullptr) {
        std::cout << "result is null" << std::endl;
        return;
    }
    common_metadata_header_t *data = result->get();
    if (data == nullptr) {
        std::cout << "data is null" << std::endl;
        return;
    }

    for (auto it = DATA_BASE.cbegin(); it != DATA_BASE.cend(); it++) {
        switch (*it) {
            case OHOS_CONTROL_AWB_MODE:
            case OHOS_CONTROL_FOCUS_MODE:
            case OHOS_CONTROL_FOCUS_STATE:
            case OHOS_CONTROL_EXPOSURE_MODE:
            case OHOS_CONTROL_EXPOSURE_STATE:
            case OHOS_CONTROL_FLASH_MODE:
            case OHOS_CONTROL_METER_MODE:
            case OHOS_CONTROL_VIDEO_STABILIZATION_MODE: {
                PrintU8Metadata(*it, data);
                break;
            }
            case OHOS_CAMERA_STREAM_ID:
            case OHOS_CONTROL_AE_EXPOSURE_COMPENSATION: {
                PrintI32Metadata(*it, data);
                break;
            }
            case OHOS_SENSOR_EXPOSURE_TIME: {
                PrintI64Metadata(*it, data);
                break;
            }
            case OHOS_SENSOR_COLOR_CORRECTION_GAINS: {
                PrintFloatMetadata(*it, data);
                break;
            }
            case OHOS_CONTROL_FPS_RANGES:
            case OHOS_CONTROL_AF_REGIONS:
            case OHOS_CONTROL_METER_POINT: {
                PrintI32ArrayMetadata(*it, data);
                break;
            }
            default: {
                std::cout << "invalid param and key = " << *it << std::endl;
                break;
            }
        }
    }
}

void MetaDataTest::PrintU8Metadata(int32_t key, common_metadata_header_t *data)
{
    uint8_t value;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, key, &entry);
    if (ret != 0) {
        std::cout << "get  key error and key = " << key << std::endl;
        return;
    }
    value = *(entry.data.u8);
    std::cout << "MetaDataTest valueu8 = " << static_cast<int>(value) << " and key = " << key << std::endl;
}

void MetaDataTest::PrintI32Metadata(int32_t key, common_metadata_header_t *data)
{
    int32_t value;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, key, &entry);
    if (ret != 0) {
        std::cout << "get  key error and key = " << key << std::endl;
        return;
    }
    value = *(entry.data.i32);

    std::cout << "MetaDataTest valueI32 = " << value << " and key = " << key << std::endl;
}

void MetaDataTest::PrintI64Metadata(int32_t key, common_metadata_header_t *data)
{
    int64_t value;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, key, &entry);
    if (ret != 0) {
        std::cout << "get  key error and key = " << key << std::endl;
        return;
    }
    value = *(entry.data.i64);
    std::cout << "MetaDataTest valueI64 = " << value << " and key = " << key << std::endl;
}

void MetaDataTest::PrintFloatMetadata(int32_t key, common_metadata_header_t *data)
{
    float value;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, key, &entry);
    if (ret != 0) {
        std::cout << "get  key error and key = " << key << std::endl;
        return;
    }
    value = *(entry.data.f);
    std::cout << "MetaDataTest valueFloat = " << std::showpoint << value << " and key = " << key << std::endl;
}

void MetaDataTest::PrintI32ArrayMetadata(int32_t key, common_metadata_header_t *data)
{
    std::vector<int32_t> results;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, key, &entry);
    if (ret != 0) {
        std::cout << "get  key error and key = " << key << std::endl;
        return;
    }
    uint32_t count = entry.count;
    std::cout << "MetaDataTest count =" << count << std::endl;

    for (int i = 0; i < count; i++) {
        results.push_back(*(entry.data.i32 + i));
    }

    for (auto iterator = results.begin(); iterator != results.end(); iterator++) {
        std::cout << "MetaDataTest valueArray = " << *iterator << " and key = " << key << std::endl;
    }
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
    const int32_t streamId = display_->STREAM_ID_VIDEO;
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
    const int32_t streamId = display_->STREAM_ID_VIDEO;
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
    const int32_t deviceStreamId = display_->STREAM_ID_CAPTURE;
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
    const int32_t streamId = display_->STREAM_ID_CAPTURE;
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
