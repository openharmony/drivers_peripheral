/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "camera_preview_test.h"

using namespace testing::ext;

void CameraPreviewTest::SetUpTestCase(void)
{
}

void CameraPreviewTest::TearDownTestCase(void)
{
}

void CameraPreviewTest::SetUp(void)
{
    if (display_ == nullptr)
    display_ = std::make_shared<TestDisplay>();
    display_->Init();
}

void CameraPreviewTest::TearDown(void)
{
    display_->Close();
}

/**
  * @tc.name: Preview
  * @tc.desc: Preview stream, expected success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_001, TestSize.Level1)
{
    std::cout << "==========[test log] Preview stream, expected success." << std::endl;
    // Get the stream manager
    display_->AchieveStreamOperator();
    // start stream
    display_->intents = {PREVIEW};
    display_->StartStream(display_->intents);
    // Get preview
    display_->StartCapture(display_->STREAM_ID_PREVIEW, display_->CAPTURE_ID_PREVIEW, false, true);
    // release stream
    display_->captureIds = {display_->CAPTURE_ID_PREVIEW};
    display_->streamIds = {display_->STREAM_ID_PREVIEW};
    display_->StopStream(display_->captureIds, display_->streamIds);
}

/**
  * @tc.name: Preview
  * @tc.desc: Preview, format error, expected return errorCode.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_003, TestSize.Level2)
{
    std::cout << "==========[test log] Preview, format error, expected return errorCode." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    std::vector<StreamInfo> streamInfos;
    StreamInfo streamInfo = {};
    streamInfo.streamId_ = 1001;
    streamInfo.width_ = 640; // 640:picture width
    streamInfo.height_ = 480; // 480:picture height
    streamInfo.format_ = -1;
    streamInfo.dataspace_ = 10; // 10:picture dataspace
    streamInfo.intent_ = PREVIEW;
    streamInfo.tunneledMode_ = 5; // 5:tunnel mode
    streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    streamInfos.push_back(streamInfo);
    display_->rc = (CamRetCode)display_->streamOperator->CreateStreams(streamInfos);
    EXPECT_EQ(true, display_->rc != HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
}

/**
  * @tc.name: Preview
  * @tc.desc: GetStreamOperator success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_010, TestSize.Level1)
{
    std::cout << "==========[test log] GetStreamOperator success." << std::endl;
    // Get the configured cameraId
    display_->cameraHost->GetCameraIds(display_->cameraIds);
    std::cout << "cameraIds.front() = " << display_->cameraIds.front() << std::endl;
    // Open the camera device and get the device
    const OHOS::sptr<ICameraDeviceCallback> callback = new DemoCameraDeviceCallback();
    display_->rc = (CamRetCode)display_->cameraHost->OpenCamera(display_->cameraIds.front(),
        callback, display_->cameraDevice);
    std::cout << "OpenCamera's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    display_->AchieveStreamOperator();
}

/**
  * @tc.name: Preview
  * @tc.desc: GetStreamOperator, input nullptr.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_011, TestSize.Level2)
{
    std::cout << "==========[test log] GetStreamOperator, input nullptr." << std::endl;
    // Get the configured cameraId
    display_->cameraHost->GetCameraIds(display_->cameraIds);
    std::cout << "cameraIds.front() = " << display_->cameraIds.front() << std::endl;
    // Open the camera device and get the device
    const OHOS::sptr<ICameraDeviceCallback> callback = new DemoCameraDeviceCallback();
    display_->rc = (CamRetCode)display_->cameraHost->OpenCamera(display_->cameraIds.front(),
        callback, display_->cameraDevice);
    std::cout << "OpenCamera's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    // Create and get streamOperator information
    OHOS::sptr<IStreamOperatorCallback> streamOperatorCallback = nullptr;
    display_->rc = (CamRetCode)display_->cameraDevice->GetStreamOperator(streamOperatorCallback,
        display_->streamOperator);
    std::cout << "GetStreamOperator's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(CamRetCode::INVALID_ARGUMENT, display_->rc);
}

/**
  * @tc.name: Preview
  * @tc.desc: CreateStreams, success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_020, TestSize.Level1)
{
    std::cout << "==========[test log] CreateStreams, success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }

    std::vector<StreamInfo> streamInfos;
    StreamInfo streamInfo = {};
    streamInfo.streamId_ = 1001;
    streamInfo.width_ = 640; // 640:picture width
    streamInfo.height_ = 480; // 480:picture height
    streamInfo.format_ = PIXEL_FMT_RGBA_8888;
    streamInfo.dataspace_ = 8; // 8:picture dataspace
    streamInfo.intent_ = PREVIEW;
    streamInfo.tunneledMode_ = 5; // 5:tunnel mode
    streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    display_->rc = (CamRetCode)display_->streamOperator->CreateStreams(streamInfos);
    std::cout << "CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    std::cout << "==========[test log] CreateStreams, success." << std::endl;
    // Submit stream information
    display_->rc = (CamRetCode)display_->streamOperator->CommitStreams(NORMAL, display_->ability_);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] CommitStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CommitStreams fail, rc = " << display_->rc << std::endl;
    }
    // capture
    display_->StartCapture(1001, display_->CAPTURE_ID_PREVIEW, false, true);
    // release stream
    display_->captureIds = {display_->CAPTURE_ID_PREVIEW};
    display_->streamIds = {1001};
    display_->StopStream(display_->captureIds, display_->streamIds);
}

/**
  * @tc.name: Preview
  * @tc.desc: CreateStreams, StreamInfo->streamId = -1, return error.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_021, TestSize.Level2)
{
    std::cout << "==========[test log] CreateStreams, success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    std::vector<StreamInfo> streamInfos;
    StreamInfo streamInfo = {};
    streamInfo.streamId_ = -1;
    streamInfo.width_ = 640; // 640:picture width
    streamInfo.height_ = 480; // 480:picture height
    streamInfo.format_ = PIXEL_FMT_RGBA_8888;
    streamInfo.dataspace_ = 8; // 8:picture dataspace
    streamInfo.intent_ = PREVIEW;
    streamInfo.tunneledMode_ = 5; // 5:tunnel mode
    streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    streamInfos.push_back(streamInfo);
    display_->rc = (CamRetCode)display_->streamOperator->CreateStreams(streamInfos);
    std::cout << "CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(false, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
}

/**
  * @tc.name: Preview
  * @tc.desc: CreateStreams, StreamInfo->streamId = 2147483647, return success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_022, TestSize.Level2)
{
    std::cout << "==========[test log] CreateStreams, StreamInfo->streamId = 2147483647,";
    std::cout << "return success." << std::endl;
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    std::vector<StreamInfo> streamInfos;
    StreamInfo streamInfo = {};
    streamInfo.streamId_ = 2147483647;
    streamInfo.width_ = 640; // 640:picture width
    streamInfo.height_ = 480; // 480:picture height
    streamInfo.format_ = PIXEL_FMT_RGBA_8888;
    streamInfo.dataspace_ = 8; // 8:picture dataspace
    streamInfo.intent_ = PREVIEW;
    streamInfo.tunneledMode_ = 5; // 5:tunnel mode
    streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    display_->rc = (CamRetCode)display_->streamOperator->CreateStreams(streamInfos);
    std::cout << "streamOperator->CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
    // Submit stream information
    display_->rc = (CamRetCode)display_->streamOperator->CommitStreams(NORMAL, display_->ability_);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    std::cout << "==========[test log] CommitStreams success." << std::endl;
    // capture
    display_->StartCapture(2147483647, display_->CAPTURE_ID_PREVIEW, false, true);
    // release stream
    display_->captureIds = {display_->CAPTURE_ID_PREVIEW};
    display_->streamIds = {2147483647};
    display_->StopStream(display_->captureIds, display_->streamIds);
}

/**
  * @tc.name: Preview
  * @tc.desc: CreateStreams, StreamInfo->width = -1, return error.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_023, TestSize.Level2)
{
    std::cout << "==========[test log] CreateStreams, StreamInfo->width = -1, return error." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    std::vector<StreamInfo> streamInfos;
    StreamInfo streamInfo = {};
    streamInfo.streamId_ = 1001;
    streamInfo.width_ = -1;
    streamInfo.height_ = 480; // 480:picture height
    streamInfo.format_ = PIXEL_FMT_RGBA_8888;
    streamInfo.dataspace_ = 8; // 8:picture dataspace
    streamInfo.intent_ = PREVIEW;
    streamInfo.tunneledMode_ = 5; // 5:tunnel mode
    streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    display_->rc = (CamRetCode)display_->streamOperator->CreateStreams(streamInfos);
    std::cout << "streamOperator->CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(true, display_->rc == INVALID_ARGUMENT);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
}

/**
  * @tc.name: Preview
  * @tc.desc: CreateStreams, StreamInfo->height = -1, return error.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_025, TestSize.Level2)
{
    std::cout << "==========[test log] CreateStreams, StreamInfo->height = -1, return error." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    std::vector<StreamInfo> streamInfos;
    StreamInfo streamInfo = {};
    streamInfo.streamId_ = 1001;
    streamInfo.width_ = 640; // 640:picture width
    streamInfo.height_ = -1;
    streamInfo.format_ = PIXEL_FMT_RGBA_8888;
    streamInfo.dataspace_ = 8; // 8:picture dataspace
    streamInfo.intent_ = PREVIEW;
    streamInfo.tunneledMode_ = 5; // 5:tunnel mode
    streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    display_->rc = (CamRetCode)display_->streamOperator->CreateStreams(streamInfos);
    std::cout << "streamOperator->CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(CamRetCode::INVALID_ARGUMENT, display_->rc);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
}

/**
  * @tc.name: Preview
  * @tc.desc: CreateStreams, StreamInfo->format = -1, return error.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_027, TestSize.Level2)
{
    std::cout << "==========[test log] CreateStreams, StreamInfo->format = -1, return error." << std::endl;
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    std::vector<StreamInfo> streamInfos;
    StreamInfo streamInfo = {};
    streamInfo.streamId_ = 1001;
    streamInfo.width_ = 640; // 640:picture width
    streamInfo.height_ = 480; // 480:picture height
    streamInfo.format_ = -1;
    streamInfo.dataspace_ = 8; // 8:picture dataspace
    streamInfo.intent_ = PREVIEW;
    streamInfo.tunneledMode_ = 5; // 5:tunnel mode
    streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    display_->rc = (CamRetCode)display_->streamOperator->CreateStreams(streamInfos);
    std::cout << "streamOperator->CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(CamRetCode::INVALID_ARGUMENT, display_->rc);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
}

/**
  * @tc.name: Preview
  * @tc.desc: CreateStreams, StreamInfo->dataspace = 2147483647, success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_030, TestSize.Level2)
{
    std::cout << "==========[test log] CreateStreams, StreamInfo->dataspace = 2147483647, success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    std::vector<StreamInfo> streamInfos;
    StreamInfo streamInfo = {};
    streamInfo.streamId_ = 1001;
    streamInfo.width_ = 640; // 640:picture width
    streamInfo.height_ = 480; // 480:picture height
    streamInfo.format_ = PIXEL_FMT_RGBA_8888;
    streamInfo.dataspace_ = 2147483647;
    streamInfo.intent_ = PREVIEW;
    streamInfo.tunneledMode_ = 5; // 5:tunnel mode
    streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    display_->rc = (CamRetCode)display_->streamOperator->CreateStreams(streamInfos);
    std::cout << "streamOperator->CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
    // Submit stream information
    display_->rc = (CamRetCode)display_->streamOperator->CommitStreams(NORMAL, display_->ability_);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    std::cout << "==========[test log] CommitStreams success." << std::endl;
    // capture
    display_->StartCapture(1001, display_->CAPTURE_ID_PREVIEW, false, true);
    // release stream
    display_->captureIds = {display_->CAPTURE_ID_PREVIEW};
    display_->streamIds = {1001};
    display_->StopStream(display_->captureIds, display_->streamIds);
}

/**
  * @tc.name: Preview
  * @tc.desc: CreateStreams, StreamInfo->StreamIntent = PREVIEW, success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_031, TestSize.Level2)
{
    std::cout << "==========[test log] CreateStreams, StreamInfo->StreamIntent = ";
    std::cout << "PREVIEW, success." << std::endl;
    // Get the stream manager
    display_->AchieveStreamOperator();
    // start stream
    display_->intents = {PREVIEW};
    display_->StartStream(display_->intents);
    // capture
    display_->StartCapture(display_->STREAM_ID_PREVIEW, display_->CAPTURE_ID_PREVIEW, false, true);
    // release stream
    display_->captureIds = {display_->CAPTURE_ID_PREVIEW};
    display_->streamIds = {display_->STREAM_ID_PREVIEW};
    display_->StopStream(display_->captureIds, display_->streamIds);
}

/**
  * @tc.name: Preview
  * @tc.desc: CreateStreams, StreamInfo->StreamIntent = VIDEO, success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_032, TestSize.Level2)
{
    std::cout << "==========[test log] CreateStreams, StreamInfo->StreamIntent = VIDEO, success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // start stream
    display_->intents = {PREVIEW, VIDEO};
    display_->StartStream(display_->intents);
    // Get preview
    display_->StartCapture(display_->STREAM_ID_PREVIEW, display_->CAPTURE_ID_PREVIEW, false, true);
    display_->StartCapture(display_->STREAM_ID_VIDEO, display_->CAPTURE_ID_VIDEO, false, true);
    // release stream
    display_->captureIds = {display_->CAPTURE_ID_PREVIEW, display_->CAPTURE_ID_VIDEO};
    display_->streamIds = {display_->STREAM_ID_PREVIEW, display_->STREAM_ID_VIDEO};
    display_->StopStream(display_->captureIds, display_->streamIds);
}

/**
  * @tc.name: Preview
  * @tc.desc: CreateStreams, StreamInfo->StreamIntent = STILL_CAPTURE, success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_033, TestSize.Level2)
{
    std::cout << "==========[test log] CreateStreams, StreamInfo->StreamIntent = ";
    std::cout << "STILL_CAPTURE, success." << std::endl;
    // Get the stream manager
    display_->AchieveStreamOperator();
    // start stream
    display_->intents = {PREVIEW, STILL_CAPTURE};
    display_->StartStream(display_->intents);
    // Get preview
    display_->StartCapture(display_->STREAM_ID_PREVIEW, display_->CAPTURE_ID_PREVIEW, false, true);
    display_->StartCapture(display_->STREAM_ID_CAPTURE, display_->CAPTURE_ID_CAPTURE, false, true);
    // release stream
    display_->captureIds = {display_->CAPTURE_ID_PREVIEW, display_->CAPTURE_ID_CAPTURE};
    display_->streamIds = {display_->STREAM_ID_PREVIEW, display_->STREAM_ID_CAPTURE};
    display_->StopStream(display_->captureIds, display_->streamIds);
}

/**
  * @tc.name: Preview
  * @tc.desc: CreateStreams, StreamInfo->StreamIntent = OHOS::POST_VIEW;, success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_034, TestSize.Level2)
{
    std::cout << "==========[test log] CreateStreams, StreamInfo->StreamIntent = ";
    std::cout << "POST_VIEW;, success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create preview stream
    // std::shared_ptr<OHOS::IBufferProducer> producer = OHOS::IBufferProducer::CreateBufferQueue();
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    std::vector<StreamInfo> streamInfos;
    StreamInfo streamInfo = {};
    streamInfo.streamId_ = 1001;
    streamInfo.width_ = 640; // 640:picture width
    streamInfo.height_ = 480; // 480:picture height
    streamInfo.format_ = PIXEL_FMT_RGBA_8888;
    streamInfo.dataspace_ = 8; // 8:picture dataspace
    streamInfo.intent_ = POST_VIEW;
    streamInfo.tunneledMode_ = 5; // 5:tunnel mode
    streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    display_->rc = (CamRetCode)display_->streamOperator->CreateStreams(streamInfos);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
    // release stream
    std::vector<int> streamIds;
    streamIds.push_back(streamInfo.streamId_);
    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams(streamIds);
    std::cout << "ReleaseStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] ReleaseStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] ReleaseStreams fail, rc = " << display_->rc << std::endl;
    }
}

/**
  * @tc.name: Preview
  * @tc.desc: CreateStreams, StreamInfo->StreamIntent = OHOS::ANALYZE;, success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_035, TestSize.Level2)
{
    std::cout << "==========[test log] CreateStreams, StreamInfo->StreamIntent = ";
    std::cout << "ANALYZE;, success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    std::vector<StreamInfo> streamInfos;
    StreamInfo streamInfo = {};
    streamInfo.streamId_ = 1001;
    streamInfo.width_ = 640; // 640:picture width
    streamInfo.height_ = 480; // 480:picture height
    streamInfo.format_ = PIXEL_FMT_RGBA_8888;
    streamInfo.dataspace_ = 8; // 8:picture dataspace
    streamInfo.intent_ = ANALYZE;
    streamInfo.tunneledMode_ = 5; // 5:tunnel mode
    streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    display_->rc = (CamRetCode)display_->streamOperator->CreateStreams(streamInfos);
    std::cout << "streamOperator->CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    std::cout << "==========[test log] CreateStreams success." << std::endl;
    // release stream
    std::vector<int> streamIds;
    streamIds.push_back(streamInfo.streamId_);
    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams(streamIds);
    std::cout << "ReleaseStreams RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] ReleaseStreams success." << std::endl;
    }
    else {
        std::cout << "==========[test log] ReleaseStreams fail, rc = " << display_->rc << std::endl;
    }
}

/**
  * @tc.name: Preview
  * @tc.desc: CreateStreams, StreamInfo->StreamIntent = CUSTOM, not support.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_036, TestSize.Level2)
{
    std::cout << "==========[test log] CreateStreams, StreamInfo->StreamIntent = ";
    std::cout << "Camera::CUSTOM, not support." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    std::vector<StreamInfo> streamInfos;
    StreamInfo streamInfo = {};
    streamInfo.streamId_ = 1001;
    streamInfo.width_ = 640; // 640:picture width
    streamInfo.height_ = 480; // 480:picture height
    streamInfo.format_ = PIXEL_FMT_RGBA_8888;
    streamInfo.dataspace_ = 8; // 8:picture dataspace
    streamInfo.intent_ = CUSTOM;
    streamInfo.tunneledMode_ = 5; // 5:tunnel mode
    streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    display_->rc = (CamRetCode)display_->streamOperator->CreateStreams(streamInfos);
    std::cout << "streamOperator->CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(true, display_->rc != HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
}

/**
  * @tc.name: Preview
  * @tc.desc: CreateStreams, StreamInfo->tunneledMode = false, success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_037, TestSize.Level2)
{
    std::cout << "==========[test log] CreateStreams, StreamInfo->tunneledMode = false, success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    std::vector<StreamInfo> streamInfos;
    StreamInfo streamInfo = {};
    streamInfo.streamId_ = 1001;
    streamInfo.width_ = 640; // 640:picture width
    streamInfo.height_ = 480; // 480:picture height
    streamInfo.format_ = PIXEL_FMT_RGBA_8888;
    streamInfo.dataspace_ = 8; // 8:picture dataspace
    streamInfo.intent_ = PREVIEW;
    streamInfo.tunneledMode_ = false;
    streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    display_->rc = (CamRetCode)display_->streamOperator->CreateStreams(streamInfos);
    std::cout << "streamOperator->CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(true, display_->rc == INVALID_ARGUMENT);
    if (display_->rc == INVALID_ARGUMENT) {
        std::cout << "==========[test log] CreateStreams fail." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams success"<< std::endl;
    }
}

/**
  * @tc.name: Preview
  * @tc.desc: CreateStreams, StreamInfo->minFrameDuration = -1, return error.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_038, TestSize.Level2)
{
    std::cout << "==========[test log] CreateStreams, StreamInfo->minFrameDuration = -1, ";
    std::cout << "return error." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    std::vector<StreamInfo> streamInfos;
    StreamInfo streamInfo = {};
    streamInfo.streamId_ = 1001;
    streamInfo.width_ = 640; // 640:picture width
    streamInfo.height_ = 480; // 480:picture height
    streamInfo.format_ = PIXEL_FMT_RGBA_8888;
    streamInfo.dataspace_ = 8; // 8:picture dataspace
    streamInfo.intent_ = PREVIEW;
    streamInfo.tunneledMode_ = 0;
    streamInfo.minFrameDuration_ = -1;
    streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    display_->rc = (CamRetCode)display_->streamOperator->CreateStreams(streamInfos);
    std::cout << "streamOperator->CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(INVALID_ARGUMENT, display_->rc);
    std::cout << "==========[test log] CreateStreams, failed." << std::endl;
}

/**
  * @tc.name: Preview
  * @tc.desc: CreateStreams, StreamInfo->minFrameDuration = 2147483647, success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_039, TestSize.Level2)
{
    std::cout << "==========[test log] CreateStreams, StreamInfo->minFrameDuration = 2147483647, ";
    std::cout << "success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;    }

    std::vector<StreamInfo> streamInfos;
    StreamInfo streamInfo = {};
    streamInfo.streamId_ = 1001;
    streamInfo.width_ = 640; // 640:picture width
    streamInfo.height_ = 480; // 480:picture height
    streamInfo.format_ = PIXEL_FMT_RGBA_8888;
    streamInfo.dataspace_ = 8; // 8:picture dataspace
    streamInfo.intent_ = PREVIEW;
    streamInfo.tunneledMode_ = 0;
    streamInfo.minFrameDuration_ = 2147483647;
    streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    display_->rc = (CamRetCode)display_->streamOperator->CreateStreams(streamInfos);
    std::cout << "streamOperator->CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(false, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    std::cout << "==========[test log] CreateStreams, success." << std::endl;
}

/**
  * @tc.name: Preview
  * @tc.desc: Preview, CommitStreams Metadata = nullptr.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_040, TestSize.Level2)
{
    std::cout << "==========[test log] Preview, CommitStreams Metadata = nullptr." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;    }

    std::vector<StreamInfo> streamInfos;
    StreamInfo streamInfo = {};
    streamInfo.streamId_ = 1001;
    streamInfo.width_ = 640; // 640:picture width
    streamInfo.height_ = 480; // 480:picture height
    streamInfo.format_ = PIXEL_FMT_RGBA_8888;
    streamInfo.dataspace_ = 8; // 8:picture dataspace
    streamInfo.intent_ = PREVIEW;
    streamInfo.tunneledMode_ = 0;
    streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    display_->rc = (CamRetCode)display_->streamOperator->CreateStreams(streamInfos);
    // Distribution stream
    std::vector<uint8_t> modeSetting = {};
    display_->rc = (CamRetCode)display_->streamOperator->CommitStreams(NORMAL, modeSetting);
    std::cout << "streamOperator->CommitStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(true, display_->rc != HDI::Camera::V1_0::NO_ERROR);
    // release stream
    std::vector<int> streamIds;
    streamIds.push_back(-1);
    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams(streamIds);
}

/**
  * @tc.name: Preview
  * @tc.desc: Preview, CommitStreams without CreateStreams, expected fail.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_050, TestSize.Level2)
{
    std::cout << "==========[test log] Preview, CommitStreams without CreateStreams, expected fail." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Distribution stream
    display_->rc = (CamRetCode)display_->streamOperator->CommitStreams(NORMAL, display_->ability_);
    std::cout << "streamOperator->CommitStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(true, display_->rc == INVALID_ARGUMENT);
    // release stream
    std::vector<int> streamIds;
    streamIds.push_back(-1);
    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams(streamIds);
}

/**
  * @tc.name: Preview
  * @tc.desc: Preview  and release streams, success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_060, TestSize.Level1)
{
    std::cout << "==========[test log] Preview  and release streams, success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    std::vector<StreamInfo> streamInfos;
    StreamInfo streamInfo = {};
    streamInfo.streamId_ = 1001;
    streamInfo.width_ = 640; // 640:picture width
    streamInfo.height_ = 480; // 480:picture height
    streamInfo.format_ = PIXEL_FMT_RGBA_8888;
    streamInfo.dataspace_ = 8; // 8:picture dataspace
    streamInfo.intent_ = PREVIEW;
    streamInfo.tunneledMode_ = 5; // 5:tunnel mode
    streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    display_->rc = (CamRetCode)display_->streamOperator->CreateStreams(streamInfos);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    // Distribution stream
    display_->rc = (CamRetCode)display_->streamOperator->CommitStreams(NORMAL, display_->ability_);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    // Get preview
    int captureId = 2001;
    CaptureInfo captureInfo = {};
    captureInfo.streamIds_ = {1001};
    captureInfo.captureSetting_ = display_->ability_;
    captureInfo.enableShutterCallback_ = false;
    display_->rc = (CamRetCode)display_->streamOperator->Capture(captureId, captureInfo, true);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    sleep(5);
    display_->streamOperator->CancelCapture(captureId);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    // release stream
    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams(captureInfo.streamIds_);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
}

/**
  * @tc.name: Preview
  * @tc.desc: ReleaseStreams-> streamID = -1, expected INVALID_ARGUMENT.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_061, TestSize.Level2)
{
    std::cout << "==========[test log] ReleaseStreams-> streamID = -1, expected success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create preview stream
    // std::shared_ptr<OHOS::IBufferProducer> producer = OHOS::IBufferProducer::CreateBufferQueue();
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    std::vector<StreamInfo> streamInfos;
    StreamInfo streamInfo = {};
    streamInfo.streamId_ = 1001;
    streamInfo.width_ = 640; // 640:picture width
    streamInfo.height_ = 480; // 480:picture height
    streamInfo.format_ = PIXEL_FMT_RGBA_8888;
    streamInfo.dataspace_ = 8; // 8:picture dataspace
    streamInfo.intent_ = PREVIEW;
    streamInfo.tunneledMode_ = 5; // 5:tunnel mode
    streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    display_->rc = (CamRetCode)display_->streamOperator->CreateStreams(streamInfos);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    // Distribution stream
    display_->rc = (CamRetCode)display_->streamOperator->CommitStreams(NORMAL, display_->ability_);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    // Get preview
    int captureId = 2001;
    CaptureInfo captureInfo = {};
    captureInfo.streamIds_ = {1001};
    captureInfo.captureSetting_ = display_->ability_;
    captureInfo.enableShutterCallback_ = false;
    display_->rc = (CamRetCode)display_->streamOperator->Capture(captureId, captureInfo, true);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    sleep(5);
    display_->streamOperator->CancelCapture(captureId);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    // release stream
    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams(
        {-1});
    std::cout << "streamOperator->ReleaseStreams's rc = " << display_->rc << std::endl;
    EXPECT_EQ(true, display_->rc == INVALID_ARGUMENT);
    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams(
        {1001});
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    std::cout << "streamOperator->ReleaseStreams's RetCode = " << display_->rc << std::endl;
}

/**
  * @tc.name: Preview
  * @tc.desc: ReleaseStreams no exist streamID, expect success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_062, TestSize.Level2)
{
    std::cout << "==========[test log] ReleaseStreams no exist streamID, expect success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams(
        {9999});
    std::cout << "streamOperator->ReleaseStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
}

/**
  * @tc.name: Preview
  * @tc.desc: Preview, Capture->captureInfo->streamID = -1 ,return error.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_070, TestSize.Level2)
{
    std::cout << "==========[test log] Preview, Capture->captureInfo->streamID = -1 ,return error." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create preview stream
    // std::shared_ptr<OHOS::IBufferProducer> producer = OHOS::IBufferProducer::CreateBufferQueue();
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }

    std::vector<StreamInfo> streamInfos;
    StreamInfo streamInfo = {};
    streamInfo.streamId_ = 1001;
    streamInfo.width_ = 640; // 640:picture width
    streamInfo.height_ = 480; // 480:picture height
    streamInfo.format_ = PIXEL_FMT_RGBA_8888;
    streamInfo.dataspace_ = 8; // 8:picture dataspace
    streamInfo.intent_ = PREVIEW;
    streamInfo.tunneledMode_ = 5; // 5:tunnel mode
    streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    display_->rc = (CamRetCode)display_->streamOperator->CreateStreams(streamInfos);
    if (display_->rc != HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==============[test log]CreateStreams failed!" << std::endl;
    }
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    // Distribution stream
    display_->rc = (CamRetCode)display_->streamOperator->CommitStreams(NORMAL, display_->ability_);
    if (display_->rc != HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==============[test log]CommitStreams failed!" << std::endl;
    }
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    // Get preview
    int captureId = 2001;
    CaptureInfo captureInfo = {};
    captureInfo.streamIds_ = {-1};
    captureInfo.captureSetting_ = display_->ability_;
    captureInfo.enableShutterCallback_ = true;
    display_->rc = (CamRetCode)display_->streamOperator->Capture(captureId, captureInfo, true);
    std::cout << "streamOperator->Capture rc = " << display_->rc << std::endl;
    if (display_->rc == INVALID_ARGUMENT) {
        std::cout << "============[test log]Capture failed " << std::endl;
    }
    EXPECT_EQ(INVALID_ARGUMENT, display_->rc);
}

/**
  * @tc.name: Preview
  * @tc.desc: Preview, Capture->captureInfo->streamID = 2147483647 ,return success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_071, TestSize.Level2)
{
    std::cout << "==========[test log] Preview, Capture->captureInfo->streamID = 2147483647 ,";
    std::cout << "return success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }

    std::vector<StreamInfo> streamInfos;
    StreamInfo streamInfo = {};
    streamInfo.streamId_ = 2147483647;
    streamInfo.width_ = 640; // 640:picture width
    streamInfo.height_ = 480; // 480:picture height
    streamInfo.format_ = PIXEL_FMT_RGBA_8888;
    streamInfo.dataspace_ = 8; // 8:picture dataspace
    streamInfo.intent_ = PREVIEW;
    streamInfo.tunneledMode_ = 5; // 5:tunnel mode
    streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    display_->rc = (CamRetCode)display_->streamOperator->CreateStreams(streamInfos);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    // Distribution stream
    display_->rc = (CamRetCode)display_->streamOperator->CommitStreams(NORMAL, display_->ability_);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    // Get preview
    int captureId = 2001;
    CaptureInfo captureInfo = {};
    captureInfo.streamIds_ = {2147483647};
    captureInfo.captureSetting_ = display_->ability_;
    captureInfo.enableShutterCallback_ = true;
    bool isStreaming = true;
    display_->rc = (CamRetCode)display_->streamOperator->Capture(captureId, captureInfo, isStreaming);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    sleep(5);
    display_->streamOperator->CancelCapture(captureId);
    // release stream
    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams(captureInfo.streamIds_);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
}

/**
  * @tc.name: Preview
  * @tc.desc: Preview, Capture->captureInfo->enableShutterCallback = false ,return success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_072, TestSize.Level2)
{
    std::cout << "==========[test log] Preview, Capture->captureInfo->enableShutterCallback = false ,";
    std::cout << "return success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    display_->intents = {PREVIEW};
    display_->StartStream(display_->intents);
    // Get preview
    display_->StartCapture(display_->STREAM_ID_PREVIEW, display_->CAPTURE_ID_PREVIEW, false, true);
    // release stream
    display_->captureIds = {display_->CAPTURE_ID_PREVIEW};
    display_->streamIds = {display_->STREAM_ID_PREVIEW};
    display_->StopStream(display_->captureIds, display_->streamIds);
}

/**
  * @tc.name: Preview
  * @tc.desc: Preview, Capture->isStreaming = false ,expected success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_073, TestSize.Level2)
{
    std::cout << "==========[test log] Preview, Capture->isStreaming = false ,expected success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    display_->intents = {PREVIEW};
    display_->StartStream(display_->intents);
    // Get preview
    int captureId = 2001;
    CaptureInfo captureInfo = {};
    captureInfo.streamIds_ = {display_->STREAM_ID_PREVIEW};
    captureInfo.captureSetting_ = display_->ability_;
    captureInfo.enableShutterCallback_ = true;
    display_->rc = (CamRetCode)display_->streamOperator->Capture(captureId, captureInfo, false);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    sleep(5);
    display_->streamOperator->CancelCapture(captureId);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    // release stream
    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams(captureInfo.streamIds_);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
}

/**
  * @tc.name: Preview
  * @tc.desc: Preview, Capture->captureId = -1 ,return error.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_074, TestSize.Level2)
{
    std::cout << "==========[test log] Preview, Capture->captureId = -1 ,return error." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    display_->intents = {PREVIEW};
    display_->StartStream(display_->intents);
    // Get preview
    int captureId = -1;
    CaptureInfo captureInfo = {};
    captureInfo.streamIds_ = {display_->STREAM_ID_PREVIEW};
    captureInfo.captureSetting_ = display_->ability_;
    captureInfo.enableShutterCallback_ = false;
    bool isStreaming = true;
    display_->rc = (CamRetCode)display_->streamOperator->Capture(captureId, captureInfo, isStreaming);
    EXPECT_EQ(INVALID_ARGUMENT, display_->rc);
}

/**
  * @tc.name: Preview
  * @tc.desc: Preview, Capture->captureInfo->enableShutterCallback = true ,return success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_075, TestSize.Level2)
{
    std::cout << "==========[test log] Preview, Capture->captureInfo->enableShutterCallback = true ,";
    std::cout << "return success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    display_->intents = {PREVIEW};
    display_->StartStream(display_->intents);
    // Get preview
    display_->StartCapture(display_->STREAM_ID_PREVIEW, display_->CAPTURE_ID_PREVIEW, true, true);
    // release stream
    display_->captureIds = {display_->CAPTURE_ID_PREVIEW};
    display_->streamIds = {display_->STREAM_ID_PREVIEW};
    display_->StopStream(display_->captureIds, display_->streamIds);
}

/**
  * @tc.name: Preview
  * @tc.desc: CancelCapture captureID = -1.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_080, TestSize.Level2)
{
    std::cout << "==========[test log] CancelCapture captureID = -1, expected fail." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }

    std::vector<StreamInfo> streamInfos;
    StreamInfo streamInfo = {};
    streamInfo.streamId_ = 1001;
    streamInfo.width_ = 640; // 640:picture width
    streamInfo.height_ = 480; // 480:picture height
    streamInfo.format_ = PIXEL_FMT_RGBA_8888;
    streamInfo.dataspace_ = 8; // 8:picture dataspace
    streamInfo.intent_ = PREVIEW;
    streamInfo.tunneledMode_ = 5; // 5:tunnel mode
    streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    display_->rc = (CamRetCode)display_->streamOperator->CreateStreams(streamInfos);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    // Distribution stream
    display_->rc = (CamRetCode)display_->streamOperator->CommitStreams(NORMAL, display_->ability_);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    // Get preview
    int captureId = 100;
    CaptureInfo captureInfo = {};
    captureInfo.streamIds_ = {1001};
    captureInfo.captureSetting_ = display_->ability_;
    captureInfo.enableShutterCallback_ = false;
    bool isStreaming = true;
    display_->rc = (CamRetCode)display_->streamOperator->Capture(captureId, captureInfo, isStreaming);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    sleep(5);
    display_->rc = (CamRetCode)display_->streamOperator->CancelCapture(-1);
    EXPECT_EQ(INVALID_ARGUMENT, display_->rc);
    display_->rc = (CamRetCode)display_->streamOperator->CancelCapture(captureId);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    // release stream
    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams(captureInfo.streamIds_);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
}

/**
  * @tc.name: Preview
  * @tc.desc: CancelCapture without Create capture.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_090, TestSize.Level2)
{
    std::cout << "==========[test log] CancelCapture without Create capture ." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    display_->intents = {PREVIEW};
    display_->StartStream(display_->intents);
    // Get preview
    int captureId = 100;
    display_->rc = (CamRetCode)display_->streamOperator->CancelCapture(captureId);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] CancelCapture success." << std::endl;
    }
    else {
        std::cout << "==========[test log] CancelCapture fail, rc = " << display_->rc << std::endl;
    }
}

/**
  * @tc.name: Preview
  * @tc.desc: Release streams, then createCapture.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_091, TestSize.Level2)
{
    std::cout << "==========[test log] Create capture, then release streams." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // start stream
    display_->intents = {PREVIEW};
    display_->StartStream(display_->intents);
    // Get preview
    display_->StartCapture(display_->STREAM_ID_PREVIEW, display_->CAPTURE_ID_PREVIEW, false, true);
    // release stream
    display_->captureIds = {display_->CAPTURE_ID_PREVIEW};
    display_->streamIds = {display_->STREAM_ID_PREVIEW};
    display_->StopStream(display_->captureIds, display_->streamIds);
}

/**
  * @tc.name: Preview
  * @tc.desc: The same CaptureID, Create capture twice, expected fail.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_092, TestSize.Level2)
{
    std::cout << "==========[test log] The same CaptureID, Create capture twice, expected fail." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // start stream
    display_->intents = {PREVIEW};
    display_->StartStream(display_->intents);

    int captureId = display_->CAPTURE_ID_PREVIEW;
    CaptureInfo captureInfo = {};
    captureInfo.streamIds_ = {display_->STREAM_ID_PREVIEW};
    captureInfo.captureSetting_ = display_->ability_;
    captureInfo.enableShutterCallback_ = false;
    bool isStreaming = true;
    display_->rc = (CamRetCode)display_->streamOperator->Capture(captureId, captureInfo, isStreaming);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);

    display_->rc = (CamRetCode)display_->streamOperator->Capture(captureId, captureInfo, isStreaming);
    EXPECT_EQ(false, display_->rc == HDI::Camera::V1_0::NO_ERROR);

    sleep(2);
    // cancel capture
    display_->rc = (CamRetCode)display_->streamOperator->CancelCapture(captureId);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);

    // release stream
    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams(captureInfo.streamIds_);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
}

/**
  * @tc.name: Preview
  * @tc.desc: Different captureIDs, Create capture，expected success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_093, TestSize.Level2)
{
    std::cout << "==========[test log] Different captureIDs, Create capture，expected success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    display_->intents = {PREVIEW};
    display_->StartStream(display_->intents);
    // Get preview
    int captureId = display_->CAPTURE_ID_PREVIEW;
    CaptureInfo captureInfo = {};
    captureInfo.streamIds_ = {display_->STREAM_ID_PREVIEW};
    captureInfo.captureSetting_ = display_->ability_;
    captureInfo.enableShutterCallback_ = false;
    bool isStreaming = true;
    display_->rc = (CamRetCode)display_->streamOperator->Capture(captureId, captureInfo, isStreaming);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    display_->rc = (CamRetCode)display_->streamOperator->Capture(captureId + 1, captureInfo, isStreaming);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);

    sleep(2);
    // cancel capture
    display_->streamOperator->CancelCapture(captureId);
    display_->streamOperator->CancelCapture(captureId + 1);
    // release stream
    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams(captureInfo.streamIds_);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
}