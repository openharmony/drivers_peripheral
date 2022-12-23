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
    CAMERA_LOGD("Preview stream, expected success.");
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
    CAMERA_LOGD("Preview, format error, expected return errorCode.");
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        CAMERA_LOGE("~~~~~~~");
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
        CAMERA_LOGI("CreateStreams success.");
    } else {
        CAMERA_LOGE("CreateStreams fail, rc = %{public}d", display_->rc);
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
    CAMERA_LOGD("GetStreamOperator success.");
    // Get the configured cameraId
    display_->cameraHost->GetCameraIds(display_->cameraIds);
    CAMERA_LOGD("cameraIds.front() = %{public}s", (display_->cameraIds.front()).c_str());
    // Open the camera device and get the device
    const OHOS::sptr<ICameraDeviceCallback> callback = new DemoCameraDeviceCallback();
    display_->rc = (CamRetCode)display_->cameraHost->OpenCamera(display_->cameraIds.front(),
        callback, display_->cameraDevice);
    CAMERA_LOGD("OpenCamera's RetCode = %{public}d", display_->rc);
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
    CAMERA_LOGD("GetStreamOperator, input nullptr.");
    // Get the configured cameraId
    display_->cameraHost->GetCameraIds(display_->cameraIds);
    CAMERA_LOGD("cameraIds.front() = %{public}s", (display_->cameraIds.front()).c_str());
    // Open the camera device and get the device
    const OHOS::sptr<ICameraDeviceCallback> callback = new DemoCameraDeviceCallback();
    display_->rc = (CamRetCode)display_->cameraHost->OpenCamera(display_->cameraIds.front(),
        callback, display_->cameraDevice);
    CAMERA_LOGD("OpenCamera's RetCode = %{public}d", display_->rc);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    // Create and get streamOperator information
    OHOS::sptr<IStreamOperatorCallback> streamOperatorCallback = nullptr;
    display_->rc = (CamRetCode)display_->cameraDevice->GetStreamOperator(streamOperatorCallback,
        display_->streamOperator);
    CAMERA_LOGD("GetStreamOperator's RetCode = %{public}d", display_->rc);
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
    CAMERA_LOGD("CreateStreams, success.");
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        CAMERA_LOGE("~~~~~~~");
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
    CAMERA_LOGD("CreateStreams's RetCode = %{public}d", display_->rc);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    CAMERA_LOGD("CreateStreams, success.");
    // Submit stream information
    display_->rc = (CamRetCode)display_->streamOperator->CommitStreams(NORMAL, display_->ability_);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("CommitStreams, success.");
    } else {
        CAMERA_LOGE("CommitStreams fail, rc = %{public}d", display_->rc);
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
    CAMERA_LOGD("CreateStreams, success.");
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        CAMERA_LOGE("~~~~~~~");
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
    CAMERA_LOGD("CreateStreams's RetCode = %{public}d", display_->rc);
    EXPECT_EQ(false, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("CreateStreams, success.");
    } else {
        CAMERA_LOGE("CreateStreams fail, rc = %{public}d", display_->rc);
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
    CAMERA_LOGD("CreateStreams, StreamInfo->streamId = 2147483647, return success.");
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        CAMERA_LOGE("~~~~~~~");
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
    CAMERA_LOGD("streamOperator->CreateStreams's RetCode = %{public}d", display_->rc);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("CreateStreams, success.");
    } else {
        CAMERA_LOGE("CreateStreams fail, rc = %{public}d", display_->rc);
    }
    // Submit stream information
    display_->rc = (CamRetCode)display_->streamOperator->CommitStreams(NORMAL, display_->ability_);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    CAMERA_LOGD("CommitStreams success.");
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
    CAMERA_LOGD("CreateStreams, StreamInfo->width = -1, return error.");
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        CAMERA_LOGE("~~~~~~~");
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
    CAMERA_LOGD("streamOperator->CreateStreams's RetCode = %{public}d", display_->rc);
    EXPECT_EQ(true, display_->rc == INVALID_ARGUMENT);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("CreateStreams, success.");
    } else {
        CAMERA_LOGE("CreateStreams fail, rc = %{public}d", display_->rc);
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
    CAMERA_LOGD("CreateStreams, StreamInfo->height = -1, return error.");
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        CAMERA_LOGE("~~~~~~~");
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
    CAMERA_LOGD("streamOperator->CreateStreams's RetCode = %{public}d", display_->rc);
    EXPECT_EQ(CamRetCode::INVALID_ARGUMENT, display_->rc);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("CreateStreams, success.");
    } else {
        CAMERA_LOGE("CreateStreams fail, rc = %{public}d", display_->rc);
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
    CAMERA_LOGD("CreateStreams, StreamInfo->format = -1, return error.");
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        CAMERA_LOGE("~~~~~~~");
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
    CAMERA_LOGD("streamOperator->CreateStreams's RetCode = %{public}d", display_->rc);
    EXPECT_EQ(CamRetCode::INVALID_ARGUMENT, display_->rc);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("CreateStreams, success.");
    } else {
        CAMERA_LOGE("CreateStreams fail, rc = %{public}d", display_->rc);
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
    CAMERA_LOGD("CreateStreams, StreamInfo->dataspace = 2147483647, success.");
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        CAMERA_LOGE("~~~~~~~");
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
    CAMERA_LOGD("streamOperator->CreateStreams's RetCode = %{public}d", display_->rc);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("CreateStreams, success.");
    } else {
        CAMERA_LOGE("CreateStreams fail, rc = %{public}d", display_->rc);
    }
    // Submit stream information
    display_->rc = (CamRetCode)display_->streamOperator->CommitStreams(NORMAL, display_->ability_);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    CAMERA_LOGD("CommitStreams success.");
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
    CAMERA_LOGD("CreateStreams, StreamInfo->StreamIntent = PREVIEW, success.");
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
    CAMERA_LOGD("CreateStreams, StreamInfo->StreamIntent = VIDEO, success.");
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
    CAMERA_LOGD("CreateStreams, StreamInfo->StreamIntent = STILL_CAPTURE, success.");
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
    CAMERA_LOGD("CreateStreams, StreamInfo->StreamIntent = POST_VIEW, success.");
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
        CAMERA_LOGE("~~~~~~~");
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
        CAMERA_LOGI("CreateStreams success.");
    } else {
        CAMERA_LOGE("CreateStreams fail, rc = %{public}d", display_->rc);
    }
    // release stream
    std::vector<int> streamIds;
    streamIds.push_back(streamInfo.streamId_);
    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams(streamIds);
    CAMERA_LOGD("ReleaseStreams's RetCode = %{public}d", display_->rc);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("ReleaseStreams success.");
    } else {
        CAMERA_LOGE("ReleaseStreams fail, rc = %{public}d", display_->rc);
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
    CAMERA_LOGD("CreateStreams, StreamInfo->StreamIntent = ANALYZE, success.");
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        CAMERA_LOGE("~~~~~~~");
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
    CAMERA_LOGD("streamOperator->CreateStreams's RetCode = %{public}d", display_->rc);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    CAMERA_LOGD("CreateStreams success.");
    // release stream
    std::vector<int> streamIds;
    streamIds.push_back(streamInfo.streamId_);
    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams(streamIds);
    CAMERA_LOGD("ReleaseStreams RetCode = %{public}d", display_->rc);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("ReleaseStreams success.");
    }
    else {
        CAMERA_LOGE("ReleaseStreams fail, rc = %{public}d", display_->rc);
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
    CAMERA_LOGD("CreateStreams, StreamInfo->StreamIntent = Camera::CUSTOM, not support.");
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        CAMERA_LOGE("~~~~~~~");
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
    CAMERA_LOGD("streamOperator->CreateStreams's RetCode = %{public}d", display_->rc);
    EXPECT_EQ(true, display_->rc != HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("CreateStreams success.");
    } else {
        CAMERA_LOGE("CreateStreams fail, rc = %{public}d", display_->rc);
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
    CAMERA_LOGD("CreateStreams, StreamInfo->tunneledMode = false, success.");
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        CAMERA_LOGE("~~~~~~~");
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
    CAMERA_LOGD("streamOperator->CreateStreams's RetCode = %{public}d", display_->rc);
    EXPECT_EQ(true, display_->rc == INVALID_ARGUMENT);
    if (display_->rc == INVALID_ARGUMENT) {
        CAMERA_LOGE("CreateStreams fail.");
    } else {
        CAMERA_LOGI("CreateStreams success.");
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
    CAMERA_LOGD("CreateStreams, StreamInfo->minFrameDuration = -1, return error.");
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        CAMERA_LOGE("~~~~~~~");
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
    CAMERA_LOGD("streamOperator->CreateStreams's RetCode = %{public}d", display_->rc);
    EXPECT_EQ(INVALID_ARGUMENT, display_->rc);
    CAMERA_LOGD("CreateStreams, failed.");
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
    CAMERA_LOGD("CreateStreams, StreamInfo->minFrameDuration = 2147483647, success.");
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        CAMERA_LOGE("~~~~~~~");
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
    streamInfo.minFrameDuration_ = 2147483647;
    streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    display_->rc = (CamRetCode)display_->streamOperator->CreateStreams(streamInfos);
    CAMERA_LOGD("streamOperator->CreateStreams's RetCode = %{public}d", display_->rc);
    EXPECT_EQ(false, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    CAMERA_LOGD("CreateStreams, success.");
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
    CAMERA_LOGD("Preview, CommitStreams Metadata = nullptr.");
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        CAMERA_LOGE("~~~~~~~");
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
    streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    display_->rc = (CamRetCode)display_->streamOperator->CreateStreams(streamInfos);
    // Distribution stream
    std::vector<uint8_t> modeSetting = {};
    display_->rc = (CamRetCode)display_->streamOperator->CommitStreams(NORMAL, modeSetting);
    CAMERA_LOGD("streamOperator->CreateStreams's RetCode = %{public}d", display_->rc);
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
    CAMERA_LOGD("Preview, CommitStreams without CreateStreams, expected fail.");
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Distribution stream
    display_->rc = (CamRetCode)display_->streamOperator->CommitStreams(NORMAL, display_->ability_);
    CAMERA_LOGD("streamOperator->CommitStreams's RetCode = %{public}d", display_->rc);
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
    CAMERA_LOGD("Preview  and release streams, success.");
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        CAMERA_LOGE("~~~~~~~");
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
    CAMERA_LOGD("ReleaseStreams-> streamID = -1, expected success.");
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
        CAMERA_LOGE("~~~~~~~");
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
    CAMERA_LOGD("streamOperator->ReleaseStreams's rc = %{public}d", display_->rc);
    EXPECT_EQ(true, display_->rc == INVALID_ARGUMENT);
    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams(
        {1001});
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    CAMERA_LOGD("streamOperator->ReleaseStreams's RetCode = %{public}d", display_->rc);
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
    CAMERA_LOGD("ReleaseStreams no exist streamID, expect success.");
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams(
        {9999});
    CAMERA_LOGD("streamOperator->ReleaseStreams's RetCode = %{public}d", display_->rc);
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
    CAMERA_LOGD("Preview, Capture->captureInfo->streamID = -1 ,return error.");
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
        CAMERA_LOGE("~~~~~~~");
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
        CAMERA_LOGE("CreateStreams failed!");
    }
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    // Distribution stream
    display_->rc = (CamRetCode)display_->streamOperator->CommitStreams(NORMAL, display_->ability_);
    if (display_->rc != HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGE("CommitStreams failed!");
    }
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    // Get preview
    int captureId = 2001;
    CaptureInfo captureInfo = {};
    captureInfo.streamIds_ = {-1};
    captureInfo.captureSetting_ = display_->ability_;
    captureInfo.enableShutterCallback_ = true;
    display_->rc = (CamRetCode)display_->streamOperator->Capture(captureId, captureInfo, true);
    CAMERA_LOGD("streamOperator->Capture rc = %{public}d", display_->rc);
    if (display_->rc == INVALID_ARGUMENT) {
        CAMERA_LOGE("Capture failed!");
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
    CAMERA_LOGD("Preview, Capture->captureInfo->streamID = 2147483647 ,return success.");
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        CAMERA_LOGE("~~~~~~~");
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
    CAMERA_LOGD("Preview, Capture->captureInfo->enableShutterCallback = false, return success.");
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
    CAMERA_LOGD("Preview, Capture->isStreaming = false ,expected success.");
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
    CAMERA_LOGD("Preview, Capture->captureId = -1 ,return error.");
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
    CAMERA_LOGD("Preview, Capture->captureInfo->enableShutterCallback = true, return success.");
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
    CAMERA_LOGD("CancelCapture captureID = -1, expected fail.");
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    if (display_->streamCustomerPreview_ == nullptr) {
        display_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = display_->streamCustomerPreview_->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        CAMERA_LOGE("~~~~~~~");
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
    CAMERA_LOGD("CancelCapture without Create capture.");
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    display_->intents = {PREVIEW};
    display_->StartStream(display_->intents);
    // Get preview
    int captureId = 100;
    display_->rc = (CamRetCode)display_->streamOperator->CancelCapture(captureId);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("CancelCapture success.");
    } else {
        CAMERA_LOGE("CancelCapture fail, rc = %{public}d", display_->rc);
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
    CAMERA_LOGD("Create capture, then release streams.");
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
    CAMERA_LOGD("The same CaptureID, Create capture twice, expected fail.");
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
    CAMERA_LOGD("Different captureIDs, Create capture，expected success.");
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

/**
  * @tc.name: GetStreamAttributes
  * @tc.desc: GetStreamAttributes, success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraPreviewTest, camera_preview_094, TestSize.Level2)
{
    display_->AchieveStreamOperator();
    // start stream
    display_->intents = {PREVIEW};
    display_->StartStream(display_->intents);

    std::vector<StreamAttribute> attributes;
    display_->rc = (CamRetCode)display_->streamOperator->GetStreamAttributes(attributes);
    EXPECT_EQ(display_->rc, HDI::Camera::V1_0::NO_ERROR);

    // release stream
    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams({PREVIEW});
    EXPECT_EQ(display_->rc, HDI::Camera::V1_0::NO_ERROR);
}