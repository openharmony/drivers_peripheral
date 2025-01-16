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
    if (cameraBase_ == nullptr)
    cameraBase_ = std::make_shared<TestCameraBase>();
    cameraBase_->Init();
}

void CameraPreviewTest::TearDown(void)
{
    cameraBase_->Close();
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
    cameraBase_->AchieveStreamOperator();
    // Create data stream
    if (cameraBase_->streamCustomerPreview_ == nullptr) {
        cameraBase_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = cameraBase_->streamCustomerPreview_->CreateProducer();
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
    ASSERT_NE(streamInfo.bufferQueue_, nullptr);
    streamInfos.push_back(streamInfo);
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CreateStreams(streamInfos);
    EXPECT_EQ(true, cameraBase_->rc != HDI::Camera::V1_0::NO_ERROR);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("CreateStreams success.");
    } else {
        CAMERA_LOGE("CreateStreams fail, rc = %{public}d", cameraBase_->rc);
    }
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
    cameraBase_->AchieveStreamOperator();
    // Create data stream
    if (cameraBase_->streamCustomerPreview_ == nullptr) {
        cameraBase_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = cameraBase_->streamCustomerPreview_->CreateProducer();
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
    ASSERT_NE(streamInfo.bufferQueue_, nullptr);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CreateStreams(streamInfos);
    CAMERA_LOGD("CreateStreams's RetCode = %{public}d", cameraBase_->rc);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    CAMERA_LOGD("CreateStreams, success.");
    // Submit stream information
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CommitStreams(NORMAL, cameraBase_->ability_);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("CommitStreams, success.");
    } else {
        CAMERA_LOGE("CommitStreams fail, rc = %{public}d", cameraBase_->rc);
    }
    // capture
    cameraBase_->StartCapture(1001, cameraBase_->CAPTURE_ID_PREVIEW, false, true);
    // release stream
    cameraBase_->captureIds = {cameraBase_->CAPTURE_ID_PREVIEW};
    cameraBase_->streamIds = {1001};
    cameraBase_->StopStream(cameraBase_->captureIds, cameraBase_->streamIds);
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
    cameraBase_->AchieveStreamOperator();
    // Create data stream
    if (cameraBase_->streamCustomerPreview_ == nullptr) {
        cameraBase_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = cameraBase_->streamCustomerPreview_->CreateProducer();
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
    ASSERT_NE(streamInfo.bufferQueue_, nullptr);
    streamInfos.push_back(streamInfo);
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CreateStreams(streamInfos);
    CAMERA_LOGD("CreateStreams's RetCode = %{public}d", cameraBase_->rc);
    EXPECT_EQ(false, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("CreateStreams, success.");
    } else {
        CAMERA_LOGE("CreateStreams fail, rc = %{public}d", cameraBase_->rc);
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
    cameraBase_->AchieveStreamOperator();
    // Create data stream
    if (cameraBase_->streamCustomerPreview_ == nullptr) {
        cameraBase_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = cameraBase_->streamCustomerPreview_->CreateProducer();
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
    ASSERT_NE(streamInfo.bufferQueue_, nullptr);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CreateStreams(streamInfos);
    CAMERA_LOGD("streamOperator->CreateStreams's RetCode = %{public}d", cameraBase_->rc);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("CreateStreams, success.");
    } else {
        CAMERA_LOGE("CreateStreams fail, rc = %{public}d", cameraBase_->rc);
    }
    // Submit stream information
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CommitStreams(NORMAL, cameraBase_->ability_);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    CAMERA_LOGD("CommitStreams success.");
    // capture
    cameraBase_->StartCapture(2147483647, cameraBase_->CAPTURE_ID_PREVIEW, false, true);
    // release stream
    cameraBase_->captureIds = {cameraBase_->CAPTURE_ID_PREVIEW};
    cameraBase_->streamIds = {2147483647};
    cameraBase_->StopStream(cameraBase_->captureIds, cameraBase_->streamIds);
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
    cameraBase_->AchieveStreamOperator();
    // start stream
    cameraBase_->intents = {PREVIEW, VIDEO};
    cameraBase_->StartStream(cameraBase_->intents);
    // Get preview
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true);
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_VIDEO, cameraBase_->CAPTURE_ID_VIDEO, false, true);
    // release stream
    cameraBase_->captureIds = {cameraBase_->CAPTURE_ID_PREVIEW, cameraBase_->CAPTURE_ID_VIDEO};
    cameraBase_->streamIds = {cameraBase_->STREAM_ID_PREVIEW, cameraBase_->STREAM_ID_VIDEO};
    cameraBase_->StopStream(cameraBase_->captureIds, cameraBase_->streamIds);
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
    cameraBase_->AchieveStreamOperator();
    // start stream
    cameraBase_->intents = {PREVIEW, STILL_CAPTURE};
    cameraBase_->StartStream(cameraBase_->intents);
    // Get preview
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true);
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_CAPTURE, cameraBase_->CAPTURE_ID_CAPTURE, false, true);
    // release stream
    cameraBase_->captureIds = {cameraBase_->CAPTURE_ID_PREVIEW, cameraBase_->CAPTURE_ID_CAPTURE};
    cameraBase_->streamIds = {cameraBase_->STREAM_ID_PREVIEW, cameraBase_->STREAM_ID_CAPTURE};
    cameraBase_->StopStream(cameraBase_->captureIds, cameraBase_->streamIds);
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
    cameraBase_->AchieveStreamOperator();
    // Create preview stream
    // std::shared_ptr<OHOS::IBufferProducer> producer = OHOS::IBufferProducer::CreateBufferQueue();
    if (cameraBase_->streamCustomerPreview_ == nullptr) {
        cameraBase_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = cameraBase_->streamCustomerPreview_->CreateProducer();
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
    ASSERT_NE(streamInfo.bufferQueue_, nullptr);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CreateStreams(streamInfos);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("CreateStreams success.");
    } else {
        CAMERA_LOGE("CreateStreams fail, rc = %{public}d", cameraBase_->rc);
    }
    // release stream
    std::vector<int> streamIds;
    streamIds.push_back(streamInfo.streamId_);
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->ReleaseStreams(streamIds);
    CAMERA_LOGD("ReleaseStreams's RetCode = %{public}d", cameraBase_->rc);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("ReleaseStreams success.");
    } else {
        CAMERA_LOGE("ReleaseStreams fail, rc = %{public}d", cameraBase_->rc);
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
    cameraBase_->AchieveStreamOperator();
    // Create data stream
    if (cameraBase_->streamCustomerPreview_ == nullptr) {
        cameraBase_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = cameraBase_->streamCustomerPreview_->CreateProducer();
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
    ASSERT_NE(streamInfo.bufferQueue_, nullptr);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CreateStreams(streamInfos);
    CAMERA_LOGD("streamOperator->CreateStreams's RetCode = %{public}d", cameraBase_->rc);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    CAMERA_LOGD("CreateStreams success.");
    // release stream
    std::vector<int> streamIds;
    streamIds.push_back(streamInfo.streamId_);
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->ReleaseStreams(streamIds);
    CAMERA_LOGD("ReleaseStreams RetCode = %{public}d", cameraBase_->rc);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("ReleaseStreams success.");
    }
    else {
        CAMERA_LOGE("ReleaseStreams fail, rc = %{public}d", cameraBase_->rc);
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
    cameraBase_->AchieveStreamOperator();
    // Create data stream
    if (cameraBase_->streamCustomerPreview_ == nullptr) {
        cameraBase_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = cameraBase_->streamCustomerPreview_->CreateProducer();
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
    ASSERT_NE(streamInfo.bufferQueue_, nullptr);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CreateStreams(streamInfos);
    CAMERA_LOGD("streamOperator->CreateStreams's RetCode = %{public}d", cameraBase_->rc);
    EXPECT_EQ(true, cameraBase_->rc != HDI::Camera::V1_0::NO_ERROR);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("CreateStreams success.");
    } else {
        CAMERA_LOGE("CreateStreams fail, rc = %{public}d", cameraBase_->rc);
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
    cameraBase_->AchieveStreamOperator();
    // Create data stream
    if (cameraBase_->streamCustomerPreview_ == nullptr) {
        cameraBase_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = cameraBase_->streamCustomerPreview_->CreateProducer();
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
    ASSERT_NE(streamInfo.bufferQueue_, nullptr);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CreateStreams(streamInfos);
    CAMERA_LOGD("streamOperator->CreateStreams's RetCode = %{public}d", cameraBase_->rc);
    EXPECT_EQ(true, cameraBase_->rc == INVALID_ARGUMENT);
    if (cameraBase_->rc == INVALID_ARGUMENT) {
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
    cameraBase_->AchieveStreamOperator();
    // Create data stream
    if (cameraBase_->streamCustomerPreview_ == nullptr) {
        cameraBase_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = cameraBase_->streamCustomerPreview_->CreateProducer();
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
    ASSERT_NE(streamInfo.bufferQueue_, nullptr);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CreateStreams(streamInfos);
    CAMERA_LOGD("streamOperator->CreateStreams's RetCode = %{public}d", cameraBase_->rc);
    EXPECT_EQ(INVALID_ARGUMENT, cameraBase_->rc);
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
    cameraBase_->AchieveStreamOperator();
    // Create data stream
    if (cameraBase_->streamCustomerPreview_ == nullptr) {
        cameraBase_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = cameraBase_->streamCustomerPreview_->CreateProducer();
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
    ASSERT_NE(streamInfo.bufferQueue_, nullptr);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CreateStreams(streamInfos);
    CAMERA_LOGD("streamOperator->CreateStreams's RetCode = %{public}d", cameraBase_->rc);
    EXPECT_EQ(false, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
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
    cameraBase_->AchieveStreamOperator();
    if (cameraBase_->streamCustomerPreview_ == nullptr) {
        cameraBase_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = cameraBase_->streamCustomerPreview_->CreateProducer();
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
    ASSERT_NE(streamInfo.bufferQueue_, nullptr);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CreateStreams(streamInfos);
    // Distribution stream
    std::vector<uint8_t> modeSetting = {};
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CommitStreams(NORMAL, modeSetting);
    CAMERA_LOGD("streamOperator->CreateStreams's RetCode = %{public}d", cameraBase_->rc);
    EXPECT_EQ(true, cameraBase_->rc != HDI::Camera::V1_0::NO_ERROR);
    // release stream
    std::vector<int> streamIds;
    streamIds.push_back(-1);
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->ReleaseStreams(streamIds);
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
    cameraBase_->AchieveStreamOperator();
    // Distribution stream
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CommitStreams(NORMAL, cameraBase_->ability_);
    CAMERA_LOGD("streamOperator->CommitStreams's RetCode = %{public}d", cameraBase_->rc);
    EXPECT_EQ(true, cameraBase_->rc == INVALID_ARGUMENT);
    // release stream
    std::vector<int> streamIds;
    streamIds.push_back(-1);
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->ReleaseStreams(streamIds);
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
    cameraBase_->AchieveStreamOperator();
    // Create data stream
    if (cameraBase_->streamCustomerPreview_ == nullptr) {
        cameraBase_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = cameraBase_->streamCustomerPreview_->CreateProducer();
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
    ASSERT_NE(streamInfo.bufferQueue_, nullptr);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CreateStreams(streamInfos);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    // Distribution stream
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CommitStreams(NORMAL, cameraBase_->ability_);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    // Get preview
    int captureId = 2001;
    CaptureInfo captureInfo = {};
    captureInfo.streamIds_ = {1001};
    captureInfo.captureSetting_ = cameraBase_->ability_;
    captureInfo.enableShutterCallback_ = false;
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->Capture(captureId, captureInfo, true);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    sleep(3);
    cameraBase_->streamOperator->CancelCapture(captureId);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    // release stream
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->ReleaseStreams(captureInfo.streamIds_);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
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
    cameraBase_->AchieveStreamOperator();
    // Create preview stream
    // std::shared_ptr<OHOS::IBufferProducer> producer = OHOS::IBufferProducer::CreateBufferQueue();
    if (cameraBase_->streamCustomerPreview_ == nullptr) {
        cameraBase_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = cameraBase_->streamCustomerPreview_->CreateProducer();
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
    ASSERT_NE(streamInfo.bufferQueue_, nullptr);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CreateStreams(streamInfos);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    // Distribution stream
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CommitStreams(NORMAL, cameraBase_->ability_);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    // Get preview
    int captureId = 2001;
    CaptureInfo captureInfo = {};
    captureInfo.streamIds_ = {1001};
    captureInfo.captureSetting_ = cameraBase_->ability_;
    captureInfo.enableShutterCallback_ = false;
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->Capture(captureId, captureInfo, true);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    sleep(3);
    cameraBase_->streamOperator->CancelCapture(captureId);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    // release stream
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->ReleaseStreams(
        {-1});
    CAMERA_LOGD("streamOperator->ReleaseStreams's rc = %{public}d", cameraBase_->rc);
    EXPECT_EQ(true, cameraBase_->rc == INVALID_ARGUMENT);
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->ReleaseStreams(
        {1001});
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    CAMERA_LOGD("streamOperator->ReleaseStreams's RetCode = %{public}d", cameraBase_->rc);
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
    cameraBase_->AchieveStreamOperator();
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->ReleaseStreams(
        {9999});
    CAMERA_LOGD("streamOperator->ReleaseStreams's RetCode = %{public}d", cameraBase_->rc);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
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
    cameraBase_->AchieveStreamOperator();
    // Create preview stream
    // std::shared_ptr<OHOS::IBufferProducer> producer = OHOS::IBufferProducer::CreateBufferQueue();
    if (cameraBase_->streamCustomerPreview_ == nullptr) {
        cameraBase_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = cameraBase_->streamCustomerPreview_->CreateProducer();
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
    ASSERT_NE(streamInfo.bufferQueue_, nullptr);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CreateStreams(streamInfos);
    if (cameraBase_->rc != HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGE("CreateStreams failed!");
    }
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    // Distribution stream
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CommitStreams(NORMAL, cameraBase_->ability_);
    if (cameraBase_->rc != HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGE("CommitStreams failed!");
    }
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    // Get preview
    int captureId = 2001;
    CaptureInfo captureInfo = {};
    captureInfo.streamIds_ = {-1};
    captureInfo.captureSetting_ = cameraBase_->ability_;
    captureInfo.enableShutterCallback_ = true;
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->Capture(captureId, captureInfo, true);
    CAMERA_LOGD("streamOperator->Capture rc = %{public}d", cameraBase_->rc);
    if (cameraBase_->rc == INVALID_ARGUMENT) {
        CAMERA_LOGE("Capture failed!");
    }
    EXPECT_EQ(INVALID_ARGUMENT, cameraBase_->rc);
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
    cameraBase_->AchieveStreamOperator();
    // Create data stream
    cameraBase_->intents = {PREVIEW};
    cameraBase_->StartStream(cameraBase_->intents);
    // Get preview
    int captureId = 2001;
    CaptureInfo captureInfo = {};
    captureInfo.streamIds_ = {cameraBase_->STREAM_ID_PREVIEW};
    captureInfo.captureSetting_ = cameraBase_->ability_;
    captureInfo.enableShutterCallback_ = true;
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->Capture(captureId, captureInfo, false);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    sleep(3);
    cameraBase_->streamOperator->CancelCapture(captureId);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    // release stream
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->ReleaseStreams(captureInfo.streamIds_);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
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
    cameraBase_->AchieveStreamOperator();
    // Create data stream
    cameraBase_->intents = {PREVIEW};
    cameraBase_->StartStream(cameraBase_->intents);
    // Get preview
    int captureId = -1;
    CaptureInfo captureInfo = {};
    captureInfo.streamIds_ = {cameraBase_->STREAM_ID_PREVIEW};
    captureInfo.captureSetting_ = cameraBase_->ability_;
    captureInfo.enableShutterCallback_ = false;
    bool isStreaming = true;
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->Capture(captureId, captureInfo, isStreaming);
    EXPECT_EQ(INVALID_ARGUMENT, cameraBase_->rc);
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
    cameraBase_->AchieveStreamOperator();
    // Create data stream
    cameraBase_->intents = {PREVIEW};
    cameraBase_->StartStream(cameraBase_->intents);
    // Get preview
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, true, true);
    // release stream
    cameraBase_->captureIds = {cameraBase_->CAPTURE_ID_PREVIEW};
    cameraBase_->streamIds = {cameraBase_->STREAM_ID_PREVIEW};
    cameraBase_->StopStream(cameraBase_->captureIds, cameraBase_->streamIds);
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
    cameraBase_->AchieveStreamOperator();
    // Create data stream
    if (cameraBase_->streamCustomerPreview_ == nullptr) {
        cameraBase_->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    OHOS::sptr<OHOS::IBufferProducer> producer = cameraBase_->streamCustomerPreview_->CreateProducer();
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
    ASSERT_NE(streamInfo.bufferQueue_, nullptr);
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CreateStreams(streamInfos);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    // Distribution stream
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CommitStreams(NORMAL, cameraBase_->ability_);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    // Get preview
    int captureId = 100;
    CaptureInfo captureInfo = {};
    captureInfo.streamIds_ = {1001};
    captureInfo.captureSetting_ = cameraBase_->ability_;
    captureInfo.enableShutterCallback_ = false;
    bool isStreaming = true;
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->Capture(captureId, captureInfo, isStreaming);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    sleep(3);
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CancelCapture(-1);
    EXPECT_EQ(INVALID_ARGUMENT, cameraBase_->rc);
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CancelCapture(captureId);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    // release stream
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->ReleaseStreams(captureInfo.streamIds_);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
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
    cameraBase_->AchieveStreamOperator();
    // Create data stream
    cameraBase_->intents = {PREVIEW};
    cameraBase_->StartStream(cameraBase_->intents);
    // Get preview
    int captureId = 100;
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CancelCapture(captureId);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("CancelCapture success.");
    } else {
        CAMERA_LOGE("CancelCapture fail, rc = %{public}d", cameraBase_->rc);
    }
    EXPECT_EQ(cameraBase_->rc, HDI::Camera::V1_0::INVALID_ARGUMENT);
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
    cameraBase_->AchieveStreamOperator();
    // start stream
    cameraBase_->intents = {PREVIEW};
    cameraBase_->StartStream(cameraBase_->intents);

    int captureId = cameraBase_->CAPTURE_ID_PREVIEW;
    CaptureInfo captureInfo = {};
    captureInfo.streamIds_ = {cameraBase_->STREAM_ID_PREVIEW};
    captureInfo.captureSetting_ = cameraBase_->ability_;
    captureInfo.enableShutterCallback_ = false;
    bool isStreaming = true;
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->Capture(captureId, captureInfo, isStreaming);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);

    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->Capture(captureId, captureInfo, isStreaming);
    EXPECT_EQ(false, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);

    sleep(2);
    // cancel capture
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CancelCapture(captureId);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);

    // release stream
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->ReleaseStreams(captureInfo.streamIds_);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
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
    cameraBase_->AchieveStreamOperator();
    // Create data stream
    cameraBase_->intents = {PREVIEW};
    cameraBase_->StartStream(cameraBase_->intents);
    // Get preview
    int captureId = cameraBase_->CAPTURE_ID_PREVIEW;
    CaptureInfo captureInfo = {};
    captureInfo.streamIds_ = {cameraBase_->STREAM_ID_PREVIEW};
    captureInfo.captureSetting_ = cameraBase_->ability_;
    captureInfo.enableShutterCallback_ = false;
    bool isStreaming = true;
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->Capture(captureId, captureInfo, isStreaming);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->Capture(captureId + 1, captureInfo, isStreaming);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);

    sleep(2);
    // cancel capture
    cameraBase_->streamOperator->CancelCapture(captureId);
    cameraBase_->streamOperator->CancelCapture(captureId + 1);
    // release stream
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->ReleaseStreams(captureInfo.streamIds_);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
}

