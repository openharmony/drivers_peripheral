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
#include "camera_capture_test.h"

using namespace testing::ext;

void CameraCaptureTest::SetUpTestCase(void)
{}
void CameraCaptureTest::TearDownTestCase(void)
{}
void CameraCaptureTest::SetUp(void)
{
    if (cameraBase_ == nullptr)
    cameraBase_ = std::make_shared<TestCameraBase>();
    cameraBase_->Init();
}
void CameraCaptureTest::TearDown(void)
{
    cameraBase_->Close();
}

/**
  * @tc.name: preview and capture
  * @tc.desc: Commit 2 streams together, Preview and still_capture streams, isStreaming is true.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraCaptureTest, camera_capture_001, TestSize.Level1)
{
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
  * @tc.name: preview and capture
  * @tc.desc: Preview + capture, then close camera, and preview + capture again.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraCaptureTest, camera_capture_002, TestSize.Level1)
{
    CAMERA_LOGD("Preview + capture, then close camera, and preview + capture again.");
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

    // the 2nd time
    // Configure two streams of information
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
  * @tc.name: preview and capture
  * @tc.desc: Preview + capture with 3A, success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraCaptureTest, camera_capture_003, TestSize.Level1)
{
    CAMERA_LOGD("Capture with 3A, success.");
    // Get the stream manager
    cameraBase_->AchieveStreamOperator();
    // start stream
    cameraBase_->intents = {PREVIEW, STILL_CAPTURE};
    cameraBase_->StartStream(cameraBase_->intents);
    // Get preview
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true);
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_CAPTURE, cameraBase_->CAPTURE_ID_CAPTURE, false, true);
    // Issue 3A parameters to increase exposure
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 2000);
    int32_t expo = 0xa0;
    meta->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &expo, 1);
    const int32_t deviceStreamId = cameraBase_->STREAM_ID_CAPTURE;
    meta->addEntry(OHOS_CAMERA_STREAM_ID, &deviceStreamId, 1);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraBase_->rc = (CamRetCode)cameraBase_->cameraDevice->UpdateSettings(setting);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("UpdateSettings success, for 10s.");
    } else {
        CAMERA_LOGE("UpdateSettings fail, rc = %{public}d", cameraBase_->rc);
    }
    // release stream
    cameraBase_->captureIds = {cameraBase_->CAPTURE_ID_PREVIEW, cameraBase_->CAPTURE_ID_CAPTURE};
    cameraBase_->streamIds = {cameraBase_->STREAM_ID_PREVIEW, cameraBase_->STREAM_ID_CAPTURE};
    cameraBase_->StopStream(cameraBase_->captureIds, cameraBase_->streamIds);
}

/**
  * @tc.name: preview and capture
  * @tc.desc: Preview + capture, then switch to preview + video.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraCaptureTest, camera_capture_004, TestSize.Level1)
{
    CAMERA_LOGD("Preview + capture, then switch to preview + video.");
    CAMERA_LOGD("First, create preview + capture.");
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
    sleep(3);

    CAMERA_LOGD("Next, switch to preview + video, rc = %{public}d", cameraBase_->rc);
    // Get the stream manager
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
  * @tc.name: preview and capture
  * @tc.desc: Commit 2 streams together, Preview and still_capture streams, isStreaming is false.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraCaptureTest, camera_capture_006, TestSize.Level1)
{
    // Get the stream manager
    cameraBase_->AchieveStreamOperator();
    // start stream
    cameraBase_->intents = {PREVIEW, STILL_CAPTURE};
    cameraBase_->StartStream(cameraBase_->intents);
    // Get preview
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true);
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_CAPTURE, cameraBase_->CAPTURE_ID_CAPTURE, false, false);

    sleep(3);
    CAMERA_LOGD("frame off.");
    cameraBase_->streamCustomerPreview_->ReceiveFrameOff();
    cameraBase_->streamCustomerCapture_->ReceiveFrameOff();

    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->ReleaseStreams(
        {cameraBase_->STREAM_ID_CAPTURE});
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("ReleaseStreams success.");
    } else {
        CAMERA_LOGE("ReleaseStreams fail, rc = %{public}d", cameraBase_->rc);
    }
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->ReleaseStreams(
        {cameraBase_->STREAM_ID_PREVIEW});
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("ReleaseStreams success.");
    } else {
        CAMERA_LOGE("ReleaseStreams fail, rc = %{public}d", cameraBase_->rc);
    }
}

/**
  * @tc.name: preview and capture
  * @tc.desc: Commit 2 streams in order, Preview and still_capture streams.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraCaptureTest, camera_capture_010, TestSize.Level1)
{
    CAMERA_LOGD("Preview and still_capture streams.");
    // Configure two streams of information
    EXPECT_EQ(true, cameraBase_->cameraDevice != nullptr);
    cameraBase_->AchieveStreamOperator();
    // Configure capture stream information
    cameraBase_->intents = {PREVIEW, STILL_CAPTURE};
    cameraBase_->StartStream(cameraBase_->intents);
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true);
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_CAPTURE, cameraBase_->CAPTURE_ID_CAPTURE, false, true);
    sleep(2);

    // post-processing
    cameraBase_->streamCustomerPreview_->ReceiveFrameOff();
    cameraBase_->streamCustomerCapture_->ReceiveFrameOff();
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CancelCapture(cameraBase_->CAPTURE_ID_CAPTURE);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("CancelCapture success.");
    } else {
        CAMERA_LOGE("CancelCapture fail, rc = %{public}d", cameraBase_->rc);
    }
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CancelCapture(cameraBase_->CAPTURE_ID_PREVIEW);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("CancelCapture success.");
    } else {
        CAMERA_LOGE("CancelCapture fail, rc = %{public}d", cameraBase_->rc);
    }
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->ReleaseStreams(
        {cameraBase_->STREAM_ID_CAPTURE});
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("ReleaseStreams success.");
    } else {
        CAMERA_LOGE("ReleaseStreams fail, rc = %{public}d", cameraBase_->rc);
    }
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->ReleaseStreams(
        {cameraBase_->STREAM_ID_PREVIEW});
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("ReleaseStreams success.");
    } else {
        CAMERA_LOGE("ReleaseStreams fail, rc = %{public}d", cameraBase_->rc);
    }
}

/**
  * @tc.name: Only Still_capture stream
  * @tc.desc: Only Still_capture stream, capture->isStreaming = false.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraCaptureTest, camera_capture_020, TestSize.Level1)
{
    CAMERA_LOGD("No preview, only still_capture.");
    // start stream
    cameraBase_->AchieveStreamOperator();
    std::shared_ptr<StreamCustomer> streamCustomer = std::make_shared<StreamCustomer>();
    OHOS::sptr<OHOS::IBufferProducer> producer = streamCustomer->CreateProducer();
    producer->SetQueueSize(8); // buffer queue size
    if (producer->GetQueueSize() != 8) { // buffer queue size
        CAMERA_LOGE("~~~~~~~");
    }
    streamCustomer->ReceiveFrameOn([this](const unsigned char *addr, const uint32_t size) {
        cameraBase_->StoreImage(addr, size);
    });
    std::vector<StreamInfo> streamInfos;
    cameraBase_->streamInfo.streamId_ = 1001;
    cameraBase_->streamInfo.width_ = 1280; // picture width
    cameraBase_->streamInfo.height_ = 960; // picture height
    cameraBase_->streamInfo.format_ = PIXEL_FMT_RGBA_8888;
    cameraBase_->streamInfo.dataspace_ = 8; // picture dataspace
    cameraBase_->streamInfo.intent_ = STILL_CAPTURE;
    cameraBase_->streamInfo.tunneledMode_ = 5; // tunnel mode
    cameraBase_->streamInfo.encodeType_ = ENCODE_TYPE_JPEG;
    cameraBase_->streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    ASSERT_NE(cameraBase_->streamInfo.bufferQueue_, nullptr);
    streamInfos.push_back(cameraBase_->streamInfo);
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CreateStreams(streamInfos);
    CAMERA_LOGE("CreateStreams! rc:0x%x\n", cameraBase_->rc);

    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CommitStreams(NORMAL, cameraBase_->ability_);
    CAMERA_LOGE("CommitStreams! rc:0x%x\n", cameraBase_->rc);
    int captureId = 2001;
    CaptureInfo captureInfo = {};
    captureInfo.streamIds_ = {1001};
    captureInfo.captureSetting_ = cameraBase_->ability_;
    captureInfo.enableShutterCallback_ = false;

    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->Capture(captureId, captureInfo, false);
    CAMERA_LOGE("Capture! rc:0x%x\n", cameraBase_->rc);
    sleep(3);
    streamCustomer->ReceiveFrameOff();
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CancelCapture(captureId);
    CAMERA_LOGE("CancelCapture! rc:0x%x\n", cameraBase_->rc);
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->ReleaseStreams(captureInfo.streamIds_);
    CAMERA_LOGE("ReleaseStreams! rc:0x%x\n", cameraBase_->rc);
}

/**
  * @tc.name: Only Still_capture stream
  * @tc.desc: Only Still_capture stream, capture->isStreaming = true.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraCaptureTest, camera_capture_021, TestSize.Level1)
{
    CAMERA_LOGD("Still_capture stream, capture->isStreaming = true.");
    // start stream
    cameraBase_->AchieveStreamOperator();
    std::shared_ptr<StreamCustomer> streamCustomer = std::make_shared<StreamCustomer>();
    OHOS::sptr<OHOS::IBufferProducer> producer = streamCustomer->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferqueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferqueue size
        CAMERA_LOGE("~~~~~~~");
    }
    streamCustomer->ReceiveFrameOn([this](const unsigned char *addr, const uint32_t size) {
        cameraBase_->StoreImage(addr, size);
    });
    std::vector<StreamInfo> streamInfos;
    cameraBase_->streamInfo.streamId_ = 1001;
    cameraBase_->streamInfo.width_ = 1280; // 640:picture width
    cameraBase_->streamInfo.height_ = 960; // 640:picture height
    cameraBase_->streamInfo.format_ = PIXEL_FMT_RGBA_8888;
    cameraBase_->streamInfo.dataspace_ = 8; // 8:picture dataspace
    cameraBase_->streamInfo.intent_ = STILL_CAPTURE;
    cameraBase_->streamInfo.tunneledMode_ = 5; // 5:tunnel mode
    cameraBase_->streamInfo.encodeType_ = ENCODE_TYPE_JPEG;
    cameraBase_->streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    ASSERT_NE(cameraBase_->streamInfo.bufferQueue_, nullptr);
    streamInfos.push_back(cameraBase_->streamInfo);
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CreateStreams(streamInfos);
    CAMERA_LOGE("CreateStreams! rc:0x%x\n", cameraBase_->rc);

    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CommitStreams(NORMAL, cameraBase_->ability_);
    CAMERA_LOGE("CommitStreams! rc:0x%x\n", cameraBase_->rc);
    int captureId = 2001;
    CaptureInfo captureInfo = {};
    captureInfo.streamIds_ = {1001};
    captureInfo.captureSetting_ = cameraBase_->ability_;
    captureInfo.enableShutterCallback_ = false;

    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->Capture(captureId, captureInfo, true);
    CAMERA_LOGE("Capture! rc:0x%x\n", cameraBase_->rc);
    sleep(3);
    streamCustomer->ReceiveFrameOff();
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CancelCapture(captureId);
    CAMERA_LOGE("CancelCapture! rc:0x%x\n", cameraBase_->rc);
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->ReleaseStreams(captureInfo.streamIds_);
    CAMERA_LOGE("ReleaseStreams! rc:0x%x\n", cameraBase_->rc);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("ReleaseStreams success.");
    } else {
        CAMERA_LOGE("ReleaseStreams fail, rc = %{public}d", cameraBase_->rc);
    }
}