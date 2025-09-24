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
    if (display_ == nullptr)
    display_ = std::make_shared<TestDisplay>();
    display_->Init();
}
void CameraCaptureTest::TearDown(void)
{
    display_->Close();
}

/**
  * @tc.name: preview and capture
  * @tc.desc: Commit 2 streams together, Preview and still_capture streams, isStreaming is true.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraCaptureTest, SUB_DriverSystem_CameraHdi_0150, TestSize.Level1)
{
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
  * @tc.name: preview and capture
  * @tc.desc: Preview + capture, then close camera, and preview + capture again.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraCaptureTest, SUB_DriverSystem_CameraHdi_0160, TestSize.Level1)
{
    std::cout << "==========[test log] Preview + capture, then cloase camera,";
    std::cout << "and preview + capture again." << std::endl;
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

    // the 2nd time
    // Configure two streams of information
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
  * @tc.name: preview and capture
  * @tc.desc: Preview + capture with 3A, success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraCaptureTest, SUB_DriverSystem_CameraHdi_0170, TestSize.Level1)
{
    std::cout << "==========[test log] Capture with 3A, success." << std::endl;
    // Get the stream manager
    display_->AchieveStreamOperator();
    // start stream
    display_->intents = {PREVIEW, STILL_CAPTURE};
    display_->StartStream(display_->intents);
    // Get preview
    display_->StartCapture(display_->STREAM_ID_PREVIEW, display_->CAPTURE_ID_PREVIEW, false, true);
    display_->StartCapture(display_->STREAM_ID_CAPTURE, display_->CAPTURE_ID_CAPTURE, false, true);
    // Issue 3A parameters to increase exposure
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 2000);
    int32_t expo = 0xa0;
    meta->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &expo, 1);
    const int32_t deviceStreamId = display_->STREAM_ID_CAPTURE;
    meta->addEntry(OHOS_CAMERA_STREAM_ID, &deviceStreamId, 1);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    display_->rc = (CamRetCode)display_->cameraDevice->UpdateSettings(setting);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] UpdateSettings success, for 10s." << std::endl;
    } else {
        std::cout << "==========[test log] UpdateSettings fail, rc = " << display_->rc << std::endl;
    }
    // release stream
    display_->captureIds = {display_->CAPTURE_ID_PREVIEW, display_->CAPTURE_ID_CAPTURE};
    display_->streamIds = {display_->STREAM_ID_PREVIEW, display_->STREAM_ID_CAPTURE};
    display_->StopStream(display_->captureIds, display_->streamIds);
}

/**
  * @tc.name: preview and capture
  * @tc.desc: Preview + capture, then switch to preview + video.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraCaptureTest, SUB_DriverSystem_CameraHdi_0180, TestSize.Level1)
{
    std::cout << "==========[test log] Preview + capture, then switch to preview + video." << std::endl;
    std::cout << "==========[test log] First, create preview + capture." << std::endl;
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
    sleep(3);

    std::cout << "==========[test log] Next, switch to preview + video." << display_->rc << std::endl;
    // Get the stream manager
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
  * @tc.name: preview and capture
  * @tc.desc: Commit 2 streams together, Preview and still_capture streams, isStreaming is false.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraCaptureTest, SUB_DriverSystem_CameraHdi_0200, TestSize.Level1)
{
    // Get the stream manager
    display_->AchieveStreamOperator();
    // start stream
    display_->intents = {PREVIEW, STILL_CAPTURE};
    display_->StartStream(display_->intents);
    // Get preview
    display_->StartCapture(display_->STREAM_ID_PREVIEW, display_->CAPTURE_ID_PREVIEW, false, true);
    display_->StartCapture(display_->STREAM_ID_CAPTURE, display_->CAPTURE_ID_CAPTURE, false, false);

    sleep(3);
    CAMERA_LOGD("frame off.");
    display_->streamCustomerPreview_->ReceiveFrameOff();
    display_->streamCustomerCapture_->ReceiveFrameOff();

    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams(
        {display_->STREAM_ID_CAPTURE});
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] ReleaseStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] ReleaseStreams fail, rc = ." << display_->rc << std::endl;
    }
    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams(
        {display_->STREAM_ID_PREVIEW});
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] ReleaseStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] ReleaseStreams fail, rc = ." << display_->rc << std::endl;
    }
}

/**
  * @tc.name: preview and capture
  * @tc.desc: Commit 2 streams in order, Preview and still_capture streams.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraCaptureTest, SUB_DriverSystem_CameraHdi_0210, TestSize.Level1)
{
    std::cout << "==========[test log] Preview and still_capture streams." << std::endl;
    // Configure two streams of information
    EXPECT_EQ(true, display_->cameraDevice != nullptr);
    display_->AchieveStreamOperator();
    // Create video stream
    display_->intents = {PREVIEW, STILL_CAPTURE};
    display_->StartStream(display_->intents);
    // Start capture recording
    display_->StartCapture(display_->STREAM_ID_PREVIEW, display_->CAPTURE_ID_PREVIEW, false, true);
    display_->StartCapture(display_->STREAM_ID_CAPTURE, display_->CAPTURE_ID_CAPTURE, false, true);
    sleep(2);

    // post-processing
    display_->streamCustomerPreview_->ReceiveFrameOff();
    display_->streamCustomerCapture_->ReceiveFrameOff();
    display_->rc = (CamRetCode)display_->streamOperator->CancelCapture(display_->CAPTURE_ID_CAPTURE);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] CancelCapture success." << std::endl;
    } else {
        std::cout << "==========[test log] CancelCapture fail, rc = ." << display_->rc << std::endl;
    }
    display_->rc = (CamRetCode)display_->streamOperator->CancelCapture(display_->CAPTURE_ID_PREVIEW);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] CancelCapture success." << std::endl;
    } else {
        std::cout << "==========[test log] CancelCapture fail, rc = ." << display_->rc << std::endl;
    }
    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams(
        {display_->STREAM_ID_CAPTURE});
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] ReleaseStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] ReleaseStreams fail, rc = ." << display_->rc << std::endl;
    }
    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams(
        {display_->STREAM_ID_PREVIEW});
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] ReleaseStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] ReleaseStreams fail, rc = ." << display_->rc << std::endl;
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
    std::cout << "==========[test log] No preview, only still_capture." << std::endl;
    // start stream
    display_->AchieveStreamOperator();
    std::shared_ptr<StreamCustomer> streamCustomer = std::make_shared<StreamCustomer>();
    OHOS::sptr<OHOS::IBufferProducer> producer = streamCustomer->CreateProducer();
    producer->SetQueueSize(8); // buffer queue size
    if (producer->GetQueueSize() != 8) { // buffer queue size
        std::cout << "~~~~~~~" << std::endl;
    }
    streamCustomer->ReceiveFrameOn([this](const unsigned char *addr, const uint32_t size) {
        display_->StoreImage(addr, size);
    });
    std::vector<StreamInfo> streamInfos;
    display_->streamInfo.streamId_ = 1001;
    display_->streamInfo.width_ = 1280; // picture width
    display_->streamInfo.height_ = 960; // picture height
    display_->streamInfo.format_ = PIXEL_FMT_RGBA_8888;
    display_->streamInfo.dataspace_ = 8; // picture dataspace
    display_->streamInfo.intent_ = STILL_CAPTURE;
    display_->streamInfo.tunneledMode_ = 5; // tunnel mode
    display_->streamInfo.encodeType_ = ENCODE_TYPE_JPEG;
    display_->streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    ASSERT_NE(display_->streamInfo.bufferQueue_, nullptr);
    streamInfos.push_back(display_->streamInfo);
    display_->rc = (CamRetCode)display_->streamOperator->CreateStreams(streamInfos);
    CAMERA_LOGE("CreateStreams! rc:0x%x\n", display_->rc);

    display_->rc = (CamRetCode)display_->streamOperator->CommitStreams(NORMAL, display_->ability_);
    CAMERA_LOGE("CommitStreams! rc:0x%x\n", display_->rc);
    int captureId = 2001;
    CaptureInfo captureInfo = {};
    captureInfo.streamIds_ = {1001};
    captureInfo.captureSetting_ = display_->ability_;
    captureInfo.enableShutterCallback_ = false;

    display_->rc = (CamRetCode)display_->streamOperator->Capture(captureId, captureInfo, false);
    CAMERA_LOGE("Capture! rc:0x%x\n", display_->rc);
    sleep(3);
    streamCustomer->ReceiveFrameOff();
    display_->rc = (CamRetCode)display_->streamOperator->CancelCapture(captureId);
    CAMERA_LOGE("CancelCapture! rc:0x%x\n", display_->rc);
    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams(captureInfo.streamIds_);
    CAMERA_LOGE("ReleaseStreams! rc:0x%x\n", display_->rc);
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
    std::cout << "==========[test log] Still_capture stream, capture->isStreaming = true." << std::endl;
    // start stream
    display_->AchieveStreamOperator();
    std::shared_ptr<StreamCustomer> streamCustomer = std::make_shared<StreamCustomer>();
    OHOS::sptr<OHOS::IBufferProducer> producer = streamCustomer->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferqueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferqueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    streamCustomer->ReceiveFrameOn([this](const unsigned char *addr, const uint32_t size) {
        display_->StoreImage(addr, size);
    });
    std::vector<StreamInfo> streamInfos;
    display_->streamInfo.streamId_ = 1001;
    display_->streamInfo.width_ = 1280; // 640:picture width
    display_->streamInfo.height_ = 960; // 640:picture height
    display_->streamInfo.format_ = PIXEL_FMT_RGBA_8888;
    display_->streamInfo.dataspace_ = 8; // 8:picture dataspace
    display_->streamInfo.tunneledMode_ = 5; // 5:tunnel mode
    display_->streamInfo.encodeType_ = ENCODE_TYPE_JPEG;
    display_->streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    ASSERT_NE(display_->streamInfo.bufferQueue_, nullptr);
    streamInfos.push_back(display_->streamInfo);
    display_->rc = (CamRetCode)display_->streamOperator->CreateStreams(streamInfos);
    CAMERA_LOGE("CreateStreams! rc:0x%x\n", display_->rc);

    display_->rc = (CamRetCode)display_->streamOperator->CommitStreams(NORMAL, display_->ability_);
    CAMERA_LOGE("CommitStreams! rc:0x%x\n", display_->rc);
    int captureId = 2001;
    CaptureInfo captureInfo = {};
    captureInfo.streamIds_ = {1001};
    captureInfo.captureSetting_ = display_->ability_;
    captureInfo.enableShutterCallback_ = false;

    display_->rc = (CamRetCode)display_->streamOperator->Capture(captureId, captureInfo, true);
    CAMERA_LOGE("Capture! rc:0x%x\n", display_->rc);
    sleep(3);
    streamCustomer->ReceiveFrameOff();
    display_->rc = (CamRetCode)display_->streamOperator->CancelCapture(captureId);
    CAMERA_LOGE("CancelCapture! rc:0x%x\n", display_->rc);
    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams(captureInfo.streamIds_);
    CAMERA_LOGE("ReleaseStreams! rc:0x%x\n", display_->rc);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] ReleaseStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] ReleaseStreams fail, rc = ." << display_->rc << std::endl;
    }
}

/**
  * @tc.name: RE_CONFIGURED_REQUIRED
  * @tc.desc: RE_CONFIGURED_REQUIRED
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraCaptureTest, Camera_Capture_022, TestSize.Level1)
{
    std::cout << "==========[test log]check Capture: Preview + video, then capture a photo." << std::endl;
    std::cout << "==========[test log]check Capture: First, create Preview + video." << std::endl;
    // Configure two streams of information
    display_->AchieveStreamOperator();
    display_->intents = {PREVIEW, VIDEO};
    display_->StartStream(display_->intents);
    // Capture preview stream
    display_->StartCapture(display_->STREAM_ID_PREVIEW, display_->CAPTURE_ID_PREVIEW, false, true);
    // Capture video stream
    display_->StartCapture(display_->STREAM_ID_VIDEO, display_->CAPTURE_ID_VIDEO, false, true);

    // Start the capture stream
    std::shared_ptr<HDI::Camera::V1_0::StreamInfo> streamInfo_capture =
        std::make_shared<HDI::Camera::V1_0::StreamInfo>();
    streamInfo_capture->streamId_ = display_->STREAM_ID_CAPTURE;
    streamInfo_capture->width_ = 640;
    streamInfo_capture->height_ = 480;
    streamInfo_capture->format_ = PIXEL_FMT_YCRCB_420_SP;
    streamInfo_capture->dataspace_ = 8;
    streamInfo_capture->tunneledMode_ = 5;

    // Query whether the IsStreamsSupported interface supports
    HDI::Camera::V1_0::StreamSupportType pType;
    std::vector<HDI::Camera::V1_0::StreamInfo> stre;
    stre.push_back(*streamInfo_capture);
    display_->rc = (CamRetCode)display_->streamOperator->IsStreamsSupported(HDI::Camera::V1_0::NORMAL,
        display_->ability_, stre, pType);
    EXPECT_EQ(display_->rc, HDI::Camera::V1_0::NO_ERROR);
    std::cout << "ptype = " << pType << std::endl;
    EXPECT_EQ(true, pType == HDI::Camera::V1_0::RE_CONFIGURED_REQUIRED);
    // post-processing
    display_->captureIds = {display_->CAPTURE_ID_PREVIEW, display_->CAPTURE_ID_VIDEO};
    display_->streamIds.push_back(display_->STREAM_ID_PREVIEW);
    display_->streamIds.push_back(display_->STREAM_ID_VIDEO);
    display_->StopStream(display_->captureIds, display_->streamIds);
}