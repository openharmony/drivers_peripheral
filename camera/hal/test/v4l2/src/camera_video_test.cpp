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
#include "camera_video_test.h"

using namespace testing::ext;

void CameraVideoTest::SetUpTestCase(void)
{}
void CameraVideoTest::TearDownTestCase(void)
{}
void CameraVideoTest::SetUp(void)
{
    if (display_ == nullptr)
    display_ = std::make_shared<TestDisplay>();
    display_->Init();
}
void CameraVideoTest::TearDown(void)
{
    display_->Close();
}

/**
  * @tc.name: Video
  * @tc.desc: Preview + video, commit together, success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraVideoTest, camera_video_001, TestSize.Level1)
{
    std::cout << "==========[test log] 1 Preview + video, commit together, success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // start stream
    display_->intents = {PREVIEW, VIDEO};
    display_->StartStream(display_->intents);
    // Get preview
    display_->StartCapture(display_->streamId_preview, display_->captureId_preview, false, true);
    display_->StartCapture(display_->streamId_video, display_->captureId_video, false, true);

    display_->captureIds = {display_->captureId_preview, display_->captureId_video};
    display_->streamIds = {display_->streamId_preview, display_->streamId_video};
    display_->StopStream(display_->captureIds, display_->streamIds);
}

/**
  * @tc.name: Video
  * @tc.desc: Preview + video, commit together, set 3A, success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraVideoTest, camera_video_002, TestSize.Level1)
{
    std::cout << "==========[test log] Preview + video, commit together, set 3A, success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();

    // start stream
    display_->intents = {PREVIEW, VIDEO};
    display_->StartStream(display_->intents);
    // Get preview
    display_->StartCapture(display_->streamId_preview, display_->captureId_preview, false, true);
    display_->StartCapture(display_->streamId_video, display_->captureId_video, false, true);
    // Issue 3A parameters to increase exposure
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 2000);
    int32_t expo = 0xa0;
    meta->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &expo, 1);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    display_->rc = (CamRetCode)display_->cameraDevice->UpdateSettings(setting);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] UpdateSettings success, for 5s." << std::endl;
    } else {
        std::cout << "==========[test log] UpdateSettings fail, rc = " << display_->rc << std::endl;
    }
    sleep(3);

    // release stream
    display_->captureIds = {display_->captureId_preview, display_->captureId_video};
    display_->streamIds = {display_->streamId_preview, display_->streamId_video};
    display_->StopStream(display_->captureIds, display_->streamIds);
}

/**
  * @tc.name: Video
  * @tc.desc: Preview + video, commit together, then close device, and preview + video again.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraVideoTest, camera_video_003, TestSize.Level1)
{
    std::cout << "==========[test log] Preview + video, commit together, then close device,";
    std::cout << "and preview + video again." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // start stream
    display_->intents = {PREVIEW, VIDEO};
    display_->StartStream(display_->intents);
    // Get preview
    display_->StartCapture(display_->streamId_preview, display_->captureId_preview, false, true);
    display_->StartCapture(display_->streamId_video, display_->captureId_video, false, true);
    // release stream
    display_->captureIds = {display_->captureId_preview, display_->captureId_video};
    display_->streamIds = {display_->streamId_preview, display_->streamId_video};
    display_->StopStream(display_->captureIds, display_->streamIds);

    // Turn off the device
    display_->Close();
    // Turn on the device
    display_->Init();
    std::cout << "==========[test log] The 2nd time." << std::endl;

    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // start stream
    display_->intents = {PREVIEW, VIDEO};
    display_->StartStream(display_->intents);
    // Get preview
    display_->StartCapture(display_->streamId_preview, display_->captureId_preview, false, true);
    display_->StartCapture(display_->streamId_video, display_->captureId_video, false, true);
    // release stream
    display_->captureIds = {display_->captureId_preview, display_->captureId_video};
    display_->streamIds = {display_->streamId_preview, display_->streamId_video};
    display_->StopStream(display_->captureIds, display_->streamIds);
}

/**
  * @tc.name: Video
  * @tc.desc: Preview + video, commit together, then close device, and preview + capture.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraVideoTest, camera_video_004, TestSize.Level1)
{
    std::cout << "==========[test log] Preview + video, commit together, then close device,";
    std::cout << "and preview + capture." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // start stream
    display_->intents = {PREVIEW, VIDEO};
    display_->StartStream(display_->intents);
    // Get preview
    display_->StartCapture(display_->streamId_preview, display_->captureId_preview, false, true);
    display_->StartCapture(display_->streamId_video, display_->captureId_video, false, true);
    // release stream
    display_->captureIds = {display_->captureId_preview, display_->captureId_video};
    display_->streamIds = {display_->streamId_preview, display_->streamId_video};
    display_->StopStream(display_->captureIds, display_->streamIds);

    // Turn off the device
    display_->Close();
    std::cout << "==========[test log] cameraDevice->Close" << std::endl;
    // Turn on the device
    display_->Init();

    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // start stream
    display_->intents = {PREVIEW, STILL_CAPTURE};
    display_->StartStream(display_->intents);
    // Get preview
    display_->StartCapture(display_->streamId_preview, display_->captureId_preview, false, true);
    display_->StartCapture(display_->streamId_capture, display_->captureId_capture, false, true);
    // release stream
    display_->captureIds = {display_->captureId_preview, display_->captureId_capture};
    display_->streamIds = {display_->streamId_preview, display_->streamId_capture};
    display_->StopStream(display_->captureIds, display_->streamIds);
}

/**
  * @tc.name: Video
  * @tc.desc: Preview + video, commit together, success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraVideoTest, camera_video_005, TestSize.Level1)
{
    std::cout << "==========[test log] 1 Preview + video, commit together, success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // start stream
    display_->intents = {PREVIEW, VIDEO};
    display_->StartStream(display_->intents);
    // Get preview
    display_->StartCapture(display_->streamId_preview, display_->captureId_preview, false, true);
    display_->StartCapture(display_->streamId_video, display_->captureId_video, false, true);
    // release stream
    display_->captureIds = {display_->captureId_preview, display_->captureId_video};
    display_->streamIds = {display_->streamId_preview, display_->streamId_video};
    display_->StopStream(display_->captureIds, display_->streamIds);
}

/**
  * @tc.name: Video
  * @tc.desc: Video start&stop, for 5 times, success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraVideoTest, camera_video_010, TestSize.Level2)
{
    std::cout << "==========[test log] Video start&stop, for 5 times, success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    for (int i = 0; i < 5; i++) {
    // start stream
    display_->intents = {PREVIEW, VIDEO};
    display_->StartStream(display_->intents);
    // Get preview
    display_->StartCapture(display_->streamId_preview, display_->captureId_preview, false, true);
    display_->StartCapture(display_->streamId_video, display_->captureId_video, false, true);
    // release stream
    display_->captureIds = {display_->captureId_preview, display_->captureId_video};
    display_->streamIds = {display_->streamId_preview, display_->streamId_video};
    display_->StopStream(display_->captureIds, display_->streamIds);
}
}

/**
  * @tc.name: Video
  * @tc.desc: Video start&stop, for 5 times, success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraVideoTest, camera_video_011, TestSize.Level2)
{
    std::cout << "==========[test log] Video start&stop, for 5 times, success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    for (int i = 0; i < 5; i++) {
        // start stream
        display_->intents = {PREVIEW, VIDEO};
        display_->StartStream(display_->intents);

        // Start capture preview
        display_->StartCapture(display_->streamId_preview, display_->captureId_preview, false, true);
        // Start capture recording
        display_->StartCapture(display_->streamId_video, display_->captureId_video, false, true);

        // post-processing
        display_->captureIds = {display_->captureId_preview, display_->captureId_video};
        display_->streamIds = {display_->streamId_preview, display_->streamId_video};
        display_->StopStream(display_->captureIds, display_->streamIds);
    }
}

/**
  * @tc.name: Video
  * @tc.desc: Dynamic Video mode, preview, success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraVideoTest, camera_video_020, TestSize.Level2)
{
    std::cout << "==========[test log] Video mode, preview, success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    display_->intents = {PREVIEW};
    display_->StartStream(display_->intents);
    // capture
    display_->StartCapture(display_->streamId_preview, display_->captureId_preview, false, true);
    // Create video stream
    display_->intents = {VIDEO};
    display_->StartStream(display_->intents);
    // Start capture preview
    display_->StartCapture(display_->streamId_preview, display_->captureId_preview, false, true);
    // Start capture recording
    display_->StartCapture(display_->streamId_video, display_->captureId_video, false, true);

    // post-processing
    display_->streamCustomerPreview_->ReceiveFrameOff();
    display_->streamCustomerVideo_->ReceiveFrameOff();
    display_->rc = (CamRetCode)display_->streamOperator->CancelCapture(display_->captureId_video);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] CancelCapture success, captureId = ";
        std::cout << display_->captureId_video << std::endl;
    } else {
        std::cout << "==========[test log] CancelCapture fail, rc = " << display_->rc << std::endl;
    }
    display_->rc = (CamRetCode)display_->streamOperator->CancelCapture(display_->captureId_preview);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] CancelCapture success, captureId = ";
        std::cout << display_->captureId_preview << std::endl;
    } else {
        std::cout << "==========[test log] CancelCapture fail, rc = " << display_->rc << std::endl;
    }
    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams(
        {display_->streamId_video});
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] ReleaseStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] ReleaseStreams fail, rc = " << display_->rc << std::endl;
    }
    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams(
        {display_->streamId_preview});
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] ReleaseStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] ReleaseStreams fail, rc = " << display_->rc << std::endl;
    }
}

/**
  * @tc.name: Video
  * @tc.desc: Video mode, preview, set 3A, success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraVideoTest, camera_video_021, TestSize.Level1)
{
    std::cout << "==========[test log] Video mode, preview, set 3A, success." << std::endl;
    EXPECT_EQ(true, display_->cameraDevice != nullptr);
    display_->AchieveStreamOperator();
    // start stream
    display_->intents = {PREVIEW, VIDEO};
    display_->StartStream(display_->intents);
    // capture
    display_->StartCapture(display_->streamId_preview, display_->captureId_preview, false, true);
    display_->StartCapture(display_->streamId_video, display_->captureId_video, false, true);
    // Issue 3A parameters to increase exposure
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 2000);
    int32_t expo = 0xa0;
    meta->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &expo, 1);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    display_->rc = (CamRetCode)display_->cameraDevice->UpdateSettings(setting);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] UpdateSettings success, for 5s." << std::endl;
    } else {
        std::cout << "==========[test log] UpdateSettings fail, rc = " << display_->rc << std::endl;
    }
    sleep(3);

    // post-processing
    display_->captureIds = {display_->captureId_preview, display_->captureId_video};
    display_->streamIds = {display_->streamId_preview, display_->streamId_video};
    display_->StopStream(display_->captureIds, display_->streamIds);
}

/**
  * @tc.name: Video
  * @tc.desc: Video mode without preview, system not support, expected return fail.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraVideoTest, camera_video_030, TestSize.Level2)
{
    std::cout << "==========[test log] Video mode without preview, system not support,";
    std::cout << "expected return fail." << std::endl;

    EXPECT_EQ(true, display_->cameraDevice != nullptr);
    display_->AchieveStreamOperator();
    // Create video stream
    std::shared_ptr<StreamCustomer> streamCustomer = std::make_shared<StreamCustomer>();
    OHOS::sptr<OHOS::IBufferProducer> producer = streamCustomer->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }

    std::vector<StreamInfo> streamInfos;
    display_->streamInfo.streamId_ = display_->streamId_video;
    display_->streamInfo.width_ = 1280; // 1280:picture width
    display_->streamInfo.height_ = 960; // 960:picture height
    display_->streamInfo.format_ = PIXEL_FMT_RGBA_8888;
    display_->streamInfo.dataspace_ = 10;
    display_->streamInfo.intent_ = VIDEO;
    display_->streamInfo.tunneledMode_ = 5; // 5:tunnel mode
    display_->streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    streamInfos.push_back(display_->streamInfo);
    display_->rc = (CamRetCode)display_->streamOperator->CreateStreams(streamInfos);
    EXPECT_EQ(false, display_->rc == OHOS::Camera::METHOD_NOT_SUPPORTED);
    if (display_->rc == OHOS::Camera::METHOD_NOT_SUPPORTED) {
        std::cout << "==========[test log] CreateStreams METHOD_NOT_SUPPORTED, streamId = ";
        std::cout << display_->streamId_video <<", intent = VIDEO" << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
    std::vector<uint8_t> modeSetting = {};
    display_->rc = (CamRetCode)display_->streamOperator->CommitStreams(NORMAL, modeSetting);
    EXPECT_EQ(false, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] CommitStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CommitStreams fail, rc = ." << display_->rc << std::endl;
    }
}