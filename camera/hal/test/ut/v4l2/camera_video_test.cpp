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

void CameraVideoTest::SetStreamInfo(StreamInfo &streamInfo, const std::shared_ptr<StreamCustomer> &streamCustomer,
    const int streamId, const StreamIntent intent)
{
    sptr<OHOS::IBufferProducer> producer;
    constexpr uint32_t DATA_SPACE = 8;
    constexpr uint32_t TUNNEL_MODE = 5;
    constexpr uint32_t BUFFER_QUEUE_SIZE = 8;
    constexpr uint32_t WIDTH = 1280;
    constexpr uint32_t HEIGHT = 960;
    if (intent == PREVIEW) {
        streamInfo.width_ = PREVIEW_WIDTH;
        streamInfo.height_ = PREVIEW_HEIGHT;
    } else if (intent == STILL_CAPTURE) {
        streamInfo.width_ = WIDTH;
        streamInfo.height_ = HEIGHT;
        streamInfo.encodeType_ = ENCODE_TYPE_JPEG;
    } else if (intent == VIDEO) {
        streamInfo.width_ = WIDTH;
        streamInfo.height_ = HEIGHT;
        streamInfo.encodeType_ = ENCODE_TYPE_H264;
    }
    streamInfo.format_ = PIXEL_FMT_RGBA_8888;
    streamInfo.streamId_ = streamId;
    streamInfo.dataspace_ = DATA_SPACE;
    streamInfo.intent_ = intent;
    streamInfo.tunneledMode_ = TUNNEL_MODE;
    producer = streamCustomer->CreateProducer();
    streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    streamInfo.bufferQueue_->producer_->SetQueueSize(BUFFER_QUEUE_SIZE);
}

void CameraVideoTest::CreateStream(int streamId, StreamIntent intent)
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
    CamRetCode result = (CamRetCode)display_->streamOperator->CreateStreams(streamInfos_);
    EXPECT_EQ(false, result != HDI::Camera::V1_0::NO_ERROR);
    if (result == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log]CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log]CreateStreams fail, result = " << result << std::endl;
    }
}

void CameraVideoTest::CommitStream()
{
    CamRetCode result = (CamRetCode)display_->streamOperator->CommitStreams(NORMAL, display_->ability_);
    EXPECT_EQ(false, result != HDI::Camera::V1_0::NO_ERROR);
    if (result == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log]CommitStreams success." << std::endl;
    } else {
        std::cout << "==========[test log]CommitStreams fail, result = " << result << std::endl;
    }
}
void CameraVideoTest::StartCapture(
    int streamId, int captureId, bool shutterCallback, bool isStreaming, const CaptureInfo captureInfo)
{
    captureInfo_.streamIds_ = {streamId};
    captureInfo_.captureSetting_ = display_->ability_;
    captureInfo_.enableShutterCallback_ = shutterCallback;
    CamRetCode result;
    if (captureInfo.captureSetting_.size() != 0) {
        result = (CamRetCode)display_->streamOperator->Capture(captureId, captureInfo, isStreaming);
    } else {
        result = (CamRetCode)display_->streamOperator->Capture(captureId, captureInfo_, isStreaming);
    }

    EXPECT_EQ(true, result == HDI::Camera::V1_0::NO_ERROR);
    if (result == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log]check Capture: Capture success, " << captureId << std::endl;
    } else {
        std::cout << "==========[test log]check Capture: Capture fail, result = " << result << captureId << std::endl;
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

void CameraVideoTest::StopStream(std::vector<int> &captureIds, std::vector<int> &streamIds)
{
    constexpr uint32_t TIME_FOR_RECEIVE_FRAME_OFF = 1;
    constexpr uint32_t TIME_FOR_WAIT_IMAGE_PREVIEW = 2;
    sleep(TIME_FOR_WAIT_IMAGE_PREVIEW);
    if (sizeof(captureIds) > 0) {
        for (const auto &captureId : captureIds) {
            if (captureId == display_->CAPTURE_ID_PREVIEW) {
                streamCustomerPreview_->ReceiveFrameOff();
            } else if (captureId == display_->CAPTURE_ID_CAPTURE) {
                streamCustomerSnapshot_->ReceiveFrameOff();
            } else if (captureId == display_->CAPTURE_ID_VIDEO) {
                streamCustomerVideo_->ReceiveFrameOff();
                sleep(TIME_FOR_RECEIVE_FRAME_OFF);
            } else {
                std::cout << "==========[test log]StopStream ignore command. " << std::endl;
            }
        }

        for (auto &captureId : captureIds) {
            CamRetCode result = (CamRetCode)display_->streamOperator->CancelCapture(captureId);
            sleep(TIME_FOR_WAIT_IMAGE_PREVIEW);
            EXPECT_EQ(true, result == HDI::Camera::V1_0::NO_ERROR);
            if (result == HDI::Camera::V1_0::NO_ERROR) {
                std::cout << "==========[test log]check Capture: CancelCapture success," << captureId << std::endl;
            } else {
                std::cout << "==========[test log]check Capture: CancelCapture fail, result = " << result;
                std::cout << "captureId = " << captureId << std::endl;
            }
        }
    }
    sleep(TIME_FOR_RECEIVE_FRAME_OFF);
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
    display_->StartCapture(display_->STREAM_ID_PREVIEW, display_->CAPTURE_ID_PREVIEW, false, true);
    display_->StartCapture(display_->STREAM_ID_VIDEO, display_->CAPTURE_ID_VIDEO, false, true);

    display_->captureIds = {display_->CAPTURE_ID_PREVIEW, display_->CAPTURE_ID_VIDEO};
    display_->streamIds = {display_->STREAM_ID_PREVIEW, display_->STREAM_ID_VIDEO};
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
    display_->StartCapture(display_->STREAM_ID_PREVIEW, display_->CAPTURE_ID_PREVIEW, false, true);
    display_->StartCapture(display_->STREAM_ID_VIDEO, display_->CAPTURE_ID_VIDEO, false, true);
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
    display_->captureIds = {display_->CAPTURE_ID_PREVIEW, display_->CAPTURE_ID_VIDEO};
    display_->streamIds = {display_->STREAM_ID_PREVIEW, display_->STREAM_ID_VIDEO};
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
    display_->StartCapture(display_->STREAM_ID_PREVIEW, display_->CAPTURE_ID_PREVIEW, false, true);
    display_->StartCapture(display_->STREAM_ID_VIDEO, display_->CAPTURE_ID_VIDEO, false, true);
    // release stream
    display_->captureIds = {display_->CAPTURE_ID_PREVIEW, display_->CAPTURE_ID_VIDEO};
    display_->streamIds = {display_->STREAM_ID_PREVIEW, display_->STREAM_ID_VIDEO};
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
    display_->StartCapture(display_->STREAM_ID_PREVIEW, display_->CAPTURE_ID_PREVIEW, false, true);
    display_->StartCapture(display_->STREAM_ID_VIDEO, display_->CAPTURE_ID_VIDEO, false, true);
    // release stream
    display_->captureIds = {display_->CAPTURE_ID_PREVIEW, display_->CAPTURE_ID_VIDEO};
    display_->streamIds = {display_->STREAM_ID_PREVIEW, display_->STREAM_ID_VIDEO};
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
    display_->StartCapture(display_->STREAM_ID_PREVIEW, display_->CAPTURE_ID_PREVIEW, false, true);
    display_->StartCapture(display_->STREAM_ID_VIDEO, display_->CAPTURE_ID_VIDEO, false, true);
    // release stream
    display_->captureIds = {display_->CAPTURE_ID_PREVIEW, display_->CAPTURE_ID_VIDEO};
    display_->streamIds = {display_->STREAM_ID_PREVIEW, display_->STREAM_ID_VIDEO};
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
    display_->StartCapture(display_->STREAM_ID_PREVIEW, display_->CAPTURE_ID_PREVIEW, false, true);
    display_->StartCapture(display_->STREAM_ID_CAPTURE, display_->CAPTURE_ID_CAPTURE, false, true);
    // release stream
    display_->captureIds = {display_->CAPTURE_ID_PREVIEW, display_->CAPTURE_ID_CAPTURE};
    display_->streamIds = {display_->STREAM_ID_PREVIEW, display_->STREAM_ID_CAPTURE};
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
    display_->StartCapture(display_->STREAM_ID_PREVIEW, display_->CAPTURE_ID_PREVIEW, false, true);
    display_->StartCapture(display_->STREAM_ID_VIDEO, display_->CAPTURE_ID_VIDEO, false, true);
    // release stream
    display_->captureIds = {display_->CAPTURE_ID_PREVIEW, display_->CAPTURE_ID_VIDEO};
    display_->streamIds = {display_->STREAM_ID_PREVIEW, display_->STREAM_ID_VIDEO};
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
    display_->StartCapture(display_->STREAM_ID_PREVIEW, display_->CAPTURE_ID_PREVIEW, false, true);
    display_->StartCapture(display_->STREAM_ID_VIDEO, display_->CAPTURE_ID_VIDEO, false, true);
    // release stream
    display_->captureIds = {display_->CAPTURE_ID_PREVIEW, display_->CAPTURE_ID_VIDEO};
    display_->streamIds = {display_->STREAM_ID_PREVIEW, display_->STREAM_ID_VIDEO};
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
        display_->StartCapture(display_->STREAM_ID_PREVIEW, display_->CAPTURE_ID_PREVIEW, false, true);
        // Start capture recording
        display_->StartCapture(display_->STREAM_ID_VIDEO, display_->CAPTURE_ID_VIDEO, false, true);

        // post-processing
        display_->captureIds = {display_->CAPTURE_ID_PREVIEW, display_->CAPTURE_ID_VIDEO};
        display_->streamIds = {display_->STREAM_ID_PREVIEW, display_->STREAM_ID_VIDEO};
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
    display_->StartCapture(display_->STREAM_ID_PREVIEW, display_->CAPTURE_ID_PREVIEW, false, true);
    // Create video stream
    display_->intents = {VIDEO};
    display_->StartStream(display_->intents);
    // Start capture preview
    display_->StartCapture(display_->STREAM_ID_PREVIEW, display_->CAPTURE_ID_PREVIEW, false, true);
    // Start capture recording
    display_->StartCapture(display_->STREAM_ID_VIDEO, display_->CAPTURE_ID_VIDEO, false, true);

    // post-processing
    display_->streamCustomerPreview_->ReceiveFrameOff();
    display_->streamCustomerVideo_->ReceiveFrameOff();
    display_->rc = (CamRetCode)display_->streamOperator->CancelCapture(display_->CAPTURE_ID_VIDEO);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] CancelCapture success, captureId = ";
        std::cout << display_->CAPTURE_ID_VIDEO << std::endl;
    } else {
        std::cout << "==========[test log] CancelCapture fail, rc = " << display_->rc << std::endl;
    }
    display_->rc = (CamRetCode)display_->streamOperator->CancelCapture(display_->CAPTURE_ID_PREVIEW);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] CancelCapture success, captureId = ";
        std::cout << display_->CAPTURE_ID_PREVIEW << std::endl;
    } else {
        std::cout << "==========[test log] CancelCapture fail, rc = " << display_->rc << std::endl;
    }
    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams(
        {display_->STREAM_ID_VIDEO});
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] ReleaseStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] ReleaseStreams fail, rc = " << display_->rc << std::endl;
    }
    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams(
        {display_->STREAM_ID_PREVIEW});
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
    display_->StartCapture(display_->STREAM_ID_PREVIEW, display_->CAPTURE_ID_PREVIEW, false, true);
    display_->StartCapture(display_->STREAM_ID_VIDEO, display_->CAPTURE_ID_VIDEO, false, true);
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
    display_->captureIds = {display_->CAPTURE_ID_PREVIEW, display_->CAPTURE_ID_VIDEO};
    display_->streamIds = {display_->STREAM_ID_PREVIEW, display_->STREAM_ID_VIDEO};
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
    display_->streamInfo.streamId_ = display_->STREAM_ID_VIDEO;
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
        std::cout << display_->STREAM_ID_VIDEO <<", intent = VIDEO" << std::endl;
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

/**
 * @tc.name: preview, still_capture and video
 * @tc.desc: Commit 3 streams in order, Preview, still_capture and video streams.
 * @tc.level: Level1
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraVideoTest, camera_video_031, TestSize.Level1)
{
    display_->AchieveStreamOperator();

    CreateStream(display_->STREAM_ID_PREVIEW, PREVIEW);
    CreateStream(display_->STREAM_ID_CAPTURE, STILL_CAPTURE);
    CreateStream(display_->STREAM_ID_VIDEO, VIDEO);

    CommitStream();

    CaptureInfo captureInfo = {};
    StartCapture(display_->STREAM_ID_PREVIEW, display_->CAPTURE_ID_PREVIEW, false, true, captureInfo);
    StartCapture(display_->STREAM_ID_VIDEO, display_->CAPTURE_ID_VIDEO, false, true, captureInfo);

    constexpr double latitude = 27.987500;  // dummy data: Qomolangma latitde
    constexpr double longitude = 86.927500; // dummy data: Qomolangma longituude
    constexpr double altitude = 8848.86;    // dummy data: Qomolangma altitude

    constexpr size_t entryCapacity = 100;
    constexpr size_t dataCapacity = 2000;
    std::shared_ptr<CameraSetting> captureSetting =
        std::make_shared<CameraSetting>(entryCapacity, dataCapacity);
    std::vector<double> gps;
    gps.push_back(latitude);
    gps.push_back(longitude);
    gps.push_back(altitude);
    captureSetting->addEntry(OHOS_JPEG_GPS_COORDINATES, gps.data(), gps.size());

    captureInfo.streamIds_ = {display_->STREAM_ID_CAPTURE};
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(captureSetting, setting);
    captureInfo.captureSetting_ = setting;
    captureInfo.enableShutterCallback_ = false;
    StartCapture(display_->STREAM_ID_CAPTURE, display_->CAPTURE_ID_CAPTURE, false, true, captureInfo);

    constexpr uint32_t TIME_FOR_WAIT_INIT_CAPTUREIDS = 5;
    sleep(TIME_FOR_WAIT_INIT_CAPTUREIDS);
    std::vector<int> captureIds = {display_->CAPTURE_ID_PREVIEW, display_->CAPTURE_ID_VIDEO,
        display_->CAPTURE_ID_CAPTURE};
    std::vector<int> streamIds = {display_->STREAM_ID_PREVIEW, display_->STREAM_ID_VIDEO, display_->STREAM_ID_CAPTURE};
    StopStream(captureIds, streamIds);
}