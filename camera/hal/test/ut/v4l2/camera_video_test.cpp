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
        CAMERA_LOGI("CreateStreams success.");
    } else {
        CAMERA_LOGE("CreateStreams fail, result = %{public}d", result);
    }
}

void CameraVideoTest::CommitStream()
{
    CamRetCode result = (CamRetCode)display_->streamOperator->CommitStreams(NORMAL, display_->ability_);
    EXPECT_EQ(false, result != HDI::Camera::V1_0::NO_ERROR);
    if (result == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("CommitStreams success.");
    } else {
        CAMERA_LOGE("CommitStreams fail, result = %{public}d", result);
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
        CAMERA_LOGI("check Capture: Capture success, captureId = %{public}d", captureId);
    } else {
        CAMERA_LOGE("check Capture: Capture fail, captureId = %{public}d, result = %{public}d", captureId, result);
    }

    if (captureId == display_->CAPTURE_ID_PREVIEW) {
        streamCustomerPreview_->ReceiveFrameOn([this](const unsigned char *addr, const uint32_t size) {
            CAMERA_LOGI("preview size = %{public}u", size);
        });
    } else if (captureId == display_->CAPTURE_ID_CAPTURE) {
        streamCustomerSnapshot_->ReceiveFrameOn([this](const unsigned char *addr, const uint32_t size) {
            CAMERA_LOGI("snapshot size = %{public}u", size);
        });
    } else if (captureId == display_->CAPTURE_ID_VIDEO) {
        streamCustomerVideo_->ReceiveFrameOn([this](const unsigned char *addr, const uint32_t size) {
            CAMERA_LOGI("video size = %{public}u", size);
        });
    } else {
        CAMERA_LOGE("StartCapture ignore command");
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
                CAMERA_LOGE("StopStream ignore command.");
            }
        }

        for (auto &captureId : captureIds) {
            CamRetCode result = (CamRetCode)display_->streamOperator->CancelCapture(captureId);
            sleep(TIME_FOR_WAIT_IMAGE_PREVIEW);
            EXPECT_EQ(true, result == HDI::Camera::V1_0::NO_ERROR);
            if (result == HDI::Camera::V1_0::NO_ERROR) {
                CAMERA_LOGI("check Capture: CancelCapture success, captureId = %{public}d", captureId);
            } else {
                CAMERA_LOGE("check Capture: CancelCapture fail, captureId = %{public}d, result = %{public}d",
                    captureId, result);
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
    CAMERA_LOGD("Preview + video, commit together, success.");
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
    CAMERA_LOGD("Preview + video, commit together, set 3A, success.");
    // Create and get streamOperator information
    display_->AchieveStreamOperator();

    std::vector<int32_t> resultsList;
    resultsList.push_back(OHOS_CAMERA_STREAM_ID);
    resultsList.push_back(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION);
    display_->cameraDevice->EnableResult(resultsList);

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
    const int32_t deviceStreamId = 0;
    meta->addEntry(OHOS_CAMERA_STREAM_ID, &deviceStreamId, 1);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    display_->rc = (CamRetCode)display_->cameraDevice->UpdateSettings(setting);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("UpdateSettings success, for 5s.");
    } else {
        CAMERA_LOGE("UpdateSettings fail, rc = %{public}d", display_->rc);
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
    CAMERA_LOGD("Preview + video, commit together, then close device, and preview + video again.");
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
    CAMERA_LOGD("The 2nd time.");

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
    CAMERA_LOGD("Preview + video, commit together, then close device, and preview + capture.");
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
    CAMERA_LOGD("cameraDevice->Close");
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
    CAMERA_LOGD("Preview + video, commit together, success.");
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
    CAMERA_LOGD("Video start&stop, for 5 times, success.");
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
    CAMERA_LOGD("Video start&stop, for 5 times, success.");
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
    CAMERA_LOGD("Video mode, preview, success.");
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
        CAMERA_LOGI("CancelCapture success, captureId = %{public}d", display_->CAPTURE_ID_VIDEO);
    } else {
        CAMERA_LOGE("CancelCapture fail, rc = %{public}d", display_->rc);
    }
    display_->rc = (CamRetCode)display_->streamOperator->CancelCapture(display_->CAPTURE_ID_PREVIEW);
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("CancelCapture success, captureId = %{public}d", display_->CAPTURE_ID_PREVIEW);
    } else {
        CAMERA_LOGE("CancelCapture fail, rc = %{public}d", display_->rc);
    }
    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams(
        {display_->STREAM_ID_VIDEO});
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("ReleaseStreams success.");
    } else {
        CAMERA_LOGE("ReleaseStreams fail, rc = %{public}d", display_->rc);
    }
    display_->rc = (CamRetCode)display_->streamOperator->ReleaseStreams(
        {display_->STREAM_ID_PREVIEW});
    EXPECT_EQ(true, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("ReleaseStreams success.");
    } else {
        CAMERA_LOGE("ReleaseStreams fail, rc = %{public}d", display_->rc);
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
    CAMERA_LOGD("Video mode, preview, set 3A, success.");
    EXPECT_EQ(true, display_->cameraDevice != nullptr);
    display_->AchieveStreamOperator();

    std::vector<int32_t> resultsList;
    resultsList.push_back(OHOS_CAMERA_STREAM_ID);
    resultsList.push_back(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION);
    display_->cameraDevice->EnableResult(resultsList);
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
    const int32_t deviceStreamId = 0;
    meta->addEntry(OHOS_CAMERA_STREAM_ID, &deviceStreamId, 1);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    display_->rc = (CamRetCode)display_->cameraDevice->UpdateSettings(setting);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("UpdateSettings success, for 5s.");
    } else {
        CAMERA_LOGE("UpdateSettings fail, rc = %{public}d", display_->rc);
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
    CAMERA_LOGD("Video mode without preview, system not support, expected return fail.");

    EXPECT_EQ(true, display_->cameraDevice != nullptr);
    display_->AchieveStreamOperator();
    // Create video stream
    std::shared_ptr<StreamCustomer> streamCustomer = std::make_shared<StreamCustomer>();
    OHOS::sptr<OHOS::IBufferProducer> producer = streamCustomer->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        CAMERA_LOGE("~~~~~~~");
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
        CAMERA_LOGI("CreateStreams METHOD_NOT_SUPPORTED, streamId = %{public}d", display_->STREAM_ID_VIDEO);
    } else {
        CAMERA_LOGE("CreateStreams fail, rc = %{public}d", display_->rc);
    }
    std::vector<uint8_t> modeSetting = {};
    display_->rc = (CamRetCode)display_->streamOperator->CommitStreams(NORMAL, modeSetting);
    EXPECT_EQ(false, display_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (display_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("CommitStreams success.");
    } else {
        CAMERA_LOGE("CommitStreams fail, rc = %{public}d", display_->rc);
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