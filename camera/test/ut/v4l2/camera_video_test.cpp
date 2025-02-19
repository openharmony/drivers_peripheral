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
    if (cameraBase_ == nullptr)
    cameraBase_ = std::make_shared<TestCameraBase>();
    cameraBase_->Init();
}
void CameraVideoTest::TearDown(void)
{
    cameraBase_->Close();
}

void CameraVideoTest::SetStreamInfo(StreamInfo &streamInfo, const std::shared_ptr<StreamCustomer> &streamCustomer,
    const int streamId, const StreamIntent intent)
{
    sptr<OHOS::IBufferProducer> producer;
    constexpr uint32_t dataSpace = 8;
    constexpr uint32_t tunnelMode = 5;
    constexpr uint32_t bufferQueueSize = 8;
    constexpr uint32_t width = 1280;
    constexpr uint32_t height = 960;
    if (intent == PREVIEW) {
        streamInfo.width_ = PREVIEW_WIDTH;
        streamInfo.height_ = PREVIEW_HEIGHT;
    } else if (intent == STILL_CAPTURE) {
        streamInfo.width_ = width;
        streamInfo.height_ = height;
        streamInfo.encodeType_ = ENCODE_TYPE_JPEG;
    } else if (intent == VIDEO) {
        streamInfo.width_ = width;
        streamInfo.height_ = height;
        streamInfo.encodeType_ = ENCODE_TYPE_H264;
    }
    streamInfo.format_ = PIXEL_FMT_RGBA_8888;
    streamInfo.streamId_ = streamId;
    streamInfo.dataspace_ = dataSpace;
    streamInfo.intent_ = intent;
    streamInfo.tunneledMode_ = tunnelMode;
    producer = streamCustomer->CreateProducer();
    streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    ASSERT_NE(streamInfo.bufferQueue_, nullptr);
    streamInfo.bufferQueue_->producer_->SetQueueSize(bufferQueueSize);
}

void CameraVideoTest::CreateStream(int streamId, StreamIntent intent)
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
    CamRetCode result = (CamRetCode)cameraBase_->streamOperator->CreateStreams(streamInfos_);
    EXPECT_EQ(false, result != HDI::Camera::V1_0::NO_ERROR);
    if (result == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("CreateStreams success.");
    } else {
        CAMERA_LOGE("CreateStreams fail, result = %{public}d", result);
    }
}

void CameraVideoTest::CommitStream()
{
    CamRetCode result = (CamRetCode)cameraBase_->streamOperator->CommitStreams(NORMAL, cameraBase_->ability_);
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
    captureInfo_.captureSetting_ = cameraBase_->ability_;
    captureInfo_.enableShutterCallback_ = shutterCallback;
    CamRetCode result;
    if (captureInfo.captureSetting_.size() != 0) {
        result = (CamRetCode)cameraBase_->streamOperator->Capture(captureId, captureInfo, isStreaming);
    } else {
        result = (CamRetCode)cameraBase_->streamOperator->Capture(captureId, captureInfo_, isStreaming);
    }

    EXPECT_EQ(true, result == HDI::Camera::V1_0::NO_ERROR);
    if (result == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("check Capture: Capture success, captureId = %{public}d", captureId);
    } else {
        CAMERA_LOGE("check Capture: Capture fail, captureId = %{public}d, result = %{public}d", captureId, result);
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
        CAMERA_LOGE("StartCapture ignore command");
    }
}

void CameraVideoTest::StopStream(std::vector<int> &captureIds, std::vector<int> &streamIds)
{
    constexpr uint32_t timeForReceiveFrameOff = 1;
    constexpr uint32_t timeForWaitImagePreview = 2;
    sleep(timeForWaitImagePreview);
    if (captureIds.size() > 0) {
        for (const auto &captureId : captureIds) {
            if (captureId == cameraBase_->CAPTURE_ID_PREVIEW) {
                streamCustomerPreview_->ReceiveFrameOff();
            } else if (captureId == cameraBase_->CAPTURE_ID_CAPTURE) {
                streamCustomerSnapshot_->ReceiveFrameOff();
            } else if (captureId == cameraBase_->CAPTURE_ID_VIDEO) {
                streamCustomerVideo_->ReceiveFrameOff();
                sleep(timeForReceiveFrameOff);
            } else {
                CAMERA_LOGE("StopStream ignore command.");
            }
        }

        for (auto &captureId : captureIds) {
            CamRetCode result = (CamRetCode)cameraBase_->streamOperator->CancelCapture(captureId);
            sleep(timeForWaitImagePreview);
            EXPECT_EQ(true, result == HDI::Camera::V1_0::NO_ERROR);
            if (result == HDI::Camera::V1_0::NO_ERROR) {
                CAMERA_LOGI("check Capture: CancelCapture success, captureId = %{public}d", captureId);
            } else {
                CAMERA_LOGE("check Capture: CancelCapture fail, captureId = %{public}d, result = %{public}d",
                    captureId, result);
            }
        }
    }
    sleep(timeForReceiveFrameOff);
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
    cameraBase_->AchieveStreamOperator();
    // start stream
    cameraBase_->intents = {PREVIEW, VIDEO};
    cameraBase_->StartStream(cameraBase_->intents);
    // Get preview
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true);
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_VIDEO, cameraBase_->CAPTURE_ID_VIDEO, false, true);

    cameraBase_->captureIds = {cameraBase_->CAPTURE_ID_PREVIEW, cameraBase_->CAPTURE_ID_VIDEO};
    cameraBase_->streamIds = {cameraBase_->STREAM_ID_PREVIEW, cameraBase_->STREAM_ID_VIDEO};
    cameraBase_->StopStream(cameraBase_->captureIds, cameraBase_->streamIds);
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
    cameraBase_->AchieveStreamOperator();

    std::vector<int32_t> resultsList;
    resultsList.push_back(OHOS_CAMERA_STREAM_ID);
    resultsList.push_back(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION);
    cameraBase_->cameraDevice->EnableResult(resultsList);

    // start stream
    cameraBase_->intents = {PREVIEW, VIDEO};
    cameraBase_->StartStream(cameraBase_->intents);
    // Get preview
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true);
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_VIDEO, cameraBase_->CAPTURE_ID_VIDEO, false, true);
    // Issue 3A parameters to increase exposure
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 2000);
    int32_t expo = 0xa0;
    meta->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &expo, 1);
    const int32_t deviceStreamId = 0;
    meta->addEntry(OHOS_CAMERA_STREAM_ID, &deviceStreamId, 1);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraBase_->rc = (CamRetCode)cameraBase_->cameraDevice->UpdateSettings(setting);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("UpdateSettings success, for 5s.");
    } else {
        CAMERA_LOGE("UpdateSettings fail, rc = %{public}d", cameraBase_->rc);
    }
    sleep(3);

    // release stream
    cameraBase_->captureIds = {cameraBase_->CAPTURE_ID_PREVIEW, cameraBase_->CAPTURE_ID_VIDEO};
    cameraBase_->streamIds = {cameraBase_->STREAM_ID_PREVIEW, cameraBase_->STREAM_ID_VIDEO};
    cameraBase_->StopStream(cameraBase_->captureIds, cameraBase_->streamIds);
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

    // Turn off the device
    cameraBase_->Close();
    // Turn on the device
    cameraBase_->Init();
    CAMERA_LOGD("The 2nd time.");

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

    // Turn off the device
    cameraBase_->Close();
    CAMERA_LOGD("cameraDevice->Close");
    // Turn on the device
    cameraBase_->Init();

    // Create and get streamOperator information
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
    cameraBase_->AchieveStreamOperator();
    for (int i = 0; i < 5; i++) {
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
    cameraBase_->AchieveStreamOperator();
    for (int i = 0; i < 5; i++) {
        // start stream
        cameraBase_->intents = {PREVIEW, VIDEO};
        cameraBase_->StartStream(cameraBase_->intents);

        // Start capture preview
        cameraBase_->StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true);
        // Start capture recording
        cameraBase_->StartCapture(cameraBase_->STREAM_ID_VIDEO, cameraBase_->CAPTURE_ID_VIDEO, false, true);

        // post-processing
        cameraBase_->captureIds = {cameraBase_->CAPTURE_ID_PREVIEW, cameraBase_->CAPTURE_ID_VIDEO};
        cameraBase_->streamIds = {cameraBase_->STREAM_ID_PREVIEW, cameraBase_->STREAM_ID_VIDEO};
        cameraBase_->StopStream(cameraBase_->captureIds, cameraBase_->streamIds);
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
    cameraBase_->AchieveStreamOperator();
    // Create video stream
    cameraBase_->intents = {PREVIEW, VIDEO};
    cameraBase_->StartStream(cameraBase_->intents);
    // Start capture recording
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true);
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_VIDEO, cameraBase_->CAPTURE_ID_VIDEO, false, true);

    // post-processing
    cameraBase_->streamCustomerPreview_->ReceiveFrameOff();
    cameraBase_->streamCustomerVideo_->ReceiveFrameOff();
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CancelCapture(cameraBase_->CAPTURE_ID_VIDEO);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("CancelCapture success, captureId = %{public}d", cameraBase_->CAPTURE_ID_VIDEO);
    } else {
        CAMERA_LOGE("CancelCapture fail, rc = %{public}d", cameraBase_->rc);
    }
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CancelCapture(cameraBase_->CAPTURE_ID_PREVIEW);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("CancelCapture success, captureId = %{public}d", cameraBase_->CAPTURE_ID_PREVIEW);
    } else {
        CAMERA_LOGE("CancelCapture fail, rc = %{public}d", cameraBase_->rc);
    }
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->ReleaseStreams(
        {cameraBase_->STREAM_ID_VIDEO});
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
  * @tc.name: Video
  * @tc.desc: Video mode, preview, set 3A, success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraVideoTest, camera_video_021, TestSize.Level1)
{
    CAMERA_LOGD("Video mode, preview, set 3A, success.");
    EXPECT_EQ(true, cameraBase_->cameraDevice != nullptr);
    cameraBase_->AchieveStreamOperator();

    std::vector<int32_t> resultsList;
    resultsList.push_back(OHOS_CAMERA_STREAM_ID);
    resultsList.push_back(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION);
    cameraBase_->cameraDevice->EnableResult(resultsList);
    // start stream
    cameraBase_->intents = {PREVIEW, VIDEO};
    cameraBase_->StartStream(cameraBase_->intents);
    // capture
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true);
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_VIDEO, cameraBase_->CAPTURE_ID_VIDEO, false, true);
    // Issue 3A parameters to increase exposure
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 2000);
    int32_t expo = 0xa0;
    meta->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &expo, 1);
    const int32_t deviceStreamId = 0;
    meta->addEntry(OHOS_CAMERA_STREAM_ID, &deviceStreamId, 1);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraBase_->rc = (CamRetCode)cameraBase_->cameraDevice->UpdateSettings(setting);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("UpdateSettings success, for 5s.");
    } else {
        CAMERA_LOGE("UpdateSettings fail, rc = %{public}d", cameraBase_->rc);
    }
    sleep(3);

    // post-processing
    cameraBase_->captureIds = {cameraBase_->CAPTURE_ID_PREVIEW, cameraBase_->CAPTURE_ID_VIDEO};
    cameraBase_->streamIds = {cameraBase_->STREAM_ID_PREVIEW, cameraBase_->STREAM_ID_VIDEO};
    cameraBase_->StopStream(cameraBase_->captureIds, cameraBase_->streamIds);
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

    EXPECT_EQ(true, cameraBase_->cameraDevice != nullptr);
    cameraBase_->AchieveStreamOperator();
    // Create video stream
    std::shared_ptr<StreamCustomer> streamCustomer = std::make_shared<StreamCustomer>();
    OHOS::sptr<OHOS::IBufferProducer> producer = streamCustomer->CreateProducer();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        CAMERA_LOGE("~~~~~~~");
    }

    std::vector<StreamInfo> streamInfos;
    cameraBase_->streamInfo.streamId_ = cameraBase_->STREAM_ID_VIDEO;
    cameraBase_->streamInfo.width_ = 1280; // 1280:picture width
    cameraBase_->streamInfo.height_ = 960; // 960:picture height
    cameraBase_->streamInfo.format_ = PIXEL_FMT_RGBA_8888;
    cameraBase_->streamInfo.dataspace_ = 10;
    cameraBase_->streamInfo.intent_ = VIDEO;
    cameraBase_->streamInfo.tunneledMode_ = 5; // 5:tunnel mode
    cameraBase_->streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    ASSERT_NE(cameraBase_->streamInfo.bufferQueue_, nullptr);
    streamInfos.push_back(cameraBase_->streamInfo);
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CreateStreams(streamInfos);
    EXPECT_EQ(false, cameraBase_->rc == OHOS::Camera::METHOD_NOT_SUPPORTED);
    if (cameraBase_->rc == OHOS::Camera::METHOD_NOT_SUPPORTED) {
        CAMERA_LOGI("CreateStreams METHOD_NOT_SUPPORTED, streamId = %{public}d", cameraBase_->STREAM_ID_VIDEO);
    } else {
        CAMERA_LOGE("CreateStreams fail, rc = %{public}d", cameraBase_->rc);
    }
    std::vector<uint8_t> modeSetting = {};
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->CommitStreams(NORMAL, modeSetting);
    EXPECT_EQ(false, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("CommitStreams success.");
    } else {
        CAMERA_LOGE("CommitStreams fail, rc = %{public}d", cameraBase_->rc);
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
    cameraBase_->AchieveStreamOperator();

    CreateStream(cameraBase_->STREAM_ID_PREVIEW, PREVIEW);
    CreateStream(cameraBase_->STREAM_ID_CAPTURE, STILL_CAPTURE);
    CreateStream(cameraBase_->STREAM_ID_VIDEO, VIDEO);

    CommitStream();

    CaptureInfo captureInfo = {};
    StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true, captureInfo);
    StartCapture(cameraBase_->STREAM_ID_VIDEO, cameraBase_->CAPTURE_ID_VIDEO, false, true, captureInfo);

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

    captureInfo.streamIds_ = {cameraBase_->STREAM_ID_CAPTURE};
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(captureSetting, setting);
    captureInfo.captureSetting_ = setting;
    captureInfo.enableShutterCallback_ = false;
    StartCapture(cameraBase_->STREAM_ID_CAPTURE, cameraBase_->CAPTURE_ID_CAPTURE, false, true, captureInfo);

    constexpr uint32_t timeForWaitInitCaptureIds = 5;
    sleep(timeForWaitInitCaptureIds);
    std::vector<int> captureIds = {cameraBase_->CAPTURE_ID_PREVIEW, cameraBase_->CAPTURE_ID_VIDEO,
        cameraBase_->CAPTURE_ID_CAPTURE};
    std::vector<int> streamIds = {cameraBase_->STREAM_ID_PREVIEW, cameraBase_->STREAM_ID_VIDEO,
        cameraBase_->STREAM_ID_CAPTURE};
    StopStream(captureIds, streamIds);
}