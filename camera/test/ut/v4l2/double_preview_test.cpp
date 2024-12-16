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
#include "double_preview_test.h"

using namespace testing::ext;
constexpr uint32_t TIME_FOR_WAIT_CANCEL_CAPTURE = 2;

void DoublePreviewTest::SetUpTestCase(void)
{}
void DoublePreviewTest::TearDownTestCase(void)
{}
void DoublePreviewTest::SetUp(void)
{
    if (cameraBase_ == nullptr) {
        cameraBase_ = std::make_shared<TestCameraBase>();
    }
    cameraBase_->Init();
}
void DoublePreviewTest::TearDown(void)
{
    cameraBase_->Close();
}

void DoublePreviewTest::SetStreamInfo(StreamInfo &streamInfo,
    const std::shared_ptr<StreamCustomer> &streamCustomer,
    const int streamId, const StreamIntent intent)
{
    sptr<OHOS::IBufferProducer> producer;
    constexpr uint32_t dataSpace = 8; // picture dataspace
    constexpr uint32_t tunnelMode = 5; // tunnel mode
    constexpr uint32_t bufferQueueSize = 8; // set bufferQueue size
    if (intent == PREVIEW) {
        streamInfo.width_ = PREVIEW_WIDTH;
        streamInfo.height_ = PREVIEW_HEIGHT;
        streamInfo.format_ = PIXEL_FMT_RGBA_8888;
    }
    streamInfo.streamId_ = streamId;
    streamInfo.dataspace_ = dataSpace;
    streamInfo.intent_ = intent;
    streamInfo.tunneledMode_ = tunnelMode;
    producer = streamCustomer->CreateProducer();
    streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    ASSERT_NE(streamInfo.bufferQueue_, nullptr);
    streamInfo.bufferQueue_->producer_->SetQueueSize(bufferQueueSize);
}

void DoublePreviewTest::CreateStream(int streamId, StreamIntent intent)
{
    StreamInfo streamInfo = {};

    if (intent == PREVIEW) {
        if (streamId == cameraBase_->STREAM_ID_PREVIEW) {
            if (streamCustomerPreview_ == nullptr) {
                    streamCustomerPreview_ = std::make_shared<StreamCustomer>();
                    SetStreamInfo(streamInfo, streamCustomerPreview_, streamId, intent);
                    std::vector<StreamInfo>().swap(streamInfos_);
                    streamInfos_.push_back(streamInfo);
                }
        } else if (streamId == STREAMID_PREVIEW_DOUBLE) {
            if (streamCustomerPreviewDouble_ == nullptr) {
                streamCustomerPreviewDouble_ = std::make_shared<StreamCustomer>();
                SetStreamInfo(streamInfo, streamCustomerPreviewDouble_, streamId, intent);
                std::vector<StreamInfo>().swap(streamInfos_);
                streamInfos_.push_back(streamInfo);
            }
        }
    }
    result_ = (CamRetCode)cameraBase_->streamOperator->CreateStreams(streamInfos_);
    EXPECT_EQ(result_, HDI::Camera::V1_0::NO_ERROR);
    if (result_ == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("CreateStreams success.");
    } else {
        CAMERA_LOGE("CreateStreams fail, result_ = %{public}d", result_);
    }
}

void DoublePreviewTest::CommitStream()
{
    result_ = (CamRetCode)cameraBase_->streamOperator->CommitStreams(NORMAL, cameraBase_->ability_);
    EXPECT_EQ(result_, HDI::Camera::V1_0::NO_ERROR);
    if (result_ == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("CommitStreams preview success.");
    } else {
        CAMERA_LOGE("CommitStreams preview  fail, result_ = %{public}d", result_);
    }
}

void DoublePreviewTest::StartCapture(int streamId, int captureId, bool shutterCallback, bool isStreaming)
{
    captureInfo_.streamIds_ = {streamId};
    captureInfo_.captureSetting_ = cameraBase_->ability_;
    captureInfo_.enableShutterCallback_ = shutterCallback;
    constexpr uint32_t timeForWaitImagePreview = 2; // sleep two second
    result_ = (CamRetCode)cameraBase_->streamOperator->Capture(captureId, captureInfo_, isStreaming);
    EXPECT_EQ(result_, HDI::Camera::V1_0::NO_ERROR);
    if (result_ == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("check Capture: Capture success, captureId = %{public}d", captureId);
    } else {
        CAMERA_LOGE("check Capture: Capture fail, captureId = %{public}d, result_ = %{public}d", captureId, result_);
    }
    if (captureId == cameraBase_->CAPTURE_ID_PREVIEW) {
        streamCustomerPreview_->ReceiveFrameOn([this](const unsigned char *addr, const uint32_t size) {
            CAMERA_LOGI("preview size = %{public}u", size);
        });
    } else if (captureId == CAPTUREID_PREVIEW_DOUBLE) {
        streamCustomerPreviewDouble_->ReceiveFrameOn([this](const unsigned char *addr, const uint32_t size) {
            CAMERA_LOGI("preview double size = %{public}u", size);
        });
    } else {
        CAMERA_LOGE("StartCapture ignore command");
    }
    sleep(timeForWaitImagePreview);
}

void DoublePreviewTest::StopStream(std::vector<int> &captureIds, std::vector<int> &streamIds)
{
    sleep(TIME_FOR_WAIT_CANCEL_CAPTURE);
    if (captureIds.size() == 0) {
        return;
    }
    for (const auto &captureId : captureIds) {
        if (captureId == cameraBase_->CAPTURE_ID_PREVIEW) {
            streamCustomerPreview_->ReceiveFrameOff();
        } else if (captureId == CAPTUREID_PREVIEW_DOUBLE) {
            streamCustomerPreviewDouble_->ReceiveFrameOff();
        }  else if (captureId == cameraBase_->CAPTURE_ID_CAPTURE) {
            cameraBase_->streamCustomerCapture_->ReceiveFrameOff();
        } else if (captureId == cameraBase_->CAPTURE_ID_VIDEO) {
            cameraBase_->streamCustomerVideo_->ReceiveFrameOff();
            sleep(TIME_FOR_WAIT_CANCEL_CAPTURE);
            cameraBase_->CloseFd();
        } else {
            CAMERA_LOGE("StopStream ignore command.");
        }
    }
    for (auto &captureId : captureIds) {
        result_ = (CamRetCode)cameraBase_->streamOperator->CancelCapture(captureId);
        sleep(TIME_FOR_WAIT_CANCEL_CAPTURE);
        EXPECT_EQ(result_, HDI::Camera::V1_0::NO_ERROR);
        if (result_ == HDI::Camera::V1_0::NO_ERROR) {
            CAMERA_LOGI("check Capture: CancelCapture success, captureId = %{public}d", captureId);
        } else {
            CAMERA_LOGE("check Capture: CancelCapture fail, captureId = %{public}d, result_ = %{public}d",
                captureId, result_);
        }
    }
}

/**
  * @tc.name: double preview
  * @tc.desc: Commit 2 streams together, Double preview streams, isStreaming is true.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
static HWTEST_F(DoublePreviewTest, double_preview_001, TestSize.Level1)
{
    // Get the stream manager
    cameraBase_->AchieveStreamOperator();

    // Start stream
    CreateStream(cameraBase_->STREAM_ID_PREVIEW, PREVIEW);
    CreateStream(STREAMID_PREVIEW_DOUBLE, PREVIEW);

    // Commit stream
    CommitStream();

    // Get preview
    StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true);
    StartCapture(STREAMID_PREVIEW_DOUBLE, CAPTUREID_PREVIEW_DOUBLE, false, true);

    constexpr uint32_t timeForWaitImagePreview = 10; // sleep ten second
    sleep(timeForWaitImagePreview);

    std::vector<int> captureIds = {cameraBase_->CAPTURE_ID_PREVIEW, CAPTUREID_PREVIEW_DOUBLE};
    std::vector<int> streamIds = {cameraBase_->STREAM_ID_PREVIEW, STREAMID_PREVIEW_DOUBLE};
    StopStream(captureIds, streamIds);
}

/**
  * @tc.name: double preview and still_capture
  * @tc.desc: Commit 3 streams together, Double preview and still_capture streams, isStreaming is true.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
static HWTEST_F(DoublePreviewTest, double_preview_002, TestSize.Level1)
{
    // Get the stream manager
    cameraBase_->AchieveStreamOperator();

    // Start stream
    CreateStream(cameraBase_->STREAM_ID_PREVIEW, PREVIEW);
    CreateStream(STREAMID_PREVIEW_DOUBLE, PREVIEW);
    cameraBase_->intents = {STILL_CAPTURE};
    cameraBase_->StartStream(cameraBase_->intents);

    // Get preview
    StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true);
    StartCapture(STREAMID_PREVIEW_DOUBLE, CAPTUREID_PREVIEW_DOUBLE, false, true);
    // add dumy exif info
    constexpr double latitude = 27.987500; // dummy data: Qomolangma latitde
    constexpr double longitude = 86.927500; // dummy data: Qomolangma longituude
    constexpr double altitude = 8848.86; // dummy data: Qomolangma altitude
    constexpr size_t entryCapacity = 100;
    constexpr size_t dataCapacity = 2000;
    std::shared_ptr<CameraSetting>  captureSetting =
        std::make_shared<CameraSetting>(entryCapacity, dataCapacity);
    std::vector<double> gps;
    gps.push_back(latitude);
    gps.push_back(longitude);
    gps.push_back(altitude);
    captureSetting->addEntry(OHOS_JPEG_GPS_COORDINATES, gps.data(), gps.size());
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(captureSetting, setting);

    CaptureInfo captureInfo = {};
    captureInfo.streamIds_ = {cameraBase_->STREAM_ID_CAPTURE};
    captureInfo.captureSetting_ = setting;
    captureInfo.enableShutterCallback_ = false;
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->Capture(cameraBase_->CAPTURE_ID_CAPTURE,
        captureInfo, true);
    EXPECT_EQ(cameraBase_->rc, HDI::Camera::V1_0::NO_ERROR);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("check Capture: Capture success, captureId = %{public}d", cameraBase_->CAPTURE_ID_CAPTURE);
    } else {
        CAMERA_LOGE("check Capture: Capture fail, captureId = %{public}d, rc = %{public}d",
            cameraBase_->CAPTURE_ID_CAPTURE, cameraBase_->rc);
    }
    cameraBase_->streamCustomerCapture_->ReceiveFrameOn([this](const unsigned char *addr, const uint32_t size) {
        cameraBase_->StoreImage(addr, size);
    });

    constexpr uint32_t timeForWaitImagePreview = 5; // sleep five second
    sleep(timeForWaitImagePreview);

    std::vector<int> captureIds = {cameraBase_->CAPTURE_ID_PREVIEW, CAPTUREID_PREVIEW_DOUBLE,
        cameraBase_->CAPTURE_ID_CAPTURE};
    std::vector<int> streamIds = {cameraBase_->STREAM_ID_PREVIEW, STREAMID_PREVIEW_DOUBLE,
        cameraBase_->STREAM_ID_CAPTURE};
    StopStream(captureIds, streamIds);
}

/**
  * @tc.name: double preview and video
  * @tc.desc: Commit 3 streams together, Double preview and video streams, isStreaming is true.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
static HWTEST_F(DoublePreviewTest, double_preview_003, TestSize.Level1)
{
    // Get the stream manager
    cameraBase_->AchieveStreamOperator();

    // Start stream
    CreateStream(cameraBase_->STREAM_ID_PREVIEW, PREVIEW);
    CreateStream(STREAMID_PREVIEW_DOUBLE, PREVIEW);
    cameraBase_->intents = {VIDEO};
    cameraBase_->StartStream(cameraBase_->intents);

    // Get preview
    StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true);
    StartCapture(STREAMID_PREVIEW_DOUBLE, CAPTUREID_PREVIEW_DOUBLE, false, true);
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_VIDEO, cameraBase_->CAPTURE_ID_VIDEO, false, true);

    constexpr uint32_t timeForWaitImagePreview = 5; // sleep five second
    sleep(timeForWaitImagePreview);

    std::vector<int> captureIds = {cameraBase_->CAPTURE_ID_PREVIEW, CAPTUREID_PREVIEW_DOUBLE,
        cameraBase_->CAPTURE_ID_VIDEO};
    std::vector<int> streamIds = {cameraBase_->STREAM_ID_PREVIEW, STREAMID_PREVIEW_DOUBLE,
        cameraBase_->STREAM_ID_VIDEO};
    StopStream(captureIds, streamIds);
}
