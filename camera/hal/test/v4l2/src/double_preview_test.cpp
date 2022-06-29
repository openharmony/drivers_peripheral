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

void DoublePreviewTest::SetUpTestCase(void)
{}
void DoublePreviewTest::TearDownTestCase(void)
{}
void DoublePreviewTest::SetUp(void)
{
    if (display_ == nullptr) {
        display_ = std::make_shared<TestDisplay>();
    }
    display_->Init();
}
void DoublePreviewTest::TearDown(void)
{
    display_->Close();
}

void DoublePreviewTest::SetStreamInfo(std::shared_ptr<OHOS::Camera::StreamInfo> &streamInfo,
    const std::shared_ptr<StreamCustomer> &streamCustomer,
    const int streamId, const OHOS::Camera::StreamIntent intent)
{
    constexpr uint32_t DATA_SPACE = 8; // picture dataspace
    constexpr uint32_t TUNNEL_MODE = 5; // tunnel mode
    constexpr uint32_t BUFFER_QUEUE_SIZE = 8; // set bufferQueue size
    if (intent == OHOS::Camera::PREVIEW) {
        streamInfo->width_ = PREVIEW_WIDTH;
        streamInfo->height_ = PREVIEW_HEIGHT;
        streamInfo->format_ = PIXEL_FMT_RGBA_8888;
        if (streamId == display_->streamId_preview) {
            streamInfo->streamId_ = streamId;
        } else if (streamId == streamId_preview_double) {
            streamInfo->streamId_ = streamId;
        }
    }
    streamInfo->datasapce_ = DATA_SPACE;
    streamInfo->intent_ = intent;
    streamInfo->tunneledMode_ = TUNNEL_MODE;
    streamInfo->bufferQueue_ = streamCustomer->CreateProducer();
    streamInfo->bufferQueue_->SetQueueSize(BUFFER_QUEUE_SIZE);
}

void DoublePreviewTest::CreateStream(int streamId, OHOS::Camera::StreamIntent intent)
{
    std::shared_ptr<OHOS::Camera::StreamInfo> streamInfo = std::make_shared<OHOS::Camera::StreamInfo>();
    if (streamInfo == nullptr) {
        std::cout << "==========[test log]std::make_shared<Camera::StreamInfo>() is nullptr" << std::endl;
        return;
    }
    if (intent == OHOS::Camera::PREVIEW) {
        if (streamId == display_->streamId_preview) {
            if (streamCustomerPreview_ == nullptr) {
                    streamCustomerPreview_ = std::make_shared<StreamCustomer>();
                    SetStreamInfo(streamInfo, streamCustomerPreview_, streamId, intent);
                    std::vector<std::shared_ptr<OHOS::Camera::StreamInfo>>().swap(streamInfos_);
                    streamInfos_.push_back(streamInfo);
                }
        } else if (streamId == streamId_preview_double) {
            if (streamCustomerPreviewDouble_ == nullptr) {
                streamCustomerPreviewDouble_ = std::make_shared<StreamCustomer>();
                SetStreamInfo(streamInfo, streamCustomerPreviewDouble_, streamId, intent);
                std::vector<std::shared_ptr<OHOS::Camera::StreamInfo>>().swap(streamInfos_);
                streamInfos_.push_back(streamInfo);
            }
        }
    }
    result_ = display_->streamOperator->CreateStreams(streamInfos_);
    EXPECT_EQ(false, result_!= OHOS::Camera::NO_ERROR);
    if (result_ == OHOS::Camera::NO_ERROR) {
        std::cout << "==========[test log]CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log]CreateStreams fail, result_ = " << result_ << std::endl;
    }
}

void DoublePreviewTest::CommitStream()
{
    result_ = display_->streamOperator->CommitStreams(OHOS::Camera::NORMAL, display_->ability);
    EXPECT_EQ(false, result_ != OHOS::Camera::NO_ERROR);
    if (result_ == OHOS::Camera::NO_ERROR) {
        std::cout << "==========[test log]CommitStreams preview success." << std::endl;
    } else {
        std::cout << "==========[test log]CommitStreams preview  fail, result_ = " << result_ << std::endl;
    }
}

void DoublePreviewTest::StartCapture(int streamId, int captureId, bool shutterCallback, bool isStreaming)
{
    captureInfo_ = std::make_shared<OHOS::Camera::CaptureInfo>();
    captureInfo_->streamIds_ = {streamId};
    captureInfo_->captureSetting_ = display_->ability;
    captureInfo_->enableShutterCallback_ = shutterCallback;
    constexpr uint32_t SLEEP_SECOND_TWO = 2; // sleep two second
    result_ = display_->streamOperator->Capture(captureId, captureInfo_, isStreaming);
    EXPECT_EQ(true, result_ == OHOS::Camera::NO_ERROR);
    if (result_ == OHOS::Camera::NO_ERROR) {
        std::cout << "==========[test log]check Capture: Capture success, " << captureId << std::endl;
    } else {
        std::cout << "==========[test log]check Capture: Capture fail, result_ = " << result_ << captureId << std::endl;
    }
    if (captureId == display_->captureId_preview) {
        streamCustomerPreview_->ReceiveFrameOn([this](void* addr, const uint32_t size) {
            std::cout << "==========[test log]preview size= " <<
                size << std::endl;
        });
    } else if (captureId == captureId_preview_double) {
        streamCustomerPreviewDouble_->ReceiveFrameOn([this](void* addr, const uint32_t size) {
            std::cout << "==========[test log]preview double size= " <<
                size << std::endl;
        });
    } else {
        std::cout << "==========[test log]StartCapture ignore command " << std::endl;
    }
    sleep(SLEEP_SECOND_TWO);
}

void DoublePreviewTest::StopStream(std::vector<int> &captureIds, std::vector<int> &streamIds)
{
    if (sizeof(captureIds_) > 0) {
        for (auto &captureId : captureIds_) {
            if (captureId == display_->captureId_preview) {
                streamCustomerPreview_->ReceiveFrameOff();
            } else if (captureId == captureId_preview_double) {
                streamCustomerPreviewDouble_->ReceiveFrameOff();
            } else {
                std::cout << "==========[test log]StopStream ignore command. " <<  std::endl;
            }
        }
        for (auto &captureId : captureIds_) {
            result_ = display_->streamOperator->CancelCapture(captureId);
            EXPECT_EQ(true, result_ == OHOS::Camera::NO_ERROR);
            if (result_ == OHOS::Camera::NO_ERROR) {
                std::cout << "==========[test log]check Capture: CancelCapture success," << captureId << std::endl;
            } else {
                std::cout << "==========[test log]check Capture: CancelCapture fail, result_ = " << result_;
                std::cout << "captureId = " << captureId << std::endl;
            }
        }
    }

    if (sizeof(streamIds_) > 0) {
        result_ = display_->streamOperator->ReleaseStreams(streamIds_);
        EXPECT_EQ(true, result_ == OHOS::Camera::NO_ERROR);
        if (result_ == OHOS::Camera::NO_ERROR) {
            std::cout << "==========[test log]check Capture: ReleaseStreams success." << std::endl;
        } else {
            std::cout << "==========[test log]check Capture: ReleaseStreams fail, result_ = " << result_ << std::endl;
            std::cout << "streamIds_ = " << streamIds_.front() << std::endl;
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
    display_->AchieveStreamOperator();

    // Start stream
    CreateStream(display_->streamId_preview, OHOS::Camera::PREVIEW);
    CreateStream(streamId_preview_double, OHOS::Camera::PREVIEW);

    // Commit stream
    CommitStream();

    // Get preview
    StartCapture(display_->streamId_preview, display_->captureId_preview, false, true);
    StartCapture(streamId_preview_double, captureId_preview_double, false, true);

    constexpr uint32_t SLEEP_SECOND_TEN = 10; // sleep ten second
    sleep(SLEEP_SECOND_TEN);

    streamIds_ = {display_->streamId_preview, streamId_preview_double};
    captureIds_ = {display_->captureId_preview, captureId_preview_double};
    StopStream(captureIds_, streamIds_);
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
    display_->AchieveStreamOperator();

    // Start stream
    CreateStream(display_->streamId_preview, OHOS::Camera::PREVIEW);
    CreateStream(streamId_preview_double, OHOS::Camera::PREVIEW);
    display_->intents = { OHOS::Camera::STILL_CAPTURE};
    display_->StartStream(display_->intents);

    // Get preview
    StartCapture(display_->streamId_preview, display_->captureId_preview, false, true);
    StartCapture(streamId_preview_double, captureId_preview_double, false, true);
    // add dumy exif info
    constexpr double latitude = 27.987500; // dummy data: Qomolangma latitde
    constexpr double longitude = 86.927500; // dummy data: Qomolangma longituude
    constexpr double altitude = 8848.86; // dummy data: Qomolangma altitude
    constexpr size_t entryCapacity = 100;
    constexpr size_t dataCapacity = 2000;
    std::shared_ptr<OHOS::Camera::CameraSetting>  captureSetting =
        std::make_shared<OHOS::Camera::CameraSetting>(entryCapacity, dataCapacity);
    std::vector<double> gps;
    gps.push_back(latitude);
    gps.push_back(longitude);
    gps.push_back(altitude);
    captureSetting->addEntry(OHOS_JPEG_GPS_COORDINATES, gps.data(), gps.size());

    std::shared_ptr<OHOS::Camera::CaptureInfo> captureInfo = std::make_shared<OHOS::Camera::CaptureInfo>();
    captureInfo->streamIds_ = {display_->streamId_capture};
    captureInfo->captureSetting_ = captureSetting;
    captureInfo->enableShutterCallback_ = false;
    display_->rc = display_->streamOperator->Capture(display_->captureId_capture, captureInfo, true);
    EXPECT_EQ(true, display_->rc == OHOS::Camera::NO_ERROR);
    if (display_->rc == OHOS::Camera::NO_ERROR) {
        std::cout << "==========[test log]check Capture: Capture success, " << display_->captureId_capture << std::endl;
    } else {
        std::cout << "==========[test log]check Capture: Capture fail, rc = " << display_->rc
            << display_->captureId_capture << std::endl;
    }
    display_->streamCustomerCapture_->ReceiveFrameOn([this](void* addr, const uint32_t size) {
        display_->StoreImage(addr, size);
    });

    constexpr uint32_t SLEEP_SECOND_FIVE = 5; // sleep five second
    sleep(SLEEP_SECOND_FIVE);

    streamIds_ = {display_->streamId_preview, streamId_preview_double};
    captureIds_ = {display_->captureId_preview, captureId_preview_double};
    std::vector<int> captureIds =  {display_->captureId_capture};
    std::vector<int> streamIds = {display_->streamId_capture};
    StopStream(captureIds_, streamIds_);
    display_->StopStream(captureIds, streamIds);
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
    display_->AchieveStreamOperator();

    // Start stream
    CreateStream(display_->streamId_preview, OHOS::Camera::PREVIEW);
    CreateStream(streamId_preview_double, OHOS::Camera::PREVIEW);
    display_->intents = { OHOS::Camera::VIDEO};
    display_->StartStream(display_->intents);

    // Get preview
    StartCapture(display_->streamId_preview, display_->captureId_preview, false, true);
    StartCapture(streamId_preview_double, captureId_preview_double, false, true);
    display_->StartCapture(display_->streamId_video, display_->captureId_video, false, true);

    constexpr uint32_t SLEEP_SECOND_FIVE = 5; // sleep five second
    sleep(SLEEP_SECOND_FIVE);

    streamIds_ = {display_->streamId_preview, streamId_preview_double};
    captureIds_ = {display_->captureId_preview, captureId_preview_double};
    std::vector<int> captureIds =  {display_->captureId_video};
    std::vector<int> streamIds = {display_->streamId_video};
    StopStream(captureIds_, streamIds_);
    display_->StopStream(captureIds, streamIds);
}
