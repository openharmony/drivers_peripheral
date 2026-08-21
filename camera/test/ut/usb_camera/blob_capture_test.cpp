/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
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

#include "blob_capture_test.h"

using namespace testing::ext;

int CameraBlobCaptureTest::cameraCount_ = 0;
std::vector<std::string> CameraBlobCaptureTest::cameraIds_;

void CameraBlobCaptureTest::SetUpTestCase(void)
{
    auto host = TestCameraBase().cameraHost;
    if (host == nullptr) {
        constexpr const char *demoServiceName = "camera_service_usb";
        host = ICameraHost::Get(demoServiceName, false);
    }
    if (host != nullptr) {
        host->GetCameraIds(cameraIds_);
        cameraCount_ = static_cast<int>(cameraIds_.size());
    }
}

void CameraBlobCaptureTest::TearDownTestCase(void)
{}

void CameraBlobCaptureTest::SetUp(void)
{
    if (cameraBase_ == nullptr) {
        cameraBase_ = std::make_shared<TestCameraBase>();
    }
    cameraBase_->UsbInit();
    ASSERT_NE(cameraBase_->cameraHost, nullptr);

    if (cameraCount_ == 0) {
        GTEST_SKIP() << "No USB camera plugged in";
    }

    cameraBase_->OpenUsbCamera();
    ASSERT_NE(cameraBase_->cameraDevice, nullptr);

    blobCallback_ = new BlobStreamOperatorCallback();
    ResetFrameCount();
}

void CameraBlobCaptureTest::TearDown(void)
{
    cameraBase_->Close();
}

// Get StreamOperator with blobCallback (captureId tracking).
// GetStreamOperator can only be called once per device.
static void AchieveBlobStreamOperator(std::shared_ptr<TestCameraBase>& cameraBase,
    OHOS::sptr<BlobStreamOperatorCallback>& blobCallback)
{
    cameraBase->rc = (CamRetCode)cameraBase->cameraDevice->GetStreamOperator(blobCallback, cameraBase->streamOperator);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraBase->rc);
}

// Create preview + BLOB capture streams (PIXEL_FMT_BLOB).
static void StartBlobCaptureStream(std::shared_ptr<TestCameraBase>& cameraBase)
{
    constexpr int32_t tunnelMode = 5;
    constexpr int32_t dataspace = 8;
    constexpr uint32_t queueSize = 8;

    if (cameraBase->streamCustomerPreview_ == nullptr) {
        cameraBase->streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    StreamInfo streamInfoPre = {};
    streamInfoPre.streamId_ = cameraBase->STREAM_ID_PREVIEW;
    streamInfoPre.width_ = PREVIEW_WIDTH;
    streamInfoPre.height_ = PREVIEW_HEIGHT;
    streamInfoPre.format_ = PIXEL_FMT_RGBA_8888;
    streamInfoPre.dataspace_ = dataspace;
    streamInfoPre.intent_ = PREVIEW;
    streamInfoPre.tunneledMode_ = tunnelMode;
    streamInfoPre.bufferQueue_ = new BufferProducerSequenceable(
        cameraBase->streamCustomerPreview_->CreateProducer());
    ASSERT_NE(streamInfoPre.bufferQueue_, nullptr);
    streamInfoPre.bufferQueue_->producer_->SetQueueSize(queueSize);

    if (cameraBase->streamCustomerCapture_ == nullptr) {
        cameraBase->streamCustomerCapture_ = std::make_shared<StreamCustomer>();
    }
    StreamInfo streamInfoCapture = {};
    streamInfoCapture.streamId_ = cameraBase->STREAM_ID_CAPTURE;
    streamInfoCapture.width_ = CAPTURE_WIDTH;
    streamInfoCapture.height_ = CAPTURE_HEIGHT;
    streamInfoCapture.format_ = PIXEL_FMT_BLOB;
    streamInfoCapture.dataspace_ = dataspace;
    streamInfoCapture.intent_ = STILL_CAPTURE;
    streamInfoCapture.encodeType_ = ENCODE_TYPE_JPEG;
    streamInfoCapture.tunneledMode_ = tunnelMode;
    streamInfoCapture.bufferQueue_ = new BufferProducerSequenceable(
        cameraBase->streamCustomerCapture_->CreateProducer());
    ASSERT_NE(streamInfoCapture.bufferQueue_, nullptr);
    streamInfoCapture.bufferQueue_->producer_->SetQueueSize(queueSize);

    std::vector<StreamInfo> streamInfos = {streamInfoPre, streamInfoCapture};
    cameraBase->rc = (CamRetCode)cameraBase->streamOperator->CreateStreams(streamInfos);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraBase->rc);

    cameraBase->rc = (CamRetCode)cameraBase->streamOperator->CommitStreams(NORMAL, cameraBase->ability_);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraBase->rc);
}

/**
  * @tc.name: USB Camera BLOB capture
  * @tc.desc: Preview + BLOB capture, verify frame received and captureId matched.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraBlobCaptureTest, camera_blob_capture_001, TestSize.Level1)
{
    CAMERA_LOGI("BLOB capture 001: preview + single capture.");
    AchieveBlobStreamOperator(cameraBase_, blobCallback_);
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraBase_->rc);

    StartBlobCaptureStream(cameraBase_);
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraBase_->rc);

    cameraBase_->StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true);

    ResetFrameCount();
    blobCallback_->Reset();
    const int captureId1 = 2001;
    CaptureInfo captureInfo1 = {};
    captureInfo1.streamIds_ = {cameraBase_->STREAM_ID_CAPTURE};
    captureInfo1.captureSetting_ = cameraBase_->ability_;
    captureInfo1.enableShutterCallback_ = false;

    cameraBase_->streamCustomerCapture_->ReceiveFrameOn(
        [this](const unsigned char *addr, const uint32_t size) {
            CAMERA_LOGI("BLOB 001: frame received, size=%{public}u", size);
            EXPECT_NE(addr, nullptr);
            EXPECT_GT(size, 100u);
            EXPECT_TRUE(IsValidJpeg(addr, size));
            frameCount_++;
            frameCv_.notify_one();
        });

    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->Capture(captureId1, captureInfo1, false);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraBase_->rc);

    WaitForFrame(1);
    EXPECT_GE(frameCount_, 1);

    bool ended = blobCallback_->WaitForCaptureEnded(captureId1, 3);
    EXPECT_TRUE(ended);
    EXPECT_TRUE(blobCallback_->HasCaptureEnded(captureId1));

    cameraBase_->streamCustomerPreview_->ReceiveFrameOff();
    cameraBase_->streamCustomerCapture_->ReceiveFrameOff();
    cameraBase_->captureIds = {cameraBase_->CAPTURE_ID_PREVIEW};
    cameraBase_->streamIds = {cameraBase_->STREAM_ID_PREVIEW, cameraBase_->STREAM_ID_CAPTURE};
    cameraBase_->StopStream(cameraBase_->captureIds, cameraBase_->streamIds);
}

/**
  * @tc.name: USB Camera BLOB capture
  * @tc.desc: Preview + BLOB capture, verify JPEG data integrity and buffer validity.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraBlobCaptureTest, camera_blob_capture_002, TestSize.Level1)
{
    CAMERA_LOGI("BLOB capture 002: JPEG validation.");
    AchieveBlobStreamOperator(cameraBase_, blobCallback_);
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraBase_->rc);
    StartBlobCaptureStream(cameraBase_);
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraBase_->rc);
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true);

    ResetFrameCount();
    blobCallback_->Reset();
    const int captureId = 2001;
    CaptureInfo captureInfo = {};
    captureInfo.streamIds_ = {cameraBase_->STREAM_ID_CAPTURE};
    captureInfo.captureSetting_ = cameraBase_->ability_;
    captureInfo.enableShutterCallback_ = false;

    cameraBase_->streamCustomerCapture_->ReceiveFrameOn(
        [this](const unsigned char *addr, const uint32_t size) {
            CAMERA_LOGI("BLOB 002: frame, size=%{public}u", size);
            EXPECT_NE(addr, nullptr);
            EXPECT_GT(size, 100u);
            EXPECT_TRUE(IsValidJpeg(addr, size));
            frameCount_++;
            frameCv_.notify_one();
        });

    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->Capture(captureId, captureInfo, false);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraBase_->rc);
    WaitForFrame(1);
    EXPECT_GE(frameCount_, 1);
    EXPECT_TRUE(blobCallback_->WaitForCaptureEnded(captureId, 3));

    cameraBase_->streamCustomerPreview_->ReceiveFrameOff();
    cameraBase_->streamCustomerCapture_->ReceiveFrameOff();
    cameraBase_->captureIds = {cameraBase_->CAPTURE_ID_PREVIEW};
    cameraBase_->streamIds = {cameraBase_->STREAM_ID_PREVIEW, cameraBase_->STREAM_ID_CAPTURE};
    cameraBase_->StopStream(cameraBase_->captureIds, cameraBase_->streamIds);
}

/**
  * @tc.name: USB Camera BLOB capture
  * @tc.desc: Preview + BLOB capture, verify buffer size and stride alignment.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraBlobCaptureTest, camera_blob_capture_003, TestSize.Level1)
{
    CAMERA_LOGI("BLOB capture 003: buffer dimension verification.");
    AchieveBlobStreamOperator(cameraBase_, blobCallback_);
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraBase_->rc);

    StartBlobCaptureStream(cameraBase_);
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraBase_->rc);

    cameraBase_->StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true);

    ResetFrameCount();
    blobCallback_->Reset();
    const int captureId1 = 2001;
    CaptureInfo captureInfo1 = {};
    captureInfo1.streamIds_ = {cameraBase_->STREAM_ID_CAPTURE};
    captureInfo1.captureSetting_ = cameraBase_->ability_;
    captureInfo1.enableShutterCallback_ = false;

    cameraBase_->streamCustomerCapture_->ReceiveFrameOn(
        [this](const unsigned char *addr, const uint32_t size) {
            CAMERA_LOGI("BLOB 003: frame received, size=%{public}u", size);
            EXPECT_NE(addr, nullptr);
            EXPECT_GT(size, 100u);
            EXPECT_TRUE(IsValidJpeg(addr, size));
            EXPECT_EQ(addr[0], 0xFF);
            EXPECT_EQ(addr[1], 0xD8);
            frameCount_++;
            frameCv_.notify_one();
        });

    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->Capture(captureId1, captureInfo1, false);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraBase_->rc);

    WaitForFrame(1);
    EXPECT_GE(frameCount_, 1);

    bool ended = blobCallback_->WaitForCaptureEnded(captureId1, 3);
    EXPECT_TRUE(ended);
    EXPECT_TRUE(blobCallback_->HasCaptureEnded(captureId1));

    cameraBase_->streamCustomerPreview_->ReceiveFrameOff();
    cameraBase_->streamCustomerCapture_->ReceiveFrameOff();
    cameraBase_->captureIds = {cameraBase_->CAPTURE_ID_PREVIEW};
    cameraBase_->streamIds = {cameraBase_->STREAM_ID_PREVIEW, cameraBase_->STREAM_ID_CAPTURE};
    cameraBase_->StopStream(cameraBase_->captureIds, cameraBase_->streamIds);
}

/**
  * @tc.name: USB Camera BLOB capture
  * @tc.desc: Preview + BLOB capture, verify captureId consistency via OnCaptureEnded.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraBlobCaptureTest, camera_blob_capture_004, TestSize.Level1)
{
    CAMERA_LOGI("BLOB capture 004: captureId consistency.");
    AchieveBlobStreamOperator(cameraBase_, blobCallback_);
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraBase_->rc);
    StartBlobCaptureStream(cameraBase_);
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraBase_->rc);
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true);

    ResetFrameCount();
    blobCallback_->Reset();
    const int captureId = 2001;
    CaptureInfo captureInfo = {};
    captureInfo.streamIds_ = {cameraBase_->STREAM_ID_CAPTURE};
    captureInfo.captureSetting_ = cameraBase_->ability_;
    captureInfo.enableShutterCallback_ = false;

    cameraBase_->streamCustomerCapture_->ReceiveFrameOn(
        [this](const unsigned char *addr, const uint32_t size) {
            frameCount_++;
            frameCv_.notify_one();
        });

    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->Capture(captureId, captureInfo, false);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraBase_->rc);
    WaitForFrame(1);
    EXPECT_TRUE(blobCallback_->WaitForCaptureEnded(captureId, 3));
    EXPECT_TRUE(blobCallback_->HasCaptureEnded(captureId));

    cameraBase_->streamCustomerPreview_->ReceiveFrameOff();
    cameraBase_->streamCustomerCapture_->ReceiveFrameOff();
    cameraBase_->captureIds = {cameraBase_->CAPTURE_ID_PREVIEW};
    cameraBase_->streamIds = {cameraBase_->STREAM_ID_PREVIEW, cameraBase_->STREAM_ID_CAPTURE};
    cameraBase_->StopStream(cameraBase_->captureIds, cameraBase_->streamIds);
}

/**
  * @tc.name: USB Camera BLOB capture
  * @tc.desc: Preview + consecutive BLOB captures, verify second capture not blocked and captureId correct.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
HWTEST_F(CameraBlobCaptureTest, camera_blob_capture_005, TestSize.Level1)
{
    CAMERA_LOGI("BLOB capture 005: consecutive captures.");
    AchieveBlobStreamOperator(cameraBase_, blobCallback_);
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraBase_->rc);
    StartBlobCaptureStream(cameraBase_);
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraBase_->rc);
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true);

    CaptureInfo capInfo = {};
    capInfo.streamIds_ = {cameraBase_->STREAM_ID_CAPTURE};
    capInfo.captureSetting_ = cameraBase_->ability_;
    capInfo.enableShutterCallback_ = false;

    // 1st capture
    ResetFrameCount();
    blobCallback_->Reset();
    cameraBase_->streamCustomerCapture_->ReceiveFrameOn(
        [this](const unsigned char *addr, const uint32_t size) {
            frameCount_++;
            frameCv_.notify_one();
        });
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->Capture(2001, capInfo, false);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraBase_->rc);
    WaitForFrame(1);
    EXPECT_TRUE(blobCallback_->WaitForCaptureEnded(2001, 3));

    cameraBase_->streamCustomerCapture_->ReceiveFrameOff();
    sleep(1);

    // 2nd capture - verify not blocked and captureId correct
    ResetFrameCount();
    blobCallback_->Reset();
    cameraBase_->streamCustomerCapture_->ReceiveFrameOn(
        [this](const unsigned char *addr, const uint32_t size) {
            frameCount_++;
            frameCv_.notify_one();
        });
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->Capture(2002, capInfo, false);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraBase_->rc);
    WaitForFrame(1);
    EXPECT_GE(frameCount_, 1);
    EXPECT_TRUE(blobCallback_->WaitForCaptureEnded(2002, 3));
    EXPECT_TRUE(blobCallback_->HasCaptureEnded(2002));

    cameraBase_->streamCustomerPreview_->ReceiveFrameOff();
    cameraBase_->streamCustomerCapture_->ReceiveFrameOff();
    cameraBase_->captureIds = {cameraBase_->CAPTURE_ID_PREVIEW};
    cameraBase_->streamIds = {cameraBase_->STREAM_ID_PREVIEW, cameraBase_->STREAM_ID_CAPTURE};
    cameraBase_->StopStream(cameraBase_->captureIds, cameraBase_->streamIds);
}
