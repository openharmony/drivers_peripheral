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
#include "hdfcamera_facedetect.h"

using namespace testing::ext;

void HdfCameraFaceDetect::SetUpTestCase(void)
{}
void HdfCameraFaceDetect::TearDownTestCase(void)
{}
void HdfCameraFaceDetect::SetUp(void)
{
    if (cameraBase_ == nullptr) {
        cameraBase_ = std::make_shared<TestCameraBase>();
    }
    cameraBase_->Init();
}
void HdfCameraFaceDetect::TearDown(void)
{
    cameraBase_->Close();
}

/**
  * @tc.name: preview and capture and face detect
  * @tc.desc: Commit 3 streams together, Preview , still_capture and analyze streams, isStreaming is true.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
static HWTEST_F(HdfCameraFaceDetect, CameraFaceDetect_001, TestSize.Level1)
{
    // Get the stream manager
    cameraBase_->AchieveStreamOperator();
    // start stream
    cameraBase_->intents = {PREVIEW, STILL_CAPTURE, ANALYZE};
    cameraBase_->StartStream(cameraBase_->intents);
    // Get preview
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true);
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_ANALYZE, cameraBase_->CAPTURE_ID_ANALYZE, false, true);

    // add dumy exif info
    constexpr double latitude = 27.987500; // dummy data: Qomolangma latitde
    constexpr double longitude = 86.927500; // dummy data: Qomolangma longituude
    constexpr double altitude = 8848.86; // dummy data: Qomolangma altitude
    constexpr size_t entryCapacity = 100;
    constexpr size_t dataCapacity = 2000;
    std::shared_ptr<CameraSetting>  captureSetting =
        std::make_shared<CameraSetting>(entryCapacity, dataCapacity);
    uint8_t captureQuality = OHOS_CAMERA_JPEG_LEVEL_HIGH;
    int32_t captureOrientation = OHOS_CAMERA_JPEG_ROTATION_270;
    uint8_t mirrorSwitch = OHOS_CAMERA_MIRROR_ON;
    std::vector<double> gps;
    gps.push_back(latitude);
    gps.push_back(longitude);
    gps.push_back(altitude);
    captureSetting->addEntry(OHOS_JPEG_QUALITY, static_cast<void*>(&captureQuality),
        sizeof(captureQuality));
    captureSetting->addEntry(OHOS_JPEG_ORIENTATION, static_cast<void*>(&captureOrientation),
        sizeof(captureOrientation));
    captureSetting->addEntry(OHOS_CONTROL_CAPTURE_MIRROR, static_cast<void*>(&mirrorSwitch),
        sizeof(mirrorSwitch));
    captureSetting->addEntry(OHOS_JPEG_GPS_COORDINATES, gps.data(), gps.size());
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(captureSetting, setting);

    CaptureInfo captureInfo = {};
    captureInfo.streamIds_ = {cameraBase_->STREAM_ID_CAPTURE};
    captureInfo.captureSetting_ = setting;
    captureInfo.enableShutterCallback_ = false;
    cameraBase_->rc = (CamRetCode)cameraBase_->streamOperator->Capture(cameraBase_->CAPTURE_ID_CAPTURE,
        captureInfo, true);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("check Capture: Capture success, captureId = %{public}d", cameraBase_->CAPTURE_ID_CAPTURE);
    } else {
        CAMERA_LOGE("check Capture: Capture fail, captureId = %{public}d, rc = %{public}d",
            cameraBase_->CAPTURE_ID_CAPTURE, cameraBase_->rc);
    }
    cameraBase_->streamCustomerCapture_->ReceiveFrameOn([this](const unsigned char *addr, const uint32_t size) {
        cameraBase_->StoreImage(addr, size);
    });
    sleep(2);
    // release stream
    cameraBase_->captureIds = {cameraBase_->CAPTURE_ID_PREVIEW, cameraBase_->CAPTURE_ID_ANALYZE,
        cameraBase_->CAPTURE_ID_CAPTURE};
    cameraBase_->streamIds = {cameraBase_->STREAM_ID_PREVIEW, cameraBase_->STREAM_ID_ANALYZE,
        cameraBase_->STREAM_ID_CAPTURE};
    cameraBase_->StopStream(cameraBase_->captureIds, cameraBase_->streamIds);
}

/**
  * @tc.name: preview and capture and face detect
  * @tc.desc: Commit 2 streams together, Preview and analyze streams, isStreaming is true.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
static HWTEST_F(HdfCameraFaceDetect, CameraFaceDetect_002, TestSize.Level1)
{
    // Get the stream manager
    cameraBase_->AchieveStreamOperator();
    // start stream
    cameraBase_->intents = {PREVIEW, ANALYZE};
    cameraBase_->StartStream(cameraBase_->intents);
    // Get preview
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true);
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_ANALYZE, cameraBase_->CAPTURE_ID_ANALYZE, false, true);
    sleep(2);
    // release stream
    cameraBase_->captureIds = {cameraBase_->CAPTURE_ID_PREVIEW, cameraBase_->CAPTURE_ID_ANALYZE};
    cameraBase_->streamIds = {cameraBase_->STREAM_ID_PREVIEW, cameraBase_->STREAM_ID_ANALYZE};
    cameraBase_->StopStream(cameraBase_->captureIds, cameraBase_->streamIds);
}