/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "usb_camera_test_mult.h"

void UtestUSBCameraTestMult::SetUpTestCase(void)
{}
void UtestUSBCameraTestMult::TearDownTestCase(void)
{}
void UtestUSBCameraTestMult::SetUp(void)
{
    if (cameraBase_ == nullptr)
    cameraBase_ = std::make_shared<TestCameraBase>();
    cameraBase_->UsbInit();
}
void UtestUSBCameraTestMult::TearDown(void)
{
    cameraBase_->Close();
}

CamRetCode UtestUSBCameraTestMult::SelectOpenCamera(std::string cameraId)
{
    cameraBase_->cameraHost->GetCameraAbility(cameraId, vecAbility_);
    MetadataUtils::ConvertVecToMetadata(vecAbility_, ability_);
    const OHOS::sptr<DemoCameraDeviceCallback> callback = new DemoCameraDeviceCallback();
    cameraBase_->rc = (CamRetCode)cameraBase_->cameraHost->OpenCamera(cameraId, callback, cameraDevice_);
    if (cameraBase_->rc != HDI::Camera::V1_0::NO_ERROR || cameraDevice_ == nullptr) {
        std::cout << "OpenCamera2 failed, rc = " << cameraBase_->rc << std::endl;
        return cameraBase_->rc;
    }
    std::cout << "OpenCamera2 success." << std::endl;
    return cameraBase_->rc;
}

void UtestUSBCameraTestMult::AchieveStreamOperator()
{
    OHOS::sptr<DemoStreamOperatorCallback> streamOperatorCallback = new DemoStreamOperatorCallback();
    cameraBase_->rc = (CamRetCode)cameraDevice_->GetStreamOperator(streamOperatorCallback, streamOperator_);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "AchieveStreamOperator2 success." << std::endl;
    } else {
        std::cout << "AchieveStreamOperator2 fail, rc = " << cameraBase_->rc << std::endl;
    }
}

void UtestUSBCameraTestMult::DefaultInfosPreview()
{
    if (streamCustomerPreview_ == nullptr) {
        streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    streamInfoPre_.streamId_ = STREAM_ID_PREVIEW_DOUBLE;
    streamInfoPre_.width_ = PREVIEW_WIDTH; // 640:picture width
    streamInfoPre_.height_ = PREVIEW_HEIGHT; // 480:picture height
    streamInfoPre_.format_ = PIXEL_FMT_RGBA_8888;
    streamInfoPre_.dataspace_ = 8; // 8:picture dataspace
    streamInfoPre_.intent_ = PREVIEW;
    streamInfoPre_.tunneledMode_ = 5; // 5:tunnel mode
    streamInfoPre_.bufferQueue_ = new BufferProducerSequenceable(streamCustomerPreview_->CreateProducer());
    ASSERT_NE(streamInfoPre_.bufferQueue_, nullptr);
    streamInfoPre_.bufferQueue_->producer_->SetQueueSize(8); // 8:set bufferQueue size
    std::cout << "preview success1." << std::endl;
    std::vector<StreamInfo>().swap(streamInfos_);
    streamInfos_.push_back(streamInfoPre_);
}

void UtestUSBCameraTestMult::DefaultInfosVideo()
{
    if (streamCustomerVideo_ == nullptr) {
        streamCustomerVideo_ = std::make_shared<StreamCustomer>();
    }
    streamInfoVideo_.streamId_ = STREAM_ID_VIDEO_DOUBLE;
    streamInfoVideo_.width_ = VIDEO_WIDTH; // 1280:picture width
    streamInfoVideo_.height_ = VIDEO_HEIGHT; // 960:picture height
    streamInfoVideo_.format_ = videoFormat_;
    streamInfoVideo_.dataspace_ = 8; // 8:picture dataspace
    streamInfoVideo_.intent_ = VIDEO;
    streamInfoVideo_.encodeType_ = ENCODE_TYPE_H264;
    streamInfoVideo_.tunneledMode_ = 5; // 5:tunnel mode
    streamInfoVideo_.bufferQueue_ = new BufferProducerSequenceable(streamCustomerVideo_->CreateProducer());
    ASSERT_NE(streamInfoVideo_.bufferQueue_, nullptr);
    streamInfoVideo_.bufferQueue_->producer_->SetQueueSize(8); // 8:set bufferQueue size
    std::cout << "video success1." << std::endl;
    std::vector<StreamInfo>().swap(streamInfos_);
    streamInfos_.push_back(streamInfoVideo_);
}

void UtestUSBCameraTestMult::DefaultInfosCapture()
{
    if (streamCustomerCapture_ == nullptr) {
        streamCustomerCapture_ = std::make_shared<StreamCustomer>();
    }
    streamInfoCapture_.streamId_ = STREAM_ID_CAPTURE_DOUBLE;
    streamInfoCapture_.width_ = CAPTURE_WIDTH; // 1280:picture width
    streamInfoCapture_.height_ = CAPTURE_HEIGHT; // 960:picture height
    streamInfoCapture_.format_ = PIXEL_FMT_RGBA_8888;
    streamInfoCapture_.dataspace_ = 8; // 8:picture dataspace
    streamInfoCapture_.intent_ = STILL_CAPTURE;
    streamInfoCapture_.encodeType_ = ENCODE_TYPE_JPEG;
    streamInfoCapture_.tunneledMode_ = 5; // 5:tunnel mode
    streamInfoCapture_.bufferQueue_ = new BufferProducerSequenceable(streamCustomerCapture_->CreateProducer());
    ASSERT_NE(streamInfoCapture_.bufferQueue_, nullptr);
    streamInfoCapture_.bufferQueue_->producer_->SetQueueSize(8); // 8:set bufferQueue size
    std::cout << "capture success1." << std::endl;
    std::vector<StreamInfo>().swap(streamInfos_);
    streamInfos_.push_back(streamInfoCapture_);
}

void UtestUSBCameraTestMult::StartStream(std::vector<StreamIntent> intents)
{
    for (auto& intent : intents) {
        if (intent == PREVIEW) {
            DefaultInfosPreview();
        } else if (intent == VIDEO) {
            DefaultInfosVideo();
        } else if (intent == STILL_CAPTURE) {
            DefaultInfosCapture();
        }
        cameraBase_->rc = (CamRetCode)streamOperator_->CreateStreams(streamInfos_);
        EXPECT_EQ(false, cameraBase_->rc != HDI::Camera::V1_0::NO_ERROR);
        if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
            std::cout << "CreateStreams2 success." << std::endl;
        } else {
            std::cout << "CreateStreams2 fail, rc = " << cameraBase_->rc << std::endl;
        }

        cameraBase_->rc = (CamRetCode)streamOperator_->CommitStreams(NORMAL, vecAbility_);
        EXPECT_EQ(false, cameraBase_->rc != HDI::Camera::V1_0::NO_ERROR);
        if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
            std::cout << "CommitStreams2 success." << std::endl;
        } else {
            std::cout << "CommitStreams2 fail, rc = " << cameraBase_->rc << std::endl;
        }
    }
}

void UtestUSBCameraTestMult::StoreImage(const unsigned char *bufStart, const uint32_t size)
{
    constexpr uint32_t pathLen = 64;
    char path[pathLen] = {0};
#ifdef CAMERA_BUILT_ON_OHOS_LITE
    char prefix[] = "/userdata/photo/";
#else
    char prefix[] = "/data/";
#endif

    int imgFD = 0;
    int ret = 0;

    struct timeval start = {};
    gettimeofday(&start, nullptr);
    if (sprintf_s(path, sizeof(path), "%spicture222_%ld.jpeg", prefix, start.tv_usec) < 0) {
        CAMERA_LOGE("sprintf_s error .....\n");
        return;
    }

    imgFD = open(path, O_RDWR | O_CREAT, 00766); // 00766:file operate permission
    if (imgFD == -1) {
        CAMERA_LOGE("demo test:open image file error %{public}s.....\n", strerror(errno));
        return;
    }

    CAMERA_LOGD("demo test:StoreImage2 %{public}s size == %{public}d\n", path, size);

    ret = write(imgFD, bufStart, size);
    if (ret == -1) {
        CAMERA_LOGE("demo test:write image file error %{public}s.....\n", strerror(errno));
    }

    close(imgFD);
}

void UtestUSBCameraTestMult::StoreVideo(const unsigned char *bufStart, const uint32_t size)
{
    int ret = 0;

    ret = write(videoFd_, bufStart, size);
    if (ret == -1) {
        CAMERA_LOGE("demo test:write video file error %{public}s.....\n", strerror(errno));
    }
    CAMERA_LOGD("demo test:StoreVideo size == %{public}d\n", size);
}

void UtestUSBCameraTestMult::OpenVideoFile()
{
    constexpr uint32_t pathLen = 64;
    char path[pathLen] = {0};
#ifdef CAMERA_BUILT_ON_OHOS_LITE
    char prefix[] = "/userdata/video/";
#else
    char prefix[] = "/data/";
#endif
    auto seconds = time(nullptr);
    if (sprintf_s(path, sizeof(path), "%svideo222%ld.h264", prefix, seconds) < 0) {
        CAMERA_LOGE("%{public}s: sprintf  failed", __func__);
        return;
    }
    videoFd_ = open(path, O_RDWR | O_CREAT, 00766); // 00766:file operate permission
    if (videoFd_ < 0) {
        CAMERA_LOGE("demo test: StartVideo open %s %{public}s failed", path, strerror(errno));
    }
}

void UtestUSBCameraTestMult::CloseFd()
{
    close(videoFd_);
    videoFd_ = -1;
}

void UtestUSBCameraTestMult::StartCapture(int streamId, int captureId, bool shutterCallback, bool isStreaming)
{
    // Get preview
    captureInfo_.streamIds_ = {streamId};
    captureInfo_.captureSetting_ = vecAbility_;
    captureInfo_.enableShutterCallback_ = shutterCallback;
    cameraBase_->rc = (CamRetCode)streamOperator_->Capture(captureId, captureInfo_, isStreaming);
    EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
    if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "check Capture: Capture2 success, captureId = " << captureId << std::endl;
    } else {
        std::cout << "check Capture: Capture2 fail, rc = " << cameraBase_->rc
                  << ", captureId = " << captureId<< std::endl;
    }
    if (captureId == CAPTURE_ID_PREVIEW_DOUBLE) {
        streamCustomerPreview_->ReceiveFrameOn(nullptr);
    } else if (captureId == CAPTURE_ID_CAPTURE_DOUBLE) {
        streamCustomerCapture_->ReceiveFrameOn([this](const unsigned char *addr, const uint32_t size) {
            StoreImage(addr, size);
        });
    } else if (captureId == CAPTURE_ID_VIDEO_DOUBLE) {
        OpenVideoFile();
        streamCustomerVideo_->ReceiveFrameOn([this](const unsigned char *addr, const uint32_t size) {
            StoreVideo(addr, size);
        });
    }
    sleep(2); // 2:sleep two second
}

void UtestUSBCameraTestMult::StopStream(std::vector<int>& captureIds, std::vector<int>& streamIds)
{
    constexpr uint32_t timeForWaitCancelCapture = 2;
    sleep(timeForWaitCancelCapture);
    if (captureIds.size() > 0) {
        for (auto &captureId : captureIds) {
            if (captureId == CAPTURE_ID_PREVIEW_DOUBLE) {
                streamCustomerPreview_->ReceiveFrameOff();
            } else if (captureId == CAPTURE_ID_CAPTURE_DOUBLE) {
                streamCustomerCapture_->ReceiveFrameOff();
            } else if (captureId == CAPTURE_ID_VIDEO_DOUBLE) {
                streamCustomerVideo_->ReceiveFrameOff();
                sleep(1);
                CloseFd();
            }
        }
        for (const auto &captureId : captureIds) {
            std::cout << "check Capture: CancelCapture success, captureId = " << captureId << std::endl;
            cameraBase_->rc = (CamRetCode)streamOperator_->CancelCapture(captureId);
            sleep(timeForWaitCancelCapture);
            EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
            if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
                std::cout << "check Capture: CancelCapture success, captureId = " << captureId << std::endl;
            } else {
                std::cout << "check Capture: CancelCapture fail, rc = "
                          << cameraBase_->rc <<", captureId = " << captureId << std::endl;
            }
        }
    }
    sleep(1); // 1:sleep two second
    if (streamIds.size() > 0) {
        // release stream
        cameraBase_->rc = (CamRetCode)streamOperator_->ReleaseStreams(streamIds);
        EXPECT_EQ(true, cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR);
        if (cameraBase_->rc == HDI::Camera::V1_0::NO_ERROR) {
            std::cout << "check Capture: ReleaseStreams success." << std::endl;
        } else {
            std::cout << "check Capture: ReleaseStreams fail, rc = "
                      << cameraBase_->rc << ", streamIds = " << streamIds.front() << std::endl;
        }
    }
}

const std::map<uint32_t, uint32_t> g_mapOhosFmtToPixFmt = {
    { OHOS_CAMERA_FORMAT_RGBA_8888, PIXEL_FMT_RGBA_8888 },
    { OHOS_CAMERA_FORMAT_YCRCB_420_SP, PIXEL_FMT_YCRCB_420_SP },
};

uint32_t UtestUSBCameraTestMult::ConvertPixfmtHal2V4l2(uint32_t ohosfmt)
{
    auto it = g_mapOhosFmtToPixFmt.find(ohosfmt);
    if (it == g_mapOhosFmtToPixFmt.end()) {
        CAMERA_LOGI("The ohosfmt is not find in g_mapOhosFmtToPixFmt");
        return PIXEL_FMT_RGBA_8888; // default value
    }
    return it->second;
}

/**
  * @tc.name: USB Camera
  * @tc.desc: USB Camera, getCameraID success.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestUSBCameraTestMult, camera_usb_mult_0001)
{
    std::vector<std::string> usbCameraIds;
    cameraBase_->cameraHost->GetCameraIds(usbCameraIds);
    // 1:number of connected cameras
    usbCameraExit_ = usbCameraIds.size() > 1;
    if (!usbCameraExit_) {
        GTEST_SKIP() << "No usb camera plugged in" << std::endl;
    }
    cameraBase_->rc = cameraBase_->SelectOpenCamera(usbCameraIds[0]); // 0:first camera id
    ASSERT_EQ(cameraBase_->rc, HDI::Camera::V1_0::NO_ERROR);
    cameraBase_->rc = SelectOpenCamera(usbCameraIds[1]);  // 1:second camera id
    ASSERT_EQ(cameraBase_->rc, HDI::Camera::V1_0::NO_ERROR);
    cameraBase_->AchieveStreamOperator();
    AchieveStreamOperator();

    cameraBase_->intents = {PREVIEW};
    cameraBase_->StartStream(cameraBase_->intents);
    StartStream(cameraBase_->intents);
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true);
    StartCapture(STREAM_ID_PREVIEW_DOUBLE, CAPTURE_ID_PREVIEW_DOUBLE, false, true);
    cameraBase_->captureIds = {cameraBase_->CAPTURE_ID_PREVIEW};
    cameraBase_->streamIds = {cameraBase_->STREAM_ID_PREVIEW};
    cameraBase_->StopStream(cameraBase_->captureIds, cameraBase_->streamIds);
    cameraBase_->captureIds = {CAPTURE_ID_PREVIEW_DOUBLE};
    cameraBase_->streamIds = {STREAM_ID_PREVIEW_DOUBLE};
    StopStream(cameraBase_->captureIds, cameraBase_->streamIds);
}

/**
  * @tc.name: USB Camera
  * @tc.desc: USB Camera, getCameraID success.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestUSBCameraTestMult, camera_usb_mult_0002)
{
    std::vector<std::string> usbCameraIds;
    cameraBase_->cameraHost->GetCameraIds(usbCameraIds);
    // 1:number of connected cameras
    usbCameraExit_ = usbCameraIds.size() > 1;
    if (!usbCameraExit_) {
        GTEST_SKIP() << "No usb camera plugged in" << std::endl;
    }
    cameraBase_->rc = cameraBase_->SelectOpenCamera(usbCameraIds[0]); // 0:first camera id
    ASSERT_EQ(cameraBase_->rc, HDI::Camera::V1_0::NO_ERROR);
    cameraBase_->rc = SelectOpenCamera(usbCameraIds[1]);  // 1:second camera id
    ASSERT_EQ(cameraBase_->rc, HDI::Camera::V1_0::NO_ERROR);
    cameraBase_->AchieveStreamOperator();
    AchieveStreamOperator();

    cameraBase_->intents = {PREVIEW, STILL_CAPTURE};
    cameraBase_->StartStream(cameraBase_->intents);
    StartStream(cameraBase_->intents);
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true);
    cameraBase_->StartCapture(cameraBase_->STREAM_ID_CAPTURE, cameraBase_->CAPTURE_ID_CAPTURE, false, true);
    StartCapture(STREAM_ID_PREVIEW_DOUBLE, CAPTURE_ID_PREVIEW_DOUBLE, false, true);
    StartCapture(STREAM_ID_CAPTURE_DOUBLE, CAPTURE_ID_CAPTURE_DOUBLE, false, true);
    cameraBase_->captureIds = {cameraBase_->CAPTURE_ID_PREVIEW, cameraBase_->CAPTURE_ID_CAPTURE};
    cameraBase_->streamIds = {cameraBase_->STREAM_ID_PREVIEW, cameraBase_->STREAM_ID_CAPTURE};
    cameraBase_->StopStream(cameraBase_->captureIds, cameraBase_->streamIds);
    cameraBase_->captureIds = {CAPTURE_ID_PREVIEW_DOUBLE, CAPTURE_ID_CAPTURE_DOUBLE};
    cameraBase_->streamIds = {STREAM_ID_PREVIEW_DOUBLE, STREAM_ID_CAPTURE_DOUBLE};
    StopStream(cameraBase_->captureIds, cameraBase_->streamIds);
}

/**
  * @tc.name: USB Camera
  * @tc.desc: USB Camera, getCameraID success.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestUSBCameraTestMult, camera_usb_mult_0003)
{
    std::vector<std::string> usbCameraIds;
    cameraBase_->cameraHost->GetCameraIds(usbCameraIds);
    // 1:number of connected cameras
    usbCameraExit_ = usbCameraIds.size() > 1;
    if (!usbCameraExit_) {
        GTEST_SKIP() << "No usb camera plugged in" << std::endl;
    }
    cameraBase_->rc = cameraBase_->SelectOpenCamera(usbCameraIds[0]); // 0:first camera id
    ASSERT_EQ(cameraBase_->rc, HDI::Camera::V1_0::NO_ERROR);
    cameraBase_->rc = SelectOpenCamera(usbCameraIds[1]);  // 1:second camera id
    ASSERT_EQ(cameraBase_->rc, HDI::Camera::V1_0::NO_ERROR);
    cameraBase_->AchieveStreamOperator();
    AchieveStreamOperator();

    ability_ = cameraBase_->GetCameraAbility();
    EXPECT_NE(ability_, nullptr);
    common_metadata_header_t *data = ability_->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS, &entry);

    uint32_t format = 0;
    if (ret == 0 && entry.data.i32 != nullptr && entry.count > 0) {
        format = entry.data.i32[entry.count - 6]; // 6:The sixth digit from the bottom is the format of video
    }
    videoFormat_ = ConvertPixfmtHal2V4l2(format);
    
    for (int i = 0; i < usbCameraIds.size(); i++) {
        cameraBase_->rc = cameraBase_->SelectOpenCamera(usbCameraIds[i]);
        ASSERT_EQ(cameraBase_->rc, HDI::Camera::V1_0::NO_ERROR);
        // Get the stream manager
        cameraBase_->AchieveStreamOperator();
        // start stream
        cameraBase_->intents = {PREVIEW, STILL_CAPTURE, VIDEO};
        cameraBase_->StartStream(cameraBase_->intents);
        // Get preview
        cameraBase_->StartCapture(cameraBase_->STREAM_ID_PREVIEW, cameraBase_->CAPTURE_ID_PREVIEW, false, true);
        cameraBase_->StartCapture(cameraBase_->STREAM_ID_CAPTURE, cameraBase_->CAPTURE_ID_CAPTURE, false, true);
        cameraBase_->StartCapture(cameraBase_->STREAM_ID_VIDEO, cameraBase_->CAPTURE_ID_VIDEO, false, true);
        // release stream
        cameraBase_->captureIds = {cameraBase_->CAPTURE_ID_PREVIEW, cameraBase_->CAPTURE_ID_CAPTURE,
        cameraBase_->CAPTURE_ID_VIDEO};
        cameraBase_->streamIds = {cameraBase_->STREAM_ID_PREVIEW, cameraBase_->STREAM_ID_CAPTURE,
        cameraBase_->STREAM_ID_VIDEO};
        cameraBase_->StopStream(cameraBase_->captureIds, cameraBase_->streamIds);
    }
}
