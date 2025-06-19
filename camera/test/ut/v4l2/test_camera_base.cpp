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
#include "test_camera_base.h"
using namespace std;

const std::vector<int32_t> DATA_BASE = {
    OHOS_CAMERA_STREAM_ID,
    OHOS_SENSOR_COLOR_CORRECTION_GAINS,
    OHOS_SENSOR_EXPOSURE_TIME,
    OHOS_CONTROL_EXPOSURE_MODE,
    OHOS_CONTROL_AE_EXPOSURE_COMPENSATION,
    OHOS_CONTROL_FOCUS_MODE,
    OHOS_CONTROL_METER_MODE,
    OHOS_CONTROL_FLASH_MODE,
    OHOS_CONTROL_FPS_RANGES,
    OHOS_CONTROL_AWB_MODE,
    OHOS_CONTROL_AF_REGIONS,
    OHOS_CONTROL_METER_POINT,
    OHOS_CONTROL_VIDEO_STABILIZATION_MODE,
    OHOS_CONTROL_FOCUS_STATE,
    OHOS_CONTROL_EXPOSURE_STATE,
};

TestCameraBase::TestCameraBase()
{
}

uint64_t TestCameraBase::GetCurrentLocalTimeStamp()
{
    std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds> tp =
        std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
    auto tmp = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch());
    return tmp.count();
}

void TestCameraBase::StoreImage(const unsigned char *bufStart, const uint32_t size) const
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
    if (sprintf_s(path, sizeof(path), "%spicture_%ld.jpeg", prefix, start.tv_usec) < 0) {
        CAMERA_LOGE("sprintf_s error .....");
        return;
    }

    imgFD = open(path, O_RDWR | O_CREAT, 00766); // 00766:file operate permission
    if (imgFD == -1) {
        CAMERA_LOGE("demo test:open image file error %{public}s.....", strerror(errno));
        return;
    }

    CAMERA_LOGD("demo test:StoreImage %{public}s size == %{public}d", path, size);

    ret = write(imgFD, bufStart, size);
    if (ret == -1) {
        CAMERA_LOGE("demo test:write image file error %{public}s.....", strerror(errno));
    }

    close(imgFD);
}

void TestCameraBase::StoreVideo(const unsigned char *bufStart, const uint32_t size) const
{
    int ret = 0;

    ret = write(videoFd_, bufStart, size);
    if (ret == -1) {
        CAMERA_LOGE("demo test:write video file error %{public}s.....", strerror(errno));
    }
    CAMERA_LOGD("demo test:StoreVideo size == %{public}d", size);
}

void TestCameraBase::OpenVideoFile()
{
    constexpr uint32_t pathLen = 64;
    char path[pathLen] = {0};
#ifdef CAMERA_BUILT_ON_OHOS_LITE
    char prefix[] = "/userdata/video/";
#else
    char prefix[] = "/data/";
#endif
    auto seconds = time(nullptr);
    if (sprintf_s(path, sizeof(path), "%svideo%ld.h264", prefix, seconds) < 0) {
        CAMERA_LOGE("%{public}s: sprintf  failed", __func__);
        return;
    }
    videoFd_ = open(path, O_RDWR | O_CREAT, 00766); // 00766:file operate permission
    if (videoFd_ < 0) {
        CAMERA_LOGE("demo test: StartVideo open %s %{public}s failed", path, strerror(errno));
    }
}

void TestCameraBase::CloseFd()
{
    close(videoFd_);
    videoFd_ = -1;
}

void TestCameraBase::PrintFaceDetectInfo(const unsigned char *bufStart, const uint32_t size) const
{
    common_metadata_header_t* data = reinterpret_cast<common_metadata_header_t*>(
        const_cast<unsigned char*>(bufStart));
    if (data->item_count > MAX_ITEM_CAPACITY || data->data_count > MAX_DATA_CAPACITY) {
        CAMERA_LOGE("demo test: invalid item_count or data_count");
        return;
    }
    camera_metadata_item_t entry;
    int ret = 0;
    ret = FindCameraMetadataItem(data, OHOS_STATISTICS_FACE_DETECT_SWITCH, &entry);
    if (ret != 0) {
        CAMERA_LOGE("demo test: get OHOS_STATISTICS_FACE_DETECT_SWITCH error");
        return;
    }
    uint8_t switchValue = *(entry.data.u8);
    CAMERA_LOGI("demo test: switchValue=%{public}d", switchValue);

    ret = FindCameraMetadataItem(data, OHOS_STATISTICS_FACE_RECTANGLES, &entry);
    if (ret != 0) {
        CAMERA_LOGE("demo test: get OHOS_STATISTICS_FACE_RECTANGLES error");
        return;
    }
    uint32_t rectCount = entry.count;
    CAMERA_LOGI("demo test: rectCount=%{public}d", rectCount);
    std::vector<std::vector<float>> faceRectangles;
    std::vector<float> faceRectangle;
    for (int i = 0; i < rectCount; i++) {
        faceRectangle.push_back(*(entry.data.f + i));
    }
    faceRectangles.push_back(faceRectangle);
    for (std::vector<std::vector<float>>::iterator it = faceRectangles.begin(); it < faceRectangles.end(); it++) {
        for (std::vector<float>::iterator innerIt = (*it).begin(); innerIt < (*it).end(); innerIt++) {
            CAMERA_LOGI("demo test: innerIt : %{public}f", *innerIt);
        }
    }

    ret = FindCameraMetadataItem(data, OHOS_STATISTICS_FACE_IDS, &entry);
    if (ret != 0) {
        CAMERA_LOGE("demo test: get OHOS_STATISTICS_FACE_IDS error");
        return;
    }
    uint32_t idCount = entry.count;
    CAMERA_LOGI("demo test: idCount=%{public}d", idCount);
    std::vector<int32_t> faceIds;
    for (int i = 0; i < idCount; i++) {
        faceIds.push_back(*(entry.data.i32 + i));
    }
    for (auto it = faceIds.begin(); it != faceIds.end(); it++) {
        CAMERA_LOGI("demo test: faceIds : %{public}d", *it);
    }
}

int32_t TestCameraBase::SaveYUV(char* type, unsigned char* buffer, int32_t size)
{
    int ret;
    char path[PATH_MAX] = {0};
    ret = sprintf_s(path, sizeof(path) / sizeof(path[0]), "/mnt/yuv/%s_%lld.yuv", type, GetCurrentLocalTimeStamp());
    if (ret < 0) {
        CAMERA_LOGE("%s, sprintf_s failed, errno = %s.", __FUNCTION__, strerror(errno));
        return -1;
    }
    CAMERA_LOGI("%s, save yuv to file %s", __FUNCTION__, path);
    system("mkdir -p /mnt/yuv");
    int imgFd = open(path, O_RDWR | O_CREAT, 00766); // 00766: file permissions
    if (imgFd == -1) {
        CAMERA_LOGI("%s, open file failed, errno = %s.", __FUNCTION__, strerror(errno));
        return -1;
    }
    ret = write(imgFd, buffer, size);
    if (ret == -1) {
        CAMERA_LOGI("%s, write file failed, error = %s", __FUNCTION__, strerror(errno));
        close(imgFd);
        return -1;
    }
    close(imgFd);
    return 0;
}

int TestCameraBase::DoFbMunmap(unsigned char* addr)
{
    int ret;
    unsigned int size = vinfo_.xres * vinfo_.yres * vinfo_.bits_per_pixel / 8; // 8:picture size;
    CAMERA_LOGI("main test:munmapped size = %d", size);
    ret = (munmap(addr, finfo_.smem_len));
    return ret;
}

unsigned char* TestCameraBase::DoFbMmap(int* pmemfd)
{
    unsigned char* ret;
    int screensize = vinfo_.xres * vinfo_.yres * vinfo_.bits_per_pixel / 8; // 8:picture size
    ret = static_cast<unsigned char*>(mmap(nullptr, screensize, PROT_READ | PROT_WRITE, MAP_SHARED, *pmemfd, 0));
    if (ret == MAP_FAILED) {
        CAMERA_LOGE("main test:do_mmap: pmem mmap() failed: %s (%d)", strerror(errno), errno);
        return nullptr;
    }
    CAMERA_LOGI("main test:do_mmap: pmem mmap fd %d len %u", *pmemfd, screensize);
    return ret;
}

void TestCameraBase::FBLog()
{
    CAMERA_LOGI("the fixed information is as follow:");
    CAMERA_LOGI("id=%s", finfo_.id);
    CAMERA_LOGI("sem_start=%lx", finfo_.smem_start);
    CAMERA_LOGI("smem_len=%u", finfo_.smem_len);
    CAMERA_LOGI("type=%u", finfo_.type);
    CAMERA_LOGI("line_length=%u", finfo_.line_length);
    CAMERA_LOGI("mmio_start=%lu", finfo_.mmio_start);
    CAMERA_LOGI("mmio_len=%d", finfo_.mmio_len);
    CAMERA_LOGI("visual=%d", finfo_.visual);

    CAMERA_LOGI("variable information is as follow:");
    CAMERA_LOGI("The xres is :%u", vinfo_.xres);
    CAMERA_LOGI("The yres is :%u", vinfo_.yres);
    CAMERA_LOGI("xres_virtual=%u", vinfo_.xres_virtual);
    CAMERA_LOGI("yres_virtual=%u", vinfo_.yres_virtual);
    CAMERA_LOGI("xoffset=%u", vinfo_.xoffset);
    CAMERA_LOGI("yoffset=%u", vinfo_.yoffset);
    CAMERA_LOGI("bits_per_pixel is :%u", vinfo_.bits_per_pixel);
    CAMERA_LOGI("red.offset=%u", vinfo_.red.offset);
    CAMERA_LOGI("red.length=%u", vinfo_.red.length);
    CAMERA_LOGI("red.msb_right=%u", vinfo_.red.msb_right);
    CAMERA_LOGI("green.offset=%d", vinfo_.green.offset);
    CAMERA_LOGI("green.length=%d", vinfo_.green.length);
    CAMERA_LOGI("green.msb_right=%d", vinfo_.green.msb_right);
    CAMERA_LOGI("blue.offset=%d", vinfo_.blue.offset);
    CAMERA_LOGI("blue.length=%d", vinfo_.blue.length);
    CAMERA_LOGI("blue.msb_right=%d", vinfo_.blue.msb_right);
    CAMERA_LOGI("transp.offset=%d", vinfo_.transp.offset);
    CAMERA_LOGI("transp.length=%d", vinfo_.transp.length);
    CAMERA_LOGI("transp.msb_right=%d", vinfo_.transp.msb_right);
    CAMERA_LOGI("height=%x", vinfo_.height);
}

OHOS::Camera::RetCode TestCameraBase::FBInit()
{
    fbFd_ = open("/dev/fb0", O_RDWR);
    if (fbFd_ < 0) {
        CAMERA_LOGE("main test:cannot open framebuffer %s file node", "/dev/fb0");
        return RC_ERROR;
    }

    if (ioctl(fbFd_, FBIOGET_VSCREENINFO, &vinfo_) < 0) {
        CAMERA_LOGE("main test:cannot retrieve vscreenInfo!");
        close(fbFd_);
        fbFd_ = -1;
        return RC_ERROR;
    }

    if (ioctl(fbFd_, FBIOGET_FSCREENINFO, &finfo_) < 0) {
        CAMERA_LOGE("main test:can't retrieve fscreenInfo!");
        close(fbFd_);
        fbFd_ = -1;
        return RC_ERROR;
    }

    FBLog();

    CAMERA_LOGI("main test:allocating display buffer memory");
    displayBuf_ = DoFbMmap(&fbFd_);
    if (displayBuf_ == nullptr) {
        CAMERA_LOGE("main test:error displayBuf_ mmap error");
        close(fbFd_);
        fbFd_ = -1;
        return RC_ERROR;
    }
    return RC_OK;
}

void TestCameraBase::ProcessImage(unsigned char* p, unsigned char* fbp)
{
    unsigned char* in = p;
    int width = 640; // 640:Displays the size of the width
    int height = 480; // 480:Displays the size of the height
    int istride = 1280; // 1280:Initial value of span
    int x;
    int y;
    int j;
    int y0;
    int u;
    int v;
    int r;
    int g;
    int b;
    int32_t location = 0;
    int xpos = (vinfo_.xres - width) / 2;
    int ypos = (vinfo_.yres - height) / 2;
    int yPos = 0; // 0:Pixel initial value
    int uPos = 1; // 1:Pixel initial value
    int vPos = 3; // 3:Pixel initial value
    int yPosIncrement = 2; // 2:yPos increase value
    int uPosIncrement = 4; // 4:uPos increase value
    int vPosIncrement = 4; // 4:vPos increase value

    for (y = ypos; y < (height + ypos); y++) {
        for (j = 0, x = xpos; j < width; j++, x++) {
            location = (x + vinfo_.xoffset) * (vinfo_.bits_per_pixel / 8) + // 8: The bytes for each time
            (y + vinfo_.yoffset) * finfo_.line_length; // add one y number of rows at a time

            y0 = in[yPos];
            u = in[uPos] - 128; // 128:display size
            v = in[vPos] - 128; // 128:display size

            r = RANGE_LIMIT(y0 + v + ((v * 103) >> 8)); // 103,8:display range
            g = RANGE_LIMIT(y0 - ((u * 88) >> 8) - ((v * 183) >> 8)); // 88,8,183:display range
            b = RANGE_LIMIT(y0 + u + ((u * 198) >> 8)); // 198,8:display range

            fbp[location + 1] = ((r & 0xF8) | (g >> 5)); // 5:display range
            fbp[location + 0] = (((g & 0x1C) << 3) | (b >> 3)); // 3:display range

            yPos += yPosIncrement;

            if (j & 0x01) {
                uPos += uPosIncrement;
                vPos += vPosIncrement;
            }
        }

        yPos = 0; // 0:Pixel initial value
        uPos = 1; // 1:Pixel initial value
        vPos = 3; // 3:Pixel initial value
        in += istride; // add one y number of rows at a time
    }
}

void TestCameraBase::LcdDrawScreen(unsigned char* displayBuf, unsigned char* addr)
{
    ProcessImage(addr, displayBuf);
}

void TestCameraBase::BufferCallback(unsigned char* addr, int choice)
{
    if (choice == PREVIEW_MODE) {
        LcdDrawScreen(displayBuf_, addr);
        return;
    } else {
        LcdDrawScreen(displayBuf_, addr);
        std::cout << "==========[test log] capture start saveYuv......" << std::endl;
        SaveYUV("capture", reinterpret_cast<unsigned char*>(addr), bufSize_);
        std::cout << "==========[test log] capture end saveYuv......" << std::endl;
        return;
    }
}

void TestCameraBase::Init()
{
    CAMERA_LOGD("TestCameraBase::Init().");
    if (cameraHost == nullptr) {
        constexpr const char *demoServiceName = "camera_service";
        cameraHost = ICameraHost::Get(demoServiceName, false);
        CAMERA_LOGI("Camera::CameraHost::CreateCameraHost()");
        if (cameraHost == nullptr) {
            CAMERA_LOGE("CreateCameraHost failed.");
            return;
        }
        CAMERA_LOGI("CreateCameraHost success.");
    }

    OHOS::sptr<DemoCameraHostCallback> cameraHostCallback = new DemoCameraHostCallback();
    OHOS::Camera::RetCode ret = cameraHost->SetCallback(cameraHostCallback);
    if (ret != HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGE("SetCallback failed.");
        return;
    } else {
        CAMERA_LOGI("SetCallback success.");
    }

    if (cameraDevice == nullptr) {
        cameraHost->GetCameraIds(cameraIds);
        cameraHost->GetCameraAbility(cameraIds.front(), ability_);
        MetadataUtils::ConvertVecToMetadata(ability_, ability);
        const OHOS::sptr<DemoCameraDeviceCallback> callback = new DemoCameraDeviceCallback();
        rc = (CamRetCode)cameraHost->OpenCamera(cameraIds.front(), callback, cameraDevice);
        if (rc != HDI::Camera::V1_0::NO_ERROR || cameraDevice == nullptr) {
            CAMERA_LOGE("OpenCamera failed, rc = %{public}d", rc);
            return;
        }
        CAMERA_LOGI("OpenCamera success.");
    }
}

void TestCameraBase::UsbInit()
{
    if (cameraHost == nullptr) {
        constexpr const char *demoServiceName = "camera_service";
        cameraHost = ICameraHost::Get(demoServiceName, false);
        if (cameraHost == nullptr) {
            std::cout << "==========[test log] CreateCameraHost failed." << std::endl;
            return;
        }
        std::cout << "==========[test log] CreateCameraHost success." << std::endl;
    }

    OHOS::sptr<DemoCameraHostCallback> cameraHostCallback = new DemoCameraHostCallback();
    OHOS::Camera::RetCode ret = cameraHost->SetCallback(cameraHostCallback);
    if (ret != HDI::Camera::V1_0::NO_ERROR) {
        std::cout << "==========[test log] SetCallback failed." << std::endl;
        return;
    } else {
        std::cout << "==========[test log] SetCallback success." << std::endl;
    }
}

std::shared_ptr<CameraAbility> TestCameraBase::GetCameraAbility()
{
    if (cameraDevice == nullptr) {
        OHOS::Camera::RetCode ret = cameraHost->GetCameraIds(cameraIds);
        if (ret != HDI::Camera::V1_0::NO_ERROR) {
            std::cout << "==========[test log]GetCameraIds failed." << std::endl;
            return ability;
        } else {
            std::cout << "==========[test log]GetCameraIds success." << std::endl;
        }
        if (cameraIds.size() == 0) {
            std::cout << "==========[test log]camera device list is empty." << std::endl;
            return ability;
        }
        if (cameraIds.size() > 0) {
            ret = cameraHost->GetCameraAbility(cameraIds.back(), ability_);
            if (ret != HDI::Camera::V1_0::NO_ERROR) {
                std::cout << "==========[test log]GetCameraAbility failed, rc = " << rc << std::endl;
            }
            MetadataUtils::ConvertVecToMetadata(ability_, ability);
        }
    }
    return ability;
}

void TestCameraBase::OpenUsbCamera()
{
    if (cameraDevice == nullptr) {
        cameraHost->GetCameraIds(cameraIds);
        if (cameraIds.size() > 0) {
            cameraHost->GetCameraAbility(cameraIds.back(), ability_);
            MetadataUtils::ConvertVecToMetadata(ability_, ability);
            const OHOS::sptr<DemoCameraDeviceCallback> callback = new DemoCameraDeviceCallback();
            rc = (CamRetCode)cameraHost->OpenCamera(cameraIds.back(), callback, cameraDevice);
            if (rc != HDI::Camera::V1_0::NO_ERROR || cameraDevice == nullptr) {
                std::cout << "OpenCamera failed, rc = " << rc << std::endl;
                return;
            }
            std::cout << "OpenCamera success." << std::endl;
        } else {
            std::cout << "No usb camera plugged in" << std::endl;
        }
    }
}

CamRetCode TestCameraBase::SelectOpenCamera(std::string cameraId)
{
    cameraHost->GetCameraAbility(cameraId, ability_);
    MetadataUtils::ConvertVecToMetadata(ability_, ability);
    const OHOS::sptr<DemoCameraDeviceCallback> callback = new DemoCameraDeviceCallback();
    rc = (CamRetCode)cameraHost->OpenCamera(cameraId, callback, cameraDevice);
    if (rc != HDI::Camera::V1_0::NO_ERROR || cameraDevice == nullptr) {
        std::cout << "OpenCamera failed, rc = " << rc << std::endl;
        return rc;
    }
    std::cout << "OpenCamera success." << std::endl;
    return rc;
}

void TestCameraBase::Close()
{
    CAMERA_LOGD("cameraDevice->Close().");
    if (cameraDevice != nullptr) {
        cameraDevice->Close();
        cameraDevice = nullptr;
    }
}

void TestCameraBase::OpenCamera()
{
    if (cameraDevice == nullptr) {
        cameraHost->GetCameraIds(cameraIds);
        const OHOS::sptr<OHOS::Camera::CameraDeviceCallback> callback = new CameraDeviceCallback();
        rc = (CamRetCode)cameraHost->OpenCamera(cameraIds.front(), callback, cameraDevice);
        if (rc != HDI::Camera::V1_0::NO_ERROR || cameraDevice == nullptr) {
            std::cout << "==========[test log] OpenCamera failed, rc = " << rc << std::endl;
            return;
        }
        std::cout << "==========[test log]  OpenCamera success." << std::endl;
    }
}

void TestCameraBase::DefaultInfosPreview()
{
    if (streamCustomerPreview_ == nullptr) {
        streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    streamInfoPre.streamId_ = STREAM_ID_PREVIEW;
    streamInfoPre.width_ = PREVIEW_WIDTH; // 640:picture width
    streamInfoPre.height_ = PREVIEW_HEIGHT; // 480:picture height
    streamInfoPre.format_ = PIXEL_FMT_RGBA_8888;
    streamInfoPre.dataspace_ = 8; // 8:picture dataspace
    streamInfoPre.intent_ = PREVIEW;
    streamInfoPre.tunneledMode_ = 5; // 5:tunnel mode
    streamInfoPre.bufferQueue_ = new BufferProducerSequenceable(streamCustomerPreview_->CreateProducer());
    ASSERT_NE(streamInfoPre.bufferQueue_, nullptr);
    streamInfoPre.bufferQueue_->producer_->SetQueueSize(8); // 8:set bufferQueue size
    std::cout << "preview success1." << std::endl;
    std::vector<StreamInfo>().swap(streamInfos);
    streamInfos.push_back(streamInfoPre);
}

void TestCameraBase::DefaultInfosCapture()
{
    if (streamCustomerCapture_ == nullptr) {
        streamCustomerCapture_ = std::make_shared<StreamCustomer>();
    }
    streamInfoCapture.streamId_ = STREAM_ID_CAPTURE;
    streamInfoCapture.width_ = CAPTURE_WIDTH; // 1280:picture width
    streamInfoCapture.height_ = CAPTURE_HEIGHT; // 960:picture height
    streamInfoCapture.format_ = PIXEL_FMT_RGBA_8888;
    streamInfoCapture.dataspace_ = 8; // 8:picture dataspace
    streamInfoCapture.intent_ = STILL_CAPTURE;
    streamInfoCapture.encodeType_ = ENCODE_TYPE_JPEG;
    streamInfoCapture.tunneledMode_ = 5; // 5:tunnel mode
    streamInfoCapture.bufferQueue_ = new BufferProducerSequenceable(streamCustomerCapture_->CreateProducer());
    ASSERT_NE(streamInfoCapture.bufferQueue_, nullptr);
    streamInfoCapture.bufferQueue_->producer_->SetQueueSize(8); // 8:set bufferQueue size
    std::cout << "capture success1." << std::endl;
    streamInfos.push_back(streamInfoCapture);
}

float TestCameraBase::CalTime(struct timeval start, struct timeval end)
{
    float timeUse = 0;
    timeUse = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec); // 1000000:time
    return timeUse;
}

void TestCameraBase::AchieveStreamOperator()
{
    // Create and get streamOperator information
    OHOS::sptr<DemoStreamOperatorCallback> streamOperatorCallback_ = new DemoStreamOperatorCallback();
    if (cameraDevice == nullptr) {
        CAMERA_LOGI("cameraDevice is nullptr");
        return;
    }
    rc = (CamRetCode)cameraDevice->GetStreamOperator(streamOperatorCallback_, streamOperator);
    EXPECT_EQ(true, rc == HDI::Camera::V1_0::NO_ERROR);
    if (rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("AchieveStreamOperator success.");
    } else {
        CAMERA_LOGE("AchieveStreamOperator fail, rc = %{public}d", rc);
    }
}

void TestCameraBase::StartStream(std::vector<StreamIntent> intents)
{
    for (auto& intent : intents) {
        if (intent == PREVIEW) {
            if (streamCustomerPreview_ == nullptr) {
                streamCustomerPreview_ = std::make_shared<StreamCustomer>();
            }
            streamInfoPre.streamId_ = STREAM_ID_PREVIEW;
            streamInfoPre.width_ = PREVIEW_WIDTH; // 640:picture width
            streamInfoPre.height_ = PREVIEW_HEIGHT; // 480:picture height
            streamInfoPre.format_ = PIXEL_FMT_RGBA_8888;
            streamInfoPre.dataspace_ = 8; // 8:picture dataspace
            streamInfoPre.intent_ = intent;
            streamInfoPre.tunneledMode_ = 5; // 5:tunnel mode
            streamInfoPre.bufferQueue_ = new BufferProducerSequenceable(streamCustomerPreview_->CreateProducer());
            ASSERT_NE(streamInfoPre.bufferQueue_, nullptr);
            streamInfoPre.bufferQueue_->producer_->SetQueueSize(8); // 8:set bufferQueue size
            CAMERA_LOGD("preview success.");
            std::vector<StreamInfo>().swap(streamInfos);
            streamInfos.push_back(streamInfoPre);
        } else if (intent == VIDEO) {
            if (streamCustomerVideo_ == nullptr) {
                streamCustomerVideo_ = std::make_shared<StreamCustomer>();
            }
            streamInfoVideo.streamId_ = STREAM_ID_VIDEO;
            streamInfoVideo.width_ = VIDEO_WIDTH; // 1280:picture width
            streamInfoVideo.height_ = VIDEO_HEIGHT; // 960:picture height
            streamInfoVideo.format_ = PIXEL_FMT_RGBA_8888;
            streamInfoVideo.dataspace_ = 8; // 8:picture dataspace
            streamInfoVideo.intent_ = intent;
            streamInfoVideo.encodeType_ = ENCODE_TYPE_H264;
            streamInfoVideo.tunneledMode_ = 5; // 5:tunnel mode
            streamInfoVideo.bufferQueue_ = new BufferProducerSequenceable(streamCustomerVideo_->CreateProducer());
            ASSERT_NE(streamInfoVideo.bufferQueue_, nullptr);
            streamInfoVideo.bufferQueue_->producer_->SetQueueSize(8); // 8:set bufferQueue size
            CAMERA_LOGD("video success.");
            std::vector<StreamInfo>().swap(streamInfos);
            streamInfos.push_back(streamInfoVideo);
        } else if (intent == STILL_CAPTURE) {
            if (streamCustomerCapture_ == nullptr) {
                streamCustomerCapture_ = std::make_shared<StreamCustomer>();
            }
            streamInfoCapture.streamId_ = STREAM_ID_CAPTURE;
            streamInfoCapture.width_ = CAPTURE_WIDTH; // 1280:picture width
            streamInfoCapture.height_ = CAPTURE_HEIGHT; // 960:picture height
            streamInfoCapture.format_ = PIXEL_FMT_RGBA_8888;
            streamInfoCapture.dataspace_ = 8; // 8:picture dataspace
            streamInfoCapture.intent_ = intent;
            streamInfoCapture.encodeType_ = ENCODE_TYPE_JPEG;
            streamInfoCapture.tunneledMode_ = 5; // 5:tunnel mode
            streamInfoCapture.bufferQueue_ = new BufferProducerSequenceable(streamCustomerCapture_->CreateProducer());
            ASSERT_NE(streamInfoCapture.bufferQueue_, nullptr);
            streamInfoCapture.bufferQueue_->producer_->SetQueueSize(8); // 8:set bufferQueue size
            CAMERA_LOGD("capture success.");
            std::vector<StreamInfo>().swap(streamInfos);
            streamInfos.push_back(streamInfoCapture);
        } else if (intent == ANALYZE) {
            if (streamCustomerAnalyze_ == nullptr) {
                streamCustomerAnalyze_ = std::make_shared<StreamCustomer>();
            }
            streamInfoAnalyze.streamId_ = STREAM_ID_ANALYZE;
            streamInfoAnalyze.width_ = ANALYZE_WIDTH; // 640:picture width
            streamInfoAnalyze.height_ = ANALYZE_HEIGHT; // 480:picture height
            streamInfoAnalyze.format_ = PIXEL_FMT_RGBA_8888;
            streamInfoAnalyze.dataspace_ = 8; // 8:picture dataspace
            streamInfoAnalyze.intent_ = intent;
            streamInfoAnalyze.tunneledMode_ = 5; // 5:tunnel mode
            streamInfoAnalyze.bufferQueue_ = new BufferProducerSequenceable(streamCustomerAnalyze_->CreateProducer());
            ASSERT_NE(streamInfoAnalyze.bufferQueue_, nullptr);
            streamInfoAnalyze.bufferQueue_->producer_->SetQueueSize(8); // 8:set bufferQueue size
            CAMERA_LOGD("analyze success.");
            std::vector<StreamInfo>().swap(streamInfos);
            streamInfos.push_back(streamInfoAnalyze);
        }
        rc = (CamRetCode)streamOperator->CreateStreams(streamInfos);
        EXPECT_EQ(false, rc != HDI::Camera::V1_0::NO_ERROR);
        if (rc == HDI::Camera::V1_0::NO_ERROR) {
            CAMERA_LOGI("CreateStreams success.");
        } else {
            CAMERA_LOGE("CreateStreams fail, rc = %{public}d", rc);
        }

        rc = (CamRetCode)streamOperator->CommitStreams(NORMAL, ability_);
        EXPECT_EQ(false, rc != HDI::Camera::V1_0::NO_ERROR);
        if (rc == HDI::Camera::V1_0::NO_ERROR) {
            CAMERA_LOGI("CommitStreams success.");
        } else {
            CAMERA_LOGE("CommitStreams fail, rc = %{public}d", rc);
        }
    }
}

void TestCameraBase::StartCapture(int streamId, int captureId, bool shutterCallback, bool isStreaming)
{
    // Get preview
    captureInfo.streamIds_ = {streamId};
    captureInfo.captureSetting_ = ability_;
    captureInfo.enableShutterCallback_ = shutterCallback;
    rc = (CamRetCode)streamOperator->Capture(captureId, captureInfo, isStreaming);
    EXPECT_EQ(true, rc == HDI::Camera::V1_0::NO_ERROR);
    if (rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("check Capture: Capture success, captureId = %{public}d", captureId);
    } else {
        CAMERA_LOGE("check Capture: Capture fail, rc = %{public}d, captureId = %{public}d", rc, captureId);
    }
    if (captureId == CAPTURE_ID_PREVIEW) {
        streamCustomerPreview_->ReceiveFrameOn(nullptr);
    } else if (captureId == CAPTURE_ID_CAPTURE) {
        streamCustomerCapture_->ReceiveFrameOn([this](const unsigned char *addr, const uint32_t size) {
            StoreImage(addr, size);
        });
    } else if (captureId == CAPTURE_ID_VIDEO) {
        OpenVideoFile();
        streamCustomerVideo_->ReceiveFrameOn([this](const unsigned char *addr, const uint32_t size) {
            StoreVideo(addr, size);
        });
    } else if (captureId == CAPTURE_ID_ANALYZE) {
        streamCustomerAnalyze_->ReceiveFrameOn([this](const unsigned char *addr, const uint32_t size) {
            PrintFaceDetectInfo(addr, size);
        });
    }
    sleep(2); // 2:sleep two second
}

void TestCameraBase::StopStream(std::vector<int>& captureIds, std::vector<int>& streamIds)
{
    constexpr uint32_t timeForWaitCancelCapture = 2;
    sleep(timeForWaitCancelCapture);
    if (captureIds.size() > 0) {
        for (const auto &captureId : captureIds) {
            if (captureId == CAPTURE_ID_PREVIEW) {
                streamCustomerPreview_->ReceiveFrameOff();
            } else if (captureId == CAPTURE_ID_CAPTURE) {
                streamCustomerCapture_->ReceiveFrameOff();
            } else if (captureId == CAPTURE_ID_VIDEO) {
                streamCustomerVideo_->ReceiveFrameOff();
                sleep(1);
                CloseFd();
            } else if (captureId == CAPTURE_ID_ANALYZE) {
                streamCustomerAnalyze_->ReceiveFrameOff();
            }
        }
        for (const auto &captureId : captureIds) {
            CAMERA_LOGI("check Capture: CancelCapture success, captureId = %{public}d", captureId);
            rc = (CamRetCode)streamOperator->CancelCapture(captureId);
            sleep(timeForWaitCancelCapture);
            EXPECT_EQ(true, rc == HDI::Camera::V1_0::NO_ERROR);
            if (rc == HDI::Camera::V1_0::NO_ERROR) {
                CAMERA_LOGI("check Capture: CancelCapture success, captureId = %{public}d", captureId);
            } else {
                CAMERA_LOGE("check Capture: CancelCapture fail, rc = %{public}d, captureId = %{public}d",
                    rc, captureId);
            }
        }
    }
    sleep(1);
    if (streamIds.size() > 0) {
        // release stream
        rc = (CamRetCode)streamOperator->ReleaseStreams(streamIds);
        EXPECT_EQ(true, rc == HDI::Camera::V1_0::NO_ERROR);
        if (rc == HDI::Camera::V1_0::NO_ERROR) {
            CAMERA_LOGI("check Capture: ReleaseStreams success.");
        } else {
            CAMERA_LOGE("check Capture: ReleaseStreams fail, rc = %{public}d, streamIds = %{public}d",
                rc, streamIds.front());
        }
    }
}

void DemoCameraDeviceCallback::PrintStabiliInfo(const std::vector<uint8_t>& result)
{
    std::shared_ptr<CameraMetadata> metaData;
    MetadataUtils::ConvertVecToMetadata(result, metaData);

    if (metaData == nullptr) {
        CAMERA_LOGE("TestCameraBase: result is null");
        return;
    }
    common_metadata_header_t* data = metaData->get();
    if (data == nullptr) {
        CAMERA_LOGE("TestCameraBase: data is null");
        return;
    }
    uint8_t videoStabiliMode;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &entry);
    if (ret != 0) {
        CAMERA_LOGE("demo test: get OHOS_CONTROL_EXPOSURE_MODE error");
        return;
    }
    videoStabiliMode = *(entry.data.u8);
    CAMERA_LOGI("videoStabiliMode: %{public}d", static_cast<int>(videoStabiliMode));
}

void DemoCameraDeviceCallback::PrintFpsInfo(const std::vector<uint8_t>& result)
{
    std::shared_ptr<CameraMetadata> metaData;
    MetadataUtils::ConvertVecToMetadata(result, metaData);

    if (metaData == nullptr) {
        CAMERA_LOGE("TestCameraBase: result is null");
        return;
    }
    common_metadata_header_t* data = metaData->get();
    if (data == nullptr) {
        CAMERA_LOGE("TestCameraBase: data is null");
        return;
    }
    std::vector<int32_t> fpsRange;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_FPS_RANGES, &entry);
    if (ret != 0) {
        CAMERA_LOGE("demo test: get OHOS_CONTROL_EXPOSURE_MODE error");
        return;
    }

    for (int i = 0; i < entry.count; i++) {
        fpsRange.push_back(*(entry.data.i32 + i));
    }
    CAMERA_LOGI("PrintFpsInfo fpsRange: [%{public}d, %{public}d]", fpsRange[0], fpsRange[1]);
}

#ifndef CAMERA_BUILT_ON_OHOS_LITE
int32_t DemoCameraDeviceCallback::OnError(ErrorType type, int32_t errorCode)
{
    CAMERA_LOGI("demo test: OnError type : %{public}d, errorMsg : %{public}d", type, errorCode);
}

int32_t DemoCameraDeviceCallback::OnResult(uint64_t timestamp, const std::vector<uint8_t>& result)
{
    CAMERA_LOGI("%{public}s, enter.", __func__);
    PrintStabiliInfo(result);
    PrintFpsInfo(result);
    DealCameraMetadata(result);
    return RC_OK;
}

int32_t DemoCameraHostCallback::OnCameraStatus(const std::string& cameraId, CameraStatus status)
{
    CAMERA_LOGI("%{public}s, enter.", __func__);
    std::cout << "OnCameraStatus, enter, cameraId = " << cameraId << ", status = " << status << std::endl;
    return RC_OK;
}

int32_t DemoCameraHostCallback::OnFlashlightStatus(const std::string& cameraId, FlashlightStatus status)
{
    CAMERA_LOGI("%{public}s, enter. cameraId = %s, status = %d",
        __func__, cameraId.c_str(), static_cast<int>(status));
    return RC_OK;
}

int32_t DemoCameraHostCallback::OnCameraEvent(const std::string& cameraId, CameraEvent event)
{
    CAMERA_LOGI("%{public}s, enter. cameraId = %s, event = %d",
        __func__, cameraId.c_str(), static_cast<int>(event));
    std::cout << "OnCameraEvent, enter, cameraId = " << cameraId << ", event = " << event<< std::endl;
    return RC_OK;
}

int32_t DemoStreamOperatorCallback::OnCaptureStarted(int32_t captureId, const std::vector<int32_t>& streamIds)
{
    CAMERA_LOGI("%{public}s, enter.", __func__);
    return RC_OK;
}

int32_t DemoStreamOperatorCallback::OnCaptureEnded(int32_t captureId, const std::vector<CaptureEndedInfo>& infos)
{
    CAMERA_LOGI("%{public}s, enter.", __func__);
    return RC_OK;
}

void DemoCameraDeviceCallback::DealCameraMetadata(const std::vector<uint8_t> &settings)
{
    std::shared_ptr<CameraMetadata> result;
    MetadataUtils::ConvertVecToMetadata(settings, result);
    if (result == nullptr) {
        CAMERA_LOGE("TestCameraBase: result is null");
        return;
    }
    common_metadata_header_t *data = result->get();
    if (data == nullptr) {
        CAMERA_LOGE("data is null");
        return;
    }
    for (auto it = DATA_BASE.cbegin(); it != DATA_BASE.cend(); it++) {
        std::string st = {};
        st = MetadataItemDump(data, *it);
        CAMERA_LOGI("%{publid}s", st.c_str());
    }
}

int32_t DemoStreamOperatorCallback::OnCaptureError(int32_t captureId, const std::vector<CaptureErrorInfo>& infos)
{
    CAMERA_LOGI("%{public}s, enter.", __func__);
    return RC_OK;
}

int32_t DemoStreamOperatorCallback::OnFrameShutter(int32_t captureId,
    const std::vector<int32_t>& streamIds, uint64_t timestamp)
{
    CAMERA_LOGI("%{public}s, enter.", __func__);
    return RC_OK;
}

#endif
