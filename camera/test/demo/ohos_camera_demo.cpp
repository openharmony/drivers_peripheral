/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "ohos_camera_demo.h"
#include "metadata_utils.h"

namespace OHOS::Camera {
OhosCameraDemo::OhosCameraDemo() {}
OhosCameraDemo::~OhosCameraDemo() {}

std::vector<int32_t> results_list_;

const int32_t METER_POINT_X = 305;
const int32_t METER_POINT_Y = 205;
const int32_t AF_REGIONS_X = 400;
const int32_t AF_REGIONS_Y = 200;
const int32_t FPS_RANGE = 30;

void OhosCameraDemo::SetStreamInfo(StreamInfo& streamInfo,
    const std::shared_ptr<StreamCustomer> &streamCustomer,
    const int streamId, const StreamIntent intent)
{
    constexpr uint32_t dataspace = 8;
    constexpr uint32_t tunneledMode = 5;
    sptr<OHOS::IBufferProducer> producer;

    if (intent == PREVIEW) {
        constexpr uint32_t width = CAMERA_PREVIEW_WIDTH;
        constexpr uint32_t height = CAMERA_PREVIEW_HEIGHT;
        streamInfo.width_ = width;
        streamInfo.height_ = height;
    } else if (intent == STILL_CAPTURE) {
        constexpr uint32_t width = CAMERA_CAPTURE_WIDTH;
        constexpr uint32_t height = CAMERA_CAPTURE_HEIGHT;
        streamInfo.width_ = width;
        streamInfo.height_ = height;
        streamInfo.encodeType_ = CAMERA_CAPTURE_ENCODE_TYPE;
    } else {
        constexpr uint32_t width = CAMERA_VIDEO_WIDTH;
        constexpr uint32_t height = CAMERA_VIDEO_HEIGHT;
        streamInfo.width_ = width;
        streamInfo.height_ = height;
        streamInfo.encodeType_ = CAMERA_VIDEO_ENCODE_TYPE;
    }

    streamInfo.streamId_ = streamId;
    streamInfo.format_ =  CAMERA_FORMAT;
    streamInfo.dataspace_ = dataspace;
    streamInfo.intent_ = intent;
    streamInfo.tunneledMode_ = tunneledMode;

    producer = streamCustomer->CreateProducer();
    streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    CHECK_IF_PTR_NULL_RETURN_VOID(streamInfo.bufferQueue_);
    streamInfo.bufferQueue_->producer_->SetQueueSize(8); // 8:set bufferQueue size
}

void OhosCameraDemo::GetStreamOpt()
{
    if (streamOperator_ == nullptr) {
#ifdef CAMERA_BUILT_ON_OHOS_LITE
        const std::shared_ptr<IStreamOperatorCallback> streamOperatorCallback =
            std::make_shared<DemoStreamOperatorCallback>();
#else
        const sptr<IStreamOperatorCallback> streamOperatorCallback = new DemoStreamOperatorCallback();
#endif
        int rc = demoCameraDevice_->GetStreamOperator(streamOperatorCallback, streamOperator_);
        if (rc != HDI::Camera::V1_0::NO_ERROR) {
            CAMERA_LOGE("demo test: GetStreamOpt GetStreamOperator fail");
            streamOperator_ = nullptr;
        }
    }
}

RetCode OhosCameraDemo::CaptureON(const int streamId,
    const int captureId, CaptureMode mode)
{
    CAMERA_LOGI("demo test: CaptureON enter streamId == %{public}d and captureId == %{public}d and mode == %{public}d",
        streamId, captureId, mode);
    std::lock_guard<std::mutex> l(metaDatalock_);
    if (mode == CAPTURE_SNAPSHOT) {
        constexpr double latitude = 27.987500; // dummy data: Qomolangma latitde
        constexpr double longitude = 86.927500; // dummy data: Qomolangma longituude
        constexpr double altitude = 8848.86; // dummy data: Qomolangma altitude
        constexpr size_t entryCapacity = 100;
        constexpr size_t dataCapacity = 2000;
        captureSetting_ = std::make_shared<CameraSetting>(entryCapacity, dataCapacity);
        captureQuality_ = OHOS_CAMERA_JPEG_LEVEL_HIGH;
        captureOrientation_ = OHOS_CAMERA_JPEG_ROTATION_270;
        mirrorSwitch_ = OHOS_CAMERA_MIRROR_ON;
        gps_.push_back(latitude);
        gps_.push_back(longitude);
        gps_.push_back(altitude);
        captureSetting_->addEntry(OHOS_JPEG_QUALITY, static_cast<void*>(&captureQuality_),
            sizeof(captureQuality_));
        captureSetting_->addEntry(OHOS_JPEG_ORIENTATION, static_cast<void*>(&captureOrientation_),
            sizeof(captureOrientation_));
        captureSetting_->addEntry(OHOS_CONTROL_CAPTURE_MIRROR, static_cast<void*>(&mirrorSwitch_),
            sizeof(mirrorSwitch_));
        captureSetting_->addEntry(OHOS_JPEG_GPS_COORDINATES, gps_.data(), gps_.size());
    }

    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(captureSetting_, setting);
    captureInfo_.streamIds_ = {streamId};
    if (mode == CAPTURE_SNAPSHOT) {
        captureInfo_.captureSetting_ = setting;
    } else {
        captureInfo_.captureSetting_ = cameraAbility_;
    }
    captureInfo_.enableShutterCallback_ = false;

    int rc = streamOperator_->Capture(captureId, captureInfo_, true);
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGE("demo test: CaptureStart Capture error");
        streamOperator_->ReleaseStreams(captureInfo_.streamIds_);
        return RC_ERROR;
    }

    if (mode == CAPTURE_PREVIEW) {
        streamCustomerPreview_->ReceiveFrameOn(nullptr);
    } else if (mode == CAPTURE_SNAPSHOT) {
        streamCustomerCapture_->ReceiveFrameOn([this](void* addr, const uint32_t size) {
            StoreImage(addr, size);
        });
    } else if (mode == CAPTURE_VIDEO) {
        OpenVideoFile();

        streamCustomerVideo_->ReceiveFrameOn([this](void* addr, const uint32_t size) {
            StoreVideo(addr, size);
        });
    }
    CAMERA_LOGD("demo test: CaptureON exit");

    return RC_OK;
}

RetCode OhosCameraDemo::CaptureOff(const int captureId, const CaptureMode mode)
{
    int rc = 0;
    CAMERA_LOGD("demo test: CaptureOff enter mode == %{public}d", mode);

    if (streamOperator_ == nullptr) {
        CAMERA_LOGE("demo test: CaptureOff streamOperator_ is nullptr");
        return RC_ERROR;
    }

    if (mode == CAPTURE_PREVIEW) {
        streamCustomerPreview_->ReceiveFrameOff();
        rc = streamOperator_->CancelCapture(captureId);
    } else if (mode == CAPTURE_SNAPSHOT) {
        streamCustomerCapture_->ReceiveFrameOff();
        rc = streamOperator_->CancelCapture(captureId);
    } else if (mode == CAPTURE_VIDEO) {
        streamCustomerVideo_->ReceiveFrameOff();
        rc = streamOperator_->CancelCapture(captureId);
        close(videoFd_);
        videoFd_ = -1;
    }

    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGE("demo test: CaptureOff CancelCapture error mode %{public}d rc == %{public}d", mode, rc);
        return RC_ERROR;
    }
    CAMERA_LOGD("demo test: CaptureOff exit");

    return RC_OK;
}

RetCode OhosCameraDemo::CreateStream(const int streamId, std::shared_ptr<StreamCustomer> &streamCustomer,
    StreamIntent intent)
{
    int rc = 0;
    CAMERA_LOGD("demo test: CreateStream enter");

    GetStreamOpt();
    if (streamOperator_ == nullptr) {
        CAMERA_LOGE("demo test: CreateStream GetStreamOpt() is nullptr");
        return RC_ERROR;
    }

    StreamInfo streamInfo = {0};

    SetStreamInfo(streamInfo, streamCustomer, streamId, intent);
    if (streamInfo.bufferQueue_->producer_ == nullptr) {
        CAMERA_LOGE("demo test: CreateStream CreateProducer(); is nullptr");
        return RC_ERROR;
    }

    std::vector<StreamInfo> streamInfos;
    streamInfos.push_back(streamInfo);

    rc = streamOperator_->CreateStreams(streamInfos);
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGE("demo test: CreateStream CreateStreams error");
        return RC_ERROR;
    }

    rc = streamOperator_->CommitStreams(NORMAL, cameraAbility_);
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGE("demo test: CreateStream CommitStreams error");
        std::vector<int> streamIds;
        streamIds.push_back(streamId);
        streamOperator_->ReleaseStreams(streamIds);
        return RC_ERROR;
    }

    CAMERA_LOGD("demo test: CreateStream exit");

    return RC_OK;
}

RetCode OhosCameraDemo::InitCameraDevice()
{
    int rc = 0;

    CAMERA_LOGD("demo test: InitCameraDevice enter");

    if (demoCameraHost_ == nullptr) {
        CAMERA_LOGE("demo test: InitCameraDevice demoCameraHost_ == nullptr");
        return RC_ERROR;
    }

    (void)demoCameraHost_->GetCameraIds(cameraIds_);
    if (cameraIds_.empty()) {
        return RC_ERROR;
    }
    const std::string cameraId = cameraIds_.front();
    demoCameraHost_->GetCameraAbility(cameraId, cameraAbility_);

    MetadataUtils::ConvertVecToMetadata(cameraAbility_, ability_);

    GetFaceDetectMode(ability_);
    GetFocalLength(ability_);
    GetAvailableFocusModes(ability_);
    GetAvailableExposureModes(ability_);
    GetExposureCompensationRange(ability_);
    GetExposureCompensationSteps(ability_);
    GetAvailableMeterModes(ability_);
    GetAvailableFlashModes(ability_);
    GetMirrorSupported(ability_);
    GetStreamBasicConfigurations(ability_);
    GetFpsRange(ability_);
    GetCameraPosition(ability_);
    GetCameraType(ability_);
    GetCameraConnectionType(ability_);
    GetFaceDetectMaxNum(ability_);

#ifdef CAMERA_BUILT_ON_OHOS_LITE
    std::shared_ptr<CameraDeviceCallback> callback = std::make_shared<CameraDeviceCallback>();
#else
    sptr<DemoCameraDeviceCallback> callback = new DemoCameraDeviceCallback();
#endif
    rc = demoCameraHost_->OpenCamera(cameraIds_.front(), callback, demoCameraDevice_);
    if (rc != HDI::Camera::V1_0::NO_ERROR || demoCameraDevice_ == nullptr) {
        CAMERA_LOGE("demo test: InitCameraDevice OpenCamera failed");
        return RC_ERROR;
    }

    CAMERA_LOGD("demo test: InitCameraDevice exit");

    return RC_OK;
}

void OhosCameraDemo::ReleaseCameraDevice()
{
    if (demoCameraDevice_ != nullptr) {
        CAMERA_LOGD("demo test: ReleaseCameraDevice close Device");
        demoCameraDevice_->Close();
        demoCameraDevice_ = nullptr;
    }
}

RetCode OhosCameraDemo::InitSensors()
{
    int rc = 0;

    CAMERA_LOGD("demo test: InitSensors enter");

    if (demoCameraHost_ != nullptr) {
        return RC_OK;
    }
#ifdef CAMERA_BUILT_ON_OHOS_LITE
    demoCameraHost_ = OHOS::Camera::CameraHost::CreateCameraHost();
#else
    constexpr const char *DEMO_SERVICE_NAME = "camera_service";
    demoCameraHost_ = ICameraHost::Get(DEMO_SERVICE_NAME, false);
#endif
    if (demoCameraHost_ == nullptr) {
        CAMERA_LOGE("demo test: ICameraHost::Get error");
        return RC_ERROR;
    }

#ifdef CAMERA_BUILT_ON_OHOS_LITE
    hostCallback_ = std::make_shared<DemoCameraHostCallback>();
#else
    hostCallback_ = new DemoCameraHostCallback();
#endif
    rc = demoCameraHost_->SetCallback(hostCallback_);
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGE("demo test: demoCameraHost_->SetCallback(hostCallback_) error");
        return RC_ERROR;
    }

    CAMERA_LOGD("demo test: InitSensors exit");

    return RC_OK;
}

void OhosCameraDemo::StoreImage(const void *bufStart, const uint32_t size) const
{
    constexpr uint32_t pathLen = 64;
    char path[pathLen] = {0};
#ifdef CAMERA_BUILT_ON_OHOS_LITE
    char prefix[] = "/userdata/photo/";
#else
    char prefix[] = "/data/";
#endif

    int imgFD = 0;
    int ret;

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

void OhosCameraDemo::StoreVideo(const void *bufStart, const uint32_t size) const
{
    int ret = 0;

    ret = write(videoFd_, bufStart, size);
    if (ret == -1) {
        CAMERA_LOGE("demo test:write video file error %{public}s.....", strerror(errno));
    }
    CAMERA_LOGD("demo test:StoreVideo size == %{public}d", size);
}

void OhosCameraDemo::OpenVideoFile()
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

RetCode OhosCameraDemo::CreateStreams(const int streamIdSecond, StreamIntent intent)
{
    int rc = 0;
    std::vector<StreamInfo> streamInfos;
    std::vector<StreamInfo>().swap(streamInfos);

    CAMERA_LOGD("demo test: CreateStreams streamIdSecond = %{public}d", streamIdSecond);
    GetStreamOpt();
    if (streamOperator_ == nullptr) {
        CAMERA_LOGE("demo test: CreateStreams GetStreamOpt() is nullptr");
        return RC_ERROR;
    }

    StreamInfo previewStreamInfo = {0};

    SetStreamInfo(previewStreamInfo, streamCustomerPreview_, STREAM_ID_PREVIEW, PREVIEW);
    if (previewStreamInfo.bufferQueue_->producer_ == nullptr) {
        CAMERA_LOGE("demo test: CreateStream CreateProducer(); is nullptr");
        return RC_ERROR;
    }
    streamInfos.push_back(previewStreamInfo);

    StreamInfo secondStreamInfo = {0};

    if (streamIdSecond == STREAM_ID_CAPTURE) {
        SetStreamInfo(secondStreamInfo, streamCustomerCapture_, STREAM_ID_CAPTURE, intent);
    } else {
        SetStreamInfo(secondStreamInfo, streamCustomerVideo_, STREAM_ID_VIDEO, intent);
    }

    if (secondStreamInfo.bufferQueue_->producer_ == nullptr) {
        CAMERA_LOGE("demo test: CreateStreams CreateProducer() secondStreamInfo is nullptr");
        return RC_ERROR;
    }
    streamInfos.push_back(secondStreamInfo);

    rc = streamOperator_->CreateStreams(streamInfos);
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGE("demo test: CreateStream CreateStreams error");
        return RC_ERROR;
    }

    rc = streamOperator_->CommitStreams(NORMAL, cameraAbility_);
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGE("demo test: CreateStream CommitStreams error");
        std::vector<int> streamIds = {STREAM_ID_PREVIEW, streamIdSecond};
        streamOperator_->ReleaseStreams(streamIds);
        return RC_ERROR;
    }

    return RC_OK;
}

RetCode OhosCameraDemo::CaptureOnDualStreams(const int streamIdSecond)
{
    int rc = 0;
    CAMERA_LOGD("demo test: CaptuCaptureOnDualStreamsreON enter");

    CaptureInfo previewCaptureInfo;
    previewCaptureInfo.streamIds_ = {STREAM_ID_PREVIEW};
    previewCaptureInfo.captureSetting_ = cameraAbility_;
    previewCaptureInfo.enableShutterCallback_ = false;

    rc = streamOperator_->Capture(CAPTURE_ID_PREVIEW, previewCaptureInfo, true);
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGE("demo test: CaptureOnDualStreams preview Capture error");
        streamOperator_->ReleaseStreams(previewCaptureInfo.streamIds_);
        return RC_ERROR;
    }
    streamCustomerPreview_->ReceiveFrameOn(nullptr);

    CaptureInfo secondCaptureInfo;
    secondCaptureInfo.streamIds_ = {streamIdSecond};
    secondCaptureInfo.captureSetting_ = cameraAbility_;
    secondCaptureInfo.enableShutterCallback_ = false;

    if (streamIdSecond == STREAM_ID_CAPTURE) {
        rc = streamOperator_->Capture(CAPTURE_ID_CAPTURE, secondCaptureInfo, true);
        if (rc != HDI::Camera::V1_0::NO_ERROR) {
            CAMERA_LOGE("demo test: CaptureOnDualStreams CAPTURE_ID_CAPTURE error");
            streamOperator_->ReleaseStreams(secondCaptureInfo.streamIds_);
            return RC_ERROR;
        }

        streamCustomerCapture_->ReceiveFrameOn([this](void *addr, const uint32_t size) {
            StoreImage(addr, size);
        });
    } else {
        rc = streamOperator_->Capture(CAPTURE_ID_VIDEO, secondCaptureInfo, true);
        if (rc != HDI::Camera::V1_0::NO_ERROR) {
            CAMERA_LOGE("demo test: CaptureOnDualStreams CAPTURE_ID_VIDEO error");
            streamOperator_->ReleaseStreams(secondCaptureInfo.streamIds_);
            return RC_ERROR;
        }

        OpenVideoFile();
        streamCustomerVideo_->ReceiveFrameOn([this](void* addr, const uint32_t size) {
            StoreVideo(addr, size);
        });
    }

    CAMERA_LOGD("demo test: CaptuCaptureOnDualStreamsreON exit");

    return RC_OK;
}

RetCode OhosCameraDemo::StartDualStreams(const int streamIdSecond)
{
    RetCode rc = RC_OK;

    CAMERA_LOGD("demo test: StartDualStreams enter");

    if (streamCustomerPreview_ == nullptr) {
        streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }
    if (isPreviewOn_ != 0) {
        return RC_OK;
    }
    isPreviewOn_ = 1;
    if (streamIdSecond == STREAM_ID_CAPTURE) {
        if (streamCustomerCapture_ == nullptr) {
            streamCustomerCapture_ = std::make_shared<StreamCustomer>();
        }

        if (isCaptureOn_ == 0) {
            isCaptureOn_ = 1;
            rc = CreateStreams(streamIdSecond, STILL_CAPTURE);
            if (rc != RC_OK) {
                CAMERA_LOGE("demo test:StartPreviewStream CreateStreams error");
                return RC_ERROR;
            }
        }
    } else {
        if (streamCustomerVideo_ == nullptr) {
            streamCustomerVideo_ = std::make_shared<StreamCustomer>();
        }

        if (isVideoOn_ == 0) {
            isVideoOn_ = 1;
            rc = CreateStreams(streamIdSecond, VIDEO);
            if (rc != RC_OK) {
                CAMERA_LOGE("demo test:StartPreviewStream CreateStreams error");
                return RC_ERROR;
            }
        }
    }

    CAMERA_LOGD("demo test: StartDualStreams exit");

    return RC_OK;
}

RetCode OhosCameraDemo::StartCaptureStream()
{
    RetCode rc = RC_OK;

    CAMERA_LOGD("demo test: StartCaptureStream enter");
    if (streamCustomerCapture_ == nullptr) {
        streamCustomerCapture_ = std::make_shared<StreamCustomer>();
    }

    if (isCaptureOn_ == 0) {
        isCaptureOn_ = 1;

        rc = CreateStream(STREAM_ID_CAPTURE, streamCustomerCapture_, STILL_CAPTURE);
        if (rc != RC_OK) {
            CAMERA_LOGE("demo test:StartCaptureStream CreateStream error");
            return RC_ERROR;
        }
    }

    CAMERA_LOGD("demo test: StartCaptureStream exit");

    return RC_OK;
}

RetCode OhosCameraDemo::StartVideoStream()
{
    RetCode rc = RC_OK;

    CAMERA_LOGD("demo test: StartVideoStream enter");
    if (streamCustomerVideo_ == nullptr) {
        streamCustomerVideo_ = std::make_shared<StreamCustomer>();
    }

    if (isVideoOn_ == 0) {
        isVideoOn_ = 1;

        rc = CreateStream(STREAM_ID_VIDEO, streamCustomerVideo_, VIDEO);
        if (rc != RC_OK) {
            CAMERA_LOGE("demo test:StartVideoStream CreateStream error");
            return RC_ERROR;
        }
    }

    CAMERA_LOGD("demo test: StartVideoStream exit");

    return RC_OK;
}

RetCode OhosCameraDemo::StartPreviewStream()
{
    RetCode rc = RC_OK;

    CAMERA_LOGD("demo test: StartPreviewStream enter");

    if (streamCustomerPreview_ == nullptr) {
        streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }

    if (isPreviewOn_ == 0) {
        isPreviewOn_ = 1;

        rc = CreateStream(STREAM_ID_PREVIEW, streamCustomerPreview_, PREVIEW);
        if (rc != RC_OK) {
            CAMERA_LOGE("demo test:StartPreviewStream CreateStream error");
            return RC_ERROR;
        }
    }

    CAMERA_LOGD("demo test: StartPreviewStream exit");

    return RC_OK;
}

RetCode OhosCameraDemo::ReleaseAllStream()
{
    std::vector<int> streamIds;

    CAMERA_LOGD("demo test: ReleaseAllStream enter");

    if (isPreviewOn_ != 1) {
        CAMERA_LOGE("demo test: ReleaseAllStream preview is not running");
        return RC_ERROR;
    }

    if (isCaptureOn_ == 1) {
        CAMERA_LOGD("demo test: ReleaseAllStream STREAM_ID_PREVIEW STREAM_ID_CAPTURE");
        streamIds = {STREAM_ID_PREVIEW, STREAM_ID_CAPTURE};
        streamOperator_->ReleaseStreams(streamIds);
    } else {
        CAMERA_LOGD("demo test: ReleaseAllStream STREAM_ID_PREVIEW STREAM_ID_VIDEO");
        streamIds = {STREAM_ID_PREVIEW, STREAM_ID_VIDEO};
        streamOperator_->ReleaseStreams(streamIds);
    }

    isPreviewOn_ = 0;
    isCaptureOn_ = 0;
    isVideoOn_ = 0;

    CAMERA_LOGD("demo test: ReleaseAllStream exit");

    return RC_OK;
}

void OhosCameraDemo::QuitDemo()
{
    ReleaseCameraDevice();
    CAMERA_LOGD("demo test: QuitDemo done");
}

void OhosCameraDemo::SetEnableResult()
{
    CAMERA_LOGI("demo test: SetEnableResult enter");

    results_list_.push_back(OHOS_CONTROL_EXPOSURE_MODE);
    results_list_.push_back(OHOS_CONTROL_FOCUS_MODE);
    demoCameraDevice_->EnableResult(results_list_);

    CAMERA_LOGI("demo test: SetEnableResult exit");
}

void OhosCameraDemo::SetAwbMode(const int mode) const
{
    CAMERA_LOGD("demo test: SetAwbMode enter");

    constexpr size_t entryCapacity = 100;
    constexpr size_t dataCapacity = 2000;

    std::shared_ptr<CameraSetting> metaData = std::make_shared<CameraSetting>(entryCapacity, dataCapacity);
    std::vector<uint8_t> result;

    const uint8_t awbMode = mode;
    metaData->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);
    MetadataUtils::ConvertMetadataToVec(metaData, result);
    demoCameraDevice_->UpdateSettings(result);

    CAMERA_LOGD("demo test: SetAwbMode exit");
}

void OhosCameraDemo::SetAeExpo()
{
    int32_t expo;

    CAMERA_LOGD("demo test: SetAeExpo enter");

    constexpr size_t entryCapacity = 100;
    constexpr size_t dataCapacity = 2000;

    std::shared_ptr<CameraSetting> metaData = std::make_shared<CameraSetting>(entryCapacity, dataCapacity);
    std::vector<uint8_t> result;

    if (aeStatus_) {
        expo = 0xa0;
    } else {
        expo = 0x30;
    }
    aeStatus_ = !aeStatus_;
    metaData->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &expo, 1);
    MetadataUtils::ConvertMetadataToVec(metaData, result);
    demoCameraDevice_->UpdateSettings(result);

    CAMERA_LOGD("demo test: SetAeExpo exit");
}

void OhosCameraDemo::SetMetadata()
{
    CAMERA_LOGI("demo test: SetMetadata enter");
    constexpr size_t entryCapacity = 100;
    constexpr size_t dataCapacity = 2000;
    std::shared_ptr<CameraSetting> metaData = std::make_shared<CameraSetting>(entryCapacity, dataCapacity);

    // awb
    SetAwbMode(OHOS_CAMERA_AWB_MODE_INCANDESCENT);

    // ae
    uint8_t aeMode = OHOS_CAMERA_EXPOSURE_MODE_CONTINUOUS_AUTO;
    metaData->addEntry(OHOS_CONTROL_EXPOSURE_MODE, &aeMode, sizeof(aeMode));

    int64_t exposureTime = 400;
    metaData->addEntry(OHOS_SENSOR_EXPOSURE_TIME, &exposureTime, sizeof(exposureTime));

    int32_t aeExposureCompensation = 4;
    metaData->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &aeExposureCompensation, sizeof(aeExposureCompensation));

    // meter
    std::vector<int32_t> meterPoint;
    meterPoint.push_back(METER_POINT_X);
    meterPoint.push_back(METER_POINT_Y);
    metaData->addEntry(OHOS_CONTROL_METER_POINT, meterPoint.data(), meterPoint.size());

    uint8_t meterMode = OHOS_CAMERA_OVERALL_METERING;
    metaData->addEntry(OHOS_CONTROL_METER_MODE, &meterMode, sizeof(meterMode));

    // flash
    uint8_t flashMode = OHOS_CAMERA_FLASH_MODE_ALWAYS_OPEN;
    metaData->addEntry(OHOS_CONTROL_FLASH_MODE, &flashMode, sizeof(flashMode));

    // mirror
    uint8_t mirror = OHOS_CAMERA_MIRROR_ON;
    metaData->addEntry(OHOS_CONTROL_CAPTURE_MIRROR, &mirror, sizeof(mirror));

    // fps
    std::vector<int32_t> fpsRange;
    fpsRange.push_back(FPS_RANGE);
    fpsRange.push_back(FPS_RANGE);
    metaData->addEntry(OHOS_CONTROL_FPS_RANGES, fpsRange.data(), fpsRange.size());

    // jpeg
    int32_t orientation = OHOS_CAMERA_JPEG_ROTATION_180;
    metaData->addEntry(OHOS_JPEG_ORIENTATION, &orientation, sizeof(orientation));

    uint8_t quality = OHOS_CAMERA_JPEG_LEVEL_HIGH;
    metaData->addEntry(OHOS_JPEG_QUALITY, &quality, sizeof(quality));

    // af
    uint8_t afMode = OHOS_CAMERA_FOCUS_MODE_AUTO;
    metaData->addEntry(OHOS_CONTROL_FOCUS_MODE, &afMode, sizeof(afMode));

    std::vector<int32_t> afRegions;
    afRegions.push_back(AF_REGIONS_X);
    afRegions.push_back(AF_REGIONS_Y);
    metaData->addEntry(OHOS_CONTROL_AF_REGIONS, afRegions.data(), afRegions.size());

    // face
    uint8_t faceMode = OHOS_CAMERA_FACE_DETECT_MODE_SIMPLE;
    metaData->addEntry(OHOS_STATISTICS_FACE_DETECT_SWITCH, &faceMode, sizeof(faceMode));

    std::vector<uint8_t> result;
    MetadataUtils::ConvertMetadataToVec(metaData, result);
    demoCameraDevice_->UpdateSettings(result);

    CAMERA_LOGI("demo test: SetMetadata exit");
}

void OhosCameraDemo::FlashlightOnOff(bool onOff)
{
    CAMERA_LOGD("demo test: FlashlightOnOff enter");

    if (demoCameraHost_ == nullptr) {
        CAMERA_LOGE("demo test: FlashlightOnOff demoCameraHost_ == nullptr");
        return;
    }

    demoCameraHost_->SetFlashlight(cameraIds_.front(), onOff);

    CAMERA_LOGD("demo test: FlashlightOnOff exit ");
}

RetCode OhosCameraDemo::StreamOffline(const int streamId)
{
    int rc = 0;
    constexpr size_t offlineDelayTime = 4;
    CAMERA_LOGD("demo test: StreamOffline enter");
#ifdef CAMERA_BUILT_ON_OHOS_LITE
    std::shared_ptr<IStreamOperatorCallback> streamOperatorCallback = std::make_shared<DemoStreamOperatorCallback>();
    std::shared_ptr<IOfflineStreamOperator> offlineStreamOperator = nullptr;
#else
    sptr<IStreamOperatorCallback> streamOperatorCallback = new DemoStreamOperatorCallback();
    sptr<IOfflineStreamOperator> offlineStreamOperator = nullptr;
#endif
    std::vector<int> streamIds;
    streamIds.push_back(streamId);
    rc = streamOperator_->ChangeToOfflineStream(streamIds, streamOperatorCallback, offlineStreamOperator);
    if (rc != HDI::Camera::V1_0::NO_ERROR || offlineStreamOperator == nullptr) {
        CAMERA_LOGE("demo test: StreamOffline ChangeToOfflineStream error");
        return RC_ERROR;
    }

    CaptureOff(CAPTURE_ID_PREVIEW, CAPTURE_PREVIEW);
    CaptureOff(CAPTURE_ID_CAPTURE, CAPTURE_SNAPSHOT);
    sleep(1);
    ReleaseAllStream();
    ReleaseCameraDevice();
    sleep(offlineDelayTime);

    CAMERA_LOGD("demo test: begin to release offlne stream");
    rc = offlineStreamOperator->CancelCapture(CAPTURE_ID_CAPTURE);
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGE("demo test: StreamOffline offlineStreamOperator->CancelCapture error");
        return RC_ERROR;
    }

    rc = offlineStreamOperator->Release();
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGE("demo test: StreamOffline offlineStreamOperator->Release() error");
        return RC_ERROR;
    }

    streamCustomerCapture_->ReceiveFrameOff();

    CAMERA_LOGD("demo test: StreamOffline exit");

    return RC_OK;
}

RetCode OhosCameraDemo::GetFaceDetectMode(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    uint8_t faceDetectMode;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_STATISTICS_FACE_DETECT_MODE, &entry);
    if (ret != 0 || entry.data.u8 == nullptr || entry.count <= 0) {
        CAMERA_LOGE("demo test: get OHOS_STATISTICS_FACE_DETECT_MODE error");
        return RC_ERROR;
    }
    faceDetectMode = *(entry.data.u8);
    CAMERA_LOGD("demo test: faceDetectMode %{public}d\n",  faceDetectMode);
    return RC_OK;
}

RetCode OhosCameraDemo::GetFocalLength(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    float focalLength = 0.0;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_FOCAL_LENGTH, &entry);
    if (ret != 0 || entry.data.f == nullptr || entry.count <= 0) {
        CAMERA_LOGE("demo test:  get OHOS_ABILITY_FOCAL_LENGTH error");
        return RC_ERROR;
    }
    focalLength = *(entry.data.f);
    CAMERA_LOGD("demo test: focalLength %{public}f\n", focalLength);
    return RC_OK;
}

RetCode OhosCameraDemo::GetAvailableFocusModes(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    std::vector<uint8_t> focusMode;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_FOCUS_MODES, &entry);
    if (ret != 0 || entry.data.u8 == nullptr || entry.count <= 0) {
        CAMERA_LOGE("demo test: get OHOS_ABILITY_FOCUS_MODES  error");
        return RC_ERROR;
    }
    uint32_t count = entry.count;
    CAMERA_LOGD("demo test: count  %{public}d\n",  count);

    for (int i = 0 ; i < count; i++) {
        focusMode.push_back(*(entry.data.u8 + i));
    }

    for (auto it = focusMode.begin(); it != focusMode.end(); it++) {
        CAMERA_LOGD("demo test: focusMode : %{public}d \n", *it);
    }
    return RC_OK;
}

RetCode OhosCameraDemo::GetAvailableExposureModes(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    std::vector<uint8_t> exposureMode;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_EXPOSURE_MODES, &entry);
    if (ret != 0 || entry.data.u8 == nullptr || entry.count <= 0) {
        CAMERA_LOGE("demo test: get OHOS_ABILITY_EXPOSURE_MODES  error");
        return RC_ERROR;
    }
    uint32_t count = entry.count;
    CAMERA_LOGD("demo test: count  %{public}d\n",  count);

    for (int i = 0 ; i < count; i++) {
        exposureMode.push_back(*(entry.data.u8 + i));
    }

    for (auto it = exposureMode.begin(); it != exposureMode.end(); it++) {
        CAMERA_LOGD("demo test: exposureMode : %{public}d \n", *it);
    }
    return RC_OK;
}

RetCode OhosCameraDemo::GetExposureCompensationRange(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    std::vector<int32_t>  exposureCompensationRange;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_AE_COMPENSATION_RANGE, &entry);
    if (ret != 0 || entry.data.i32 == nullptr || entry.count <= 0) {
        CAMERA_LOGE("demo test: get OHOS_CONTROL_AE_COMPENSATION_RANGE error");
        return RC_ERROR;
    }

    uint32_t count = entry.count;
    CAMERA_LOGD("demo test:  exposureCompensationRange count  %{public}d\n",  count);
    for (int i = 0 ; i < count; i++) {
        exposureCompensationRange.push_back(*(entry.data.i32 + i));
    }

    for (auto it = exposureCompensationRange.begin(); it != exposureCompensationRange.end(); it++) {
        CAMERA_LOGD("demo test: exposureCompensationRange %{public}d \n", *it);
    }

    return RC_OK;
}

RetCode OhosCameraDemo::GetExposureCompensationSteps(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    camera_rational_t exposureCompensationSteps;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_AE_COMPENSATION_STEP, &entry);
    if (ret != 0 || entry.data.r == nullptr || entry.count <= 0) {
        CAMERA_LOGE("demo test: get OHOS_CONTROL_AE_COMPENSATION_STEP error");
        return RC_ERROR;
    }
    exposureCompensationSteps.numerator = entry.data.r->numerator;
    exposureCompensationSteps.denominator = entry.data.r->denominator;
    CAMERA_LOGD("demo test: steps.numerator %{public}d  and steps.denominator %{public}d \n",
        exposureCompensationSteps.numerator, exposureCompensationSteps.denominator);
    return RC_OK;
}

RetCode OhosCameraDemo::GetAvailableMeterModes(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    std::vector<uint8_t> meterModes;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_METER_MODES, &entry);
    if (ret != 0 || entry.data.u8 == nullptr || entry.count <= 0) {
        CAMERA_LOGE("demo test: get OHOS_ABILITY_METER_MODES  error");
        return RC_ERROR;
    }
    uint32_t count = entry.count;
    CAMERA_LOGD("demo test: count  %{public}d\n",  count);

    for (int i = 0 ; i < count; i++) {
        meterModes.push_back(*(entry.data.u8 + i));
    }

    for (auto it = meterModes.begin(); it != meterModes.end(); it++) {
        CAMERA_LOGD("demo test: meterModes : %{public}d \n", *it);
    }
    return RC_OK;
}

RetCode OhosCameraDemo::GetAvailableFlashModes(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    std::vector<uint8_t> flashModes;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_FLASH_MODES, &entry);
    if (ret != 0 || entry.data.u8 == nullptr || entry.count <= 0) {
        CAMERA_LOGE("demo test: get OHOS_ABILITY_FLASH_MODES  error");
        return RC_ERROR;
    }
    uint32_t count = entry.count;
    CAMERA_LOGD("demo test: count  %{public}d\n",  count);

    for (int i = 0 ; i < count; i++) {
        flashModes.push_back(*(entry.data.u8 + i));
    }

    for (auto it = flashModes.begin(); it != flashModes.end(); it++) {
        CAMERA_LOGD("demo test: flashModes : %{public}d \n", *it);
    }
    return RC_OK;
}

RetCode OhosCameraDemo::GetMirrorSupported(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    uint8_t mirrorSupported;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED, &entry);
    if (ret != 0 || entry.data.u8 == nullptr || entry.count <= 0) {
        CAMERA_LOGE("demo test: get OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED error");
        return RC_ERROR;
    }
    mirrorSupported = *(entry.data.u8);
    CAMERA_LOGD("demo test: mirrorSupported  %{public}d\n",  mirrorSupported);
    return RC_OK;
}

RetCode OhosCameraDemo::GetStreamBasicConfigurations(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    std::vector<int32_t>  streamBasicConfigurations;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS, &entry);
    if (ret != 0 || entry.data.i32 == nullptr || entry.count <= 0) {
        CAMERA_LOGE("demo test: get OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS error");
        return RC_ERROR;
    }

    uint32_t count = entry.count;
    CAMERA_LOGD("demo test: streamBasicConfigurations count  %{public}d\n",  count);
    for (int i = 0 ; i < count; i++) {
        streamBasicConfigurations.push_back(*(entry.data.i32 + i));
    }

    for (auto it = streamBasicConfigurations.begin(); it != streamBasicConfigurations.end(); it++) {
        CAMERA_LOGD("demo test: streamBasicConfigurations %{public}d \n", *it);
    }

    return RC_OK;
}

RetCode OhosCameraDemo::GetFpsRange(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    std::vector<int32_t>  fpsRange;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_FPS_RANGES, &entry);
    if (ret != 0 || entry.data.i32 == nullptr || entry.count <= 0) {
        CAMERA_LOGE("demo test: get OHOS_ABILITY_FPS_RANGES error");
        return RC_ERROR;
    }

    uint32_t count = entry.count;
    CAMERA_LOGD("demo test: fpsRange count  %{public}d\n",  count);
    for (int i = 0 ; i < count; i++) {
        fpsRange.push_back(*(entry.data.i32 + i));
    }

    for (auto it = fpsRange.begin(); it != fpsRange.end(); it++) {
        CAMERA_LOGD("demo test: fpsRange %{public}d \n", *it);
    }

    return RC_OK;
}

RetCode OhosCameraDemo::GetCameraPosition(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    uint8_t  cameraPosition;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_POSITION, &entry);
    if (ret != 0 || entry.data.u8 == nullptr || entry.count <= 0) {
        CAMERA_LOGE("demo test: get OHOS_ABILITY_CAMERA_POSITION error");
        return RC_ERROR;
    }

    cameraPosition= *(entry.data.u8);
    CAMERA_LOGD("demo test: cameraPosition  %{public}d\n", cameraPosition);
    return RC_OK;
}

RetCode OhosCameraDemo::GetCameraType(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    uint8_t  cameraType;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_TYPE, &entry);
    if (ret != 0 || entry.data.u8 == nullptr || entry.count <= 0) {
        CAMERA_LOGE("demo test: get OHOS_ABILITY_CAMERA_TYPE error");
        return RC_ERROR;
    }

    cameraType= *(entry.data.u8);
    CAMERA_LOGD("demo test: cameraType  %{public}d\n", cameraType);
    return RC_OK;
}

RetCode OhosCameraDemo::GetCameraConnectionType(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    uint8_t  cameraConnectionType;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_CONNECTION_TYPE, &entry);
    if (ret != 0 || entry.data.u8 == nullptr || entry.count <= 0) {
        CAMERA_LOGE("demo test: get OHOS_ABILITY_CAMERA_CONNECTION_TYPE error");
        return RC_ERROR;
    }

    cameraConnectionType= *(entry.data.u8);
    CAMERA_LOGD("demo test: cameraConnectionType  %{public}d\n", cameraConnectionType);
    return RC_OK;
}

RetCode OhosCameraDemo::GetFaceDetectMaxNum(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    uint8_t  faceDetectMaxNum;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_STATISTICS_FACE_DETECT_MAX_NUM, &entry);
    if (ret != 0 || entry.data.u8 == nullptr || entry.count <= 0) {
        CAMERA_LOGE("demo test: get OHOS_STATISTICS_FACE_DETECT_MAX_NUM error");
        return RC_ERROR;
    }
    faceDetectMaxNum = *(entry.data.u8);
    CAMERA_LOGD("demo test: faceDetectMaxNum %{public}d \n", faceDetectMaxNum);
    return RC_OK;
}

#ifndef CAMERA_BUILT_ON_OHOS_LITE
int32_t DemoCameraDeviceCallback::OnError(ErrorType type, int32_t errorCode)
{
    CAMERA_LOGI("demo test: OnError type : %{public}d, errorCode : %{public}d", type, errorCode);
}

int32_t DemoCameraDeviceCallback::OnResult(uint64_t timestamp, const std::vector<uint8_t>& result)
{
    CAMERA_LOGI("demo test: OnResult timestamp : %{public}ld,", timestamp);
    std::shared_ptr<CameraMetadata> updateSettings;

    MetadataUtils::ConvertVecToMetadata(result, updateSettings);
    for (auto it = results_list_.cbegin(); it != results_list_.cend(); it++) {
        switch (*it) {
            case OHOS_CONTROL_FOCUS_MODE: {
                common_metadata_header_t* data = updateSettings->get();
                uint8_t focusMode;
                camera_metadata_item_t entry;
                int ret = FindCameraMetadataItem(data, OHOS_CONTROL_FOCUS_MODE, &entry);
                if (ret != 0 || entry.data.u8 == nullptr || entry.count <= 0) {
                    CAMERA_LOGE("demo test: get OHOS_CONTROL_FOCUS_MODE error");
                    return RC_ERROR;
                }
                focusMode = *(entry.data.u8);
                CAMERA_LOGI("demo test: focusMode %{public}d\n", focusMode);
                break;
            }
            case OHOS_CONTROL_EXPOSURE_MODE: {
                common_metadata_header_t* data = updateSettings->get();
                uint8_t exposureMode;
                camera_metadata_item_t entry;
                int ret = FindCameraMetadataItem(data, OHOS_CONTROL_EXPOSURE_MODE, &entry);
                if (ret != 0 || entry.data.u8 == nullptr || entry.count <= 0) {
                    CAMERA_LOGE("demo test: get OHOS_CONTROL_EXPOSURE_MODE error");
                    return RC_ERROR;
                }
                exposureMode = *(entry.data.u8);
                CAMERA_LOGI("demo test: exposureMode %{public}d\n", exposureMode);
                break;
            }
            default:
                break;
        }
    }

    return RC_OK;
}

int32_t DemoCameraHostCallback::OnCameraStatus(const std::string& cameraId, CameraStatus status)
{
    (void)cameraId;
    CAMERA_LOGI("%{public}s, enter.", __func__);
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
    return RC_OK;
}

int32_t DemoStreamOperatorCallback::OnCaptureStarted(int32_t captureId, const std::vector<int32_t>& streamIds)
{
    (void)captureId;
    CAMERA_LOGI("%{public}s, enter.", __func__);
    return RC_OK;
}

int32_t DemoStreamOperatorCallback::OnCaptureEnded(int32_t captureId, const std::vector<CaptureEndedInfo>& infos)
{
    (void)captureId;
    CAMERA_LOGI("%{public}s, enter.", __func__);
    return RC_OK;
}

int32_t DemoStreamOperatorCallback::OnCaptureError(int32_t captureId, const std::vector<CaptureErrorInfo>& infos)
{
    (void)captureId;
    CAMERA_LOGI("%{public}s, enter.", __func__);
    return RC_OK;
}

int32_t DemoStreamOperatorCallback::OnFrameShutter(int32_t captureId,
    const std::vector<int32_t>& streamIds, uint64_t timestamp)
{
    (void)captureId;
    (void)timestamp;
    CAMERA_LOGI("%{public}s, enter.", __func__);
    return RC_OK;
}

#endif
} // namespace OHOS::Camera
