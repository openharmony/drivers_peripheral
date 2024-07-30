/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "dcamera_hdf_demo.h"

#include "distributed_hardware_log.h"
#include "metadata_utils.h"

namespace OHOS {
namespace DistributedHardware {
DcameraHdfDemo::DcameraHdfDemo() {}
DcameraHdfDemo::~DcameraHdfDemo() {}

std::vector<int32_t> results_list_;

const int32_t METER_POINT_X = 305;
const int32_t METER_POINT_Y = 205;
const int32_t AF_REGIONS_X = 400;
const int32_t AF_REGIONS_Y = 200;
const int32_t FPS_RANGE = 30;

void DcameraHdfDemo::SetStreamInfo(StreamInfo& streamInfo,
    const std::shared_ptr<StreamCustomer> &streamCustomer,
    const int streamId, const StreamIntent intent)
{
    constexpr uint32_t dataspace = 8;
    constexpr uint32_t tunneledMode = 5;
    sptr<OHOS::IBufferProducer> producer;

    if (intent == OHOS::HDI::Camera::V1_0::PREVIEW) {
        constexpr uint32_t width = CAMERA_PREVIEW_WIDTH;
        constexpr uint32_t height = CAMERA_PREVIEW_HEIGHT;
        streamInfo.width_ = width;
        streamInfo.height_ = height;
        producer = streamCustomer->CreateProducer(CAPTURE_PREVIEW, nullptr);
    } else if (intent == OHOS::HDI::Camera::V1_0::STILL_CAPTURE) {
        constexpr uint32_t width = CAMERA_CAPTURE_WIDTH;
        constexpr uint32_t height = CAMERA_CAPTURE_HEIGHT;
        streamInfo.width_ = width;
        streamInfo.height_ = height;
        streamInfo.encodeType_ = CAMERA_CAPTURE_ENCODE_TYPE;
        producer = streamCustomer->CreateProducer(CAPTURE_SNAPSHOT, [this](void* addr, const uint32_t size) {
            StoreImage(addr, size);
        });
    } else {
        constexpr uint32_t width = CAMERA_VIDEO_WIDTH;
        constexpr uint32_t height = CAMERA_VIDEO_HEIGHT;
        streamInfo.width_ = width;
        streamInfo.height_ = height;
        streamInfo.encodeType_ = CAMERA_VIDEO_ENCODE_TYPE;
        OpenVideoFile();
        producer = streamCustomer->CreateProducer(CAPTURE_VIDEO, [this](void* addr, const uint32_t size) {
            StoreVideo(addr, size);
        });
    }

    streamInfo.streamId_ = streamId;
    streamInfo.format_ = CAMERA_FORMAT;
    streamInfo.dataspace_ = dataspace;
    streamInfo.intent_ = intent;
    streamInfo.tunneledMode_ = tunneledMode;
 
    streamInfo.bufferQueue_ = sptr<BufferProducerSequenceable>(new BufferProducerSequenceable(producer));
    streamInfo.bufferQueue_->producer_->SetQueueSize(8); // 8:set bufferQueue size
}

void DcameraHdfDemo::GetStreamOpt()
{
    int rc = 0;

    if (streamOperator_ == nullptr) {
        const sptr<IStreamOperatorCallback> streamOperatorCallback(new DemoStreamOperatorCallback());
        rc = demoCameraDevice_->GetStreamOperator(streamOperatorCallback, streamOperator_);
        if (rc != HDI::Camera::V1_0::NO_ERROR) {
            DHLOGE("demo test: GetStreamOpt GetStreamOperator fail");
            streamOperator_ = nullptr;
        }
    }
}

RetCode DcameraHdfDemo::CaptureON(const int streamId,
    const int captureId, CaptureMode mode)
{
    DHLOGI("demo test: CaptureON enter streamId == %{public}d and captureId == %{public}d and mode == %{public}d",
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
    bool iscapture = true;
    OHOS::Camera::MetadataUtils::ConvertMetadataToVec(captureSetting_, setting);
    captureInfo_.streamIds_ = {streamId};
    if (mode == CAPTURE_SNAPSHOT) {
        captureInfo_.captureSetting_ = setting;
        iscapture = false;
    } else {
        captureInfo_.captureSetting_ = cameraAbility_;
        iscapture = true;
    }
    captureInfo_.enableShutterCallback_ = false;
    int rc = streamOperator_->Capture(captureId, captureInfo_, iscapture);
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        DHLOGE("demo test: CaptureStart Capture error");
        streamOperator_->ReleaseStreams(captureInfo_.streamIds_);
        return RC_ERROR;
    }
    DHLOGI("demo test: CaptureON exit");

    return RC_OK;
}

RetCode DcameraHdfDemo::CaptureOff(const int captureId, const CaptureMode mode)
{
    int rc = 0;
    DHLOGI("demo test: CaptureOff enter mode == %{public}d", mode);

    if (streamOperator_ == nullptr) {
        DHLOGE("demo test: CaptureOff streamOperator_ is nullptr");
        return RC_ERROR;
    }

    if (mode == CAPTURE_PREVIEW) {
        rc = streamOperator_->CancelCapture(captureId);
    } else if (mode == CAPTURE_SNAPSHOT) {
        rc = streamOperator_->CancelCapture(captureId);
    } else if (mode == CAPTURE_VIDEO) {
        rc = streamOperator_->CancelCapture(captureId);
        close(videoFd_);
        videoFd_ = -1;
    }

    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        DHLOGE("demo test: CaptureOff CancelCapture error mode %{public}d rc == %{public}d", mode, rc);
        return RC_ERROR;
    }
    DHLOGI("demo test: CaptureOff exit");

    return RC_OK;
}

RetCode DcameraHdfDemo::CreateStreamInfo(const int streamId, std::shared_ptr<StreamCustomer> &streamCustomer,
    StreamIntent intent)
{
    DHLOGI("demo test: CreateStream enter");
    GetStreamOpt();
    if (streamOperator_ == nullptr) {
        DHLOGE("demo test: CreateStream GetStreamOpt() is nullptr");
        return RC_ERROR;
    }

    StreamInfo streamInfo = {0};

    SetStreamInfo(streamInfo, streamCustomer, streamId, intent);
    if (streamInfo.bufferQueue_->producer_ == nullptr) {
        DHLOGE("demo test: CreateStream CreateProducer(); is nullptr");
        return RC_ERROR;
    }
    streamInfos_.push_back(streamInfo);
    streamIds_.push_back(streamId);
    return RC_OK;
}

RetCode DcameraHdfDemo::CreateStream()
{
    int rc = 0;
    DHLOGI("demo test: CreateStreams start");
    rc = streamOperator_->CreateStreams(streamInfos_);
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        DHLOGE("demo test: CreateStream CreateStreams error");
        return RC_ERROR;
    }
    DHLOGI("demo test: CommitStreams start");
    rc = streamOperator_->CommitStreams(NORMAL, cameraAbility_);
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        DHLOGE("demo test: CreateStream CommitStreams error");
        streamOperator_->ReleaseStreams(streamIds_);
        return RC_ERROR;
    }

    DHLOGI("demo test: CreateStream exit");

    return RC_OK;
}

RetCode DcameraHdfDemo::InitCameraDevice()
{
    int rc = 0;

    DHLOGI("demo test: InitCameraDevice enter");

    if (demoCameraHost_ == nullptr) {
        DHLOGE("demo test: InitCameraDevice demoCameraHost_ == nullptr");
        return RC_ERROR;
    }

    (void)demoCameraHost_->GetCameraIds(cameraIds_);
    if (cameraIds_.empty()) {
        return RC_ERROR;
    }

    const std::string cameraId = cameraIds_.front();
    demoCameraHost_->GetCameraAbility(cameraId, cameraAbility_);

    OHOS::Camera::MetadataUtils::ConvertVecToMetadata(cameraAbility_, ability_);

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

    sptr<DemoCameraDeviceCallback> callback(new DemoCameraDeviceCallback());
    rc = demoCameraHost_->OpenCamera(cameraIds_.front(), callback, demoCameraDevice_);
    if (rc != HDI::Camera::V1_0::NO_ERROR || demoCameraDevice_ == nullptr) {
        DHLOGE("demo test: InitCameraDevice OpenCamera failed");
        return RC_ERROR;
    }

    DHLOGI("demo test: InitCameraDevice exit");

    return RC_OK;
}

void DcameraHdfDemo::ReleaseCameraDevice()
{
    if (demoCameraDevice_ != nullptr) {
        DHLOGI("demo test: ReleaseCameraDevice close Device");
        demoCameraDevice_->Close();
        demoCameraDevice_ = nullptr;
    }
}

RetCode DcameraHdfDemo::InitSensors()
{
    int rc = 0;
    DHLOGI("demo test: InitSensors enter");
    if (demoCameraHost_ != nullptr) {
        return RC_OK;
    }

    constexpr const char *demoServiceName = "distributed_camera_service";
    demoCameraHost_ = ICameraHost::Get(demoServiceName, false);
    if (demoCameraHost_ == nullptr) {
        DHLOGE("demo test: ICameraHost::Get error");
        return RC_ERROR;
    }

    hostCallback_ = sptr<DemoCameraHostCallback>(new DemoCameraHostCallback());
    rc = demoCameraHost_->SetCallback(hostCallback_);
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        DHLOGE("demo test: demoCameraHost_->SetCallback(hostCallback_) error");
        return RC_ERROR;
    }

    DHLOGI("demo test: InitSensors exit");

    return RC_OK;
}

void DcameraHdfDemo::StoreImage(const void *bufStart, const uint32_t size) const
{
    DHLOGI("demo test:StoreImage size == %{public}d", size);
    constexpr uint32_t pathLen = 64;
    char path[pathLen] = {0};
    char prefix[] = "/data/";

    int imgFD = 0;
    int ret;
    struct timeval start = {};
    gettimeofday(&start, nullptr);
    if (sprintf_s(path, sizeof(path), "%spicture_%ld.jpeg", prefix, start.tv_usec) < 0) {
        DHLOGE("sprintf_s error .....");
        return;
    }

    imgFD = open(path, O_RDWR | O_CREAT, 00766); // 00766:file operate permission
    if (imgFD == -1) {
        DHLOGE("demo test:open image file error %{public}s.....", strerror(errno));
        return;
    }

    ret = write(imgFD, bufStart, size);
    if (ret == -1) {
        DHLOGE("demo test:write image file error %{public}s.....", strerror(errno));
    }

    close(imgFD);
    DHLOGI("demo test:StoreImage save success");
}

void DcameraHdfDemo::StoreVideo(const void *bufStart, const uint32_t size) const
{
    int ret = 0;

    ret = write(videoFd_, bufStart, size);
    if (ret == -1) {
        DHLOGE("demo test:write video file error %{public}s.....", strerror(errno));
    }
    DHLOGI("demo test:StoreVideo size == %{public}d", size);
}

void DcameraHdfDemo::OpenVideoFile()
{
    constexpr uint32_t pathLen = 64;
    char path[pathLen] = {0};
    char prefix[] = "/data/";
    auto seconds = time(nullptr);
    if (sprintf_s(path, sizeof(path), "%svideo%ld.h264", prefix, seconds) < 0) {
        DHLOGE("%{public}s: sprintf  failed", __func__);
        return;
    }
    videoFd_ = open(path, O_RDWR | O_CREAT, 00766); // 00766:file operate permission
    if (videoFd_ < 0) {
        DHLOGE("demo test: StartVideo open %{public}s %{public}s failed", path, strerror(errno));
    }
}

RetCode DcameraHdfDemo::CreateStreams(const int streamIdSecond, StreamIntent intent)
{
    int rc = 0;
    std::vector<StreamInfo> streamInfos;
    std::vector<StreamInfo>().swap(streamInfos);

    DHLOGI("demo test: CreateStreams streamIdSecond = %{public}d", streamIdSecond);
    GetStreamOpt();
    if (streamOperator_ == nullptr) {
        DHLOGE("demo test: CreateStreams GetStreamOpt() is nullptr");
        return RC_ERROR;
    }

    StreamInfo previewStreamInfo = {0};

    SetStreamInfo(previewStreamInfo, streamCustomerPreview_, STREAM_ID_PREVIEW, OHOS::HDI::Camera::V1_0::PREVIEW);
    if (previewStreamInfo.bufferQueue_->producer_ == nullptr) {
        DHLOGE("demo test: CreateStream CreateProducer(); is nullptr");
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
        DHLOGE("demo test: CreateStreams CreateProducer() secondStreamInfo is nullptr");
        return RC_ERROR;
    }
    streamInfos.push_back(secondStreamInfo);

    rc = streamOperator_->CreateStreams(streamInfos);
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        DHLOGE("demo test: CreateStream CreateStreams error");
        return RC_ERROR;
    }

    rc = streamOperator_->CommitStreams(NORMAL, cameraAbility_);
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        DHLOGE("demo test: CreateStream CommitStreams error");
        std::vector<int> streamIds = {STREAM_ID_PREVIEW, streamIdSecond};
        streamOperator_->ReleaseStreams(streamIds);
        return RC_ERROR;
    }

    return RC_OK;
}

RetCode DcameraHdfDemo::CaptureOnDualStreams(const int streamIdSecond)
{
    int rc = 0;
    DHLOGI("demo test: CaptuCaptureOnDualStreamsreON enter");

    CaptureInfo previewCaptureInfo;
    previewCaptureInfo.streamIds_ = {STREAM_ID_PREVIEW};
    previewCaptureInfo.captureSetting_ = cameraAbility_;
    previewCaptureInfo.enableShutterCallback_ = false;

    rc = streamOperator_->Capture(CAPTURE_ID_PREVIEW, previewCaptureInfo, true);
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        DHLOGE("demo test: CaptureOnDualStreams preview Capture error");
        streamOperator_->ReleaseStreams(previewCaptureInfo.streamIds_);
        return RC_ERROR;
    }

    CaptureInfo secondCaptureInfo;
    secondCaptureInfo.streamIds_ = {streamIdSecond};
    secondCaptureInfo.captureSetting_ = cameraAbility_;
    previewCaptureInfo.enableShutterCallback_ = false;

    if (streamIdSecond == STREAM_ID_CAPTURE) {
        rc = streamOperator_->Capture(CAPTURE_ID_CAPTURE, secondCaptureInfo, true);
        if (rc != HDI::Camera::V1_0::NO_ERROR) {
            DHLOGE("demo test: CaptureOnDualStreams CAPTURE_ID_CAPTURE error");
            streamOperator_->ReleaseStreams(secondCaptureInfo.streamIds_);
            return RC_ERROR;
        }
    } else {
        rc = streamOperator_->Capture(CAPTURE_ID_VIDEO, secondCaptureInfo, true);
        if (rc != HDI::Camera::V1_0::NO_ERROR) {
            DHLOGE("demo test: CaptureOnDualStreams CAPTURE_ID_VIDEO error");
            streamOperator_->ReleaseStreams(secondCaptureInfo.streamIds_);
            return RC_ERROR;
        }
    }

    DHLOGI("demo test: CaptuCaptureOnDualStreamsreON exit");

    return RC_OK;
}

RetCode DcameraHdfDemo::StartDualStreams(const int streamIdSecond)
{
    RetCode rc = RC_OK;

    DHLOGI("demo test: StartDualStreams enter");

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
            rc = CreateStreams(streamIdSecond, OHOS::HDI::Camera::V1_0::STILL_CAPTURE);
            if (rc != RC_OK) {
                DHLOGE("demo test:StartPreviewStream CreateStreams error");
                return RC_ERROR;
            }
        }
    } else {
        if (streamCustomerVideo_ == nullptr) {
            streamCustomerVideo_ = std::make_shared<StreamCustomer>();
        }

        if (isVideoOn_ == 0) {
            isVideoOn_ = 1;
            rc = CreateStreams(streamIdSecond, OHOS::HDI::Camera::V1_0::VIDEO);
            if (rc != RC_OK) {
                DHLOGE("demo test:StartPreviewStream CreateStreams error");
                return RC_ERROR;
            }
        }
    }

    DHLOGI("demo test: StartDualStreams exit");

    return RC_OK;
}

RetCode DcameraHdfDemo::StartCaptureStream()
{
    RetCode rc = RC_OK;

    DHLOGI("demo test: StartCaptureStream enter");
    if (streamCustomerCapture_ == nullptr) {
        streamCustomerCapture_ = std::make_shared<StreamCustomer>();
    }

    if (isCaptureOn_ == 0) {
        isCaptureOn_ = 1;

        rc = CreateStreamInfo(STREAM_ID_CAPTURE, streamCustomerCapture_, OHOS::HDI::Camera::V1_0::STILL_CAPTURE);
        if (rc != RC_OK) {
            DHLOGE("demo test:StartCaptureStream CreateStream error");
            return RC_ERROR;
        }
    }

    DHLOGI("demo test: StartCaptureStream exit");

    return RC_OK;
}

RetCode DcameraHdfDemo::StartVideoStream()
{
    RetCode rc = RC_OK;

    DHLOGI("demo test: StartVideoStream enter");
    if (streamCustomerVideo_ == nullptr) {
        streamCustomerVideo_ = std::make_shared<StreamCustomer>();
    }

    if (isVideoOn_ == 0) {
        isVideoOn_ = 1;

        rc = CreateStreamInfo(STREAM_ID_VIDEO, streamCustomerVideo_, OHOS::HDI::Camera::V1_0::VIDEO);
        if (rc != RC_OK) {
            DHLOGE("demo test:StartVideoStream CreateStream error");
            return RC_ERROR;
        }
    }

    DHLOGI("demo test: StartVideoStream exit");

    return RC_OK;
}

RetCode DcameraHdfDemo::StartPreviewStream()
{
    RetCode rc = RC_OK;

    DHLOGI("demo test: StartPreviewStream enter");

    if (streamCustomerPreview_ == nullptr) {
        streamCustomerPreview_ = std::make_shared<StreamCustomer>();
    }

    if (isPreviewOn_ == 0) {
        isPreviewOn_ = 1;

        rc = CreateStreamInfo(STREAM_ID_PREVIEW, streamCustomerPreview_, OHOS::HDI::Camera::V1_0::PREVIEW);
        if (rc != RC_OK) {
            DHLOGE("demo test:StartPreviewStream CreateStream error");
            return RC_ERROR;
        }
    }

    DHLOGI("demo test: StartPreviewStream exit");

    return RC_OK;
}

RetCode DcameraHdfDemo::ReleaseAllStream()
{
    std::vector<int> streamIds;

    DHLOGI("demo test: ReleaseAllStream enter");

    if (isPreviewOn_ != 1) {
        DHLOGE("demo test: ReleaseAllStream preview is not running");
        return RC_ERROR;
    }

    if (isCaptureOn_ == 1) {
        DHLOGI("demo test: ReleaseAllStream STREAM_ID_PREVIEW STREAM_ID_CAPTURE");
        streamIds = {STREAM_ID_PREVIEW, STREAM_ID_CAPTURE};
        streamOperator_->ReleaseStreams(streamIds);
    } else {
        DHLOGI("demo test: ReleaseAllStream STREAM_ID_PREVIEW STREAM_ID_VIDEO");
        streamIds = {STREAM_ID_PREVIEW, STREAM_ID_VIDEO};
        streamOperator_->ReleaseStreams(streamIds);
    }

    streamInfos_.clear();
    streamIds_.clear();

    isPreviewOn_ = 0;
    isCaptureOn_ = 0;
    isVideoOn_ = 0;

    DHLOGI("demo test: ReleaseAllStream exit");

    return RC_OK;
}

void DcameraHdfDemo::QuitDemo()
{
    ReleaseCameraDevice();
    DHLOGI("demo test: QuitDemo done");
}

void DcameraHdfDemo::SetEnableResult()
{
    DHLOGI("demo test: SetEnableResult enter");

    results_list_.push_back(OHOS_CONTROL_EXPOSURE_MODE);
    results_list_.push_back(OHOS_CONTROL_FOCUS_MODE);
    demoCameraDevice_->EnableResult(results_list_);

    DHLOGI("demo test: SetEnableResult exit");
}

void DcameraHdfDemo::SetAwbMode(const int mode) const
{
    DHLOGI("demo test: SetAwbMode enter");

    constexpr size_t entryCapacity = 100;
    constexpr size_t dataCapacity = 2000;

    std::shared_ptr<CameraSetting> metaData = std::make_shared<CameraSetting>(entryCapacity, dataCapacity);
    std::vector<uint8_t> result;

    const uint8_t awbMode = mode;
    metaData->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);
    OHOS::Camera::MetadataUtils::ConvertMetadataToVec(metaData, result);
    demoCameraDevice_->UpdateSettings(result);

    DHLOGI("demo test: SetAwbMode exit");
}

void DcameraHdfDemo::SetAeExpo()
{
    int32_t expo;

    DHLOGI("demo test: SetAeExpo enter");

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
    OHOS::Camera::MetadataUtils::ConvertMetadataToVec(metaData, result);
    demoCameraDevice_->UpdateSettings(result);

    DHLOGI("demo test: SetAeExpo exit");
}

void DcameraHdfDemo::SetMetadata()
{
    DHLOGI("demo test: SetMetadata enter");
    constexpr size_t entryCapacity = 100;
    constexpr size_t dataCapacity = 2000;
    std::shared_ptr<CameraSetting> metaData = std::make_shared<CameraSetting>(entryCapacity, dataCapacity);
    SetAwbMode(OHOS_CAMERA_AWB_MODE_INCANDESCENT);

    uint8_t aeMode = OHOS_CAMERA_EXPOSURE_MODE_CONTINUOUS_AUTO;
    metaData->addEntry(OHOS_CONTROL_EXPOSURE_MODE, &aeMode, sizeof(aeMode));

    int64_t exposureTime = 400;
    metaData->addEntry(OHOS_SENSOR_EXPOSURE_TIME, &exposureTime, sizeof(exposureTime));

    int32_t aeExposureCompensation = 4;
    metaData->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &aeExposureCompensation, sizeof(aeExposureCompensation));

    std::vector<int32_t> meterPoint;
    meterPoint.push_back(METER_POINT_X);
    meterPoint.push_back(METER_POINT_Y);
    metaData->addEntry(OHOS_CONTROL_METER_POINT, meterPoint.data(), meterPoint.size());

    uint8_t meterMode = OHOS_CAMERA_OVERALL_METERING;
    metaData->addEntry(OHOS_CONTROL_METER_MODE, &meterMode, sizeof(meterMode));

    uint8_t flashMode = OHOS_CAMERA_FLASH_MODE_ALWAYS_OPEN;
    metaData->addEntry(OHOS_CONTROL_FLASH_MODE, &flashMode, sizeof(flashMode));

    uint8_t mirror = OHOS_CAMERA_MIRROR_ON;
    metaData->addEntry(OHOS_CONTROL_CAPTURE_MIRROR, &mirror, sizeof(mirror));

    std::vector<int32_t> fpsRange;
    fpsRange.push_back(FPS_RANGE);
    fpsRange.push_back(FPS_RANGE);
    metaData->addEntry(OHOS_CONTROL_FPS_RANGES, fpsRange.data(), fpsRange.size());

    int32_t orientation = OHOS_CAMERA_JPEG_ROTATION_180;
    metaData->addEntry(OHOS_JPEG_ORIENTATION, &orientation, sizeof(orientation));

    uint8_t quality = OHOS_CAMERA_JPEG_LEVEL_HIGH;
    metaData->addEntry(OHOS_JPEG_QUALITY, &quality, sizeof(quality));

    uint8_t afMode = OHOS_CAMERA_FOCUS_MODE_AUTO;
    metaData->addEntry(OHOS_CONTROL_FOCUS_MODE, &afMode, sizeof(afMode));

    std::vector<int32_t> afRegions;
    afRegions.push_back(AF_REGIONS_X);
    afRegions.push_back(AF_REGIONS_Y);
    metaData->addEntry(OHOS_CONTROL_AF_REGIONS, afRegions.data(), afRegions.size());

    uint8_t faceMode = OHOS_CAMERA_FACE_DETECT_MODE_SIMPLE;
    metaData->addEntry(OHOS_STATISTICS_FACE_DETECT_SWITCH, &faceMode, sizeof(faceMode));

    std::vector<uint8_t> result;
    OHOS::Camera::MetadataUtils::ConvertMetadataToVec(metaData, result);
    demoCameraDevice_->UpdateSettings(result);

    DHLOGI("demo test: SetMetadata exit");
}

void DcameraHdfDemo::FlashlightOnOff(bool onOff)
{
    DHLOGI("demo test: FlashlightOnOff enter");

    if (demoCameraHost_ == nullptr) {
        DHLOGE("demo test: FlashlightOnOff demoCameraHost_ == nullptr");
        return;
    }

    demoCameraHost_->SetFlashlight(cameraIds_.front(), onOff);

    DHLOGI("demo test: FlashlightOnOff exit ");
}

RetCode DcameraHdfDemo::StreamOffline(const int streamId)
{
    int rc = 0;
    constexpr size_t offlineDelayTime = 4;
    DHLOGI("demo test: StreamOffline enter");
    sptr<IStreamOperatorCallback> streamOperatorCallback(new DemoStreamOperatorCallback());
    sptr<IOfflineStreamOperator> offlineStreamOperator = nullptr;
    std::vector<int> streamIds;
    streamIds.push_back(streamId);
    rc = streamOperator_->ChangeToOfflineStream(streamIds, streamOperatorCallback, offlineStreamOperator);
    if (rc != CamRetCode::METHOD_NOT_SUPPORTED) {
        DHLOGE("demo test: StreamOffline ChangeToOfflineStream error");
        return RC_ERROR;
    }

    CaptureOff(CAPTURE_ID_PREVIEW, CAPTURE_PREVIEW);
    CaptureOff(CAPTURE_ID_CAPTURE, CAPTURE_SNAPSHOT);
    sleep(1);
    ReleaseAllStream();
    ReleaseCameraDevice();
    sleep(offlineDelayTime);

    DHLOGI("demo test: begin to release offlne stream");
    if (offlineStreamOperator != nullptr) {
        rc = offlineStreamOperator->CancelCapture(CAPTURE_ID_CAPTURE);
        if (rc != CamRetCode::METHOD_NOT_SUPPORTED) {
            DHLOGE("demo test: StreamOffline offlineStreamOperator->CancelCapture error");
            return RC_ERROR;
        }

        rc = offlineStreamOperator->Release();
        if (rc != CamRetCode::METHOD_NOT_SUPPORTED) {
            DHLOGE("demo test: StreamOffline offlineStreamOperator->Release() error");
            return RC_ERROR;
        }
    }

    DHLOGI("demo test: StreamOffline exit");

    return RC_OK;
}

RetCode DcameraHdfDemo::GetFaceDetectMode(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    uint8_t faceDetectMode;
    camera_metadata_item_t entry;
    int ret = OHOS::Camera::FindCameraMetadataItem(data, OHOS_STATISTICS_FACE_DETECT_MODE, &entry);
    if (ret != 0) {
        DHLOGE("demo test: get OHOS_STATISTICS_FACE_DETECT_MODE error");
        return RC_ERROR;
    }
    faceDetectMode = *(entry.data.u8);
    DHLOGI("demo test: faceDetectMode %{public}d",  faceDetectMode);
    return RC_OK;
}

RetCode DcameraHdfDemo::GetFocalLength(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    float focalLength = 0.0;
    camera_metadata_item_t entry;
    int ret = OHOS::Camera::FindCameraMetadataItem(data, OHOS_ABILITY_FOCAL_LENGTH, &entry);
    if (ret != 0) {
        DHLOGE("demo test:  get OHOS_ABILITY_FOCAL_LENGTH error");
        return RC_ERROR;
    }
    focalLength = *(entry.data.f);
    DHLOGI("demo test: focalLength %{public}f", focalLength);
    return RC_OK;
}

RetCode DcameraHdfDemo::GetAvailableFocusModes(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    std::vector<uint8_t> focusMode;
    camera_metadata_item_t entry;
    int ret = OHOS::Camera::FindCameraMetadataItem(data, OHOS_ABILITY_FOCUS_MODES, &entry);
    if (ret != 0) {
        DHLOGE("demo test: get OHOS_ABILITY_FOCUS_MODES  error");
        return RC_ERROR;
    }
    uint32_t count = entry.count;
    DHLOGI("demo test: count  %{public}d",  count);

    for (uint32_t i = 0 ; i < count; i++) {
        focusMode.push_back(*(entry.data.u8 + i));
    }

    for (auto it = focusMode.begin(); it != focusMode.end(); it++) {
        DHLOGI("demo test: focusMode : %{public}d ", *it);
    }
    return RC_OK;
}

RetCode DcameraHdfDemo::GetAvailableExposureModes(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    std::vector<uint8_t> exposureMode;
    camera_metadata_item_t entry;
    int ret = OHOS::Camera::FindCameraMetadataItem(data, OHOS_ABILITY_EXPOSURE_MODES, &entry);
    if (ret != 0) {
        DHLOGE("demo test: get OHOS_ABILITY_EXPOSURE_MODES  error");
        return RC_ERROR;
    }
    uint32_t count = entry.count;
    DHLOGI("demo test: count  %{public}d",  count);

    for (uint32_t i = 0 ; i < count; i++) {
        exposureMode.push_back(*(entry.data.u8 + i));
    }

    for (auto it = exposureMode.begin(); it != exposureMode.end(); it++) {
        DHLOGI("demo test: exposureMode : %{public}d ", *it);
    }
    return RC_OK;
}

RetCode DcameraHdfDemo::GetExposureCompensationRange(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    std::vector<int32_t>  exposureCompensationRange;
    camera_metadata_item_t entry;
    int ret = OHOS::Camera::FindCameraMetadataItem(data, OHOS_ABILITY_AE_COMPENSATION_RANGE, &entry);
    if (ret != 0) {
        DHLOGE("demo test: get OHOS_ABILITY_AE_COMPENSATION_RANGE error");
        return RC_ERROR;
    }

    uint32_t count = entry.count;
    DHLOGI("demo test:  exposureCompensationRange count  %{public}d",  count);
    for (uint32_t i = 0 ; i < count; i++) {
        exposureCompensationRange.push_back(*(entry.data.i32 + i));
    }

    for (auto it = exposureCompensationRange.begin(); it != exposureCompensationRange.end(); it++) {
        DHLOGI("demo test: exposureCompensationRange %{public}d ", *it);
    }

    return RC_OK;
}

RetCode DcameraHdfDemo::GetExposureCompensationSteps(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    camera_rational_t exposureCompensationSteps;
    camera_metadata_item_t entry;
    int ret = OHOS::Camera::FindCameraMetadataItem(data, OHOS_ABILITY_AE_COMPENSATION_STEP, &entry);
    if (ret != 0) {
        DHLOGE("demo test: get OHOS_ABILITY_AE_COMPENSATION_STEP error");
        return RC_ERROR;
    }
    exposureCompensationSteps.numerator = entry.data.r->numerator;
    exposureCompensationSteps.denominator = entry.data.r->denominator;
    DHLOGI("demo test: steps.numerator %{public}d  and steps.denominator %{public}d ",
        exposureCompensationSteps.numerator, exposureCompensationSteps.denominator);
    return RC_OK;
}

RetCode DcameraHdfDemo::GetAvailableMeterModes(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    std::vector<uint8_t> meterModes;
    camera_metadata_item_t entry;
    int ret = OHOS::Camera::FindCameraMetadataItem(data, OHOS_ABILITY_METER_MODES, &entry);
    if (ret != 0) {
        DHLOGE("demo test: get OHOS_ABILITY_METER_MODES  error");
        return RC_ERROR;
    }
    uint32_t count = entry.count;
    DHLOGI("demo test: count  %{public}d",  count);

    for (uint32_t i = 0 ; i < count; i++) {
        meterModes.push_back(*(entry.data.u8 + i));
    }

    for (auto it = meterModes.begin(); it != meterModes.end(); it++) {
        DHLOGI("demo test: meterModes : %{public}d ", *it);
    }
    return RC_OK;
}

RetCode DcameraHdfDemo::GetAvailableFlashModes(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    std::vector<uint8_t> flashModes;
    camera_metadata_item_t entry;
    int ret = OHOS::Camera::FindCameraMetadataItem(data, OHOS_ABILITY_FLASH_MODES, &entry);
    if (ret != 0) {
        DHLOGE("demo test: get OHOS_ABILITY_FLASH_MODES  error");
        return RC_ERROR;
    }
    uint32_t count = entry.count;
    DHLOGI("demo test: count  %{public}d",  count);

    for (uint32_t i = 0 ; i < count; i++) {
        flashModes.push_back(*(entry.data.u8 + i));
    }

    for (auto it = flashModes.begin(); it != flashModes.end(); it++) {
        DHLOGI("demo test: flashModes : %{public}d ", *it);
    }
    return RC_OK;
}

RetCode DcameraHdfDemo::GetMirrorSupported(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    uint8_t mirrorSupported;
    camera_metadata_item_t entry;
    int ret = OHOS::Camera::FindCameraMetadataItem(data, OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED, &entry);
    if (ret != 0) {
        DHLOGE("demo test: get OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED error");
        return RC_ERROR;
    }
    mirrorSupported = *(entry.data.u8);
    DHLOGI("demo test: mirrorSupported  %{public}d",  mirrorSupported);
    return RC_OK;
}

RetCode DcameraHdfDemo::GetStreamBasicConfigurations(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    std::vector<int32_t>  streamBasicConfigurations;
    camera_metadata_item_t entry;
    int ret = OHOS::Camera::FindCameraMetadataItem(data, OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS, &entry);
    if (ret != 0) {
        DHLOGE("demo test: get OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS error");
        return RC_ERROR;
    }

    uint32_t count = entry.count;
    DHLOGI("demo test: streamBasicConfigurations count  %{public}d",  count);
    for (uint32_t i = 0 ; i < count; i++) {
        streamBasicConfigurations.push_back(*(entry.data.i32 + i));
    }

    for (auto it = streamBasicConfigurations.begin(); it != streamBasicConfigurations.end(); it++) {
        DHLOGI("demo test: streamBasicConfigurations %{public}d ", *it);
    }

    return RC_OK;
}

RetCode DcameraHdfDemo::GetFpsRange(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    std::vector<int32_t>  fpsRange;
    camera_metadata_item_t entry;
    int ret = OHOS::Camera::FindCameraMetadataItem(data, OHOS_ABILITY_FPS_RANGES, &entry);
    if (ret != 0) {
        DHLOGE("demo test: get OHOS_ABILITY_FPS_RANGES error");
        return RC_ERROR;
    }

    uint32_t count = entry.count;
    DHLOGI("demo test: fpsRange count  %{public}d",  count);
    for (uint32_t i = 0 ; i < count; i++) {
        fpsRange.push_back(*(entry.data.i32 + i));
    }

    for (auto it = fpsRange.begin(); it != fpsRange.end(); it++) {
        DHLOGI("demo test: fpsRange %{public}d ", *it);
    }

    return RC_OK;
}

RetCode DcameraHdfDemo::GetCameraPosition(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    uint8_t  cameraPosition;
    camera_metadata_item_t entry;
    int ret = OHOS::Camera::FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_POSITION, &entry);
    if (ret != 0) {
        DHLOGE("demo test: get OHOS_ABILITY_CAMERA_POSITION error");
        return RC_ERROR;
    }

    cameraPosition= *(entry.data.u8);
    DHLOGI("demo test: cameraPosition  %{public}d", cameraPosition);
    return RC_OK;
}

RetCode DcameraHdfDemo::GetCameraType(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    uint8_t  cameraType;
    camera_metadata_item_t entry;
    int ret = OHOS::Camera::FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_TYPE, &entry);
    if (ret != 0) {
        DHLOGE("demo test: get OHOS_ABILITY_CAMERA_TYPE error");
        return RC_ERROR;
    }

    cameraType= *(entry.data.u8);
    DHLOGI("demo test: cameraType  %{public}d", cameraType);
    return RC_OK;
}

RetCode DcameraHdfDemo::GetCameraConnectionType(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    uint8_t  cameraConnectionType;
    camera_metadata_item_t entry;
    int ret = OHOS::Camera::FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_CONNECTION_TYPE, &entry);
    if (ret != 0) {
        DHLOGE("demo test: get OHOS_ABILITY_CAMERA_CONNECTION_TYPE error");
        return RC_ERROR;
    }

    cameraConnectionType= *(entry.data.u8);
    DHLOGI("demo test: cameraConnectionType  %{public}d", cameraConnectionType);
    return RC_OK;
}

RetCode DcameraHdfDemo::GetFaceDetectMaxNum(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    uint8_t  faceDetectMaxNum;
    camera_metadata_item_t entry;
    int ret = OHOS::Camera::FindCameraMetadataItem(data, OHOS_STATISTICS_FACE_DETECT_MAX_NUM, &entry);
    if (ret != 0) {
        DHLOGE("demo test: get OHOS_STATISTICS_FACE_DETECT_MAX_NUM error");
        return RC_ERROR;
    }
    faceDetectMaxNum = *(entry.data.u8);
    DHLOGI("demo test: faceDetectMaxNum %{public}d ", faceDetectMaxNum);
    return RC_OK;
}

int32_t DemoCameraDeviceCallback::OnError(ErrorType type, int32_t errorCode)
{
    DHLOGI("demo test: OnError type : %{public}d, errorCode : %{public}d", type, errorCode);
    return RC_OK;
}

int32_t DemoCameraDeviceCallback::OnResult(uint64_t timestamp, const std::vector<uint8_t>& result)
{
    DHLOGI("demo test: OnResult timestamp : %{public}" PRIu64, timestamp);
    std::shared_ptr<OHOS::Camera::CameraMetadata> updateSettings;

    OHOS::Camera::MetadataUtils::ConvertVecToMetadata(result, updateSettings);
    for (auto it = results_list_.cbegin(); it != results_list_.cend(); it++) {
        switch (*it) {
            case OHOS_CONTROL_FOCUS_MODE: {
                common_metadata_header_t* data = updateSettings->get();
                uint8_t focusMode;
                camera_metadata_item_t entry;
                int ret = OHOS::Camera::FindCameraMetadataItem(data, OHOS_CONTROL_FOCUS_MODE, &entry);
                if (ret != 0) {
                    DHLOGE("demo test: get OHOS_CONTROL_FOCUS_MODE error");
                    return RC_ERROR;
                }
                focusMode = *(entry.data.u8);
                DHLOGI("demo test: focusMode %{public}d", focusMode);
                break;
            }
            case OHOS_CONTROL_EXPOSURE_MODE: {
                common_metadata_header_t* data = updateSettings->get();
                uint8_t exposureMode;
                camera_metadata_item_t entry;
                int ret = OHOS::Camera::FindCameraMetadataItem(data, OHOS_CONTROL_EXPOSURE_MODE, &entry);
                if (ret != 0) {
                    return RC_ERROR;
                }
                exposureMode = *(entry.data.u8);
                DHLOGI("demo test: exposureMode %{public}d", exposureMode);
                break;
            }
            default:
                return RC_ERROR;
        }
    }

    return RC_OK;
}

int32_t DemoCameraHostCallback::OnCameraStatus(const std::string& cameraId, CameraStatus status)
{
    DHLOGI("%{public}s, enter. cameraId = %{public}s, status = %{public}d",
        __func__, cameraId.c_str(), static_cast<int>(status));
    return RC_OK;
}

int32_t DemoCameraHostCallback::OnFlashlightStatus(const std::string& cameraId, FlashlightStatus status)
{
    DHLOGI("%{public}s, enter. cameraId = %{public}s, status = %{public}d",
        __func__, cameraId.c_str(), static_cast<int>(status));
    return RC_OK;
}

int32_t DemoCameraHostCallback::OnCameraEvent(const std::string& cameraId, CameraEvent event)
{
    DHLOGI("%{public}s, enter. cameraId = %{public}s, event = %{public}d",
        __func__, cameraId.c_str(), static_cast<int>(event));
    return RC_OK;
}

int32_t DemoStreamOperatorCallback::OnCaptureStarted(int32_t captureId, const std::vector<int32_t>& streamIds)
{
    DHLOGI("%{public}s, enter. captureId = %{public}d, streamIds size = %{public}zu", __func__, captureId,
        streamIds.size());
    return RC_OK;
}

int32_t DemoStreamOperatorCallback::OnCaptureEnded(int32_t captureId, const std::vector<CaptureEndedInfo>& infos)
{
    DHLOGI("%{public}s, enter. captureId = %{public}d, infos size = %{public}zu", __func__, captureId, infos.size());
    return RC_OK;
}

int32_t DemoStreamOperatorCallback::OnCaptureError(int32_t captureId, const std::vector<CaptureErrorInfo>& infos)
{
    DHLOGI("%{public}s, enter. captureId = %{public}d, infos size = %{public}zu", __func__, captureId, infos.size());
    return RC_OK;
}

int32_t DemoStreamOperatorCallback::OnFrameShutter(int32_t captureId,
    const std::vector<int32_t>& streamIds, uint64_t timestamp)
{
    DHLOGI("%{public}s, enter. captureId = %{public}d, streamIds size = %{public}zu, timestamp = %{public}" PRIu64,
        __func__, captureId, streamIds.size(), timestamp);
    return RC_OK;
}
}
} // namespace OHOS::DistributedHardware