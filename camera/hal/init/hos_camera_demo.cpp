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

#include "hos_camera_demo.h"

namespace OHOS::Camera {
HosCameraDemo::HosCameraDemo() {}
HosCameraDemo::~HosCameraDemo() {}

void HosCameraDemo::SetStreamInfo(std::shared_ptr<StreamInfo>& streamInfo,
    const std::shared_ptr<StreamCustomer>& streamCustomer,
    const int streamId, const StreamIntent intent)
{
    constexpr uint32_t datasapce = 8;
    constexpr uint32_t tunneledMode = 5;

    if (intent == PREVIEW) {
        constexpr uint32_t width = CAMERA_PREVIEW_WIDTH;
        constexpr uint32_t height = CAMERA_PREVIEW_HEIGHT;
        streamInfo->width_ = width;
        streamInfo->height_ = height;
    } else if (intent == STILL_CAPTURE) {
        constexpr uint32_t width = CAMERA_CAPTURE_WIDTH;
        constexpr uint32_t height = CAMERA_CAPTURE_HEIGHT;
        streamInfo->width_ = width;
        streamInfo->height_ = height;
        streamInfo->encodeType_ = CAMERA_CAPTURE_ENCODE_TYPE;
    } else {
        constexpr uint32_t width = CAMERA_VIDEO_WIDTH;
        constexpr uint32_t height = CAMERA_VIDEO_HEIGHT;
        streamInfo->width_ = width;
        streamInfo->height_ = height;
        streamInfo->encodeType_ = CAMERA_VIDEO_ENCODE_TYPE;
    }

    streamInfo->streamId_ = streamId;
    streamInfo->format_ =  CAMERA_FORMAT;
    streamInfo->datasapce_ = datasapce;
    streamInfo->intent_ = intent;
    streamInfo->tunneledMode_ = tunneledMode;
    streamInfo->bufferQueue_ = streamCustomer->CreateProducer();
    streamInfo->bufferQueue_->SetQueueSize(8); // 8:set bufferQueue size
}

void HosCameraDemo::GetStreamOpt()
{
    int rc = 0;

    if (streamOperator_ == nullptr) {
#ifdef CAMERA_BUILT_ON_OHOS_LITE
        const std::shared_ptr<IStreamOperatorCallback> streamOperatorCallback =
            std::make_shared<StreamOperatorCallback>();
#else
        const sptr<IStreamOperatorCallback> streamOperatorCallback = new StreamOperatorCallback();
#endif
        rc = demoCameraDevice_->GetStreamOperator(streamOperatorCallback, streamOperator_);
        if (rc != Camera::NO_ERROR) {
            CAMERA_LOGE("demo test: GetStreamOpt GetStreamOperator fail\n");
            streamOperator_ = nullptr;
        }
    }
}

RetCode HosCameraDemo::CaptureON(const int streamId, const int captureId, CaptureMode mode)
{
    CAMERA_LOGD("demo test: CaptureON enter mode == %{public}d", mode);

    std::shared_ptr<Camera::CaptureInfo> captureInfo = std::make_shared<Camera::CaptureInfo>();
    captureInfo->streamIds_ = {streamId};
    captureInfo->captureSetting_ = ability_;
    captureInfo->enableShutterCallback_ = false;

    int rc = streamOperator_->Capture(captureId, captureInfo, true);
    if (rc != Camera::NO_ERROR) {
        CAMERA_LOGE("demo test: CaptureStart Capture error\n");
        streamOperator_->ReleaseStreams(captureInfo->streamIds_);
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

RetCode HosCameraDemo::CaptureOff(const int captureId, const CaptureMode mode)
{
    int rc = 0;
    CAMERA_LOGD("demo test: CaptureOff enter mode == %{public}d", mode);

    if (streamOperator_ == nullptr) {
        CAMERA_LOGE("demo test: CaptureOff streamOperator_ is nullptr\n");
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

    if (rc != Camera::NO_ERROR) {
        CAMERA_LOGE("demo test: CaptureOff CancelCapture error mode %{public}d rc == %{public}d\n", mode, rc);
        return RC_ERROR;
    }
    CAMERA_LOGD("demo test: CaptureOff exit");

    return RC_OK;
}

RetCode HosCameraDemo::CreateStream(const int streamId, std::shared_ptr<StreamCustomer>& streamCustomer,
    StreamIntent intent)
{
    int rc = 0;
    CAMERA_LOGD("demo test: CreateStream enter");

    GetStreamOpt();
    if (streamOperator_ == nullptr) {
        CAMERA_LOGE("demo test: CreateStream GetStreamOpt() is nullptr\n");
        return RC_ERROR;
    }

    std::shared_ptr<StreamInfo> streamInfo = std::make_shared<StreamInfo>();
    if (streamInfo == nullptr) {
        CAMERA_LOGE("demo test: std::make_shared<Camera::StreamInfo>() is nullptr\n");
        return RC_ERROR;
    }

    SetStreamInfo(streamInfo, streamCustomer, streamId, intent);
    if (streamInfo->bufferQueue_ == nullptr) {
        CAMERA_LOGE("demo test: CreateStream CreateProducer(); is nullptr\n");
        return RC_ERROR;
    }

    std::vector<std::shared_ptr<StreamInfo>> streamInfos;
    std::vector<std::shared_ptr<StreamInfo>>().swap(streamInfos);
    streamInfos.push_back(streamInfo);

    rc = streamOperator_->CreateStreams(streamInfos);
    if (rc != Camera::NO_ERROR) {
        CAMERA_LOGE("demo test: CreateStream CreateStreams error\n");
        return RC_ERROR;
    }

    rc = streamOperator_->CommitStreams(Camera::NORMAL, ability_);
    if (rc != Camera::NO_ERROR) {
        CAMERA_LOGE("demo test: CreateStream CommitStreams error\n");
        streamOperator_->ReleaseStreams({streamId});
        return RC_ERROR;
    }

    CAMERA_LOGD("demo test: CreateStream exit");

    return RC_OK;
}

RetCode HosCameraDemo::InitCameraDevice()
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
    demoCameraHost_->GetCameraAbility(cameraId, ability_);

    if (ability_ == nullptr) {
        CAMERA_LOGE("demo test: InitCameraDevice ability_ == nullptr");
        return RC_ERROR;
    }

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
    sptr<CameraDeviceCallback> callback = new CameraDeviceCallback();
#endif
    rc = demoCameraHost_->OpenCamera(cameraIds_.front(), callback, demoCameraDevice_);
    if (rc != Camera::NO_ERROR || demoCameraDevice_ == nullptr) {
        CAMERA_LOGE("demo test: InitCameraDevice OpenCamera failed");
        return RC_ERROR;
    }

    CAMERA_LOGD("demo test: InitCameraDevice exit");

    return RC_OK;
}

void HosCameraDemo::ReleaseCameraDevice()
{
    if (demoCameraDevice_ != nullptr) {
        CAMERA_LOGD("demo test: ReleaseCameraDevice close Device");
        demoCameraDevice_->Close();
        demoCameraDevice_ = nullptr;
    }
}

RetCode HosCameraDemo::InitSensors()
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
    demoCameraHost_ = ICameraHost::Get(DEMO_SERVICE_NAME);
#endif
    if (demoCameraHost_ == nullptr) {
        CAMERA_LOGE("demo test: ICameraHost::Get error");
        return RC_ERROR;
    }

#ifdef CAMERA_BUILT_ON_OHOS_LITE
    hostCallback_ = std::make_shared<CameraHostCallback>();
#else
    hostCallback_ = new CameraHostCallback();
#endif
    rc = demoCameraHost_->SetCallback(hostCallback_);
    if (rc != Camera::NO_ERROR) {
        CAMERA_LOGE("demo test: demoCameraHost_->SetCallback(hostCallback_) error");
        return RC_ERROR;
    }

    CAMERA_LOGD("demo test: InitSensors exit");

    return RC_OK;
}

void HosCameraDemo::StoreImage(const void* bufStart, const uint32_t size) const
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
        CAMERA_LOGE("sprintf_s error .....\n");
        return;
    }

    imgFD = open(path, O_RDWR | O_CREAT, 00766); // 00766:file operate permission
    if (imgFD == -1) {
        CAMERA_LOGE("demo test:open image file error %{public}s.....\n", strerror(errno));
        return;
    }

    CAMERA_LOGD("demo test:StoreImage %{public}s buf_start == %{public}p size == %{public}d\n", path, bufStart, size);

    ret = write(imgFD, bufStart, size);
    if (ret == -1) {
        CAMERA_LOGE("demo test:write image file error %{public}s.....\n", strerror(errno));
    }

    close(imgFD);
}

void HosCameraDemo::StoreVideo(const void* bufStart, const uint32_t size) const
{
    int ret = 0;

    ret = write(videoFd_, bufStart, size);
    if (ret == -1) {
        CAMERA_LOGE("demo test:write video file error %{public}s.....\n", strerror(errno));
    }
    CAMERA_LOGD("demo test:StoreVideo buf_start == %{public}p size == %{public}d\n", bufStart, size);
}

void HosCameraDemo::OpenVideoFile()
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

RetCode HosCameraDemo::CreateStreams(const int streamIdSecond, StreamIntent intent)
{
    int rc = 0;
    std::vector<std::shared_ptr<StreamInfo>> streamInfos;
    std::vector<std::shared_ptr<StreamInfo>>().swap(streamInfos);

    CAMERA_LOGD("demo test: CreateStreams streamIdSecond = %{public}d", streamIdSecond);
    GetStreamOpt();
    if (streamOperator_ == nullptr) {
        CAMERA_LOGE("demo test: CreateStreams GetStreamOpt() is nullptr\n");
        return RC_ERROR;
    }

    std::shared_ptr<StreamInfo> previewStreamInfo = std::make_shared<StreamInfo>();
    if (previewStreamInfo == nullptr) {
        CAMERA_LOGE("demo test: CreateStreams previewStreamInfo is nullptr\n");
        return RC_ERROR;
    }

    SetStreamInfo(previewStreamInfo, streamCustomerPreview_, STREAM_ID_PREVIEW, PREVIEW);
    if (previewStreamInfo->bufferQueue_ == nullptr) {
        CAMERA_LOGE("demo test: CreateStream CreateProducer(); is nullptr\n");
        return RC_ERROR;
    }
    streamInfos.push_back(previewStreamInfo);

    std::shared_ptr<StreamInfo> secondStreamInfo = std::make_shared<StreamInfo>();
    if (secondStreamInfo == nullptr) {
        CAMERA_LOGE("demo test: CreateStreams previewStreamInfo is nullptr\n");
        return RC_ERROR;
    }

    if (streamIdSecond == STREAM_ID_CAPTURE) {
        SetStreamInfo(secondStreamInfo, streamCustomerCapture_, STREAM_ID_CAPTURE, intent);
    } else {
        SetStreamInfo(secondStreamInfo, streamCustomerVideo_, STREAM_ID_VIDEO, intent);
    }

    if (secondStreamInfo->bufferQueue_ == nullptr) {
        CAMERA_LOGE("demo test: CreateStreams CreateProducer() secondStreamInfo is nullptr\n");
        return RC_ERROR;
    }
    streamInfos.push_back(secondStreamInfo);

    rc = streamOperator_->CreateStreams(streamInfos);
    if (rc != Camera::NO_ERROR) {
        CAMERA_LOGE("demo test: CreateStream CreateStreams error\n");
        return RC_ERROR;
    }

    rc = streamOperator_->CommitStreams(Camera::NORMAL, ability_);
    if (rc != Camera::NO_ERROR) {
        CAMERA_LOGE("demo test: CreateStream CommitStreams error\n");
        std::vector<int> streamIds = {STREAM_ID_PREVIEW, streamIdSecond};
        streamOperator_->ReleaseStreams(streamIds);
        return RC_ERROR;
    }

    return RC_OK;
}

RetCode HosCameraDemo::CaptureOnDualStreams(const int streamIdSecond)
{
    int rc = 0;
    CAMERA_LOGD("demo test: CaptuCaptureOnDualStreamsreON enter");

    std::shared_ptr<Camera::CaptureInfo> previewCaptureInfo = std::make_shared<Camera::CaptureInfo>();
    previewCaptureInfo->streamIds_ = {STREAM_ID_PREVIEW};
    previewCaptureInfo->captureSetting_ = ability_;
    previewCaptureInfo->enableShutterCallback_ = false;

    rc = streamOperator_->Capture(CAPTURE_ID_PREVIEW, previewCaptureInfo, true);
    if (rc != Camera::NO_ERROR) {
        CAMERA_LOGE("demo test: CaptureOnDualStreams preview Capture error\n");
        streamOperator_->ReleaseStreams(previewCaptureInfo->streamIds_);
        return RC_ERROR;
    }
    streamCustomerPreview_->ReceiveFrameOn(nullptr);

    std::shared_ptr<Camera::CaptureInfo> secondCaptureInfo = std::make_shared<Camera::CaptureInfo>();
    secondCaptureInfo->streamIds_ = {streamIdSecond};
    secondCaptureInfo->captureSetting_ = ability_;
    previewCaptureInfo->enableShutterCallback_ = false;

    if (streamIdSecond == STREAM_ID_CAPTURE) {
        rc = streamOperator_->Capture(CAPTURE_ID_CAPTURE, secondCaptureInfo, true);
        if (rc != Camera::NO_ERROR) {
            CAMERA_LOGE("demo test: CaptureOnDualStreams CAPTURE_ID_CAPTURE error\n");
            streamOperator_->ReleaseStreams(secondCaptureInfo->streamIds_);
            return RC_ERROR;
        }

        streamCustomerCapture_->ReceiveFrameOn([this](void* addr, const uint32_t size) {
            StoreImage(addr, size);
        });
    } else {
        rc = streamOperator_->Capture(CAPTURE_ID_VIDEO, secondCaptureInfo, true);
        if (rc != Camera::NO_ERROR) {
            CAMERA_LOGE("demo test: CaptureOnDualStreams CAPTURE_ID_VIDEO error\n");
            streamOperator_->ReleaseStreams(secondCaptureInfo->streamIds_);
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

RetCode HosCameraDemo::StartDualStreams(const int streamIdSecond)
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

RetCode HosCameraDemo::StartCaptureStream()
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

RetCode HosCameraDemo::StartVideoStream()
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

RetCode HosCameraDemo::StartPreviewStream()
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

RetCode HosCameraDemo::ReleaseAllStream()
{
    std::vector<int> streamIds = {};

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

void HosCameraDemo::QuitDemo()
{
    ReleaseCameraDevice();
    CAMERA_LOGD("demo test: QuitDemo done\n");
}

void HosCameraDemo::SetAwbMode(const int mode) const
{
    CAMERA_LOGD("demo test: SetAwbMode enter\n");

    constexpr size_t entryCapacity = 100;
    constexpr size_t dataCapacity = 2000;

    std::shared_ptr<CameraSetting> metaData = std::make_shared<CameraSetting>(entryCapacity, dataCapacity);

    const uint8_t awbMode = mode;
    metaData->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);
    demoCameraDevice_->UpdateSettings(metaData);

    CAMERA_LOGD("demo test: SetAwbMode exit\n");
}

void HosCameraDemo::SetAeExpo()
{
    int32_t expo;

    CAMERA_LOGD("demo test: SetAeExpo enter\n");

    constexpr size_t entryCapacity = 100;
    constexpr size_t dataCapacity = 2000;

    std::shared_ptr<CameraSetting> metaData = std::make_shared<CameraSetting>(entryCapacity, dataCapacity);

    if (aeStatus_) {
        expo = 0xa0;
    } else {
        expo = 0x30;
    }
    aeStatus_ = !aeStatus_;
    metaData->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &expo, 1);
    demoCameraDevice_->UpdateSettings(metaData);

    CAMERA_LOGD("demo test: SetAeExpo exit\n");
}

void HosCameraDemo::FlashlightOnOff(bool onOff)
{
    CAMERA_LOGD("demo test: FlashlightOnOff enter\n");

    if (demoCameraHost_ == nullptr) {
        CAMERA_LOGE("demo test: FlashlightOnOff demoCameraHost_ == nullptr\n");
        return;
    }

    demoCameraHost_->SetFlashlight(cameraIds_.front(), onOff);

    CAMERA_LOGD("demo test: FlashlightOnOff exit \n");
}

RetCode HosCameraDemo::StreamOffline(const int streamId)
{
    int rc = 0;
    constexpr size_t offlineDelayTime = 4;
    CAMERA_LOGD("demo test: StreamOffline enter\n");
#ifdef CAMERA_BUILT_ON_OHOS_LITE
    std::shared_ptr<IStreamOperatorCallback> streamOperatorCallback = std::make_shared<StreamOperatorCallback>();
    std::shared_ptr<IOfflineStreamOperator> offlineStreamOperator = nullptr;
#else
    sptr<IStreamOperatorCallback> streamOperatorCallback = new StreamOperatorCallback();
    sptr<IOfflineStreamOperator> offlineStreamOperator = nullptr;
#endif
    rc = streamOperator_->ChangeToOfflineStream({streamId}, streamOperatorCallback, offlineStreamOperator);
    if (rc != NO_ERROR) {
        CAMERA_LOGE("demo test: StreamOffline ChangeToOfflineStream error\n");
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
    if (rc != NO_ERROR) {
        CAMERA_LOGE("demo test: StreamOffline offlineStreamOperator->CancelCapture error\n");
        return RC_ERROR;
    }

    rc = offlineStreamOperator->Release();
    if (rc != OHOS::Camera::NO_ERROR) {
        CAMERA_LOGE("demo test: StreamOffline offlineStreamOperator->Release() error\n");
        return RC_ERROR;
    }

    streamCustomerCapture_->ReceiveFrameOff();

    CAMERA_LOGD("demo test: StreamOffline exit\n");

    return RC_OK;
}

RetCode HosCameraDemo::GetFaceDetectMode(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    uint8_t faceDetectMode;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_STATISTICS_FACE_DETECT_MODE, &entry);
    if (ret != 0) {
        CAMERA_LOGE("demo test: get OHOS_STATISTICS_FACE_DETECT_MODE error\n");
        return RC_ERROR;
    }
    faceDetectMode = *(entry.data.u8);
    CAMERA_LOGD("demo test: faceDetectMode %{public}d\n",  faceDetectMode);
    return RC_OK;
}

RetCode HosCameraDemo::GetFocalLength(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    float focalLength = 0.0;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_FOCAL_LENGTH, &entry);
    if (ret != 0) {
        CAMERA_LOGE("demo test:  get OHOS_ABILITY_FOCAL_LENGTH error\n");
        return RC_ERROR;
    }
    focalLength = *(entry.data.f);
    CAMERA_LOGD("demo test: focalLength %{public}f\n", focalLength);
    return RC_OK;
}

RetCode HosCameraDemo::GetAvailableFocusModes(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    std::vector<uint8_t> focusMode;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_FOCUS_MODES, &entry);
    if (ret != 0) {
        CAMERA_LOGE("demo test: get OHOS_ABILITY_FOCUS_MODES  error\n");
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

RetCode HosCameraDemo::GetAvailableExposureModes(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    std::vector<uint8_t> exposureMode;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_EXPOSURE_MODES, &entry);
    if (ret != 0) {
        CAMERA_LOGE("demo test: get OHOS_ABILITY_EXPOSURE_MODES  error\n");
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

RetCode HosCameraDemo::GetExposureCompensationRange(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    std::vector<int32_t>  exposureCompensationRange;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_AE_COMPENSATION_RANGE, &entry);
    if (ret != 0) {
        CAMERA_LOGE("demo test: get OHOS_CONTROL_AE_COMPENSATION_RANGE error\n");
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

RetCode HosCameraDemo::GetExposureCompensationSteps(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    camera_rational_t exposureCompensationSteps;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_AE_COMPENSATION_STEP, &entry);
    if (ret != 0) {
        CAMERA_LOGE("demo test: get OHOS_CONTROL_AE_COMPENSATION_STEP error\n");
        return RC_ERROR;
    }
    exposureCompensationSteps.numerator = entry.data.r->numerator;
    exposureCompensationSteps.denominator = entry.data.r->denominator;
    CAMERA_LOGD("demo test: steps.numerator %{public}d  and steps.denominator %{public}d \n",
        exposureCompensationSteps.numerator, exposureCompensationSteps.denominator);
    return RC_OK;
}

RetCode HosCameraDemo::GetAvailableMeterModes(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    std::vector<uint8_t> meterModes;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_METER_MODES, &entry);
    if (ret != 0) {
        CAMERA_LOGE("demo test: get OHOS_ABILITY_METER_MODES  error\n");
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

RetCode HosCameraDemo::GetAvailableFlashModes(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    std::vector<uint8_t> flashModes;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_FLASH_MODES, &entry);
    if (ret != 0) {
        CAMERA_LOGE("demo test: get OHOS_ABILITY_FLASH_MODES  error\n");
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

RetCode HosCameraDemo::GetMirrorSupported(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    uint8_t mirrorSupported;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED, &entry);
    if (ret != 0) {
        CAMERA_LOGE("demo test: get OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED error\n");
        return RC_ERROR;
    }
    mirrorSupported = *(entry.data.u8);
    uint8_t  *tmpPtr = entry.data.u8;
    CAMERA_LOGD("demo test: mirrorSupported  %{public}d\n",  mirrorSupported);
    return RC_OK;
}

RetCode HosCameraDemo::GetStreamBasicConfigurations(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    std::vector<int32_t>  streamBasicConfigurations;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS, &entry);
    if (ret != 0) {
        CAMERA_LOGE("demo test: get OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS error\n");
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

RetCode HosCameraDemo::GetFpsRange(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    std::vector<int32_t>  fpsRange;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_FPS_RANGES, &entry);
    if (ret != 0) {
        CAMERA_LOGE("demo test: get OHOS_ABILITY_FPS_RANGES error\n");
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

RetCode HosCameraDemo::GetCameraPosition(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    uint8_t  cameraPosition;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_POSITION, &entry);
    if (ret != 0) {
        CAMERA_LOGE("demo test: get OHOS_ABILITY_CAMERA_POSITION error\n");
        return RC_ERROR;
    }

    cameraPosition= *(entry.data.u8);
    CAMERA_LOGD("demo test: cameraPosition  %{public}d\n", cameraPosition);
    return RC_OK;
}

RetCode HosCameraDemo::GetCameraType(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    uint8_t  cameraType;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_TYPE, &entry);
    if (ret != 0) {
        CAMERA_LOGE("demo test: get OHOS_ABILITY_CAMERA_TYPE error\n");
        return RC_ERROR;
    }

    cameraType= *(entry.data.u8);
    CAMERA_LOGD("demo test: cameraType  %{public}d\n", cameraType);
    return RC_OK;
}

RetCode HosCameraDemo::GetCameraConnectionType(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    uint8_t  cameraConnectionType;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_CONNECTION_TYPE, &entry);
    if (ret != 0) {
        CAMERA_LOGE("demo test: get OHOS_ABILITY_CAMERA_CONNECTION_TYPE error\n");
        return RC_ERROR;
    }

    cameraConnectionType= *(entry.data.u8);
    CAMERA_LOGD("demo test: cameraConnectionType  %{public}d\n", cameraConnectionType);
    return RC_OK;
}

RetCode HosCameraDemo::GetFaceDetectMaxNum(std::shared_ptr<CameraAbility> &ability)
{
    common_metadata_header_t* data = ability->get();
    uint8_t  faceDetectMaxNum;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_STATISTICS_FACE_DETECT_MAX_NUM, &entry);
    if (ret != 0) {
        CAMERA_LOGE("demo test: get OHOS_STATISTICS_FACE_DETECT_MAX_NUM error\n");
        return RC_ERROR;
    }
    faceDetectMaxNum = *(entry.data.u8);
    CAMERA_LOGD("demo test: faceDetectMaxNum %{public}d \n", faceDetectMaxNum);
    return RC_OK;
}
} // namespace OHOS::Camera
