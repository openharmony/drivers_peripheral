/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "hdi_common_v1_2.h"
#include "camera.h"
#include "video_key_info.h"

namespace OHOS::Camera {
OHOS::HDI::Camera::V1_0::FlashlightStatus HdiCommonV1_2::statusCallback =
                static_cast<OHOS::HDI::Camera::V1_0::FlashlightStatus>(0);

void HdiCommonV1_2::Init()
{
    uint32_t mainVer;
    uint32_t minVer;
    int32_t ret;
    if (serviceV1_2 == nullptr) {
        serviceV1_2 = OHOS::HDI::Camera::V1_2::ICameraHost::Get("camera_service", false);
        if (serviceV1_2 == nullptr) {
            printf("Init ICameraHost get failed serviceV1_2 nullptr\n");
            CAMERA_LOGE("Init ICameraHost get failed serviceV1_2 nullptr");
            return;
        }
        CAMERA_LOGI("V1_2::ICameraHost get success");
        ret = serviceV1_2->GetVersion(mainVer, minVer);
        if (ret != 0) {
            printf("Init GetVersion failed, ret = %d\n", ret);
            CAMERA_LOGE("Init GetVersion failed, ret = %{public}d", ret);
            return;
        }
        CAMERA_LOGI("V1_2::ICameraHost get version success, %{public}d, %{public}d", mainVer, minVer);
        service = static_cast<OHOS::HDI::Camera::V1_0::ICameraHost *>(serviceV1_2.GetRefPtr());
    }

    hostCallback = new TestCameraHostCallback();
    ret = service->SetCallback(hostCallback);
    if (ret != 0) {
        printf("Init SetCallback failed, ret = %d\n", ret);
        CAMERA_LOGE("Init SetCallback failed, ret = %{public}d", ret);
    }
}

int32_t HdiCommonV1_2::DefferredImageTestInit()
{
    constexpr const char* serviceName = "camera_image_process_service";
    constexpr const int userId = 100;
    int ret = 0;

    // get ImageProcessService
    imageProcessService_ = OHOS::HDI::Camera::V1_2::ImageProcessServiceProxy::Get(serviceName, false);
    if (imageProcessService_ == nullptr) {
        CAMERA_LOGE("ImageProcessServiceProxy::Get Fail, imageProcessService is nullptr");
        printf("ImageProcessServiceProxy::Get Fail, imageProcessService is nullptr\n");
        return -1;
    }
    imageProcessCallback_ = new OHOS::Camera::HdiCommonV1_2::TestImageProcessCallback();
    if (imageProcessCallback_ == nullptr) {
        CAMERA_LOGE("DefferredImageTestInit imageProcessCallback_ get failed imageProcessCallback_ nullptr");
        printf("DefferredImageTestInit imageProcessCallback_ get failed imageProcessCallback_ nullptr\n");
        return -1;
    }
    ret = imageProcessService_->CreateImageProcessSession(userId, imageProcessCallback_, imageProcessSession_);
    if (ret != 0) {
        CAMERA_LOGE("CreateImageProcessSession failed, ret = %{public}d", ret);
        printf("CreateImageProcessSession failed, ret = %d\n", ret);
        return -1;
    }
    if (imageProcessSession_ == nullptr) {
        CAMERA_LOGE("CreateImageProcessSession Fail, imageProcessSession is nullptr: %{public}d", ret);
        printf("CreateImageProcessSession Fail, imageProcessSession is nullptr: %d\r\n", ret);
        return -1;
    }
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(itemCapacity, dataCapacity);
    int32_t cameraUserId = 100;
    meta->addEntry(OHOS_CAMERA_USER_ID, &cameraUserId, dataCount);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    cameraDevice->UpdateSettings(metaVec);
    return 0;
}

void HdiCommonV1_2::Open(int cameraId)
{
    if (cameraDevice == nullptr) {
        if (service == nullptr) {
            printf("Open failed service nullptr\n");
            CAMERA_LOGE("Open failed service nullptr");
            return;
        }
        service->GetCameraIds(cameraIds);
        if (cameraIds.size() == 0) {
            printf("Open GetCameraIds failed\n");
            CAMERA_LOGE("Open GetCameraIds failed");
            return;
        }
        GetCameraMetadata(cameraId);
        deviceCallback = new OHOS::Camera::HdiCommon::DemoCameraDeviceCallback();
        if (serviceV1_2 == nullptr) {
            printf("Open failed serviceV1_2 nullptr\n");
            CAMERA_LOGE("Open failed serviceV1_2 nullptr");
            return;
        }
        if (DEVICE_1 == cameraId) {
            rc = serviceV1_2->OpenCamera_V1_1(cameraIds[1], deviceCallback, cameraDeviceV1_1);
        } else {
            rc = serviceV1_2->OpenCamera_V1_1(cameraIds[0], deviceCallback, cameraDeviceV1_1);
        }
        if (rc != HDI::Camera::V1_0::NO_ERROR || cameraDeviceV1_1 == nullptr) {
            printf("Open OpenCamera_V1_1 failed, rc = %d\n", rc);
            CAMERA_LOGE("Open OpenCamera_V1_1 failed, rc = %{public}d", rc);
            return;
        }
        cameraDevice = static_cast<OHOS::HDI::Camera::V1_0::ICameraDevice *>(cameraDeviceV1_1.GetRefPtr());
        CAMERA_LOGI("OpenCamera V1_2 success");
    }
}

void HdiCommonV1_2::OpenCameraV1_2(int cameraId)
{
    if (cameraDevice == nullptr) {
        if (service == nullptr) {
            printf("OpenCameraV1_2 failed service nullptr\n");
            CAMERA_LOGE("OpenCameraV1_2 failed service nullptr");
            return;
        }
        service->GetCameraIds(cameraIds);
        if (cameraIds.size() == 0) {
            printf("OpenCameraV1_2 GetCameraIds failed\n");
            CAMERA_LOGE("OpenCameraV1_2 GetCameraIds failed");
            return;
        }
        GetCameraMetadata(cameraId);
        deviceCallback = new OHOS::Camera::HdiCommon::DemoCameraDeviceCallback();
        if (serviceV1_2 == nullptr) {
            printf("OpenCameraV1_2 failed serviceV1_2 nullptr\n");
            CAMERA_LOGE("OpenCameraV1_2 failed serviceV1_2 nullptr");
            return;
        }
        if (cameraId == DEVICE_1) {
            rc = serviceV1_2->OpenCamera_V1_2(cameraIds[1], deviceCallback, cameraDeviceV1_2);
        } else {
            rc = serviceV1_2->OpenCamera_V1_2(cameraIds[0], deviceCallback, cameraDeviceV1_2);
        }
        if (rc != HDI::Camera::V1_0::NO_ERROR || cameraDeviceV1_2 == nullptr) {
            printf("OpenCameraV1_2 failed, rc = %d\n", rc);
            CAMERA_LOGE("OpenCameraV1_2 failed, rc = %{public}d", rc);
            return;
        }
        cameraDevice = static_cast<OHOS::HDI::Camera::V1_0::ICameraDevice *>(cameraDeviceV1_2.GetRefPtr());
        CAMERA_LOGI("OpenCamera V1_2 success");
    }
}

void HdiCommonV1_2::GetCameraMetadata(int cameraId)
{
    if (DEVICE_1 == cameraId) {
        rc = service->GetCameraAbility(cameraIds[1], abilityVec);
    } else {
        rc = service->GetCameraAbility(cameraIds[0], abilityVec);
    }
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        printf("GetCameraAbility failed, rc = %d\n", rc);
        CAMERA_LOGE("GetCameraAbility failed, rc = %{public}d", rc);
        return;
    }
    MetadataUtils::ConvertVecToMetadata(abilityVec, ability);
}

void HdiCommonV1_2::DefaultSketch(
    std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> &infos)
{
    infos->v1_0.streamId_ = streamIdSketch;
    infos->v1_0.width_ = sketchWidth;
    infos->v1_0.height_ = sketchHeight;
    infos->v1_0.format_ = previewFormat;
    infos->v1_0.dataspace_ = UT_DATA_SIZE;
    infos->v1_0.intent_ = StreamIntent::PREVIEW;
    infos->v1_0.tunneledMode_ = UT_TUNNEL_MODE;
}

void HdiCommonV1_2::DefaultInfosSketch(
    std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> &infos)
{
    DefaultSketch(infos);
    std::shared_ptr<StreamConsumer> consumer_pre = std::make_shared<StreamConsumer>();
    infos->v1_0.bufferQueue_ = consumer_pre->CreateProducerSeq([this](void* addr, uint32_t size) {
        DumpImageFile(streamIdSketch, "yuv", addr, size);
    });
    infos->v1_0.bufferQueue_->producer_->SetQueueSize(UT_DATA_SIZE);
    consumerMap_[StreamIntent::PREVIEW] = consumer_pre;
}

void HdiCommonV1_2::DefaultInfosPreviewV1_2(
    std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> &infos)
{
    DefaultPreview(infos);
    std::shared_ptr<StreamConsumer> consumer_pre = std::make_shared<StreamConsumer>();
    infos->v1_0.bufferQueue_ = consumer_pre->CreateProducerSeq([this](void* addr, uint32_t size) {
        DumpImageFile(streamIdPreview, "yuv", addr, size);
    });
    infos->v1_0.bufferQueue_->producer_->SetQueueSize(UT_DATA_SIZE);
}

void HdiCommonV1_2::StartCapture(int streamId, int captureId, bool shutterCallback, bool isStreaming)
{
    captureInfo = std::make_shared<CaptureInfo>();
    captureInfo->streamIds_ = {streamId};
    captureInfo->captureSetting_ = abilityVec;
    captureInfo->enableShutterCallback_ = shutterCallback;
    if (streamOperator_V1_2 != nullptr) {
        rc = (OHOS::HDI::Camera::V1_2::CamRetCode)streamOperator_V1_2->Capture(captureId, *captureInfo, isStreaming);
    } else if (streamOperator_V1_1 != nullptr) {
        rc = (OHOS::HDI::Camera::V1_2::CamRetCode)streamOperator_V1_1->Capture(captureId, *captureInfo, isStreaming);
    } else {
        rc = (OHOS::HDI::Camera::V1_2::CamRetCode)streamOperator->Capture(captureId, *captureInfo, isStreaming);
    }

    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        printf("check Capture: Capture fail, rc = %d\n", rc);
        CAMERA_LOGE("check Capture: Capture fail, rc = %{public}d", rc);
    }
    sleep(UT_SLEEP_TIME);
}

void HdiCommonV1_2::StopStream(std::vector<int>& captureIds, std::vector<int>& streamIds)
{
    if (captureIds.size() > 0) {
        for (auto &captureId : captureIds) {
            if (streamOperator_V1_2 != nullptr) {
                rc = streamOperator_V1_2->CancelCapture(captureId);
            } else if (streamOperator_V1_1 != nullptr) {
                rc = streamOperator_V1_1->CancelCapture(captureId);
            } else {
                rc = streamOperator->CancelCapture(captureId);
            }
            if (rc != HDI::Camera::V1_0::NO_ERROR) {
                printf("CancelCapture fail, rc = %d, captureId = %d\n", rc, captureId);
                CAMERA_LOGE("CancelCapture fail, rc = %{public}d, captureId = %{public}d", rc, captureId);
            }
        }
    }
    if (streamIds.size() > 0) {
        if (streamOperator_V1_2 != nullptr) {
            rc = streamOperator_V1_2->ReleaseStreams(streamIds);
        } else if (streamOperator_V1_1 != nullptr) {
            rc = streamOperator_V1_1->ReleaseStreams(streamIds);
        } else {
            rc = streamOperator->ReleaseStreams(streamIds);
        }
        if (rc != HDI::Camera::V1_0::NO_ERROR) {
            printf("check Capture: ReleaseStreams fail, rc = %d\n", rc);
            CAMERA_LOGE("check Capture: ReleaseStreams fail, rc = %{public}d", rc);
        }
    }
}

int32_t HdiCommonV1_2::TestStreamOperatorCallbackV1_2::OnCaptureStarted(
    int32_t captureId, const std::vector<int32_t> &streamId)
{
    for (auto it : streamId) {
        CAMERA_LOGE("captureId: %{public}d, streamId: %{public}d", captureId, it);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t HdiCommonV1_2::TestStreamOperatorCallbackV1_2::OnCaptureEnded(int32_t captureId,
    const std::vector<CaptureEndedInfo> &infos)
{
    for (auto it : infos) {
        CAMERA_LOGE("captureId: %{public}d, streamId: %{public}d, count: %{public}d", captureId, it.streamId_,
            it.frameCount_);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t HdiCommonV1_2::TestStreamOperatorCallbackV1_2::OnCaptureError(int32_t captureId,
    const std::vector<CaptureErrorInfo> &infos)
{
    for (auto it : infos) {
        CAMERA_LOGE("captureId: %{public}d, streamId: %{public}d, error: %{public}d", captureId, it.streamId_,
            it.error_);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t HdiCommonV1_2::TestStreamOperatorCallbackV1_2::OnFrameShutter(int32_t captureId,
    const std::vector<int32_t> &streamIds, uint64_t timestamp)
{
    (void)timestamp;
    for (auto it : streamIds) {
        CAMERA_LOGE("captureId: %{public}d, streamId: %{public}d", captureId, it);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t HdiCommonV1_2::TestStreamOperatorCallbackV1_2::OnCaptureStarted_V1_2(int32_t captureId,
    const std::vector<HDI::Camera::V1_2::CaptureStartedInfo> &infos)
{
    for (auto it : infos) {
        CAMERA_LOGE("captureId: %{public}d, streamId: %{public}d", captureId, it.streamId_);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t HdiCommonV1_2::TestCameraHostCallbackV1_2::OnCameraStatus(const std::string& cameraId, CameraStatus status)
{
    CAMERA_LOGE("cameraId: %{public}s, status: %{public}d", cameraId.c_str(), status);
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t HdiCommonV1_2::TestCameraHostCallbackV1_2::OnFlashlightStatus(
    const std::string& cameraId, FlashlightStatus status)
{
    CAMERA_LOGE("cameraId: %{public}s, status: %{public}d", cameraId.c_str(), status);
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t HdiCommonV1_2::TestCameraHostCallbackV1_2::OnCameraEvent(const std::string& cameraId, CameraEvent event)
{
    CAMERA_LOGE("cameraId: %{public}s, status: %{public}d", cameraId.c_str(), event);
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t HdiCommonV1_2::TestCameraHostCallbackV1_2::OnFlashlightStatus_V1_2(FlashlightStatus status)
{
    CAMERA_LOGE("status: %{public}d", status);
    HdiCommonV1_2::statusCallback = status;
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t HdiCommonV1_2::TestImageProcessCallback::OnProcessDone(const std::string& imageId,
    const OHOS::HDI::Camera::V1_2::ImageBufferInfo& buffer)
{
    CAMERA_LOGI("imageId: %{public}s", imageId.c_str());
    coutProcessDone_++;
    curImageId_ = imageId;
    curImageBufferInfo_ = buffer;
    isDone_ = true;
    return 0;
}

int32_t HdiCommonV1_2::TestImageProcessCallback::OnStatusChanged(OHOS::HDI::Camera::V1_2::SessionStatus status)
{
    CAMERA_LOGI("status: %{public}d", status);
    curStatus_ = status;
    coutStatusChanged_++;
    return 0;
}

int32_t HdiCommonV1_2::TestImageProcessCallback::OnError(const std::string& imageId,
    OHOS::HDI::Camera::V1_2::ErrorCode errorCode)
{
    CAMERA_LOGI("imageId: %{public}s, errorCode: %{public}d", imageId.c_str(), errorCode);
    curImageId_ = imageId;
    curErrorCode_ = errorCode;
    countError_++;
    return 0;
}
} // OHOS::Camera