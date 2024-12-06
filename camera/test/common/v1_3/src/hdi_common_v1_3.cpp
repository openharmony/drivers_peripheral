/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "hdi_common_v1_3.h"
#include "camera.h"
#include "video_key_info.h"

namespace OHOS::Camera {
HdiCommonV1_3::StreamResultCallback HdiCommonV1_3::streamResultCallback_ = 0;

void HdiCommonV1_3::Init()
{
    uint32_t mainVer;
    uint32_t minVer;
    int32_t ret;
    if (serviceV1_3 == nullptr) {
        serviceV1_3 = OHOS::HDI::Camera::V1_3::ICameraHost::Get("camera_service", false);
        if (serviceV1_3 == nullptr) {
            printf("Init ICameraHost get failed serviceV1_3 nullptr\n");
            CAMERA_LOGE("Init ICameraHost get failed serviceV1_3 nullptr");
            return;
        }
        CAMERA_LOGI("V1_3::ICameraHost get success");
        ret = serviceV1_3->GetVersion(mainVer, minVer);
        if (ret != 0) {
            printf("Init GetVersion failed, ret = %d\n", ret);
            CAMERA_LOGE("Init GetVersion failed, ret = %{public}d", ret);
            return;
        }
        CAMERA_LOGI("V1_3::ICameraHost get version success, %{public}d, %{public}d", mainVer, minVer);
    }

    hostCallback = new TestCameraHostCallback();
    ret = serviceV1_3->SetCallback(hostCallback);
    if (ret != 0) {
        printf("Init SetCallback failed, ret = %d\n", ret);
        CAMERA_LOGE("Init SetCallback failed, ret = %{public}d", ret);
    }
}

int32_t HdiCommonV1_3::DefferredVideoTestInit()
{
    constexpr const char* serviceName = "camera_video_process_service";
    constexpr const int userId = 100;
    int ret = 0;

    // get VideoProcessService
    videoProcessService_ = OHOS::HDI::Camera::V1_3::IVideoProcessService::Get(serviceName, false);
    if (videoProcessService_ == nullptr) {
        CAMERA_LOGE("IVideoProcessService::Get Fail, videoProcessService_ is nullptr");
        printf("IVideoProcessService::Get Fail, videoProcessService_ is nullptr\n");
        return -1;
    }
    videoProcessCallback_ = new OHOS::Camera::HdiCommonV1_3::TestVideoProcessCallback();
    if (videoProcessCallback_ == nullptr) {
        CAMERA_LOGE("DefferredVideoTestInit videoProcessCallback_ get failed videoProcessCallback_ nullptr");
        printf("DefferredVideoTestInit videoProcessCallback_ get failed videoProcessCallback_ nullptr\n");
        return -1;
    }
    ret = videoProcessService_->CreateVideoProcessSession(userId, videoProcessCallback_, videoProcessSession_);
    if (ret != 0) {
        CAMERA_LOGE("CreateVideoProcessSession failed, ret = %{public}d", ret);
        printf("CreateVideoProcessSession failed, ret = %d\n", ret);
        return -1;
    }
    if (videoProcessSession_ == nullptr) {
        CAMERA_LOGE("CreateVideoProcessSession Fail, videoProcessSession_ is nullptr: %{public}d", ret);
        printf("CreateVideoProcessSession Fail, videoProcessSession_ is nullptr: %d\r\n", ret);
        return -1;
    }
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(itemCapacity, dataCapacity);
    int32_t cameraUserId = 100;
    meta->addEntry(OHOS_CAMERA_USER_ID, &cameraUserId, dataCount);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    cameraDeviceV1_3->UpdateSettings(metaVec);
    return ret;
}

void HdiCommonV1_3::Open(int cameraId)
{
    if (cameraDeviceV1_3 == nullptr) {
        if (serviceV1_3 == nullptr) {
            printf("Open failed serviceV1_3 nullptr\n");
            CAMERA_LOGE("Open failed serviceV1_3 nullptr");
            return;
        }
        serviceV1_3->GetCameraIds(cameraIds);
        if (cameraIds.size() == 0) {
            printf("Open GetCameraIds failed\n");
            CAMERA_LOGE("Open GetCameraIds failed");
            return;
        }
        GetCameraMetadata(cameraId);
        deviceCallback = new OHOS::Camera::HdiCommon::DemoCameraDeviceCallback();
        if (DEVICE_1 == cameraId) {
            rc = serviceV1_3->OpenCamera_V1_3(cameraIds[1], deviceCallback, cameraDeviceV1_3);
        } else {
            rc = serviceV1_3->OpenCamera_V1_3(cameraIds[0], deviceCallback, cameraDeviceV1_3);
        }
        if (rc != HDI::Camera::V1_0::NO_ERROR || cameraDeviceV1_3 == nullptr) {
            printf("Open OpenCamera_V1_3 failed, rc = %d\n", rc);
            CAMERA_LOGE("Open OpenCamera_V1_3 failed, rc = %{public}d", rc);
        } else {
            CAMERA_LOGI("Open success");
        }
    }
}

void HdiCommonV1_3::OpenSecureCamera(int cameraId)
{
    if (cameraDeviceV1_3 == nullptr) {
        if (serviceV1_3 == nullptr) {
            printf("OpenSecureCamera failed serviceV1_3 nullptr\n");
            CAMERA_LOGE("OpenSecureCamera failed serviceV1_3 nullptr");
            return;
        }
        serviceV1_3->GetCameraIds(cameraIds);
        if (cameraIds.size() == 0) {
            printf("OpenSecureCamera GetCameraIds failed\n");
            CAMERA_LOGE("OpenSecureCamera GetCameraIds failed");
            return;
        }
        GetCameraMetadata(cameraId);
        deviceCallback = new OHOS::Camera::HdiCommon::DemoCameraDeviceCallback();
        if (DEVICE_1 == cameraId) {
            rc = serviceV1_3->OpenSecureCamera(cameraIds[1], deviceCallback, cameraDeviceV1_3);
        } else {
            rc = serviceV1_3->OpenSecureCamera(cameraIds[0], deviceCallback, cameraDeviceV1_3);
        }
        if (rc != HDI::Camera::V1_0::NO_ERROR || cameraDeviceV1_3 == nullptr) {
            printf("Open OpenCamera_V1_3 failed, rc = %d\n", rc);
            CAMERA_LOGE("Open OpenCamera_V1_3 failed, rc = %{public}d", rc);
        } else {
            CAMERA_LOGI("OpenSecureCamera success");
        }
    }
}

void HdiCommonV1_3::GetCameraMetadata(int cameraId)
{
    if (DEVICE_1 == cameraId) {
        rc = serviceV1_3->GetCameraAbility(cameraIds[1], abilityVec);
    } else {
        rc = serviceV1_3->GetCameraAbility(cameraIds[0], abilityVec);
    }
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        printf("GetCameraAbility failed, rc = %d\n", rc);
        CAMERA_LOGE("GetCameraAbility failed, rc = %{public}d", rc);
        return;
    }
    MetadataUtils::ConvertVecToMetadata(abilityVec, ability);
}

void HdiCommonV1_3::Close()
{
    if (cameraDeviceV1_3 != nullptr) {
        cameraDeviceV1_3->Close();
        cameraDeviceV1_3 = nullptr;
    }
}

void HdiCommonV1_3::DefaultMeta(
    std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> &infos)
{
    infos->v1_0.streamId_ = streamIdMeta;
    infos->v1_0.width_ = metaWidth;
    infos->v1_0.height_ = metaHeight;
    infos->v1_0.format_ = snapshotFormat;
    infos->v1_0.dataspace_ = UT_DATA_SIZE;
    infos->v1_0.intent_ = StreamIntent::VIDEO;
    infos->v1_0.encodeType_ = OHOS::HDI::Camera::V1_0::ENCODE_TYPE_H265;
    infos->v1_0.tunneledMode_ = UT_TUNNEL_MODE;
}

void HdiCommonV1_3::DefaultInfosMeta(
    std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> &infos)
{
    DefaultMeta(infos);
    std::shared_ptr<StreamConsumer> consumer_meta = std::make_shared<StreamConsumer>();
    infos->v1_0.bufferQueue_ = consumer_meta->CreateProducerSeq([this](void* addr, uint32_t size) {
        DumpImageFile(streamIdMeta, "yuv", addr, size);
    });
    infos->v1_0.bufferQueue_->producer_->SetQueueSize(UT_DATA_SIZE);
    consumerMap_[StreamIntent::PREVIEW] = consumer_meta;
}

void HdiCommonV1_3::DefaultInfosProfessionalCapture(
    std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> &infos)
{
    DefaultCapture(infos);
    std::shared_ptr<StreamConsumer> consumer_capture = std::make_shared<StreamConsumer>();
    infos->v1_0.bufferQueue_ = consumer_capture->CreateProducerSeq([this](void* addr, uint32_t size) {
        DumpImageFile(streamIdCapture, "yuv", addr, size);
    });
    infos->v1_0.bufferQueue_->producer_->SetQueueSize(UT_DATA_SIZE);
    consumerMap_[StreamIntent::STILL_CAPTURE] = consumer_capture;
}

void HdiCommonV1_3::StartProfessionalStream(std::vector<StreamIntent> intents, uint8_t professionalMode)
{
    streamOperatorCallbackV1_3 = new OHOS::Camera::HdiCommonV1_3::TestStreamOperatorCallbackV1_3();
    uint32_t mainVersion = 1;
    uint32_t minVersion = 0;
    rc = cameraDeviceV1_3->GetStreamOperator_V1_3(streamOperatorCallbackV1_3, streamOperator_V1_3);
    if (rc == HDI::Camera::V1_0::NO_ERROR) {
        rc = streamOperator_V1_3->GetVersion(mainVersion, minVersion);
        if (rc != HDI::Camera::V1_0::NO_ERROR) {
            printf("streamOperator_V1_3 get version failed, rc = %d\n", rc);
            CAMERA_LOGE("streamOperator_V1_3 get version failed, rc = %{public}d", rc);
        }
        CAMERA_LOGI("GetStreamOperator success");
    } else {
        printf("GetStreamOperator fail, rc = %d\n", rc);
        CAMERA_LOGE("GetStreamOperator fail, rc = %{public}d", rc);
    }
    streamInfoPre = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    streamInfoVideo = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    streamInfoCapture = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    streamInfoAnalyze = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    for (auto& streamType : intents) {
        if (streamType == StreamIntent::PREVIEW) {
            DefaultInfosPreview(streamInfoPre);
            streamInfos.push_back(*streamInfoPre);
        } else if (streamType == StreamIntent::VIDEO) {
            DefaultInfosVideo(streamInfoVideo);
            streamInfos.push_back(*streamInfoVideo);
        } else if (streamType == StreamIntent::ANALYZE) {
            DefaultInfosAnalyze(streamInfoAnalyze);
            streamInfos.push_back(*streamInfoAnalyze);
        } else {
            DefaultInfosProfessionalCapture(streamInfoCapture);
            streamInfos.push_back(*streamInfoCapture);
        }
    }
    rc = streamOperator_V1_3->CreateStreams_V1_1(streamInfos);
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        printf("check StartProfessionalStream: CreateStreams_V1_1 fail, rc = %d\n", rc);
        CAMERA_LOGE("check StartProfessionalStream: CreateStreams_V1_1 fail, rc = %{public}d", rc);
    }
    rc = streamOperator_V1_3->CommitStreams_V1_1(
        static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(professionalMode), abilityVec);
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        printf("check StartProfessionalStream: CommitStreams_V1_1 fail, rc = %d\n", rc);
        CAMERA_LOGE("check StartProfessionalStream: CommitStreams_V1_1 fail, rc = %{public}d", rc);
    }
    sleep(1);
    std::vector<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>().swap(streamInfos);
}

void HdiCommonV1_3::StartStream(std::vector<StreamIntent> intents, OHOS::HDI::Camera::V1_3::OperationMode mode)
{
    streamOperatorCallbackV1_3 = new OHOS::Camera::HdiCommonV1_3::TestStreamOperatorCallbackV1_3();
    uint32_t mainVersion = 1;
    uint32_t minVersion = 0;
    rc = cameraDeviceV1_3->GetStreamOperator_V1_3(streamOperatorCallbackV1_3, streamOperator_V1_3);
    if (rc == HDI::Camera::V1_0::NO_ERROR) {
        rc = streamOperator_V1_3->GetVersion(mainVersion, minVersion);
        if (rc != HDI::Camera::V1_0::NO_ERROR) {
            printf("streamOperator_V1_3 get version failed, rc = %d\n", rc);
            CAMERA_LOGE("streamOperator_V1_3 get version failed, rc = %{public}d", rc);
        }
        CAMERA_LOGI("GetStreamOperator success");
    } else {
        printf("GetStreamOperator fail, rc = %d\n", rc);
        CAMERA_LOGE("GetStreamOperator fail, rc = %{public}d", rc);
    }
    streamInfoPre = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    streamInfoVideo = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    streamInfoCapture = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    streamInfoAnalyze = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    for (auto& intent : intents) {
        if (intent == StreamIntent::PREVIEW) {
            DefaultInfosPreview(streamInfoPre);
            streamInfos.push_back(*streamInfoPre);
        } else if (intent == StreamIntent::VIDEO) {
            DefaultInfosVideo(streamInfoVideo);
            streamInfos.push_back(*streamInfoVideo);
        } else if (intent == StreamIntent::ANALYZE) {
            DefaultInfosAnalyze(streamInfoAnalyze);
            streamInfos.push_back(*streamInfoAnalyze);
        } else {
            DefaultInfosCapture(streamInfoCapture);
            streamInfos.push_back(*streamInfoCapture);
        }
    }
    rc = streamOperator_V1_3->CreateStreams_V1_1(streamInfos);
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        printf("check StartStream: CreateStreams_V1_1 fail, rc = %d\n", rc);
        CAMERA_LOGE("check StartStream: CreateStreams_V1_1 fail, rc = %{public}d", rc);
    }
    rc = streamOperator_V1_3->CommitStreams_V1_1(
        static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(mode), abilityVec);
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        printf("check StartStream: CommitStreams_V1_1 fail, rc = %d\n", rc);
        CAMERA_LOGE("check StartStream: CommitStreams_V1_1 fail, rc = %{public}d", rc);
    }
    sleep(1);
    std::vector<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>().swap(streamInfos);
}

void HdiCommonV1_3::StartCapture(int streamId, int captureId, bool shutterCallback, bool isStreaming)
{
    captureInfo = std::make_shared<CaptureInfo>();
    captureInfo->streamIds_ = {streamId};
    captureInfo->captureSetting_ = abilityVec;
    captureInfo->enableShutterCallback_ = shutterCallback;
    if (streamOperator_V1_3 == nullptr) {
        printf("StartCapture failed streamOperator_V1_3 nullptr\n");
        CAMERA_LOGE("StartCapture failed streamOperator_V1_3 nullptr");
        return;
    }
    rc = (OHOS::HDI::Camera::V1_0::CamRetCode)streamOperator_V1_3->Capture(captureId, *captureInfo, isStreaming);
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        printf("check Capture: Capture fail, rc = %d\n", rc);
        CAMERA_LOGE("check Capture: Capture fail, rc = %{public}d", rc);
    }
    sleep(UT_SLEEP_TIME);
}

void HdiCommonV1_3::StopStream(std::vector<int>& captureIds, std::vector<int>& streamIds)
{
    if (captureIds.size() > 0) {
        for (auto &captureId : captureIds) {
            if (streamOperator_V1_3 == nullptr) {
                printf("StopStream failed streamOperator_V1_3 nullptr\n");
                CAMERA_LOGE("StopStream failed streamOperator_V1_3 nullptr");
                return;
            }
            rc = streamOperator_V1_3->CancelCapture(captureId);
            if (rc != HDI::Camera::V1_0::NO_ERROR) {
                printf("CancelCapture fail, rc = %d, captureId = %d\n", rc, captureId);
                CAMERA_LOGE("CancelCapture fail, rc = %{public}d, captureId = %{public}d", rc, captureId);
            }
        }
    }
    if (streamIds.size() > 0) {
        if (streamOperator_V1_3 == nullptr) {
            printf("StopStream failed streamOperator_V1_3 nullptr\n");
            CAMERA_LOGE("StopStream failed streamOperator_V1_3 nullptr");
            return;
        }
        rc = streamOperator_V1_3->ReleaseStreams(streamIds);
        if (rc != HDI::Camera::V1_0::NO_ERROR) {
            printf("check Capture: ReleaseStreams fail, rc = %d\n", rc);
            CAMERA_LOGE("check Capture: ReleaseStreams fail, rc = %{public}d", rc);
        }
    }
}

int32_t HdiCommonV1_3::TestStreamOperatorCallbackV1_3::OnCaptureStarted(
    int32_t captureId, const std::vector<int32_t> &streamId)
{
    for (auto it : streamId) {
        CAMERA_LOGE("captureId: %{public}d, streamId: %{public}d", captureId, it);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t HdiCommonV1_3::TestStreamOperatorCallbackV1_3::OnCaptureEnded(int32_t captureId,
    const std::vector<CaptureEndedInfo> &infos)
{
    for (auto it : infos) {
        CAMERA_LOGE("captureId: %{public}d, streamId: %{public}d, count: %{public}d", captureId, it.streamId_,
            it.frameCount_);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t HdiCommonV1_3::TestStreamOperatorCallbackV1_3::OnCaptureEndedExt(int32_t captureId,
    const std::vector<HDI::Camera::V1_3::CaptureEndedInfoExt> &infos)
{
    for (auto it : infos) {
        CAMERA_LOGI("OnCaptureEndedExt captureId: %{public}d, streamId: %{public}d", captureId, it.streamId_);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t HdiCommonV1_3::TestStreamOperatorCallbackV1_3::OnCaptureError(int32_t captureId,
    const std::vector<CaptureErrorInfo> &infos)
{
    for (auto it : infos) {
        CAMERA_LOGE("captureId: %{public}d, streamId: %{public}d, error: %{public}d", captureId, it.streamId_,
            it.error_);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t HdiCommonV1_3::TestStreamOperatorCallbackV1_3::OnFrameShutter(int32_t captureId,
    const std::vector<int32_t> &streamIds, uint64_t timestamp)
{
    (void)timestamp;
    for (auto it : streamIds) {
        CAMERA_LOGE("captureId: %{public}d, streamId: %{public}d", captureId, it);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t HdiCommonV1_3::TestStreamOperatorCallbackV1_3::OnCaptureStarted_V1_2(int32_t captureId,
    const std::vector<HDI::Camera::V1_2::CaptureStartedInfo> &infos)
{
    for (auto it : infos) {
        CAMERA_LOGI("captureId: %{public}d, streamId: %{public}d", captureId, it.streamId_);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t HdiCommonV1_3::TestStreamOperatorCallbackV1_3::OnCaptureReady(int32_t captureId,
    const std::vector<int32_t> &streamIds, uint64_t timestamp)
{
    (void)timestamp;
    for (auto it : streamIds) {
        CAMERA_LOGI("OnCaptureReady captureId: %{public}d, streamId: %{public}d", captureId, it);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t HdiCommonV1_3::TestStreamOperatorCallbackV1_3::OnFrameShutterEnd(int32_t captureId,
    const std::vector<int32_t> &streamIds, uint64_t timestamp)
{
    (void)timestamp;
    for (auto it : streamIds) {
        CAMERA_LOGI("OnFrameShutterEnd captureId: %{public}d, streamId: %{public}d", captureId, it);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t HdiCommonV1_3::TestStreamOperatorCallbackV1_3::OnResult(int32_t streamId, const std::vector<uint8_t> &result)
{
    MetadataUtils::ConvertVecToMetadata(result, streamResultMeta);
    if (HdiCommonV1_3::streamResultCallback_) {
        HdiCommonV1_3::streamResultCallback_(streamId, streamResultMeta);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t HdiCommonV1_3::TestVideoProcessCallback::OnStatusChanged(OHOS::HDI::Camera::V1_2::SessionStatus status)
{
    CAMERA_LOGE("OnStatusChanged status: %{public}d", static_cast<int>(status));
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t HdiCommonV1_3::TestVideoProcessCallback::OnProcessDone(const std::string& videoId)
{
    CAMERA_LOGE("OnProcessDone videoId: %{public}s", videoId.c_str());
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t HdiCommonV1_3::TestVideoProcessCallback::OnError(
    const std::string& videoId, OHOS::HDI::Camera::V1_2::ErrorCode errorCode)
{
    CAMERA_LOGE("OnError videoId: %{public}s errorCode: %{public}d", videoId.c_str(), static_cast<int>(errorCode));
    return HDI::Camera::V1_0::NO_ERROR;
}

} // OHOS::Camera