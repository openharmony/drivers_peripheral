/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "common.h"

namespace OHOS::Camera {
CameraManager::ResultCallback CameraManager::resultCallback_ = 0;
void CameraManager::Init()
{
    uint32_t mainVer;
    uint32_t minVer;
    int32_t ret;
    if (serviceV1_1 == nullptr) {
        serviceV1_1 = OHOS::HDI::Camera::V1_1::ICameraHost::Get("camera_service", false);
        if (serviceV1_1 == nullptr) {
            CAMERA_LOGE("V1_1::IcameraHost get failed");
            return;
        } else {
            CAMERA_LOGI("ICameraHost get success");
            ret = serviceV1_1->GetVersion(mainVer, minVer);
            if (ret != 0) {
                CAMERA_LOGE("V1_1::ICameraHost get version failed, ret = %{public}d", ret);
            } else {
                CAMERA_LOGE("V1_1::ICameraHost get version success, %{public}d, %{public}d", mainVer, minVer);
            }
        }

        service = static_cast<OHOS::HDI::Camera::V1_0::ICameraHost *>(serviceV1_1.GetRefPtr());
    }

    hostCallback = new TestCameraHostCallback();
    service->SetCallback(hostCallback);
}

void CameraManager::InitV1_2()
{
    uint32_t mainVer;
    uint32_t minVer;
    int32_t ret;
    if (serviceV1_2 == nullptr) {
        serviceV1_2 = OHOS::HDI::Camera::V1_2::ICameraHost::Get("camera_service", false);
        if (serviceV1_2 == nullptr) {
            CAMERA_LOGE("V1_2::IcameraHost get failed");
            return;
        } else {
            CAMERA_LOGI("ICameraHost get success");
            ret = serviceV1_2->GetVersion(mainVer, minVer);
            if (ret != 0) {
                CAMERA_LOGE("V1_2::ICameraHost get version failed, ret = %{public}d", ret);
            } else {
                CAMERA_LOGE("V1_2::ICameraHost get version success, %{public}d, %{public}d", mainVer, minVer);
            }
        }

        service = static_cast<OHOS::HDI::Camera::V1_0::ICameraHost *>(serviceV1_2.GetRefPtr());
    }

    hostCallback = new TestCameraHostCallback();
    service->SetCallback(hostCallback);
}

void CameraManager::OpenV1_2()
{
    if (cameraDevice == nullptr) {
        service->GetCameraIds(cameraIds);
        if (cameraIds.size() == 0) {
            CAMERA_LOGE("camera device list empty");
        }
        GetCameraMetadata();
        deviceCallback = new OHOS::Camera::CameraManager::DemoCameraDeviceCallback();

        rc = serviceV1_2->OpenCamera_V1_1(cameraIds.front(), deviceCallback, cameraDeviceV1_1);
        if (rc != HDI::Camera::V1_0::NO_ERROR || cameraDeviceV1_1 == nullptr) {
            CAMERA_LOGE("openCamera V1_1 failed, rc = %{public}d", rc);
            return;
        }

        cameraDevice = static_cast<OHOS::HDI::Camera::V1_0::ICameraDevice *>(cameraDeviceV1_1.GetRefPtr());
        CAMERA_LOGI("OpenCamera V1_2 success");
    }
}

void CameraManager::OpenCameraV1_2()
{
    if (cameraDevice == nullptr) {
        service->GetCameraIds(cameraIds);
        if (cameraIds.size() == 0) {
            CAMERA_LOGE("camera device list empty");
        }
        GetCameraMetadata();
        deviceCallback = new OHOS::Camera::CameraManager::DemoCameraDeviceCallback();

        rc = serviceV1_2->OpenCameraV1_2(cameraIds.front(), deviceCallback, cameraDeviceV1_2);
        if (rc != HDI::Camera::V1_0::NO_ERROR || cameraDeviceV1_2 == nullptr) {
            CAMERA_LOGE("openCamera V1_1 failed, rc = %{public}d", rc);
            return;
        }

        cameraDevice = static_cast<OHOS::HDI::Camera::V1_0::ICameraDevice *>(cameraDeviceV1_2.GetRefPtr());
        CAMERA_LOGI("OpenCamera V1_2 success");
    }
}

void CameraManager::Open()
{
    if (cameraDevice == nullptr) {
        service->GetCameraIds(cameraIds);
        if (cameraIds.size() == 0) {
            CAMERA_LOGE("camera device list empty");
        }
        GetCameraMetadata();
        deviceCallback = new OHOS::Camera::CameraManager::DemoCameraDeviceCallback();

        rc = serviceV1_1->OpenCamera_V1_1(cameraIds.front(), deviceCallback, cameraDeviceV1_1);
        if (rc != HDI::Camera::V1_0::NO_ERROR || cameraDeviceV1_1 == nullptr) {
            CAMERA_LOGE("openCamera V1_1 failed, rc = %{public}d", rc);
            return;
        }

        cameraDevice = static_cast<OHOS::HDI::Camera::V1_0::ICameraDevice *>(cameraDeviceV1_1.GetRefPtr());
        CAMERA_LOGI("OpenCamera V1_1 success");
    }
}

void CameraManager::GetCameraMetadata()
{
    rc = service->GetCameraAbility(cameraIds.front(), abilityVec);
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGE("GetCameraAbility failed, rc = %{public}d", rc);
    }
    MetadataUtils::ConvertVecToMetadata(abilityVec, ability);

    common_metadata_header_t* data = ability->get();
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_AE_AVAILABLE_MODES, &entry);
    if (ret == 0) {
        CAMERA_LOGI("get OHOS_CONTROL_AE_AVAILABLE_MODES success");
    }
}

void CameraManager::Close()
{
    if (cameraDevice != nullptr) {
        cameraDevice->Close();
        cameraDevice = nullptr;
    }
}

int32_t CameraManager::TestStreamOperatorCallback::OnCaptureStarted(int32_t captureId,
    const std::vector<int32_t> &streamId)
{
    for (auto it : streamId) {
        CAMERA_LOGE("captureId: %{public}d, streamId: %{public}d", captureId, it);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t CameraManager::TestStreamOperatorCallback::OnCaptureEnded(int32_t captureId,
    const std::vector<CaptureEndedInfo> &infos)
{
    for (auto it : infos) {
        CAMERA_LOGE("captureId: %{public}d, streamId: %{public}d, count: %{public}d", captureId, it.streamId_,
            it.frameCount_);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t CameraManager::TestStreamOperatorCallback::OnCaptureError(int32_t captureId,
    const std::vector<CaptureErrorInfo> &infos)
{
    for (auto it : infos) {
        CAMERA_LOGE("captureId: %{public}d, streamId: %{public}d, error: %{public}d", captureId, it.streamId_,
            it.error_);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t CameraManager::TestStreamOperatorCallback::OnFrameShutter(int32_t captureId,
    const std::vector<int32_t> &streamIds, uint64_t timestamp)
{
    (void)timestamp;
    for (auto it : streamIds) {
        CAMERA_LOGE("captureId: %{public}d, streamId: %{public}d", captureId, it);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t CameraManager::DemoCameraDeviceCallback::OnError(ErrorType type, int32_t errorMsg)
{
    CAMERA_LOGE("type: %{public}d, errorMsg: %{public}d", type, errorMsg);
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t CameraManager::DemoCameraDeviceCallback::OnResult(uint64_t timestamp, const std::vector<uint8_t> &result)
{
    if (CameraManager::resultCallback_) {
        std::shared_ptr<CameraMetadata> resultMeta;
        MetadataUtils::ConvertVecToMetadata(result, resultMeta);
        CameraManager::resultCallback_(timestamp, resultMeta);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t CameraManager::TestCameraHostCallback::OnCameraStatus(const std::string& cameraId, CameraStatus status)
{
    CAMERA_LOGE("cameraId: %{public}s, status: %{public}d", cameraId.c_str(), status);
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t CameraManager::TestCameraHostCallback::OnFlashlightStatus(const std::string& cameraId, FlashlightStatus status)
{
    CAMERA_LOGE("cameraId: %{public}s, status: %{public}d", cameraId.c_str(), status);
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t CameraManager::TestCameraHostCallback::OnCameraEvent(const std::string& cameraId, CameraEvent event)
{
    CAMERA_LOGE("cameraId: %{public}s, status: %{public}d", cameraId.c_str(), event);
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t Test::TestStreamOperatorCallbackV1_2::OnCaptureStarted(int32_t captureId, const std::vector<int32_t> &streamId)
{
    for (auto it : streamId) {
        CAMERA_LOGE("captureId: %{public}d, streamId: %{public}d", captureId, it);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t Test::TestStreamOperatorCallbackV1_2::OnCaptureEnded(int32_t captureId,
    const std::vector<CaptureEndedInfo> &infos)
{
    for (auto it : infos) {
        CAMERA_LOGE("captureId: %{public}d, streamId: %{public}d, count: %{public}d", captureId, it.streamId_,
            it.frameCount_);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t Test::TestStreamOperatorCallbackV1_2::OnCaptureError(int32_t captureId,
    const std::vector<CaptureErrorInfo> &infos)
{
    for (auto it : infos) {
        CAMERA_LOGE("captureId: %{public}d, streamId: %{public}d, error: %{public}d", captureId, it.streamId_,
            it.error_);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t Test::TestStreamOperatorCallbackV1_2::OnFrameShutter(int32_t captureId,
    const std::vector<int32_t> &streamIds, uint64_t timestamp)
{
    (void)timestamp;
    for (auto it : streamIds) {
        CAMERA_LOGE("captureId: %{public}d, streamId: %{public}d", captureId, it);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t Test::TestStreamOperatorCallbackV1_2::OnCaptureStartedV1_2(int32_t captureId,
    const std::vector<HDI::Camera::V1_2::CaptureStartedInfo> &infos)
{
    for (auto it : infos) {
        CAMERA_LOGE("captureId: %{public}d, streamId: %{public}d", captureId, it.streamId_);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

}
