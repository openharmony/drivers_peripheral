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

#include "camera_host_service_callback.h"
#include "iproxy_broker.h"

constexpr int NAME_START_POS = 6;

namespace OHOS::Camera {
CameraHostServiceCallback::CameraHostServiceCallback(OHOS::sptr<ICameraHostCallback> cameraHostCallback,
    OHOS::sptr<ICameraHostVdi> cameraHostVdi, std::vector<CameraIdInfo> &cameraIdInfoList)
    : cameraHostCallback_(cameraHostCallback),
      cameraHostVdi_(cameraHostVdi),
      cameraIdInfoList_(cameraIdInfoList)
{
}

int32_t CameraHostServiceCallback::OnCameraStatus(const std::string &cameraId, VdiCameraStatus status)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(cameraHostCallback_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    auto itr = std::find_if(cameraIdInfoList_.begin(), cameraIdInfoList_.end(),
        [cameraId, this](const struct CameraIdInfo &cameraIdInfo) {
            return cameraId == cameraIdInfo.vendorCameraId && cameraHostVdi_.GetRefPtr() == cameraIdInfo.cameraHostVdi;
        });
    if (itr == cameraIdInfoList_.end()) {
        CAMERA_LOGE("Vendor camera id %{public}s doesn't exist", cameraId.c_str());
        return OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT;
    }
    CAMERA_LOGD("Current cameraId %{public}s, vendor camera id %{public}s, status=%{public}d",
        itr->currentCameraId.c_str(), cameraId.c_str(), status);

    return cameraHostCallback_->OnCameraStatus(itr->currentCameraId, static_cast<CameraStatus>(status));
}

int32_t CameraHostServiceCallback::OnFlashlightStatus(const std::string &cameraId, VdiFlashlightStatus status)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(cameraHostCallback_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    auto itr = std::find_if(cameraIdInfoList_.begin(), cameraIdInfoList_.end(),
        [cameraId, this](const struct CameraIdInfo &cameraIdInfo) {
            return cameraId == cameraIdInfo.vendorCameraId && cameraHostVdi_.GetRefPtr() == cameraIdInfo.cameraHostVdi;
        });
    if (itr == cameraIdInfoList_.end()) {
        CAMERA_LOGE(" Vendor camera id %{public}s doesn't exist", cameraId.c_str());
        return OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT;
    }

    return cameraHostCallback_->OnFlashlightStatus(itr->currentCameraId, static_cast<FlashlightStatus>(status));
}

static inline const std::string vdiCameraIdToPrefix(const std::string &id)
{
    size_t startPos;
    size_t endPos;
    std::string preFix = "lcam00";
    if ((startPos = id.find("&name=")) != std::string::npos) {
        startPos += NAME_START_POS;
        endPos = id.find("&id=");
        preFix = id.substr(startPos, endPos - startPos);
        preFix += "/";
    }
    return preFix;
}

int32_t CameraHostServiceCallback::OnCameraEvent(const std::string &cameraId, VdiCameraEvent event)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(cameraHostCallback_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    std::string currentCameraId;
    if (event == OHOS::VDI::Camera::V1_0::CAMERA_EVENT_DEVICE_ADD) {
        auto itr = std::find_if(cameraIdInfoList_.begin(), cameraIdInfoList_.end(),
            [](const struct CameraIdInfo &cameraIdInfo) {
                return cameraIdInfo.isDeleted;
            });
        if (itr == cameraIdInfoList_.end()) {
            struct CameraIdInfo cameraIdInfo;
            currentCameraId = vdiCameraIdToPrefix(cameraId) + std::to_string(cameraIdInfoList_.size() + 1);
            cameraIdInfo.currentCameraId = currentCameraId;
            cameraIdInfo.cameraHostVdi = cameraHostVdi_;
            cameraIdInfo.vendorCameraId = cameraId;
            cameraIdInfo.isDeleted = false;
            cameraIdInfoList_.push_back(cameraIdInfo);
        } else {
            itr->cameraHostVdi = cameraHostVdi_;
            itr->vendorCameraId = cameraId;
            itr->isDeleted = false;
            currentCameraId = itr->currentCameraId;
        }
    } else {
        auto itr = std::find_if(cameraIdInfoList_.begin(), cameraIdInfoList_.end(),
            [cameraId, this](const struct CameraIdInfo &cameraIdInfo) {
                return cameraId == cameraIdInfo.vendorCameraId &&
                    cameraHostVdi_.GetRefPtr() == cameraIdInfo.cameraHostVdi;
            });
        if (itr == cameraIdInfoList_.end()) {
            CAMERA_LOGE("Remove camera id error, vendor camera id %{public}s doesn't exist", cameraId.c_str());
            return OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT;
        }
        itr->isDeleted = true;
        currentCameraId = itr->currentCameraId;
    }
    CAMERA_LOGD("Current cameraId %{public}s, vendor camera id %{public}s, event=%{public}d",
        currentCameraId.c_str(), cameraId.c_str(), event);

    return cameraHostCallback_->OnCameraEvent(currentCameraId, static_cast<CameraEvent>(event));
}

const sptr<IRemoteObject> CameraHostServiceCallback::Remote() const
{
    return OHOS::HDI::hdi_objcast<ICameraHostCallback>(cameraHostCallback_);
}

} // end namespace OHOS::Camera
