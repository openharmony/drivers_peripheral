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

namespace OHOS::Camera {
CameraHostServiceCallback::CameraHostServiceCallback(OHOS::sptr<ICameraHostCallback> cameraHostCallback)
    : cameraHostCallback_(cameraHostCallback)
{
}

int32_t CameraHostServiceCallback::OnCameraStatus(const std::string &cameraId, VdiCameraStatus status)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(cameraHostCallback_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return cameraHostCallback_->OnCameraStatus(cameraId, static_cast<CameraStatus>(status));
}

int32_t CameraHostServiceCallback::OnFlashlightStatus(const std::string &cameraId, VdiFlashlightStatus status)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(cameraHostCallback_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return cameraHostCallback_->OnFlashlightStatus(cameraId, static_cast<FlashlightStatus>(status));
}

int32_t CameraHostServiceCallback::OnCameraEvent(const std::string &cameraId, VdiCameraEvent event)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(cameraHostCallback_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return cameraHostCallback_->OnCameraEvent(cameraId, static_cast<CameraEvent>(event));
}

} // end namespace OHOS::Camera
