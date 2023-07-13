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

#include "camera_device_service_callback.h"

namespace OHOS::Camera {
CameraDeviceServiceCallback::CameraDeviceServiceCallback(OHOS::sptr<ICameraDeviceCallback> cameraDeviceCallback)
    : cameraDeviceCallback_(cameraDeviceCallback)
{
}

int32_t CameraDeviceServiceCallback::OnError(VdiErrorType type, int32_t errorCode)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(cameraDeviceCallback_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return cameraDeviceCallback_->OnError(static_cast<ErrorType>(type), errorCode);
}

int32_t CameraDeviceServiceCallback::OnResult(uint64_t timestamp, const std::vector<uint8_t> &result)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(cameraDeviceCallback_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return cameraDeviceCallback_->OnResult(timestamp, result);
}

} // end namespace OHOS::Camera
