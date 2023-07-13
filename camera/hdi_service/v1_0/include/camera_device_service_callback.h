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

#ifndef CAMERA_DEVICE_SERVICE_CALLBACK_H
#define CAMERA_DEVICE_SERVICE_CALLBACK_H

#include "camera.h"
#include "v1_0/icamera_device_callback.h"
#include "v1_0/icamera_device_vdi_callback.h"

namespace OHOS::Camera {
using namespace OHOS::HDI::Camera::V1_0;
using namespace OHOS::VDI::Camera::V1_0;

class CameraDeviceServiceCallback : public ICameraDeviceVdiCallback {
public:

    explicit CameraDeviceServiceCallback(OHOS::sptr<ICameraDeviceCallback> cameraDeviceCallback);

    CameraDeviceServiceCallback() = delete;

    virtual ~CameraDeviceServiceCallback() = default;

    int32_t OnError(VdiErrorType type, int32_t errorCode) override;

    int32_t OnResult(uint64_t timestamp, const std::vector<uint8_t>& result) override;

private:
    OHOS::sptr<ICameraDeviceCallback> cameraDeviceCallback_;
};

} // end namespace OHOS::Camera
#endif // CAMERA_DEVICE_SERVICE_CALLBACK_H
