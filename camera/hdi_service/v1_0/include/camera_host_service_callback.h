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

#ifndef CAMERA_HOST_SERVICE_CALLBACK_H
#define CAMERA_HOST_SERVICE_CALLBACK_H

#include "camera.h"
#include "v1_0/icamera_host_callback.h"
#include "v1_0/icamera_host_vdi_callback.h"
#include "v1_0/icamera_host_vdi.h"
#include "camera_host_service.h"

namespace OHOS::Camera {
using namespace OHOS::HDI::Camera::V1_0;
using namespace OHOS::VDI::Camera::V1_0;

class CameraHostServiceCallback : public ICameraHostVdiCallback {
public:

    CameraHostServiceCallback(OHOS::sptr<ICameraHostCallback> cameraHostCallback,
        OHOS::sptr<ICameraHostVdi> cameraHostVdi, std::vector<CameraIdInfo> &cameraIdInfoList);

    CameraHostServiceCallback() = delete;

    virtual ~CameraHostServiceCallback() = default;

    int32_t OnCameraStatus(const std::string &cameraId, VdiCameraStatus status) override;

    int32_t OnFlashlightStatus(const std::string &cameraId, VdiFlashlightStatus status) override;

    int32_t OnCameraEvent(const std::string &cameraId, VdiCameraEvent event) override;

    const sptr<IRemoteObject> Remote() const override;

private:
    OHOS::sptr<ICameraHostCallback> cameraHostCallback_;
    OHOS::sptr<ICameraHostVdi> cameraHostVdi_;
    std::vector<CameraIdInfo> &cameraIdInfoList_;
};

} // end namespace OHOS::Camera
#endif // CAMERA_HOST_SERVICE_CALLBACK_H
