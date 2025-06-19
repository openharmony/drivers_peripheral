/*
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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

#ifndef CAMERA_HOST_CAMERA_HOST_VDI_IMPL_H
#define CAMERA_HOST_CAMERA_HOST_VDI_IMPL_H
#include <mutex>
#include <map>
#include "v1_0/icamera_host_vdi.h"
#include "v1_0/icamera_device_vdi.h"
#include "camera_device_vdi_impl.h"
#include "utils.h"

namespace OHOS::Camera {
using namespace OHOS::VDI::Camera::V1_0;

class CameraHostVdiImpl : public ICameraHostVdi {
public:
    VdiCamRetCode Init();
    int32_t SetCallback(const sptr<ICameraHostVdiCallback> &callbackObj) override;
    int32_t GetCameraIds(std::vector<std::string> &cameraIds) override;
    int32_t GetCameraAbility(const std::string &cameraId,
        std::vector<uint8_t> &cameraAbility) override;
    int32_t OpenCamera(const std::string &cameraId, const sptr<ICameraDeviceVdiCallback> &callbackObj,
        sptr<ICameraDeviceVdi> &device) override;
    int32_t SetFlashlight(const std::string &cameraId, bool isEnable) override;

public:
    CameraHostVdiImpl();
    virtual ~CameraHostVdiImpl();
    CameraHostVdiImpl(const CameraHostVdiImpl &other) = delete;
    CameraHostVdiImpl(CameraHostVdiImpl &&other) = delete;
    CameraHostVdiImpl &operator=(const CameraHostVdiImpl &other) = delete;
    CameraHostVdiImpl &operator=(CameraHostVdiImpl &&other) = delete;

private:
    RetCode CameraPowerUp(const std::string &cameraId,
        const std::vector<std::string> &phyCameraIds);
    void CameraPowerDown(const std::vector<std::string> &phyCameraIds);
    RetCode CameraIdInvalid(const std::string &cameraId);
    RetCode SetFlashlight(const std::vector<std::string> &phyCameraIds,
        bool isEnable, VdiFlashlightStatus &flashlightStatus);
    void OnCameraStatus(CameraId cameraId, VdiCameraStatus status, const std::shared_ptr<CameraAbility> ability,
        const std::string &cameraName = "");

    int32_t CloseAllCameras() override;

private:
    // key: cameraId, value: CameraDevice
    using CameraDeviceMap = std::map<std::string, std::shared_ptr<CameraDeviceVdiImpl>>;
    std::mutex mtx;
    CameraDeviceMap cameraDeviceMap_;
    OHOS::sptr<ICameraHostVdiCallback> cameraHostCallback_;
    // to keep remote object OHOS::sptr<ICameraDeviceVdi> alive
    std::map<std::string, OHOS::sptr<ICameraDeviceVdi>> deviceBackup_ = {};
};
} // end namespace OHOS::Camera
#endif // CAMERA_HOST_CAMERA_HOST_VDI_IMPL_H
