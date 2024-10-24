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

#ifndef CAMERA_HOST_SERVICE_H
#define CAMERA_HOST_SERVICE_H

#include <map>
#include "camera.h"
#include "hcs_dm_parser.h"
#include "v1_0/icamera_device.h"
#include "v1_0/icamera_host.h"
#include "v1_0/icamera_host_vdi.h"
#include "camera_hal_hicollie.h"

namespace OHOS::Camera {
#ifdef CHIP_PROD_CAMERA_HOST_CONFIG
#define CONFIG_PATH_NAME HDF_CHIP_PROD_CONFIG_DIR"/camera_host_config.hcb"
#else
#define CONFIG_PATH_NAME HDF_CONFIG_DIR"/camera_host_config.hcb"
#endif

using namespace OHOS::HDI::Camera::V1_0;
using namespace OHOS::VDI::Camera::V1_0;

struct CameraIdInfo {
    std::string currentCameraId;
    ICameraHostVdi* cameraHostVdi;
    std::string vendorCameraId;
    bool isDeleted;
};

class CameraHostService : public ICameraHost {
public:
    static OHOS::sptr<CameraHostService> GetInstance();
    int32_t SetCallback(const sptr<ICameraHostCallback> &callbackObj) override;
    int32_t GetCameraIds(std::vector<std::string> &cameraIds) override;
    int32_t GetCameraAbility(const std::string &cameraId,
        std::vector<uint8_t> &cameraAbility) override;
    int32_t OpenCamera(const std::string &cameraId, const sptr<ICameraDeviceCallback> &callbackObj,
        sptr<ICameraDevice> &device) override;
    int32_t SetFlashlight(const std::string &cameraId, bool isEnable) override;

private:
    CameraHostService(std::vector<ICameraHostVdi*> cameraHostVdiList,
        std::vector<struct HdfVdiObject *> cameraHostVdiLoaderList);
    virtual ~CameraHostService();
    CameraHostService(const CameraHostService &other) = delete;
    CameraHostService(CameraHostService &&other) = delete;
    CameraHostService &operator=(const CameraHostService &other) = delete;
    CameraHostService &operator=(CameraHostService &&other) = delete;

    static int32_t GetVdiLibList(std::vector<std::string> &vdiLibList);
    static void HdfCloseVdiLoaderList(std::vector<struct HdfVdiObject *> &cameraHostVdiLoaderList);
    ICameraHostVdi* GetCameraHostVdi(const std::string &currentCameraId);
    const std::string GetVendorCameraId(const std::string &currentCameraId);
    int32_t UpdateCameraIdMapList();

    std::vector<ICameraHostVdi*> cameraHostVdiList_;
    std::vector<CameraIdInfo> cameraIdInfoList_;
    std::vector<struct HdfVdiObject *> cameraHostVdiLoaderList_;
    static OHOS::sptr<CameraHostService> cameraHostService_;
};
} // end namespace OHOS::Camera
#endif // CAMERA_HOST_SERVICE_H
