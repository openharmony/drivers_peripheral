/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef HOS_CAMERA_ISENSOR_H
#define HOS_CAMERA_ISENSOR_H

#include "device_manager_adapter.h"
#include <string>

namespace OHOS {
namespace Camera {
class ISensor {
public:
    ISensor();
    explicit ISensor(std::string sensorName);
    virtual ~ISensor();
    virtual void Init(CameraMetadata& camera_meta_data) = 0;
    std::string GetSensorName()
    {
        return sensorName_;
    };
    virtual void InitSensitivityRange(CameraMetadata& camera_meta_data);
    virtual void InitAwbModes(CameraMetadata& camera_meta_data);
    virtual void InitCompensationRange(CameraMetadata& camera_meta_data);
    virtual void InitFpsTarget(CameraMetadata& camera_meta_data);
    virtual void InitAvailableModes(CameraMetadata& camera_meta_data);
    virtual void InitAntiBandingModes(CameraMetadata& camera_meta_data);
    virtual void InitPhysicalSize(CameraMetadata& camera_meta_data);
private:
    std::string sensorName_;
};
} // namespace Camera
} // namespace OHOS
#endif