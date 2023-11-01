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

#ifndef OHOS_VDI_CAMERA_V1_0_ICAMERAHOSTVDICALLBACK_H
#define OHOS_VDI_CAMERA_V1_0_ICAMERAHOSTVDICALLBACK_H

#include <stdint.h>
#include <string>
#include <hdf_base.h>
#include <hdi_base.h>
#include "v1_0/vdi_types.h"

namespace OHOS {
namespace VDI {
namespace Camera {
namespace V1_0 {
using namespace OHOS;
using namespace OHOS::HDI;

class ICameraHostVdiCallback : public HdiBase {
public:

    virtual ~ICameraHostVdiCallback() = default;

    virtual int32_t OnCameraStatus(const std::string &cameraId, VdiCameraStatus status) = 0;

    virtual int32_t OnFlashlightStatus(const std::string &cameraId, VdiFlashlightStatus status) = 0;

    virtual int32_t OnCameraEvent(const std::string &cameraId, VdiCameraEvent event) = 0;

    virtual const sptr<IRemoteObject> Remote() const = 0;
};
} // V1_0
} // Camera
} // VDI
} // OHOS

#endif // OHOS_VDI_CAMERA_V1_0_ICAMERAHOSTVDICALLBACK_H