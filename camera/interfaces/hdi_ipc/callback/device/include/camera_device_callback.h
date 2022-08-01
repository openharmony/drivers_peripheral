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

#ifndef HDI_CAMERA_DEVICE_CALLBACK_H
#define HDI_CAMERA_DEVICE_CALLBACK_H

#include "v1_0/icamera_device_callback.h"

namespace OHOS::Camera {
using namespace OHOS::HDI::Camera::V1_0;
class CameraDeviceCallback : public ICameraDeviceCallback {
public:
    CameraDeviceCallback() = default;
    virtual ~CameraDeviceCallback() = default;

public:
    int32_t OnError(ErrorType type, int32_t errorCode) override;
    int32_t OnResult(uint64_t timestamp, const std::vector<uint8_t>& result) override;
};
}
#endif // HDI_CAMERA_DEVICE_CALLBACK_H