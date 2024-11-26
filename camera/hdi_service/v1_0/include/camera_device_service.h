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

#ifndef CAMERA_DEVICE_SERVICE_H
#define CAMERA_DEVICE_SERVICE_H

#include <mutex>
#include "camera.h"
#include "stream_operator_service.h"
#include "v1_0/icamera_device.h"
#include "v1_0/icamera_device_callback.h"
#include "v1_0/icamera_device_vdi.h"
#include "v1_0/icamera_device_vdi_callback.h"
#include "camera_hal_hicollie.h"

namespace OHOS::Camera {
using namespace OHOS::HDI::Camera::V1_0;
using namespace OHOS::VDI::Camera::V1_0;

class IPipelineCore;
class CameraDeviceService : public ICameraDevice, public std::enable_shared_from_this<CameraDeviceService> {
public:
    explicit CameraDeviceService(OHOS::sptr<ICameraDeviceVdi> cameraDeviceServiceVdi);
    CameraDeviceService() = delete;
    virtual ~CameraDeviceService() = default;
    CameraDeviceService(const CameraDeviceService &other) = delete;
    CameraDeviceService(CameraDeviceService &&other) = delete;
    CameraDeviceService &operator=(const CameraDeviceService &other) = delete;
    CameraDeviceService &operator=(CameraDeviceService &&other) = delete;

public:
    int32_t GetStreamOperator(const sptr<IStreamOperatorCallback> &callbackObj,
        sptr<IStreamOperator> &streamOperator) override;
    int32_t UpdateSettings(const std::vector<uint8_t> &settings) override;
    int32_t SetResultMode(ResultCallbackMode mode) override;
    int32_t GetEnabledResults(std::vector<int32_t> &results) override;
    int32_t EnableResult(const std::vector<int32_t> &results) override;
    int32_t DisableResult(const std::vector<int32_t> &results) override;
    int32_t Close() override;
private:
    OHOS::sptr<ICameraDeviceVdi> cameraDeviceServiceVdi_;
};
} // end namespace OHOS::Camera
#endif // CAMERA_DEVICE_SERVICE_H
