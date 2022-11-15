/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef CAMERA_CONTROL_H
#define CAMERA_CONTROL_H

#include "camera_common.h"

namespace OHOS::Camera {
class CameraControl {
public:
    CameraControl();
    ~CameraControl();

    RetCode CameraPowerUp(struct CameraFeature feature);
    RetCode CameraPowerDown(struct CameraFeature feature);
    RetCode CameraQueryConfig(struct CameraFeature feature, CameraCtrl &ctrl);
    RetCode CameraSetConfig(struct CameraFeature feature, CameraCtrl &ctrl);
    RetCode CameraGetConfig(struct CameraFeature feature, CameraCtrl &ctrl);
    RetCode CameraGetConfigs(struct CameraFeature feature, std::vector<CameraCtrl> &ctrl, int count);
    RetCode CameraSetConfigs(struct CameraFeature feature, std::vector<CameraCtrl> &ctrl, int count);
    RetCode CameraEnumDevices(struct CameraFeature feature, struct DeviceaInfo &device);
    RetCode CameraGetAbility(struct CameraFeature feature);
    RetCode CameraMatchDevice(struct CameraFeature feature);

private:
    int ReadAbilitySbufData(struct HdfSBuf *respData, struct CameraCapability &ability);
    int ReadDeviceSbufData(int type, struct HdfSBuf *respData, struct DeviceaInfo &device);
    int ReadSensorSbufData(struct HdfSBuf *respData, struct DeviceaInfo &device);
    int ReadIspSbufData(struct HdfSBuf *respData, struct DeviceaInfo &device);
    int ReadVcmSbufData(struct HdfSBuf *respData, struct DeviceaInfo &device);
    int ReadLensSbufData(struct HdfSBuf *respData, struct DeviceaInfo &device);
    int ReadFlashSbufData(struct HdfSBuf *respData, struct DeviceaInfo &device);
    int ReadStreamSbufData(struct HdfSBuf *respData, struct DeviceaInfo &device);
};
} // namespace OHOS::Camera

#endif // CAMERA_CONTROL_H
