/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HOS_CAMERA_SOURCE_NODE_H
#define HOS_CAMERA_SOURCE_NODE_H

#include <vector>
#include "device_manager_adapter.h"
#include "v4l2_device_manager.h"
#include "utils.h"
#include "camera.h"
#include "node_base.h"
#include "sensor_controller.h"
#include "sensor_manager.h"

namespace OHOS::Camera{
class SourceNode : public NodeBase
{
public:
    SourceNode(const std::string& name, const std::string& type, const int streamId);
    ~SourceNode() override;
    RetCode Start() override;
    RetCode Stop() override;
    RetCode GetDeviceController();
    RetCode Configure(std::shared_ptr<CameraStandard::CameraMetadata> meta);
    void DistributeBuffers();
    void AchieveBuffer(std::shared_ptr<FrameSpec> frameSpec);
    void SendCallBack();
    RetCode ProvideBuffers(std::shared_ptr<FrameSpec> frameSpec) override;
private:
    std::shared_ptr<SensorController>       sensorController_ = nullptr;
};
}// namespace OHOS::Camera
#endif
