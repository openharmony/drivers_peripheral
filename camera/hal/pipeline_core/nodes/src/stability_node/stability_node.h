/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef STABILITY_NODE_H
#define STABILITY_NODE_H

#include "camera.h"
#include "device_manager_adapter.h"
#include "source_node.h"
#include "utils.h"
#include <condition_variable>
#include <ctime>
#include <vector>

namespace OHOS {
namespace Camera {
class StabilityNode : public NodeBase {
public:
    StabilityNode(const std::string &name, const std::string &type);
    ~StabilityNode() override;
    void DeliverBuffer(std::shared_ptr<IBuffer> &buffer) override;
    RetCode SetCallback() override;
    void OnMetadataChanged(const std::shared_ptr<CameraMetadata> &metadata);

private:
    RetCode PrintNodeMetaData(std::shared_ptr<CameraMetadata> meta);
};
} // namespace Camera
} // namespace OHOS
#endif /* STABILITY_NODE_H */
