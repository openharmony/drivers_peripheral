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

#include "stability_node.h"
#include "metadata_controller.h"

namespace OHOS {
namespace Camera {
StabilityNode::StabilityNode(const std::string &name, const std::string &type) : NodeBase(name, type) {}

StabilityNode::~StabilityNode() {}

RetCode StabilityNode::SetCallback()
{
    MetadataController &metaDataController = MetadataController::GetInstance();
    metaDataController.AddNodeCallback([this](const std::shared_ptr<CameraMetadata> &metadata) {
        OnMetadataChanged(metadata);
    });
    return RC_OK;
}

void StabilityNode::OnMetadataChanged(const std::shared_ptr<CameraMetadata> &metadata)
{
    if (metadata == nullptr) {
        CAMERA_LOGE("meta is nullptr");
        return;
    }
    PrintNodeMetaData(metadata);
}

void StabilityNode::DeliverBuffer(std::shared_ptr<IBuffer> &buffer)
{
    if (buffer == nullptr) {
        CAMERA_LOGE("StabilityNode::DeliverBuffer frameSpec is null");
        return;
    }

    int32_t id = buffer->GetStreamId();

    auto &it = std::find_if(outPutPorts.begin(), outPutPorts.end(), [id](const std::shared_ptr<IPort>& port) {
        return port->format_.streamId_ == id;
    });
    if (it == outPutPorts.end()) {
        return -1;
    }
    it->DeliverBuffer(buffer);
    if (it != nullptr) {
        CAMERA_LOGI("StabilityNode deliver buffer streamid = %{public}d", it->format_.streamId_);
    }
    return;
}

RetCode StabilityNode::PrintNodeMetaData(std::shared_ptr<CameraMetadata> meta)
{
    common_metadata_header_t *data = meta->get();
    camera_metadata_item_t entry;

    if (data == nullptr) {
        CAMERA_LOGE("data is nullptr");
        return RC_ERROR;
    }

    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_VIDEO_STABILIZATION_MODE, &entry);
    if (ret != 0) {
        CAMERA_LOGE("%{public}s get OHOS_JPEG_QUALITY error and ret= %{public}d", __FUNCTION__, ret);
        return RC_ERROR;
    }
    CAMERA_LOGE("%{public}s get videoStabiliMode value = %{public}d", __FUNCTION__, *(entry.data.u8));
    return RC_OK;
}

REGISTERNODE(StabilityNode, {"stability"})
} // namespace Camera
} // namespace OHOS
