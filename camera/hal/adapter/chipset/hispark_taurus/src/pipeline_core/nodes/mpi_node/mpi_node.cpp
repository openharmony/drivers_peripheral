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

#include "mpi_node.h"
namespace OHOS::Camera {
MpiNode::MpiNode(const std::string& name, const std::string& type, const int streamId)
    :NodeBase(name, type, streamId)
{
    CAMERA_LOGI("%s enter, type(%s), stream id = %d\n", name_.c_str(), type_.c_str(), streamId);
}

RetCode MpiNode::GetMpiDeviceManager()
{
    deviceManager_ = IDeviceManager::GetInstance();
    if (deviceManager_ == nullptr) {
        CAMERA_LOGE("get device manager failed.");
        return RC_ERROR;
    }
    return RC_OK;
}


RetCode MpiNode::ConnectMpi()
{
    RetCode rc = RC_OK;
    std::vector<std::shared_ptr<IPort>> ports = GetOutPorts();
    if (ports.empty() || deviceManager_ == nullptr) {
        CAMERA_LOGE("have no outport or devicemanager is null");
        return RC_OK;
    }
    for (const auto& it : ports) {
        CAMERA_LOGV("%s, mpp try to connect %s to %s.", __FUNCTION__,
                it->GetNode()->GetName().c_str(), it->Peer()->GetNode()->GetName().c_str());
        rc = deviceManager_->Connect(name_, it->GetName(), it->Peer()->GetNode()->GetName(), it->Peer()->GetName());
        if (rc == RC_ERROR) {
            CAMERA_LOGE("failed to connect.");
            return rc;
        }
        CAMERA_LOGI("connect success");
    }
    return rc;
}

RetCode MpiNode::DisConnectMpi()
{
    RetCode rc = RC_OK;
    std::vector<std::shared_ptr<IPort>> ports = GetOutPorts();
    if (ports.empty() || deviceManager_ == nullptr) {
        CAMERA_LOGE("have no outport or devicemanager is null");
        return RC_OK;
    }
    for (const auto& it : ports) {
        rc = deviceManager_->UnConnect(name_, it->GetName(), it->Peer()->GetNode()->GetName(),
            it->Peer()->GetName());
        if (rc == RC_ERROR) {
            CAMERA_LOGE("failed to unconnect.");
            return rc;
        }
        CAMERA_LOGI("disconnect success");
    }
    return rc;
}
} // namespace OHOS::Camera
