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

#include "vi_node.h"
namespace OHOS::Camera{
ViNode::ViNode(const std::string& name, const std::string& type, const int streamId)
        :MpiNode(name, type, streamId)
{
    CAMERA_LOGI("%s enter, type(%s), stream id = %d\n", name_.c_str(), type_.c_str(), streamId);
}

RetCode ViNode::GetDeviceController()
{
    GetMpiDeviceManager();
    viController_ = std::static_pointer_cast<ViController>
        ((std::static_pointer_cast<ViManager>(deviceManager_->GetManager(DM_M_VI)))->GetController(DM_C_VI));
    if (viController_ == nullptr) {
        CAMERA_LOGE("get device controller failed");
        return RC_ERROR;
    }
    return RC_OK;
}

RetCode ViNode::Start()
{
    RetCode rc = RC_OK;
    rc = GetDeviceController();
    if (rc == RC_ERROR) {
        CAMERA_LOGE("GetDeviceController failed.");
        return RC_ERROR;
    }
    rc = viController_->ConfigVi();
    if (rc == RC_ERROR) {
        CAMERA_LOGE("configvi failed.");
        return RC_ERROR;
    }
    rc = viController_->StartVi();
    if (rc == RC_ERROR) {
        CAMERA_LOGE("startvi failed.");
        return RC_ERROR;
    }
    rc = ConnectMpi();
    if (rc == RC_ERROR) {
        CAMERA_LOGE("connectMpi failed.");
        return RC_ERROR;
    }
    streamRunning_ = true;
    return RC_OK;
}

RetCode ViNode::Stop()
{
    RetCode rc = RC_OK;
    if (streamRunning_ == false) {
        CAMERA_LOGI("vi node : streamrunning is already false");
        return RC_OK;
    }
    streamRunning_ = false;
    rc = DisConnectMpi();
    if (rc == RC_ERROR) {
        CAMERA_LOGE("DisConnectMpi failed!");
        return RC_ERROR;
    }
    rc = viController_->StopVi();
    if (rc == RC_ERROR) {
        CAMERA_LOGE("stopvi failed!");
        return RC_ERROR;
    }
    return RC_OK;
}

RetCode ViNode::Configure(std::shared_ptr<CameraStandard::CameraMetadata> meta)
{
    RetCode rc = RC_OK;
    IS_NULLPTR(meta)
    rc = viController_->Configure(meta);
    IS_ERROR(rc)
    return rc;
}

REGISTERNODE(ViNode, {"vi"})
} // namespace OHOS::Camera
