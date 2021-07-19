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
#include "venc_node.h"

namespace OHOS::Camera {
VencNode::VencNode(const std::string& name, const std::string& type, const int streamId)
    :MpiNode(name, type, streamId)
{
    CAMERA_LOGI("%s enter, type(%s), stream id = %d\n", name_.c_str(), type_.c_str(), streamId);
}

RetCode VencNode::GetDeviceController() const
{
    return RC_OK;
}

RetCode VencNode::Start()
{
    return RC_OK;
}
RetCode VencNode::Stop()
{
    return RC_OK;
}

REGISTERNODE(VencNode, {"venc"})
} // namespace OHOS::Camera
