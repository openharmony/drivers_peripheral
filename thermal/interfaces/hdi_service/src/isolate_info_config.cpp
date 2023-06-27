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
#include "isolate_info_config.h"

#define HDF_LOG_TAG IsolateInfoConfig

namespace OHOS {
namespace HDI {
namespace Thermal {
namespace V1_1 {

void IsolateInfoConfig::SetIsolateNodeInfo(std::vector<IsolateNodeInfo> &vXmlNodeList)
{
    nodeInfoList_ = vXmlNodeList;
}

std::vector<IsolateNodeInfo> IsolateInfoConfig::GetIsolateNodeInfo()
{
    return nodeInfoList_;
}

void IsolateInfoConfig::SetGroupName(const std::string &groupName)
{
    groupName_ = groupName;
}

std::string IsolateInfoConfig::GetGroupName()
{
    return groupName_;
}
} // V1_1
} // Thermal
} // HDI
} // OHOS