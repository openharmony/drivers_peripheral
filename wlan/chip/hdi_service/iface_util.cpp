/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <hdf_log.h>
#include "iface_util.h"

namespace OHOS {
namespace HDI {
namespace Wlan {
namespace Chip {
namespace V2_0 {
IfaceUtil::IfaceUtil(const std::weak_ptr<IfaceTool> ifaceTool)
    : ifaceTool_(ifaceTool)
{}

bool IfaceUtil::SetMacAddress(const std::string& ifaceName, const std::string& mac)
{
    bool success = ifaceTool_.lock()->SetMacAddress(ifaceName.c_str(), mac.c_str());
    if (!success) {
        HDF_LOGE("SetMacAddress failed on %{public}s", ifaceName.c_str());
    } else {
        HDF_LOGD("SetMacAddress successed on %{public}s", ifaceName.c_str());
    }
    return success;
}

bool IfaceUtil::SetUpState(const std::string& ifaceName, bool requestUp)
{
    return ifaceTool_.lock()->SetUpState(ifaceName.c_str(), requestUp);
}

bool IfaceUtil::GetUpState(const std::string& ifaceName)
{
    return ifaceTool_.lock()->GetUpState(ifaceName.c_str());
}
}
}
}
}
}