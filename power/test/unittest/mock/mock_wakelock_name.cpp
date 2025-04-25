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

#include "mock_wakelock_name.h"

#include <algorithm>

namespace OHOS {
namespace HDI {
namespace Power {
namespace V1_3 {
std::vector<std::string> MockWakeLockName::wakeLockName = {};

bool MockWakeLockName::FindWakeLockName(const std::string &name)
{
    auto it = std::find(wakeLockName.begin(), wakeLockName.end(), name);
    if (it != wakeLockName.end()) {
        return true;
    }
    return false;
}

void MockWakeLockName::WriteWakeLockName(const std::string &name)
{
    auto it = std::find(wakeLockName.begin(), wakeLockName.end(), name);
    if (it == wakeLockName.end()) {
        wakeLockName.emplace_back(name);
    }
}

void MockWakeLockName::WriteWakeUnlockName(const std::string &name)
{
    auto it = std::find(wakeLockName.begin(), wakeLockName.end(), name);
    if (it != wakeLockName.end()) {
        wakeLockName.erase(it);
    }
}
} // namespace V1_3
} // namespace Power
} // namespace HDI
} // namespace OHOS