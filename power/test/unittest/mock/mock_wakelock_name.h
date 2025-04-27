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

#ifndef MOCK_WAKELOCK_NAME_H
#define MOCK_WAKELOCK_NAME_H

#include <string>
#include <vector>

namespace OHOS {
namespace HDI {
namespace Power {
namespace V1_2 {
class MockWakeLockName {
public:
    static bool FindWakeLockName(const std::string &name);
    static void WriteWakeLockName(const std::string &name);
    static void WriteWakeUnlockName(const std::string &name);

private:
    static std::vector<std::string> wakeLockName;
};
} // namespace V1_2
} // namespace Power
} // namespace HDI
} // namespace OHOS

#endif // MOCK_WAKELOCK_NAME_H