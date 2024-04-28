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

#ifndef OHOS_HDI_POWER_V1_2_SYSTEMOPERATION_H
#define OHOS_HDI_POWER_V1_2_SYSTEMOPERATION_H

#include <string>

namespace OHOS {
namespace HDI {
namespace Power {
namespace V1_2 {
class SystemOperation {
public:
    static int32_t WriteWakeLock(const std::string &name);
    static int32_t WriteWakeUnlock(const std::string &name);
};
} // namespace V1_2
} // namespace Power
} // namespace HDI
} // namespace OHOS

#endif // OHOS_HDI_POWER_V1_2_SYSTEMOPERATION_H