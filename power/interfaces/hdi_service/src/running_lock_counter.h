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

#ifndef OHOS_HDI_POWER_V1_1_RUNNINGLOCKCOUNTER_H
#define OHOS_HDI_POWER_V1_1_RUNNINGLOCKCOUNTER_H

#include <cstdint>
#include <map>

#include "v1_1/running_lock_types.h"

namespace OHOS {
namespace HDI {
namespace Power {
namespace V1_1 {
class RunningLockCounter {
public:
    RunningLockCounter(RunningLockType type, const std::string &tag)
        : type_(type), tag_(tag), counter_(0) {}
    ~RunningLockCounter() = default;
    int32_t Increase(const RunningLockInfo &info);
    int32_t Decrease(const RunningLockInfo &info);
    uint32_t GetCount() const
    {
        return counter_;
    }
    RunningLockType GetType() const
    {
        return type_;
    }
private:
    const RunningLockType type_;
    const std::string tag_;
    uint32_t counter_;
    std::map<std::string, RunningLockInfo> runninglockInfos_ {};
};
} // namespace V1_1
} // namespace Power
} // namespace HDI
} // namespace OHOS

#endif // OHOS_HDI_POWER_V1_1_RUNNINGLOCKCOUNTER_H