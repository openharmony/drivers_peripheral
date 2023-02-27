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

#ifndef OHOS_HDI_POWER_V1_1_RUNNINGLOCKIMPL_H
#define OHOS_HDI_POWER_V1_1_RUNNINGLOCKIMPL_H

#include <cstdint>
#include <map>
#include <mutex>

#include "running_lock_counter.h"
#include "running_lock_timer_handler.h"
#include "v1_1/power_types.h"
#include "v1_1/running_lock_types.h"

namespace OHOS {
namespace HDI {
namespace Power {
namespace V1_1 {
class RunningLockImpl {
public:
    static int32_t Hold(const RunningLockInfo &info, PowerHdfState state);
    static int32_t Unhold(const RunningLockInfo &info);
    static uint32_t GetCount(RunningLockType type);

private:
    static bool IsValidType(RunningLockType type, PowerHdfState state = PowerHdfState::AWAKE);
    static RunningLockInfo FillRunningLockInfo(const RunningLockInfo &info);
    static std::string GetRunningLockTag(RunningLockType type);
    static std::mutex mutex_;
    static std::unique_ptr<RunningLockTimerHandler> timerHandler_;
    static std::map<RunningLockType, std::shared_ptr<RunningLockCounter>> lockCounters_;
};

} // namespace V1_1
} // namespace Power
} // namespace HDI
} // namespace OHOS

#endif // OHOS_HDI_POWER_V1_1_RUNNINGLOCKIMPL_H
