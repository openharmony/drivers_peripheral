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

#ifndef OHOS_HDI_POWER_V1_2_RUNNINGLOCK_TIMERHANDKER_H
#define OHOS_HDI_POWER_V1_2_RUNNINGLOCK_TIMERHANDKER_H

#include <cstdint>
#include <map>
#include <timer.h>

#include "v1_2/running_lock_types.h"

namespace OHOS {
namespace HDI {
namespace Power {
namespace V1_2 {
class RunningLockTimerHandler {
public:
    RunningLockTimerHandler() = default;
    ~RunningLockTimerHandler();

    bool RegisterRunningLockTimer(const RunningLockInfo &info, const std::function<void()> &callback, bool once = true);
    bool UnregisterRunningLockTimer(const RunningLockInfo &info);
    void Clean();

private:
    uint32_t GetRunningLockTimerId(RunningLockType type, std::string name);
    void AddRunningLockTimerMap(RunningLockType type, std::string name, uint32_t timerId);
    void RemoveRunningLockTimerMap(RunningLockType type, std::string name);
    void UnregisterTimer(uint32_t timerId);
    std::unique_ptr<OHOS::Utils::Timer> handlerTimer_;
    std::map<RunningLockType, std::map<std::string, uint32_t>> runninglockTimerMap_;
};
} // namespace V1_2
} // namespace Power
} // namespace HDI
} // namespace OHOS

#endif // OHOS_HDI_POWER_V1_2_RUNNINGLOCK_TIMERHANDKER_H
