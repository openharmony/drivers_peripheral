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

#ifndef OHOS_HDI_POWER_V1_3_RUNNINGLOCKIMPL_H
#define OHOS_HDI_POWER_V1_3_RUNNINGLOCKIMPL_H

#include <cstdint>
#include <map>
#include <mutex>

#include "running_lock_counter.h"
#include "running_lock_timer_handler.h"
#include "v1_3/power_types.h"
#include "v1_3/ipower_running_lock_callback.h"
#include "v1_3/running_lock_types.h"

namespace OHOS {
namespace HDI {
namespace Power {
namespace V1_3 {
class RunningLockImpl {
public:
    static int32_t Hold(const RunningLockInfo &info, PowerHdfState state,
        uint64_t lockid = 0, const std::string &bundleName = "");
    static int32_t Unhold(const RunningLockInfo &info,
        uint64_t lockid = 0, const std::string &bundleName = "");
    static int32_t HoldLock(const RunningLockInfo &info, PowerHdfState state,
        uint64_t lockid = 0, const std::string &bundleName = "");
    static int32_t UnholdLock(const RunningLockInfo &info,
        uint64_t lockid = 0, const std::string &bundleName = "");
    static void Clean();
    static uint32_t GetCount(RunningLockType type);
    static std::string GetRunningLockTag(RunningLockType type);
    static std::string GetRunningLockTagInner(RunningLockType type);
    static void SetDefaultTimeOutMs(int32_t timeOutMs);

    static void RegisterRunningLockCallback(const sptr<IPowerRunningLockCallback>
        &iPowerRunningLockCallback);
    static void UnRegisterRunningLockCallback();

    static void NotifyChanged(const RunningLockInfo &info,
        const uint64_t &lockid, const std::string &bundleName, const std::string &tag);

private:
    static bool IsValidType(RunningLockType type, PowerHdfState state = PowerHdfState::AWAKE);
    static RunningLockInfo FillRunningLockInfo(const RunningLockInfo &info);
    static std::mutex mutex_;
    static int32_t defaultTimeOutMs_;
    static std::unique_ptr<RunningLockTimerHandler> timerHandler_;
    static std::map<RunningLockType, std::shared_ptr<RunningLockCounter>> lockCounters_;
};

} // namespace V1_3
} // namespace Power
} // namespace HDI
} // namespace OHOS

#endif // OHOS_HDI_POWER_V1_3_RUNNINGLOCKIMPL_H
