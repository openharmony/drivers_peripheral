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
#include "running_lock_timer_handler.h"

#include "common_timer_errors.h"
#include "hdf_log.h"

namespace OHOS {
namespace HDI {
namespace Power {
namespace V1_1 {
namespace {
const std::string RUNNINGLOCK_TIMER_HANDLER_NAME = "RunningLock.Timer.Handler";
}
RunningLockTimerHandler::~RunningLockTimerHandler()
{
    if (handlerTimer_ != nullptr) {
        handlerTimer_->Shutdown();
    }
}

bool RunningLockTimerHandler::RegisterRunningLockTimer(const RunningLockInfo &info,
    const std::function<void()> &callback, bool once)
{
    if (handlerTimer_ == nullptr) {
        handlerTimer_ = std::make_unique<OHOS::Utils::Timer>(RUNNINGLOCK_TIMER_HANDLER_NAME);
        handlerTimer_->Setup();
    }
    RunningLockType runninglockType = info.type;
    std::string runninglockName = info.name;
    uint32_t timeoutMs = info.timeoutMs;
    uint32_t lastTimerId = GetRunningLockTimerId(runninglockType, runninglockName);
    if (lastTimerId != OHOS::Utils::TIMER_ERR_DEAL_FAILED) {
        HDF_LOGI("Running lock timer is exist, unregister old timerId = %{public}d, register new timer", lastTimerId);
        UnregisterTimer(lastTimerId);
    }
    uint32_t curTimerId = handlerTimer_->Register(callback, timeoutMs, once);
    if (curTimerId == OHOS::Utils::TIMER_ERR_DEAL_FAILED) {
        HDF_LOGW("Register running lock timer failed");
        if (lastTimerId != OHOS::Utils::TIMER_ERR_DEAL_FAILED) {
            UpdateRunninglockTimerMap(runninglockType, runninglockName, lastTimerId, true);
        }
        return false;
    }
    UpdateRunninglockTimerMap(runninglockType, runninglockName, curTimerId, false);
    return true;
}

bool RunningLockTimerHandler::UnregisterRunningLockTimer(const RunningLockInfo &info)
{
    RunningLockType runninglockType = info.type;
    std::string runninglockName = info.name;
    uint32_t timerId = GetRunningLockTimerId(runninglockType, runninglockName);
    if (timerId != OHOS::Utils::TIMER_ERR_DEAL_FAILED) {
        HDF_LOGI("Running lock timer is exist, unregister timerId = %{public}d", timerId);
        UnregisterTimer(timerId);
        UpdateRunninglockTimerMap(runninglockType, runninglockName, timerId, true);
    }
    return true;
}

uint32_t RunningLockTimerHandler::GetRunningLockTimerCount()
{
    uint32_t lockCount = 0;
    for (auto typeIter : runninglockTimerMap_) {
        for (auto nameIter : typeIter.second) {
            lockCount++;
        }
    }
    return lockCount;
}

uint32_t RunningLockTimerHandler::GetRunningLockTimerId(RunningLockType type, std::string name)
{
    uint32_t timerId = OHOS::Utils::TIMER_ERR_DEAL_FAILED;
    auto typeIter = runninglockTimerMap_.find(type);
    if (typeIter != runninglockTimerMap_.end()) {
        auto nameIter = typeIter->second.find(name);
        if (nameIter != typeIter->second.end()) {
            timerId = nameIter->second;
        }
    }
    return timerId;
}

void RunningLockTimerHandler::UpdateRunninglockTimerMap(RunningLockType type, std::string name,
    uint32_t timerId, bool remove)
{
    if (remove) {
        auto typeIter = runninglockTimerMap_.find(type);
        if (typeIter != runninglockTimerMap_.end()) {
            auto nameIter = typeIter->second.find(name);
            if(nameIter != typeIter->second.end()) {
                typeIter->second.erase(name);
                if (typeIter->second.size() == 0) {
                    runninglockTimerMap_.erase(type);
                }
            }
        }
        return;
    }
    auto typeIter = runninglockTimerMap_.find(type);
    if (typeIter == runninglockTimerMap_.end()) {
        std::map<std::string, uint32_t> timerIdMap;
        timerIdMap.emplace(name, timerId);
        runninglockTimerMap_.emplace(type, timerIdMap);
        return;
    }
    auto nameIter = typeIter->second.find(name);
    if(nameIter == typeIter->second.end()) {
        typeIter->second.emplace(name, timerId);
        return;
    }
    if (nameIter->second != timerId) {
        nameIter->second = timerId;
    }
}

void RunningLockTimerHandler::UnregisterTimer(uint32_t timerId)
{
    if (handlerTimer_ != nullptr) {
        handlerTimer_->Unregister(timerId);
    }
}
} // namespace V1_1
} // namespace Power
} // namespace HDI
} // namespace OHOS