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
#include "power_hdf_log.h"

namespace OHOS {
namespace HDI {
namespace Power {
namespace V1_2 {
namespace {
const std::string RUNNINGLOCK_TIMER_HANDLER_NAME = "RunningLock.Timer.Handler";
}
RunningLockTimerHandler::~RunningLockTimerHandler()
{
    if (handlerTimer_ != nullptr) {
        handlerTimer_->Shutdown();
    }
}

bool RunningLockTimerHandler::RegisterRunningLockTimer(
    const RunningLockInfo &info, const std::function<void()> &callback, bool once)
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
        HDF_LOGI("Running lock timer is exist, unregister old timerId=%{public}d, register new timer", lastTimerId);
        UnregisterTimer(lastTimerId);
    }
    uint32_t curTimerId = handlerTimer_->Register(callback, timeoutMs, once);
    if (curTimerId == OHOS::Utils::TIMER_ERR_DEAL_FAILED) {
        HDF_LOGW("Register running lock timer failed");
        if (lastTimerId != OHOS::Utils::TIMER_ERR_DEAL_FAILED) {
            RemoveRunningLockTimerMap(runninglockType, runninglockName);
        }
        return false;
    }
    AddRunningLockTimerMap(runninglockType, runninglockName, curTimerId);
    return true;
}

bool RunningLockTimerHandler::UnregisterRunningLockTimer(const RunningLockInfo &info)
{
    RunningLockType runninglockType = info.type;
    std::string runninglockName = info.name;
    uint32_t timerId = GetRunningLockTimerId(runninglockType, runninglockName);
    if (timerId != OHOS::Utils::TIMER_ERR_DEAL_FAILED) {
        HDF_LOGI("Running lock timer is exist, unregister timerId=%{public}d", timerId);
        UnregisterTimer(timerId);
        RemoveRunningLockTimerMap(runninglockType, runninglockName);
    }
    return true;
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

void RunningLockTimerHandler::AddRunningLockTimerMap(RunningLockType type, std::string name, uint32_t timerId)
{
    auto typeIter = runninglockTimerMap_.find(type);
    if (typeIter == runninglockTimerMap_.end()) {
        std::map<std::string, uint32_t> timerIdMap;
        timerIdMap.emplace(name, timerId);
        runninglockTimerMap_.emplace(type, timerIdMap);
        return;
    }
    auto nameIter = typeIter->second.find(name);
    if (nameIter == typeIter->second.end()) {
        typeIter->second.emplace(name, timerId);
        return;
    }
    nameIter->second = timerId;
}

void RunningLockTimerHandler::RemoveRunningLockTimerMap(RunningLockType type, std::string name)
{
    auto typeIter = runninglockTimerMap_.find(type);
    if (typeIter != runninglockTimerMap_.end()) {
        auto nameIter = typeIter->second.find(name);
        if (nameIter != typeIter->second.end()) {
            typeIter->second.erase(name);
            if (typeIter->second.size() == 0) {
                runninglockTimerMap_.erase(type);
            }
        }
    }
}

void RunningLockTimerHandler::UnregisterTimer(uint32_t timerId)
{
    if (handlerTimer_ != nullptr) {
        handlerTimer_->Unregister(timerId);
    }
}

void RunningLockTimerHandler::Clean()
{
    if (handlerTimer_ != nullptr) {
        handlerTimer_->Shutdown();
        for (auto &timer : runninglockTimerMap_) {
            timer.second.clear();
        }
        runninglockTimerMap_.clear();
        handlerTimer_ = nullptr;
    }
}

} // namespace V1_2
} // namespace Power
} // namespace HDI
} // namespace OHOS
