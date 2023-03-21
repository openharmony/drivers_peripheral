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

#include "running_lock_impl.h"

#include "hdf_base.h"
#include "hdf_log.h"

namespace OHOS {
namespace HDI {
namespace Power {
namespace V1_1 {
namespace {
const std::string RUNNINGLOCK_TAG_BACKGROUND_INVALID = "OHOS.RunningLock.Background.Invalid";
const std::string RUNNINGLOCK_TAG_BACKGROUND_PHONE = "OHOS.RunningLock.Background.Phone";
const std::string RUNNINGLOCK_TAG_BACKGROUND_NOTIFICATION = "OHOS.RunningLock.Background.Notification";
const std::string RUNNINGLOCK_TAG_BACKGROUND_AUDIO = "OHOS.RunningLock.Background.Audio";
const std::string RUNNINGLOCK_TAG_BACKGROUND_SPORT = "OHOS.RunningLock.Background.Sport";
const std::string RUNNINGLOCK_TAG_BACKGROUND_NAVIGATION = "OHOS.RunningLock.Background.Navigation";
const std::string RUNNINGLOCK_TAG_BACKGROUND_TASK = "OHOS.RunningLock.Background.Task";
constexpr int32_t DEFAULT_TIMEOUT = 3000;
} // namespace
std::mutex RunningLockImpl::mutex_;
int32_t RunningLockImpl::defaultTimeOutMs_ = DEFAULT_TIMEOUT;
std::unique_ptr<RunningLockTimerHandler> RunningLockImpl::timerHandler_ = nullptr;
std::map<RunningLockType, std::shared_ptr<RunningLockCounter>> RunningLockImpl::lockCounters_ = {};

int32_t RunningLockImpl::Hold(const RunningLockInfo &info, PowerHdfState state)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (info.name.empty()) {
        HDF_LOGW("Runninglock hold failed, name is empty");
        return HDF_ERR_INVALID_PARAM;
    }
    RunningLockInfo filledInfo = FillRunningLockInfo(info);
    if (!IsValidType(filledInfo.type, state)) {
        HDF_LOGW("Runninglock hold failed, type=%{public}d or state=%{public}d is invalid", filledInfo.type, state);
        return HDF_ERR_INVALID_PARAM;
    }
    auto iterator = lockCounters_.find(filledInfo.type);
    if (iterator == lockCounters_.end()) {
        auto pair = lockCounters_.emplace(filledInfo.type,
            std::make_shared<RunningLockCounter>(filledInfo.type, GetRunningLockTag(filledInfo.type)));
        if (pair.second == false) {
            HDF_LOGW("Runninglock hold failed, type=%{public}d is not in lockCounters", filledInfo.type);
            return HDF_FAILURE;
        }
        iterator = pair.first;
    }
    std::shared_ptr<RunningLockCounter> lockCounter = iterator->second;
    if (lockCounter->Increase(filledInfo) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    if (filledInfo.timeoutMs > 0) {
        if (timerHandler_ == nullptr) {
            timerHandler_ = std::make_unique<RunningLockTimerHandler>();
        }
        std::function<void()> unholdFunc = std::bind(&RunningLockImpl::Unhold, filledInfo);
        timerHandler_->RegisterRunningLockTimer(filledInfo, unholdFunc);
    }
    return HDF_SUCCESS;
}

int32_t RunningLockImpl::Unhold(const RunningLockInfo &info)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (info.name.empty()) {
        HDF_LOGW("Runninglock unhold failed, name is empty");
        return HDF_ERR_INVALID_PARAM;
    }
    RunningLockInfo filledInfo = FillRunningLockInfo(info);
    if (!IsValidType(filledInfo.type)) {
        HDF_LOGW("Runninglock unhold failed, type=%{public}d is invalid", filledInfo.type);
        return HDF_ERR_INVALID_PARAM;
    }
    auto iterator = lockCounters_.find(filledInfo.type);
    if (iterator == lockCounters_.end()) {
        HDF_LOGW("type=%{public}d is not in lockCounters, no need to unhold", filledInfo.type);
        return HDF_SUCCESS;
    }
    if (timerHandler_ != nullptr) {
        timerHandler_->UnregisterRunningLockTimer(filledInfo);
    }
    std::shared_ptr<RunningLockCounter> lockCounter = iterator->second;
    if (lockCounter->Decrease(filledInfo) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

uint32_t RunningLockImpl::GetCount(RunningLockType type)
{
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t count = 0;
    auto iterator = lockCounters_.find(type);
    if (iterator != lockCounters_.end()) {
        count = iterator->second->GetCount();
    }
    return count;
}

void RunningLockImpl::SetDefaultTimeOutMs(int32_t timeOutMs)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (timeOutMs > 0) {
        defaultTimeOutMs_ = timeOutMs;
    }
}

bool RunningLockImpl::IsValidType(RunningLockType type, PowerHdfState state)
{
    switch (state) {
        case PowerHdfState::SLEEP:
            return false;
        case PowerHdfState::INACTIVE:
            return type == RUNNINGLOCK_BACKGROUND_PHONE || type == RUNNINGLOCK_BACKGROUND_NOTIFICATION;
        case PowerHdfState::AWAKE:
            return type == RUNNINGLOCK_BACKGROUND_PHONE || type == RUNNINGLOCK_BACKGROUND_NOTIFICATION ||
                type == RUNNINGLOCK_BACKGROUND_AUDIO || type == RUNNINGLOCK_BACKGROUND_SPORT ||
                type == RUNNINGLOCK_BACKGROUND_NAVIGATION || type == RUNNINGLOCK_BACKGROUND_TASK;
        default:
            break;
    }
    return false;
}

RunningLockInfo RunningLockImpl::FillRunningLockInfo(const RunningLockInfo &info)
{
    struct RunningLockInfo filledInfo {
        .name = info.name,
        .type = info.type,
        .timeoutMs = info.timeoutMs,
        .pid = info.pid,
        .uid = info.uid,
    };
    if (static_cast<uint32_t>(filledInfo.type) == 0) {
        filledInfo.type = RunningLockType::RUNNINGLOCK_BACKGROUND_TASK;
    }
    if (filledInfo.timeoutMs == 0) {
        filledInfo.timeoutMs = defaultTimeOutMs_;
    }
    return filledInfo;
}

std::string RunningLockImpl::GetRunningLockTag(RunningLockType type)
{
    switch (type) {
        case RunningLockType::RUNNINGLOCK_BACKGROUND_PHONE:
            return RUNNINGLOCK_TAG_BACKGROUND_PHONE;
        case RunningLockType::RUNNINGLOCK_BACKGROUND_NOTIFICATION:
            return RUNNINGLOCK_TAG_BACKGROUND_NOTIFICATION;
        case RunningLockType::RUNNINGLOCK_BACKGROUND_AUDIO:
            return RUNNINGLOCK_TAG_BACKGROUND_AUDIO;
        case RunningLockType::RUNNINGLOCK_BACKGROUND_SPORT:
            return RUNNINGLOCK_TAG_BACKGROUND_SPORT;
        case RunningLockType::RUNNINGLOCK_BACKGROUND_NAVIGATION:
            return RUNNINGLOCK_TAG_BACKGROUND_NAVIGATION;
        case RunningLockType::RUNNINGLOCK_BACKGROUND_TASK:
            return RUNNINGLOCK_TAG_BACKGROUND_TASK;
        default: {
            HDF_LOGE("type=%{public}d is invalid, there is no corresponding tag", type);
            return RUNNINGLOCK_TAG_BACKGROUND_INVALID;
        }
    }
}
} // namespace V1_1
} // namespace Power
} // namespace HDI
} // namespace OHOS