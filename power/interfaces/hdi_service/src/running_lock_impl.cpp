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
#include "power_hdf_log.h"
#include "system_operation.h"

namespace OHOS {
namespace HDI {
namespace Power {
namespace V1_3 {
namespace {
const std::string RUNNINGLOCK_TAG_BACKGROUND_INVALID = "OHOS.RunningLock.Background.Invalid";
const std::string RUNNINGLOCK_TAG_BACKGROUND_PHONE = "OHOS.RunningLock.Background.Phone";
const std::string RUNNINGLOCK_TAG_BACKGROUND_NOTIFICATION = "OHOS.RunningLock.Background.Notification";
const std::string RUNNINGLOCK_TAG_BACKGROUND_AUDIO = "OHOS.RunningLock.Background.Audio";
const std::string RUNNINGLOCK_TAG_BACKGROUND_SPORT = "OHOS.RunningLock.Background.Sport";
const std::string RUNNINGLOCK_TAG_BACKGROUND_NAVIGATION = "OHOS.RunningLock.Background.Navigation";
const std::string RUNNINGLOCK_TAG_BACKGROUND_TASK = "OHOS.RunningLock.Background.Task";
const std::string RUNNINGLOCK_TAG_BACKGROUND_PHONEEXT = "OHOS.RunningLock.Background.PhoneExt";
constexpr int32_t DEFAULT_TIMEOUT = 3000;
} // namespace
std::mutex RunningLockImpl::mutex_;
int32_t RunningLockImpl::defaultTimeOutMs_ = DEFAULT_TIMEOUT;
std::unique_ptr<RunningLockTimerHandler> RunningLockImpl::timerHandler_ = nullptr;
std::map<RunningLockType, std::shared_ptr<RunningLockCounter>> RunningLockImpl::lockCounters_ = {};
sptr<IPowerRunningLockCallback> g_iPowerRunningLockCallback = nullptr;

int32_t RunningLockImpl::Hold(const RunningLockInfo &info, PowerHdfState state,
    uint64_t lockid, const std::string &bundleName)
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
        std::function<void()> unholdFunc = std::bind(&RunningLockImpl::Unhold, filledInfo, lockid, bundleName);
        timerHandler_->RegisterRunningLockTimer(filledInfo, unholdFunc);
    }
    RunningLockImpl::NotifyChanged(filledInfo, lockid, bundleName, "DUBAI_TAG_RUNNINGLOCK_ADD");
    return HDF_SUCCESS;
}

int32_t RunningLockImpl::Unhold(const RunningLockInfo &info,
    uint64_t lockid, const std::string &bundleName)
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
        return HDF_ERR_NOT_SUPPORT;
    }
    if (timerHandler_ != nullptr) {
        timerHandler_->UnregisterRunningLockTimer(filledInfo);
    }
    std::shared_ptr<RunningLockCounter> lockCounter = iterator->second;
    int32_t status = lockCounter->Decrease(filledInfo);
    if (status == HDF_SUCCESS) {
        RunningLockImpl::NotifyChanged(filledInfo, lockid, bundleName, "DUBAI_TAG_RUNNINGLOCK_REMOVE");
    }
    return status;
}

int32_t RunningLockImpl::HoldLock(const RunningLockInfo &info, PowerHdfState state,
    uint64_t lockid, const std::string &bundleName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsValidType(info.type, state)) {
        HDF_LOGW("HoldLock failed, type=%{public}d or state=%{public}d is invalid", info.type, state);
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t status = SystemOperation::WriteWakeLock(GetRunningLockTagInner(info.type));
    return status;
}

int32_t RunningLockImpl::UnholdLock(const RunningLockInfo &info,
    uint64_t lockid, const std::string &bundleName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!IsValidType(info.type)) {
        HDF_LOGW("UnholdLock failed, type=%{public}d is invalid", info.type);
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t status = SystemOperation::WriteWakeUnlock(GetRunningLockTagInner(info.type));
    return status;
}

void RunningLockImpl::Clean()
{
    HDF_LOGI("start to clear running locks");
    std::lock_guard<std::mutex> lock(mutex_);
    if (timerHandler_ != nullptr) {
        timerHandler_->Clean();
    }

    for (auto &iter : lockCounters_) {
        HDF_LOGI("clear running lock type %{public}d", iter.first);
        SystemOperation::WriteWakeUnlock(GetRunningLockTag(iter.first));
        iter.second->Clean();
    }
    lockCounters_.clear();
}

uint32_t RunningLockImpl::GetCount(RunningLockType type)
{
    std::lock_guard<std::mutex> lock(mutex_);
    uint32_t count = 0;
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
        case PowerHdfState::INACTIVE:
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
            return RUNNINGLOCK_TAG_BACKGROUND_PHONEEXT;
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

std::string RunningLockImpl::GetRunningLockTagInner(RunningLockType type)
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

void RunningLockImpl::RegisterRunningLockCallback(const sptr<IPowerRunningLockCallback>
        &iPowerRunningLockCallback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    g_iPowerRunningLockCallback = iPowerRunningLockCallback;
    HDF_LOGI("RegisterRunningLockCallback success");
}

void RunningLockImpl::UnRegisterRunningLockCallback()
{
    std::lock_guard<std::mutex> lock(mutex_);
    g_iPowerRunningLockCallback = nullptr;
    HDF_LOGI("UnRegisterRunningLockCallback success");
}

void RunningLockImpl::NotifyChanged(const RunningLockInfo &info,
    const uint64_t &lockid, const std::string &bundleName, const std::string &tag)
{
    int32_t pid = info.pid;
    int32_t uid = info.uid;
    int32_t type = static_cast<int32_t>(info.type);
    std::string name = info.name;
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    std::string message;
    message.append("LOCKID=").append(std::to_string(lockid))
            .append(" PID=").append(std::to_string(pid))
            .append(" UID=").append(std::to_string(uid))
            .append(" TYPE=").append(std::to_string(type))
            .append(" NAME=").append(name)
            .append(" BUNDLENAME=").append(bundleName)
            .append(" TAG=").append(tag)
            .append(" TIMESTAMP=").append(std::to_string(timestamp));
    HDF_LOGI("runninglock message: %{public}s, timeout: %{public}d", message.c_str(), info.timeoutMs);
    if (g_iPowerRunningLockCallback != nullptr) {
        g_iPowerRunningLockCallback->HandleRunningLockMessage(message);
    }
}

} // namespace V1_3
} // namespace Power
} // namespace HDI
} // namespace OHOS
