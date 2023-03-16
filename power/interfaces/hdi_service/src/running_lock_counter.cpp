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

#include "running_lock_counter.h"

#include <file_ex.h>

#include "hdf_base.h"
#include "unique_fd.h"
#include "hdf_log.h"

namespace OHOS {
namespace HDI {
namespace Power {
namespace V1_1 {
#ifndef HDF_RUNNINGLOCK_UNIT_TEST
static constexpr const char * const WAKE_LOCK_PATH = "/sys/power/wake_lock";
static constexpr const char * const WAKE_UNLOCK_PATH = "/sys/power/wake_unlock";
#endif
int32_t RunningLockCounter::Increase(const RunningLockInfo &info)
{
    auto iterator = runninglockInfos_.find(info.name);
    if (iterator != runninglockInfos_.end()) {
        if (info.timeoutMs < 0) {
            HDF_LOGW("Lock counter increase failed, runninglock name = %{public}s is exist and timeout < 0",
                info.name.c_str());
            return HDF_FAILURE;
        }
        iterator->second.timeoutMs = info.timeoutMs;
        return HDF_SUCCESS;
    }
    ++counter_;
    if (counter_ == 1) {
        SuspendBlock(tag_);
    }
    runninglockInfos_.emplace(info.name, info);
    return HDF_SUCCESS;
}

int32_t RunningLockCounter::Decrease(const RunningLockInfo &info)
{
    auto iterator = runninglockInfos_.find(info.name);
    if (iterator == runninglockInfos_.end()) {
        HDF_LOGW("Lock counter decrease failed, runninglock name = %{public}s is not exist", info.name.c_str());
        return HDF_SUCCESS;
    }
    --counter_;
    if (counter_ == 0) {
        SuspendUnblock(tag_);
    }
    runninglockInfos_.erase(info.name);
    return HDF_SUCCESS;
}

void RunningLockCounter::Clear()
{
    runninglockInfos_.clear();
    counter_ = 0;
}

int32_t RunningLockCounter::SuspendBlock(const std::string &name)
{
#ifndef HDF_RUNNINGLOCK_UNIT_TEST
    if (name.empty()) {
        return HDF_ERR_INVALID_PARAM;
    }
    UniqueFd fd(TEMP_FAILURE_RETRY(open(WAKE_LOCK_PATH, O_RDWR | O_CLOEXEC)));
    bool ret = SaveStringToFd(fd, name);
    if (!ret) {
        return HDF_FAILURE;
    }
#endif
    return HDF_SUCCESS;
}

int32_t RunningLockCounter::SuspendUnblock(const std::string &name)
{
#ifndef HDF_RUNNINGLOCK_UNIT_TEST
    if (name.empty()) {
        return HDF_ERR_INVALID_PARAM;
    }
    UniqueFd fd(TEMP_FAILURE_RETRY(open(WAKE_UNLOCK_PATH, O_RDWR | O_CLOEXEC)));
    bool ret = SaveStringToFd(fd, name);
    if (!ret) {
        return HDF_FAILURE;
    }
#endif
    return HDF_SUCCESS;
}
} // namespace V1_1
} // namespace Power
} // namespace HDI
} // namespace OHOS