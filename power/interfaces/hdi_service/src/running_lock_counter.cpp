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
#include "hdf_base.h"
#include "system_operation.h"
#include "power_hdf_log.h"

namespace OHOS {
namespace HDI {
namespace Power {
namespace V1_2 {
int32_t RunningLockCounter::Increase(const RunningLockInfo &info)
{
    auto iterator = runninglockInfos_.find(info.name);
    if (iterator != runninglockInfos_.end()) {
        if (info.timeoutMs < 0) {
            // Lock counter increase failed, runninglock is exist and timeout < 0
            HDF_LOGW("LCIF,N=%{public}s exist", info.name.c_str());
            return HDF_FAILURE;
        }
        iterator->second.timeoutMs = info.timeoutMs;
        return HDF_SUCCESS;
    }
    ++counter_;
    if (counter_ == 1) {
        SystemOperation::WriteWakeLock(tag_);
    }
    runninglockInfos_.emplace(info.name, info);
    return HDF_SUCCESS;
}

int32_t RunningLockCounter::Decrease(const RunningLockInfo &info)
{
    auto iterator = runninglockInfos_.find(info.name);
    if (iterator == runninglockInfos_.end()) {
        // Runninglock is not exist, no need to decrease lock counter
        HDF_LOGW("RL N=%{public}s no exist", info.name.c_str());
        return HDF_ERR_NOT_SUPPORT;
    }
    --counter_;
    if (counter_ == 0) {
        SystemOperation::WriteWakeUnlock(tag_);
    }
    runninglockInfos_.erase(info.name);
    return HDF_SUCCESS;
}

void RunningLockCounter::Clean()
{
    runninglockInfos_.clear();
}

} // namespace V1_2
} // namespace Power
} // namespace HDI
} // namespace OHOS
