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

namespace OHOS {
namespace HDI {
namespace Power {
namespace V1_1 {
constexpr int32_t DEFAULT_TIMEOUT = 3000;
int32_t RunningLockImpl::Hold(const RunningLockInfo &info)
{
    if (info.name.empty()) {
        return HDF_ERR_INVALID_PARAM;
    }
    if (!IsValidType(info.type)) {
        return HDF_ERR_INVALID_PARAM;
    }
    struct RunningLockInfo filledInfo = FillRunningLockInfo(info);
    (void)filledInfo;
    return HDF_SUCCESS;
}

bool RunningLockImpl::IsValidType(RunningLockType type)
{
    return type == RUNNINGLOCK_BACKGROUND_PHONE || type == RUNNINGLOCK_BACKGROUND_NOTIFICATION ||
        type == RUNNINGLOCK_BACKGROUND_AUDIO || type == RUNNINGLOCK_BACKGROUND_SPORT ||
        type == RUNNINGLOCK_BACKGROUND_NAVIGATION || type == RUNNINGLOCK_BACKGROUND_TASK;
}

int32_t RunningLockImpl::Unhold(const RunningLockInfo &info)
{
    if (info.name.empty()) {
        return HDF_ERR_INVALID_PARAM;
    }
    return HDF_SUCCESS;
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
        filledInfo.timeoutMs = DEFAULT_TIMEOUT;
    }
    return filledInfo;
}
} // namespace V1_1
} // namespace Power
} // namespace HDI
} // namespace OHOS