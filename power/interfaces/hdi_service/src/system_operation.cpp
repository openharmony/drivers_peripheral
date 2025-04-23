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

#include "system_operation.h"

#include <fcntl.h>
#include <file_ex.h>

#include "hdf_base.h"
#include "unique_fd.h"

namespace OHOS {
namespace HDI {
namespace Power {
namespace V1_3 {
static constexpr const char * const WAKE_LOCK_PATH = "/sys/power/wake_lock";
static constexpr const char * const WAKE_UNLOCK_PATH = "/sys/power/wake_unlock";

int32_t SystemOperation::WriteWakeLock(const std::string &name)
{
    if (name.empty()) {
        return HDF_ERR_INVALID_PARAM;
    }
    UniqueFd fd(TEMP_FAILURE_RETRY(open(WAKE_LOCK_PATH, O_RDWR | O_CLOEXEC)));
    bool ret = SaveStringToFd(fd, name);
    if (!ret) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t SystemOperation::WriteWakeUnlock(const std::string &name)
{
    if (name.empty()) {
        return HDF_ERR_INVALID_PARAM;
    }
    UniqueFd fd(TEMP_FAILURE_RETRY(open(WAKE_UNLOCK_PATH, O_RDWR | O_CLOEXEC)));
    bool ret = SaveStringToFd(fd, name);
    if (!ret) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
} // namespace V1_3
} // namespace Power
} // namespace HDI
} // namespace OHOS
