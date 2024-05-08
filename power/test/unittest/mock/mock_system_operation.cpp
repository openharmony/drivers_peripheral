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

#include "hdf_base.h"
#include "mock_wakelock_name.h"

namespace OHOS {
namespace HDI {
namespace Power {
namespace V1_2 {
int32_t SystemOperation::WriteWakeLock(const std::string &name)
{
    MockWakeLockName::WriteWakeLockName(name);
    return HDF_SUCCESS;
}

int32_t SystemOperation::WriteWakeUnlock(const std::string &name)
{
    MockWakeLockName::WriteWakeUnlockName(name);
    return HDF_SUCCESS;
}
} // namespace V1_2
} // namespace Power
} // namespace HDI
} // namespace OHOS