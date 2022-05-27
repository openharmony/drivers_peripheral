/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "memorytracker_interface_impl.h"
#include <hdf_base.h>
#include <hdf_log.h>

namespace OHOS {
namespace HDI {
namespace MemoryTracker {
namespace V1_0 {
#define HDF_LOG_TAG           hdf_memorytracker_impl

extern "C" IMemoryTrackerInterface *MemoryTrackerInterfaceImplGetInstance(void)
{
    return new (std::nothrow) MemoryTrackerInterfaceImpl();
}

// vendor should implement this method
int32_t MemoryTrackerInterfaceImpl::GetDevMem(int32_t pid, MemoryTrackerType type, std::vector<MemoryRecord>& records)
{
    HDF_LOGI("%{public}s called!", __func__);
    // just for testing
    records.push_back( { FLAG_UNMAPPED, 123 } ); // 123: just for testing
    records.push_back( { FLAG_MAPPED, 456 } ); // 456: just for testing
    return HDF_SUCCESS;
}
} // V1_0
} // MemoryTracker
} // HDI
} // OHOS
