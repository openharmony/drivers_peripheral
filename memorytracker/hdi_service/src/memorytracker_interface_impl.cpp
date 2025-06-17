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
#include <dlfcn.h>

namespace OHOS {
namespace HDI {
namespace Memorytracker {
namespace V1_0 {
#define HDF_LOG_TAG           hdf_memorytracker_impl
using GetDevMemFunc = int32_t (*)(int32_t, MemoryTrackerType, std::vector<MemoryRecord>&);

extern "C" IMemoryTrackerInterface *MemoryTrackerInterfaceImplGetInstance(void)
{
    return new (std::nothrow) MemoryTrackerInterfaceImpl();
}

int32_t MemoryTrackerInterfaceImpl::GetDevMem(int32_t pid, MemoryTrackerType type, std::vector<MemoryRecord>& records)
{
    HDF_LOGD("%{public}s called!", __func__);

    auto libMemTrackHandle = dlopen("libmemorytracker.default.so", RTLD_NOW);
    if (!libMemTrackHandle) {
        HDF_LOGE("%{public}s, dlopen libmemorytracker failed!", __func__);
        return HDF_FAILURE;
    }

    auto getDevMemFunc = reinterpret_cast<GetDevMemFunc>(dlsym(libMemTrackHandle, "GetDevMem"));
    if (!getDevMemFunc) {
        HDF_LOGE("%{public}s, dlsym getDevMemFunc failed!", __func__);
        dlclose(libMemTrackHandle);
        return HDF_FAILURE;
    }

    if (getDevMemFunc(pid, type, records) != 0) {
        HDF_LOGD("%{public}s, get device memory failed!", __func__);
        dlclose(libMemTrackHandle);
        return HDF_FAILURE;
    }

    dlclose(libMemTrackHandle);
    HDF_LOGD("%{public}s, get device memory success!", __func__);
    return HDF_SUCCESS;
}
} // V1_0
} // Memorytracker
} // HDI
} // OHOS
