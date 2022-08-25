/*
 * Copyright (c) 2022 Shenzhen Kaihong DID Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ashmem_wrapper.h"
#include <sys/mman.h>
#include <unistd.h>
#include "ashmem.h"
#include "hdf_base.h"
#include "hdf_log.h"

#define HDF_LOG_TAG codec_hdi_share_mem

using namespace OHOS;

#ifdef __cplusplus
extern "C"
{
#endif

int32_t AshmemCreateFd(const char *name, int32_t size)
{
    if (size <= 0) {
        HDF_LOGE("%{public}s: Failed to create invalid size: %{public}d", __func__, size);
        return HDF_FAILURE;
    }
    int32_t fd = AshmemCreate(name, size);
    if (fd < 0) {
        HDF_LOGE("%{public}s: Failed to create fd = %{public}d", __func__, fd);
    }
    return fd;
}

uint8_t* MapAshmemFd(int32_t fd, int32_t size)
{
    if (fd < 0) {
        HDF_LOGE("%{public}s: Failed to map invalid fd: %{public}d", __func__, fd);
        return nullptr;
    }
    if (size <= 0) {
        HDF_LOGE("%{public}s: Failed to map invalid size: %{public}d", __func__, size);
        return nullptr;
    }
    uint8_t *addr = static_cast<uint8_t *>(mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
    return addr;
}

void UnmapAshmemFd(uint8_t *addr, int32_t size)
{
    if (addr == nullptr) {
        HDF_LOGE("%{public}s: invalid nullptr addr!", __func__);
        return;
    }
    munmap(static_cast<void *>(addr), size);
}

int32_t CloseAshmemFd(int32_t fd)
{
    return close(fd);
}

#ifdef __cplusplus
}
#endif
