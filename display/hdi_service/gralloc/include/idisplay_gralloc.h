/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef HDI_IDISPLAY_GRALLOC_V1_0_H
#define HDI_IDISPLAY_GRALLOC_V1_0_H

#include <vector>
#include "display_type.h"
#include "buffer_handle.h"

namespace OHOS {
namespace HDI {
namespace Display {
namespace V1_0 {
using AllocatorDeathCallback = void (*)(void *);
class IDisplayGralloc {
public:
    virtual ~IDisplayGralloc() = default;

    virtual int32_t RegAllocatorDeathCallback(AllocatorDeathCallback func, void* data) = 0;

    /**
     * @brief Obtains all interfaces of IDisplayGralloc.
     *
     * @return Returns <b>IDisplayGralloc*</b> if the operation is successful; returns an null point otherwise.
     * @since 1.0
     * @version 1.0
     */
    static IDisplayGralloc* Get();

    /**
     * @brief Allocates memory based on the parameters passed by the GUI.
     *
     * @param info Indicates the description of the memory to allocate.
     *
     * @param handle Indicates the pointer to the buffer of the memory to allocate.
     *
     * @return Returns <b>0</b> if the operation is successful; returns an error code defined in {@link DispErrCode}
     * otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t AllocMem(const AllocInfo &info, BufferHandle *&handle) const = 0;

    /**
     * @brief Releases memory.
     *
     * @param handle Indicates the reference to the buffer of the memory to release.
     *
     * @since 1.0
     * @version 1.0
     */
    virtual void FreeMem(const BufferHandle &handle) const = 0;

    /**
     * @brief Maps memory to memory without cache in the process's address space.
     *
     * @param handle Indicates the reference to the buffer of the memory to map.
     *
     * @return Returns the pointer to a valid address if the operation is successful; returns <b>NULL</b> otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual void *Mmap(const BufferHandle &handle) const = 0;

    /**
     * @brief Maps memory to memory with cache in the process's address space.
     *
     * @param handle Indicates the reference to the buffer of the memory to map.
     *
     * @return Returns the pointer to a valid address if the operation is successful; returns <b>NULL</b> otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual void *MmapCache(const BufferHandle &buffer) const = 0;

    /**
     * @brief Unmaps memory, that is, removes mappings from the process's address space.
     *
     * @param handle Indicates the reference to the buffer of the memory to unmap.
     *
     * @return Returns <b>0</b> if the operation is successful; returns an error code defined in {@link DispErrCode}
     * otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t Unmap(const BufferHandle &handle) const = 0;

    /**
     * @brief Flushes data from the cache to memory and invalidates the data in the cache.
     *
     * @param handle Indicates the reference to the buffer of the cache to flush.
     *
     * @return Returns <b>0</b> if the operation is successful; returns an error code defined in {@link DispErrCode}
     * otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t FlushCache(const BufferHandle &handle) const = 0;

    /**
     * @brief Flushes data from the cache mapped via {@link Mmap} to memory and invalidates the data in the cache.
     *
     * @param handle Indicates the reference to the buffer of the cache to flush.
     *
     * @return Returns <b>0</b> if the operation is successful; returns an error code defined in {@link DispErrCode}
     * otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t FlushMCache(const BufferHandle &buffer) const = 0;

    /**
     * @brief Invalidates the cache to update it from memory.
     *
     * @param handle Indicates the reference to the buffer of the cache, which will be invalidated.
     *
     * @return Returns <b>0</b> if the operation is successful; returns an error code defined in {@link DispErrCode}
     * otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t InvalidateCache(const BufferHandle &handle) const = 0;

    /**
     * @brief Checks whether the given VerifyAllocInfo array is allocatable.
     *
     * @param infos Indicates the VerifyAllocInfo array.
     * @param supporteds Indicates whether the array is allocatable.
     *
     * @return Returns <b>0</b> if the operation is successful; returns an error code defined in {@link DispErrCode}
     * otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual int32_t IsSupportedAlloc(const std::vector<VerifyAllocInfo> &infos,
                                     std::vector<bool> &supporteds) const = 0;
};
} // namespace V1_0
} // namespace Display
} // namespace HDI
} // namespace OHOS

#endif // HDI_IDISPLAY_GRALLOC_V1_0_H
