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

#ifndef OHOS_HDI_DISPLAY_V1_0_IDISPLAY_BUFFER_VDI_H
#define OHOS_HDI_DISPLAY_V1_0_IDISPLAY_BUFFER_VDI_H

#include <vector>
#include "buffer_handle.h"
#include "v1_2/display_buffer_type.h"

namespace OHOS {
namespace HDI {
namespace Display {
namespace Buffer {
namespace V1_0 {

#ifdef BUFFER_VDI_DEFAULT_LIBRARY_ENABLE
#define DISPLAY_BUFFER_VDI_DEFAULT_LIBRARY "libdisplay_buffer_vdi_impl_default.z.so"
#endif // BUFFER_VDI_DEFAULT_LIBRARY_ENABLE
#define DISPLAY_BUFFER_VDI_LIBRARY "libdisplay_buffer_vdi_impl.z.so"
#define NOT_SUPPORT (-2)

class IDisplayBufferVdi {
public:
    virtual ~IDisplayBufferVdi() = default;

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
    virtual int32_t AllocMem(const AllocInfo& info, BufferHandle*& handle) const = 0;

    /**
     * @brief Releases memory.
     *
     * @param handle Indicates the reference to the buffer of the memory to release.
     *
     * @since 1.0
     * @version 1.0
     */
    virtual void FreeMem(const BufferHandle& handle) const = 0;

    /**
     * @brief Maps memory to memory without cache in the process's address space.
     *
     * @param handle Indicates the reference to the buffer of the memory to map.
     *
     * @return Returns the pointer to a valid address if the operation is successful; returns <b>NULL</b> otherwise.
     * @since 1.0
     * @version 1.0
     */
    virtual void *Mmap(const BufferHandle& handle) const = 0;

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
    virtual int32_t Unmap(const BufferHandle& handle) const = 0;

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
    virtual int32_t FlushCache(const BufferHandle& handle) const = 0;

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
    virtual int32_t InvalidateCache(const BufferHandle& handle) const = 0;

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
    virtual int32_t IsSupportedAlloc(
        const std::vector<VerifyAllocInfo>& infos, std::vector<bool>& supporteds) const = 0;

    virtual int32_t RegisterBuffer(const BufferHandle& handle)
    {
        return 0;
    }

    virtual int32_t SetMetadata(const BufferHandle& handle, uint32_t key, const std::vector<uint8_t>& value)
    {
        return 0;
    }

    virtual int32_t GetMetadata(const BufferHandle& handle, uint32_t key, std::vector<uint8_t>& value)
    {
        return 0;
    }

    virtual int32_t ListMetadataKeys(const BufferHandle& handle, std::vector<uint32_t>& keys)
    {
        return 0;
    }

    virtual int32_t EraseMetadataKey(const BufferHandle& handle, uint32_t key)
    {
        return 0;
    }

    virtual int32_t GetImageLayout(const BufferHandle& handle, V1_2::ImageLayout& layout) const
    {
        return 0;
    }

    virtual int32_t IsSupportAllocPassthrough(const AllocInfo& info) const
    {
        return NOT_SUPPORT;
    }
};

using CreateDisplayBufferVdiFunc = IDisplayBufferVdi* (*)();
using DestroyDisplayBufferVdiFunc = void (*)(IDisplayBufferVdi* vdi);
extern "C" IDisplayBufferVdi* CreateDisplayBufferVdi();
extern "C" void DestroyDisplayBufferVdi(IDisplayBufferVdi* vdi);
} // namespace V1_0
} // namespace Buffer
} // namespace Display
} // namespace HDI
} // namespace OHOS

#endif // OHOS_HDI_DISPLAY_V1_0_IDISPLAY_BUFFER_VDI_H
