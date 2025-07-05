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

#ifndef OHOS_HDI_DISPLAY_BUFFER_V1_0_MAPPER_SERVICE_H
#define OHOS_HDI_DISPLAY_BUFFER_V1_0_MAPPER_SERVICE_H

#include "idisplay_buffer_vdi.h"
#include "v1_2/display_buffer_type.h"
#include "v1_3/imapper.h"
#include <mutex>

namespace OHOS {
namespace HDI {
namespace Display {
namespace Buffer {
namespace V1_0 {
using OHOS::HDI::Display::Buffer::V1_2::IDisplayBufferVdi;
using OHOS::HDI::Display::Buffer::V1_2::CreateDisplayBufferVdiFunc;
using OHOS::HDI::Display::Buffer::V1_2::DestroyDisplayBufferVdiFunc;
class MapperService : public Buffer::V1_3::IMapper {
public:
    MapperService();
    virtual ~MapperService();

    int32_t FreeMem(const sptr<NativeBuffer>& handle) override;
    int32_t Mmap(const sptr<NativeBuffer>& handle) override;
    int32_t Unmap(const sptr<NativeBuffer>& handle) override;
    int32_t FlushCache(const sptr<NativeBuffer>& handle) override;
    int32_t InvalidateCache(const sptr<NativeBuffer>& handle) override;
    int32_t GetImageLayout(const sptr<NativeBuffer>& handle, V1_2::ImageLayout& layout) override;
    int32_t AllocMem(const AllocInfo& info, sptr<NativeBuffer>& handle) override;
    int32_t IsSupportAllocPassthrough(const AllocInfo& info) override;

private:
    int32_t LoadVdi();
    void FreeMemVdi(BufferHandle* handle);
    std::mutex mutex_;
    void* libHandle_;
    IDisplayBufferVdi* vdiImpl_;
    CreateDisplayBufferVdiFunc createVdi_;
    DestroyDisplayBufferVdiFunc destroyVdi_;
};
} // namespace V1_0
} // namespace Buffer
} // namespace Display
} // namespace HDI
} // namespace OHOS

#endif // OHOS_HDI_DISPLAY_BUFFER_V1_0_MAPPER_SERVICE_H
