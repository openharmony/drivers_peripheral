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

#ifndef OHOS_HDI_DISPLAY_BUFFER_V1_0_MAPPERINTERFACESERVICE_H
#define OHOS_HDI_DISPLAY_BUFFER_V1_0_MAPPERINTERFACESERVICE_H

#include "buffer_handle_parcelable.h"
#include "idisplay_buffer_hwi.h"
#include "v1_0/display_buffer_type.h"
#include "v1_0/imapper_interface.h"

namespace OHOS {
namespace HDI {
namespace Display {
namespace Buffer {
namespace V1_0 {
class MapperInterfaceService : public IMapperInterface {
public:
    MapperInterfaceService();
    virtual ~MapperInterfaceService();

    int32_t FreeMem(const sptr<BufferHandleParcelable> &handle) override;
    int32_t Mmap(const sptr<BufferHandleParcelable> &handle) override;
    int32_t MmapCache(const sptr<BufferHandleParcelable> &buffer) override;
    int32_t Unmap(const sptr<BufferHandleParcelable> &handle) override;
    int32_t FlushCache(const sptr<BufferHandleParcelable> &handle) override;
    int32_t FlushMCache(const sptr<BufferHandleParcelable> &buffer) override;
    int32_t InvalidateCache(const sptr<BufferHandleParcelable> &handle) override;

private:
    int32_t LoadHwi();

private:
    void *libHandle_;
    IDisplayBufferHwi *hwiImpl_;

    Create_DisplayBufferHwiFunc_t *createHwi_;
    Destroy_DisplayBufferHwiFunc_t *destroyHwi_;
};
} // namespace V1_0
} // namespace Buffer
} // namespace Display
} // namespace HDI
} // namespace OHOS

#endif // OHOS_HDI_DISPLAY_BUFFER_V1_0_MAPPERINTERFACESERVICE_H
