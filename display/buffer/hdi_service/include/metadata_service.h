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

#ifndef OHOS_HDI_DISPLAY_BUFFER_V1_1_METADATASERVICE_H
#define OHOS_HDI_DISPLAY_BUFFER_V1_1_METADATASERVICE_H

#include "v1_1/imetadata.h"
#include "idisplay_buffer_vdi.h"
#include <mutex>
namespace OHOS {
namespace HDI {
namespace Display {
namespace Buffer {
namespace V1_1 {
using OHOS::HDI::Display::Buffer::V1_0::IDisplayBufferVdi;
using OHOS::HDI::Display::Buffer::V1_0::CreateDisplayBufferVdiFunc;
using OHOS::HDI::Display::Buffer::V1_0::DestroyDisplayBufferVdiFunc;
class MetadataService : public OHOS::HDI::Display::Buffer::V1_1::IMetadata {
public:
    MetadataService();
    virtual ~MetadataService();

    int32_t RegisterBuffer(const sptr<NativeBuffer>& handle) override;

    int32_t SetMetadata(const sptr<NativeBuffer>& handle, uint32_t key, const std::vector<uint8_t>& value) override;

    int32_t GetMetadata(const sptr<NativeBuffer>& handle, uint32_t key, std::vector<uint8_t>& value) override;

    int32_t ListMetadataKeys(const sptr<NativeBuffer>& handle, std::vector<uint32_t>& keys) override;

    int32_t EraseMetadataKey(const sptr<NativeBuffer>& handle, uint32_t key) override;
private:
    int32_t LoadVdi();
    std::mutex mutex_;
    void* libHandle_;
    IDisplayBufferVdi* vdiImpl_;
    CreateDisplayBufferVdiFunc createVdi_;
    DestroyDisplayBufferVdiFunc destroyVdi_;
};
} // V1_1
} // Buffer
} // Display
} // HDI
} // OHOS

#endif // OHOS_HDI_DISPLAY_BUFFER_V1_1_METADATASERVICE_H