/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_HDI_CODEC_V2_1_BUFFERHANDLEREGISTRATIONMGR_H
#define OHOS_HDI_CODEC_V2_1_BUFFERHANDLEREGISTRATIONMGR_H

#include "v1_0/display_composer_type.h"
#include "v1_0/imapper.h"
#include "v1_1/imetadata.h"
#include "native_buffer.h"
#include <mutex>

namespace OHOS {
namespace HDI {
namespace Codec {
namespace Image {
namespace V2_1 {
class BufferHandleRegistrationMgr {
public:
    ~BufferHandleRegistrationMgr() = default;

    static bool ReWrapNativeBuffer(sptr<OHOS::HDI::Base::NativeBuffer>& buffer);
private:
    BufferHandleRegistrationMgr() = default;
    static sptr<OHOS::HDI::Display::Buffer::V1_0::IMapper> GetMapperService();
    static sptr<OHOS::HDI::Display::Buffer::V1_1::IMetadata> GetMetaService();
    static void BufferDestructor(BufferHandle* handle);
private:
    static std::mutex g_mapperMtx;
    static std::mutex g_metaMtx;
    static sptr<OHOS::HDI::Display::Buffer::V1_0::IMapper> g_mapperService;
    static sptr<OHOS::HDI::Display::Buffer::V1_1::IMetadata> g_metaService;
};
} // V2_1
} // Image
} // Codec
} // HDI
} // OHOS

#endif // OHOS_HDI_CODEC_V2_1_BUFFERHANDLEREGISTRATIONMGR_H
