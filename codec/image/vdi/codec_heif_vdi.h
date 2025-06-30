/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef CODEC_HEIF_VDI_H
#define CODEC_HEIF_VDI_H

#include <vector>
#include "native_buffer.h"
#include "ashmem.h"
#include "v2_1/codec_image_type.h"
#include "buffer_helper.h"

namespace OHOS::VDI::HEIF {
namespace ImageHDI = OHOS::HDI::Codec::Image::V2_1;
struct SharedBuffer {
    sptr<Ashmem> ashmem;
    uint32_t filledLen;
};

inline SharedBuffer ConvertSharedBuffer(const ImageHDI::SharedBuffer& src)
{
    return SharedBuffer {
        .ashmem = sptr<Ashmem>::MakeSptr(src.fd, src.capacity),
        .filledLen = src.filledLen,
    };
}

struct ImageItem {
    std::string itemName;
    uint32_t id;
    OHOS::sptr<OHOS::HDI::Base::NativeBuffer> pixelBuffer;
    SharedBuffer pixelSharedBuffer;
    bool isPrimary;
    bool isHidden;
    std::string compressType;
    uint32_t quality;
    std::vector<uint8_t> liteProperties;
    SharedBuffer sharedProperties;
};

inline ImageItem ConvertImageItem(const ImageHDI::ImageItem& src)
{
    return ImageItem {.itemName = src.itemName, .id = src.id,
        .pixelBuffer = OHOS::Codec::Omx::ReWrap(src.pixelBuffer, true),
        .pixelSharedBuffer = ConvertSharedBuffer(src.pixelSharedBuffer),
        .isPrimary = src.isPrimary,
        .isHidden = src.isHidden,
        .compressType = src.compressType,
        .quality = src.quality,
        .liteProperties = src.liteProperties,
        .sharedProperties = ConvertSharedBuffer(src.sharedProperties),
    };
}

struct MetaItem {
    std::string itemName;
    uint32_t id;
    SharedBuffer data;
    std::vector<uint8_t> properties;
};

inline MetaItem ConvertMetaItem(const ImageHDI::MetaItem& src)
{
    return MetaItem {
        .itemName = src.itemName,
        .id = src.id,
        .data = ConvertSharedBuffer(src.data),
        .properties = src.properties,
    };
}

#ifdef __cplusplus
extern "C" {
#endif

#define CODEC_HEIF_VDI_LIB_NAME "libheif_vdi_impl.z.so"

struct ICodecHeifHwi {
    int32_t (*DoHeifEncode)(const std::vector<ImageItem>& inputImgs,
                            const std::vector<MetaItem>& inputMetas,
                            const std::vector<ImageHDI::ItemRef>& refs,
                            SharedBuffer& output);
};

struct ICodecHeifHwi *GetCodecHeifHwi(void);

#ifdef __cplusplus
}
#endif
} // namespace OHOS::VDI::HEIF
#endif /* CODEC_HEIF_VDI_H */
