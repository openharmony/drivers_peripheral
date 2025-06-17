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
#include "v2_1/codec_image_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CODEC_HEIF_VDI_LIB_NAME "libheif_vdi_impl.z.so"

struct ICodecHeifHwi {
    int32_t (*DoHeifEncode)(const std::vector<OHOS::HDI::Codec::Image::V2_1::ImageItem>& inputImgs,
                            const std::vector<OHOS::HDI::Codec::Image::V2_1::MetaItem>& inputMetas,
                            const std::vector<OHOS::HDI::Codec::Image::V2_1::ItemRef>& refs,
                            OHOS::HDI::Codec::Image::V2_1::SharedBuffer& output);
};

struct ICodecHeifHwi *GetCodecHeifHwi(void);

#ifdef __cplusplus
}
#endif
#endif /* CODEC_HEIF_VDI_H */
