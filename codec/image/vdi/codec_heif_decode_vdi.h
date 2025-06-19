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

#ifndef CODEC_HEIF_DECODE_VDI_H
#define CODEC_HEIF_DECODE_VDI_H

#include <vector>
#include "ashmem.h"
#include "native_buffer.h"
#include "v2_1/codec_image_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CODEC_HEIF_DECODE_VDI_LIB_NAME "libheifdecode_vdi_impl.z.so"

struct ICodecHeifDecodeHwi {
    int32_t (*DoHeifDecode)(const std::vector<OHOS::sptr<OHOS::Ashmem>>& inputs,
                            const OHOS::sptr<OHOS::HDI::Base::NativeBuffer>& output,
                            const OHOS::HDI::Codec::Image::V2_1::CodecHeifDecInfo& decInfo);
};

struct ICodecHeifDecodeHwi *GetCodecHeifDecodeHwi(void);

#ifdef __cplusplus
}
#endif
#endif /* CODEC_HEIF_DECODE_VDI_H */
