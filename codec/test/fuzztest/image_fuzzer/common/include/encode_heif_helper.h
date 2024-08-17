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
#ifndef ENCODE_HEIF_HELPER_FUZZ
#define ENCODE_HEIF_HELPER_FUZZ

#include <vector>
#include "encode_buffer_helper.h"

namespace OHOS::VDI::HEIF {
enum ImgType {
    PRIMARY_IMG,
    AUXILIARY_IMG,
    THUMBNAIL_IMG,
    GAIN_MAP,
    T_MAP
};
enum MetaType {
    EXIF_DATA,
    USER_DATA
};
class HeifEncodeHelper {
public:
    HeifEncodeHelper() {};
    ~HeifEncodeHelper() {};
    void Reset();
    bool AssembleParamForTmap(uint8_t *data, size_t size);
    bool AssembleParamForPrimaryImg(uint8_t *data, size_t size);
    bool AssembleParamForOtherImg(uint32_t primaryImgId, uint8_t *data, size_t size);
    bool AssembleParamForMetaData(uint32_t primaryImgId, uint8_t *data, size_t size);
    bool FillImageItem(ImgType type, OHOS::HDI::Codec::Image::V2_0::ImageItem& item, uint8_t *data, size_t size);
    OHOS::HDI::Codec::Image::V2_0::ItemRef FillRefItem(OHOS::HDI::Codec::Image::V2_0::ItemRef item,
                                                       uint8_t *data, size_t size);
    bool FillMetaItem(MetaType type, OHOS::HDI::Codec::Image::V2_0::MetaItem& item, uint8_t *data, size_t size);
    bool AllocOutputBuffer(OHOS::HDI::Codec::Image::V2_0::SharedBuffer& output);
public:
    std::vector<OHOS::HDI::Codec::Image::V2_0::ImageItem> inputImgs_;
    std::vector<OHOS::HDI::Codec::Image::V2_0::MetaItem> inputMetas_;
    std::vector<OHOS::HDI::Codec::Image::V2_0::ItemRef> refs_;
    uint32_t id_ = 0;
    EncodeBufferHelper bufferHelper_;
};
} // OHOS::VDI::HEIF
#endif // ENCODE_HEIF_HELPER_FUZZ