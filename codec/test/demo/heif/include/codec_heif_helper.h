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

#ifndef OHOS_HDI_CODEC_IMAGE_V2_1_CODEC_HEIF_HELPER
#define OHOS_HDI_CODEC_IMAGE_V2_1_CODEC_HEIF_HELPER

#include <vector>
#include "command_parser.h"
#include "buffer_helper.h"

namespace OHOS::VDI::HEIF {
class HeifEncoderHelper {
public:
    explicit HeifEncoderHelper(const CommandOpt& opt) : encodeOpt_(opt) {}
    ~HeifEncoderHelper() = default;
    void DoEncode();
private:
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
private:
    void Reset();
    bool AssembleParamForTmap();
    bool AssembleParamForPrimaryImg();
    bool AssembleParamForOtherImg(uint32_t primaryImgId);
    bool AssembleParamForMetaData(uint32_t primaryImgId);
    uint32_t GetNextId() { return id_++; }
    bool FillImageItem(ImgType type, OHOS::HDI::Codec::Image::V2_1::ImageItem& item);
    bool FillMetaItem(const std::string& metaFile, MetaType type, OHOS::HDI::Codec::Image::V2_1::MetaItem& item);
    static bool AddPropOnlyForTmap(ByteWriter& bw);
    bool AddPropMirrorAndRotate(ByteWriter& bw);
    bool CreateImgParam(ImgType type, std::vector<uint8_t>& props);
    bool AllocOutputBuffer(OHOS::HDI::Codec::Image::V2_1::SharedBuffer& output);
private:
    CommandOpt encodeOpt_;
    std::vector<OHOS::HDI::Codec::Image::V2_1::ImageItem> inputImgs_;
    std::vector<OHOS::HDI::Codec::Image::V2_1::MetaItem> inputMetas_;
    std::vector<OHOS::HDI::Codec::Image::V2_1::ItemRef> refs_;
    uint32_t id_ = 0;
    BufferHelper bufferHelper_;
};
} // OHOS::VDI::HEIF
#endif // OHOS_HDI_CODEC_IMAGE_V2_1_CODEC_HEIF_HELPER