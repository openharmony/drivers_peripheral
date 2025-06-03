/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef JPEGDECODER_H
#define JPEGDECODER_H

#include <fstream>
#include <mutex>
#include <map>
#include "codec_jpeg_helper.h"
#include "command_parse.h"
#include "v1_0/display_composer_type.h"
#include "v1_0/display_buffer_type.h"
#include "v1_0/include/idisplay_buffer.h"
#include "v2_1/icodec_image.h"

class JpegDecoder {
public:
    JpegDecoder();

    ~JpegDecoder();

    int32_t OnEvent(int32_t error);

    int32_t Init();

    int32_t DeInit();

    int32_t PrepareData(std::string fileInput, std::string fileOutput);

    int32_t AllocBuffer(uint32_t width, uint32_t height);

    int32_t Decode(CommandOpt opt);

private:
    uint32_t inline AlignUp(uint32_t width)
    {
        return (((width) + alignment_ - 1) & (~(alignment_ - 1)));
    }

private:
    OHOS::sptr<OHOS::HDI::Codec::Image::V2_1::ICodecImage> hdiJpeg_;
    OHOS::HDI::Display::Buffer::V1_0::IDisplayBuffer *hdiBuffer_;
    OHOS::HDI::Codec::Image::V2_1::CodecJpegHelper *helper_ = nullptr;
    OHOS::HDI::Codec::Image::V2_1::CodecImageBuffer inBuffer_;
    OHOS::HDI::Codec::Image::V2_1::CodecImageBuffer outBuffer_;
    std::unique_ptr<char[]> jpegBuffer_;
    std::ifstream ioIn_;
    std::ofstream ioOut_;
    uint32_t dataStart_;
    uint32_t bufferLen_;
    uint32_t compDataLen_;
    OHOS::HDI::Codec::Image::V2_1::CodecJpegDecInfo decInfo_;
    std::unique_ptr<int8_t[]> compressBuffer_;
    uint32_t alignment_ = 16;
};
#endif // JPEGDECODER_H
