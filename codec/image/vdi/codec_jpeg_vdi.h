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

#ifndef CODEC_JPEG_VDI_H
#define CODEC_JPEG_VDI_H

#include <vector>
#include "buffer_handle.h"
#ifdef __cplusplus
extern "C" {
#endif

#define CODEC_JPEG_VDI_LIB_NAME "libjpeg_vdi_impl.z.so"

struct ICodecJpegHwi {
    int32_t (*JpegInit)();

    int32_t (*JpegDeInit)();

    int32_t (*AllocateInBuffer)(BufferHandle **buffer, uint32_t size);

    int32_t (*FreeInBuffer)(BufferHandle *buffer);

    int32_t (*DoJpegDecode)(BufferHandle *buffer, BufferHandle *outBuffer, const struct CodecJpegDecInfo *decInfo);
};

struct CodecImageRegion {
    uint32_t left;
    uint32_t right;
    uint32_t top;
    uint32_t bottom;
    uint32_t flag;
    uint32_t rsv;
};

struct CodecJpegQuantTable {
    std::vector<uint16_t> quantVal;
    bool tableFlag;
};

struct CodecJpegHuffTable {
    std::vector<uint8_t> bits;
    std::vector<uint8_t> huffVal;
    bool tableFlag;
};
struct CodecJpegCompInfo {
    uint32_t componentId;
    uint32_t componentIndex;
    uint32_t hSampFactor;
    uint32_t vSampFactor;
    uint32_t quantTableNo;
    uint32_t dcTableNo;
    uint32_t acTableNo;
    bool infoFlag;
};

struct CodecJpegDecInfo {
    uint32_t imageWidth;
    uint32_t imageHeight;
    uint32_t dataPrecision;
    uint32_t numComponents;
    uint32_t restartInterval;
    bool arithCode;
    bool progressiveMode;
    std::vector<CodecJpegCompInfo> compInfo;
    std::vector<CodecJpegHuffTable> dcHuffTbl;
    std::vector<CodecJpegHuffTable> acHuffTbl;
    std::vector<CodecJpegQuantTable> quantTbl;
    struct CodecImageRegion region;
    unsigned int sampleSize;
    unsigned int compressPos;
};

struct ICodecJpegHwi *GetCodecJpegHwi(void);

#ifdef __cplusplus
}
#endif
#endif /* CODEC_JPEG_VDI_H */
