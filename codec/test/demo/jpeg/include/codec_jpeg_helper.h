/*
 * Copyright (c) 2023 Shenzhen Kaihong DID Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_HDI_CODEC_IMAGE_V2_0_CODECJPEGHELPER_H
#define OHOS_HDI_CODEC_IMAGE_V2_0_CODECJPEGHELPER_H
#include <cinttypes>
#include "v2_0/icodec_image.h"
#include <memory>
namespace OHOS {
namespace HDI {
namespace Codec {
namespace Image {
namespace V2_0 {
class CodecJpegHelper {
public:
    enum JpegMarker : int16_t {
        SOF0 = 0xffc0,
        DHT = 0xffc4,
        SOI = 0xffd8,
        EOI = 0xffd9,
        SOS = 0xffda,
        DQT = 0xffdb,
        DRI = 0xffdd,
        UNKNOWN = 0xffff
    };
    explicit CodecJpegHelper() = default;
    ~CodecJpegHelper() = default;
    int32_t JpegAssemble(const struct CodecJpegDecInfo &decInfo, int8_t *buffer, int32_t fd);
    bool DessambleJpeg(int8_t *buffer, size_t bufferLen, struct CodecJpegDecInfo &decInfo,
                       std::unique_ptr<int8_t[]> &compressBuffer, uint32_t &comBufLen, uint32_t &dataStart);

private:
    int32_t FindMarker(int8_t *start);
    int32_t JpegDqtAssemble(const struct CodecJpegDecInfo &decInfo, int8_t *buffer, int32_t curPos);
    int32_t JpegDriAssemble(const struct CodecJpegDecInfo &decInfo, int8_t *buffer, int32_t curPos);
    int32_t JpegDhtAssemble(const struct CodecJpegDecInfo &decInfo, int8_t *buffer, int32_t curPos);
    int32_t JpegDhtAssemble(const std::vector<CodecJpegHuffTable> &table, int8_t *buffer, int32_t curPos,
                            bool dc = true);
    int32_t JpegSofAssemble(const struct CodecJpegDecInfo &decInfo, int8_t *buffer, int32_t curPos);
    int32_t JpegSosAssemble(const struct CodecJpegDecInfo &decInfo, int8_t *buffer, int32_t curPos);
    int32_t JpegDataAssemble(int8_t *buffer, int32_t curPos, int32_t fd);
    int32_t DessambleSof(int8_t *buffer, struct CodecJpegDecInfo &decInfo);
    int32_t DessambleSos(int8_t *buffer, struct CodecJpegDecInfo &decInfo);
    int32_t DessambleCompressData(int8_t *buffer, std::unique_ptr<int8_t[]> &compressBuffer, uint32_t &comBufLen);
    int32_t DessambleDqt(int8_t *buffer, struct CodecJpegDecInfo &decInfo);
    int32_t DessambleDht(int8_t *buffer, struct CodecJpegDecInfo &decInfo);
    int32_t PutInt16(int8_t *buffer, int32_t curPos, int16_t value);
    int32_t PutInt8(int8_t *buffer, int32_t curPos, int8_t value);
    int32_t GetInt8(int8_t *buffer);
    int32_t GetInt16(int8_t *buffer);
private:
    static constexpr int32_t MAX_BUFFER_LEN = 128;
};
}
}
}
}
}
#endif // OHOS_HDI_CODEC_IMAGE_V2_0_CODECJPEGHELPER_H
