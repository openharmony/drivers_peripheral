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

#ifndef OHOS_HDI_CODEC_V2_1_CODECJPEGCORE_H
#define OHOS_HDI_CODEC_V2_1_CODECJPEGCORE_H

#include "codec_jpeg_vdi.h"
#include "v2_1/icodec_image.h"

namespace OHOS {
namespace HDI {
namespace Codec {
namespace Image {
class CodecJpegCore {
public:
    using GetCodecJpegHwi = ICodecJpegHwi*(*)();

    explicit CodecJpegCore() = default;

    ~CodecJpegCore();

    void NotifyPowerOn();

    int32_t JpegInit();

    int32_t JpegDeInit();

    int32_t AllocateInBuffer(BufferHandle **buffer, uint32_t size);

    int32_t FreeInBuffer(BufferHandle *buffer);

    int32_t DoDecode(BufferHandle *buffer, BufferHandle *outBuffer, const V2_1::CodecJpegDecInfo *decInfo);

private:
    void AddVendorLib();

private:
    void *libHandle_ = nullptr;
    GetCodecJpegHwi getCodecJpegHwi_ = nullptr;
    ICodecJpegHwi *JpegHwi_ = nullptr;
};
} // Image
} // Codec
} // HDI
} // OHOS

#endif // OHOS_HDI_CODEC_V2_1_CODECJPEGCORE_H
