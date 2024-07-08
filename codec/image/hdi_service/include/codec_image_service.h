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

#ifndef OHOS_HDI_CODEC_V1_0_CODECIMAGESERVICE_H
#define OHOS_HDI_CODEC_V1_0_CODECIMAGESERVICE_H

#include <map>
#include <mutex>
#include "buffer_handle.h"
#include "codec_image_config.h"
#include "v1_0/icodec_image.h"
#include "codec_jpeg_service.h"

constexpr uint32_t CODEC_IMAGE_MAX_BUFFER_SIZE = 50 * 1024 *1024;
namespace OHOS {
namespace HDI {
namespace Codec {
namespace Image {
namespace V1_0 {
class CodecImageService : public ICodecImage {
public:
    explicit CodecImageService();

    virtual ~CodecImageService() = default;

    int32_t GetImageCapability(std::vector<CodecImageCapability>& capList) override;

    int32_t Init(enum CodecImageRole role) override;

    int32_t DeInit(enum CodecImageRole role) override;

    int32_t DoJpegDecode(const CodecImageBuffer& inBuffer, const CodecImageBuffer& outBuffer,
        const CodecJpegDecInfo& decInfo) override;

    int32_t AllocateInBuffer(CodecImageBuffer& inBuffer, uint32_t size, CodecImageRole role) override;

    int32_t FreeInBuffer(const CodecImageBuffer& buffer) override;

private:
    std::unique_ptr<CodecJpegService> jpegImpl_;
};
} // V1_0
} // Image
} // Codec
} // HDI
} // OHOS

#endif // OHOS_HDI_CODEC_V1_0_CODECIMAGESERVICE_H
