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

#ifndef OHOS_HDI_CODEC_V1_0_CODECJPEGSERVICE_H
#define OHOS_HDI_CODEC_V1_0_CODECJPEGSERVICE_H

#include <map>
#include <mutex>
#include "buffer_handle.h"
#include "codec_jpeg_core.h"
#include "codec_image_config.h"

namespace OHOS {
namespace HDI {
namespace Codec {
namespace Image {
namespace V1_0 {
class CodecJpegService {
public:
    explicit CodecJpegService();

    ~CodecJpegService() = default;

    int32_t JpegInit();

    int32_t JpegDeInit();

    int32_t DoJpegDecode(const CodecImageBuffer& inBuffer, const CodecImageBuffer& outBuffer,
        const CodecJpegDecInfo& decInfo);

    int32_t AllocateJpegInBuffer(CodecImageBuffer& inBuffer, uint32_t size);

    int32_t FreeJpegInBuffer(const CodecImageBuffer& buffer);

private:
    uint32_t GetNextBufferId();

private:
    uint32_t bufferId_;
    std::mutex mutex_;
    std::mutex initMutex_;
    std::unique_ptr<CodecJpegCore> core_;
};
} // V1_0
} // Image
} // Codec
} // HDI
} // OHOS

#endif // OHOS_HDI_CODEC_V1_0_CODECJPEGSERVICE_H
