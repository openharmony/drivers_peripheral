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

#ifndef OHOS_HDI_CODEC_V2_1_CODECHEIFDECODESERVICE_H
#define OHOS_HDI_CODEC_V2_1_CODECHEIFDECODESERVICE_H

#include <mutex>
#include "codec_heif_decode_vdi.h"
#include "v2_1/icodec_image.h"

namespace OHOS {
namespace HDI {
namespace Codec {
namespace Image {
namespace V2_1 {
class CodecHeifDecodeService {
public:
    CodecHeifDecodeService();
    virtual ~CodecHeifDecodeService();
    int32_t DoHeifDecode(const std::vector<sptr<Ashmem>>& inputs, const sptr<NativeBuffer>& output,
                         const CodecHeifDecInfo& decInfo);
private:
    bool LoadVendorLib();
private:
    std::mutex mutex_;
    std::shared_ptr<void> libHeif_ = nullptr;
    ICodecHeifDecodeHwi* heifDecodeHwi_ = nullptr;
    bool isIPCMode_;
};
} // V2_1
} // Image
} // Codec
} // HDI
} // OHOS

#endif // OHOS_HDI_CODEC_V2_1_CODECHEIFDECODESERVICE_H
