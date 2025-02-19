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

#ifndef OHOS_HDI_CODEC_V2_0_CODECHEIFENCODESERVICE_H
#define OHOS_HDI_CODEC_V2_0_CODECHEIFENCODESERVICE_H

#include <mutex>
#include "codec_heif_vdi.h"
#include "v2_0/icodec_image.h"

namespace OHOS {
namespace HDI {
namespace Codec {
namespace Image {
namespace V2_0 {
class CodecHeifEncodeService {
public:
    CodecHeifEncodeService();
    virtual ~CodecHeifEncodeService();
    int32_t DoHeifEncode(const std::vector<ImageItem>& inputImgs, const std::vector<MetaItem>& inputMetas,
                         const std::vector<ItemRef>& refs, const SharedBuffer& output, uint32_t& filledLen);
private:
    bool LoadVendorLib();
    bool ReWrapNativeBufferInImageItem(const std::vector<ImageItem>& inputImgs);
private:
    std::mutex mutex_;
    std::shared_ptr<void> libHeif_ = nullptr;
    ICodecHeifHwi* heifHwi_ = nullptr;
    bool isIPCMode_;
};
} // V2_0
} // Image
} // Codec
} // HDI
} // OHOS

#endif // OHOS_HDI_CODEC_V2_0_CODECHEIFENCODESERVICE_H
