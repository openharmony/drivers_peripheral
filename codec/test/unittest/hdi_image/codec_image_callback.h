/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_HDI_CODEC_IMAGE_V1_0_CODECIMAGECALLBACK_H
#define OHOS_HDI_CODEC_IMAGE_V1_0_CODECIMAGECALLBACK_H

#include "v1_0/icodec_image_callback.h"

namespace OHOS {
namespace HDI {
namespace Codec {
namespace Image {
namespace V1_0 {
class CodecImageCallback : public ICodecImageCallback {
public:
    CodecImageCallback() = default;
    virtual ~CodecImageCallback() = default;

    int32_t OnImageEvent(int32_t status) override;
};
} // V1_0
} // Image
} // Codec
} // HDI
} // OHOS
#endif // OHOS_HDI_CODEC_IMAGE_V1_0_CODECIMAGECALLBACK_H
