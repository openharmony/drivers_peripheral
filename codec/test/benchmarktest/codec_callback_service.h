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

#ifndef OHOS_HDI_CODEC_V4_0_CODECCALLBACKSERVICE_H
#define OHOS_HDI_CODEC_V4_0_CODECCALLBACKSERVICE_H

#include "v4_0/icodec_callback.h"

namespace OHOS {
namespace HDI {
namespace Codec {
namespace V4_0 {
class CodecCallbackService : public ICodecCallback {
public:
    CodecCallbackService() = default;
    virtual ~CodecCallbackService() = default;
    int32_t EventHandler(CodecEventType event, const EventInfo &info) override;
    int32_t EmptyBufferDone(int64_t appData, const OmxCodecBuffer &buffer) override;
    int32_t FillBufferDone(int64_t appData, const OmxCodecBuffer &buffer) override;
};
} // V4_0
} // Codec
} // HDI
} // OHOS

#endif // OHOS_HDI_CODEC_V4_0_CODECCALLBACKSERVICE_H
