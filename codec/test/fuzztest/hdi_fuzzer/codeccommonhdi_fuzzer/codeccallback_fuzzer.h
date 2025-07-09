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

#ifndef CODECCALLBACK_FUZZER_H
#define CODECCALLBACK_FUZZER_H

#include "v4_0/icodec_callback.h"
#include "v4_0/codec_types.h"

namespace OHOS {
namespace Codec {
class CodecCallbackFuzz : public OHOS::HDI::Codec::V4_0::ICodecCallback {
public:
    CodecCallbackFuzz() = default;
    virtual ~CodecCallbackFuzz() = default;
    int32_t EventHandler(OHOS::HDI::Codec::V4_0::CodecEventType event,
        const OHOS::HDI::Codec::V4_0::EventInfo &info) override;
    int32_t EmptyBufferDone(int64_t appData, const OHOS::HDI::Codec::V4_0::OmxCodecBuffer &buffer) override;
    int32_t FillBufferDone(int64_t appData, const OHOS::HDI::Codec::V4_0::OmxCodecBuffer &buffer) override;
};
} // namespace Codec
} // namespace OHOS
#endif // CODECCALLBACK_FUZZER_H
