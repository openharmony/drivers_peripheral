/*
 * Copyright 2023 Shenzhen Kaihong DID Co., Ltd.
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

#ifndef CODEC_HDI_BASE_H
#define CODEC_HDI_BASE_H
#include "v4_0/codec_types.h"
class ICodecHdiCallBackBase {
public:
    virtual int32_t EventHandler(OHOS::HDI::Codec::V4_0::CodecEventType event,
        const OHOS::HDI::Codec::V4_0::EventInfo &info) = 0;
    virtual int32_t OnEmptyBufferDone(const OHOS::HDI::Codec::V4_0::OmxCodecBuffer &buffer) = 0;
    virtual int32_t OnFillBufferDone(const OHOS::HDI::Codec::V4_0::OmxCodecBuffer &buffer) = 0;
};
#endif  // CODEC_HDI_BASE_H