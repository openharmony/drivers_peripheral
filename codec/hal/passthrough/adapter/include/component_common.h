/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#ifndef COMPONENT_COMMON_H
#define COMPONENT_COMMON_H

#include <OMX_Component.h>
#include "codec_capability_parser.h"
#include "codec_component_type.h"
#include "codec_type.h"

const int32_t INPUT_PORTINDEX = 0;
const int32_t OUTPUT_PORTINDEX = 1;

namespace OHOS {
namespace Codec {
namespace Common {
    int32_t SplitParam(int32_t paramIndex, int8_t *paramIn, Param *paramOut, int32_t &paramCnt, CodecType type);
    int32_t ParseParam(int32_t paramIndex, Param *paramIn, int32_t paramCnt, int8_t *paramOut, CodecExInfo info);
    int32_t ConvertOmxBufferTypeToBufferType(int32_t type, BufferType &bufferType);
    void ConvertOmxCodecBufferToCodecBuffer(const OmxCodecBuffer &omxBuffer, CodecBuffer &codecBuffer);
    void ConvertCodecBufferToOmxCodecBuffer(OmxCodecBuffer &omxBuffer, CodecBuffer &codecBuffer);
}  // namespace Common
}  // namespace Codec
}  // namespace OHOS

#endif  // COMPONENT_COMMON_H
