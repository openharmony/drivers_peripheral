/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef CODEC_BUFFER_WRAPPER_H
#define CODEC_BUFFER_WRAPPER_H

#include "v3_0/codec_types.h"
#include "buffer_helper.h"

namespace OHOS::Codec::Omx {
namespace CodecHDI = OHOS::HDI::Codec::V3_0;

struct OmxCodecBuffer {
    uint32_t bufferId;
    uint32_t bufferType;
    sptr<NativeBuffer> bufferhandle;
    std::shared_ptr<UniqueFd> fd;
    uint32_t allocLen;
    uint32_t filledLen;
    uint32_t offset;
    std::shared_ptr<UniqueFd> fenceFd;
    CodecHDI::ShareMemTypes type;
    int64_t pts;
    uint32_t flag;
    std::vector<uint8_t> alongParam;
};

OmxCodecBuffer Convert(const CodecHDI::OmxCodecBuffer& src, bool isIpcMode);
CodecHDI::OmxCodecBuffer Convert(const OmxCodecBuffer& src, bool isIpcMode);

}
#endif