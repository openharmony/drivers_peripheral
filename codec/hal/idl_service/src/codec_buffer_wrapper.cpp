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
#include "codec_buffer_wrapper.h"
#include <unistd.h>

namespace OHOS::Codec::Omx {

OmxCodecBuffer Convert(const CodecHDI::OmxCodecBuffer& src, bool isIpcMode)
{
    return OmxCodecBuffer {
        .bufferId = src.bufferId,
        .bufferType = src.bufferType,
        .bufferhandle = ReWrap(src.bufferhandle, isIpcMode),
        .fd = UniqueFd::Create(src.fd, isIpcMode),
        .allocLen = src.allocLen,
        .filledLen = src.filledLen,
        .offset = src.offset,
        .fenceFd = UniqueFd::Create(src.fenceFd, isIpcMode),
        .type = src.type,
        .pts = src.pts,
        .flag = src.flag,
        .alongParam = std::move(src.alongParam),
    };
}

CodecHDI::OmxCodecBuffer Convert(const OmxCodecBuffer& src, bool isIpcMode)
{
    return CodecHDI::OmxCodecBuffer {
        .bufferId = src.bufferId,
        .bufferType = src.bufferType,
        .bufferhandle = src.bufferhandle,
        .fd = src.fd ? (isIpcMode ? src.fd->Get() : dup(src.fd->Get())) : -1,
        .allocLen = src.allocLen,
        .filledLen = src.filledLen,
        .offset = src.offset,
        .fenceFd = src.fenceFd ? (isIpcMode ? src.fenceFd->Get() : dup(src.fenceFd->Get())) : -1,
        .type = src.type,
        .pts = src.pts,
        .flag = src.flag,
        .alongParam = std::move(src.alongParam),
    };
}
}