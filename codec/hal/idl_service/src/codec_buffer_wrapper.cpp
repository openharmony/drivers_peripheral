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