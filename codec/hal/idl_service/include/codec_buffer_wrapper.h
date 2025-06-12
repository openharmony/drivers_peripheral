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