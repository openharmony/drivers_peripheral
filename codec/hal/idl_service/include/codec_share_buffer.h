/*
 * Copyright (c) 2022 Shenzhen Kaihong DID Co., Ltd..
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CODEC_SHARE_BUFFER_H
#define CODEC_SHARE_BUFFER_H
#include <ashmem.h>
#include <memory>
#include "icodec_buffer.h"

namespace OHOS {
namespace Codec {
namespace Omx {
class CodecShareBuffer : public ICodecBuffer {
public:
    ~CodecShareBuffer() = default;
    static sptr<ICodecBuffer> UseBuffer(OMX_HANDLETYPE comp, uint32_t portIndex,
        OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE *&header, bool doCopy);
    static sptr<ICodecBuffer> AllocateBuffer(OMX_HANDLETYPE comp, uint32_t portIndex,
        OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE *&header);
    int32_t EmptyThisBuffer(OmxCodecBuffer &codecBuffer) override;
    int32_t FillBufferDone(OMX_BUFFERHEADERTYPE &omxBuffer, OmxCodecBuffer& codecBuffer) override;

protected:
    CodecShareBuffer(const InitInfo& info, sptr<Ashmem> shMem, bool doCopy)
        : ICodecBuffer(info), shMem_(shMem), doCopy_(doCopy) {}

private:
    sptr<Ashmem> shMem_;
    bool doCopy_ = false;
};
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS
#endif