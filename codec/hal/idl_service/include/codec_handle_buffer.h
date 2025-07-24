/*
 * Copyright (c) 2022-2023 Shenzhen Kaihong DID Co., Ltd..
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

#ifndef CODEC_HANDLE_BUFFER_H
#define CODEC_HANDLE_BUFFER_H
#include <buffer_handle.h>
#include "icodec_buffer.h"

namespace OHOS {
namespace Codec {
namespace Omx {
class CodecHandleBuffer : ICodecBuffer {
public:
    ~CodecHandleBuffer() = default;
    static sptr<ICodecBuffer> UseBuffer(OMX_HANDLETYPE comp, uint32_t portIndex,
        OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE *&header);
    int32_t EmptyThisBuffer(OmxCodecBuffer &codecBuffer) override;
    int32_t FillThisBuffer(OmxCodecBuffer &codecBuffer) override;

protected:
    CodecHandleBuffer(const InitInfo& info, sptr<HDI::Base::NativeBuffer> nativebuffer)
        : ICodecBuffer(info), buffer_(nativebuffer) {}

private:
    sptr<HDI::Base::NativeBuffer> buffer_;
};
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS
#endif  // CODEC_HANDLE_BUFFER_H