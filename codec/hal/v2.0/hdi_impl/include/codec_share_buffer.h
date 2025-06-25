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
class CodecShareBuffer : ICodecBuffer {
public:
    ~CodecShareBuffer() override;
    static OHOS::sptr<ICodecBuffer> Create(struct OmxCodecBuffer &codecBuffer);
    static OHOS::sptr<ICodecBuffer> Allocate(struct OmxCodecBuffer &codecBuffer);
    int32_t FillOmxBuffer(struct OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE &omxBuffer) override;
    int32_t EmptyOmxBuffer(struct OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE &omxBuffer) override;
    int32_t FreeBuffer(struct OmxCodecBuffer &codecBuffer) override;
    int32_t EmptyOmxBufferDone(OMX_BUFFERHEADERTYPE &omxBuffer) override;
    int32_t FillOmxBufferDone(OMX_BUFFERHEADERTYPE &omxBuffer) override;
    void SetAshMem(std::shared_ptr<OHOS::Ashmem> shMem);
    uint8_t *GetBuffer() override;

protected:
    explicit CodecShareBuffer(struct OmxCodecBuffer &codecBuffer);
    bool CheckInvalid(struct OmxCodecBuffer &codecBuffer) override;

private:
    void ReleaseFd(struct OmxCodecBuffer &codecBuffer);

private:
    std::shared_ptr<OHOS::Ashmem> shMem_;
};
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS
#endif