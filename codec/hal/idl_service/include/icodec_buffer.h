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

#ifndef I_CODEC_BUFFER_H
#define I_CODEC_BUFFER_H
#include <OMX_Component.h>
#include <OMX_Core.h>
#include <OMX_Types.h>
#include <buffer_handle.h>
#include <buffer_handle_utils.h>
#include <memory>
#include <refbase.h>
#include "codec_omx_ext.h"
#include "v3_0/codec_types.h"
#include "codec_buffer_wrapper.h"

constexpr uint32_t TIME_WAIT_MS = 10;
namespace OHOS {
namespace Codec {
namespace Omx {
struct DynamicBuffer {
    int32_t type = 0;
    BufferHandle *bufferHandle = nullptr;
};

class ICodecBuffer : public RefBase {
public:
    ICodecBuffer(struct OmxCodecBuffer &codecBuffer);
    virtual ~ICodecBuffer();
    sptr<ICodecBuffer> static CreateCodeBuffer(struct OmxCodecBuffer &codecBuffer);
    sptr<ICodecBuffer> static AllocateCodecBuffer(struct OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE &omxBuffer);
    virtual int32_t FillOmxBuffer(struct OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE &omxBuffer);
    virtual int32_t EmptyOmxBuffer(struct OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE &omxBuffer);
    virtual int32_t FreeBuffer(struct OmxCodecBuffer &codecBuffer);
    virtual int32_t EmptyOmxBufferDone(OMX_BUFFERHEADERTYPE &omxBuffer);
    virtual int32_t FillOmxBufferDone(OMX_BUFFERHEADERTYPE &omxBuffer);
    virtual uint8_t *GetBuffer();
    struct OmxCodecBuffer &GetCodecBuffer();
    void SetBufferId(int32_t bufferId);

protected:
    ICodecBuffer()
    {}
    virtual bool CheckInvalid(struct OmxCodecBuffer &codecBuffer);
    int32_t SyncWait(int fd, uint32_t timeout);
protected:
    struct OmxCodecBuffer codecBuffer_;
};
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS
#endif