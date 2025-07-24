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
#include "v4_0/codec_types.h"
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
    virtual ~ICodecBuffer();
    static sptr<ICodecBuffer> UseBuffer(OMX_HANDLETYPE comp, uint32_t portIndex,
        OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE *&header, bool doCopy);
    static sptr<ICodecBuffer> AllocateBuffer(OMX_HANDLETYPE comp, uint32_t portIndex,
        OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE *&header);
    virtual int32_t EmptyThisBuffer(OmxCodecBuffer &codecBuffer);
    virtual int32_t FillThisBuffer(OmxCodecBuffer &codecBuffer);
    int32_t EmptyBufferDone(OMX_BUFFERHEADERTYPE &omxBuffer, OmxCodecBuffer& codecBuffer);
    virtual int32_t FillBufferDone(OMX_BUFFERHEADERTYPE &omxBuffer, OmxCodecBuffer& codecBuffer);
    void FreeBuffer();

protected:
    struct InitInfo {
        OMX_HANDLETYPE comp;
        uint32_t portIndex;
        OmxCodecBuffer codecBuf;
        OMX_BUFFERHEADERTYPE* omxHeader;
    };
    ICodecBuffer(const InitInfo& info) : comp_(info.comp), portIndex_(info.portIndex),
        codecBuffer_(info.codecBuf), omxBufHeader_(info.omxHeader) {}
    int32_t SyncWait(int fd, uint32_t timeout);
protected:
    OMX_HANDLETYPE comp_ = nullptr;
    uint32_t portIndex_;
    struct OmxCodecBuffer codecBuffer_;
    OMX_BUFFERHEADERTYPE *omxBufHeader_ = nullptr;
};
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS
#endif