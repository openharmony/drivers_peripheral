/*
 * Copyright 2022 Shenzhen Kaihong DID Co., Ltd..
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
#include "icodec_buffer.h"
#include <hdf_base.h>
#include <hdf_log.h>
#include "codec_dyna_buffer.h"
#include "codec_handle_buffer.h"
#include "codec_share_buffer.h"

namespace OHOS {
namespace Codec {
namespace Omx {
ICodecBuffer::ICodecBuffer(struct OmxCodecBuffer &codecBuffer)
{
    codecBuffer_ = codecBuffer;
}
ICodecBuffer::~ICodecBuffer()
{}

sptr<ICodecBuffer> ICodecBuffer::CreateCodeBuffer(struct OmxCodecBuffer &codecBuffer)
{
    sptr<ICodecBuffer> buffer = nullptr;
    switch (codecBuffer.bufferType) {
        case BUFFER_TYPE_AVSHARE_MEM_FD:
            buffer = CodecShareBuffer::Create(codecBuffer);
            break;
        case BUFFER_TYPE_HANDLE:
            buffer = CodecHandleBuffer::Create(codecBuffer);
            break;
        case BUFFER_TYPE_DYNAMIC_HANDLE:
            buffer = CodecDynaBuffer::Create(codecBuffer);
            break;
        default:
            HDF_LOGE("%s: bufferType[%{public}d] is unexpected", __func__, codecBuffer.bufferType);
            break;
    }
    return buffer;
}

sptr<ICodecBuffer> ICodecBuffer::AllocateCodecBuffer(struct OmxCodecBuffer &codecBuffer)
{
    sptr<ICodecBuffer> buffer = nullptr;
    switch (codecBuffer.bufferType) {
        case BUFFER_TYPE_AVSHARE_MEM_FD:
            buffer = CodecShareBuffer::Allocate(codecBuffer);
            break;
        default:
            HDF_LOGE("%s: bufferType[%{public}d] is unexpected", __func__, codecBuffer.bufferType);
            break;
    }
    return buffer;
}

struct OmxCodecBuffer &ICodecBuffer::GetCodecBuffer()
{
    return codecBuffer_;
}

void ICodecBuffer::SetBufferId(int32_t bufferId)
{
    codecBuffer_.bufferId = bufferId;
}

bool ICodecBuffer::CheckInvalid(struct OmxCodecBuffer &codecBuffer)
{
    if (codecBuffer_.type != codecBuffer.type) {
        HDF_LOGE("%{public}s :input buffer type [%{public}d], but expect type [%{public}d]", __func__,
                 codecBuffer.bufferType, codecBuffer_.bufferType);
        return false;
    }
    return true;
}

int32_t ICodecBuffer::FillOmxBuffer(struct OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE &omxBuffer)
{
    omxBuffer.nOffset = codecBuffer.offset;
    omxBuffer.nFilledLen = codecBuffer.filledLen;
    return HDF_SUCCESS;
}

int32_t ICodecBuffer::EmptyOmxBuffer(struct OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE &omxBuffer)
{
    omxBuffer.nOffset = codecBuffer.offset;
    omxBuffer.nFilledLen = codecBuffer.filledLen;
    omxBuffer.nFlags = codecBuffer.flag;
    omxBuffer.nTimeStamp = codecBuffer.pts;
    return HDF_SUCCESS;
}

int32_t ICodecBuffer::EmptyOmxBufferDone(OMX_BUFFERHEADERTYPE &omxBuffer)
{
    codecBuffer_.offset = omxBuffer.nOffset;
    codecBuffer_.filledLen = omxBuffer.nFilledLen;
    return HDF_SUCCESS;
}

int32_t ICodecBuffer::FillOmxBufferDone(OMX_BUFFERHEADERTYPE &omxBuffer)
{
    codecBuffer_.offset = omxBuffer.nOffset;
    codecBuffer_.filledLen = omxBuffer.nFilledLen;
    codecBuffer_.flag = omxBuffer.nFlags;
    codecBuffer_.pts = omxBuffer.nTimeStamp;
    return HDF_SUCCESS;
}
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS