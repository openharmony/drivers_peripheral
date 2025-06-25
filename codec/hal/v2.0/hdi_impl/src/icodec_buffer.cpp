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
#include "icodec_buffer.h"
#include <hdf_base.h>
#include <poll.h>
#include <securec.h>
#include "codec_dyna_buffer.h"
#include "codec_handle_buffer.h"
#include "codec_share_buffer.h"
#include "codec_log_wrapper.h"

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
    sptr<ICodecBuffer> buffer = sptr<ICodecBuffer>();
    switch (codecBuffer.bufferType) {
        case CODEC_BUFFER_TYPE_AVSHARE_MEM_FD:
            buffer = CodecShareBuffer::Create(codecBuffer);
            break;
        case CODEC_BUFFER_TYPE_HANDLE:
            buffer = CodecHandleBuffer::Create(codecBuffer);
            break;
        case CODEC_BUFFER_TYPE_DYNAMIC_HANDLE:
            buffer = CodecDynaBuffer::Create(codecBuffer);
            break;
        default:
            CODEC_LOGE("bufferType[%{public}d] is unexpected", codecBuffer.bufferType);
            break;
    }
    return buffer;
}

sptr<ICodecBuffer> ICodecBuffer::AllocateCodecBuffer(struct OmxCodecBuffer &codecBuffer)
{
    sptr<ICodecBuffer> buffer = sptr<ICodecBuffer>();
    if (codecBuffer.bufferType == CODEC_BUFFER_TYPE_AVSHARE_MEM_FD) {
        buffer = CodecShareBuffer::Allocate(codecBuffer);
    } else {
        CODEC_LOGE("bufferType[%{public}d] is unexpected", codecBuffer.bufferType);
    }
    return buffer;
}

struct OmxCodecBuffer &ICodecBuffer::GetCodecBuffer()
{
    return codecBuffer_;
}

void ICodecBuffer::SetBufferId(int32_t bufferId)
{
    codecBuffer_.bufferId = static_cast<uint32_t>(bufferId);
}

bool ICodecBuffer::CheckInvalid(struct OmxCodecBuffer &codecBuffer)
{
    if (codecBuffer_.type != codecBuffer.type) {
        CODEC_LOGE("input buffer type [%{public}d], but expect type [%{public}d]", codecBuffer.bufferType,
            codecBuffer_.bufferType);
        return false;
    }
    return true;
}

int32_t ICodecBuffer::SyncWait(int fd, uint32_t timeout)
{
    int retCode = -EPERM;
    if (fd < 0) {
        CODEC_LOGE("The fence id is invalid.");
        return retCode;
    }

    struct pollfd pollfds = {0};
    pollfds.fd = fd;
    pollfds.events = POLLIN;

    do {
        retCode = poll(&pollfds, 1, timeout);
    } while (retCode == -EPERM && (errno == EINTR || errno == EAGAIN));

    if (retCode == 0) {
        retCode = -EPERM;
        errno = ETIME;
    } else if (retCode > 0) {
        if (static_cast<uint32_t>(pollfds.revents) & (POLLERR | POLLNVAL)) {
            retCode = -EPERM;
            errno = EINVAL;
        }
    }
    return retCode < 0 ? -errno : EOK;
}

int32_t ICodecBuffer::FillOmxBuffer(struct OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE &omxBuffer)
{
    omxBuffer.nOffset = codecBuffer.offset;
    omxBuffer.nFilledLen = codecBuffer.filledLen;
    omxBuffer.nFlags = codecBuffer.flag;
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