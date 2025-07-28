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
#include "codec_dma_buffer.h"
#include "codec_log_wrapper.h"
#include "codec_share_buffer.h"
#include "v4_0/codec_types.h"
using namespace OHOS::HDI::Codec::V4_0;
namespace OHOS {
namespace Codec {
namespace Omx {

sptr<ICodecBuffer> ICodecBuffer::UseBuffer(OMX_HANDLETYPE comp, uint32_t portIndex,
    OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE *&header, bool doCopy)
{
    switch (codecBuffer.bufferType) {
        case CODEC_BUFFER_TYPE_AVSHARE_MEM_FD:
            return CodecShareBuffer::UseBuffer(comp, portIndex, codecBuffer, header, doCopy);
        case CODEC_BUFFER_TYPE_HANDLE:
            return CodecHandleBuffer::UseBuffer(comp, portIndex, codecBuffer, header);
        case CODEC_BUFFER_TYPE_DYNAMIC_HANDLE:
            return CodecDynaBuffer::UseBuffer(comp, portIndex, codecBuffer, header);
        case CODEC_BUFFER_TYPE_DMA_MEM_FD:
            return CodecDMABuffer::UseBuffer(comp, portIndex, codecBuffer, header);
        default:
            CODEC_LOGE("bufferType[%{public}d] is unexpected", codecBuffer.bufferType);
            return nullptr;
    }
}

sptr<ICodecBuffer> ICodecBuffer::AllocateBuffer(OMX_HANDLETYPE comp, uint32_t portIndex,
    OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE *&header)
{
    switch (codecBuffer.bufferType) {
        case CODEC_BUFFER_TYPE_AVSHARE_MEM_FD:
            return CodecShareBuffer::AllocateBuffer(comp, portIndex, codecBuffer, header);
        case CODEC_BUFFER_TYPE_DMA_MEM_FD:
            return CodecDMABuffer::AllocateBuffer(comp, portIndex, codecBuffer, header);
        default:
            CODEC_LOGE("bufferType[%{public}d] is unexpected", codecBuffer.bufferType);
            return nullptr;
    }
}

int32_t ICodecBuffer::EmptyThisBuffer(OmxCodecBuffer &codecBuffer)
{
    CHECK_AND_RETURN_RET_LOG(comp_ != nullptr, OMX_ErrorInvalidComponent, "null component");
    CHECK_AND_RETURN_RET_LOG(omxBufHeader_ != nullptr, OMX_ErrorBadParameter, "null header");
    omxBufHeader_->nOffset = codecBuffer.offset;
    omxBufHeader_->nFilledLen = codecBuffer.filledLen;
    omxBufHeader_->nFlags = codecBuffer.flag;
    omxBufHeader_->nTimeStamp = codecBuffer.pts;

    codecBuffer_.alongParam = std::move(codecBuffer.alongParam);
    omxBufHeader_->pAppPrivate = nullptr;
    OMXBufferAppPrivateData privateData{};
    if (codecBuffer_.bufferType == CODEC_BUFFER_TYPE_DYNAMIC_HANDLE && !codecBuffer_.alongParam.empty()) {
        privateData.sizeOfParam = static_cast<uint32_t>(codecBuffer_.alongParam.size());
        privateData.param = static_cast<void *>(codecBuffer_.alongParam.data());
        omxBufHeader_->pAppPrivate = static_cast<void *>(&privateData);
    }
    int32_t ret = OMX_EmptyThisBuffer(comp_, omxBufHeader_);
    omxBufHeader_->pAppPrivate = nullptr;
    return ret;
}

int32_t ICodecBuffer::FillThisBuffer(OmxCodecBuffer &codecBuffer)
{
    CHECK_AND_RETURN_RET_LOG(comp_ != nullptr, OMX_ErrorInvalidComponent, "null component");
    CHECK_AND_RETURN_RET_LOG(omxBufHeader_ != nullptr, OMX_ErrorBadParameter, "null header");
    omxBufHeader_->nOffset = codecBuffer.offset;
    omxBufHeader_->nFilledLen = codecBuffer.filledLen;
    omxBufHeader_->nFlags = codecBuffer.flag;
    return OMX_FillThisBuffer(comp_, omxBufHeader_);
}

int32_t ICodecBuffer::EmptyBufferDone(OMX_BUFFERHEADERTYPE &omxBuffer, OmxCodecBuffer& codecBuffer)
{
    (void)omxBuffer;
    codecBuffer = codecBuffer_;
    codecBuffer.bufferhandle = nullptr;
    codecBuffer.fd = nullptr;
    codecBuffer.fenceFd = nullptr;
    codecBuffer.alongParam.clear();
    return 0;
}

int32_t ICodecBuffer::FillBufferDone(OMX_BUFFERHEADERTYPE &omxBuffer, OmxCodecBuffer& codecBuffer)
{
    codecBuffer = codecBuffer_;
    codecBuffer.bufferhandle = nullptr;
    codecBuffer.fd = nullptr;
    codecBuffer.fenceFd = nullptr;
    codecBuffer.offset = omxBuffer.nOffset;
    codecBuffer.filledLen = omxBuffer.nFilledLen;
    codecBuffer.flag = omxBuffer.nFlags;
    codecBuffer.pts = omxBuffer.nTimeStamp;
    auto appPrivate = static_cast<OMXBufferAppPrivateData *>(omxBuffer.pAppPrivate);
    if (appPrivate != nullptr && appPrivate->param != nullptr &&
        appPrivate->sizeOfParam < 1024) { // 1024: to protect from taint data
        codecBuffer.alongParam.resize(appPrivate->sizeOfParam);
        std::copy(static_cast<uint8_t*>(appPrivate->param),
                  static_cast<uint8_t*>(appPrivate->param) + appPrivate->sizeOfParam,
                  codecBuffer.alongParam.begin());
    } else {
        codecBuffer.alongParam.clear();
    }
    return 0;
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

ICodecBuffer::~ICodecBuffer()
{
    FreeBuffer();
}

void ICodecBuffer::FreeBuffer()
{
    if (comp_ && omxBufHeader_) {
        OMX_FreeBuffer(comp_, portIndex_, omxBufHeader_);
    }
    comp_ = nullptr;
    omxBufHeader_ = nullptr;
}

}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS