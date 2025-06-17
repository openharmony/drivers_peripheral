/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "codec_dma_buffer.h"
#include <hdf_base.h>
#include <securec.h>
#include <unistd.h>
#include <hdf_remote_service.h>
#include "codec_log_wrapper.h"
#include "v4_0/codec_types.h"
using namespace OHOS::HDI::Codec::V4_0;
namespace OHOS {
namespace Codec {
namespace Omx {
CodecDMABuffer::CodecDMABuffer(struct OmxCodecBuffer &codecBuffer) : ICodecBuffer(codecBuffer)
{}

CodecDMABuffer::~CodecDMABuffer()
{}

sptr<ICodecBuffer> CodecDMABuffer::Create(struct OmxCodecBuffer &codecBuffer)
{
    if (codecBuffer.fd < 0) {
        CODEC_LOGE("codecBuffer.fd is invalid");
        return sptr<ICodecBuffer>();
    }

    CodecDMABuffer *buffer = new CodecDMABuffer(codecBuffer);
    return sptr<ICodecBuffer>(buffer);
}

sptr<ICodecBuffer> CodecDMABuffer::Allocate(struct OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE &omxBuffer)
{
    if (omxBuffer.pAppPrivate == nullptr) {
        CODEC_LOGE("omxBuffer.pAppPrivate is invalid!");
        return sptr<ICodecBuffer>();
    }

    codecBuffer.bufferType = CODEC_BUFFER_TYPE_DMA_MEM_FD;
    codecBuffer.offset = 0;
    codecBuffer.filledLen = 0;
    OMXBufferAppPrivateData *privateData = static_cast<OMXBufferAppPrivateData *>(omxBuffer.pAppPrivate);
    codecBuffer.fd = UniqueFd::Create(privateData->fd, false);
    CodecDMABuffer *buffer = new CodecDMABuffer(codecBuffer);
    return sptr<ICodecBuffer>(buffer);
}

int32_t CodecDMABuffer::FillOmxBuffer(struct OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE &omxBuffer)
{
    if (!CheckInvalid(codecBuffer)) {
        CODEC_LOGE("CheckInvalid return false or mem has no right to write ");
        return HDF_ERR_INVALID_PARAM;
    }

    return ICodecBuffer::FillOmxBuffer(codecBuffer, omxBuffer);
}

int32_t CodecDMABuffer::EmptyOmxBuffer(struct OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE &omxBuffer)
{
    if (!CheckInvalid(codecBuffer)) {
        CODEC_LOGE("CheckInvalid return false or mem has no right to write ");
        return HDF_ERR_INVALID_PARAM;
    }

    return ICodecBuffer::EmptyOmxBuffer(codecBuffer, omxBuffer);
}

int32_t CodecDMABuffer::FreeBuffer(struct OmxCodecBuffer &codecBuffer)
{
    if (!CheckInvalid(codecBuffer)) {
        CODEC_LOGE("shMem_ is null or CheckInvalid return false");
        return HDF_ERR_INVALID_PARAM;
    }

    return HDF_SUCCESS;
}

int32_t CodecDMABuffer::EmptyOmxBufferDone(OMX_BUFFERHEADERTYPE &omxBuffer)
{
    return ICodecBuffer::EmptyOmxBufferDone(omxBuffer);
}

int32_t CodecDMABuffer::FillOmxBufferDone(OMX_BUFFERHEADERTYPE &omxBuffer)
{
    return ICodecBuffer::FillOmxBufferDone(omxBuffer);
}

uint8_t *CodecDMABuffer::GetBuffer()
{
    return nullptr;
}

bool CodecDMABuffer::CheckInvalid(struct OmxCodecBuffer &codecBuffer)
{
    return ICodecBuffer::CheckInvalid(codecBuffer);
}
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS