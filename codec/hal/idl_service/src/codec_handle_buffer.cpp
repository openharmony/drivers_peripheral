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

#include "codec_handle_buffer.h"
#include <hdf_base.h>
#include <securec.h>
#include <unistd.h>
#include "codec_log_wrapper.h"
#include "v3_0/codec_types.h"
using namespace OHOS::HDI::Codec::V3_0;
namespace OHOS {
namespace Codec {
namespace Omx {
CodecHandleBuffer::CodecHandleBuffer(struct OmxCodecBuffer &codecBuffer)
    : ICodecBuffer(codecBuffer)
{
    buffer_ = codecBuffer.bufferhandle;
}

CodecHandleBuffer::~CodecHandleBuffer()
{
}

sptr<ICodecBuffer> CodecHandleBuffer::Create(struct OmxCodecBuffer &codecBuffer)
{
    if (codecBuffer.bufferhandle == nullptr) {
        CODEC_LOGE("nativebuffer is null");
        return nullptr;
    }
    BufferHandle *bufferHandle = codecBuffer.bufferhandle->GetBufferHandle();
    if (bufferHandle == nullptr) {
        CODEC_LOGE("bufferHandle is null");
        return nullptr;
    }
    CodecHandleBuffer *buffer = new CodecHandleBuffer(codecBuffer);
    codecBuffer.bufferhandle = nullptr;
    return sptr<ICodecBuffer>(buffer);
}

int32_t CodecHandleBuffer::FillOmxBuffer(struct OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE &omxBuffer)
{
    if (!CheckInvalid(codecBuffer)) {
        CODEC_LOGE("CheckInvalid return false or mem has no right to write ");
        return HDF_ERR_INVALID_PARAM;
    }

    if (codecBuffer.fenceFd != nullptr) {
        auto ret = SyncWait(codecBuffer.fenceFd->Get(), TIME_WAIT_MS);
        if (ret != EOK) {
            CODEC_LOGE("SyncWait ret err [%{public}d]", ret);
        }
    }
    return ICodecBuffer::FillOmxBuffer(codecBuffer, omxBuffer);
}

int32_t CodecHandleBuffer::EmptyOmxBuffer(struct OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE &omxBuffer)
{
    CODEC_LOGE("bufferHandle is not support in EmptyThisBuffer");
    (void)codecBuffer;
    (void)omxBuffer;
    return HDF_ERR_INVALID_PARAM;
}

int32_t CodecHandleBuffer::FreeBuffer(struct OmxCodecBuffer &codecBuffer)
{
    if (!CheckInvalid(codecBuffer)) {
        CODEC_LOGE("shMem_ is null or CheckInvalid return false");
        return HDF_ERR_INVALID_PARAM;
    }
    codecBuffer.bufferhandle = nullptr;
    buffer_ = nullptr;

    return HDF_SUCCESS;
}

int32_t CodecHandleBuffer::EmptyOmxBufferDone(OMX_BUFFERHEADERTYPE &omxBuffer)
{
    CODEC_LOGE("bufferHandle is not support in EmptyThisBuffer");
    (void)omxBuffer;
    return HDF_ERR_INVALID_PARAM;
}

int32_t CodecHandleBuffer::FillOmxBufferDone(OMX_BUFFERHEADERTYPE &omxBuffer)
{
    return ICodecBuffer::FillOmxBufferDone(omxBuffer);
}

uint8_t *CodecHandleBuffer::GetBuffer()
{
    if (buffer_ == nullptr) {
        return nullptr;
    }
    return reinterpret_cast<uint8_t *>(buffer_->GetBufferHandle());
}

}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS