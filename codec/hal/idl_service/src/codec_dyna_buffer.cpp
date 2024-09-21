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
#include "codec_dyna_buffer.h"
#include <buffer_handle_utils.h>
#include <hdf_base.h>
#include <securec.h>
#include <unistd.h>
#include "codec_log_wrapper.h"
#include "v3_0/codec_types.h"
using namespace OHOS::HDI::Codec::V3_0;
namespace OHOS {
namespace Codec {
namespace Omx {
CodecDynaBuffer::CodecDynaBuffer(struct OmxCodecBuffer &codecBuffer)
    : ICodecBuffer(codecBuffer)
{
}

CodecDynaBuffer::~CodecDynaBuffer()
{
}

sptr<ICodecBuffer> CodecDynaBuffer::Create(struct OmxCodecBuffer &codecBuffer)
{
    codecBuffer.bufferhandle = nullptr;
    codecBuffer.allocLen = sizeof(DynamicBuffer);
    CodecDynaBuffer *buffer = new CodecDynaBuffer(codecBuffer);
    return sptr<ICodecBuffer>(buffer);
}

int32_t CodecDynaBuffer::FillOmxBuffer(struct OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE &omxBuffer)
{
    if (!CheckInvalid(codecBuffer)) {
        CODEC_LOGE("CheckInvalid return false");
        return HDF_ERR_INVALID_PARAM;
    }

    if (buffer_ == nullptr && codecBuffer.bufferhandle != nullptr) {
        BufferHandle* handle = codecBuffer.bufferhandle->GetBufferHandle();
        if (handle != nullptr) {
            buffer_ = codecBuffer.bufferhandle;
            dynaBuffer_.bufferHandle = handle;
        }
    }

    int fenceFd = codecBuffer.fenceFd;
    if (fenceFd >= 0) {
        auto ret = SyncWait(fenceFd, TIME_WAIT_MS);
        if (ret != EOK) {
            CODEC_LOGW("SyncWait ret err");
        }
        close(codecBuffer.fenceFd);
        codecBuffer.fenceFd = -1;
    }
    return ICodecBuffer::FillOmxBuffer(codecBuffer, omxBuffer);
}

int32_t CodecDynaBuffer::EmptyOmxBuffer(struct OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE &omxBuffer)
{
    if (!CheckInvalid(codecBuffer)) {
        CODEC_LOGE("CheckInvalid return false");
        return HDF_ERR_INVALID_PARAM;
    }
    if (codecBuffer.bufferhandle != nullptr) {
        BufferHandle* handle = codecBuffer.bufferhandle->GetBufferHandle();
        if (handle != nullptr) {
            buffer_ = codecBuffer.bufferhandle;
            dynaBuffer_.bufferHandle = handle;
            codecBuffer.filledLen = sizeof(DynamicBuffer);
        }
    }

    int fence = codecBuffer.fenceFd;
    if (fence >= 0) {
        auto ret = SyncWait(fence, TIME_WAIT_MS);
        if (ret != EOK) {
            CODEC_LOGW("SyncWait ret err");
        }
        close(codecBuffer.fenceFd);
        codecBuffer.fenceFd = -1;
    }

    return ICodecBuffer::EmptyOmxBuffer(codecBuffer, omxBuffer);
}

int32_t CodecDynaBuffer::FreeBuffer(struct OmxCodecBuffer &codecBuffer)
{
    if (!CheckInvalid(codecBuffer)) {
        CODEC_LOGE("shMem_ is null or CheckInvalid return false");
        return HDF_ERR_INVALID_PARAM;
    }

    buffer_ = nullptr;
    return HDF_SUCCESS;
}

int32_t CodecDynaBuffer::EmptyOmxBufferDone(OMX_BUFFERHEADERTYPE &omxBuffer)
{
    return ICodecBuffer::EmptyOmxBufferDone(omxBuffer);
}

int32_t CodecDynaBuffer::FillOmxBufferDone(OMX_BUFFERHEADERTYPE &omxBuffer)
{
    return ICodecBuffer::FillOmxBufferDone(omxBuffer);
}

uint8_t *CodecDynaBuffer::GetBuffer()
{
    return reinterpret_cast<uint8_t *>(&dynaBuffer_);
}

}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS