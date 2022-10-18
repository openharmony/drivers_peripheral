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
#include "codec_dyna_buffer.h"
#include <buffer_handle_utils.h>
#include <hdf_base.h>
#include <hdf_log.h>
#include <securec.h>
#include <unistd.h>
namespace OHOS {
namespace Codec {
namespace Omx {
CodecDynaBuffer::CodecDynaBuffer(struct OmxCodecBuffer &codecBuffer) : ICodecBuffer(codecBuffer)
{}

CodecDynaBuffer::~CodecDynaBuffer()
{
    dynaBuffer_ = nullptr;
}

sptr<ICodecBuffer> CodecDynaBuffer::Create(struct OmxCodecBuffer &codecBuffer)
{
    auto bufferHandle = reinterpret_cast<BufferHandle *>(codecBuffer.buffer);
    // may be empty for bufferHandle
    codecBuffer.buffer = nullptr;
    codecBuffer.bufferLen = 0;
    codecBuffer.allocLen = sizeof(DynamicBuffer);

    CodecDynaBuffer *buffer = new CodecDynaBuffer(codecBuffer);
    buffer->dynaBuffer_ = std::make_shared<DynamicBuffer>();
    buffer->dynaBuffer_->bufferHandle = bufferHandle;
    return sptr<ICodecBuffer>(buffer);
}

int32_t CodecDynaBuffer::FillOmxBuffer(struct OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE &omxBuffer)
{
    HDF_LOGE("%{public}s :dyna buffer handle is not supported in FillThisBuffer ", __func__);
    (void)codecBuffer;
    (void)omxBuffer;
    return HDF_ERR_INVALID_PARAM;
}

int32_t CodecDynaBuffer::EmptyOmxBuffer(struct OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE &omxBuffer)
{
    if (!CheckInvalid(codecBuffer)) {
        HDF_LOGE("%{public}s : CheckInvalid return false", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    ResetBuffer(codecBuffer, omxBuffer);

    int fence = codecBuffer.fenceFd;
    if (fence >= 0) {
        auto ret = SyncWait(fence, TIME_WAIT_MS);
        if (ret != EOK) {
            HDF_LOGW("%{public}s : SyncWait ret err", __func__);
        }
        close(codecBuffer.fenceFd);
        codecBuffer.fenceFd = -1;
    }

    return ICodecBuffer::EmptyOmxBuffer(codecBuffer, omxBuffer);
}

int32_t CodecDynaBuffer::FreeBuffer(struct OmxCodecBuffer &codecBuffer)
{
    if (!CheckInvalid(codecBuffer)) {
        HDF_LOGE("%{public}s :shMem_ is null or CheckInvalid return false", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (codecBuffer.buffer != nullptr) {
        auto bufferHandle = reinterpret_cast<BufferHandle *>(codecBuffer.buffer);
        // if recv new BufferHandle, free it
        FreeBufferHandle(bufferHandle);
        codecBuffer.buffer = 0;
        codecBuffer.bufferLen = 0;
    }

    dynaBuffer_ = nullptr;

    return HDF_SUCCESS;
}

int32_t CodecDynaBuffer::EmptyOmxBufferDone(OMX_BUFFERHEADERTYPE &omxBuffer)
{
    return ICodecBuffer::EmptyOmxBufferDone(omxBuffer);
}

int32_t CodecDynaBuffer::FillOmxBufferDone(OMX_BUFFERHEADERTYPE &omxBuffer)
{
    HDF_LOGE("%{public}s :dyna buffer handle is not supported in FillThisBuffer ", __func__);
    (void)omxBuffer;
    return HDF_ERR_INVALID_PARAM;
}

uint8_t *CodecDynaBuffer::GetBuffer()
{
    return reinterpret_cast<uint8_t *>(dynaBuffer_.get());
}

bool CodecDynaBuffer::CheckInvalid(struct OmxCodecBuffer &codecBuffer)
{
    if (!ICodecBuffer::CheckInvalid(codecBuffer) || dynaBuffer_ == nullptr) {
        HDF_LOGE("%{public}s :dynaBuffer_ is null or CheckInvalid return false", __func__);
        return false;
    }
    return true;
}

void CodecDynaBuffer::ResetBuffer(struct OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE &omxBuffer)
{
    (void)omxBuffer;
    if (codecBuffer.buffer == nullptr) {
        return;
    }
    auto bufferHandle = reinterpret_cast<BufferHandle *>(codecBuffer.buffer);
    // if recv new BufferHandle, save it, but do not need to save to omxBuffer
    if (dynaBuffer_->bufferHandle != nullptr) {
        FreeBufferHandle(dynaBuffer_->bufferHandle);
    }
    dynaBuffer_->bufferHandle = bufferHandle;
    codecBuffer.buffer = 0;
    codecBuffer.filledLen = sizeof(DynamicBuffer);
    codecBuffer.bufferLen = 0;
}
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS