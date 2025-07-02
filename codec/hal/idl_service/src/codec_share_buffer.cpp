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

#include "codec_share_buffer.h"
#include <hdf_base.h>
#include <securec.h>
#include <unistd.h>
#include "codec_log_wrapper.h"
using namespace OHOS::HDI::Codec::V4_0;
namespace OHOS {
namespace Codec {
namespace Omx {
CodecShareBuffer::CodecShareBuffer(struct OmxCodecBuffer &codecBuffer) : ICodecBuffer(codecBuffer)
{}

CodecShareBuffer::~CodecShareBuffer()
{
    shMem_ = nullptr;
}

void CodecShareBuffer::SetAshMem(std::shared_ptr<OHOS::Ashmem> shMem)
{
    shMem_ = shMem;
}

OHOS::sptr<ICodecBuffer> CodecShareBuffer::Create(struct OmxCodecBuffer &codecBuffer)
{
    if (codecBuffer.fd == nullptr) {
        CODEC_LOGE("codecBuffer.fd is invalid");
        return OHOS::sptr<ICodecBuffer>();
    }
    int size = OHOS::AshmemGetSize(codecBuffer.fd->Get());
    std::shared_ptr<OHOS::Ashmem> sharedMem = std::make_shared<OHOS::Ashmem>(codecBuffer.fd->Release(), size);
    if (sharedMem == nullptr) {
        CODEC_LOGE("Failed to init sharedMem");
        return OHOS::sptr<ICodecBuffer>();
    }
    bool mapd = false;
    if (codecBuffer.type == READ_WRITE_TYPE) {
        mapd = sharedMem->MapReadAndWriteAshmem();
    } else {
        mapd = sharedMem->MapReadOnlyAshmem();
    }
    if (!mapd) {
        CODEC_LOGE("MapReadAndWriteAshmem or MapReadOnlyAshmem return false");
        return OHOS::sptr<ICodecBuffer>();
    }
    codecBuffer.fd.reset();
    CodecShareBuffer *buffer = new CodecShareBuffer(codecBuffer);
    buffer->SetAshMem(sharedMem);
    return OHOS::sptr<ICodecBuffer>(buffer);
}

OHOS::sptr<ICodecBuffer> CodecShareBuffer::Allocate(struct OmxCodecBuffer &codecBuffer)
{
    codecBuffer.bufferType = CODEC_BUFFER_TYPE_AVSHARE_MEM_FD;
    // create shared memory
    int sharedFD = AshmemCreate(nullptr, codecBuffer.allocLen);

    std::shared_ptr<Ashmem> sharedMemory = std::make_shared<Ashmem>(sharedFD, codecBuffer.allocLen);
    if (sharedMemory == nullptr) {
        CODEC_LOGE("Failed to init sharedMemory");
        return OHOS::sptr<ICodecBuffer>();
    }
    bool mapd = false;
    if (codecBuffer.type == READ_WRITE_TYPE) {
        mapd = sharedMemory->MapReadAndWriteAshmem();
    } else {
        mapd = sharedMemory->MapReadOnlyAshmem();
    }
    if (!mapd) {
        CODEC_LOGE("MapReadAndWriteAshmem or MapReadOnlyAshmem return false");
        return OHOS::sptr<ICodecBuffer>();
    }
    codecBuffer.offset = 0;
    codecBuffer.filledLen = 0;
    codecBuffer.fd = UniqueFd::Create(sharedFD, false);
    CodecShareBuffer *buffer = new CodecShareBuffer(codecBuffer);
    buffer->SetAshMem(sharedMemory);
    return OHOS::sptr<ICodecBuffer>(buffer);
}

int32_t CodecShareBuffer::FillOmxBuffer(struct OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE &omxBuffer)
{
    if (!CheckInvalid(codecBuffer) || codecBuffer_.type != READ_WRITE_TYPE) {
        CODEC_LOGE("CheckInvalid return false or mem has no right to write ");
        return HDF_ERR_INVALID_PARAM;
    }

    return ICodecBuffer::FillOmxBuffer(codecBuffer, omxBuffer);
}

int32_t CodecShareBuffer::EmptyOmxBuffer(struct OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE &omxBuffer)
{
    if (!CheckInvalid(codecBuffer)) {
        CODEC_LOGE("shMem_ is null or CheckInvalid return false");
        return HDF_ERR_INVALID_PARAM;
    }

    void *sharedPtr = const_cast<void *>(shMem_->ReadFromAshmem(codecBuffer.filledLen, codecBuffer.offset));
    if (!sharedPtr) {
        CODEC_LOGE("omxBuffer.length [%{public}d omxBuffer.offset[%{public}d]", codecBuffer.filledLen,
                   codecBuffer.offset);
        return HDF_ERR_INVALID_PARAM;
    }
    auto ret = memcpy_s(omxBuffer.pBuffer + codecBuffer.offset, codecBuffer.allocLen - codecBuffer.offset, sharedPtr,
                        codecBuffer.filledLen);
    if (ret != EOK) {
        CODEC_LOGE("memcpy_s ret [%{public}d]", ret);
        return HDF_ERR_INVALID_PARAM;
    }
    return ICodecBuffer::EmptyOmxBuffer(codecBuffer, omxBuffer);
}

int32_t CodecShareBuffer::FreeBuffer(struct OmxCodecBuffer &codecBuffer)
{
    if (!CheckInvalid(codecBuffer)) {
        CODEC_LOGE("shMem_ is null or CheckInvalid return false");
        return HDF_ERR_INVALID_PARAM;
    }

    shMem_ = nullptr;
    return HDF_SUCCESS;
}

uint8_t *CodecShareBuffer::GetBuffer()
{
    return nullptr;
}

int32_t CodecShareBuffer::EmptyOmxBufferDone(OMX_BUFFERHEADERTYPE &omxBuffer)
{
    return ICodecBuffer::EmptyOmxBufferDone(omxBuffer);
}

int32_t CodecShareBuffer::FillOmxBufferDone(OMX_BUFFERHEADERTYPE &omxBuffer)
{
    if (shMem_ == nullptr || !shMem_->WriteToAshmem(omxBuffer.pBuffer, omxBuffer.nFilledLen, omxBuffer.nOffset)) {
        CODEC_LOGE("write to ashmem fail");
        return HDF_ERR_INVALID_PARAM;
    }

    return ICodecBuffer::FillOmxBufferDone(omxBuffer);
}

bool CodecShareBuffer::CheckInvalid(struct OmxCodecBuffer &codecBuffer)
{
    if (!ICodecBuffer::CheckInvalid(codecBuffer) || shMem_ == nullptr) {
        CODEC_LOGE("shMem_ is null or CheckInvalid return false");
        return false;
    }
    return true;
}
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS