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

#include "codec_share_buffer.h"
#include <hdf_base.h>
#include <hdf_log.h>
#include <securec.h>
#include <unistd.h>

namespace OHOS {
namespace Codec {
namespace Omx {
CodecShareBuffer::CodecShareBuffer(struct OmxCodecBuffer &codecBuffer) : ICodecBuffer(codecBuffer)
{}

CodecShareBuffer::~CodecShareBuffer()
{
    if (shMem_ != nullptr) {
        shMem_->UnmapAshmem();
        shMem_->CloseAshmem();
        shMem_ = nullptr;
    }
}

void CodecShareBuffer::SetAshMem(std::shared_ptr<OHOS::Ashmem> shMem)
{
    shMem_ = shMem;
}

OHOS::sptr<ICodecBuffer> CodecShareBuffer::Create(struct OmxCodecBuffer &codecBuffer)
{
    int shardFd = (int)reinterpret_cast<uintptr_t>(codecBuffer.buffer);
    if (shardFd < 0) {
        HDF_LOGE("%{public}s error, shardFd < 0", __func__);
        return nullptr;
    }
    int size = OHOS::AshmemGetSize(shardFd);
    std::shared_ptr<OHOS::Ashmem> sharedMem = std::make_shared<OHOS::Ashmem>(shardFd, size);
    bool mapd = false;
    if (codecBuffer.type == READ_WRITE_TYPE) {
        mapd = sharedMem->MapReadAndWriteAshmem();
    } else {
        mapd = sharedMem->MapReadOnlyAshmem();
    }
    if (!mapd) {
        HDF_LOGE("%{public}s error, MapReadAndWriteAshmem or MapReadOnlyAshmem return false", __func__);
        return nullptr;
    }

    codecBuffer.buffer = nullptr;
    codecBuffer.bufferLen = 0;
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
    codecBuffer.type = READ_WRITE_TYPE;
    bool mapd = false;
    if (codecBuffer.type == READ_WRITE_TYPE) {
        mapd = sharedMemory->MapReadAndWriteAshmem();
    } else {
        mapd = sharedMemory->MapReadOnlyAshmem();
    }
    if (!mapd) {
        HDF_LOGE("%{public}s error, MapReadAndWriteAshmem or MapReadOnlyAshmem return false", __func__);
        return nullptr;
    }
    codecBuffer.offset = 0;
    codecBuffer.filledLen = 0;

    CodecShareBuffer *buffer = new CodecShareBuffer(codecBuffer);
    codecBuffer.buffer = reinterpret_cast<uint8_t *>(sharedFD);
    codecBuffer.bufferLen = sizeof(int);
    buffer->SetAshMem(sharedMemory);
    return OHOS::sptr<ICodecBuffer>(buffer);
}

int32_t CodecShareBuffer::FillOmxBuffer(struct OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE &omxBuffer)
{
    if (!CheckInvalid(codecBuffer) || codecBuffer_.type != READ_WRITE_TYPE) {
        HDF_LOGE("%{public}s :CheckInvalid return false or mem has no right to write ", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    ReleaseFd(codecBuffer);

    return ICodecBuffer::FillOmxBuffer(codecBuffer, omxBuffer);
}

int32_t CodecShareBuffer::EmptyOmxBuffer(struct OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE &omxBuffer)
{
    if (!CheckInvalid(codecBuffer)) {
        HDF_LOGE("%{public}s :shMem_ is null or CheckInvalid return false", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    ReleaseFd(codecBuffer);

    void *sharedPtr = const_cast<void *>(shMem_->ReadFromAshmem(codecBuffer.filledLen, codecBuffer.offset));
    if (!sharedPtr) {
        HDF_LOGE("%{public}s error, omxBuffer.length [%{public}d omxBuffer.offset[%{public}d]", __func__,
                 codecBuffer.filledLen, codecBuffer.offset);
        return HDF_ERR_INVALID_PARAM;
    }
    auto ret = memcpy_s(omxBuffer.pBuffer + codecBuffer.offset, codecBuffer.allocLen - codecBuffer.offset, sharedPtr,
                        codecBuffer.filledLen);
    if (ret != EOK) {
        HDF_LOGE("%{public}s error, memcpy_s ret [%{public}d", __func__, ret);
        return HDF_ERR_INVALID_PARAM;
    }
    return ICodecBuffer::EmptyOmxBuffer(codecBuffer, omxBuffer);
}

int32_t CodecShareBuffer::FreeBuffer(struct OmxCodecBuffer &codecBuffer)
{
    if (!CheckInvalid(codecBuffer)) {
        HDF_LOGE("%{public}s :shMem_ is null or CheckInvalid return false", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    ReleaseFd(codecBuffer);

    shMem_->UnmapAshmem();
    shMem_->CloseAshmem();
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
        HDF_LOGE("%{public}s write to ashmem[%{public}p] fail", __func__, shMem_.get());
        return HDF_ERR_INVALID_PARAM;
    }

    return ICodecBuffer::FillOmxBufferDone(omxBuffer);
}

bool CodecShareBuffer::CheckInvalid(struct OmxCodecBuffer &codecBuffer)
{
    if (!ICodecBuffer::CheckInvalid(codecBuffer) || shMem_ == nullptr) {
        HDF_LOGE("%{public}s :shMem_ is null or CheckInvalid return false", __func__);
        return false;
    }
    return true;
}

void CodecShareBuffer::ReleaseFd(struct OmxCodecBuffer &codecBuffer)
{
    // close the fd, if fd is sent by codecBuffer
    if (codecBuffer.buffer != nullptr) {
        int fd = (int)reinterpret_cast<uintptr_t>(codecBuffer.buffer);
        close(fd);
        codecBuffer.buffer = 0;
        codecBuffer.bufferLen = 0;
    }
}
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS