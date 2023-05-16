/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <ashmem.h>
#include "codec_log_wrapper.h"
#include "codec_jpeg_dec.h"
namespace OHOS {
namespace HDI {
namespace Codec {
namespace Image {
namespace V1_0 {
extern "C" ICodecImageJpeg *CodecImageJpegImplGetInstance(void)
{
    return new (std::nothrow) CodecJpegDecoder();
}
CodecJpegDecoder::CodecJpegDecoder()
{
    core_ = std::make_unique<CodecJpegCore>();
    bufferId_ = 0;
}

int32_t CodecJpegDecoder::GetImageCapability(std::vector<CodecImageCapability>& capList)
{
    return CodecImageConfig::GetInstance()->GetImageCapabilityList(capList);
}

int32_t CodecJpegDecoder::JpegInit()
{
    CODEC_LOGI("servcie impl!");
    CHECK_AND_RETURN_RET_LOG(core_ != nullptr, HDF_FAILURE, "core_ is null");

    int32_t ret = core_->Init();
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("error = [%{public}d]", ret);
    }
    return ret;
}

int32_t CodecJpegDecoder::JpegDeInit()
{
    CODEC_LOGI("servcie impl!");
    CHECK_AND_RETURN_RET_LOG(core_ != nullptr, HDF_FAILURE, "core_ is null");

    int32_t ret = core_->DeInit();
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("error = [%{public}d]", ret);
    }
    return ret;
}

int32_t CodecJpegDecoder::DoJpegDecode(const CodecImageBuffer& inBuffer, const CodecImageBuffer& outBuffer,
    const sptr<ICodecImageCallback>& callbacks, const CodecJpegDecInfo& decInfo)
{
    CODEC_LOGI("servcie impl!");
    CHECK_AND_RETURN_RET_LOG(core_ != nullptr, HDF_FAILURE, "core_ is null");
    CHECK_AND_RETURN_RET_LOG(callbacks != nullptr, HDF_ERR_INVALID_PARAM, "callbacks is null");

    BufferHandle *inHandle = inBuffer.buffer->Move();
    CHECK_AND_RETURN_RET_LOG(inHandle != nullptr, HDF_FAILURE, "inHandle is null");
    BufferHandle *outHandle = outBuffer.buffer->Move();
    CHECK_AND_RETURN_RET_LOG(outHandle != nullptr, HDF_FAILURE, "outHandle is null");

    int32_t ret = core_->DoDecode(inHandle, outHandle, &decInfo, callbacks, outBuffer.fenceFd);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("error = [%{public}d]", ret);
    }
    return ret;
}

int32_t CodecJpegDecoder::AllocateInBuffer(CodecImageBuffer& inBuffer, uint32_t size)
{
    CODEC_LOGI("servcie impl!");
    CHECK_AND_RETURN_RET_LOG(core_ != nullptr, HDF_FAILURE, "core_ is null");
    CHECK_AND_RETURN_RET_LOG(size != 0, HDF_ERR_INVALID_PARAM, "buffer size is 0");
    CHECK_AND_RETURN_RET_LOG(size <= CODEC_IMAGE_MAX_BUFFER_SIZE, HDF_ERR_INVALID_PARAM, "buffer size is too large");

    BufferHandle *bufferHandle;
    int32_t ret = core_->AllocateInBuffer(&bufferHandle, size);
    CHECK_AND_RETURN_RET_LOG(ret == HDF_SUCCESS, ret, "error = [%{public}d]", ret);

    inBuffer.buffer = new NativeBuffer(bufferHandle);
    inBuffer.id = GetNextBufferId();
    bufferHandleMap_.emplace(std::make_pair(inBuffer.id, bufferHandle));
    CODEC_LOGI("success, bufferId [%{public}d]!", inBuffer.id);
    return ret;
}

int32_t CodecJpegDecoder::FreeInBuffer(const CodecImageBuffer& inBuffer)
{
    CODEC_LOGI("servcie impl, bufferId [%{public}d]!", inBuffer.id);
    CHECK_AND_RETURN_RET_LOG(core_ != nullptr, HDF_FAILURE, "core_ is null");

    uint32_t bufferId = inBuffer.id;
    auto entry = bufferHandleMap_.find(bufferId);
    CHECK_AND_RETURN_RET_LOG(entry != bufferHandleMap_.end(), HDF_FAILURE, "not find bufferId:[%{public}d]", bufferId);

    BufferHandle *bufferHandle = entry->second;
    int32_t ret = core_->FreeInBuffer(bufferHandle);
    CHECK_AND_RETURN_RET_LOG(ret == HDF_SUCCESS, ret, "error = [%{public}d]", ret);

    bufferHandleMap_.erase(entry);
    return ret;
}

uint32_t CodecJpegDecoder::GetNextBufferId(void)
{
    std::lock_guard<std::mutex> lk(mutex_);
    bufferId_++;
    return bufferId_;
}

} // V1_0
} // Image
} // Codec
} // HDI
} // OHOS
