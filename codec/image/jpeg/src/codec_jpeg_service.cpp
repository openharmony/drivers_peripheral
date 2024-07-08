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
#include "codec_jpeg_service.h"
#include "codec_log_wrapper.h"

namespace OHOS {
namespace HDI {
namespace Codec {
namespace Image {
namespace V1_0 {
CodecJpegService::CodecJpegService()
{
    core_ = std::make_unique<CodecJpegCore>();
    bufferId_ = 0;
}

int32_t CodecJpegService::JpegInit()
{
    CODEC_LOGI("servcie impl!");
    CHECK_AND_RETURN_RET_LOG(core_ != nullptr, HDF_FAILURE, "core_ is null");
    std::lock_guard<std::mutex> lk(initMutex_);
    int32_t ret = core_->JpegInit();
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("error = [%{public}d]", ret);
    }
    return ret;
}

int32_t CodecJpegService::JpegDeInit()
{
    CODEC_LOGI("servcie impl!");
    CHECK_AND_RETURN_RET_LOG(core_ != nullptr, HDF_FAILURE, "core_ is null");

    int32_t ret = core_->JpegDeInit();
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("error = [%{public}d]", ret);
    }
    return ret;
}

int32_t CodecJpegService::DoJpegDecode(const CodecImageBuffer& inBuffer, const CodecImageBuffer& outBuffer,
    const CodecJpegDecInfo& decInfo)
{
    CODEC_LOGI("servcie impl!");
    CHECK_AND_RETURN_RET_LOG(core_ != nullptr, HDF_FAILURE, "core_ is null");
    CHECK_AND_RETURN_RET_LOG(inBuffer.buffer != nullptr, HDF_FAILURE, "inBuffer.buffer is null");
    CHECK_AND_RETURN_RET_LOG(outBuffer.buffer != nullptr, HDF_FAILURE, "outBuffer.buffer is null");

    BufferHandle *inHandle = inBuffer.buffer->GetBufferHandle();
    CHECK_AND_RETURN_RET_LOG(inHandle != nullptr, HDF_FAILURE, "inHandle is null");
    BufferHandle *outHandle = outBuffer.buffer->GetBufferHandle();
    CHECK_AND_RETURN_RET_LOG(outHandle != nullptr, HDF_FAILURE, "outHandle is null");

    int32_t ret = core_->DoDecode(inHandle, outHandle, &decInfo);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("error = [%{public}d]", ret);
    }
    return ret;
}

int32_t CodecJpegService::AllocateJpegInBuffer(CodecImageBuffer& inBuffer, uint32_t size)
{
    CODEC_LOGI("servcie impl!");
    CHECK_AND_RETURN_RET_LOG(core_ != nullptr, HDF_FAILURE, "core_ is null");
    
    BufferHandle *bufferHandle;
    int32_t ret = core_->AllocateInBuffer(&bufferHandle, size);
    inBuffer.fenceFd = -1;
    CHECK_AND_RETURN_RET_LOG(ret == HDF_SUCCESS, ret, "error = [%{public}d]", ret);
    inBuffer.buffer = new NativeBuffer();
    if (inBuffer.buffer == nullptr) {
        CODEC_LOGE("jpeg new NativeBuffer fail!");
        ret = core_->FreeInBuffer(bufferHandle);
        CHECK_AND_RETURN_RET_LOG(ret == HDF_SUCCESS, ret, "free bufferhandle fail, error = [%{public}d]", ret);
        return HDF_FAILURE;
    }
    inBuffer.buffer->SetBufferHandle(bufferHandle, true, [this](BufferHandle* freeBuffer) {
        int32_t err = core_->FreeInBuffer(freeBuffer);
        if (err != HDF_SUCCESS) {
            CODEC_LOGE("free bufferhandle fail, error = [%{public}d]", err);
        }
    });
    std::lock_guard<std::mutex> lk(mutex_);
    inBuffer.id = GetNextBufferId();
    CODEC_LOGI("success, bufferId [%{public}d]!", inBuffer.id);
    return ret;
}

int32_t CodecJpegService::FreeJpegInBuffer(const CodecImageBuffer& inBuffer)
{
    // inBuffer has been automatically destructed during AllocateJpegInBuffer
    return HDF_SUCCESS;
}

uint32_t CodecJpegService::GetNextBufferId(void)
{
    bufferId_++;
    return bufferId_;
}

} // V1_0
} // Image
} // Codec
} // HDI
} // OHOS
