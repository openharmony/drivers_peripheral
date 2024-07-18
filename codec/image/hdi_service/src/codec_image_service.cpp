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

#include "codec_log_wrapper.h"
#include "codec_image_service.h"
#include "hitrace_meter.h"
#include "codec_xcollie.h"
#include <unistd.h>

namespace OHOS {
namespace HDI {
namespace Codec {
namespace Image {
namespace V1_0 {
extern "C" ICodecImage *CodecImageImplGetInstance(void)
{
    return new (std::nothrow) CodecImageService();
}

CodecImageService::CodecImageService()
{
    jpegImpl_ = std::make_unique<CodecJpegService>();
}

int32_t CodecImageService::GetImageCapability(std::vector<CodecImageCapability>& capList)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HdfCodecGetImageCapability");
    return CodecImageConfig::GetInstance()->GetImageCapabilityList(capList);
}

int32_t CodecImageService::Init(enum CodecImageRole role)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HdfCodecInit");
    CODEC_LOGI("servcie impl!");
    if (role == CODEC_IMAGE_JPEG) {
        CHECK_AND_RETURN_RET_LOG(jpegImpl_ != nullptr, HDF_FAILURE, "jpegImpl_ is null");
        return jpegImpl_->JpegInit();
    } else {
        return HDF_ERR_NOT_SUPPORT;
    }
}

int32_t CodecImageService::DeInit(enum CodecImageRole role)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HdfCodecDeInit");
    CODEC_LOGI("servcie impl!");
    if (role == CODEC_IMAGE_JPEG) {
        CHECK_AND_RETURN_RET_LOG(jpegImpl_ != nullptr, HDF_FAILURE, "jpegImpl_ is null");
        return jpegImpl_->JpegDeInit();
    } else {
        return HDF_ERR_NOT_SUPPORT;
    }
}

int32_t CodecImageService::DoJpegDecode(const CodecImageBuffer& inBuffer, const CodecImageBuffer& outBuffer,
    const CodecJpegDecInfo& decInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HdfCodecDoJpegDecode");
    CODEC_LOGI("servcie impl!");
    XCOLLIE_LISTENER("DoJpegDecode");
    if (inBuffer.fenceFd >= 0) {
        close(inBuffer.fenceFd);
    }
    CHECK_AND_RETURN_RET_LOG(jpegImpl_ != nullptr, HDF_FAILURE, "jpegImpl_ is null");
    return jpegImpl_->DoJpegDecode(inBuffer, outBuffer, decInfo);
}

int32_t CodecImageService::AllocateInBuffer(CodecImageBuffer& inBuffer, uint32_t size, CodecImageRole role)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HdfCodecAllocateInBuffer");
    CODEC_LOGI("servcie impl, size [%{public}d]", size);
    CHECK_AND_RETURN_RET_LOG(size != 0, HDF_ERR_INVALID_PARAM, "buffer size is 0");
    CHECK_AND_RETURN_RET_LOG(size <= CODEC_IMAGE_MAX_BUFFER_SIZE, HDF_ERR_INVALID_PARAM, "buffer size is too large");
    inBuffer.bufferRole = role;
    inBuffer.size = size;
    if (role == CODEC_IMAGE_JPEG) {
        CHECK_AND_RETURN_RET_LOG(jpegImpl_ != nullptr, HDF_FAILURE, "jpegImpl_ is null");
        return jpegImpl_->AllocateJpegInBuffer(inBuffer, size);
    } else {
        return HDF_ERR_NOT_SUPPORT;
    }
}

int32_t CodecImageService::FreeInBuffer(const CodecImageBuffer& inBuffer)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HdfCodecFreeInBuffer");
    CODEC_LOGI("servcie impl, bufferId [%{public}d]", inBuffer.id);
    if (inBuffer.fenceFd >= 0) {
        close(inBuffer.fenceFd);
    }
    if (inBuffer.bufferRole == CODEC_IMAGE_JPEG) {
        CHECK_AND_RETURN_RET_LOG(jpegImpl_ != nullptr, HDF_FAILURE, "jpegImpl_ is null");
        return jpegImpl_->FreeJpegInBuffer(inBuffer);
    } else {
        return HDF_ERR_NOT_SUPPORT;
    }
}
} // V1_0
} // Image
} // Codec
} // HDI
} // OHOS
