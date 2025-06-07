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
#include "v1_0/display_composer_type.h"
#include "v1_0/imapper.h"
#include "v1_1/imetadata.h"
#include <unistd.h>

namespace OHOS {
namespace HDI {
namespace Codec {
namespace Image {
namespace V2_1 {
extern "C" ICodecImage *CodecImageImplGetInstance(void)
{
    return new (std::nothrow) CodecImageService();
}

CodecImageService::CodecImageService()
{
    jpegImpl_ = std::make_unique<CodecJpegService>();
    heifEncodeImpl_ = std::make_unique<CodecHeifEncodeService>();
    heifDecodeImpl_ = std::make_unique<CodecHeifDecodeService>();
}

int32_t CodecImageService::NotifyPowerOn(enum CodecImageRole role)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HdfCodecPrePowerOn");
    CODEC_LOGD("servcie impl!");
    if (role == CODEC_IMAGE_JPEG) {
        CHECK_AND_RETURN_RET_LOG(jpegImpl_ != nullptr, HDF_FAILURE, "jpegImpl_ is null");
        jpegImpl_->NotifyJpegPowerOn();
    }
    return HDF_SUCCESS;
}

int32_t CodecImageService::GetImageCapability(std::vector<CodecImageCapability>& capList)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HdfCodecGetImageCapability");
    return CodecImageConfig::GetInstance()->GetImageCapabilityList(capList);
}

int32_t CodecImageService::Init(enum CodecImageRole role)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HdfCodecInit");
    CODEC_LOGD("servcie impl!");
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
    CODEC_LOGD("servcie impl!");
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
    CODEC_LOGD("servcie impl!");
    if (inBuffer.fenceFd >= 0) {
        close(inBuffer.fenceFd);
    }
    CHECK_AND_RETURN_RET_LOG(jpegImpl_ != nullptr, HDF_FAILURE, "jpegImpl_ is null");
    return jpegImpl_->DoJpegDecode(inBuffer, outBuffer, decInfo);
}

int32_t CodecImageService::AllocateInBuffer(CodecImageBuffer& inBuffer, uint32_t size, CodecImageRole role)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HdfCodecAllocateInBuffer");
    CODEC_LOGD("servcie impl, size [%{public}d]", size);
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

int32_t CodecImageService::DoHeifEncode(const std::vector<ImageItem>& inputImgs,
                                        const std::vector<MetaItem>& inputMetas,
                                        const std::vector<ItemRef>& refs,
                                        const SharedBuffer& output, uint32_t& filledLen)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HdfCodecDoHeifEncode");
    CODEC_LOGI("servcie impl!");
    CHECK_AND_RETURN_RET_LOG(heifEncodeImpl_ != nullptr, HDF_FAILURE, "heifEncodeImpl_ is null");
    return heifEncodeImpl_->DoHeifEncode(inputImgs, inputMetas, refs, output, filledLen);
}

int32_t CodecImageService::DoHeifDecode(const std::vector<sptr<Ashmem>>& inputs, const sptr<NativeBuffer>& output,
                                        const CodecHeifDecInfo& decInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HdfCodecDoHeifDecode");
    CODEC_LOGI("servcie impl!");
    CHECK_AND_RETURN_RET_LOG(heifDecodeImpl_ != nullptr, HDF_FAILURE, "heifDecodeImpl_ is null");
    return heifDecodeImpl_->DoHeifDecode(inputs, output, decInfo);
}
} // V2_1
} // Image
} // Codec
} // HDI
} // OHOS
