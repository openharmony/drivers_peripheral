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

#include <dlfcn.h>
#include <poll.h>
#include <securec.h>
#include <unistd.h>
#include "codec_jpeg_core.h"
#include "codec_log_wrapper.h"
#include "hdf_base.h"

namespace OHOS {
namespace HDI {
namespace Codec {
namespace Image {
CodecJpegCore::~CodecJpegCore()
{
    if (libHandle_ != nullptr) {
        dlclose(libHandle_);
        libHandle_ = nullptr;
    }
}

void CodecJpegCore::NotifyPowerOn()
{
    CHECK_AND_RETURN_RET_LOG(JpegHwi_ != nullptr, , "JpegHwi_ is null");
    JpegHwi_->NotifyPowerOn();
}

void CodecJpegCore::AddVendorLib()
{
    CODEC_LOGI("start load jpeg dependency library!");
    libHandle_ = dlopen(CODEC_JPEG_VDI_LIB_NAME, RTLD_LAZY);
    if (libHandle_ == nullptr) {
        CODEC_LOGE("Failed to dlopen %{public}s, error [%{public}s]", CODEC_JPEG_VDI_LIB_NAME, dlerror());
        return;
    }

    getCodecJpegHwi_= reinterpret_cast<GetCodecJpegHwi>(dlsym(libHandle_, "GetCodecJpegHwi"));
    if (getCodecJpegHwi_ == NULL) {
        CODEC_LOGE("Failed to dlsym GetCodecJpegHwi");
        dlclose(libHandle_);
        libHandle_ = nullptr;
        return;
    }

    JpegHwi_ =  getCodecJpegHwi_();
    if (JpegHwi_ == nullptr) {
        CODEC_LOGE("run GetCodecJpegHwi error!");
        dlclose(libHandle_);
        libHandle_ = nullptr;
        return;
    }
    CODEC_LOGI("load dependency library success!");
}

int32_t CodecJpegCore::JpegInit()
{
    if (JpegHwi_ == nullptr) {
        AddVendorLib();
    }
    CHECK_AND_RETURN_RET_LOG(JpegHwi_ != nullptr, HDF_FAILURE, "JpegHwi_ is null");
    return (JpegHwi_->JpegInit)();
}

int32_t CodecJpegCore::JpegDeInit()
{
    CHECK_AND_RETURN_RET_LOG(JpegHwi_ != nullptr, HDF_FAILURE, "JpegHwi_ is null");
    return (JpegHwi_->JpegDeInit)();
}

int32_t CodecJpegCore::AllocateInBuffer(BufferHandle **buffer, uint32_t size)
{
    CHECK_AND_RETURN_RET_LOG(JpegHwi_ != nullptr, HDF_FAILURE, "JpegHwi_ is null");
    return (JpegHwi_->AllocateInBuffer)(buffer, size);
}

int32_t CodecJpegCore::FreeInBuffer(BufferHandle *buffer)
{
    CHECK_AND_RETURN_RET_LOG(JpegHwi_ != nullptr, HDF_FAILURE, "JpegHwi_ is null");
    return (JpegHwi_->FreeInBuffer)(buffer);
}

int32_t CodecJpegCore::DoDecode(BufferHandle *buffer, BufferHandle *outBuffer,
    const V2_1::CodecJpegDecInfo *decInfo)
{
    CHECK_AND_RETURN_RET_LOG(JpegHwi_ != nullptr, HDF_FAILURE, "JpegHwi_ is null");
    CodecJpegDecInfo *vdiDecInfo = reinterpret_cast<CodecJpegDecInfo *>(const_cast<V2_1::CodecJpegDecInfo *>(decInfo));
    return (JpegHwi_->DoJpegDecode)(buffer, outBuffer, vdiDecInfo);
}
} // Image
} // Codec
} // HDI
} // OHOS
