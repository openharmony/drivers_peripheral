/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <unistd.h>
#include "codec_log_wrapper.h"
#include "hdf_base.h"
#include "hdf_remote_service.h"
#include "buffer_helper.h"
#include "codec_heif_decode_service.h"

namespace OHOS {
namespace HDI {
namespace Codec {
namespace Image {
namespace V2_1 {
using GetCodecHeifDecodeHwi = ICodecHeifDecodeHwi*(*)();

CodecHeifDecodeService::CodecHeifDecodeService()
{
    isIPCMode_ = (HdfRemoteGetCallingPid() == getpid() ? false : true);
}

CodecHeifDecodeService::~CodecHeifDecodeService()
{
    heifDecodeHwi_ = nullptr;
    libHeif_ = nullptr;
}

bool CodecHeifDecodeService::LoadVendorLib()
{
    std::lock_guard<std::mutex> lk(mutex_);
    if (heifDecodeHwi_) {
        return true;
    }
    if (libHeif_ == nullptr) {
        void *handle = dlopen(CODEC_HEIF_DECODE_VDI_LIB_NAME, RTLD_LAZY);
        if (handle == nullptr) {
            CODEC_LOGE("failed to load vendor lib");
            return false;
        }
        libHeif_ = std::shared_ptr<void>(handle, dlclose);
    }
    auto func = reinterpret_cast<GetCodecHeifDecodeHwi>(dlsym(libHeif_.get(), "GetCodecHeifDecodeHwi"));
    if (func == nullptr) {
        CODEC_LOGE("failed to load symbol from vendor lib");
        return false;
    }
    heifDecodeHwi_ = func();
    if (heifDecodeHwi_ == nullptr) {
        CODEC_LOGE("failed to create heif hardware encoder");
        return false;
    }
    return true;
}

int32_t CodecHeifDecodeService::DoHeifDecode(const std::vector<sptr<Ashmem>>& inputs,
                                             const sptr<NativeBuffer>& output,
                                             const CodecHeifDecInfo& decInfo)
{
    if (!isIPCMode_) {
        return HDF_FAILURE;
    }
    if (!LoadVendorLib()) {
        return HDF_FAILURE;
    }
    sptr<NativeBuffer> registered = OHOS::Codec::Omx::ReWrap(output, true);
    return (heifDecodeHwi_->DoHeifDecode)(inputs, registered, decInfo);
}
} // V2_1
} // Image
} // Codec
} // HDI
} // OHOS