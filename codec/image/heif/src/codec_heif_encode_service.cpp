/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "codec_heif_encode_service.h"
#include "codec_log_wrapper.h"
#include "hdf_base.h"
#include "hdf_remote_service.h"
#include "v1_0/display_composer_type.h"
#include "v1_0/imapper.h"
#include "v1_1/imetadata.h"
#include <dlfcn.h>
#include <unistd.h>
#include <mutex>

namespace OHOS {
namespace HDI {
namespace Codec {
namespace Image {
namespace V2_0 {
using GetCodecHeifHwi = ICodecHeifHwi*(*)();

std::mutex g_mapperMtx;
std::mutex g_metaMtx;
sptr<OHOS::HDI::Display::Buffer::V1_0::IMapper> g_mapperService;
sptr<OHOS::HDI::Display::Buffer::V1_1::IMetadata> g_metaService;

sptr<OHOS::HDI::Display::Buffer::V1_0::IMapper> GetMapperService()
{
    std::lock_guard<std::mutex> lk(g_mapperMtx);
    if (g_mapperService) {
        return g_mapperService;
    }
    g_mapperService = OHOS::HDI::Display::Buffer::V1_0::IMapper::Get(true);
    if (g_mapperService) {
        CODEC_LOGI("get IMapper succ");
        return g_mapperService;
    }
    CODEC_LOGE("get IMapper failed");
    return nullptr;
}

sptr<OHOS::HDI::Display::Buffer::V1_1::IMetadata> GetMetaService()
{
    std::lock_guard<std::mutex> lk(g_metaMtx);
    if (g_metaService) {
        return g_metaService;
    }
    g_metaService = OHOS::HDI::Display::Buffer::V1_1::IMetadata::Get(true);
    if (g_metaService) {
        CODEC_LOGI("get IMetadata succ");
        return g_metaService;
    }
    CODEC_LOGE("get IMetadata failed");
    return nullptr;
}
 
void BufferDestructor(BufferHandle* handle)
{
    if (handle == nullptr) {
        return;
    }
    sptr<OHOS::HDI::Display::Buffer::V1_0::IMapper> mapper = GetMapperService();
    if (mapper == nullptr) {
        return;
    }
    sptr<NativeBuffer> buffer = new NativeBuffer();
    buffer->SetBufferHandle(handle, true);
    mapper->FreeMem(buffer);
}

bool ReWrapNativeBuffer(sptr<NativeBuffer>& buffer)
{
    if (buffer == nullptr) {
        return true;
    }
    BufferHandle* handle = buffer->Move();
    if (handle == nullptr) {
        return true;
    }
    buffer->SetBufferHandle(handle, true, BufferDestructor);
    sptr<OHOS::HDI::Display::Buffer::V1_1::IMetadata> meta = GetMetaService();
    if (meta == nullptr) {
        return false;
    }
    int32_t ret = meta->RegisterBuffer(buffer);
    if (ret != Display::Composer::V1_0::DISPLAY_SUCCESS &&
        ret != Display::Composer::V1_0::DISPLAY_NOT_SUPPORT) {
        CODEC_LOGE("RegisterBuffer failed, ret = %{public}d", ret);
        return false;
    }
    return true;
}

CodecHeifEncodeService::CodecHeifEncodeService()
{
    isIPCMode_ = (HdfRemoteGetCallingPid() == getpid() ? false : true);
}

CodecHeifEncodeService::~CodecHeifEncodeService()
{
    heifHwi_ = nullptr;
    libHeif_ = nullptr;
}

bool CodecHeifEncodeService::LoadVendorLib()
{
    std::lock_guard<std::mutex> lk(mutex_);
    if (heifHwi_) {
        return true;
    }
    if (libHeif_ == nullptr) {
        void *handle = dlopen(CODEC_HEIF_VDI_LIB_NAME, RTLD_LAZY);
        if (handle == nullptr) {
            CODEC_LOGE("failed to load vendor lib");
            return false;
        }
        libHeif_ = std::shared_ptr<void>(handle, dlclose);
    }
    auto func = reinterpret_cast<GetCodecHeifHwi>(dlsym(libHeif_.get(), "GetCodecHeifHwi"));
    if (func == nullptr) {
        CODEC_LOGE("failed to load symbol from vendor lib");
        return false;
    }
    heifHwi_ = func();
    if (heifHwi_ == nullptr) {
        CODEC_LOGE("failed to create heif hardware encoder");
        return false;
    }
    return true;
}

bool CodecHeifEncodeService::ReWrapNativeBufferInImageItem(const std::vector<ImageItem>& inputImgs)
{
    if (!isIPCMode_) {
        return true;
    }

    for (const auto &image : inputImgs) {
        if (!ReWrapNativeBuffer(const_cast<ImageItem &>(image).pixelBuffer)) {
            return false;
        }
    }

    return true;
}

int32_t CodecHeifEncodeService::DoHeifEncode(const std::vector<ImageItem>& inputImgs,
                                             const std::vector<MetaItem>& inputMetas,
                                             const std::vector<ItemRef>& refs,
                                             const SharedBuffer& output, uint32_t& filledLen)
{
    if (!LoadVendorLib()) {
        return HDF_FAILURE;
    }

    if (!ReWrapNativeBufferInImageItem(inputImgs)) {
        return HDF_FAILURE;
    }

    SharedBuffer outputToReturn = output;
    int32_t ret = (heifHwi_->DoHeifEncode)(inputImgs, inputMetas, refs, outputToReturn);
    filledLen = outputToReturn.filledLen;
    auto releaseRes = [](int fd) {
        if (fd > 0) {
            close(fd);
        }
    };
    for (auto one : inputImgs) {
        releaseRes(one.sharedProperties.fd);
    }
    for (auto one : inputMetas) {
        releaseRes(one.data.fd);
    }
    releaseRes(output.fd);
    return ret;
}
} // V2_0
} // Image
} // Codec
} // HDI
} // OHOS