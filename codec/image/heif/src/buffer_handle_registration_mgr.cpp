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
#include "buffer_handle_registration_mgr.h"
#include "codec_log_wrapper.h"

namespace OHOS {
namespace HDI {
namespace Codec {
namespace Image {
namespace V2_1 {
std::mutex BufferHandleRegistrationMgr::g_mapperMtx;
std::mutex BufferHandleRegistrationMgr::g_metaMtx;
sptr<OHOS::HDI::Display::Buffer::V1_0::IMapper> BufferHandleRegistrationMgr::g_mapperService;
sptr<OHOS::HDI::Display::Buffer::V1_1::IMetadata> BufferHandleRegistrationMgr::g_metaService;

sptr<OHOS::HDI::Display::Buffer::V1_0::IMapper> BufferHandleRegistrationMgr::GetMapperService()
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

sptr<OHOS::HDI::Display::Buffer::V1_1::IMetadata> BufferHandleRegistrationMgr::GetMetaService()
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
 
void BufferHandleRegistrationMgr::BufferDestructor(BufferHandle* handle)
{
    if (handle == nullptr) {
        return;
    }
    sptr<OHOS::HDI::Display::Buffer::V1_0::IMapper> mapper = GetMapperService();
    if (mapper == nullptr) {
        return;
    }
    sptr<OHOS::HDI::Base::NativeBuffer> buffer = new OHOS::HDI::Base::NativeBuffer();
    buffer->SetBufferHandle(handle, true);
    mapper->FreeMem(buffer);
}

bool BufferHandleRegistrationMgr::ReWrapNativeBuffer(sptr<OHOS::HDI::Base::NativeBuffer>& buffer)
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
} // V2_1
} // Image
} // Codec
} // HDI
} // OHOS