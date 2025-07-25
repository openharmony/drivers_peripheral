/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "buffer_helper.h"
#include <mutex>
#include <unistd.h>
#include "v1_0/imapper.h"
#include "v1_1/imetadata.h"
#include "v1_0/display_composer_type.h"
#include "codec_log_wrapper.h"

namespace OHOS::Codec::Omx {

std::shared_ptr<UniqueFd> UniqueFd::Create(int fd, bool transferOwnership)
{
    int finalFd = transferOwnership ? fd : dup(fd);
    if (finalFd < 0) {
        return nullptr;
    }
    return std::shared_ptr<UniqueFd>(new UniqueFd(finalFd));
}

UniqueFd::UniqueFd(int fd) : fd_(fd) {}

UniqueFd::~UniqueFd()
{
    if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
    }
}

int UniqueFd::Get()
{
    return fd_;
}

int UniqueFd::Release()
{
    int fd = fd_;
    fd_ = -1;
    return fd;
}

std::mutex g_mapperMtx;
sptr<OHOS::HDI::Display::Buffer::V1_0::IMapper> g_mapperService;

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

std::mutex g_metaMtx;
sptr<OHOS::HDI::Display::Buffer::V1_1::IMetadata> g_metaService;

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
        CODEC_LOGE("destruct bufferHandle failed: unable to get mapper");
        return;
    }
    sptr<NativeBuffer> buffer = sptr<NativeBuffer>::MakeSptr();
    if (buffer == nullptr) {
        CODEC_LOGE("destruct bufferHandle failed: unable to get nativeBuffer");
        return;
    }
    buffer->SetBufferHandle(handle, true);
    mapper->FreeMem(buffer);
}

sptr<NativeBuffer> ReWrap(const sptr<NativeBuffer>& src, bool isIpcMode)
{
    if (!isIpcMode) {
        return src;
    }
    CHECK_AND_RETURN_RET((src != nullptr), nullptr);
    BufferHandle* handle = src->Move();
    CHECK_AND_RETURN_RET((handle != nullptr), nullptr);
    sptr<NativeBuffer> buffer = sptr<NativeBuffer>::MakeSptr();
    CHECK_AND_RETURN_RET((buffer != nullptr), nullptr);
    buffer->SetBufferHandle(handle, true, BufferDestructor);
    sptr<OHOS::HDI::Display::Buffer::V1_1::IMetadata> meta = GetMetaService();
    CHECK_AND_RETURN_RET((meta != nullptr), nullptr);
    int32_t ret = meta->RegisterBuffer(buffer);
    if (ret != OHOS::HDI::Display::Composer::V1_0::DISPLAY_SUCCESS &&
        ret != OHOS::HDI::Display::Composer::V1_0::DISPLAY_NOT_SUPPORT) {
        CODEC_LOGE("RegisterBuffer failed, ret = %{public}d", ret);
        return nullptr;
    }
    return buffer;
}

int32_t Mmap(const sptr<NativeBuffer>& handle)
{
    sptr<OHOS::HDI::Display::Buffer::V1_0::IMapper> mapper = GetMapperService();
    if (mapper == nullptr) {
        return HDF_FAILURE;
    }
    return mapper->Mmap(handle);
}

int32_t Unmap(const sptr<NativeBuffer>& handle)
{
    sptr<OHOS::HDI::Display::Buffer::V1_0::IMapper> mapper = GetMapperService();
    if (mapper == nullptr) {
        return HDF_FAILURE;
    }
    return mapper->Unmap(handle);
}
}