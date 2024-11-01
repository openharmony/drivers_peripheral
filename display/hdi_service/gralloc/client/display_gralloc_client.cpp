/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "display_gralloc_client.h"
#include "hdf_log.h"

#define HDF_LOG_TAG HDI_DISP_CLIENT

namespace OHOS {
namespace HDI {
namespace Display {
namespace V1_0 {
class GrallocDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    GrallocDeathRecipient(AllocatorDeathCallback func, void *data) : deathCbFun_(func), data_(data) {};
    void OnRemoteDied(const wptr<IRemoteObject> &object) override
    {
        HDF_LOGI("%{public}s: allocator service is dead", __func__);
        if (deathCbFun_ != nullptr) {
            HDF_LOGI("%{public}s: notify the death event of allocator to RS", __func__);
            deathCbFun_(data_);
        }
    }
private:
    AllocatorDeathCallback deathCbFun_;
    void *data_;
};

IDisplayGralloc *IDisplayGralloc::Get()
{
    IDisplayGralloc *instance = nullptr;
    instance = new DisplayGrallocClient();
    if (instance == nullptr) {
        HDF_LOGE("%{public}s: Can't new a DisplayGrallocClient instance", __func__);
        return nullptr;
    }
    HDF_LOGI("%{public}s: Get display gralloc client handle succ", __func__);
    return instance;
}

DisplayGrallocClient::DisplayGrallocClient() : mapperAdapter_(std::make_shared<MapperAdapter>())
{
    allocatorProxy_ = IDisplayAllocator::Get("hdi_display_gralloc_service");
    if (allocatorProxy_ == nullptr) {
        return;
    }
}

int32_t DisplayGrallocClient::RegAllocatorDeathCallback(AllocatorDeathCallback func, void *data)
{
    const sptr<IRemoteObject::DeathRecipient> recipient = new GrallocDeathRecipient(func, data);
    if (allocatorProxy_ == nullptr) {
        HDF_LOGE("%{public}s: allocatorProxy_ is null", __func__);
        return DISPLAY_FAILURE;
    }
    bool ret = allocatorProxy_->AsObject()->AddDeathRecipient(recipient);
    if (ret) {
        HDF_LOGI("%{public}s: add alocator death notify success", __func__);
        return DISPLAY_SUCCESS;
    } else {
        HDF_LOGE("%{public}s: add alocator death notify failed", __func__);
        return DISPLAY_FAILURE;
    }
}

int32_t DisplayGrallocClient::AllocMem(const AllocInfo &info, BufferHandle *&handle) const
{
    if (allocatorProxy_ == nullptr) {
        HDF_LOGE("%{public}s: allocatorProxy_ is null", __func__);
        return DISPLAY_FAILURE;
    }
    auto ret = allocatorProxy_->AllocMem(info, handle);
    return ret;
}

void DisplayGrallocClient::FreeMem(const BufferHandle &handle) const
{
    mapperAdapter_->FreeBuffer(handle);
}

void* DisplayGrallocClient::Mmap(const BufferHandle &handle) const
{
    void* data = nullptr;
    int32_t ret = mapperAdapter_->MapBuffer(handle, data);
    if (ret != DISPLAY_SUCCESS) {
        FreeMem(handle);
        HDF_LOGE("%{public}s: DisplayGrallocClient::Mmap, mapBuffer failed", __func__);
        return nullptr;
    }
    return data;
}

int32_t DisplayGrallocClient::Unmap(const BufferHandle &handle) const
{
    auto ret = mapperAdapter_->UnmapBuffer(handle);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: failed, ret %{public}d", __func__, ret);
    }
    return ret;
}

int32_t DisplayGrallocClient::FlushCache(const BufferHandle &handle) const
{
    auto ret = mapperAdapter_->FlushCache(handle);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s: failed, ret %{public}d", __func__, ret);
    }
    return ret;
}

int32_t DisplayGrallocClient::InvalidateCache(const BufferHandle &handle) const
{
    auto ret = mapperAdapter_->InvalidateCache(handle);
    if (ret != DISPLAY_SUCCESS) {
        HDF_LOGI("%{public}s: failed, ret %{public}d", __func__, ret);
    }
    return ret;
}

void* DisplayGrallocClient::MmapCache(const BufferHandle &handle) const
{
    (void)handle;
    return nullptr;
}

int32_t DisplayGrallocClient::FlushMCache(const BufferHandle &handle) const
{
    (void)handle;
    return DISPLAY_NOT_SUPPORT;
}

int32_t DisplayGrallocClient::IsSupportedAlloc(const std::vector<VerifyAllocInfo> &infos,
                                               std::vector<bool> &supporteds) const
{
    (void)infos;
    (void)supporteds;
    return DISPLAY_NOT_SUPPORT;
}
} // namespace V1_0
} // namespace Display
} // namespace HDI
} // namespace OHOS
