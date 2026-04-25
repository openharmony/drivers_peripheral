/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "hdi_z_factory_service.h"
#include <hdf_base.h>
#include <hdf_core_log.h>
#include <dlfcn.h>
#include "key_value.h"
#include "vdi/zcodec_vdi.h"

#define HDF_LOG_TAG    hdi_z_factory_service

namespace OHOS::HDI::Codec::Zcodec::V1_0 {

extern "C" HdiZFactory *HdiZFactoryImplGetInstance(void)
{
    // LOGI(">>");
    return new (std::nothrow) HdiZFactoryService();
}

int32_t HdiZFactoryService::GetCapabilities(std::vector<HdiCapability>& caps)
{
    std::lock_guard<std::mutex> lk(mtx_);
    if (vdiHandle_ == nullptr) {
        vdiHandle_ = dlopen(SONAME, RTLD_LAZY);
    }
    if (vdiHandle_ == nullptr) {
        return HDF_FAILURE;
    }
    auto fun = reinterpret_cast<GetZCapabilityFunc>(dlsym(vdiHandle_, GET_CAPABILITY_FUNC_NAME));
    if (fun == nullptr) {
        return HDF_FAILURE;
    }
    return fun(caps);
}

int32_t HdiZFactoryService::CreateByStandard(int32_t standard, bool isEncoder,
    const sptr<HdiZCallback>& cb, const sptr<ParcelableParam>& param, sptr<HdiZComponent>& instance)
{
    std::lock_guard<std::mutex> lk(mtx_);
    if (vdiHandle_ == nullptr) {
        vdiHandle_ = dlopen(SONAME, RTLD_LAZY);
    }
    if (vdiHandle_ == nullptr) {
        return HDF_FAILURE;
    }
    auto fun = reinterpret_cast<CreateZCodecByStdFunc>(dlsym(vdiHandle_, CREATE_ZCODEC_BY_STD_FUNC));
    if (fun == nullptr) {
        HDF_LOGE("dlsym %{public}s failed, dlerror=%{public}s", CREATE_ZCODEC_BY_STD_FUNC, dlerror());
        return HDF_FAILURE;
    }
    int32_t ret = fun(static_cast<Standard>(standard), isEncoder, cb, param, instance);
    HDF_LOGI("ret=%d", ret);
    return ret;
}

int32_t HdiZFactoryService::CreateByName(const std::string& name,
    const sptr<HdiZCallback>& cb, const sptr<ParcelableParam>& param, sptr<HdiZComponent>& instance)
{
    std::lock_guard<std::mutex> lk(mtx_);
    if (vdiHandle_ == nullptr) {
        vdiHandle_ = dlopen(SONAME, RTLD_LAZY);
    }
    if (vdiHandle_ == nullptr) {
        return HDF_FAILURE;
    }
    auto fun = reinterpret_cast<CreateZCodecByNameFunc>(dlsym(vdiHandle_, CREATE_ZCODEC_BY_NAME_FUNC));
    if (fun == nullptr) {
        return HDF_FAILURE;
    }
    int32_t ret = fun(name, cb, param, instance);
    return ret;
}

HdiZFactoryService::~HdiZFactoryService()
{
    std::lock_guard<std::mutex> lk(mtx_);
    if (vdiHandle_) {
        dlclose(vdiHandle_);
        vdiHandle_ = nullptr;
    }
}

}
