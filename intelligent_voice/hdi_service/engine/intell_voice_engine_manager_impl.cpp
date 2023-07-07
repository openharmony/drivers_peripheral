/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "intell_voice_engine_manager_impl.h"

#include <dlfcn.h>
#include <cinttypes>
#include "hdf_base.h"
#include "intell_voice_log.h"
#include "intell_voice_engine_adapter_impl.h"

#undef HDF_LOG_TAG
#define HDF_LOG_TAG "IntelligentVoiceEngineManagerImpl"

using namespace OHOS::HDI::IntelligentVoice::Engine::V1_0;

namespace OHOS {
namespace IntelligentVoice {
namespace Engine {
extern "C" IIntellVoiceEngineManager *IntellVoiceEngineManagerImplGetInstance(void)
{
    return new (std::nothrow) IntellVoiceEngineManagerImpl();
}

int32_t IntellVoiceEngineManagerImpl::LoadVendorLib()
{
    std::string error;
    const char *vendorLibPath = HDF_LIBRARY_FULL_PATH("libvendor_intell_voice_engine");
    engineManagerPriv_.handle = dlopen(vendorLibPath, RTLD_LAZY);
    if (engineManagerPriv_.handle == nullptr) {
        error = dlerror();
        INTELLIGENT_VOICE_LOGE("load path%{public}s, dlopen err=%{public}s", vendorLibPath, error.c_str());
        return HDF_FAILURE;
    }

    (void)dlerror(); // clear existing error

    engineManagerPriv_.getEngineManagerHalInst = reinterpret_cast<GetEngineManagerHalInstFunc>(dlsym(
        engineManagerPriv_.handle, "GetIntellVoiceEngineManagerHalInst"));
    if (engineManagerPriv_.getEngineManagerHalInst == nullptr) {
        error = dlerror();
        INTELLIGENT_VOICE_LOGE("dlsym GetIntellVoiceEngineManagerHalInst err=%{public}s", error.c_str());
        dlclose(engineManagerPriv_.handle);
        engineManagerPriv_.handle = nullptr;
        return HDF_FAILURE;
    }

    INTELLIGENT_VOICE_LOGI("load vendor lib success");

    return HDF_SUCCESS;
}

void IntellVoiceEngineManagerImpl::UnloadVendorLib()
{
    if (engineManagerPriv_.handle != nullptr) {
        dlclose(engineManagerPriv_.handle);
        engineManagerPriv_.handle = nullptr;
    }
}

IntellVoiceEngineManagerImpl::IntellVoiceEngineManagerImpl()
{
    if (LoadVendorLib() == static_cast<int32_t>(HDF_SUCCESS)) {
        inst_ = engineManagerPriv_.getEngineManagerHalInst();
    }
}

IntellVoiceEngineManagerImpl::~IntellVoiceEngineManagerImpl()
{
    UnloadVendorLib();
    adapters_.clear();
    inst_ = nullptr;
}

int32_t IntellVoiceEngineManagerImpl::GetAdapterDescriptors(std::vector<IntellVoiceEngineAdapterDescriptor>& descs)
{
    return HDF_SUCCESS;
}

int32_t IntellVoiceEngineManagerImpl::CreateAdapter(
    const IntellVoiceEngineAdapterDescriptor &descriptor, sptr<IIntellVoiceEngineAdapter> &adapter)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (inst_ == nullptr) {
        INTELLIGENT_VOICE_LOGE("inst is nullptr");
        return HDF_FAILURE;
    }

    std::unique_ptr<IEngine> engine = nullptr;
    inst_->CreateAdapter(descriptor, engine);
    if (engine == nullptr) {
        INTELLIGENT_VOICE_LOGE("get adapter device from hal failed");
        return HDF_FAILURE;
    }

    adapter = sptr<IIntellVoiceEngineAdapter>(new (std::nothrow) IntellVoiceEngineAdapterImpl(std::move(engine)));
    if (adapter == nullptr) {
        INTELLIGENT_VOICE_LOGE("malloc intell voice adapter server failed ");
        return HDF_ERR_MALLOC_FAIL;
    }

    adapters_.insert(std::make_pair(descriptor.adapterType, adapter));
    return HDF_SUCCESS;
}

int32_t IntellVoiceEngineManagerImpl::ReleaseAdapter(const IntellVoiceEngineAdapterDescriptor &descriptor)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (inst_ == nullptr) {
        INTELLIGENT_VOICE_LOGE("inst is nullptr");
        return HDF_FAILURE;
    }

    auto it = adapters_.find(descriptor.adapterType);
    if (it == adapters_.end()) {
        INTELLIGENT_VOICE_LOGW("can not find adapter, %{public}d", descriptor.adapterType);
        return HDF_SUCCESS;
    }

    inst_->ReleaseAdapter(descriptor);

    it->second = nullptr;
    adapters_.erase(it);
    return HDF_SUCCESS;
}
}
}
}
