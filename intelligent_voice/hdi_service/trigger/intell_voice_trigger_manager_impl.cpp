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
#include "intell_voice_trigger_manager_impl.h"

#include <dlfcn.h>

#include "hdf_base.h"
#include "intell_voice_log.h"
#include "intell_voice_trigger_adapter_impl.h"

#undef HDF_LOG_TAG
#define HDF_LOG_TAG "TriggerManagerImpl"

using namespace OHOS::HDI::IntelligentVoice::Trigger::V1_0;

namespace OHOS {
namespace IntelligentVoice {
namespace Trigger {
extern "C" IIntellVoiceTriggerManager *IntellVoiceTriggerManagerImplGetInstance(void)
{
    return new (std::nothrow) IntellVoiceTriggerManagerImpl();
}

extern "C" void IntellVoiceTriggerManagerImplRelease(IIntellVoiceTriggerManager *mgr)
{
    INTELLIGENT_VOICE_LOGI("enter");
    if (mgr == nullptr) {
        INTELLIGENT_VOICE_LOGE("mgr is nullptr");
        return;
    }
    delete mgr;
}

int32_t IntellVoiceTriggerManagerImpl::LoadVendorLib()
{
    std::string error;
    const char *vendorLibPath = HDF_LIBRARY_FULL_PATH("libvendor_intell_voice_trigger");
    triggerManagerPriv_.handle = dlopen(vendorLibPath, RTLD_LAZY);
    if (triggerManagerPriv_.handle == nullptr) {
        error = dlerror();
        INTELLIGENT_VOICE_LOGE("load path%{public}s, dlopen err=%{public}s", vendorLibPath, error.c_str());
        return HDF_FAILURE;
    }

    (void)dlerror(); // clear existing error

    triggerManagerPriv_.getTriggerManagerHalInst = reinterpret_cast<GetTriggerManagerHalInstFunc>(dlsym(
        triggerManagerPriv_.handle, "GetIntellVoiceTriggerHalInst"));
    if (triggerManagerPriv_.getTriggerManagerHalInst == nullptr) {
        error = dlerror();
        INTELLIGENT_VOICE_LOGE("dlsym GetIntellVoiceEngineManagerHalInst err=%{public}s", error.c_str());
        dlclose(triggerManagerPriv_.handle);
        triggerManagerPriv_.handle = nullptr;
        return HDF_FAILURE;
    }

    INTELLIGENT_VOICE_LOGI("load vendor lib success");
    return HDF_SUCCESS;
}

void IntellVoiceTriggerManagerImpl::UnloadVendorLib()
{
    if (triggerManagerPriv_.handle != nullptr) {
        dlclose(triggerManagerPriv_.handle);
        triggerManagerPriv_.handle = nullptr;
    }
}

IntellVoiceTriggerManagerImpl::IntellVoiceTriggerManagerImpl()
{
    if (LoadVendorLib() == static_cast<int32_t>(HDF_SUCCESS)) {
        inst_ = triggerManagerPriv_.getTriggerManagerHalInst();
        if (inst_ == nullptr) {
            INTELLIGENT_VOICE_LOGE("failed to get trigger manager hal inst");
        }
    }
}

IntellVoiceTriggerManagerImpl::~IntellVoiceTriggerManagerImpl()
{
    UnloadVendorLib();
    inst_ = nullptr;
    halAdapters_.clear();
}

int32_t IntellVoiceTriggerManagerImpl::LoadAdapter(const IntellVoiceTriggerAdapterDsecriptor &descriptor,
    sptr<OHOS::HDI::IntelligentVoice::Trigger::V1_0::IIntellVoiceTriggerAdapter> &adapter)
{
    return LoadIntellVoiceTriggerAdapter(descriptor, adapter);
}

int32_t IntellVoiceTriggerManagerImpl::LoadAdapter_V1_1(const IntellVoiceTriggerAdapterDsecriptor &descriptor,
    sptr<OHOS::HDI::IntelligentVoice::Trigger::V1_1::IIntellVoiceTriggerAdapter> &adapter)
{
    return LoadIntellVoiceTriggerAdapter(descriptor, adapter);
}

template<typename T>
int32_t IntellVoiceTriggerManagerImpl::LoadIntellVoiceTriggerAdapter(
    const IntellVoiceTriggerAdapterDsecriptor &descriptor, sptr<T> &adapter)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (inst_ == nullptr) {
        INTELLIGENT_VOICE_LOGE("inst is nullptr");
        return HDF_FAILURE;
    }

    auto it = halAdapters_.find(descriptor.adapterName);
    if (it != halAdapters_.end()) {
        INTELLIGENT_VOICE_LOGW("adapter %{public}s already exist", descriptor.adapterName.c_str());
        inst_->UnloadAdapter(descriptor);
        it->second = nullptr;
        halAdapters_.erase(it);
    }

    std::unique_ptr<ITrigger> triggerAdapterDevice = nullptr;
    int32_t ret = inst_->LoadAdapter(descriptor, triggerAdapterDevice);
    if (triggerAdapterDevice == nullptr) {
        INTELLIGENT_VOICE_LOGE("get adapter device from hal failed, ret:%{public}d", ret);
        return HDF_FAILURE;
    }

    adapter = sptr<T>(new (std::nothrow) IntellVoiceTriggerAdapterImpl(std::move(triggerAdapterDevice)));
    if (adapter == nullptr) {
        INTELLIGENT_VOICE_LOGE("new adapter failed");
        return HDF_ERR_MALLOC_FAIL;
    }

    halAdapters_[descriptor.adapterName] = adapter;
    return HDF_SUCCESS;
}

int32_t IntellVoiceTriggerManagerImpl::UnloadAdapter(const IntellVoiceTriggerAdapterDsecriptor &descriptor)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (inst_ == nullptr) {
        INTELLIGENT_VOICE_LOGE("inst is nullptr");
        return HDF_FAILURE;
    }

    auto adapter = halAdapters_.find(descriptor.adapterName);
    if (adapter == halAdapters_.end()) {
        INTELLIGENT_VOICE_LOGE("there is no %{public}s adapter", descriptor.adapterName.c_str());
        return HDF_ERR_INVALID_OBJECT;
    }

    int32_t ret = inst_->UnloadAdapter(descriptor);
    adapter->second = nullptr;
    halAdapters_.erase(adapter);
    return ret;
}
}
}
}