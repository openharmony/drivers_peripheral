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
#include <dlfcn.h>
#include "intell_voice_trigger_manager_impl.h"
#include "hdf_base.h"
#include "intell_voice_log.h"
#include "intell_voice_trigger_adapter_impl.h"

#define LOG_TAG "TriggerManagerImpl"

using namespace OHOS::HDI::IntelligentVoice::Trigger::V1_0;

namespace OHOS {
namespace IntellVoiceTrigger {
extern "C" IIntellVoiceTriggerManager *IntellVoiceTriggerManagerImplGetInstance(void)
{
    return new (std::nothrow) IntellVoiceTriggerManagerImpl();
}

int32_t IntellVoiceTriggerManagerImpl::LoadVendorLib()
{
    char *error = nullptr;
    const char *vendorLibPath = HDF_LIBRARY_FULL_PATH("libvendor_intell_voice_trigger");
    triggerManagerPriv_.handle = dlopen(vendorLibPath, RTLD_LAZY);
    if (triggerManagerPriv_.handle == nullptr) {
        error = dlerror();
        INTELL_VOICE_LOG_ERROR("load path%{public}s, dlopen err=%{public}s", vendorLibPath, error);
        return -1;
    }

    (void)dlerror(); // clear existing error

    triggerManagerPriv_.getTriggerManagerHalInst = reinterpret_cast<GetTriggerManagerHalInstFunc>(dlsym(
        triggerManagerPriv_.handle, "GetIntellVoiceTriggerHalInst"));
    if (triggerManagerPriv_.getTriggerManagerHalInst == nullptr) {
        error = dlerror();
        INTELL_VOICE_LOG_ERROR("dlsym GetIntellVoiceEngineManagerHalInst err=%{public}s", error);
        dlclose(triggerManagerPriv_.handle);
        triggerManagerPriv_.handle = nullptr;
        return -1;
    }

    INTELL_VOICE_LOG_INFO("load vendor lib success");
    return 0;
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
    if (LoadVendorLib() == 0) {
        inst_ = triggerManagerPriv_.getTriggerManagerHalInst();
        if (inst_ == nullptr) {
            INTELL_VOICE_LOG_ERROR("failed to get trigger manager hal inst");
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
     sptr<IIntellVoiceTriggerAdapter> &adapter)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (inst_ == nullptr) {
        INTELL_VOICE_LOG_ERROR("inst is nullptr");
        return HDF_FAILURE;
    }

    if (halAdapters_.find(descriptor.adapterName) != halAdapters_.end()) {
        INTELL_VOICE_LOG_ERROR("adapter %{public}s already exist", descriptor.adapterName.c_str());
        return HDF_ERR_INVALID_OBJECT;
    }

    std::unique_ptr<ITrigger> triggerAdapterDevice = nullptr;
    int32_t ret = inst_->LoadAdapter(descriptor, triggerAdapterDevice);
    if (triggerAdapterDevice == nullptr) {
        INTELL_VOICE_LOG_ERROR("get adapter device from hal failed, ret:%{public}d", ret);
        return HDF_FAILURE;
    }

    adapter = sptr<IIntellVoiceTriggerAdapter>(new (std::nothrow) IntellVoiceTriggerAdapterImpl(
        std::move(triggerAdapterDevice)));
    if (adapter == nullptr) {
        INTELL_VOICE_LOG_ERROR("new adapter failed");
        return HDF_ERR_MALLOC_FAIL;
    }

    halAdapters_[descriptor.adapterName] = adapter;
    return HDF_SUCCESS;
}

int32_t IntellVoiceTriggerManagerImpl::UnloadAdapter(const IntellVoiceTriggerAdapterDsecriptor &descriptor)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (inst_ == nullptr) {
        INTELL_VOICE_LOG_ERROR("inst is nullptr");
        return HDF_FAILURE;
    }

    auto adapter = halAdapters_.find(descriptor.adapterName);
    if (adapter == halAdapters_.end()) {
        INTELL_VOICE_LOG_ERROR("there is no %{public}s adapter", descriptor.adapterName.c_str());
        return HDF_ERR_INVALID_OBJECT;
    }

    int32_t ret = inst_->UnloadAdapter(descriptor);
    adapter->second = nullptr;
    halAdapters_.erase(adapter);
    return ret;
}
} // IntellVoiceTrigger
} // OHOS