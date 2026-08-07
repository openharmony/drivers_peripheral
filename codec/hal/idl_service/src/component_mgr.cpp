/*
 * Copyright (c) 2022-2023 Shenzhen Kaihong DID Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "component_mgr.h"
#include <hdf_base.h>
#include "codec_log_wrapper.h"
namespace OHOS {
namespace Codec {
namespace Omx {

ComponentMgr& ComponentMgr::GetInstance()
{
    static ComponentMgr mgr;
    return mgr;
}

ComponentMgr::ComponentMgr()
{
    CODEC_LOGI("enter");
    AddVendorComponent();
    AddSoftComponent();
}

ComponentMgr::~ComponentMgr()
{
    CleanComponent();
}

int32_t ComponentMgr::CreateComponentInstance(const std::string &componentName, const OMX_CALLBACKTYPE *callbacks,
                                              void *appData, OMX_COMPONENTTYPE **component)
{
    int32_t err = HDF_ERR_INVALID_PARAM;

    auto iter = compName2libName_.find(componentName);
    if (iter == compName2libName_.end()) {
        CODEC_LOGE("can not find component[%{public}s] in core", componentName.c_str());
        return HDF_ERR_NOT_SUPPORT;
    }
    std::string libName = iter->second;
    bool permanent = isLibPermanent_[libName];

    std::shared_ptr<CodecOMXCore> core;
    if (permanent) {
        auto iter2 = permanentLibs_.find(libName);
        if (iter2 == permanentLibs_.end()) {
            CODEC_LOGE("cannot find %{public}s in permanentLibs_", libName.c_str());
            return HDF_FAILURE;
        }
        core = iter2->second;
    } else {
        auto iter2 = nonPermanentLibs_.find(libName);
        if (iter2 != nonPermanentLibs_.end()) {
            core = iter2->second.lock();
        }
        if (core == nullptr) {
            core = CodecOMXCore::Create(libName);
            if (core == nullptr) {
                CODEC_LOGE("fail to create CodecOMXCore for %{public}s", libName.c_str());
                return HDF_FAILURE;
            }
            nonPermanentLibs_[libName] = core;
        }
    }

    if (core == nullptr) {
        CODEC_LOGE("can not find core of comonentName");
        return HDF_FAILURE;
    }
    OMX_HANDLETYPE handle = nullptr;
    std::string name(componentName);
    err = core->GetHandle(handle, name, appData, *callbacks);
    if (err == OMX_ErrorNone && handle) {
        OMXComponent comp;
        comp.name = name;
        comp.core = core;
        *component = reinterpret_cast<OMX_COMPONENTTYPE *>(handle);
        comp.handle = handle;
        components_.push_back(comp);
    }
    return err;
}

int32_t ComponentMgr::DeleteComponentInstance(OMX_COMPONENTTYPE *component)
{
    int32_t err = OMX_ErrorInvalidComponent;
    for (size_t i = 0; i < components_.size(); i++) {
        if (components_[i].handle == component) {
            err = components_[i].core->FreeHandle(components_[i].handle);
            components_.erase(components_.begin() + i);
            break;
        }
    }
    return err;
}

int32_t ComponentMgr::GetRolesForComponent(const std::string &componentName, std::vector<std::string> &roles)
{
    auto iter = std::find_if(components_.begin(), components_.end(), [&componentName](OMXComponent& comp) {
        return comp.name == componentName;
    });
    if (iter == components_.end()) {
        CODEC_LOGE("can not find component[%{public}s]", componentName.c_str());
        return HDF_FAILURE;
    }
    return iter->core->GetRolesOfComponent(componentName, roles);
}

void ComponentMgr::AddVendorComponent()
{
    AddComponentByLibName("libOMX_Core.z.so", true);
    AddComponentByLibName("libomx_audio_codec.z.so", false);
}

void ComponentMgr::AddSoftComponent()
{}

void ComponentMgr::AddComponentByLibName(const std::string &libName, bool permanent)
{
    std::lock_guard<std::mutex> autoLock(mutex_);
    auto core = CodecOMXCore::Create(libName);
    if (core == nullptr) {
        CODEC_LOGE("fail to create CodecOMXCore");
        return;
    }

    isLibPermanent_[libName] = permanent;
    if (permanent) {
        permanentLibs_[libName] = core;
    }

    std::string name("");
    uint32_t index = 0;
    while (HDF_SUCCESS == core->ComponentNameEnum(name, index)) {
        ++index;
        compName2libName_[name] = libName;
    }
}

void ComponentMgr::CleanComponent()
{
    std::lock_guard<std::mutex> lk(mutex_);
    for (size_t i = 0; i < components_.size(); i++) {
        components_[i].core->FreeHandle(components_[i].handle);
    }
    components_.clear();
    permanentLibs_.clear();
    nonPermanentLibs_.clear();
}

}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS
