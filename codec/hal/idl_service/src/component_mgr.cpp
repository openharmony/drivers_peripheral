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
ComponentMgr::ComponentMgr()
{
    AddVendorComponent();
    AddSoftComponent();
}

ComponentMgr::~ComponentMgr()
{
    CleanComponent();
}

int32_t ComponentMgr::CreateComponentInstance(const char *componentName, const OMX_CALLBACKTYPE *callbacks,
                                              void *appData, OMX_COMPONENTTYPE **component)
{
    int32_t err = HDF_ERR_INVALID_PARAM;
    std::lock_guard<std::mutex> lk(mutex_);

   auto iter = compName2libName_.find(componentName);
    if (iter == compName2libName_.end()) {
        CODEC_LOGE("can not find component[%{public}s] in core", componentName);
        return HDF_ERR_NOT_SUPPORT;
    }
    std::string libName = iter->second;
 
    std::shared_ptr<CodecOMXCore> core;
    auto iter2 = permanentLibs_.find(libName);
    if (iter2 == permanentLibs_.end()) {
        core = std::make_shared<CodecOMXCore>();
        core->Init(libName);
    } else {
        core = iter2->second;
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
    std::lock_guard<std::mutex> lk(mutex_);
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

int32_t ComponentMgr::GetRolesForComponent(const char *componentName, std::vector<std::string> *roles)
{
    (void)roles;
    (void)componentName;
    return OMX_ErrorNone;
}

void ComponentMgr::AddVendorComponent()
{
    AddComponentByLibName("libOMX_Core.z.so", true);
    AddComponentByLibName("libomx_audio_codec.z.so", false);
}

void ComponentMgr::AddSoftComponent()
{}

void ComponentMgr::AddComponentByLibName(const char *libName, bool permanent)
{
    auto core = std::make_shared<CodecOMXCore>();
    if (core == nullptr) {
        CODEC_LOGE("fail to init CodecOMXCore");
        return;
    }
    core->Init(libName);
    std::lock_guard<std::mutex> lk(mutex_);
    std::string libNameStr(libName);
    if (permanent) {
        permanentLibs_[libNameStr] = core;
    }
    std::string name("");
    uint32_t index = 0;
    while (HDF_SUCCESS == core->ComponentNameEnum(name, index)) {
        ++index;
        compName2libName_[name] = libNameStr;
    }
}

void ComponentMgr::CleanComponent()
{
    std::lock_guard<std::mutex> lk(mutex_);
    for (size_t i = 0; i < components_.size(); i++) {
        components_[i].core->FreeHandle(components_[i].handle);
    }
    components_.clear();

   for (auto& [libName, core] : permanentLibs_) {
        core->DeInit();
    }
    permanentLibs_.clear();
}

int32_t ComponentMgr::GetCoreOfComponent(CodecOMXCore* &core, const std::string compName)
{
    std::lock_guard<std::mutex> lk(mutex_);
       auto iter = std::find_if(components_.begin(), components_.end(), [&compName](OMXComponent& comp) {
        return comp.name == compName;
    });
    if (iter == components_.end()) {
        CODEC_LOGE("can not find component[%{public}s] in core", compName.c_str());
        return HDF_FAILURE;
    }
    core = iter->core.get();
    return HDF_SUCCESS;
}
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS
