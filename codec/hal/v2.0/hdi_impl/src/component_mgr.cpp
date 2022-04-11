/*
 * Copyright 2022 Shenzhen Kaihong DID Co., Ltd.
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

#include <cstring>
#include <dlfcn.h>
#include <hdf_log.h>
#include <memory.h>
#include <securec.h>

#include "component_mgr.h"
#define HDF_LOG_TAG codec_hdi_server
constexpr int COMPONENT_NAME_MAX_LEN = 128;
#ifdef __ARM64__
constexpr char DRIVER_PATH[] = "/vendor/lib64";
#else
constexpr char DRIVER_PATH[] = "/vendor/lib";
#endif

namespace OHOS {
namespace Codec {
namespace Omx {
ComponentMgr::ComponentMgr() : loadLibSuc_(false), currentComType_(NULL), currentComName_("")
{
    AddVendorComponent();
    AddSoftComponent();
}

bool ComponentMgr::IsOMXHandleValid(OMX_COMPONENTTYPE *handle)
{
    for (size_t i = 0; i < componentTypePointAndObjectPoint_.size(); i++) {
        if (handle == componentTypePointAndObjectPoint_[i].componentType) {
            return true;
        }
    }
    HDF_LOGE("%{public}s can not find handle [0x%{public}p]", __func__, handle);
    return false;
}

ComponentMgr::~ComponentMgr()
{
    CleanComponent();
}

int32_t ComponentMgr::CreateComponentInstance(const char *componentName, const OMX_CALLBACKTYPE *callbacks,
                                              void *appData, OMX_COMPONENTTYPE **component)
{
    HDF_LOGI("ComponentMgr::CreateComponentInstance:%{public}s", componentName);
    *component = NULL;
    int32_t err = OMX_ErrorMax;

    std::vector<ComponentNameAndObjectPoint>::iterator it;
    for (it = componentNameAndObjectPoint_.begin(); it != componentNameAndObjectPoint_.end(); ++it) {
        if (strcmp(componentName, it->componentName.c_str()) != 0) {
            continue;
        }
        if (it->omxComponentMgr == nullptr) {
            break;
        }
        err = it->omxComponentMgr->CreateComponentInstance(componentName, callbacks, appData, component);
        std::vector<std::string> roles;
        it->omxComponentMgr->GetRolesForComponent(componentName, &roles);
        if (err != OMX_ErrorNone) {
            HDF_LOGE("%{public}s CreateComponentInstance error %{public}x", __func__, err);
            break;
        }
        ComponentTypePointAndObjectPoint point;
        point.componentType = *component;
        point.omxComponentMgr = it->omxComponentMgr;
        componentTypePointAndObjectPoint_.push_back(point);
        currentComType_ = *component;
        currentComName_ = componentName;
    }
    return err;
}

int32_t ComponentMgr::DeleteComponentInstance(OMX_COMPONENTTYPE *component)
{
    std::vector<ComponentTypePointAndObjectPoint>::iterator it;
    for (it = componentTypePointAndObjectPoint_.begin(); it != componentTypePointAndObjectPoint_.end(); ++it) {
        if (it->componentType == component) {
            IComponentMgr *pOMXComponentMgr = it->omxComponentMgr;
            componentTypePointAndObjectPoint_.erase(it);
            if (pOMXComponentMgr != nullptr) {
                return pOMXComponentMgr->DeleteComponentInstance(component);
            }
            return OMX_ErrorMax;
        }
    }
    return OMX_ErrorMax;
}

int32_t ComponentMgr::EnumerateComponentsByIndex(uint32_t index, char *componentName, size_t componentNameSize)
{
    size_t componentNum = componentNameAndObjectPoint_.size();
    if (index >= componentNum) {
        HDF_LOGE("%{public}s index [%{public}d] > componentNum [%{public}d]", __func__, index, componentNum);
        return OMX_ErrorInvalidComponentName;
    }
    std::string &compName = componentNameAndObjectPoint_[index].componentName;
    if (componentNameSize < compName.length() + 1) {
        HDF_LOGE("%{public}s componentNameSize [%{public}d] is too short", __func__, index);
        return OMX_ErrorMax;
    }
    errno_t ret = strcpy_s(componentName, componentNameSize, compName.c_str());
    if (ret != EOK) {
        HDF_LOGE("%{public}s strcpy_s return error", __func__);
        return OMX_ErrorInsufficientResources;
    }

    return OMX_ErrorNone;
}

int32_t ComponentMgr::GetRolesForComponent(const char *componentName, std::vector<std::string> *roles)
{
    if (roles == NULL) {
        return OMX_ErrorMax;
    }
    roles->clear();
    std::vector<ComponentNameAndObjectPoint>::iterator it;
    for (it = componentNameAndObjectPoint_.begin(); it != componentNameAndObjectPoint_.end(); ++it) {
        if (strcmp(componentName, it->componentName.c_str()) != 0) {
            continue;
        }
        if (it->omxComponentMgr == nullptr) {
            HDF_LOGE("%{public}s omxComponentMgr is null", __func__);
            return OMX_ErrorInvalidComponentName;
        }

        int32_t err = it->omxComponentMgr->GetRolesForComponent(componentName, roles);
        return err;
    }
    return OMX_ErrorInvalidComponentName;
}

void ComponentMgr::AddVendorComponent()
{
    AddComponentByLibName("libOMX_Pluginhw.z.so");
}

void ComponentMgr::AddSoftComponent()
{}

void ComponentMgr::AddComponentByLibName(const char *libName)
{
    char path[PATH_MAX + 1] = {0};

    if (snprintf_s(path, sizeof(path), sizeof(path) - 1, "%s/%s", DRIVER_PATH, libName) < 0) {
        HDF_LOGE("%{public}s: snprintf_s failed", __func__);
        return;
    }
    void *libHandle = NULL;
    libHandle = dlopen(path, RTLD_LAZY);
    if (libHandle == NULL) {
        HDF_LOGE("ComponentMgr::AddComponentByLibName:libHandle is NULL");
        return;
    }
    typedef IComponentMgr *(*CreateOMXPluginFunc)();
    CreateOMXPluginFunc createOMXPlugin = (CreateOMXPluginFunc)dlsym(libHandle, "createOMXPlugin");

    IComponentMgr *plugin = nullptr;
    if (createOMXPlugin != nullptr) {
        plugin = (*createOMXPlugin)();
    }
    if (plugin != nullptr) {
        ComponentInfo info;
        info.omxComponent = plugin;
        info.LibHandle = libHandle;
        componentsList_.push_back(info);
        AddComponentByInstance(plugin);
        loadLibSuc_ = true;
    } else {
        dlclose(libHandle);
    }
}

void ComponentMgr::AddComponentByInstance(IComponentMgr *pMrg)
{
    uint32_t index = 0;
    char name[COMPONENT_NAME_MAX_LEN];
    bool exists = false;
    int32_t err;
    while ((err = pMrg->EnumerateComponentsByIndex(index++, name, sizeof(name))) == OMX_ErrorNone) {
        std::vector<ComponentNameAndObjectPoint>::iterator it;
        for (it = componentNameAndObjectPoint_.begin(); it != componentNameAndObjectPoint_.end(); ++it) {
            if (strcmp(name, it->componentName.c_str()) == 0) {
                exists = true;
                break;
            }
        }
        if (exists) {
            exists = false;
            continue;
        }
        HDF_LOGI("ComponentMgr::AddComponentByInstance:component name=%{public}s", name);
        ComponentNameAndObjectPoint point;
        point.componentName = name;
        point.omxComponentMgr = pMrg;
        componentNameAndObjectPoint_.push_back(point);
    }
}

void ComponentMgr::CleanComponent()
{
    componentNameAndObjectPoint_.clear();
    componentTypePointAndObjectPoint_.clear();

    typedef void (*DestroyOMXPluginFunc)(IComponentMgr *);
    for (const ComponentInfo &comInfo : componentsList_) {
        DestroyOMXPluginFunc destroyOMXPlugin = (DestroyOMXPluginFunc)dlsym(comInfo.LibHandle, "destroyOMXPlugin");
        if (destroyOMXPlugin != nullptr) {
            destroyOMXPlugin(comInfo.omxComponent);
        } else {
            delete comInfo.omxComponent;
        }
        dlclose(comInfo.LibHandle);
    }
    componentsList_.clear();
}
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS