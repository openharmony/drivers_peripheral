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

#ifndef COMPONENT_MGR_H
#define COMPONENT_MGR_H
#include <OMX_Component.h>
#include <OMX_Core.h>
#include <list>
#include <map>
#include <vector>

#include "icomponent_mgr.h"
namespace OHOS {
namespace Codec {
namespace Omx {
class ComponentMgr : public IComponentMgr {
public:
    ComponentMgr();
    ~ComponentMgr();
    ComponentMgr(const ComponentMgr &) = delete;
    ComponentMgr &operator=(const ComponentMgr &) = delete;

    virtual int32_t CreateComponentInstance(const char *componentName, const OMX_CALLBACKTYPE *callbacks,
                                            void *appData, OMX_COMPONENTTYPE **component);

    virtual int32_t DeleteComponentInstance(OMX_COMPONENTTYPE *component);

    virtual int32_t EnumerateComponentsByIndex(uint32_t index, char *componentName, size_t componentNameSize);

    virtual int32_t GetRolesForComponent(const char *componentName, std::vector<std::string> *roles);

    bool IsOMXHandleValid(OMX_COMPONENTTYPE *handle);

    bool IsLoadLibSuc()
    {
        return loadLibSuc_;
    }

private:
    void AddVendorComponent();
    void AddSoftComponent();
    void AddComponentByLibName(const char *libName);
    void AddComponentByInstance(IComponentMgr *);
    void CleanComponent();

private:
    bool loadLibSuc_;
    struct ComponentInfo {
        IComponentMgr *omxComponent;
        void *LibHandle;
    };
    struct ComponentNameAndObjectPoint {
        std::string componentName;
        IComponentMgr *omxComponentMgr;
    };
    struct ComponentTypePointAndObjectPoint {
        OMX_COMPONENTTYPE *componentType;
        IComponentMgr *omxComponentMgr;
    };
    std::list<ComponentInfo> componentsList_;
    std::vector<ComponentNameAndObjectPoint> componentNameAndObjectPoint_;
    std::vector<ComponentTypePointAndObjectPoint> componentTypePointAndObjectPoint_;
    OMX_COMPONENTTYPE *currentComType_;
    std::string currentComName_;
};
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS

#endif