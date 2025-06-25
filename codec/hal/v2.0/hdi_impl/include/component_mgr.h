/*
 * Copyright (c) 2022 Shenzhen Kaihong DID Co., Ltd.
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
#include <mutex>
#include <vector>
#include "codec_omx_core.h"
#include "icomponent_mgr.h"
namespace OHOS {
namespace Codec {
namespace Omx {
class ComponentMgr : public IComponentMgr {
public:
    using OMXComponent = struct {
        OMX_HANDLETYPE handle;
        std::shared_ptr<CodecOMXCore> core;
    };

public:
    ComponentMgr();
    ~ComponentMgr() override;
    ComponentMgr(const ComponentMgr &) = delete;
    ComponentMgr &operator=(const ComponentMgr &) = delete;

    virtual int32_t CreateComponentInstance(const char *componentName, const OMX_CALLBACKTYPE *callbacks, void *appData,
                                            OMX_COMPONENTTYPE **component) override;

    virtual int32_t DeleteComponentInstance(OMX_COMPONENTTYPE *component) override;

    virtual int32_t GetRolesForComponent(const char *componentName, std::vector<std::string> *roles) override;

    virtual int32_t GetCoreOfComponent(CodecOMXCore* &core, const char *componentName) override;

private:
    void AddVendorComponent();
    void AddSoftComponent();
    void AddComponentByLibName(const char *libName);
    void CleanComponent();

private:
    std::vector<std::shared_ptr<CodecOMXCore>> cores_;                    // save all the core
    std::map<std::string, std::shared_ptr<CodecOMXCore>> componentsCore_;  // save the compoentname<--> core
    std::vector<OMXComponent> components_;                                // save the opened compoents
    std::mutex mutex_;
};
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS

#endif