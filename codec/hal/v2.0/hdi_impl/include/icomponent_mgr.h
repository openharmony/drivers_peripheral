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

#ifndef I_COMPONENT_MGR_H
#define I_COMPONENT_MGR_H
#include <OMX_Component.h>
#include <iostream>
#include <vector>

namespace OHOS {
namespace Codec {
namespace Omx {
class IComponentMgr {
public:
    IComponentMgr()
    {}
    virtual ~IComponentMgr()
    {}
    IComponentMgr(const IComponentMgr &) = delete;
    IComponentMgr &operator=(const IComponentMgr &) = delete;

    virtual int32_t CreateComponentInstance(const char *componentName, const OMX_CALLBACKTYPE *callbacks,
                                            void *appData, OMX_COMPONENTTYPE **component) = 0;

    virtual int32_t DeleteComponentInstance(OMX_COMPONENTTYPE *component) = 0;

    virtual int32_t GetRolesForComponent(const char *componentName, std::vector<std::string> *vRoles) = 0;

    virtual int32_t GetCoreOfComponent(CodecOMXCore* &core, const char *componentName) = 0;
};
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS

#endif