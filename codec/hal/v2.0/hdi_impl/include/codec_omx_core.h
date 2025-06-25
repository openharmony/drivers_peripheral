/*
 * Copyright (c) 2022 Shenzhen Kaihong DID Co., Ltd..
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OMX_CODEC_CORE_H
#define OMX_CODEC_CORE_H
#include <OMX_Component.h>
#include <functional>
#include <string>
#include <vector>
namespace OHOS {
namespace Codec {
namespace Omx {
class CodecOMXCore {
public:
    typedef OMX_ERRORTYPE (*InitFunc)();
    typedef OMX_ERRORTYPE (*DeinitFunc)();
    typedef OMX_ERRORTYPE (*ComponentNameEnumFunc)(OMX_STRING, OMX_U32, OMX_U32);
    typedef OMX_ERRORTYPE (*GetHandleFunc)(OMX_HANDLETYPE *, OMX_STRING, OMX_PTR, OMX_CALLBACKTYPE *);
    typedef OMX_ERRORTYPE (*FreeHandleFunc)(OMX_HANDLETYPE);
    typedef OMX_ERRORTYPE (*GetRolesOfComponentFunc)(OMX_STRING, OMX_U32 *, OMX_U8 **);

public:
    CodecOMXCore() = default;
    ~CodecOMXCore();
    int32_t Init(const std::string &libName);
    void DeInit();
    int32_t GetHandle(OMX_HANDLETYPE &handle, std::string &compName, OMX_PTR appData,
                      const OMX_CALLBACKTYPE &callbacks);
    int32_t FreeHandle(OMX_HANDLETYPE handle);
    int32_t ComponentNameEnum(std::string &name, uint32_t index);
    int32_t GetRolesOfComponent(std::string &name, std::vector<std::string> &roles);

private:
    void *libHandle_ = nullptr;
    InitFunc init_ = nullptr;
    DeinitFunc deInit_ = nullptr;
    ComponentNameEnumFunc componentNameEnum_ = nullptr;
    GetHandleFunc getHandle_ = nullptr;
    FreeHandleFunc freeHandle_ = nullptr;
    GetRolesOfComponentFunc getRoles_ = nullptr;
};
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS
#endif