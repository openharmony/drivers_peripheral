/*
 * Copyright (c) 2022-2023 Shenzhen Kaihong DID Co., Ltd..
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

#include "codec_omx_core.h"
#include <OMX_Core.h>
#include <dlfcn.h>
#include <hdf_base.h>
#include <memory.h>
#include <securec.h>
#include "codec_log_wrapper.h"
namespace OHOS {
namespace Codec {
namespace Omx {
CodecOMXCore::~CodecOMXCore()
{
    if (libHandle_ != nullptr) {
        dlclose(libHandle_);
    }
}
int32_t CodecOMXCore::Init(const std::string &libName)
{
    if (libName.empty()) {
        CODEC_LOGE("param is empty");
        return HDF_ERR_INVALID_PARAM;
    }

    libHandle_ = dlopen(libName.c_str(), RTLD_LAZY);
    if (libHandle_ == nullptr) {
        CODEC_LOGE("Failed to dlopen %{public}s.", libName.c_str());
        return HDF_ERR_INVALID_PARAM;
    }

    init_ = reinterpret_cast<InitFunc>(dlsym(libHandle_, "OMX_Init"));
    deInit_ = reinterpret_cast<DeinitFunc>(dlsym(libHandle_, "OMX_Deinit"));
    getHandle_ = reinterpret_cast<GetHandleFunc>(dlsym(libHandle_, "OMX_GetHandle"));
    freeHandle_ = reinterpret_cast<FreeHandleFunc>(dlsym(libHandle_, "OMX_FreeHandle"));
    getRoles_ = reinterpret_cast<GetRolesOfComponentFunc>(dlsym(libHandle_, "OMX_GetRolesOfComponent"));
    componentNameEnum_ = reinterpret_cast<ComponentNameEnumFunc>(dlsym(libHandle_, "OMX_ComponentNameEnum"));

    if (init_ != NULL) {
        (*(init_))();
    }
    return HDF_SUCCESS;
}

void CodecOMXCore::DeInit()
{
    if (deInit_) {
        (*deInit_)();
    }
}

int32_t CodecOMXCore::GetHandle(OMX_HANDLETYPE &handle, std::string &compName, OMX_PTR appData,
                                const OMX_CALLBACKTYPE &callbacks)
{
    if (getHandle_ == nullptr) {
        CODEC_LOGE("getHandle_ is nullptr.");
        return HDF_ERR_INVALID_PARAM;
    }
    if (compName.empty()) {
        CODEC_LOGE("invalid component name");
        return HDF_ERR_INVALID_PARAM;
    }
    return (*getHandle_)(&handle, const_cast<char *>(compName.c_str()), appData, (OMX_CALLBACKTYPE *)&callbacks);
}

int32_t CodecOMXCore::FreeHandle(OMX_HANDLETYPE handle)
{
    if (freeHandle_ == nullptr) {
        CODEC_LOGE("freeHandle_ is nullptr.");
        return HDF_ERR_INVALID_PARAM;
    }
    return (*freeHandle_)(handle);
}

int32_t CodecOMXCore::ComponentNameEnum(std::string &name, uint32_t index)
{
    if (componentNameEnum_ == nullptr) {
        CODEC_LOGE("componentNameEnum_ is nullptr.");
        return HDF_ERR_INVALID_PARAM;
    }
    char tmpComponentName[OMX_MAX_STRINGNAME_SIZE] = {0};
    uint32_t err = (*(componentNameEnum_))(tmpComponentName, OMX_MAX_STRINGNAME_SIZE, index);
    if (err == HDF_SUCCESS) {
        name = tmpComponentName;
    }
    return err;
}
int32_t CodecOMXCore::GetRolesOfComponent(std::string &name, std::vector<std::string> &roles)
{
    if (getRoles_ == nullptr) {
        CODEC_LOGE("getRoles_ is null.");
        return HDF_ERR_INVALID_PARAM;
    }
    if (name.empty()) {
        CODEC_LOGE("empty name");
        return HDF_ERR_INVALID_PARAM;
    }
    uint32_t roleCount = 0;
    uint32_t err = (*getRoles_)(const_cast<char *>(name.c_str()), &roleCount, nullptr);
    if (err != HDF_SUCCESS) {
        CODEC_LOGE("get roleCount return err [%{public}x].", err);
        return err;
    }
    if (roleCount == 0) {
        return err;
    }

    char *role[roleCount];
    char array[roleCount][OMX_MAX_STRINGNAME_SIZE];
    for (uint32_t i = 0; i < roleCount; i++) {
        int32_t ret = memset_s(array[i], OMX_MAX_STRINGNAME_SIZE, 0, OMX_MAX_STRINGNAME_SIZE);
        if (ret != EOK) {
            CODEC_LOGE("memset_s array err [%{public}d].", ret);
            return ret;
        }
        role[i] = array[i];
    }

    uint32_t roleLen = roleCount;
    err = (*getRoles_)(const_cast<char *>(name.c_str()), &roleCount, reinterpret_cast<OMX_U8 **>(role));
    if (err != HDF_SUCCESS) {
        CODEC_LOGE("get roles return err [%{public}x].", err);
        return err;
    }
    for (uint32_t i = 0; i < roleLen; i++) {
        roles.push_back(role[i]);
    }

    return err;
}
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS
