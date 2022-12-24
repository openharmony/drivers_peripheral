/*
 * Copyright 2022 Shenzhen Kaihong DID Co., Ltd..
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
#include <hdf_log.h>
#include <securec.h>

#define HDF_LOG_TAG codec_hdi_server

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
    char pathBuf[PATH_MAX] = {'\0'};
    if (realpath(libName.c_str(), pathBuf) == nullptr) {
        HDF_LOGE("%{public}s: realpath failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    libHandle_ = dlopen(pathBuf, RTLD_LAZY);
    if (libHandle_ == nullptr) {
        HDF_LOGE("%{public}s:failed to dlopen %{public}s.", __func__, libName.c_str());
        return HDF_ERR_INVALID_PARAM;
    }

    init_ = reinterpret_cast<InitFunc>(dlsym(libHandle_, "OMX_Init"));
    deInit_ = reinterpret_cast<DeinitFunc>(dlsym(libHandle_, "OMX_Deinit"));
    getHandle_ = reinterpret_cast<GetHandleFunc>(dlsym(libHandle_, "OMX_GetHandle"));
    freeHandle_ = reinterpret_cast<FreeHandleFunc>(dlsym(libHandle_, "OMX_FreeHandle"));
    getRoles_ = reinterpret_cast<GetRolesOfComponentFunc>(dlsym(libHandle_, "OMX_GetRolesOfComponent"));
    componentNameEnum_ = reinterpret_cast<ComponentNameEnumFunc>(dlsym(libHandle_, "OMX_ComponentNameEnum"));

    if (init_ != nullptr) {
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
        HDF_LOGE("%{public}s: getHandle is null.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return (*getHandle_)(&handle, const_cast<char *>(compName.c_str()), appData, (OMX_CALLBACKTYPE *)&callbacks);
}

int32_t CodecOMXCore::FreeHandle(OMX_HANDLETYPE handle)
{
    if (freeHandle_ == nullptr) {
        HDF_LOGE("%{public}s: freeHandle_ is null.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return (*freeHandle_)(handle);
}

int32_t CodecOMXCore::ComponentNameEnum(std::string &name, uint32_t index)
{
    if (componentNameEnum_ == nullptr) {
        HDF_LOGE("%{public}s: componentNameEnum is null.", __func__);
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
        HDF_LOGE("%{public}s: getRoles is null.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    uint32_t roleCount = 0;
    int32_t err = (*getRoles_)(const_cast<char *>(name.c_str()), &roleCount, nullptr);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: getRoles_ nullptr return err [%{public}x].", __func__, err);
        return err;
    }
    if (roleCount == 0) {
        HDF_LOGE("%{public}s: roleCount = 0 ", __func__);
        return err;
    }

    char *role[roleCount];
    char array[roleCount][OMX_MAX_STRINGNAME_SIZE];
    for (uint32_t i = 0; i < roleCount; i++) {
        int32_t ret = memset_s(array[i], OMX_MAX_STRINGNAME_SIZE, 0, OMX_MAX_STRINGNAME_SIZE);
        if (ret != EOK) {
            HDF_LOGE("%{public}s: memset_s array err [%{public}x].", __func__, ret);
            return ret;
        }
        role[i] = array[i];
    }

    uint32_t roleLen = roleCount;
    err = (*getRoles_)(const_cast<char *>(name.c_str()), &roleCount, reinterpret_cast<OMX_U8 **>(role));
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: getRoles_ pRole return err [%{public}x].", __func__, err);
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