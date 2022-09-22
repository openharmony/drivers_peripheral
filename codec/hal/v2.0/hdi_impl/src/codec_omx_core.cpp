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
    if (realpath(libName.c_str(), pathBuf) == NULL) {
        HDF_LOGE("%{public}s: realpath failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    libHandle_ = dlopen(pathBuf, RTLD_LAZY);
    if (libHandle_ == NULL) {
        HDF_LOGE("%{public}s:failed to dlopen %{public}s.", __func__, libName.c_str());
        return HDF_ERR_INVALID_PARAM;
    }

    init_ = (InitFunc)dlsym(libHandle_, "OMX_Init");
    deInit_ = (DeinitFunc)dlsym(libHandle_, "OMX_Deinit");
    getHandle_ = (GetHandleFunc)dlsym(libHandle_, "OMX_GetHandle");
    freeHandle_ = (FreeHandleFunc)dlsym(libHandle_, "OMX_FreeHandle");
    getRoles_ = (GetRolesOfComponentFunc)dlsym(libHandle_, "OMX_GetRolesOfComponent");
    componentNameEnum_ = (ComponentNameEnumFunc)dlsym(libHandle_, "OMX_ComponentNameEnum");

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
    uint32_t err = (*getRoles_)(const_cast<char *>(name.c_str()), &roleCount, nullptr);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: getRoles_ return err [%{public}x].", __func__, err);
        return err;
    }
    if (roleCount == 0) {
        return err;
    }

    char role[roleCount][OMX_MAX_STRINGNAME_SIZE];
    uint32_t bufferSize = sizeof(char) * (roleCount * OMX_MAX_STRINGNAME_SIZE);
    int32_t ret = memset_s(role, sizeof(role), 0, bufferSize);
    if (ret != EOK) {
        HDF_LOGE("%{public}s: memset failed, error code: [%{public}d]", __func__, ret);
        return HDF_FAILURE;
    }

    uint32_t roleLen = roleCount;
    err = (*getRoles_)(const_cast<char *>(name.c_str()), &roleCount, reinterpret_cast<OMX_U8 **>(role));
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: getRoles_ return err [%{public}x].", __func__, err);
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