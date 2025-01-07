/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "usb_ddk_permission.h"
#include <hdf_base.h>
#include <hdf_log.h>
#include <dlfcn.h>
#include <mutex>

#include "ipc_skeleton.h"

namespace OHOS {
namespace HDI {
namespace Usb {
namespace Ddk {
namespace V1_0 {
using VerifyAccessTokenFunc = int(*)(uint32_t callerToken, const std::string &permissionName);
using GetApiVersion = int(*)(uint32_t callerToken, int32_t &apiVersion);
static constexpr int PERMISSION_GRANTED = 0;

static void *g_libHandle = nullptr;
static VerifyAccessTokenFunc g_verifyAccessToken = nullptr;
static GetApiVersion g_getApiVersion = nullptr;
static std::mutex g_mutex;

static void InitVerifyAccessToken()
{
    if (g_verifyAccessToken != nullptr && g_verifyAccessToken != nullptr) {
        return;
    }

    g_libHandle = dlopen("libusb_ddk_dynamic_library_wrapper.z.so", RTLD_LAZY);
    if (g_libHandle == nullptr) {
        HDF_LOGE("%{public}s dlopen failed: %{public}s", __func__, dlerror());
        return;
    }

    void *funcPtr = dlsym(g_libHandle, "VerifyAccessToken");
    if (funcPtr == nullptr) {
        HDF_LOGE("%{public}s dlsym failed: %{public}s", __func__, dlerror());
        dlclose(g_libHandle);
        g_libHandle = nullptr;
        return;
    }

    g_verifyAccessToken = reinterpret_cast<VerifyAccessTokenFunc>(funcPtr);

    void *getApiVersionPtr = dlsym(g_libHandle, "GetApiVersion");
    if (getApiVersionPtr == nullptr) {
        HDF_LOGE("%{public}s dlsym getApiVersionPtr failed: %{public}s", __func__, dlerror());
        dlclose(g_libHandle);
        g_libHandle = nullptr;
        return;
    }
    g_getApiVersion = reinterpret_cast<GetApiVersion>(getApiVersionPtr);
}

void DdkPermissionManager::Reset()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_verifyAccessToken = nullptr;
    if (g_libHandle != nullptr) {
        dlclose(g_libHandle);
        g_libHandle = nullptr;
    }
}

bool DdkPermissionManager::VerifyPermission(const std::string &permissionName)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    InitVerifyAccessToken();
    if (g_verifyAccessToken == nullptr) {
        return false;
    }

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int result = g_verifyAccessToken(callerToken, permissionName);
    HDF_LOGI("%{public}s VerifyAccessToken: %{public}d", __func__, result);
    return result == PERMISSION_GRANTED;
}

int32_t DdkPermissionManager::GetHapApiVersion(int32_t &apiVersion)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    InitVerifyAccessToken();
    if (g_getApiVersion == nullptr) {
        return HDF_FAILURE;
    }

    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    return g_getApiVersion(callerToken, apiVersion);
}
} // namespace V1_0
} // namespace Ddk
} // namespace Usb
} // namespace HDI
} // namespace OHOS