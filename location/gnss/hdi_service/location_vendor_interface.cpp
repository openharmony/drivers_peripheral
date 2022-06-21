/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "location_vendor_interface.h"

#include <dlfcn.h>
#include <hdf_log.h>

#include "gnss_interface_impl.h"

namespace OHOS {
namespace HDI {
namespace Location {
namespace {
void *g_vendorHandle = nullptr;
const GnssVendorInterface *g_vendorInterface = nullptr;
const std::string VENDOR_NAME = "vendorGnssAdapter.so";
} // namespace

void LocationVendorInterface::Init()
{
    HDF_LOGI("%{public}s.", __func__);
    g_vendorHandle = dlopen(VENDOR_NAME.c_str(), RTLD_LAZY);
    if (!g_vendorHandle) {
        HDF_LOGE("%{public}s:dlopen %{public}s failed.", __func__, VENDOR_NAME.c_str());
        return;
    }
    GnssVendorDevice *gnssDevice = static_cast<GnssVendorDevice *>(dlsym(g_vendorHandle, "GnssVendorInterface"));
    if (gnssDevice == nullptr) {
        HDF_LOGE("%{public}s:dlsym GnssInterface failed.", __func__);
        return;
    }
    g_vendorInterface = gnssDevice->get_gnss_interface();
    if (g_vendorInterface == nullptr) {
        HDF_LOGE("%{public}s:get_gnss_interface failed.", __func__);
        return;
    }
}

const GnssVendorInterface *LocationVendorInterface::GetVendorInterface()
{
    if (g_vendorInterface == nullptr) {
        HDF_LOGE("%{public}s:GetVendorInterface() failed.", __func__);
    }
    return g_vendorInterface;
}

const void *LocationVendorInterface::GetModuleInterface(int moduleId)
{
    auto vendorInterface = GetVendorInterface();
    if (vendorInterface == nullptr) {
        HDF_LOGE("%{public}s:can not get vendorInterface.", __func__);
        return nullptr;
    }
    auto moduleInterface = vendorInterface->get_gnss_module_iface(moduleId);
    if (moduleInterface == nullptr) {
        HDF_LOGE("%{public}s:can not get moduleInterface.", __func__);
    }
    return moduleInterface;
}

void LocationVendorInterface::CleanUp()
{
    if (g_vendorInterface == nullptr) {
        return;
    }
    g_vendorInterface = nullptr;
    dlclose(g_vendorHandle);
}
} // Location
} // HDI
} // OHOS
