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
const std::string VENDOR_NAME = "vendorGnssAdapter.so";
} // namespace

std::mutex LocationVendorInterface::mutex_;
LocationVendorInterface* LocationVendorInterface::instance_ = nullptr;

LocationVendorInterface::LocationVendorInterface()
{
    Init();
    HDF_LOGI("%{public}s constructed.", __func__);
}

LocationVendorInterface::~LocationVendorInterface()
{
    CleanUp();
    HDF_LOGI("%{public}s destructed.", __func__);
}
 
LocationVendorInterface* LocationVendorInterface::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = new LocationVendorInterface();
        }
    }
    return instance_;
}

void LocationVendorInterface::DestroyInstance()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (instance_ != nullptr) {
        delete instance_;
        instance_ = nullptr;
    }
}

void LocationVendorInterface::Init()
{
    HDF_LOGI("%{public}s.", __func__);
    vendorHandle_ = dlopen(VENDOR_NAME.c_str(), RTLD_LAZY);
    if (!vendorHandle_) {
        HDF_LOGE("%{public}s:dlopen %{public}s failed: %{public}s", __func__, VENDOR_NAME.c_str(), dlerror());
        return;
    }
    GnssVendorDevice *gnssDevice = static_cast<GnssVendorDevice *>(dlsym(vendorHandle_, "GnssVendorInterface"));
    if (gnssDevice == nullptr) {
        HDF_LOGE("%{public}s:dlsym GnssInterface failed.", __func__);
        return;
    }
    vendorInterface_ = gnssDevice->get_gnss_interface();
    if (vendorInterface_ == nullptr) {
        HDF_LOGE("%{public}s:get_gnss_interface failed.", __func__);
        return;
    }
}

const GnssVendorInterface *LocationVendorInterface::GetGnssVendorInterface() const
{
    if (vendorInterface_ == nullptr) {
        HDF_LOGE("%{public}s:GetGnssVendorInterface() failed.", __func__);
    }
    return vendorInterface_;
}

const void *LocationVendorInterface::GetModuleInterface(int moduleId) const
{
    auto vendorInterface = GetGnssVendorInterface();
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
    if (vendorInterface_ == nullptr) {
        return;
    }
    vendorInterface_ = nullptr;
    dlclose(vendorHandle_);
    vendorHandle_ = nullptr;
}
} // Location
} // HDI
} // OHOS
