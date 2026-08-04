/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "power_interface_impl.h"
#include <hdf_base.h>
#include <hdf_log.h>
#include "iservmgr_hdi.h"
#include "power_hdf_log.h"

#define HDF_LOG_TAG power_interface_impl

using namespace OHOS::HDI::Power::V1_4;
using OHOS::sptr;
using OHOS::HDI::ServiceManager::IServiceManager;

extern "C" IPowerInterface *PowerInterfaceImplGetInstance(void)
{
    return new (std::nothrow) PowerInterfaceImpl();
}

int32_t PowerInterfaceImplInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGI("%{public}s: enter", __func__);
    auto powerInterfaceImpl = new (std::nothrow) PowerInterfaceImpl();
    if (powerInterfaceImpl == nullptr) {
        HDF_LOGE("%{public}s: new power interface impl fail", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    auto servmgr = IServiceManager::Get();
    if (servmgr == nullptr) {
        HDF_LOGE("%{public}s: get service manager fail", __func__);
        delete powerInterfaceImpl;
        return HDF_FAILURE;
    }
    int32_t ret = servmgr->AddService("power_interface_service", powerInterfaceImpl, false);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: add service fail ret=%{public}d", __func__, ret);
        delete powerInterfaceImpl;
        return HDF_FAILURE;
    }
    if (powerInterfaceImpl->Init() != HDF_SUCCESS) {
        delete powerInterfaceImpl;
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s: init power interface service success", __func__);
    return HDF_SUCCESS;
}

struct HdfDriverEntry g_powerInterfaceEntry = {
    .moduleVersion = 1,
    .moduleName = "power_interface_service",
    .Bind = nullptr,
    .Init = PowerInterfaceImplInit,
    .Release = nullptr,
};

#ifndef __cplusplus
extern "C" {
#endif
HDF_INIT(g_powerInterfaceEntry);
#ifndef __cplusplus
}
#endif
