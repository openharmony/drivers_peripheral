/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "usbd_load_usb_service.h"

#include <cstdlib>
#include <iostream>
#include <unistd.h>

#include "hdf_base.h"
#include "iservice_registry.h"
#include "osal_thread.h"
#include "osal_time.h"
#include "securec.h"
#include "usbd_wrapper.h"

using namespace OHOS;
using namespace std;
#define HDF_LOG_TAG usbd_load_usb_service

namespace OHOS {
namespace HDI {
namespace Usb {
namespace V1_1 {
OnDemandLoadCallback::OnDemandLoadCallback()
{
    HDF_LOGI("%{public}s:construct", __func__);
}

OnDemandLoadCallback::~OnDemandLoadCallback()
{
    HDF_LOGI("%{public}s:deconstruct", __func__);
}

void OnDemandLoadCallback::OnLoadSystemAbilitySuccess(int32_t systemAbilityId, const sptr<IRemoteObject> &remoteObject)
{
    loading_ = false;
    HDF_LOGI("%{public}s: OnLoadSystemAbilitySuccess systemAbilityId: %{public}d", __func__, systemAbilityId);
}

void OnDemandLoadCallback::OnLoadSystemAbilityFail(int32_t systemAbilityId)
{
    loading_ = false;
    HDF_LOGI("%{public}s: OnLoadSystemAbilityFail systemAbilityId: %{public}d", __func__, systemAbilityId);
}

UsbdLoadService::UsbdLoadService(int32_t saId) : saId_(saId)
{
    HDF_LOGI("%{public}s:construct", __func__);
}

UsbdLoadService::~UsbdLoadService()
{
    HDF_LOGI("%{public}s:deconstruct", __func__);
}
int32_t UsbdLoadService::LoadService()
{
    if (loadCallback_ != nullptr && loadCallback_->loading_) {
        HDF_LOGW("%{public}s:sa is loading", __func__);
        return HDF_SUCCESS;
    }

    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        HDF_LOGE("%{public}s:GetSystemAbilityManager failed", __func__);
        return HDF_FAILURE;
    }
    auto saObj = samgr->CheckSystemAbility(saId_);
    if (saObj != nullptr) {
        return HDF_SUCCESS;
    }

    if (loadCallback_ == nullptr) {
        loadCallback_ = new (std::nothrow) OnDemandLoadCallback();
        if (loadCallback_ == nullptr) {
            HDF_LOGE("create OnDemandLoadCallback failed");
            return HDF_DEV_ERR_NO_MEMORY;
        }
    }

    loadCallback_->loading_ = true;
    int32_t result = samgr->LoadSystemAbility(saId_, loadCallback_);
    if (result != ERR_OK) {
        HDF_LOGE("LoadSystemAbility failed");
        loadCallback_->loading_ = false;
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
} // namespace V1_1
} // namespace Usb
} // namespace HDI
} // namespace OHOS
