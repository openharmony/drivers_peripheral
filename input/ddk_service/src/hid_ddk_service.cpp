/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "v1_0/hid_ddk_service.h"
#include <hdf_base.h>
#include "emit_event_manager.h"
#include "hid_ddk_permission.h"
#include "input_uhdf_log.h"

#define HDF_LOG_TAG hid_ddk_service

namespace OHOS {
namespace HDI {
namespace Input {
namespace Ddk {
namespace V1_0 {
static const std::string PERMISSION_NAME = "ohos.permission.ACCESS_DDK_HID";

extern "C" IHidDdk *HidDdkImplGetInstance(void)
{
    return new (std::nothrow) HidDdkService();
}

int32_t HidDdkService::CreateDevice(const Hid_Device &hidDevice,
    const Hid_EventProperties &hidEventProperties, uint32_t &deviceId)
{
    HDF_LOGI("%{public}s create device enter", __func__);
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HDF_ERR_NOPERM;
    }

    int32_t ret = OHOS::ExternalDeviceManager::EmitEventManager::GetInstance()
        .CreateDevice(hidDevice, hidEventProperties);
    if (ret < 0) {
        HDF_LOGE("%{public}s create device faild, ret=%{public}d", __func__, ret);
        return ret;
    }

    deviceId = static_cast<uint32_t>(ret);
    return Hid_DdkErrCode::HID_DDK_SUCCESS;
}

int32_t HidDdkService::EmitEvent(uint32_t deviceId, const std::vector<Hid_EmitItem> &items)
{
    HDF_LOGI("%{public}s emit event enter, deviceId=%{public}d", __func__, deviceId);
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HDF_ERR_NOPERM;
    }

    return OHOS::ExternalDeviceManager::EmitEventManager::GetInstance().EmitEvent(deviceId, items);
}

int32_t HidDdkService::DestroyDevice(uint32_t deviceId)
{
    HDF_LOGI("%{public}s destroy device enter, deviceId=%{public}d", __func__, deviceId);
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HDF_ERR_NOPERM;
    }
    
    return OHOS::ExternalDeviceManager::EmitEventManager::GetInstance().DestroyDevice(deviceId);
}

} // V1_0
} // Ddk
} // Input
} // HDI
} // OHOS
