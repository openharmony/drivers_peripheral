/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "accesstoken_kit.h"
#include <dlfcn.h>
#include <mutex>
#include <hdf_log.h>
#include "ipc_skeleton.h"
#include "usb_serial_ddk_permission.h"
#include "usbd_wrapper.h"

#define HDF_LOG_TAG usb_serial_ddk_permission
#define HDF_PERMISSION_NOT_CHECK

namespace OHOS {
namespace HDI {
namespace Usb {
namespace UsbSerialDdk {
namespace V1_0 {
using namespace OHOS::Security::AccessToken;

bool DdkPermissionManager::VerifyPermission(const std::string &permissionName)
{
#ifndef HDF_PERMISSION_NOT_CHECK
    AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    int result = AccessTokenKit::VerifyAccessToken(callerToken, permissionName);
    HDF_LOGI("%{public}s VerifyAccessToken: %{public}d", __func__, result);
    return result == PERMISSION_GRANTED;
#else
    return true;
#endif
}

} // namespace V1_0
} // namespace UsbSerialDdk
} // namespace Usb
} // namespace HDI
} // namespace OHOS