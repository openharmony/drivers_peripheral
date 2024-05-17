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

#include <hdf_log.h>

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace HDI {
namespace Usb {
namespace Ddk {
namespace V1_0 {
using namespace OHOS::Security::AccessToken;

bool DdkPermissionManager::VerifyPermission(std::string permissionName)
{
    AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    int result = AccessTokenKit::VerifyAccessToken(callerToken, permissionName);
    HDF_LOGI("%{public}s VerifyAccessToken: %{public}d", __func__, result);
    return result == PERMISSION_GRANTED;
}
} // namespace V1_0
} // namespace Ddk
} // namespace Usb
} // namespace HDI
} // namespace OHOS