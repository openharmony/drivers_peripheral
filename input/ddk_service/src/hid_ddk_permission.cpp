/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "hid_ddk_permission.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "input_uhdf_log.h"

namespace OHOS {
namespace HDI {
namespace Input {
namespace Ddk {
namespace V1_1 {
using namespace OHOS::Security::AccessToken;

bool DdkPermissionManager::VerifyPermission(std::string permissionName)
{
    AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    int result = AccessTokenKit::VerifyAccessToken(callerToken, permissionName);
    HDF_LOGI("%{public}s VerifyAccessToken: %{public}d", __func__, result);
    return result == PERMISSION_GRANTED;
}
} // namespace V1_1
} // namespace Ddk
} // namespace Input
} // namespace HDI
} // namespace OHOS