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

#ifndef USB_DDK_PERMISSION_H
#define USB_DDK_PERMISSION_H

#include <iostream>

namespace OHOS {
namespace HDI {
namespace Usb {
namespace Ddk {
namespace V1_0 {
class DdkPermissionManager {
public:
    static bool VerifyPermission(const std::string &permissionName);
    static void Reset();
    static int32_t GetHapApiVersion(int32_t &apiVersion);
};
} // namespace V1_0
} // namespace Ddk
} // namespace Usb
} // namespace HDI
} // namespace OHOS
#endif // USB_DDK_PERMISSION_H