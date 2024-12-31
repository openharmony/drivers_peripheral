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

#ifndef USB_DRIVER_MANAGER_H
#define USB_DRIVER_MANAGER_H
#include <inttypes.h>
#include <map>
#include <mutex>

#include "v1_1/usb_ddk_types.h"

namespace OHOS {
namespace HDI {
namespace Usb {
namespace Ddk {
namespace V1_1 {
class UsbDriverManager final {
public:
    static UsbDriverManager& GetInstance();

    bool UpdateDriverInfo(const DriverAbilityInfo &driverInfo);
    bool RemoveDriverInfo(const std::string &driverUid);
    bool QueryDriverInfo(uint32_t tokenId, DriverAbilityInfo &driverInfo);

private:
    UsbDriverManager() = default;
    ~UsbDriverManager() = default;
    UsbDriverManager(const UsbDriverManager &) = delete;
    UsbDriverManager &operator=(const UsbDriverManager &) = delete;
    UsbDriverManager(UsbDriverManager &&) = delete;
    UsbDriverManager &operator=(UsbDriverManager &&) = delete;
    std::mutex mutex_;
    std::map<uint32_t, std::unique_ptr<DriverAbilityInfo>> driverMap_;
};
} // namespace V1_1
} // namespace Ddk
} // namespace Usb
} // namespace HDI
} // namespace OHOS
#endif // USB_DRIVER_MANAGER_H