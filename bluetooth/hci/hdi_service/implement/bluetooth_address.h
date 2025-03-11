/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_BLUETOOTH_HCI_BLUETOOTH_ADDRESS_H
#define OHOS_HDI_BLUETOOTH_HCI_BLUETOOTH_ADDRESS_H

#include <memory>
#include <string>
#include <vector>
#include "bt_hal_constant.h"

namespace OHOS {
namespace HDI {
namespace Bluetooth {
namespace Hci {
class BluetoothAddress {
public:
    BluetoothAddress();
    ~BluetoothAddress() = default;
    static std::shared_ptr<BluetoothAddress> GetDeviceAddress(const std::string &path = BT_DEVICE_ADDRESS_PATH);
    static std::shared_ptr<BluetoothAddress> GenerateDeviceAddress(const std::string &prefix = "");
    void ReadAddress(std::vector<uint8_t> &address) const;
    void ReadAddress(std::string &address) const;

private:
    static void ParseAddressToString(std::vector<uint8_t> &address, std::string &outString);
    int ParseAddressFromString(const std::string &string) const;
    static bool GetConstantAddress(char *address, int len);
    static bool CheckAddress(char *address);
    static std::shared_ptr<BluetoothAddress> GenerateDeviceAddressFile(
        const std::string &path = BT_DEVICE_ADDRESS_PATH);
#ifdef PC_STANDARD
    static bool NeedReloadAddress();
#endif

private:
    std::vector<uint8_t> address_;
    static constexpr const char *BT_MAC_LIB = "libnb_mac.z.so";
    static constexpr const char *GET_BT_MAC_SYMBOL_NAME = "GetConstantMac";
    static constexpr unsigned int MAC_TYPE_BLUETOOTH = 1;
};
}  // namespace Hci
}  // namespace Bluetooth
}  // namespace HDI
}  // namespace OHOS
#endif /* OHOS_HDI_BLUETOOTH_HCI_BLUETOOTH_ADDRESS_H */
