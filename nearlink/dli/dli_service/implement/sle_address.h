/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_NEARLINK_HCI_NEARLINK_ADDRESS_H
#define OHOS_HDI_NEARLINK_HCI_NEARLINK_ADDRESS_H

#include <memory>
#include <string>
#include <vector>

#include "sle_hal_constant.h"

namespace OHOS {
namespace HDI {
namespace Nearlink {
namespace Dli {
class SleAddress {
public:
    SleAddress();
    ~SleAddress() = default;
    static std::shared_ptr<SleAddress> GetDeviceAddress(const std::string &path = SLE_DEVICE_ADDRESS_PATH);
    static std::shared_ptr<SleAddress> GenerateDeviceAddress(const std::string &prefix = "");
    static void ParseAddressToString(std::vector<uint8_t> &address, std::string &outString);
    static std::string GetEncryptAddr(std::string addr);
    void ReadAddress(std::vector<uint8_t> &address) const;
    void ReadAddress(std::string &address) const;

private:
    int ParseAddressFromString(const std::string &string) const;
    static bool GetConstantAddress(char *address, int len);
#ifdef RELOAD_ADDRESS
    static bool NeedReloadAddress();
#endif
    static std::shared_ptr<SleAddress> UpdateAddressFromNV(const std::string &path);

private:
    std::vector<uint8_t> address_;
};
}  // namespace Dli
}  // namespace Nearlink
}  // namespace HDI
}  // namespace OHOS
#endif /* OHOS_HDI_NEARLINK_HCI_NEARLINK_ADDRESS_H */