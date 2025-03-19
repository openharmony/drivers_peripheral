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

#ifndef OHOS_HDI_USB_V1_0_SERIALIMPL_H
#define OHOS_HDI_USB_V1_0_SERIALIMPL_H

#include "v1_0/iserial_interface.h"

namespace OHOS {
namespace HDI {
namespace Usb {
namespace Serial {
namespace V1_0 {
class SerialImpl : public ISerialInterface {
public:
    SerialImpl();
    ~SerialImpl() override;
    int32_t SerialOpen(int32_t portId) override;
    int32_t SerialClose(int32_t portId) override;
    int32_t SerialRead(int32_t portId, std::vector<uint8_t>& data, uint32_t size, uint32_t timeout) override;
    int32_t SerialWrite(int32_t portId, const std::vector<uint8_t>& data, uint32_t size, uint32_t timeout) override;
    int32_t SerialSetAttribute(int32_t portId, const SerialAttribute& attribute) override;
    int32_t SerialGetAttribute(int32_t portId, SerialAttribute& attribute) override;
    int32_t SerialGetPortList(std::vector<SerialPort>& portList) override;
};
} // V1_0
} // Serial
} // Usb
} // HDI
} // OHOS

#endif // OHOS_HDI_USB_V1_0_SERIALIMPL_H