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

#ifndef USB_SERIAL_LINUX_ADAPTER_H
#define USB_SERIAL_LINUX_ADAPTER_H

#include <stdint.h>
#include "usb_serial_os_apdater.h"

namespace OHOS {
namespace HDI {
namespace Usb {
namespace UsbSerialDdk {
namespace V1_0 {

class LinuxUsbSerialOsAdapter : public UsbSerialOsAdapter {
public:
    LinuxUsbSerialOsAdapter() = default;
    virtual ~LinuxUsbSerialOsAdapter() = default;

    int32_t SetBaudRate(int32_t fd, uint32_t baudRate) override;
    int32_t SetParams(int32_t fd, const UsbSerialParams &params) override;
    int32_t SetTimeout(int32_t fd, int32_t timeout) override;
    int32_t SetFlowControl(int32_t fd, int32_t flowControl) override;
    bool IsDeviceDisconnect(int32_t fd) override;
    int32_t Flush(int32_t fd) override;
    int32_t FlushInput(int32_t fd) override;
    int32_t FlushOutput(int32_t fd) override;
};

} // namespace V1_0
} // namespace UsbSerialDdk
} // namespace Usb
} // namespace HDI
} // namespace OHOS
#endif