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

#ifndef USBSERIALCOMMONFUNCTION_FUZZER_H
#define USBSERIALCOMMONFUNCTION_FUZZER_H

#include <unistd.h>
#include "usbd_wrapper.h"
#include "v1_0/iusb_interface.h"
#include "v1_0/usb_types.h"
#include "v1_0/iusb_serial_ddk.h"
#include "v1_0/usb_serial_ddk_types.h"


using OHOS::HDI::Usb::UsbSerialDdk::V1_0::IUsbSerialDdk;
using OHOS::HDI::Usb::UsbSerialDdk::V1_0::UsbSerialDeviceHandle;

namespace OHOS {
namespace USBSerial {
constexpr int32_t ZERO_MOVE_LEN = 24;
constexpr int32_t FIRST_MOVE_LEN = 16;
constexpr int32_t SECOND_MOVE_LEN = 8;
constexpr int32_t SECOND_BIT = 2;
constexpr int32_t THIRD_BIT = 3;

int32_t UsbSerialFuzzTestHostModeInit(const sptr<IUsbSerialDdk> &usbSerialInterface,
                                      UsbSerialDeviceHandle *device);

const int32_t SLEEP_TIME = 3;
}
} // namespace HDI

#endif // USBCOMMONFUNCTION_FUZZER_H