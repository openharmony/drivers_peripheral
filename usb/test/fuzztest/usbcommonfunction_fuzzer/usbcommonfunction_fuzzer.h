/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef USBCOMMONFUNCTION_FUZZER_H
#define USBCOMMONFUNCTION_FUZZER_H

#include <unistd.h>
#include "v1_0/iusb_interface.h"
#include "v1_0/usb_types.h"

using OHOS::HDI::Usb::V1_0::UsbDev;
using OHOS::HDI::Usb::V1_0::IUsbInterface;

namespace OHOS {
namespace USB {
int32_t UsbFuzzTestHostModeInit(UsbDev &dev, const sptr<IUsbInterface> &usbInterface);

const int32_t SLEEP_TIME = 3;
const int32_t DEFAULT_PORT_ID = 1;
const int32_t DEFAULT_ROLE_HOST = 1;
const int32_t DEFAULT_ROLE_DEVICE = 2;
} // namespace USB
} // namespace OHOS
#endif // USBCOMMONFUNCTION_FUZZER_H