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

#ifndef SCSICOMMONFUNCTION_FUZZER_H
#define SCSICOMMONFUNCTION_FUZZER_H

#include <unistd.h>
#include "usbd_wrapper.h"
#include "v1_0/iusb_interface.h"
#include "v1_0/usb_types.h"
#include "v1_0/iscsi_peripheral_ddk.h"


using OHOS::HDI::Usb::ScsiDdk::V1_0::IScsiPeripheralDdk;
using OHOS::HDI::Usb::ScsiDdk::V1_0::ScsiPeripheralDevice;

namespace OHOS {
namespace SCSI {
int32_t ScsiFuzzTestHostModeInit(const sptr<IScsiPeripheralDdk> &scsiPeripheralDdk, ScsiPeripheralDevice &device);

const int32_t SLEEP_TIME = 3;
} // namespace SCSI
} // namespace OHOS

#endif // SCSICOMMONFUNCTION_FUZZER_H