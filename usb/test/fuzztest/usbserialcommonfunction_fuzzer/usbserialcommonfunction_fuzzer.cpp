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

#include <cinttypes>
#include "usbserialcommonfunction_fuzzer.h"
#include "UsbSubscriberTest.h"
#include "hdf_log.h"

using namespace OHOS::HDI::Usb::UsbSerialDdk::V1_0;

namespace OHOS {
namespace USBSerial {

constexpr uint32_t SHIFT_32 = 32;

static uint64_t ToDdkDeviceId(const uint8_t busNum, const uint8_t devAddr)
{
    return (static_cast<uint64_t>(busNum) << SHIFT_32) + devAddr;
}

int32_t UsbSerialFuzzTestHostModeInit(const sptr<IUsbSerialDdk> &usbSerialInterface, UsbSerialDeviceHandle *device)
{
    sptr<OHOS::HDI::Usb::V1_0::IUsbInterface> usbInterface = OHOS::HDI::Usb::V1_0::IUsbInterface::Get();
    sleep(SLEEP_TIME);

    sptr<OHOS::USB::UsbSubscriberTest> subscriber = new OHOS::USB::UsbSubscriberTest();
    int32_t ret = usbInterface->BindUsbdSubscriber(subscriber);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: bind usbd subscriber failed", __func__);
        return ret;
    }

    uint8_t busNum = subscriber->busNum_;
    uint8_t devAddr = subscriber->devAddr_;
    uint64_t interfaceIndex = 0x00;

    HDF_LOGI("%{public}s: busNum:%{public}d, devAddr:%{public}d, deviceID:%{public}016" PRIX64, __func__,
             subscriber->busNum_, subscriber->devAddr_, ToDdkDeviceId(busNum, devAddr));
    ret = usbSerialInterface->Open(ToDdkDeviceId(busNum, devAddr), interfaceIndex, *device);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: open device failed", __func__);
        return ret;
    }
    return ret;
}
} // namespace V1_0
} // namespace UsbSerialDdk
