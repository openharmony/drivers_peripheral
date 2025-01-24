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

#include "usbserialflushoutput_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include "hdf_log.h"
#include "usbserialcommonfunction_fuzzer.h"

using namespace OHOS::HDI::Usb::UsbSerialDdk::V1_0;

namespace OHOS {
constexpr size_t THRESHOLD = 10;

namespace USBSerial {

bool UsbSerialFlushFuzzTest(const uint8_t *data, size_t size)
{
    (void) data;
    (void) size;
    sptr<IUsbSerialDdk> usbSerialInterface = IUsbSerialDdk::Get();
    int32_t ret = usbSerialInterface->Init();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: init failed, ret = %d", __func__, ret);
        return false;
    }

    UsbSerialDeviceHandle* device = nullptr;
    ret = UsbSerialFuzzTestHostModeInit(usbSerialInterface, device);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: UsbSerial open device failed, ret = %d", __func__, ret);
        return false;
    }

    ret = usbSerialInterface->Flush(*device);
    ret = usbSerialInterface->Close(*device);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: close device failed", __func__);
        usbSerialInterface->Release();
        return false;
    }
    ret = usbSerialInterface->Release();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: release failed", __func__);
        return false;
    }
    return true;
}
} // namespace USBSerial
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < OHOS::THRESHOLD) {
        return 0;
    }
    OHOS::USBSerial::UsbSerialFlushFuzzTest(data, size);
    return 0;
}