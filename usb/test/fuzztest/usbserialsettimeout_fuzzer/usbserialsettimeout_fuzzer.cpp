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

#include "usbserialsettimeout_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include "hdf_log.h"
#include "usbserialcommonfunction_fuzzer.h"

using namespace OHOS::HDI::Usb::UsbSerialDdk::V1_0;

namespace OHOS {
constexpr size_t THRESHOLD = 10;

namespace USBSerial {
constexpr int32_t DEFAULT_TIMEOUT = 3000;

static int32_t GetTimeoutFromData(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        HDF_LOGE("Invalid input data or insufficient size.");
        return DEFAULT_TIMEOUT;
    }

    int32_t timeout = static_cast<int32_t>(static_cast<uint32_t>(data[0]) |
            (static_cast<uint32_t>(data[1]) << SECOND_MOVE_LEN) |
            (static_cast<uint32_t>(data[SECOND_BIT]) << FIRST_MOVE_LEN) |
            (static_cast<uint32_t>(data[THIRD_BIT]) << ZERO_MOVE_LEN));

    return timeout;
}

bool UsbSerialSetBaudRateFuzzTest(const uint8_t *data, size_t size)
{
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

    int32_t timeout = GetTimeoutFromData(data, size);
    ret = usbSerialInterface->SetTimeout(*device, timeout);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: SetBaudRate failed", __func__);
        return false;
    }

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
    OHOS::USBSerial::UsbSerialSetBaudRateFuzzTest(data, size);
    return 0;
}