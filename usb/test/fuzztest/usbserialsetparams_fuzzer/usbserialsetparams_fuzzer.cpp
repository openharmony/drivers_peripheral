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

#include "usbserialsetparams_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include "hdf_log.h"
#include "usbserialcommonfunction_fuzzer.h"

using namespace OHOS::HDI::Usb::UsbSerialDdk::V1_0;

namespace OHOS {
constexpr size_t THRESHOLD = 10;

namespace USBSerial {

constexpr uint32_t DEFAULT_BAUD_RATE = 9600;
constexpr uint8_t DEFAULT_DATA_BITS = 8;
constexpr uint8_t DEFAULT_STOP_BITS = 1;

static void UpdateParamsFromData(UsbSerialParams& params, const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        HDF_LOGE("Invalid input data.");
        return;
    }

    size_t offset = 0;
    if (size >= sizeof(uint32_t)) {
        params.baudRate = static_cast<uint32_t>(data[0]) | (static_cast<uint32_t>(data[1]) << SECOND_MOVE_LEN) |
                            (static_cast<uint32_t>(data[SECOND_BIT]) << FIRST_MOVE_LEN) |
                            (static_cast<uint32_t>(data[THIRD_BIT]) << ZERO_MOVE_LEN);
        offset += sizeof(uint32_t);
    }

    if (size >= offset + sizeof(uint8_t)) {
        params.nDataBits = data[offset++];
    }

    if (size >= offset + sizeof(uint8_t)) {
        params.nStopBits = data[offset++];
    }

    if (size >= offset + sizeof(uint8_t)) {
        enum UsbSerialParity parityValue = static_cast<enum UsbSerialParity>(data[offset]);
        params.parity = parityValue;
    }
}

bool UsbSerialSetParamsFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IUsbSerialDdk> usbSerialInterface = IUsbSerialDdk::Get();
    int32_t ret = usbSerialInterface->Init();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: init failed, ret = %d", __func__, ret);
        return false;
    }

    UsbSerialParams params = {
        .baudRate = DEFAULT_BAUD_RATE,
        .nDataBits = DEFAULT_DATA_BITS,
        .nStopBits = DEFAULT_STOP_BITS,
        .parity = USB_SERIAL_PARITY_NONE,
    };

    UsbSerialDeviceHandle* device = nullptr;
    ret = UsbSerialFuzzTestHostModeInit(usbSerialInterface, device);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: UsbSerial open device failed, ret = %d", __func__, ret);
        return false;
    }

    UpdateParamsFromData(params, data, size);
    ret = usbSerialInterface->SetParams(*device, params);
    if (ret != HDF_SUCCESS) {
        usbSerialInterface->Release();
        HDF_LOGE("%{public}s: SetBaudRate failed", __func__);
        return false;
    }

    ret = usbSerialInterface->Close(*device);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: close device failed", __func__);
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
    OHOS::USBSerial::UsbSerialSetParamsFuzzTest(data, size);
    return 0;
}