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

#include "usbserialddk_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include "hdf_log.h"
#include "v1_0/usb_serial_ddk_stub.h"
#include "v1_0/iusb_serial_ddk.h"

using namespace OHOS::HDI::Usb::UsbSerialDdk::V1_0;

namespace OHOS {
constexpr size_t THRESHOLD = 10;

namespace USBSerial {
constexpr int32_t OFFSET = 4;
constexpr int32_t ZERO_BIT = 0;
constexpr int32_t FIRST_BIT = 1;
constexpr int32_t SECOND_BIT = 2;
constexpr int32_t THIRD_BIT = 3;
constexpr int32_t ZERO_MOVE_LEN = 24;
constexpr int32_t FIRST_MOVE_LEN = 16;
constexpr int32_t SECOND_MOVE_LEN = 8;
const std::u16string USBSERIAL_INTERFACE_TOKEN = u"ohos.hdi.usb.usb_serial_ddk.v1_0.IUsbSerialDdk";

uint32_t Convert2Uint32(const uint8_t *ptr)
{
    if (ptr == nullptr) {
        HDF_LOGE("%{public}s: ptr is null", __func__);
        return 0;
    }
    /*
     * Move the 0th digit 24 to the left, the first digit 16 to the left, the second digit 8 to the left,
     * and the third digit no left
     */
    return (ptr[ZERO_BIT] << ZERO_MOVE_LEN) | (ptr[FIRST_BIT] << FIRST_MOVE_LEN) | (ptr[SECOND_BIT] <<
        SECOND_MOVE_LEN) | (ptr[THIRD_BIT]);
}

bool DoSomethingInterestingWithMyAPI(const uint8_t *rawData, size_t size)
{
    if (rawData == nullptr) {
        HDF_LOGE("%{public}s: rawData is null", __func__);
        return false;
    }
    uint32_t code = Convert2Uint32(rawData);
    rawData = rawData + OFFSET;
    size = size - OFFSET;

    MessageParcel data;
    data.WriteInterfaceToken(USBSERIAL_INTERFACE_TOKEN);
    data.WriteBuffer(rawData, size);
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    sptr<IUsbSerialDdk> usbDdkSerialInterface = IUsbSerialDdk::Get(false);
    if (usbDdkSerialInterface == nullptr) {
        HDF_LOGE("%{public}s: get usbSerialDdkInterface failed", __func__);
        return false;
    }
    sptr<UsbSerialDdkStub> usbSerialDdk = new UsbSerialDdkStub(usbDdkSerialInterface);
    if (usbSerialDdk == nullptr) {
        HDF_LOGE("%{public}s: new usbSerialDdk failed", __func__);
        return false;
    }
    usbSerialDdk->OnRemoteRequest(code, data, reply, option);

    return true;
}

} // namespace USBSerial
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < OHOS::THRESHOLD) {
        return 0;
    }

    /* Run your code on data */
    OHOS::USBSerial::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}