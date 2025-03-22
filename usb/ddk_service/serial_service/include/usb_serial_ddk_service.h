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

#ifndef USB_SERIAL_DDK_SERVICE_H
#define USB_SERIAL_DDK_SERVICE_H

#include "v1_0/iusb_serial_ddk.h"

namespace OHOS {
namespace HDI {
namespace Usb {
namespace UsbSerialDdk {
namespace V1_0 {

class UsbSerialOsAdapter;

typedef enum {
    DATA_BITS_5 = 5,
    DATA_BITS_6 = 6,
    DATA_BITS_7 = 7,
    DATA_BITS_8 = 8
} UsbSerialDataBits;

typedef enum {
    STOP_ONE = 1,
    STOP_TWO = 2
} UsbSerialStopBits;

enum UsbSerialDdkRetCode {
    USB_SERIAL_DDK_NO_PERM = 201,
    USB_SERIAL_DDK_INVALID_PARAMETER = 401,
    USB_SERIAL_DDK_SUCCESS = 31600000,
    USB_SERIAL_DDK_INVALID_OPERATION = 31600001,
    USB_SERIAL_DDK_INIT_ERROR = 31600002,
    USB_SERIAL_DDK_SERVICE_ERROR = 31600003,
    USB_SERIAL_DDK_MEMORY_ERROR = 31600004,
    USB_SERIAL_DDK_IO_ERROR = 31600005,
    USB_SERIAL_DDK_DEVICE_NOT_FOUND = 31600006,
};

class UsbSerialDdkService : public IUsbSerialDdk {
public:
    UsbSerialDdkService(std::shared_ptr<UsbSerialOsAdapter> &osAdapter) : osAdapter_(osAdapter) {};
    virtual ~UsbSerialDdkService() = default;

    int32_t Init() override;

    int32_t Release() override;

    int32_t Open(uint64_t deviceId, uint64_t interfaceIndex,
        OHOS::HDI::Usb::UsbSerialDdk::V1_0::UsbSerialDeviceHandle &dev) override;

    int32_t Close(const OHOS::HDI::Usb::UsbSerialDdk::V1_0::UsbSerialDeviceHandle &dev) override;

    int32_t Read(const OHOS::HDI::Usb::UsbSerialDdk::V1_0::UsbSerialDeviceHandle &dev, uint32_t bufferSize,
        std::vector<uint8_t> &buff) override;

    int32_t Write(const OHOS::HDI::Usb::UsbSerialDdk::V1_0::UsbSerialDeviceHandle &dev,
        const std::vector<uint8_t> &buff, uint32_t &bytesWritten) override;

    int32_t SetBaudRate(const OHOS::HDI::Usb::UsbSerialDdk::V1_0::UsbSerialDeviceHandle &dev,
        uint32_t baudRate) override;

    int32_t SetParams(const OHOS::HDI::Usb::UsbSerialDdk::V1_0::UsbSerialDeviceHandle &dev,
        const OHOS::HDI::Usb::UsbSerialDdk::V1_0::UsbSerialParams &params) override;

    int32_t SetTimeout(const OHOS::HDI::Usb::UsbSerialDdk::V1_0::UsbSerialDeviceHandle &dev, int32_t timeout) override;

    int32_t SetFlowControl(const OHOS::HDI::Usb::UsbSerialDdk::V1_0::UsbSerialDeviceHandle &dev,
        OHOS::HDI::Usb::UsbSerialDdk::V1_0::UsbSerialFlowControl flowControl) override;

    int32_t Flush(const OHOS::HDI::Usb::UsbSerialDdk::V1_0::UsbSerialDeviceHandle &dev) override;

    int32_t FlushInput(const OHOS::HDI::Usb::UsbSerialDdk::V1_0::UsbSerialDeviceHandle &dev) override;

    int32_t FlushOutput(const OHOS::HDI::Usb::UsbSerialDdk::V1_0::UsbSerialDeviceHandle &dev) override;

private:
    std::shared_ptr<UsbSerialOsAdapter> osAdapter_;
};
} // namespace V1_0
} // namespace UsbSerialDdk
} // namespace Usb
} // namespace HDI
} // namespace OHOS
#endif // USB_SERIAL_DDK_SERVICE_H