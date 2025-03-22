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

#include "usb_serial_liteos_adapter.h"
#include <cstdint>
#include <hdf_base.h>

#define HDF_LOG_TAG usb_serial_liteos_adapter

namespace OHOS {
namespace HDI {
namespace Usb {
namespace UsbSerialDdk {
namespace V1_0 {

int32_t LiteOsUsbSerialOsAdapter::SetBaudRate(int32_t fd, uint32_t baudRate)
{
    return USB_SERIAL_DDK_INVALID_OPERATION;
}

int32_t LiteOsUsbSerialOsAdapter::SetParams(int32_t fd, const UsbSerialParams &params)
{
    return USB_SERIAL_DDK_INVALID_OPERATION;
}

int32_t LiteOsUsbSerialOsAdapter::SetTimeout(int32_t fd, int32_t timeout)
{
    return USB_SERIAL_DDK_INVALID_OPERATION;
}

int32_t LiteOsUsbSerialOsAdapter::SetFlowControl(int32_t fd, int32_t flowControl)
{
    return USB_SERIAL_DDK_INVALID_OPERATION;
}

bool LiteOsUsbSerialOsAdapter::IsDeviceDisconnect(int32_t fd)
{
    return false;
}

int32_t LiteOsUsbSerialOsAdapter::Flush(int32_t fd)
{
    return USB_SERIAL_DDK_INVALID_OPERATION;
}

int32_t LiteOsUsbSerialOsAdapter::FlushInput(int32_t fd)
{
    return USB_SERIAL_DDK_INVALID_OPERATION;
}

int32_t LiteOsUsbSerialOsAdapter::FlushOutput(int32_t fd)
{
    return USB_SERIAL_DDK_INVALID_OPERATION;
}

} // namespace V1_0
} // namespace UsbSerialDdk
} // namespace Usb
} // namespace HDI
} // namespace OHOS
