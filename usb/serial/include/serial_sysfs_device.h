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

#ifndef SERIAL_SYSFS_DEVICE_H
#define SERIAL_SYSFS_DEVICE_H
#include <stdint.h>
#include <string>

#define SERIAL_MAX_INTERFACES     32
#define SYSFS_DEVICES_DIR "/sys/bus/usb-serial/devices/"

namespace OHOS {
namespace HDI {
namespace Usb {
namespace Serial {
namespace V1_0 {

struct UsbPnpNotifyInterfaceInfo {
    uint8_t interfaceClass;
    uint8_t interfaceSubClass;
    uint8_t interfaceProtocol;
    uint8_t interfaceNumber;
};

struct UsbPnpNotifyDeviceInfo {
    uint16_t vendorId;
    uint16_t productId;
    uint16_t bcdDeviceLow;
    uint16_t bcdDeviceHigh;
    uint8_t deviceClass;
    uint8_t deviceSubClass;
    uint8_t deviceProtocol;
    std::string serialNo;
};

struct UsbPnpNotifyMatchInfoTable {
    uint64_t usbDevAddr;
    int32_t devNum;
    int32_t busNum;

    struct UsbPnpNotifyDeviceInfo deviceInfo;

    uint8_t removeType;
    uint8_t numInfos;

    struct UsbPnpNotifyInterfaceInfo interfaceInfo[SERIAL_MAX_INTERFACES];
};

typedef struct DevInterfaceInfo {
    uint32_t busNum;
    uint32_t devNum;
    uint8_t  intfNum;
} DevInterfaceInfo;

uint64_t SerialMakeDevAddr(uint32_t busNum, uint32_t devNum);
int32_t SerialGetDevice(const char *deviceDir, struct UsbPnpNotifyMatchInfoTable *device);
} // V1_0
} // Serial
} // Usb
} // HDI
} // OHOS
#endif // SERIAL_SYSFS_DEVICE_H