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
#ifndef LINUX_SERIAL_H
#define LINUX_SERIAL_H

#include <mutex>
#include <atomic>
#include <string>
#include <vector>
#include <termios.h>
#include <thread>
#include <map>
#include "v1_0/serial_types.h"
#include "serial_sysfs_device.h"
#include "hdf_dlist.h"
#include "hdf_io_service_if.h"
#include "hdf_sbuf.h"
#include "osal_mem.h"
#include "osal_mutex.h"

namespace OHOS {
namespace HDI {
namespace Usb {
namespace Serial {
namespace V1_0 {

struct Serialfd {
    int32_t fd;
    int32_t portId;
};

struct UsbDdkDeviceInfo {
    struct OsalMutex deviceMutex;
    struct DListHead list;
    struct UsbPnpNotifyMatchInfoTable info;
};

class LinuxSerial {
public:
    static LinuxSerial &GetInstance();
    int32_t SerialOpen(int32_t portId);
    int32_t SerialClose(int32_t portId);
    int32_t SerialGetPortList(std::vector<SerialPort>& portIds);
    int32_t SerialRead(int32_t portId, std::vector<uint8_t>& data, uint32_t size, uint32_t timeout);
    int32_t SerialWrite(int32_t portId, const std::vector<uint8_t>& data, uint32_t size, uint32_t timeout);
    int32_t SerialGetAttribute(int32_t portId, struct SerialAttribute& attribute);
    int32_t SerialSetAttribute(int32_t portId, const struct SerialAttribute& attribute);

private:
    LinuxSerial();
    ~LinuxSerial();

    int32_t GetFdByPortId(int32_t portId);
    int32_t GetBaudrate(unsigned int baudrate);
    int32_t GetDatabits(unsigned char dataBits, tcflag_t& cflag);
    int32_t GetParity(tcflag_t& cflag, unsigned char parity);
    int32_t GetStopbits(tcflag_t& cflag, unsigned char stopBits);
    void HandleDevListEntry(struct UsbPnpNotifyMatchInfoTable *device, std::vector<SerialPort>& portIds,
        std::string targetPath);
private:
    std::mutex portMutex_;
    std::vector<Serialfd> serialPortList_;
    struct termios options_;
};
} // V1_0
} // Serial
} // Usb
} // HDI
} // OHOS

#endif // LINUX_SERIAL_H