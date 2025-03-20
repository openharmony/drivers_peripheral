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
#ifndef LIBUSB_SERIAL_H
#define LIBUSB_SERIAL_H

#include <libusb.h>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <thread>
#include <string>
#include <vector>

#include "v1_0/serial_types.h"

namespace OHOS {
namespace HDI {
namespace Usb {
namespace Serial {
namespace V1_0 {

class LibusbSerial {
public:
    static LibusbSerial &GetInstance();
    int32_t SerialOpen(int32_t num);
    int32_t SerialClose(int32_t num);
    int32_t SerialGetPortList(std::vector<SerialPort>& portIds);
    int32_t SerialRead(int32_t portId, std::vector<uint8_t>& data, uint32_t size, uint32_t timeout);
    int32_t SerialWrite(int32_t portId, const std::vector<uint8_t>& data, uint32_t size, uint32_t timeout);
    int32_t SerialGetAttribute(int32_t portId, struct SerialAttribute& attribute);
    int32_t SerialSetAttribute(int32_t portId, const struct SerialAttribute& attribute);

private:
    // DeviceHandleInfo struct to hold device info
    typedef struct DeviceHandleInfo {
        int num;
        libusb_device_handle* handle;
        bool isOpen;
        uint8_t outputEndpointAddr;
        uint8_t inputEndpointAddr;
        int32_t interface;
    } DeviceHandleInfo;

    LibusbSerial();
    ~LibusbSerial();
    int32_t GetApiVersion();
    int GetEndPoint(DeviceHandleInfo* deviceHandleInfo);
    void EventHandlingThread();
    int32_t GetPortIdByDevice(libusb_device* device);
    static int32_t HotplugCallback(libusb_context* ctx, libusb_device* device,
        libusb_hotplug_event event, void* user_data);
    int32_t HandleDeviceArrival(libusb_device* device);
    void HandleDeviceRemoval(libusb_device* device);
    libusb_device_handle* GetDeviceHandle(int portId);
    libusb_device* GetDevice(int portId);
    int32_t GetSerialDeviceInfo(libusb_device* device, libusb_device_handle* handle, DeviceInfo &deviceInfo);
    void GetExistedDevices();

private:
    libusb_context* ctx_;
    libusb_hotplug_callback_handle hotplug_handle_ = 0;
    // Map devices by libusb_device*
    std::unordered_map<libusb_device*, DeviceHandleInfo> devices_;
    std::mutex map_mutex_;
    std::mutex writeMutex_;
    std::atomic<bool> running_;
    std::thread event_thread_;
};
} // V1_0
} // Serial
} // Usb
} // HDI
} // OHOS

#endif // LIBUSB_SERIAL_H