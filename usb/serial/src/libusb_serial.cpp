/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include "libusb_serial.h"
#include <cerrno>
#include <hdf_base.h>
#include <hdf_log.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <climits>
#include <iostream>
#include <cstring>
#include <string>
#include <chrono>
#include <libudev.h>
#include "usbd_wrapper.h"
#include "securec.h"

namespace OHOS {
namespace HDI {
namespace Usb {
namespace Serial {
namespace V1_0 {

#define TARGET_INTERFACE 0xFF
#define MAX_TRANS_DATA_SIZE 8192
#define ENABLE_UNREF 1
#define TRANSFER_TIMEOUT 1000
#define DIRECT_NUM 2
#define TRANSFER_CONTROL_OUT_CODE 0x20
#define TRANSFER_CONTROL_IN_CODE 0x21
#define RETRY_TIMEOUT 200
#define RETRY_NUM 5
#define BUFFER_SIZE 256
#define ERR_CODE_IOEXCEPTION (-5)
#define ERR_CODE_DEVICENOTOPEN (-6)

static const std::string SERIAL_TYPE_NAME = "ttyUSB";
static const std::string DEVICE_NAME_STR = "/dev/ttyUSB";
static const char *UDEV_SUB_SYSTEM = "tty";
static const char *UDEV_PARENT_TYPE = "usb";
static const char *UDEV_PARENT_DEVICE = "usb_device";
static const char *BUSNUM_STR = "busnum";
static const char *DEVNUM_STR = "devnum";

LibusbSerial &LibusbSerial::GetInstance()
{
    static LibusbSerial instance;
    return instance;
}

LibusbSerial::LibusbSerial(): ctx_(nullptr), running_(true)
{
    HDF_LOGI("%{public}s: enter SerialUSBWrapper initialization.", __func__);

    int rc = libusb_init(&ctx_);
    if (rc != LIBUSB_SUCCESS) {
        HDF_LOGE("%{public}s: Failed to initialize libusb: %{public}d", __func__, rc);
        ctx_ = nullptr;

        return;
    }

    if (!libusb_has_capability(LIBUSB_CAP_HAS_HOTPLUG)) {
        HDF_LOGE("%{public}s: Hotplug capability is not supported on this platform", __func__);
        libusb_exit(ctx_);
        ctx_ = nullptr;

        return;
    }

    rc = libusb_hotplug_register_callback(ctx_,
        static_cast<libusb_hotplug_event>(
            LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED |
            LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT),
        LIBUSB_HOTPLUG_NO_FLAGS,
        LIBUSB_HOTPLUG_MATCH_ANY,
        LIBUSB_HOTPLUG_MATCH_ANY,
        LIBUSB_HOTPLUG_MATCH_ANY,
        HotplugCallback,
        this,
        &hotplug_handle_);
    if (rc != LIBUSB_SUCCESS) {
        HDF_LOGE("%{public}s: Failed to register hotplug callback: %{public}d", __func__, rc);
        libusb_exit(ctx_);
        ctx_ = nullptr;

        return;
    }

    GetExistedDevices();
    event_thread_ = std::thread(&LibusbSerial::EventHandlingThread, this);
    HDF_LOGI("%{public}s: SerialUSBWrapper initialization completed.", __func__);
}

LibusbSerial::~LibusbSerial()
{
    HDF_LOGI("%{public}s: enter Destroying SerialUSBWrapper.", __func__);
    running_ = false;
    if (event_thread_.joinable()) {
        event_thread_.join();
    }
    if (ctx_) {
        libusb_hotplug_deregister_callback(ctx_, hotplug_handle_);
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    for (auto& pair : devices_) {
        if (pair.second.handle) {
            libusb_close(pair.second.handle);
            pair.second.handle = nullptr;
        }
    }

    devices_.clear();

    if (ctx_) {
        libusb_exit(ctx_);
        ctx_ = nullptr;
    }

    HDF_LOGI("%{public}s: SerialUSBWrapper destroyed.", __func__);
}

void LibusbSerial::GetExistedDevices()
{
    libusb_device** device_list = nullptr;
    ssize_t count = libusb_get_device_list(ctx_, &device_list);
    if (count < 0) {
        HDF_LOGE("%{public}s: Failed to get device list: %{public}d", __func__, (int)count);
        return;
    }

    for (ssize_t idx = 0; idx < count; ++idx) {
        libusb_device* device = device_list[idx];
        int num = GetDeviceNum(device);
        if (num >= 0) {
            HandleDeviceArrival(device);
        }
    }

    libusb_free_device_list(device_list, ENABLE_UNREF);
    HDF_LOGI("%{public}s: Existing devices enumeration completed. device count: %{public}d", __func__, count);
}

int32_t LibusbSerial::SerialOpen(int32_t num)
{
    HDF_LOGI("%{public}s: enter SerialOpen called for num: %{public}d.", __func__, num);
    std::lock_guard<std::mutex> lock(map_mutex_);
    for (auto& pair : devices_) {
        if (pair.second.num == num) {
            if (pair.second.isOpen) {
                return HDF_SUCCESS;
            }
            pair.second.isOpen = true;
            return HDF_SUCCESS;
        }
    }
    HDF_LOGE("%{public}s: Device not found: num = %{public}d", __func__, num);
    return HDF_FAILURE;
}

int32_t LibusbSerial::SerialClose(int32_t num)
{
    HDF_LOGI("%{public}s: enter SerialClose called for num: %{public}d.", __func__, num);
    std::lock_guard<std::mutex> lock(map_mutex_);
    for (auto& pair : devices_) {
        if (pair.second.num == num) {
            if (pair.second.isOpen) {
                pair.second.isOpen = false;
                HDF_LOGI("%{public}s: Device logically closed: num = %{public}d", __func__, num);
            }
            return HDF_SUCCESS;
        }
    }
    return HDF_SUCCESS;
}

int32_t LibusbSerial::GetSerialDeviceInfo(libusb_device* device, libusb_device_handle* handle, DeviceInfo &deviceInfo)
{
    HDF_LOGI("%{public}s: enter GetSerialDeviceInfo.", __func__);
    struct libusb_device_descriptor desc;
    int result = -1;
    result = libusb_get_device_descriptor(device, &desc);
    if (result < 0) {
        HDF_LOGE("%{public}s: get device descriptor error: %{public}d", __func__, result);
        return HDF_FAILURE;
    }

    char serialNumber[BUFFER_SIZE] = {'\0'};
    unsigned char serial[BUFFER_SIZE] = {'\0'};
    if (handle && desc.iSerialNumber) {
        result = libusb_get_string_descriptor_ascii(handle, desc.iSerialNumber, serial, sizeof(serial));
    }
    if (result > 0) {
        int n = snprintf_s(serialNumber, sizeof(serialNumber), sizeof(serialNumber)-1, "%s",
            reinterpret_cast<char*>(serial));
        if (n < 0) {
            return HDF_FAILURE;
        }
    } else {
        HDF_LOGE("%{public}s: get serial num error, result: %{public}d", __func__, result);
        return HDF_FAILURE;
    }

    deviceInfo.vid = desc.idVendor;
    deviceInfo.pid = desc.idProduct;
    deviceInfo.busNum = libusb_get_bus_number(device);
    deviceInfo.devAddr = libusb_get_device_address(device);
    deviceInfo.serialNum = std::string(serialNumber);
    return HDF_SUCCESS;
}

int32_t LibusbSerial::SerialGetPortList(std::vector<SerialPort>& portIds)
{
    HDF_LOGI("%{public}s: enter SerialGetPortList.", __func__);

    std::lock_guard<std::mutex> lock(map_mutex_);
    portIds.clear();
    for (const std::pair<libusb_device*, DeviceHandleInfo>& device : devices_) {
        SerialPort serialPort;
        libusb_device* dev = device.first;
        libusb_device_handle* handle = device.second.handle;

        GetSerialDeviceInfo(dev, handle, serialPort.deviceInfo);
        serialPort.portId = device.second.num;
        portIds.push_back(serialPort);
    }
    return HDF_SUCCESS;
}

libusb_device_handle* LibusbSerial::GetDeviceHandle(int portId)
{
    std::lock_guard guard(map_mutex_);
    for (auto ite = devices_.cbegin(); ite != devices_.cend(); ++ite) {
        if (ite->second.num == portId) {
            return ite->second.handle;
        }
    }
    return nullptr;
}

libusb_device* LibusbSerial::GetDevice(int portId)
{
    std::lock_guard guard(map_mutex_);
    for (auto ite = devices_.cbegin(); ite != devices_.cend(); ++ite) {
        if (ite->second.num == portId) {
            return ite->first;
        }
    }
    return nullptr;
}

int32_t LibusbSerial::SerialRead(int32_t portId, std::vector<uint8_t>& data, uint32_t size)
{
    HDF_LOGI("%{public}s: enter serial read.", __func__);
    libusb_device* device = GetDevice(portId);
    if (device == nullptr) {
        HDF_LOGE("%{public}s: get device failed", __func__);
        return ERR_CODE_IOEXCEPTION;
    }
    DeviceHandleInfo deviceHandleInfo = devices_[device];
    if (!deviceHandleInfo.isOpen) {
        HDF_LOGE("%{public}s: device not open", __func__);
        return ERR_CODE_DEVICENOTOPEN;
    }
    int ret = 0;
    int actual_length = 0;
    uint8_t data_in[MAX_TRANS_DATA_SIZE] = {0};
    
    std::lock_guard<std::mutex> lock(writeMutex_);
    libusb_attach_kernel_driver(deviceHandleInfo.handle, deviceHandleInfo.interface);
    libusb_release_interface(deviceHandleInfo.handle, deviceHandleInfo.interface);
    libusb_detach_kernel_driver(deviceHandleInfo.handle, deviceHandleInfo.interface);
    ret = libusb_claim_interface(deviceHandleInfo.handle, deviceHandleInfo.interface);
    if (ret < 0) {
        HDF_LOGE("%{public}s: libusb claim failed, ret:%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    ret = 0;
    ret = libusb_bulk_transfer(deviceHandleInfo.handle,
        deviceHandleInfo.intputEndpointAddr, data_in, size, &actual_length, TRANSFER_TIMEOUT);
    if (ret < 0 && actual_length == 0) {
        libusb_release_interface(deviceHandleInfo.handle, deviceHandleInfo.interface);
        libusb_attach_kernel_driver(deviceHandleInfo.handle, deviceHandleInfo.interface);
        HDF_LOGE("%{public}s: read message failed, ret:%{public}d", __func__, ret);
        return ret;
    }

    std::vector<uint8_t> vec(data_in, data_in + actual_length);
    data.insert(data.end(), vec.begin(), vec.end());
    size = actual_length;
    libusb_release_interface(deviceHandleInfo.handle, deviceHandleInfo.interface);
    libusb_attach_kernel_driver(deviceHandleInfo.handle, deviceHandleInfo.interface);
    return HDF_SUCCESS;
}

int32_t LibusbSerial::SerialWrite(int32_t portId, const std::vector<uint8_t>& data, uint32_t size)
{
    HDF_LOGI("%{public}s: enter serial write.", __func__);
    libusb_device* device = GetDevice(portId);
    if (device == nullptr) {
        HDF_LOGE("%{public}s: get device failed", __func__);
        return ERR_CODE_IOEXCEPTION;
    }
    
    DeviceHandleInfo deviceHandleInfo = devices_[device];
    if (!deviceHandleInfo.isOpen) {
        HDF_LOGE("%{public}s: device not open", __func__);
        return ERR_CODE_DEVICENOTOPEN;
    }
    int ret = 0;
    int actual_length = 0;
    const uint8_t* data_out = data.data();
    std::lock_guard<std::mutex> lock(writeMutex_);
    libusb_release_interface(deviceHandleInfo.handle, deviceHandleInfo.interface);
    libusb_attach_kernel_driver(deviceHandleInfo.handle, deviceHandleInfo.interface);
    libusb_detach_kernel_driver(deviceHandleInfo.handle, deviceHandleInfo.interface);
    ret = libusb_claim_interface(deviceHandleInfo.handle, deviceHandleInfo.interface);
    if (ret < 0) {
        HDF_LOGE("%{public}s: libusb claim failed, ret:%{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    ret = libusb_bulk_transfer(deviceHandleInfo.handle, deviceHandleInfo.outputEndpointAddr,
        const_cast<uint8_t*>(data_out), data.size(), &actual_length, TRANSFER_TIMEOUT);
    if (ret < 0) {
        HDF_LOGE("%{public}s: write message failed, ret:%{public}d", __func__, ret);
        libusb_release_interface(deviceHandleInfo.handle, deviceHandleInfo.interface);
        libusb_attach_kernel_driver(deviceHandleInfo.handle, deviceHandleInfo.interface);
        return ret;
    }
    size = actual_length;
    libusb_release_interface(deviceHandleInfo.handle, deviceHandleInfo.interface);
    libusb_attach_kernel_driver(deviceHandleInfo.handle, deviceHandleInfo.interface);
    return HDF_SUCCESS;
}

int LibusbSerial::GetEndPoint(DeviceHandleInfo *deviceHandleInfo)
{
    int endpointNum = 0;
    struct libusb_config_descriptor *config;
    libusb_device *device = libusb_get_device(deviceHandleInfo->handle);

    libusb_get_active_config_descriptor(device, &config);
    for (int j = 0; j < config->bNumInterfaces; j++) {
        const struct libusb_interface *interface = &config->interface[j];
        const struct libusb_interface_descriptor *interfaceDesc = interface->altsetting;
        if (interfaceDesc->bInterfaceClass != TARGET_INTERFACE) {
            continue;
        }
        for (int k = 0; k < interfaceDesc->bNumEndpoints; k++) {
            const struct libusb_endpoint_descriptor *endpoint = &interfaceDesc->endpoint[k];
            if ((endpoint->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) == LIBUSB_TRANSFER_TYPE_BULK &&
                (endpoint->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_IN) {
                deviceHandleInfo->interface = j;
                deviceHandleInfo->intputEndpointAddr = endpoint->bEndpointAddress;
                endpointNum++;
            }
            if ((endpoint->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) == LIBUSB_TRANSFER_TYPE_BULK &&
                (endpoint->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_OUT) {
                endpointNum++;
                deviceHandleInfo->interface = j;
                deviceHandleInfo->outputEndpointAddr = endpoint->bEndpointAddress;
            }
        }
    }
    libusb_free_config_descriptor(config);

    return endpointNum != DIRECT_NUM ? HDF_FAILURE : HDF_SUCCESS;
}

int32_t LibusbSerial::SerialGetAttribute(int32_t portId, struct SerialAttribute& attribute)
{
    HDF_LOGI("%{public}s: enter GetAttribute msg", __func__);
    libusb_device* device = GetDevice(portId);
    if (device == nullptr) {
        HDF_LOGE("%{public}s: libusb_device is null", __func__);
        return ERR_CODE_IOEXCEPTION;
    }
    DeviceHandleInfo deviceHandleInfo = devices_[device];
    if (!deviceHandleInfo.isOpen) {
        HDF_LOGE("%{public}s: device not open", __func__);
        return ERR_CODE_DEVICENOTOPEN;
    }
    int ret = 0;
    libusb_release_interface(deviceHandleInfo.handle, deviceHandleInfo.interface);
    libusb_attach_kernel_driver(deviceHandleInfo.handle, deviceHandleInfo.interface);
    libusb_detach_kernel_driver(deviceHandleInfo.handle, deviceHandleInfo.interface);
    ret = libusb_claim_interface(deviceHandleInfo.handle, deviceHandleInfo.interface);
    if (ret < 0) {
        HDF_LOGE("%{public}s: libusb claim failed, ret:%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    unsigned char request_type = LIBUSB_ENDPOINT_IN | LIBUSB_REQUEST_TYPE_CLASS | LIBUSB_RECIPIENT_INTERFACE;
    uint16_t index = 0;
    uint16_t value = 0;
    int length = sizeof(struct SerialAttribute);
    ret =  libusb_control_transfer(deviceHandleInfo.handle, request_type, TRANSFER_CONTROL_IN_CODE,
        value, index, (unsigned char *)&attribute, length, TRANSFER_TIMEOUT);
    libusb_release_interface(deviceHandleInfo.handle, deviceHandleInfo.interface);
    libusb_attach_kernel_driver(deviceHandleInfo.handle, deviceHandleInfo.interface);
    if (ret < 0) {
        HDF_LOGE("%{public}s: libusb get attribute failed, ret:%{public}d", __func__, ret);
        return ret;
    }
    return HDF_SUCCESS;
}

int32_t LibusbSerial::SerialSetAttribute(int32_t portId, const struct SerialAttribute& attribute)
{
    HDF_LOGI("%{public}s: enter setAttribute msg", __func__);
    libusb_device* device = GetDevice(portId);
    if (device == nullptr) {
        return ERR_CODE_IOEXCEPTION;
    }
    DeviceHandleInfo deviceHandleInfo = devices_[device];
    if (!deviceHandleInfo.isOpen) {
        HDF_LOGE("%{public}s: device not open", __func__);
        return ERR_CODE_DEVICENOTOPEN;
    }
    int ret = 0;
    //init
    libusb_release_interface(deviceHandleInfo.handle, deviceHandleInfo.interface);
    libusb_attach_kernel_driver(deviceHandleInfo.handle, deviceHandleInfo.interface);
    libusb_detach_kernel_driver(deviceHandleInfo.handle, deviceHandleInfo.interface);
    ret = libusb_claim_interface(deviceHandleInfo.handle, deviceHandleInfo.interface);
    if (ret < 0) {
        HDF_LOGE("%{public}s: libusb claim failed, ret:%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    unsigned char request_type = LIBUSB_ENDPOINT_OUT | LIBUSB_REQUEST_TYPE_CLASS | LIBUSB_RECIPIENT_INTERFACE;
    uint16_t index = 0;
    uint16_t value = 0;
    int length = sizeof(struct SerialAttribute);
    ret = libusb_control_transfer(deviceHandleInfo.handle, request_type, TRANSFER_CONTROL_OUT_CODE,
        value, index, (unsigned char *)&attribute, length, TRANSFER_TIMEOUT);
    libusb_release_interface(deviceHandleInfo.handle, deviceHandleInfo.interface);
    libusb_attach_kernel_driver(deviceHandleInfo.handle, deviceHandleInfo.interface);
    if (ret < 0) {
        HDF_LOGE("%{public}s: libusb set attribute failed, ret:%{public}d", __func__, ret);
        return ret;
    }
    HDF_LOGI("%{public}s: set attribute success", __func__);
    return HDF_SUCCESS;
}


int32_t LibusbSerial::HotplugCallback(libusb_context* ctx, libusb_device* device,
    libusb_hotplug_event event, void* user_data)
{
    LibusbSerial* self = static_cast<LibusbSerial*>(user_data);

    if (event == LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED) {
        self->HandleDeviceArrival(device);
    } else if (event == LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT) {
        self->HandleDeviceRemoval(device);
    }

    return HDF_SUCCESS;
}

int32_t LibusbSerial::HandleDeviceArrival(libusb_device* device)
{
    HDF_LOGI("%{public}s: Device arrival detected.", __func__);

    int num = -1;
    int retry = 5;

    while (retry-- > 0) {
        HDF_LOGI("%{public}s: Attempting to get device number, retry count: %{public}d", __func__, (RETRY_NUM - retry));
        num = GetDeviceNum(device);
        if (num >= 0) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(RETRY_TIMEOUT));
    }

    if (num < 0) {
        HDF_LOGE("%{public}s: Failed to find matching /dev/ttyUSBN for the device after retries", __func__);
        return HDF_FAILURE;
    }

    libusb_device_handle* handle = nullptr;
    int rc = libusb_open(device, &handle);
    if (rc != LIBUSB_SUCCESS) {
        HDF_LOGE("%{public}s: Failed to open device: %{public}d", __func__, rc);
        return HDF_FAILURE;
    }

    std::lock_guard<std::mutex> lock(map_mutex_);
    DeviceHandleInfo info;
    info.num = num;
    info.handle = handle;
    info.isOpen = false;

    if (GetEndPoint(&info) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get endpoint failed", __func__);
    }

    devices_[device] = info;

    HDF_LOGI("%{public}s: Device arrived and opened: num = %{public}d", __func__, num);
    return HDF_SUCCESS;
}

void LibusbSerial::HandleDeviceRemoval(libusb_device* device)
{
    HDF_LOGI("%{public}s: Device removal detected.", __func__);
    std::lock_guard<std::mutex> lock(map_mutex_);
    auto it = devices_.find(device);
    if (it == devices_.end()) {
        HDF_LOGE("%{public}s: Device not found in map during removal.", __func__);
        return;
    }
    // Close the handle
    if (it->second.handle) {
        libusb_close(it->second.handle);
        it->second.handle = nullptr;
    }
    int num = it->second.num;
    devices_.erase(it);
    HDF_LOGI("%{public}s: Device removed: num = %{public}d", __func__, num);
}

void LibusbSerial::EventHandlingThread()
{
    HDF_LOGI("%{public}s: enter Event handling thread.", __func__);
    while (running_) {
        int rc = libusb_handle_events_completed(ctx_, nullptr);
        if (rc != LIBUSB_SUCCESS) {
            HDF_LOGE("%{public}s: libusb_handle_events_completed failed: %{public}d", __func__, rc);
        }
    }
    HDF_LOGI("%{public}s: Event handling thread end.", __func__);
}

static void HandleUdevListEntry(struct udev* udev, struct udev_list_entry* devices,
    uint8_t busNumber, uint8_t deviceAddress, int *matchedNum)
{
    struct udev_list_entry* entry = nullptr;
    HDF_LOGI("%{public}s: enter handle udevliset.", __func__);
    udev_list_entry_foreach(entry, devices) {
        const char* sysPath = udev_list_entry_get_name(entry);
        struct udev_device* ttyDevice = udev_device_new_from_syspath(udev, sysPath);
        if (!ttyDevice) {
            continue;
        }
        const char* devname = udev_device_get_devnode(ttyDevice);
        if (!devname) {
            udev_device_unref(ttyDevice);
            continue;
        }
        std::string devNameStr(devname);
        if (devNameStr.find(DEVICE_NAME_STR) != 0) {
            udev_device_unref(ttyDevice);
            continue;
        }
        struct udev_device* parent = udev_device_get_parent_with_subsystem_devtype(
            ttyDevice, UDEV_PARENT_TYPE, UDEV_PARENT_DEVICE);
        if (!parent) {
            udev_device_unref(ttyDevice);
            continue;
        }
        const char* busNumStr = udev_device_get_sysattr_value(parent, BUSNUM_STR);
        const char* devAddrStr = udev_device_get_sysattr_value(parent, DEVNUM_STR);
        if (!busNumStr || !devAddrStr) {
            udev_device_unref(ttyDevice);
            continue;
        }
        uint8_t busNum = static_cast<uint8_t>(atoi(busNumStr));
        uint8_t devAddr = static_cast<uint8_t>(atoi(devAddrStr));
        if (busNum != busNumber || devAddr != deviceAddress) {
            udev_device_unref(ttyDevice);
            continue;
        }
        size_t pos = devNameStr.find(SERIAL_TYPE_NAME);
        if (pos != std::string::npos) {
            std::string numStr = devNameStr.substr(pos + SERIAL_TYPE_NAME.length());
            int num = atoi(numStr.c_str());
            if (num >= 0) {
                *matchedNum = num;
                udev_device_unref(ttyDevice);
                break;
            }
        }
        udev_device_unref(ttyDevice);
    }
}

int32_t LibusbSerial::GetDeviceNum(libusb_device* device)
{
    uint8_t busNumber = libusb_get_bus_number(device);
    uint8_t deviceAddress = libusb_get_device_address(device);

    struct udev* udev = udev_new();
    if (!udev) {
        HDF_LOGE("%{public}s: Failed to initialize udev", __func__);
        return HDF_FAILURE;
    }

    struct udev_enumerate* enumerate = udev_enumerate_new(udev);
    if (!enumerate) {
        HDF_LOGE("%{public}s: Failed to create udev enumerate", __func__);
        udev_unref(udev);
        return HDF_FAILURE;
    }

    udev_enumerate_add_match_subsystem(enumerate, UDEV_SUB_SYSTEM);
    if (udev_enumerate_scan_devices(enumerate) != 0) {
        HDF_LOGE("%{public}s: Failed to scan udev devices", __func__);
        udev_enumerate_unref(enumerate);
        udev_unref(udev);
        return HDF_FAILURE;
    }

    struct udev_list_entry* devices = udev_enumerate_get_list_entry(enumerate);
    int matchedNum = -1;
    HandleUdevListEntry(udev, devices, busNumber, deviceAddress, &matchedNum);

    udev_enumerate_unref(enumerate);
    udev_unref(udev);

    return matchedNum;
}
} // V1_0
} // Serial
} // Usb
} // HDI
} // OHOS
