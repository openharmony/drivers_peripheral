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
#include <dirent.h>
#include <hdf_log.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <sstream>
#include <climits>
#include <iostream>
#include <filesystem>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstring>
#include <string>
#include <chrono>
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
#define SERIAL_NUM 256
#define ERR_CODE_IOEXCEPTION (-5)
#define ERR_CODE_DEVICENOTOPEN (-6)
#define OUTPUT_WIDTH 2

static const std::string BUS_NUM_STR = "/busnum";
static const std::string DEV_NUM_STR = "/devnum";
static const std::string DEV_FILENAME_PREFIX = "ttyUSB";
static const std::string DEV_PATH_PREFIX = "/sys/bus/usb-serial/devices";
static const std::string TTYUSB_PATH = "/sys/class/tty";

namespace fs = std::filesystem;

LibusbSerial &LibusbSerial::GetInstance()
{
    static LibusbSerial instance;
    return instance;
}

LibusbSerial::LibusbSerial(): ctx_(nullptr), running_(true)
{
    HDF_LOGI("%{public}s: enter SerialUSBWrapper initialization.", __func__);

    int ret = libusb_init(&ctx_);
    if (ret != LIBUSB_SUCCESS) {
        HDF_LOGE("%{public}s: Failed to initialize libusb: %{public}d", __func__, ret);
        ctx_ = nullptr;

        return;
    }

    if (!libusb_has_capability(LIBUSB_CAP_HAS_HOTPLUG)) {
        HDF_LOGE("%{public}s: Hotplug capability is not supported on this platform", __func__);
        libusb_exit(ctx_);
        ctx_ = nullptr;

        return;
    }

    ret = libusb_hotplug_register_callback(ctx_,
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
    if (ret != LIBUSB_SUCCESS) {
        HDF_LOGE("%{public}s: Failed to register hotplug callback: %{public}d", __func__, ret);
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

bool IsSerialDevice(libusb_device * device)
{
    struct libusb_device_descriptor desc;
    int ret = 0;
    ret = libusb_get_device_descriptor(device, &desc);
    if (ret < 0) {
        HDF_LOGE("%{public}s: libusb_get_device_descriptor failed: %{public}s", __func__, libusb_error_name(ret));
        return false;
    }
    if (desc.bDeviceClass == LIBUSB_CLASS_COMM) {
        return true;
    } else {
        HDF_LOGE("%{public}s : This is not a USB to serial device.", __func__);
        return false;
    }
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
        struct libusb_device_descriptor desc;
        int ret = libusb_get_device_descriptor(device, &desc);
        if (ret < 0) {
            continue;
        }
        if (desc.bDeviceClass == LIBUSB_CLASS_HUB) {
            continue;
        }
        int num = GetPortIdByDevice(device);
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
        HDF_LOGI("%{public}s: desc  serialNum: %{public}hhu", __func__, desc.iSerialNumber);
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

std::string VectorToHex(const std::vector<uint8_t>& data)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t byte : data) {
        oss << std::setw(OUTPUT_WIDTH) << static_cast<int>(byte);
    }
    return oss.str();
}

int32_t LibusbSerial::SerialRead(int32_t portId, std::vector<uint8_t>& data, uint32_t size, uint32_t timeout)
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
    int actualLength = 0;
    uint8_t data_in[MAX_TRANS_DATA_SIZE] = {0};
    
    std::lock_guard<std::mutex> lock(writeMutex_);
    libusb_release_interface(deviceHandleInfo.handle, deviceHandleInfo.interface);
    libusb_attach_kernel_driver(deviceHandleInfo.handle, deviceHandleInfo.interface);
    libusb_detach_kernel_driver(deviceHandleInfo.handle, deviceHandleInfo.interface);
    ret = libusb_claim_interface(deviceHandleInfo.handle, deviceHandleInfo.interface);
    if (ret < 0) {
        HDF_LOGE("%{public}s: libusb claim failed, ret:%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    ret = 0;
    ret = libusb_bulk_transfer(deviceHandleInfo.handle,
        deviceHandleInfo.intputEndpointAddr, data_in, size, &actualLength, timeout);
    if (ret < 0 && actualLength == 0) {
        libusb_release_interface(deviceHandleInfo.handle, deviceHandleInfo.interface);
        libusb_attach_kernel_driver(deviceHandleInfo.handle, deviceHandleInfo.interface);
        HDF_LOGE("%{public}s: read message failed, ret:%{public}d", __func__, ret);
        return ret;
    }
    std::vector<uint8_t> vec(data_in, data_in + actualLength);
    data.insert(data.end(), vec.begin(), vec.end());
    std::string tempHexBuff = VectorToHex(vec);
    HDF_LOGI("%{public}s: read msg : %{public}s", __func__, data.data());
    HDF_LOGI("%{public}s: read msg hex : %{public}s", __func__, tempHexBuff.c_str());
    size = actualLength;
    libusb_release_interface(deviceHandleInfo.handle, deviceHandleInfo.interface);
    libusb_attach_kernel_driver(deviceHandleInfo.handle, deviceHandleInfo.interface);
    return HDF_SUCCESS;
}

int32_t LibusbSerial::SerialWrite(int32_t portId, const std::vector<uint8_t>& data, uint32_t size, uint32_t timeout)
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
    int actualLength = 0;
    const uint8_t* dataOut = data.data();
    std::lock_guard<std::mutex> lock(writeMutex_);
    libusb_release_interface(deviceHandleInfo.handle, deviceHandleInfo.interface);
    libusb_attach_kernel_driver(deviceHandleInfo.handle, deviceHandleInfo.interface);
    libusb_detach_kernel_driver(deviceHandleInfo.handle, deviceHandleInfo.interface);
    ret = libusb_claim_interface(deviceHandleInfo.handle, deviceHandleInfo.interface);
    if (ret < 0) {
        HDF_LOGE("%{public}s: libusb claim failed, ret:%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s: read msg : %{public}s", __func__, data.data());
    ret = libusb_bulk_transfer(deviceHandleInfo.handle, deviceHandleInfo.outputEndpointAddr,
        const_cast<uint8_t*>(dataOut), data.size(), &actualLength, timeout);
    if (ret < 0) {
        HDF_LOGE("%{public}s: write message failed, ret:%{public}d", __func__, ret);
        libusb_release_interface(deviceHandleInfo.handle, deviceHandleInfo.interface);
        libusb_attach_kernel_driver(deviceHandleInfo.handle, deviceHandleInfo.interface);
        return ret;
    }
    size = actualLength;
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
    unsigned char requestType = LIBUSB_ENDPOINT_IN | LIBUSB_REQUEST_TYPE_CLASS | LIBUSB_RECIPIENT_INTERFACE;
    uint16_t index = 0;
    uint16_t value = 0;
    int length = sizeof(struct SerialAttribute);
    ret =  libusb_control_transfer(deviceHandleInfo.handle, requestType, TRANSFER_CONTROL_IN_CODE,
        value, index, (unsigned char *)&attribute, length, TRANSFER_TIMEOUT);
    libusb_release_interface(deviceHandleInfo.handle, deviceHandleInfo.interface);
    libusb_attach_kernel_driver(deviceHandleInfo.handle, deviceHandleInfo.interface);
    HDF_LOGI("%{public}s: getattribute baudrate :%{public}d"
        "databit :%{public}d stop :%{public}d parity :%{public}d", __func__, attribute.baudrate,
        attribute.dataBits, attribute.stopBits, attribute.parity);
    if (ret < 0) {
        HDF_LOGE("%{public}s: libusb get attribute failed, ret:%{public}d", __func__, ret);
        return ret;
    }
    return HDF_SUCCESS;
}

int32_t LibusbSerial::SerialSetAttribute(int32_t portId, const struct SerialAttribute& attribute)
{
    HDF_LOGI("%{public}s: setattribute baudrate :%{public}d"
        "databit :%{public}d stop :%{public}d parity :%{public}d", __func__, attribute.baudrate,
        attribute.dataBits, attribute.stopBits, attribute.parity);
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
    libusb_release_interface(deviceHandleInfo.handle, deviceHandleInfo.interface);
    libusb_attach_kernel_driver(deviceHandleInfo.handle, deviceHandleInfo.interface);
    libusb_detach_kernel_driver(deviceHandleInfo.handle, deviceHandleInfo.interface);
    ret = libusb_claim_interface(deviceHandleInfo.handle, deviceHandleInfo.interface);
    if (ret < 0) {
        HDF_LOGE("%{public}s: libusb claim failed, ret:%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    unsigned char requestType = LIBUSB_REQUEST_TYPE_CLASS | LIBUSB_RECIPIENT_INTERFACE;
    uint16_t index = 0;
    uint16_t value = 0;
    int length = sizeof(struct SerialAttribute);
    ret = libusb_control_transfer(deviceHandleInfo.handle, requestType, TRANSFER_CONTROL_OUT_CODE,
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
    int retry = RETRY_NUM;

    while (retry-- > 0) {
        HDF_LOGI("%{public}s: Attempting to get device number, retry count: %{public}d", __func__, (RETRY_NUM - retry));
        num = GetPortIdByDevice(device);
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
    int ret = libusb_open(device, &handle);
    if (ret != LIBUSB_SUCCESS) {
        HDF_LOGE("%{public}s: Failed to open device: %{public}d", __func__, ret);
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
        int ret = libusb_handle_events_completed(ctx_, nullptr);
        if (ret != LIBUSB_SUCCESS) {
            HDF_LOGE("%{public}s: libusb_handle_events_completed failed: %{public}d", __func__, ret);
        }
    }
    HDF_LOGI("%{public}s: Event handling thread end.", __func__);
}

std::string GetTtyDevicePath(const std::string& ttyDevice)
{
    fs::path ttyPath = fs::path(TTYUSB_PATH) /= ttyDevice;
    if (!fs::exists(ttyPath) || !fs::is_symlink(ttyPath)) {
        HDF_LOGE("%{public}s: path %{public}s not exist", __func__, ttyPath.string().c_str());
        return NULL;
    }
    fs::path realPath = fs::read_symlink(ttyPath);
    realPath = fs::weakly_canonical(ttyPath.parent_path() /= realPath);
    std::string targetPath = realPath.parent_path().parent_path().parent_path().parent_path().string();
    return targetPath;
}

bool CheckTtyDeviceInfo(std::string ttyUsbPath, libusb_device* device)
{
    HDF_LOGI("%{public}s : enter checkTtyDeviceInfo.", __func__);
    int busnumFd = 0;
    int devnumFd = 0;
    busnumFd = open((ttyUsbPath + BUS_NUM_STR).c_str(), O_RDONLY);
    if (busnumFd < 0) {
        HDF_LOGE("%{public}s : open file failed. ret = %{public}s", __func__, strerror(errno));
        close(busnumFd);
        return false;
    }
    char busnumBuff[BUFFER_SIZE] = {'\0'};
    ssize_t readBytes = read(busnumFd, busnumBuff, BUFFER_SIZE);
    if (readBytes < 0) {
        close(busnumFd);
        return false;
    }
    devnumFd = open((ttyUsbPath + DEV_NUM_STR).c_str(), O_RDONLY);
    if (devnumFd < 0) {
        HDF_LOGE("%{public}s : open file failed. ret = %{public}s", __func__, strerror(errno));
        close(devnumFd);
        close(busnumFd);
        return false;
    }
    char devnumBuff[BUFFER_SIZE] = {'\0'};
    readBytes = read(devnumFd, devnumBuff, BUFFER_SIZE);
    if (readBytes < 0) {
        close(busnumFd);
        close(devnumFd);
        return false;
    }
    close(devnumFd);
    close(busnumFd);
    if (atoi(devnumBuff) == libusb_get_device_address(device) && atoi(busnumBuff) == libusb_get_bus_number(device)) {
        return true;
    }
    return false;
}

int32_t LibusbSerial::GetPortIdByDevice(libusb_device* device)
{
    HDF_LOGI("%{public}s : getDeviceNum", __func__);
    DIR* dir = opendir(DEV_PATH_PREFIX.c_str());
    if (dir == nullptr) {
        HDF_LOGI("%{public}s : dir is not existed %{public}s", __func__, strerror(errno));
        return -1;
    }
    struct dirent* entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        if (strncmp(entry->d_name, DEV_FILENAME_PREFIX.c_str(), DEV_FILENAME_PREFIX.size()) == 0) {
            std::string devName = entry->d_name;
            std::string targetPath = GetTtyDevicePath(devName);
            if (targetPath.size() == 0) {
                continue;
            }
            if (CheckTtyDeviceInfo(targetPath, device)) {
                closedir(dir);
                int32_t target = atoi(devName.substr(DEV_FILENAME_PREFIX.size()).c_str());
                return target;
            }
        }
    }
    closedir(dir);
    HDF_LOGI("%{public}s : it's not a serial device", __func__);
    return -1;
}
} // V1_0
} // Serial
} // Usb
} // HDI
} // OHOS
