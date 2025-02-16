/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "linux_serial.h"
#include <hdf_base.h>
#include <hdf_log.h>
#include <unistd.h>
#include <cstdlib>
#include <fcntl.h>
#include <cstring>
#include <cerrno>
#include <cstdio>
#include <cctype>
#include <sys/un.h>
#include <sys/ioctl.h>
#include "usbd_wrapper.h"
#include "securec.h"

#define UEVENT_BUFFER_SIZE 2048
#define CMSPAR 010000000000
#define BUFF_SIZE 50

#define ERR_CODE_DEVICEHASOPENNED (-4)
#define ERR_CODE_IOEXCEPTION (-5)
#define ERR_CODE_DEVICENOTOPEN (-6)
#define ERR_CODE_DEVICECANTOPEN (-7)
#define ERR_CODE_DEVICENOTEXIST (-8)


namespace OHOS {
namespace HDI {
namespace Usb {
namespace Serial {
namespace V1_0 {

static const std::string SERIAL_TYPE_NAME = "ttyUSB";
static const char *DEVICE_NAME_STR = "/dev/ttyUSB";
static const char *UDEV_SUB_SYSTEM = "tty";
static const char *UDEV_PARENT_TYPE = "usb";
static const char *UDEV_PARENT_DEVICE = "usb_device";
static const char *BUSNUM_STR = "busnum";
static const char *DEVNUM_STR = "devnum";
static const char *IDVENDOR_STR = "idVendor";
static const char *IDPRODUCT_STR = "idProduct";
static const char *SERIAL_STR = "serial";
static const int32_t ERR_NO = -1;
typedef std::pair<int32_t, int32_t> BaudratePair;

BaudratePair g_baudratePairs[] = {
    {BAUDRATE_50, B50},
    {BAUDRATE_75, B75},
    {BAUDRATE_110, B110},
    {BAUDRATE_134, B134},
    {BAUDRATE_150, B150},
    {BAUDRATE_200, B200},
    {BAUDRATE_300, B300},
    {BAUDRATE_600, B600},
    {BAUDRATE_1200, B1200},
    {BAUDRATE_1800, B1800},
    {BAUDRATE_2400, B2400},
    {BAUDRATE_4800, B4800},
    {BAUDRATE_9600, B9600},
    {BAUDRATE_19200, B19200},
    {BAUDRATE_38400, B38400},
    {BAUDRATE_57600, B57600},
    {BAUDRATE_115200, B115200},
    {BAUDRATE_230400, B230400},
    {BAUDRATE_460800, B460800},
    {BAUDRATE_500000, B500000},
    {BAUDRATE_576000, B576000},
    {BAUDRATE_921600, B921600},
    {BAUDRATE_1000000, B1000000},
    {BAUDRATE_1152000, B1152000},
    {BAUDRATE_1500000, B1500000},
    {BAUDRATE_2000000, B2000000},
    {BAUDRATE_2500000, B2500000},
    {BAUDRATE_3000000, B3000000},
    {BAUDRATE_3500000, B3500000},
    {BAUDRATE_4000000, B4000000},
};

LinuxSerial::LinuxSerial()
{
}

LinuxSerial::~LinuxSerial()
{
}

LinuxSerial &LinuxSerial::GetInstance()
{
    static LinuxSerial instance;
    return instance;
}

int32_t LinuxSerial::GetBaudrate(unsigned int baudrate)
{
    for (const auto& pair : g_baudratePairs) {
        if (pair.first == baudrate) {
            return pair.second;
        }
    }
    return HDF_FAILURE;
}

tcflag_t LinuxSerial::GetDatabits(unsigned char dataBits)
{
    tcflag_t bit_temp;
    switch (dataBits) {
        case USB_ATTR_DATABIT_4:
            // Since there is no CS4 definition in termios-c_cflag.h, Linux does not support 4 data bits.
            return HDF_FAILURE;
        case USB_ATTR_DATABIT_5:
            bit_temp = CS5;
            break;
        case USB_ATTR_DATABIT_6:
            bit_temp = CS6;
            break;
        case USB_ATTR_DATABIT_7:
            bit_temp = CS7;
            break;
        case USB_ATTR_DATABIT_8:
            bit_temp = CS8;
            break;
        default:
            return HDF_FAILURE;
        }
        return bit_temp;
}

tcflag_t LinuxSerial::GetParity(tcflag_t c_cflag, unsigned char parity)
{
    c_cflag &= ~(PARENB | PARODD);
    c_cflag |= PARENB;
    if (parity == USB_ATTR_PARITY_NONE) {
        c_cflag &= ~PARENB;
    } else if (parity == USB_ATTR_PARITY_ODD) {
        c_cflag |= PARODD;
    } else if (parity == USB_ATTR_PARITY_EVEN) {
        c_cflag &= ~PARODD;
    } else if (parity == USB_ATTR_PARITY_MARK || parity == USB_ATTR_PARITY_SPACE) {
        HDF_LOGE("%{public}s: Not Supported Mark and Space.", __func__);
        return HDF_FAILURE;
    } else {
        return HDF_FAILURE;
    }
    return c_cflag;
}

tcflag_t LinuxSerial::GetStopbits(tcflag_t c_cflag, unsigned char stopBits)
{
    if (stopBits == USB_ATTR_STOPBIT_1) {
        c_cflag &= ~CSTOPB;
    } else if (stopBits == USB_ATTR_STOPBIT_1P5) {
        HDF_LOGE("%{public}s: Not Supported 1.5.", __func__);
        return HDF_FAILURE;
    } else if (stopBits == USB_ATTR_STOPBIT_2) {
        c_cflag |= CSTOPB;
    } else {
        return HDF_FAILURE;
    }
    return c_cflag;
}

int32_t LinuxSerial::SerialCheck(int32_t portId)
{
    size_t i = 0;
    bool isFind = false;
    for (i = 0; i < g_serialPortList.size(); i++) {
        if (portId == g_serialPortList[i].portId) {
            isFind = true;
            break;
        }
    }

    if (!isFind) {
        HDF_LOGE("%{public}s: not find portId.", __func__);
        return ERR_CODE_DEVICENOTEXIST;
    }

    if (ERR_NO == g_serialPortList[i].fd) {
        HDF_LOGE("%{public}s: fd not exist.", __func__);
        return ERR_CODE_DEVICENOTEXIST;
    }
    return i;
}
int32_t LinuxSerial::SerialOpen(int32_t portId)
{
    int ret = 0;
    size_t i = 0;
    bool isFind = false;
    char path[BUFF_SIZE] = {'\0'};
    for (i = 0; i < g_serialPortList.size(); i++) {
        if (portId == g_serialPortList[i].portId) {
            isFind = true;
            break;
        }
    }

    if (!isFind) {
        HDF_LOGE("%{public}s: not find portId.", __func__);
        return ERR_CODE_DEVICENOTEXIST;
    }

    if (ERR_NO != g_serialPortList[i].fd) {
        HDF_LOGE("%{public}s: device has been opened,fd=%{public}d", __func__, g_serialPortList[i].fd);
        return ERR_CODE_DEVICEHASOPENNED;
    }
    std::lock_guard<std::mutex> lock(portMutex_);

    ret = snprintf_s(path, sizeof(path), sizeof(path)-1, "/dev/ttyUSB%d", portId);
    if (ret < 0) {
        HDF_LOGE("%{public}s: sprintf_s path failed, ret:%{public}d", __func__, ret);
        return ret;
    }

    g_serialPortList[i].fd = open(path, O_RDWR | O_NOCTTY | O_NDELAY);
    if (g_serialPortList[i].fd <= 0) {
        HDF_LOGE("%{public}s: Unable to open serial port.", __func__);
        return ERR_CODE_DEVICECANTOPEN;
    }

    tcgetattr(g_serialPortList[i].fd, &options_);
    options_.c_lflag &= ~ICANON;
    options_.c_lflag &= ~ECHO;
    tcsetattr(g_serialPortList[i].fd, TCSANOW, &options_);

    return HDF_SUCCESS;
}

int32_t LinuxSerial::SerialClose(int32_t portId)
{
    size_t i = SerialCheck(portId);
    if (i < 0) {
        return i;
    }
    std::lock_guard<std::mutex> lock(portMutex_);
    close(g_serialPortList[i].fd);
    g_serialPortList[i].fd = -1;
    return HDF_SUCCESS;
}

int32_t LinuxSerial::SerialRead(int32_t portId, std::vector<uint8_t>& data, uint32_t size)
{
    size_t i = -1;
    int bytes_read = 0;
    if (size <= 0) {
        return HDF_FAILURE;
    }
    uint8_t *buffer = (uint8_t *)malloc(size);
    i = SerialCheck(portId);
    if (i < 0) {
        return HDF_FAILURE;
    }
    bytes_read = read(g_serialPortList[i].fd, buffer, size - 1);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        data.assign(buffer, buffer + 1 + bytes_read);
        size = bytes_read;
        free(buffer);
        return HDF_SUCCESS;
    }
    free(buffer);
    return ERR_CODE_IOEXCEPTION;
}

int32_t LinuxSerial::SerialWrite(int32_t portId, const std::vector<uint8_t>& data, uint32_t size)
{
    size_t i;
    ssize_t bytesWritten;
    i = SerialCheck(portId);
    if (i < 0) {
        return HDF_FAILURE;
    }
    std::lock_guard<std::mutex> lock(writeMutex_);
    if (data.empty())
    return HDF_FAILURE;

    uint8_t *buffer = (uint8_t *)malloc(data.size());
    std::copy(data.begin(), data.end(), buffer);

    tcflush(g_serialPortList[i].fd, TCIFLUSH);
    bytesWritten = write(g_serialPortList[i].fd, buffer, data.size());
    if (bytesWritten == ERR_NO) {
        HDF_LOGE("%{public}s: write fail.", __func__);
        return ERR_CODE_IOEXCEPTION;
    }
    tcflush(g_serialPortList[i].fd, TCIFLUSH);
    free(buffer);
    return HDF_SUCCESS;
}

int32_t LinuxSerial::SerialGetAttribute(int32_t portId, SerialAttribute& attribute)
{
    HDF_LOGI("%{public}s: enter get attribute.", __func__);
    size_t i = SerialCheck(portId);
    if (i < 0) {
        return HDF_FAILURE;
    }
    tcgetattr(g_serialPortList[i].fd, &options_);

    for (const auto& pair : g_baudratePairs) {
        if (pair.second == cfgetispeed(&options_)) {
            attribute.baudrate = pair.first;
        }
    }

    int databits = options_.c_cflag & CSIZE;
    switch (databits) {
        case CS5:
            attribute.dataBits = USB_ATTR_DATABIT_5;
            break;
        case CS6:
            attribute.dataBits = USB_ATTR_DATABIT_6;
            break;
        case CS7:
            attribute.dataBits = USB_ATTR_DATABIT_7;
            break;
        case CS8:
            attribute.dataBits = USB_ATTR_DATABIT_8;
            break;
        default:
            HDF_LOGE("%{public}s: Unknown data bits setting", __func__);
            return HDF_FAILURE;
    }

    if (options_.c_cflag & PARENB) {
        attribute.parity = (options_.c_cflag & PARODD) ? USB_ATTR_PARITY_ODD : USB_ATTR_PARITY_EVEN;
    } else {
        attribute.parity = USB_ATTR_PARITY_NONE;
    }
    
    attribute.stopBits = (options_.c_cflag & CSTOPB) ? USB_ATTR_STOPBIT_2 : USB_ATTR_STOPBIT_1;
    return HDF_SUCCESS;
}

int32_t LinuxSerial::SerialSetAttribute(int32_t portId, const SerialAttribute& attribute)
{
    HDF_LOGI("%{public}s: enter set attribute.", __func__);
    size_t i;
    int retry = 3;
    i = SerialCheck(portId);
    if (i < 0) {
        return i;
    }
    tcgetattr(g_serialPortList[i].fd, &options_);
    if (GetStopbits(options_.c_cflag, attribute.stopBits) < 0) {
        HDF_LOGE("%{public}s: stopBits set fail.", __func__);
        return GetStopbits(options_.c_cflag, attribute.stopBits);
    }
    options_.c_cflag |= (CLOCAL | CREAD);
    if (GetBaudrate(attribute.baudrate) < 0) {
        HDF_LOGE("%{public}s: baudrate set fail.", __func__);
        return HDF_FAILURE;
    }
    cfsetispeed(&options_, GetBaudrate(attribute.baudrate));
    cfsetospeed(&options_, GetBaudrate(attribute.baudrate));
    options_.c_cflag &= ~CSIZE;
    if (GetDatabits(attribute.dataBits) < 0) {
        HDF_LOGE("%{public}s: dataBits set fail.", __func__);
        return GetDatabits(attribute.dataBits);
    }
    options_.c_cflag |= GetDatabits(attribute.dataBits);
    if (GetParity(options_.c_cflag, attribute.parity)< 0) {
        HDF_LOGE("%{public}s:parity set fail.", __func__);
        return GetParity(options_.c_cflag, attribute.parity);
    }
    options_.c_cflag = GetParity(options_.c_cflag, attribute.parity);
    options_.c_cflag = GetStopbits(options_.c_cflag, attribute.stopBits);
    options_.c_cc[VMIN] = 1;
    options_.c_cc[VTIME] = 0;
    while (retry-- > 0) {
        if (tcsetattr(g_serialPortList[i].fd, TCSANOW, &options_) == 0) {
            break;
        } else if (errno != EINTR) {
            HDF_LOGE("%{public}s: tcsetattr failed.", __func__);
            return ERR_CODE_IOEXCEPTION;
        }
    }
    if (retry <= 0) {
        HDF_LOGE("%{public}s: Failed to set attributes after multiple attempts.", __func__);
        return ERR_CODE_IOEXCEPTION;
    }
    return HDF_SUCCESS;
}

void LinuxSerial::HandleUdevListEntry(struct udev_device *dev,
    struct udev_device* parent, std::vector<SerialPort>& portIds)
{
    SerialPort serialPort;
    Serialfd serialPortId;

    if (strncmp(udev_device_get_devnode(dev), DEVICE_NAME_STR, strlen(DEVICE_NAME_STR)) == 0) {
        std::lock_guard<std::mutex> lock(portMutex_);
        const char* devname = udev_device_get_devnode(dev);
        std::string devname_str(devname);
        size_t pos = devname_str.find(SERIAL_TYPE_NAME);
        if (pos != std::string::npos) {
            std::string num_str = devname_str.substr(pos + SERIAL_TYPE_NAME.length());
            int num = atoi(num_str.c_str());
            serialPort.portId = num;
            serialPortId.portId = num;
            serialPortId.fd = -1;
        }
        const char* busNumStr = udev_device_get_sysattr_value(parent, BUSNUM_STR);
        const char* devNumStr = udev_device_get_sysattr_value(parent, DEVNUM_STR);
        const char* idVendorStr = udev_device_get_sysattr_value(parent, IDVENDOR_STR);
        const char* idProductStr = udev_device_get_sysattr_value(parent, IDPRODUCT_STR);
        const char* serialStr = udev_device_get_sysattr_value(parent, SERIAL_STR);
        if (busNumStr == nullptr || devNumStr == nullptr ||
            idVendorStr == nullptr || idProductStr == nullptr) {
            HDF_LOGE("%{public}s: Attribute parameter missing.", __func__);
            return;
        }
        serialPort.deviceInfo.busNum = static_cast<uint8_t>(atoi(busNumStr));
        serialPort.deviceInfo.devAddr = static_cast<uint8_t>(atoi(devNumStr));
        serialPort.deviceInfo.vid = static_cast<int32_t>(atoi(idVendorStr));
        serialPort.deviceInfo.pid = static_cast<int32_t>(atoi(idProductStr));
        if (serialStr == nullptr) {
            serialPort.deviceInfo.serialNum = "";
        } else {
            serialPort.deviceInfo.serialNum = serialStr;
        }
        g_serialPortList.push_back(serialPortId);
        portIds.push_back(serialPort);
    }
}

int32_t LinuxSerial::SerialGetPortList(std::vector<SerialPort>& portIds)
{
    struct udev *udev;
    struct udev_enumerate *enumerate;
    struct udev_list_entry *devices;
    struct udev_list_entry *dev_list_entry;
    struct udev_device *dev;
    if (portIds.size()) {
        HDF_LOGE("%{public}s: portIds not empty!", __func__);
    }
    portIds.clear();

    udev = udev_new();
    if (!udev) {
        HDF_LOGE("%{public}s: Failed to create udev.", __func__);
        return HDF_FAILURE;
    }
    enumerate = udev_enumerate_new(udev);
    udev_enumerate_add_match_subsystem(enumerate, UDEV_SUB_SYSTEM);
    udev_enumerate_scan_devices(enumerate);
    devices = udev_enumerate_get_list_entry(enumerate);
    udev_list_entry_foreach(dev_list_entry, devices) {
        const char *path = udev_list_entry_get_name(dev_list_entry);
        dev = udev_device_new_from_syspath(udev, path);
        struct udev_device* parent = udev_device_get_parent_with_subsystem_devtype(
            dev, UDEV_PARENT_TYPE, UDEV_PARENT_DEVICE);
        HandleUdevListEntry(dev, parent, portIds);
        udev_device_unref(dev);
    }
    udev_enumerate_unref(enumerate);
    udev_unref(udev);
    return HDF_SUCCESS;
}
} // V1_0
} // Serial
} // Usb
} // HDI
} // OHOS
