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
#include <sys/types.h>
#include <dirent.h>
#include <sys/select.h>
#include "usbd_wrapper.h"
#include "securec.h"

#define UEVENT_BUFFER_SIZE 2048
#define CMSPAR 010000000000
#define BUFF_SIZE 50
#define SYSFS_PATH_LEN   128
#define RETRY_NUM 5

#define ERR_CODE_IOEXCEPTION (-5)
#define ERR_CODE_DEVICENOTOPEN (-6)
#define ERR_CODE_TIMEOUT (-7)

namespace OHOS {
namespace HDI {
namespace Usb {
namespace Serial {
namespace V1_0 {

static const std::string SERIAL_TYPE_NAME = "ttyUSB";
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
    HDF_LOGI("%{public}s: enter SerialUSBWrapper initialization.", __func__);
}

LinuxSerial::~LinuxSerial()
{
    HDF_LOGI("%{public}s: enter Destroying SerialUSBWrapper.", __func__);
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
            HDF_LOGE("%{public}s: Not Supported 4 data bits.", __func__);
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
        HDF_LOGE("%{public}s: Parity not exist!", __func__);
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

int32_t LinuxSerial::GetFdByPortId(int32_t portId)
{
    size_t index = 0;
    bool isFound = false;
    std::lock_guard<std::mutex> lock(portMutex_);
    for (index = 0; index < serialPortList_.size(); index++) {
        if (portId == serialPortList_[index].portId) {
            isFound = true;
            break;
        }
    }
    if (!isFound) {
        HDF_LOGE("%{public}s: not find portId.", __func__);
        return HDF_FAILURE;
    }
    if (ERR_NO == serialPortList_[index].fd) {
        HDF_LOGE("%{public}s: fd not exist.", __func__);
        return HDF_FAILURE;
    }
    return serialPortList_[index].fd;
}

int32_t LinuxSerial::SerialOpen(int32_t portId)
{
    std::lock_guard<std::mutex> lock(portMutex_);
    size_t index = 0;
    bool isFound = false;
    char path[BUFF_SIZE] = {'\0'};
    for (index = 0; index < serialPortList_.size(); index++) {
        if (portId == serialPortList_[index].portId) {
            isFound = true;
            break;
        }
    }
    if (!isFound) {
        HDF_LOGE("%{public}s: not find portId.", __func__);
        return HDF_FAILURE;
    }
    if (ERR_NO != serialPortList_[index].fd) {
        HDF_LOGE("%{public}s: device has been opened,fd=%{public}d", __func__, serialPortList_[index].fd);
        return HDF_FAILURE;
    }
    int32_t ret = 0;
    ret = snprintf_s(path, sizeof(path), sizeof(path)-1, "/dev/ttyUSB%d", portId);
    if (ret < 0) {
        HDF_LOGE("%{public}s: sprintf_s path failed, ret:%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    serialPortList_[index].fd = open(path, O_RDWR | O_NOCTTY | O_NDELAY);
    if (serialPortList_[index].fd <= 0) {
        HDF_LOGE("%{public}s: Unable to open serial port.", __func__);
        return HDF_FAILURE;
    }
    fdsan_exchange_owner_tag(serialPortList_[index].fd, 0, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));

    if (tcgetattr(serialPortList_[index].fd, &options_) = -1) {
        fdsan_close_with_tag(serialPortList_[index].fd, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
        HDF_LOGE("%{public}s: get attribute failed %{public}d.", __func__, errno);
        serialPortList_.erase(index);
        return HDF_FAILURE;
    }
    options_.c_lflag &= ~ICANON;
    options_.c_lflag &= ~ECHO;
    if (tcsetattr(serialPortList_[index].fd, TCSANOW, &options_) = -1) {
        fdsan_close_with_tag(serialPortList_[index].fd, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
        HDF_LOGE("%{public}s: set attribute failed %{public}d.", __func__, errno);
        serialPortList_.erase(index);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t LinuxSerial::SerialClose(int32_t portId)
{
    std::lock_guard<std::mutex> lock(portMutex_);
    size_t index = 0;
    bool isFound = false;
    for (index = 0; index < serialPortList_.size(); index++) {
        if (portId == serialPortList_[index].portId) {
            isFound = true;
            break;
        }
    }
    if (!isFound) {
        HDF_LOGE("%{public}s: not find portId.", __func__);
        return HDF_FAILURE;
    }
    if (ERR_NO == serialPortList_[index].fd) {
        HDF_LOGE("%{public}s: fd not exist.", __func__);
        return HDF_FAILURE;
    }
    fdsan_close_with_tag(serialPortList_[index].fd, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
    serialPortList_[index].fd = -1;
    return HDF_SUCCESS;
}

int32_t LinuxSerial::SerialRead(int32_t portId, std::vector<uint8_t>& data, uint32_t size, uint32_t timeout)
{
    int32_t fd = -1;
    if (size <= 0) {
        return HDF_FAILURE;
    }
    fd = GetFdByPortId(portId);
    if (fd < 0) {
        return ERR_CODE_DEVICENOTOPEN;
    }
    
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);

    struct timeval readTimeout;
    readTimeout.tv_sec = 0;
    readTimeout.tv_usec = timeout;

    int32_t status = select(fd + 1, &readfds, nullptr, nullptr, &readTimeout);
    if (status == -1) {
        return HDF_FAILURE;
    } else if (status == 0) {
        return ERR_CODE_TIMEOUT;
    } else {
        int32_t bytesRead = read(fd, data.data(), size);
        if (bytesRead < 0) {
            HDF_LOGE("%{public}s: read fail.", __func__);
            return ERR_CODE_IOEXCEPTION;
        }
    }
    return HDF_SUCCESS;
}

int32_t LinuxSerial::SerialWrite(int32_t portId, const std::vector<uint8_t>& data, uint32_t size, uint32_t timeout)
{
    int32_t fd;
    int32_t bytesWritten;
    fd = GetFdByPortId(portId);
    if (fd < 0) {
        return ERR_CODE_DEVICENOTOPEN;
    }
    if (data.empty()) {
        HDF_LOGE("%{public}s: data is empty!", __func__);
        return HDF_FAILURE;
    }

    bytesWritten = write(fd, data.data(), data.size());
    if (bytesWritten == ERR_NO) {
        HDF_LOGE("%{public}s: write fail.", __func__);
        return ERR_CODE_IOEXCEPTION;
    }
    return HDF_SUCCESS;
}

int32_t LinuxSerial::SerialGetAttribute(int32_t portId, SerialAttribute& attribute)
{
    HDF_LOGI("%{public}s: enter get attribute.", __func__);
    int32_t fd = GetFdByPortId(portId);
    if (fd < 0) {
        return ERR_CODE_DEVICENOTOPEN;
    }
    if (tcgetattr(fd, &options_) = -1) {
        HDF_LOGE("%{public}s: get attribute failed %{public}d.", __func__, errno);
        return HDF_FAILURE;
    }

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
    int32_t fd;
    int retry = RETRY_NUM;
    fd = GetFdByPortId(portId);
    if (fd < 0) {
        return ERR_CODE_DEVICENOTOPEN;
    }
    if (tcgetattr(fd, &options_) = -1) {
        HDF_LOGE("%{public}s: get attribute failed %{public}d.", __func__, errno);
        return HDF_FAILURE;
    }
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
        if (tcsetattr(fd, TCSANOW, &options_) == 0) {
            break;
        } else {
            HDF_LOGE("%{public}s: tcsetattr failed.", __func__);
        }
    }
    if (retry <= 0) {
        HDF_LOGE("%{public}s: Failed to set attributes after multiple attempts.", __func__);
        return ERR_CODE_IOEXCEPTION;
    }
    return HDF_SUCCESS;
}

void LinuxSerial::HandleDevListEntry(struct UsbPnpNotifyMatchInfoTable *device, std::vector<SerialPort>& portIds)
{
    SerialPort serialPort;
    Serialfd serialPortId;
    struct UsbPnpNotifyDeviceInfo *devInfo = &device->deviceInfo;
    HDF_LOGI("%{public}s: device: devNum = %{public}d, busNum = %{public}d, numInfos = %{public}d",
        __func__, device->devNum, device->busNum, device->numInfos);
    HDF_LOGI("%{public}s: device info: vendorId = %{public}d, productId = %{public}d, deviceClass = %{public}d",
        __func__, devInfo->vendorId, devInfo->productId, devInfo->deviceClass);

    char nodePath[SYSFS_PATH_LEN] = { 0x00 };
    DevInterfaceInfo interfaceInfo;
    interfaceInfo.busNum = device->busNum;
    interfaceInfo.devNum = device->devNum;
    interfaceInfo.intfNum = 0;
    int32_t ret = DdkSysfsGetDevNodePath(&interfaceInfo, SERIAL_TYPE_NAME.c_str(), nodePath, sizeof(nodePath));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Get device node path failed.", __func__);
        return;
    }
    HDF_LOGI("%{public}s: Device node path: %{public}s", __func__, nodePath);
    std::string devnameStr(nodePath);
    int32_t pos = devnameStr.find(SERIAL_TYPE_NAME);
    if (pos != std::string::npos) {
        std::string numStr = devnameStr.substr(pos + SERIAL_TYPE_NAME.length());
        int num = atoi(numStr.c_str());
        serialPort.portId = num;
        serialPortId.portId = num;
        serialPortId.fd = -1;
    }
    serialPort.deviceInfo.busNum = static_cast<uint8_t>(device->busNum);
    serialPort.deviceInfo.devAddr = static_cast<uint8_t>(device->devNum);
    serialPort.deviceInfo.vid = static_cast<int32_t>(devInfo->vendorId);
    serialPort.deviceInfo.pid = static_cast<int32_t>(devInfo->productId);
    auto it = std::find_if(serialPortList_.begin(), serialPortList_.end(), [&](const Serialfd& tempSerial) {
        return tempSerial.portId == serialPortId.portId;
    });
    if (it == serialPortList_.end()) {
        serialPortList_.push_back(serialPortId);
    }
    portIds.push_back(serialPort);
}

static int32_t DdkDevMgrInitDevice(struct UsbDdkDeviceInfo *deviceInfo)
{
    (void)memset_s(deviceInfo, sizeof(struct UsbDdkDeviceInfo), 0, sizeof(struct UsbDdkDeviceInfo));
    int32_t ret = OsalMutexInit(&deviceInfo->deviceMutex);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: init mutex failed", __func__);
        return HDF_FAILURE;
    }
    DListHeadInit(&deviceInfo->list);

    return HDF_SUCCESS;
}

int32_t LinuxSerial::SerialGetPortList(std::vector<SerialPort>& portIds)
{
    DIR *dir = opendir(SYSFS_DEVICES_DIR);
    if (dir == NULL) {
        HDF_LOGE("%{public}s: opendir failed sysfsDevDir:%{public}s", __func__, SYSFS_DEVICES_DIR);
        return HDF_FAILURE;
    }

    struct UsbDdkDeviceInfo *device = (struct UsbDdkDeviceInfo *)OsalMemCalloc(sizeof(struct UsbDdkDeviceInfo));
    if (device == NULL) {
        HDF_LOGE("%{public}s: init device failed", __func__);
        closedir(dir);
        return HDF_FAILURE;
    }
    int32_t status = HDF_SUCCESS;
    struct dirent *devHandle;
    while ((devHandle = readdir(dir))) {
        if (devHandle->d_name[0] > '9' || devHandle->d_name[0] < '0' || strchr(devHandle->d_name, ':')) {
            continue;
        }
        status = DdkDevMgrInitDevice(device);
        if (status != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: init device failed:%{public}d", __func__, status);
            break;
        }
        status = DdkSysfsGetDevice(devHandle->d_name, &device->info);
        if (status != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: sysfs get device failed:%{public}d", __func__, status);
            break;
        }
        HandleDevListEntry(&device->info, portIds);
    }

    OsalMemFree(device);
    closedir(dir);
    return HDF_SUCCESS;
}
} // V1_0
} // Serial
} // Usb
} // HDI
} // OHOS
