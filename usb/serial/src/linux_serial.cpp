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
#include <filesystem>
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

#define _BSD_SOURCE

#define UEVENT_BUFFER_SIZE 2048
#define CMSPAR 010000000000
#define BUFF_SIZE 50
#define SYSFS_PATH_LEN   128
#define RETRY_NUM 5
#define MAX_TRANS_DATA_SIZE 8192


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
static const uint8_t DATABITS_FIVE = 5;
static const uint8_t DATABITS_SIX = 6;
static const uint8_t DATABITS_SEVEN = 7;
static const uint8_t DATABITS_EIGHT = 8;
static const int32_t THOUSAND = 1000;

namespace fs = std::filesystem;

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
        if (static_cast<unsigned int>(pair.first) == baudrate) {
            return pair.second;
        }
    }
    return HDF_FAILURE;
}

int32_t LinuxSerial::GetDatabits(unsigned char dataBits, tcflag_t& cflag)
{
    switch (dataBits) {
        case DATABITS_FIVE:
            cflag |= CS5;
            break;
        case DATABITS_SIX:
            cflag |= CS6;
            break;
        case DATABITS_SEVEN:
            cflag |= CS7;
            break;
        case DATABITS_EIGHT:
            cflag |= CS8;
            break;
        default:
            return HDF_FAILURE;
        }
    return HDF_SUCCESS;
}

int32_t LinuxSerial::GetParity(tcflag_t& cflag, unsigned char parity)
{
    cflag &= ~(PARENB | PARODD | CMSPAR);
    switch (parity) {
        case USB_ATTR_PARITY_NONE:
            break;
        case USB_ATTR_PARITY_ODD:
            cflag |= PARENB | PARODD;
            break;
        case USB_ATTR_PARITY_EVEN:
            cflag |= PARENB;
            break;
        case USB_ATTR_PARITY_MARK:
            cflag |= PARENB | PARODD | CMSPAR;
            break;
        case USB_ATTR_PARITY_SPACE:
            cflag |= PARENB | CMSPAR;
            break;
        default:
            HDF_LOGE("%{public}s: Parity not exist!", __func__);
            return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t LinuxSerial::GetStopbits(tcflag_t& cflag, unsigned char stopBits)
{
    if (stopBits == USB_ATTR_STOPBIT_1) {
        cflag &= ~CSTOPB;
    } else if (stopBits == USB_ATTR_STOPBIT_2) {
        cflag |= CSTOPB;
    } else {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
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

    if (tcgetattr(serialPortList_[index].fd, &options_) == -1) {
        fdsan_close_with_tag(serialPortList_[index].fd, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
        HDF_LOGE("%{public}s: get attribute failed %{public}d.", __func__, errno);
        serialPortList_.erase(serialPortList_.begin() + index);
        return HDF_FAILURE;
    }
    options_.c_lflag &= ~ICANON;
    options_.c_lflag &= ~ECHO;
    if (tcsetattr(serialPortList_[index].fd, TCSANOW, &options_) == -1) {
        fdsan_close_with_tag(serialPortList_[index].fd, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
        HDF_LOGE("%{public}s: set attribute failed %{public}d.", __func__, errno);
        serialPortList_.erase(serialPortList_.begin() + index);
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
        return ERR_CODE_IOEXCEPTION;
    }
     
    uint8_t dataIn[MAX_TRANS_DATA_SIZE] = {0};
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);

    struct timeval readTimeout;
    readTimeout.tv_sec = 0;
    readTimeout.tv_usec = timeout * THOUSAND;
    
    int32_t bytesRead;
    int32_t status = select(fd + 1, &readfds, nullptr, nullptr, &readTimeout);
    if (status == -1) {
        return HDF_FAILURE;
    } else if (status == 0) {
        return ERR_CODE_TIMEOUT;
    } else {
        bytesRead = read(fd, dataIn, size);
        if (bytesRead < 0) {
            HDF_LOGE("%{public}s: read fail. %{public}d", __func__, errno);
            return ERR_CODE_IOEXCEPTION;
        }
    }
    std::vector<uint8_t> vec(dataIn, dataIn + bytesRead);
    data.insert(data.end(), vec.begin(), vec.end());
    HDF_LOGI("%{public}s: read success. %{public}s", __func__, data.data());
    return bytesRead;
}

int32_t LinuxSerial::SerialWrite(int32_t portId, const std::vector<uint8_t>& data, uint32_t size, uint32_t timeout)
{
    int32_t fd;
    int32_t bytesWritten;
    fd = GetFdByPortId(portId);
    if (fd < 0) {
        return ERR_CODE_IOEXCEPTION;
    }
    if (data.empty()) {
        HDF_LOGE("%{public}s: data is empty!", __func__);
        return HDF_FAILURE;
    }
    fd_set writefd;
    FD_ZERO(&writefd);
    FD_SET(fd, &writefd);

    struct timeval writeTimeout;
    writeTimeout.tv_sec = 0;
    writeTimeout.tv_usec = timeout * THOUSAND;
    
    int32_t status = select(fd + 1, nullptr, &writefd, nullptr, &writeTimeout);
    if (status == -1) {
        return HDF_FAILURE;
    } else if (status == 0) {
        HDF_LOGE("%{public}s: write timed out. %{public}d", __func__, errno);
        return ERR_CODE_TIMEOUT;
    } else {
        bytesWritten = write(fd, data.data(), data.size());
        if (bytesWritten == ERR_NO) {
            HDF_LOGE("%{public}s: write fail.", __func__);
            return ERR_CODE_IOEXCEPTION;
        }
    }
    return bytesWritten;
}

void TranslateParity(tcflag_t parity, SerialAttribute& attribute)
{
    if ((parity & PARENB) && (parity & CMSPAR)) {
        if (parity & PARODD) {
            attribute.parity = USB_ATTR_PARITY_MARK;
        } else {
            attribute.parity = USB_ATTR_PARITY_SPACE;
        }
    } else {
        if (parity & PARODD) {
            attribute.parity = USB_ATTR_PARITY_ODD;
        } else {
            attribute.parity = USB_ATTR_PARITY_EVEN;
        }
    }
}

int32_t LinuxSerial::SerialGetAttribute(int32_t portId, SerialAttribute& attribute)
{
    HDF_LOGI("%{public}s: enter get attribute.", __func__);
    int32_t fd = GetFdByPortId(portId);
    if (fd < 0) {
        return ERR_CODE_IOEXCEPTION;
    }
    if (tcgetattr(fd, &options_) == -1) {
        HDF_LOGE("%{public}s: get attribute failed %{public}d.", __func__, errno);
        return HDF_FAILURE;
    }

    for (const auto& pair : g_baudratePairs) {
        if (static_cast<unsigned int>(pair.second) == cfgetispeed(&options_)) {
            attribute.baudrate = static_cast<unsigned int>(pair.first);
        }
    }

    auto databits = options_.c_cflag & CSIZE;

    switch (databits) {
        case CS5:
            attribute.dataBits = DATABITS_FIVE;
            break;
        case CS6:
            attribute.dataBits = DATABITS_SIX;
            break;
        case CS7:
            attribute.dataBits = DATABITS_SEVEN;
            break;
        case CS8:
            attribute.dataBits = DATABITS_EIGHT;
            break;
        default:
            HDF_LOGE("%{public}s: Unknown data bits setting", __func__);
            return HDF_FAILURE;
    }

    if (options_.c_cflag & PARENB) {
        TranslateParity(options_.c_cflag, attribute);
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
        return ERR_CODE_IOEXCEPTION;
    }

    if (tcgetattr(fd, &options_) == -1) {
        HDF_LOGE("%{public}s: get attribute failed %{public}d.", __func__, errno);
        return HDF_FAILURE;
    }

    int ret = GetStopbits(options_.c_cflag, attribute.stopBits);
    if (ret < 0) {
        HDF_LOGE("%{public}s: stopBits set fail.", __func__);
        return HDF_FAILURE;
    }

    ret = GetParity(options_.c_cflag, attribute.parity);
    if (ret < 0) {
        HDF_LOGE("%{public}s:parity set fail.", __func__);
        return ret;
    }

    options_.c_cflag &= ~CSIZE;
    if (GetDatabits(attribute.dataBits, options_.c_cflag) < 0) {
        HDF_LOGE("%{public}s: dataBits set fail.", __func__);
        return HDF_FAILURE;
    }
    
    options_.c_cflag |= (CLOCAL | CREAD);
    if (GetBaudrate(attribute.baudrate) < 0) {
        HDF_LOGE("%{public}s: baudrate set fail.", __func__);
        return HDF_FAILURE;
    }

    cfsetispeed(&options_, GetBaudrate(attribute.baudrate));
    cfsetospeed(&options_, GetBaudrate(attribute.baudrate));
    while (retry-- > 0) {
        //dev/ttyUSB0
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

void LinuxSerial::HandleDevListEntry(struct UsbPnpNotifyMatchInfoTable *device, std::vector<SerialPort>& portIds,
    std::string targetPath)
{
    SerialPort serialPort;
    Serialfd serialPortId;
    struct UsbPnpNotifyDeviceInfo *devInfo = &device->deviceInfo;
    HDF_LOGI("%{public}s: device: devNum = %{public}d, busNum = %{public}d, numInfos = %{public}d",
        __func__, device->devNum, device->busNum, device->numInfos);
    HDF_LOGI("%{public}s: device info: vendorId = %{public}d, productId = %{public}d, deviceClass = %{public}d",
        __func__, devInfo->vendorId, devInfo->productId, devInfo->deviceClass);
    HDF_LOGI("%{public}s: device: serialNo: %{public}s", __func__, devInfo->serialNo.c_str());

    std::string devnameStr(targetPath);
    size_t pos = devnameStr.find(SERIAL_TYPE_NAME);
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
    serialPort.deviceInfo.serialNum = devInfo->serialNo;
    auto it = std::find_if(serialPortList_.begin(), serialPortList_.end(), [&](const Serialfd& tempSerial) {
        return tempSerial.portId == serialPortId.portId;
    });
    if (it == serialPortList_.end()) {
        serialPortList_.push_back(serialPortId);
    }
    portIds.push_back(serialPort);
}

static int32_t DevMgrInitDevice(struct UsbDdkDeviceInfo *deviceInfo)
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
        std::string ttyPathStr(devHandle->d_name);
        if (ttyPathStr == "." || ttyPathStr == "..") {
            continue;
        }
        fs::path ttyPath(SYSFS_DEVICES_DIR + ttyPathStr);
        if (!fs::exists(ttyPath) || !fs::is_symlink(ttyPath)) {
            HDF_LOGE("%{public}s: path %{public}s not exist", __func__, ttyPath.string().c_str());
            continue;
        }
        fs::path realPath = fs::read_symlink(ttyPath);
        std::string tempPath = ttyPath.parent_path().string() + "/" + realPath.string();
        realPath = fs::weakly_canonical(fs::path(tempPath));
        std::string targetPath = realPath.parent_path().parent_path().string();
        status = DevMgrInitDevice(device);
        if (status != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: init device failed:%{public}d", __func__, status);
            break;
        }
        status = SerialGetDevice(targetPath.c_str(), &device->info);
        if (status != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: sysfs get device failed:%{public}d", __func__, status);
            break;
        }
        HandleDevListEntry(&device->info, portIds, ttyPath.string());
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
