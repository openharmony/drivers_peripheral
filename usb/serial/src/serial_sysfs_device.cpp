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

#include "serial_sysfs_device.h"
#include <dirent.h>
#include <fcntl.h>
#include <cinttypes>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <regex.h>
#include <hdf_base.h>

#include "hdf_log.h"
#include "securec.h"
#include "usbd_wrapper.h"

#define SEIAL_NUMBER_NAME "serial"
#define SYSFS_PATH_LEN   128
#define PROPERTY_MAX_LEN 128
#define HDF_LOG_TAG      usb_ddk_sysfs_dev

namespace OHOS {
namespace HDI {
namespace Usb {
namespace Serial {
namespace V1_0 {

const int32_t DEC_BASE = 10;
const int32_t HEX_BASE = 16;
const uint64_t MOVE_NUM = 32;

static inline int32_t SerialGetBase(const char *propName)
{
    if (strcmp(propName, "idProduct") == 0 || strcmp(propName, "idVendor") == 0 ||
        strcmp(propName, "bInterfaceNumber") == 0 || strcmp(propName, "bInterfaceProtocol") == 0 ||
        strcmp(propName, "bInterfaceClass") == 0 || strcmp(propName, "bInterfaceSubClass") == 0) {
        return HEX_BASE;
    }
    return DEC_BASE;
}

inline uint64_t SerialMakeDevAddr(uint32_t busNum, uint32_t devNum)
{
    return ((static_cast<uint64_t>(busNum) << MOVE_NUM) | devNum);
}

static int32_t SerialReadProperty(const char *deviceDir, const char *propName, int64_t *value, uint64_t maxVal)
{
    char pathTmp[SYSFS_PATH_LEN] = {0};
    int32_t num = 0;
    num = sprintf_s(pathTmp, SYSFS_PATH_LEN, "%s/%s", deviceDir, propName);
    if (num <= 0) {
        HDF_LOGE("%{public}s: sprintf_s error deviceDir:%{public}s, propName:%{public}s",
            __func__, deviceDir, propName);
        return HDF_FAILURE;
    }
    // read string from file
    char path[PATH_MAX] = {'\0'};
    if (realpath(pathTmp, path) == nullptr) {
        HDF_LOGE("file %{public}s is invalid", pathTmp);
        return HDF_FAILURE;
    }
    int32_t fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        HDF_LOGE("%{public}s: open file failed path:%{public}s, errno:%{public}d", __func__, path, errno);
        return HDF_ERR_IO;
    }
    int32_t ret = HDF_SUCCESS;
    do {
        char buf[PROPERTY_MAX_LEN] = {0};
        ssize_t numRead = read(fd, buf, PROPERTY_MAX_LEN);
        if (numRead <= 0) {
            HDF_LOGE("%{public}s: read prop failed path:%{public}s, errno:%{public}d", __func__, path, errno);
            ret = HDF_ERR_IO;
            break;
        }
        // convert string to int64_t
        if (buf[numRead - 1] != '\n') {
            HDF_LOGE("%{public}s: prop is not end with newline path:%{public}s", __func__, path);
            ret = HDF_ERR_INVALID_PARAM;
            break;
        }
        buf[numRead - 1] = '\0';
        int64_t res = strtoll(buf, nullptr, SerialGetBase(propName));
        if (res == LLONG_MAX || res == LLONG_MIN || res > (int64_t)maxVal) {
            HDF_LOGE("%{public}s: convert failed path:%{public}s, res:%{public}" PRId64 "", __func__, path, res);
            ret = HDF_ERR_INVALID_PARAM;
            break;
        }
        *value = res;
    } while (0);

    close(fd);
    return ret;
}

static std::string SerialGetSerialNo(const char *deviceDir)
{
    std::string serialNo;
    char pathTmp[SYSFS_PATH_LEN] = {0};
    int32_t num = sprintf_s(pathTmp, SYSFS_PATH_LEN, "%s/%s", deviceDir, SEIAL_NUMBER_NAME);
    if (num <= 0) {
        HDF_LOGE("%{public}s: sprintf_s error deviceDir:%{public}s, propName:%{public}s",
            __func__, deviceDir, SEIAL_NUMBER_NAME);
        return serialNo;
    }
    char path[PATH_MAX] = {'\0'};
    if (realpath(pathTmp, path) == nullptr) {
        HDF_LOGE("file %{public}s is invalid", pathTmp);
        return serialNo;
    }
    int32_t fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        HDF_LOGE("%{public}s: open file failed path:%{public}s, errno:%{public}d", __func__, path, errno);
        return serialNo;
    }
    char buf[PROPERTY_MAX_LEN] = {0};
    do {
        ssize_t numRead = read(fd, buf, PROPERTY_MAX_LEN);
        if (numRead <= 0) {
            HDF_LOGE("%{public}s: read prop failed path:%{public}s, errno:%{public}d", __func__, path, errno);
            break;
        }
        if (buf[numRead - 1] != '\n') {
            HDF_LOGE("%{public}s: prop is not end with newline path:%{public}s", __func__, path);
            break;
        }
        buf[numRead - 1] = '\0';
        serialNo = std::string(buf);
    } while (0);

    close(fd);
    return serialNo;
}

int32_t SerialGetDevice(const char *deviceDir, struct UsbPnpNotifyMatchInfoTable *device)
{
    int64_t value = 0;
    int32_t ret = SerialReadProperty(deviceDir, "devnum", &value, INT32_MAX);
    device->devNum = static_cast<int32_t>(value);
    ret += SerialReadProperty(deviceDir, "busnum", &value, INT32_MAX);
    device->busNum = static_cast<int32_t>(value);
    ret += SerialReadProperty(deviceDir, "bNumInterfaces", &value, UINT8_MAX);
    device->numInfos = static_cast<uint8_t>(value);

    struct UsbPnpNotifyDeviceInfo *devInfo = &device->deviceInfo;
    ret += SerialReadProperty(deviceDir, "idVendor", &value, UINT16_MAX);
    devInfo->vendorId = static_cast<uint16_t>(value);
    ret += SerialReadProperty(deviceDir, "idProduct", &value, UINT16_MAX);
    devInfo->productId = static_cast<uint16_t>(value);
    ret += SerialReadProperty(deviceDir, "bcdDevice", &value, UINT16_MAX);
    devInfo->bcdDeviceLow = static_cast<uint16_t>(value);
    devInfo->bcdDeviceHigh = devInfo->bcdDeviceLow;
    ret += SerialReadProperty(deviceDir, "bDeviceClass", &value, UINT8_MAX);
    devInfo->deviceClass = static_cast<uint8_t>(value);
    ret += SerialReadProperty(deviceDir, "bDeviceSubClass", &value, UINT8_MAX);
    devInfo->deviceSubClass = static_cast<uint8_t>(value);
    ret += SerialReadProperty(deviceDir, "bDeviceProtocol", &value, UINT8_MAX);
    devInfo->deviceProtocol = static_cast<uint8_t>(value);
    devInfo->serialNo = SerialGetSerialNo(deviceDir);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get property failed:%{public}d", __func__, ret);
        return ret;
    }
    return HDF_SUCCESS;
}

} // V1_0
} // Serial
} // Usb
} // HDI
} // OHOS