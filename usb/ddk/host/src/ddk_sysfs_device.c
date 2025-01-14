/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "ddk_sysfs_device.h"
#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <regex.h>

#include "hdf_log.h"
#include "securec.h"
#include "usbd_wrapper.h"

#define SYSFS_PATH_LEN   128
#define PROPERTY_MAX_LEN 128
#define HDF_LOG_TAG      usb_ddk_sysfs_dev

const int DEC_BASE = 10;
const int HEX_BASE = 16;

static inline int32_t DdkSysfsGetBase(const char *propName)
{
    if (strcmp(propName, "idProduct") == 0 || strcmp(propName, "idVendor") == 0 ||
        strcmp(propName, "bInterfaceNumber") == 0 || strcmp(propName, "bInterfaceProtocol") == 0 ||
        strcmp(propName, "bInterfaceClass") == 0 || strcmp(propName, "bInterfaceSubClass") == 0) {
        return HEX_BASE;
    }
    return DEC_BASE;
}

inline uint64_t DdkSysfsMakeDevAddr(uint32_t busNum, uint32_t devNum)
{
    return (((uint64_t)busNum << 32) | devNum); // 32 means left shift 32 bit
}

static int32_t DdkSysfsReadProperty(const char *deviceDir, const char *propName, int64_t *value, uint64_t maxVal)
{
    char pathTmp[SYSFS_PATH_LEN] = {0};
    int32_t num = sprintf_s(pathTmp, SYSFS_PATH_LEN, "%s%s/%s", SYSFS_DEVICES_DIR, deviceDir, propName);
    if (num <= 0) {
        HDF_LOGE(
            "%{public}s: sprintf_s error deviceDir:%{public}s, propName:%{public}s", __func__, deviceDir, propName);
        return HDF_FAILURE;
    }

    // read string  from file
    char path[PATH_MAX] = {'\0'};
    if (realpath(pathTmp, path) == NULL) {
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
        int64_t res = strtoll(buf, NULL, DdkSysfsGetBase(propName));
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

static int32_t DdkSysfsGetInterface(
    const char *deviceDir, const char *intfDir, struct UsbPnpNotifyInterfaceInfo * const intf)
{
    char intfPath[SYSFS_PATH_LEN] = {0};
    int32_t num = sprintf_s(intfPath, SYSFS_PATH_LEN, "%s/%s", deviceDir, intfDir);
    if (num <= 0) {
        HDF_LOGE("%{public}s: sprintf_s error intfDir:%{public}s", __func__, intfDir);
        return HDF_FAILURE;
    }

    int64_t value = 0;
    int32_t ret = DdkSysfsReadProperty(intfPath, "bInterfaceClass", &value, UINT8_MAX);
    intf->interfaceClass = (uint8_t)value;
    ret += DdkSysfsReadProperty(intfPath, "bInterfaceSubClass", &value, UINT8_MAX);
    intf->interfaceSubClass = (uint8_t)value;
    ret += DdkSysfsReadProperty(intfPath, "bInterfaceProtocol", &value, UINT8_MAX);
    intf->interfaceProtocol = (uint8_t)value;
    ret += DdkSysfsReadProperty(intfPath, "bInterfaceNumber", &value, UINT8_MAX);
    intf->interfaceNumber = (uint8_t)value;
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get intterface property failed", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t DdkSysfsGetActiveInterfaces(
    const char *deviceDir, uint8_t intfNum, struct UsbPnpNotifyInterfaceInfo intfs[])
{
    if (intfNum == 0) {
        HDF_LOGW("%{public}s: infNum is zero", __func__);
        return HDF_SUCCESS;
    }

    int64_t configValue = 0;
    int32_t ret = DdkSysfsReadProperty(deviceDir, "bConfigurationValue", &configValue, INT8_MAX);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get bConfigurationValue failed:%{public}d", __func__, ret);
        return ret;
    }

    if (configValue == -1) { // unconfigure the device
        HDF_LOGE("%{public}s: unconfigure the device", __func__);
        return HDF_FAILURE;
    }

    char devPath[SYSFS_PATH_LEN] = {0};
    int32_t num = sprintf_s(devPath, SYSFS_PATH_LEN, "%s%s/", SYSFS_DEVICES_DIR, deviceDir);
    if (num <= 0) {
        HDF_LOGE("%{public}s: sprintf_s error deviceDir:%{public}s", __func__, deviceDir);
        return HDF_FAILURE;
    }

    DIR *dir = opendir(devPath);
    if (dir == NULL) {
        HDF_LOGE("%{public}s: opendir failed sysfsDevDir:%{public}s", __func__, devPath);
        return HDF_ERR_BAD_FD;
    }

    struct dirent *devHandle;
    uint16_t intfIndex = 0;
    while ((devHandle = readdir(dir)) && (intfIndex < intfNum)) {
        // only read dir like 3-1:1.1
        if (strncmp(devHandle->d_name, deviceDir, strlen(deviceDir)) != 0) {
            continue;
        }

        ret = DdkSysfsGetInterface(deviceDir, devHandle->d_name, &intfs[intfIndex]);
        if (ret != HDF_SUCCESS) {
            HDF_LOGW("%{public}s: create device failed d_name:%{public}s", __func__, devHandle->d_name);
            continue;
        }

        ++intfIndex;
    }
    closedir(dir);

    if (intfIndex != intfNum) {
        HDF_LOGE("%{public}s num error intfIndex:%{public}u, intfNum:%{public}u", __func__, intfIndex, intfNum);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t DdkSysfsStandardizeDevice(struct UsbPnpNotifyMatchInfoTable * const device)
{
    device->usbDevAddr = DdkSysfsMakeDevAddr(device->busNum, device->devNum);
    return HDF_SUCCESS;
}

int32_t DdkSysfsGetDevice(const char *deviceDir, struct UsbPnpNotifyMatchInfoTable *device)
{
    int64_t value = 0;
    int32_t ret = DdkSysfsReadProperty(deviceDir, "devnum", &value, INT32_MAX);
    device->devNum = (int32_t)value;
    ret += DdkSysfsReadProperty(deviceDir, "busnum", &value, INT32_MAX);
    device->busNum = (int32_t)value;
    ret += DdkSysfsReadProperty(deviceDir, "bNumInterfaces", &value, UINT8_MAX);
    device->numInfos = (uint8_t)value;

    struct UsbPnpNotifyDeviceInfo *devInfo = &device->deviceInfo;
    ret += DdkSysfsReadProperty(deviceDir, "idVendor", &value, UINT16_MAX);
    devInfo->vendorId = (uint16_t)value;
    ret += DdkSysfsReadProperty(deviceDir, "idProduct", &value, UINT16_MAX);
    devInfo->productId = (uint16_t)value;
    ret += DdkSysfsReadProperty(deviceDir, "bcdDevice", &value, UINT16_MAX);
    devInfo->bcdDeviceLow = (uint16_t)value;
    devInfo->bcdDeviceHigh = devInfo->bcdDeviceLow;
    ret += DdkSysfsReadProperty(deviceDir, "bDeviceClass", &value, UINT8_MAX);
    devInfo->deviceClass = (uint8_t)value;
    ret += DdkSysfsReadProperty(deviceDir, "bDeviceSubClass", &value, UINT8_MAX);
    devInfo->deviceSubClass = (uint8_t)value;
    ret += DdkSysfsReadProperty(deviceDir, "bDeviceProtocol", &value, UINT8_MAX);
    devInfo->deviceProtocol = (uint8_t)value;
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get property failed:%{public}d", __func__, ret);
        return ret;
    }

    ret = DdkSysfsGetActiveInterfaces(deviceDir, device->numInfos, device->interfaceInfo);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get active interfaces failed:%{public}d", __func__, ret);
        return ret;
    }

    ret = DdkSysfsStandardizeDevice(device);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: standardize failed:%{public}d", __func__, ret);
        return ret;
    }

    return HDF_SUCCESS;
}

static int32_t DdkSysfsFindDevPath(uint32_t busNum, uint32_t devNum, char *buff, uint32_t buffSize)
{
    if (buff == NULL || buffSize == 0) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t ret = HDF_ERR_OUT_OF_RANGE;
    DIR *dir = opendir(SYSFS_DEVICES_DIR);
    if (dir == NULL) {
        HDF_LOGE("%{public}s: opendir failed sysfsDevDir:%{public}s", __func__, SYSFS_DEVICES_DIR);
        return HDF_ERR_BAD_FD;
    }

    struct dirent *devHandle;
    while ((devHandle = readdir(dir)) != NULL) {
        if ((uint32_t)strtol(devHandle->d_name, NULL, DEC_BASE) != busNum || strchr(devHandle->d_name, ':')) {
            continue;
        }
        int64_t value = 0;
        ret = DdkSysfsReadProperty(devHandle->d_name, "devnum", &value, INT32_MAX);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: retrieve devnum failed:%{public}d", __func__, ret);
            break;
        }
        if ((uint32_t)value != devNum) {
            continue;
        }

        errno_t err = strncpy_s(buff, buffSize, devHandle->d_name, buffSize - 1);
        if (err != 0) {
            HDF_LOGE("%{public}s: strncpy_s error for devHandle->d_name:%{public}s", __func__, devHandle->d_name);
            break;
        }

        break;
    }

    closedir(dir);
    return ret;
}

static int32_t DdkSysfsFindIntfPath(char *deviceDir, uint8_t intfNum, char *buff, uint32_t buffSize)
{
    if (deviceDir == NULL || buff == NULL || buffSize == 0) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t ret = HDF_ERR_OUT_OF_RANGE;
    int32_t num = sprintf_s(buff, buffSize, "%s%s/", SYSFS_DEVICES_DIR, deviceDir);
    if (num <= 0) {
        HDF_LOGE("%{public}s: sprintf_s error deviceDir:%{public}s", __func__, deviceDir);
        return HDF_FAILURE;
    }

    DIR *dir = opendir(buff);
    if (dir == NULL) {
        HDF_LOGE("%{public}s: opendir failed buff:%{public}s", __func__, buff);
        return HDF_ERR_BAD_FD;
    }

    struct dirent *devHandle;
    while ((devHandle = readdir(dir)) != NULL) {
        if (strncmp(devHandle->d_name, deviceDir, strlen(deviceDir)) != 0) {
            continue;
        }

        struct UsbPnpNotifyInterfaceInfo intf;
        ret = DdkSysfsGetInterface(deviceDir, devHandle->d_name, &intf);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: DdkSysfsGetInterface failed:%{public}d", __func__, ret);
            break;
        }

        if (intf.interfaceNumber != intfNum) {
            continue;
        }

        errno_t err = strncat_s(buff, buffSize, devHandle->d_name, buffSize - strlen(buff) - 1);
        if (err == 0) {
            ret = HDF_SUCCESS;
            break;
        }
    }

    closedir(dir);
    return ret;
}

static bool DdkCheckProductDir(char *inputString)
{
    if (inputString == NULL) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return false;
    }

    regex_t regex;
    const char *pattern = "^[0-9A-F]{4}:[0-9A-F]{4}:[0-9A-F]{4}\\.[0-9A-F]{4}$";
    int32_t ret = regcomp(&regex, pattern, REG_EXTENDED);
    if (ret != 0) {
        HDF_LOGE("%{public}s: Could not compile regex", __func__);
        return false;
    }

    ret = regexec(&regex, inputString, 0, NULL, 0);
    regfree(&regex);
    return ret == 0;
}

static int32_t DdkSysfsFindDevNodeName(char *path, const char *prefix, char *buff, uint32_t buffSize)
{
    if (path == NULL || prefix == NULL || buff == NULL || buffSize == 0) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t ret = HDF_ERR_OUT_OF_RANGE;
    DIR *dir = opendir(path);
    if (dir == NULL) {
        HDF_LOGE("%{public}s: opendir failed path:%{public}s", __func__, path);
        return HDF_ERR_BAD_FD;
    }

    struct dirent *devHandle;
    while ((devHandle = readdir(dir)) != NULL) {
        char *pSubStrOffset = strstr(devHandle->d_name, prefix);
        if (pSubStrOffset != NULL && strlen(devHandle->d_name) > strlen(prefix)) {
            errno_t err = strncpy_s(buff, buffSize, devHandle->d_name, buffSize - 1);
            if (err != 0) {
                HDF_LOGE("%{public}s: strncpy_s error for devHandle->d_name:%{public}s", __func__, devHandle->d_name);
                ret = HDF_FAILURE;
                break;
            }
            ret = HDF_SUCCESS;
            break;
        }

        if (!DdkCheckProductDir(devHandle->d_name) && strcmp(devHandle->d_name, prefix) != 0) {
            continue;
        }

        char subPath[SYSFS_PATH_LEN] = { 0x00 };
        int32_t num = sprintf_s(subPath, sizeof(subPath), "%s/%s", path, devHandle->d_name);
        if (num <= 0) {
            HDF_LOGE("%{public}s: sprintf_s error devHandle->d_name:%{public}s", __func__, devHandle->d_name);
            ret = HDF_FAILURE;
            break;
        }

        ret = DdkSysfsFindDevNodeName(subPath, prefix, buff, buffSize);
        if (ret != HDF_ERR_OUT_OF_RANGE) {
            HDF_LOGI("%{public}s: subPath:%{public}s", __func__, subPath);
            break;
        }
    }

    closedir(dir);
    return ret;
}

int32_t DdkSysfsGetDevNodePath(DevInterfaceInfo *devInfo, const char *prefix, char *buff, uint32_t buffSize)
{
    if (devInfo == NULL || buff == NULL || buffSize == 0) {
        HDF_LOGE("%{public}s: invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    char devicePath[SYSFS_PATH_LEN] = { 0x00 };
    int32_t ret = DdkSysfsFindDevPath(devInfo->busNum, devInfo->devNum, devicePath, sizeof(devicePath));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: retrieve device path failed, ret:%{public}d", __func__, ret);
        return ret;
    }
    char fullPath[SYSFS_PATH_LEN] = { 0x00 };
    ret = DdkSysfsFindIntfPath(devicePath, devInfo->intfNum, fullPath, sizeof(fullPath));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: retrieve interface path failed, ret:%{public}d", __func__, ret);
        return ret;
    }

    HDF_LOGI("%{public}s: fullPath [%{public}s]", __func__, fullPath);

    char nodeName[SYSFS_PATH_LEN] = { 0x00 };
    ret = DdkSysfsFindDevNodeName(fullPath, prefix, nodeName, sizeof(nodeName));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: retrieve device file path failed, ret:%{public}d", __func__, ret);
        return ret;
    }

    int32_t num = sprintf_s(buff, buffSize, "/dev/%s", nodeName);
    if (num <= 0) {
        HDF_LOGE("%{public}s: sprintf_s error nodeName:%{public}s", __func__, nodeName);
        return HDF_FAILURE;
    }

    HDF_LOGI("%{public}s: devPath [%{public}s]", __func__, buff);
    return HDF_SUCCESS;
}