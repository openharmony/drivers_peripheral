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

#include "hdf_log.h"
#include "securec.h"

#define SYSFS_PATH_LEN   128
#define PROPERTY_MAX_LEN 128
#define HDF_LOG_TAG      usb_ddk_sysfs_dev

static inline int32_t DdkSysfsGetBase(const char *propName)
{
    if (strcmp(propName, "idProduct") == 0 || strcmp(propName, "idVendor") == 0) {
        return 16; // 16 means hexadecimal
    }
    return 10; // 10 means decimal
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