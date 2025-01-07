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

#include "libusb_adapter.h"

#include <iostream>
#include <map>
#include <cerrno>
#include <cstdio>
#include <climits>
#include <limits>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <shared_mutex>
#include <sys/types.h>
#include <sys/mman.h>
#include <hdf_base.h>
#include <hdf_log.h>

#include "accesstoken_kit.h"
#include "hap_token_info.h"
#include "ipc_skeleton.h"
#include "osal_mem.h"
#include "securec.h"
#include "usbd_wrapper.h"

namespace OHOS {
namespace HDI {
namespace Usb {
namespace V1_1 {
namespace {
constexpr uint8_t LIBUSB_MAX_INTERFACEID = 0x80;
constexpr int32_t USB_MAX_INTERFACES = 32;
constexpr int32_t READ_BUF_SIZE = 8192;
constexpr int32_t USB_MAX_DESCRIPTOR_SIZE = 256;
constexpr uint16_t ENGLISH_US_LANGUAGE_ID = 0x0409;
constexpr int32_t USB_ENDPOINT_DIR_MASK = 0x80;
constexpr int32_t USB_ENDPOINT_DIR_OUT = 0;
constexpr int32_t USB_ENDPOINT_DIR_IN = 0x80;
constexpr int32_t MAX_CONTROL_BUFF_SIZE = 1024;
constexpr uint32_t INTERRUPT_READ_BUF_SIZE = 128;
constexpr int32_t DISPLACEMENT_NUMBER = 8;
constexpr uint32_t LIBUSB_PATH_LENGTH = 64;
constexpr uint64_t MAX_TOTAL_SIZE = 520447;
constexpr int32_t API_VERSION_ID = 16;
constexpr int32_t LIBUSB_IO_ERROR = -1;
constexpr int32_t LIBUSB_IO_ERROR_INVALID = 0;
constexpr const char* USB_DEV_FS_PATH = "/dev/bus/usb";
constexpr const char* LIBUSB_DEVICE_MMAP_PATH = "/data/service/el1/public/usb/";
static libusb_context *g_libusb_context = nullptr;
static std::shared_ptr<LibusbAdapter> g_LibusbAdapter = std::make_shared<LibusbAdapter>();
struct CurrentUsbSetting {
    int32_t configurationIndex = -1;
    int32_t interfaceNumber = -1;
    int32_t alternateSetting = -1;
};
std::vector<std::pair<UsbDev, libusb_device_handle*>> g_handleVector;
std::map<uint32_t, uint8_t> g_InterfaceIdMap;
std::map<libusb_device_handle*, CurrentUsbSetting> g_deviceSettingsMap;
std::map<uint32_t, int32_t> g_usbOpenFdMap;
std::shared_mutex g_mapMutexInterfaceIdMap;
std::shared_mutex g_mapMutexDeviceSettingsMap;
std::shared_mutex g_mapMutexContext;
std::shared_mutex g_mapMutexUsbOpenFdMap;
std::shared_mutex g_mapMutexHandleVector;
} // namespace

std::shared_ptr<LibusbAdapter> LibusbAdapter::GetInstance()
{
    return g_LibusbAdapter;
}

LibusbAdapter::LibusbAdapter()
{
}

LibusbAdapter::~LibusbAdapter()
{
    LibUSBExit();
}

void GetApiVersion(int32_t &apiVersion)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    OHOS::Security::AccessToken::HapTokenInfo info;
    int32_t ret = OHOS::Security::AccessToken::AccessTokenKit::GetHapTokenInfo(callerToken, info);
    if (ret < HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get hapInfo failed", __func__);
        return;
    }
    apiVersion = info.apiVersion;
}

int32_t LibusbAdapter::LibUSBInit()
{
    HDF_LOGI("%{public}s enter", __func__);
    if (g_libusb_context != nullptr) {
        HDF_LOGI("%{public}s g_libusb_context is initialized", __func__);
        return HDF_SUCCESS;
    }
    std::unique_lock<std::shared_mutex> lock(g_mapMutexContext);
    int32_t ret = libusb_init(&g_libusb_context);
    if (ret < 0) {
        HDF_LOGE("%{public}s libusb_init is error", __func__);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s leave", __func__);
    return HDF_SUCCESS;
}

void LibusbAdapter::LibUSBExit()
{
    HDF_LOGI("%{public}s enter", __func__);
    std::unique_lock<std::shared_mutex> lock(g_mapMutexContext);
    if (g_libusb_context != nullptr) {
        libusb_exit(g_libusb_context);
        g_libusb_context = nullptr;
    }
    HDF_LOGI("%{public}s leave", __func__);
}

int32_t LibusbAdapter::GetUsbDevice(const UsbDev &dev, libusb_device **device)
{
    HDF_LOGD("%{public}s enter", __func__);
    if (dev.busNum == 0 || dev.devAddr == 0) {
        HDF_LOGE("%{public}s Invalid parameter", __func__);
        return HDF_DEV_ERR_NO_DEVICE;
    }
    if (g_libusb_context == nullptr) {
        HDF_LOGE("%{public}s: g_libusb_context is nullptr", __func__);
        return HDF_FAILURE;
    }
    libusb_device **devs = nullptr;
    size_t count = libusb_get_device_list(g_libusb_context, &devs);
    for (size_t i = 0; i < count; i++) {
        uint8_t devDusNum = libusb_get_bus_number(devs[i]);
        uint8_t devDevAddr = libusb_get_device_address(devs[i]);
        if (devDusNum == dev.busNum && devDevAddr == dev.devAddr) {
            *device = devs[i];
            libusb_free_device_list(devs, 1);
            HDF_LOGD("%{public}s success leave", __func__);
            return HDF_SUCCESS;
        }
    }
    libusb_free_device_list(devs, 1);
    HDF_LOGE("%{public}s: Search device does not exist leave", __func__);
    return HDF_DEV_ERR_NO_DEVICE;
}

int32_t LibusbAdapter::FindHandleByDev(const UsbDev &dev, libusb_device_handle **handle)
{
    HDF_LOGD("%{public}s enter", __func__);
    std::shared_lock<std::shared_mutex> lock(g_mapMutexHandleVector);
    for (auto it = g_handleVector.begin(); it != g_handleVector.end(); ++it) {
        if (it->first.busNum == dev.busNum && it->first.devAddr == dev.devAddr) {
            *handle = it->second;
            HDF_LOGD("%{public}s Search handle success leave", __func__);
            return HDF_SUCCESS;
        }
    }
    HDF_LOGE("%{public}s Search handle failed leave", __func__);
    return HDF_DEV_ERR_NO_DEVICE;
}

int32_t LibusbAdapter::DeleteHandleVectorAndSettingsMap(const UsbDev &dev, libusb_device_handle* handle)
{
    HDF_LOGD("%{public}s enter", __func__);
    {
        std::unique_lock<std::shared_mutex> lock(g_mapMutexDeviceSettingsMap);
        auto entry = g_deviceSettingsMap.find(handle);
        if (entry != g_deviceSettingsMap.end()) {
            g_deviceSettingsMap.erase(entry);
        }
    }
    int32_t ret = HDF_FAILURE;
    {
        std::unique_lock<std::shared_mutex> lock(g_mapMutexHandleVector);
        for (auto it = g_handleVector.begin(); it != g_handleVector.end(); ++it) {
            if (it->first.busNum == dev.busNum && it->first.devAddr == dev.devAddr) {
                g_handleVector.erase(it);
                ret = HDF_SUCCESS;
                break;
            }
        }
    }
    HDF_LOGD("%{public}s leave", __func__);
    return ret;
}

int32_t LibusbAdapter::OpenDevice(const UsbDev &dev)
{
    HDF_LOGI("%{public}s enter", __func__);
    int32_t ret = LibUSBInit();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:LibUSBInit is failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    libusb_device *device = nullptr;
    ret = GetUsbDevice(dev, &device);
    if (device == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:GetUsbDevice is failed ret=%{public}d", __func__, ret);
        return HDF_DEV_ERR_NO_DEVICE;
    }
    libusb_device_handle* devHandle = nullptr;
    ret = libusb_open(device, &devHandle);
    if (devHandle == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:Opening device failed ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    {
        std::unique_lock<std::shared_mutex> lock(g_mapMutexHandleVector);
        g_handleVector.push_back(std::make_pair(dev, devHandle));
    }
    int32_t currentConfig = -1;
    ret = GetCurrentConfiguration(devHandle, currentConfig);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: GetCurrentConfiguration failed", __func__);
        return HDF_FAILURE;
    }
    {
        std::unique_lock<std::shared_mutex> lock(g_mapMutexDeviceSettingsMap);
        g_deviceSettingsMap[devHandle].configurationIndex = currentConfig;
    }
    HDF_LOGI("%{public}s succeeded", __func__);
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::CloseDevice(const UsbDev &dev)
{
    HDF_LOGI("%{public}s enter", __func__);
    libusb_device_handle *devHandle = nullptr;
    int32_t ret = FindHandleByDev(dev, &devHandle);
    if (devHandle == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:FindHandleByDev is failed ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    uint32_t result = (static_cast<uint32_t>(dev.busNum) << DISPLACEMENT_NUMBER) |
        static_cast<uint32_t>(dev.devAddr);
    ret = DeleteHandleVectorAndSettingsMap(dev, devHandle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:DeleteHandleVectorAndSettingsMap is failed ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    auto it = g_usbOpenFdMap.find(result);
    if (it != g_usbOpenFdMap.end()) {
        close(it->second);
        g_usbOpenFdMap.erase(it);
    }
    libusb_close(devHandle);

    HDF_LOGI("%{public}s leave", __func__);
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::ResetDevice(const UsbDev &dev)
{
    HDF_LOGI("%{public}s enter", __func__);
    libusb_device_handle *devHandle = nullptr;
    int32_t ret = FindHandleByDev(dev, &devHandle);
    if (devHandle == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: FindHandleByDev failed ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    ret = libusb_reset_device(devHandle);
    if (ret < 0) {
        HDF_LOGE("%{public}s: Failed to reset device, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s leave", __func__);
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::GetDeviceDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor)
{
    HDF_LOGI("%{public}s enter", __func__);
    struct libusb_device_descriptor desc;
    libusb_device *device = nullptr;
    int32_t ret = GetUsbDevice(dev, &device);
    if (device == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: GetUsbDevice is failed ret=%{public}d", __func__, ret);
        return HDF_DEV_ERR_NO_DEVICE;
    }
    ret = libusb_get_device_descriptor(device, &desc);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: libusb_get_device_descriptor is failed ret=%{public}d", __func__, ret);
        return ret;
    }

    descriptor.resize(desc.bLength);
    ret = memcpy_s(descriptor.data(), descriptor.size(), &desc, desc.bLength);
    if (ret != EOK) {
        HDF_LOGE("%{public}s: memcpy_s failed", __func__);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s leave", __func__);
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::GetConfigDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor)
{
    HDF_LOGI("%{public}s enter", __func__);
    libusb_device *device = nullptr;
    int32_t ret = GetUsbDevice(dev, &device);
    if (device == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: GetConfigDescriptor Find device failed", __func__);
        return HDF_FAILURE;
    }

    ret = GetConfigDescriptor(device, descId, descriptor);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Failed to copy configuration descriptor", __func__);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s is success leave", __func__);
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::GetDeviceFileDescriptor(const UsbDev &dev, int32_t &fd)
{
    HDF_LOGI("%{public}s enter", __func__);
    uint32_t result = (static_cast<uint32_t>(dev.busNum) << DISPLACEMENT_NUMBER) |
        static_cast<uint32_t>(dev.devAddr);
    {
        std::shared_lock<std::shared_mutex> lock(g_mapMutexUsbOpenFdMap);
        auto info = g_usbOpenFdMap.find(result);
        if (info != g_usbOpenFdMap.end()) {
            fd = info->second;
            HDF_LOGI("%{public}s open is already on, fd: %{public}d", __func__, info->second);
            return HDF_SUCCESS;
        }
    }
    char path[LIBUSB_PATH_LENGTH] = {"\0"};
    int32_t ret = sprintf_s(path, sizeof(path), "%s/%03u/%03u", USB_DEV_FS_PATH, dev.busNum, dev.devAddr);
    if (ret < 0) {
        HDF_LOGE("%{public}s: sprintf_s path failed, ret:%{public}d", __func__, ret);
        return ret;
    }
    int32_t fileFd = open(path, O_RDWR);
    if (fileFd < 0) {
        HDF_LOGE("%{public}s: open device failed errno = %{public}d %{public}s", __func__, errno, strerror(errno));
        return HDF_FAILURE;
    }
    fd = fileFd;
    {
        std::unique_lock<std::shared_mutex> lock(g_mapMutexUsbOpenFdMap);
        g_usbOpenFdMap[result] = fd;
    }
    HDF_LOGI("%{public}s leave", __func__);
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::SetConfig(const UsbDev &dev, uint8_t configIndex)
{
    HDF_LOGI("%{public}s:enter", __func__);
    libusb_device_handle *devHandle = nullptr;
    int32_t ret = FindHandleByDev(dev, &devHandle);
    if (devHandle == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Find UsbHandle failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    int configIdOld = 0;
    ret = libusb_get_configuration(devHandle, &configIdOld);
    if (ret != LIBUSB_SUCCESS) {
        HDF_LOGE("%{public}s: Failed to get current configuration ret:%{public}d", __func__, ret);
        return HDF_ERR_IO;
    }
    std::unique_lock<std::shared_mutex> lock(g_mapMutexDeviceSettingsMap);
    auto it = g_deviceSettingsMap.find(devHandle);
    if (it == g_deviceSettingsMap.end()) {
        HDF_LOGE("No device handle found");
        return HDF_FAILURE;
    }
    if (configIdOld == configIndex) {
        HDF_LOGE("%{public}s: setConfiguration success, configIndex:%{public}d configIdOld:%{public}d", __func__,
            configIndex, configIdOld);
        it->second.configurationIndex = static_cast<int32_t>(configIndex);
        return HDF_SUCCESS;
    }
    ret = libusb_set_configuration(devHandle, configIndex);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: setConfiguration failed ret:%{public}d", __func__, ret);
        return HDF_ERR_IO;
    }
    g_deviceSettingsMap[devHandle].configurationIndex = static_cast<int32_t>(configIndex);
    HDF_LOGI("%{public}s: leave", __func__);
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::GetConfig(const UsbDev &dev, uint8_t &configIndex)
{
    HDF_LOGI("%{public}s enter", __func__);
    libusb_device_handle *devHandle = nullptr;
    libusb_device *device = nullptr;
    int32_t ret = GetUsbDevice(dev, &device);
    if (device == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Find device failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    ret = FindHandleByDev(dev, &devHandle);
    if (devHandle == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Find UsbHandle failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    int tampconfigIndex = static_cast<int>(configIndex);
    ret = libusb_get_configuration(devHandle, &tampconfigIndex);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Find configIndex failed", __func__);
        return HDF_FAILURE;
    }
    configIndex = static_cast<uint8_t>(tampconfigIndex);
    HDF_LOGI("%{public}s leave", __func__);
    return ret;
}

int32_t LibusbAdapter::ManageInterface(const UsbDev &dev, uint8_t interfaceId, bool disable)
{
    HDF_LOGI("%{public}s enter", __func__);
    libusb_device *device = nullptr;
    int32_t ret = GetUsbDevice(dev, &device);
    if (device == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: GetUsbDevice failed, ret=%{public}d", __func__, ret);
        return HDF_DEV_ERR_NO_DEVICE;
    }

    libusb_device_handle *devHandle = nullptr;
    ret = FindHandleByDev(dev, &devHandle);
    if (devHandle == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: FindHandleByDev failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    if (disable) {
        ret = libusb_detach_kernel_driver(devHandle, interfaceId);
    } else {
        ret = libusb_attach_kernel_driver(devHandle, interfaceId);
    }
    if (ret == LIBUSB_ERROR_NOT_FOUND) {
        ret = libusb_set_auto_detach_kernel_driver(devHandle, disable);
    }
    if (ret == LIBUSB_ERROR_NO_DEVICE || ret == LIBUSB_ERROR_NOT_SUPPORTED) {
        HDF_LOGE("%{public}s: ManageInterface failed, busNum=%{public}u, devAddr=%{public}u",
            __func__, dev.busNum, dev.devAddr);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s leave ret=%{public}d", __func__, ret);

    return (ret >= 0) ? HDF_SUCCESS : HDF_FAILURE;
}

int32_t LibusbAdapter::ReleaseInterface(const UsbDev &dev, uint8_t interfaceId)
{
    HDF_LOGI("%{public}s enter", __func__);
    {
        std::unique_lock<std::shared_mutex> lock(g_mapMutexInterfaceIdMap);
        uint32_t result = (static_cast<uint32_t>(dev.busNum) << DISPLACEMENT_NUMBER) |
            static_cast<uint32_t>(dev.devAddr);
        if (g_InterfaceIdMap.find(result) != g_InterfaceIdMap.end()) {
            HDF_LOGI("%{public}s erase dev.busNum=%{public}u, dev.devAddr=%{public}u, result=%{public}d,",
                __func__, dev.busNum, dev.devAddr, result);
            g_InterfaceIdMap.erase(result);
        }
    }
    libusb_device_handle *devHandle = nullptr;
    int32_t ret = FindHandleByDev(dev, &devHandle);
    if (devHandle == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: FindHandleByDev failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    if (interfaceId >= USB_MAX_INTERFACES) {
        HDF_LOGE("%{public}s: interfaceId failed busNum:%{public}u devAddr:%{public}u interfaceId:%{public}u",
            __func__, dev.busNum, dev.devAddr, interfaceId);
        return HDF_FAILURE;
    }
    ret = libusb_release_interface(devHandle, interfaceId);
    if (ret < HDF_SUCCESS) {
        HDF_LOGE("%{public}s: libusb_release_interface failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    if (!CheckDeviceAndConfiguration(devHandle)) {
        HDF_LOGE("CheckDeviceAndConfiguration failed");
        return HDF_FAILURE;
    }
    {
        std::unique_lock<std::shared_mutex> lock(g_mapMutexDeviceSettingsMap);
        g_deviceSettingsMap[devHandle].interfaceNumber = -1;
        g_deviceSettingsMap[devHandle].alternateSetting = -1;
    }
    HDF_LOGI("%{public}s leave", __func__);
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::BulkTransferRead(const UsbDev &dev, const UsbPipe &pipe, int32_t timeout,
    std::vector<uint8_t> &data)
{
    HDF_LOGI("%{public}s enter", __func__);
    if (pipe.intfId >= LIBUSB_MAX_INTERFACEID) {
        HDF_LOGE("interfaceId is invalid");
        return HDF_ERR_INVALID_PARAM;
    }
    uint8_t tbuf[READ_BUF_SIZE] = {'\0'};
    uint32_t tsize = READ_BUF_SIZE;
    int actlength = 0;
    libusb_device_handle *devHandle = nullptr;
    int32_t ret = FindHandleByDev(dev, &devHandle);
    if (ret != HDF_SUCCESS || devHandle == nullptr) {
        HDF_LOGE("%{public}s: FindHandleByDev failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    ret = libusb_bulk_transfer(devHandle, pipe.endpointId, tbuf, tsize, &actlength, timeout);
    if (ret < 0) {
        HDF_LOGE("%{public}s: libusb_bulk_transfer is error ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    if (actlength > 0) {
        data.assign(tbuf, tbuf + actlength);
        ret = HDF_SUCCESS;
    }
    HDF_LOGI("%{public}s leave", __func__);
    return ret;
}

int32_t LibusbAdapter::BulkTransferReadwithLength(const UsbDev &dev,
    const UsbPipe &pipe, int32_t timeout, int32_t length, std::vector<uint8_t> &data)
{
    HDF_LOGI("%{public}s enter", __func__);
    if (pipe.intfId >= LIBUSB_MAX_INTERFACEID) {
        HDF_LOGE("%{public}s interfaceId is invalid", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (length <= 0) {
        HDF_LOGE("%{public}s: invalid length param, length: %{public}d.", __func__, length);
        return HDF_ERR_INVALID_PARAM;
    }

    libusb_device_handle* devHandle = nullptr;
    libusb_endpoint_descriptor* endpointDes = nullptr;
    int32_t ret = GetEndpointDesc(dev, pipe, &endpointDes, &devHandle);
    if (ret != HDF_SUCCESS || devHandle == nullptr) {
        HDF_LOGE("%{public}s:GetEndpointDesc failed ret:%{public}d", __func__, ret);
        return ret;
    }
    uint8_t interfaceId = 0;
    ret = GetInterfaceIdByUsbDev(dev, interfaceId);
    if (ret != HDF_SUCCESS || interfaceId != pipe.intfId) {
        HDF_LOGE("%{public}s get interfaceId failed", __func__);
        return HDF_FAILURE;
    }
    std::vector<uint8_t> buffer(length);
    int32_t transferred = 0;
    ret = libusb_bulk_transfer(devHandle, (pipe.endpointId | LIBUSB_ENDPOINT_IN), (unsigned char *)buffer.data(),
        length, &transferred, timeout);
    if (ret < 0) {
        if (ret == LIBUSB_IO_ERROR && interfaceId == pipe.intfId) {
            HDF_LOGD("%{public}s: interfaceId=%{public}d, pipe.intfId=%{public}d", __func__, interfaceId, pipe.intfId);
            return LIBUSB_IO_ERROR_INVALID;
        }
        HDF_LOGE("%{public}s: libusb_bulk_transfer failed, ret: %{public}d",
            __func__, ret);
        return ret;
    }
    if (transferred > 0) {
        data.assign(buffer.begin(), buffer.begin() + transferred);
        ret = HDF_SUCCESS;
    }
    HDF_LOGI("%{public}s leave", __func__);
    return ret;
}

int32_t LibusbAdapter::BulkTransferWrite(
    const UsbDev &dev, const UsbPipe &pipe, int32_t timeout, const std::vector<uint8_t> &data)
{
    HDF_LOGI("%{public}s enter", __func__);
    if (pipe.intfId >= LIBUSB_MAX_INTERFACEID) {
        HDF_LOGE("%{public}s interfaceId is invalid", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t actlength = 0;
    libusb_device_handle* devHandle = nullptr;
    libusb_endpoint_descriptor* endpointDes = nullptr;
    int32_t ret = GetEndpointDesc(dev, pipe, &endpointDes, &devHandle);
    if (ret != HDF_SUCCESS || devHandle == nullptr) {
        HDF_LOGE("%{public}s:GetEndpointDesc failed ret:%{public}d", __func__, ret);
        return ret;
    }
    uint8_t interfaceId = 0;
    ret = GetInterfaceIdByUsbDev(dev, interfaceId);
    if (ret != HDF_SUCCESS || interfaceId != pipe.intfId) {
        HDF_LOGE("%{public}s get interfaceId failed", __func__);
        return HDF_FAILURE;
    }
    ret = libusb_bulk_transfer(devHandle, pipe.endpointId, (unsigned char *)data.data(), data.size(),
        &actlength, timeout);
    if (ret < 0) {
        if (ret == LIBUSB_IO_ERROR && interfaceId == pipe.intfId) {
            HDF_LOGE("%{public}s: interfaceId=%{public}d, pipe.intfId=%{public}d", __func__, interfaceId, pipe.intfId);
            return LIBUSB_IO_ERROR_INVALID;
        }
        HDF_LOGE("%{public}s: libusb_bulk_transfer is error ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s leave", __func__);
    return ret;
}

int32_t LibusbAdapter::IsoTransferRead(const UsbDev &dev, const UsbPipe &pipe,
    int32_t timeout, std::vector<uint8_t> &data)
{
    HDF_LOGI("%{public}s enter", __func__);
    if (pipe.intfId >= LIBUSB_MAX_INTERFACEID) {
        HDF_LOGE("%{public}s interfaceId is invalid", __func__);
        return HDF_FAILURE;
    }
    uint8_t tbuf[READ_BUF_SIZE] = {0};
    uint32_t tsize = READ_BUF_SIZE;
    int32_t actlength = 0;
    libusb_device_handle *devHandle = nullptr;
    int32_t ret = FindHandleByDev(dev, &devHandle);
    if (devHandle == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: FindHandleByDev failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    ret = libusb_bulk_transfer(devHandle, pipe.endpointId, tbuf, tsize, &actlength, timeout);
    if (ret < 0) {
        HDF_LOGE("%{public}s: libusb_bulk_transfer is error ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    if (actlength > 0) {
        data.assign(tbuf, tbuf + actlength);
        ret = HDF_SUCCESS;
    }
    HDF_LOGI("%{public}s leave", __func__);
    return ret;
}

int32_t LibusbAdapter::IsoTransferWrite(
    const UsbDev &dev, const UsbPipe &pipe, int32_t timeout, const std::vector<uint8_t> &data)
{
    HDF_LOGI("%{public}s enter", __func__);
    if (pipe.intfId >= LIBUSB_MAX_INTERFACEID) {
        HDF_LOGE("%{public}s interfaceId is invalid", __func__);
        return HDF_FAILURE;
    }
    int actlength = data.size();
    libusb_device_handle *devHandle = nullptr;
    int32_t ret = FindHandleByDev(dev, &devHandle);
    if (devHandle == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: FindHandleByDev failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    ret = libusb_bulk_transfer(devHandle, pipe.endpointId, (unsigned char *)data.data(),
        data.size(), &actlength, timeout);
    if (ret < 0) {
        HDF_LOGE("%{public}s: libusb_bulk_transfer is error ", __func__);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s leave", __func__);
    return ret;
}

int32_t LibusbAdapter::SetInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t altIndex)
{
    HDF_LOGI("%{public}s enter", __func__);
    libusb_device_handle *devHandle = nullptr;
    int32_t ret = FindHandleByDev(dev, &devHandle);
    if (devHandle == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: FindHandleByDev failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    ret = libusb_set_interface_alt_setting(devHandle, interfaceId, altIndex);
    if (ret == LIBUSB_ERROR_NO_DEVICE || ret == LIBUSB_ERROR_NOT_FOUND || ret == LIBUSB_ERROR_INVALID_PARAM) {
        HDF_LOGE("%{public}s: SetInterface failed, busNum=%{public}u, devAddr=%{public}u, ret=%{public}d", __func__,
            dev.busNum, dev.devAddr, ret);
        return HDF_FAILURE;
    }
    if (!CheckDeviceAndConfiguration(devHandle)) {
        HDF_LOGE("%{public}s: CheckDeviceAndConfiguration failed", __func__);
        return HDF_FAILURE;
    }
    std::unique_lock<std::shared_mutex> lock(g_mapMutexDeviceSettingsMap);
    g_deviceSettingsMap[devHandle].interfaceNumber = static_cast<int32_t>(interfaceId);
    g_deviceSettingsMap[devHandle].alternateSetting = static_cast<int32_t>(altIndex);
    HDF_LOGI("%{public}s leave", __func__);
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::ClearHalt(const UsbDev &dev, const UsbPipe &pipe)
{
    HDF_LOGI("%{public}s enter", __func__);
    if (pipe.intfId >= LIBUSB_MAX_INTERFACEID) {
        HDF_LOGE("interfaceId is invalid");
        return HDF_ERR_INVALID_PARAM;
    }
    libusb_device_handle *devHandle = nullptr;
    int32_t ret = FindHandleByDev(dev, &devHandle);
    if (devHandle == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:FindHandleByDev failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    ret = libusb_clear_halt(devHandle, pipe.endpointId);
    if (ret < 0) {
        HDF_LOGE("%{public}s: libusb_clear_halt error: %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s leave", __func__);
    return ret;
}

int32_t LibusbAdapter::GetEndpointDesc(const UsbDev &dev, const UsbPipe &pipe,
    libusb_endpoint_descriptor **endpoint_desc, libusb_device_handle** deviceHandle)
{
    HDF_LOGD("%{public}s enter", __func__);
    libusb_device *device = nullptr;
    int32_t ret = GetUsbDevice(dev, &device);
    if (device == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: LibusbFindDevice is failed, ret=%{public}d", __func__, ret);
        return HDF_DEV_ERR_NO_DEVICE;
    }
    libusb_device_handle *devHandle = nullptr;
    ret = FindHandleByDev(dev, &devHandle);
    if (devHandle == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: FindHandleByDev is failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    *deviceHandle = devHandle;
    libusb_config_descriptor *config_desc = nullptr;
    ret = libusb_get_active_config_descriptor(libusb_get_device(devHandle), &config_desc);
    if (ret < 0) {
        HDF_LOGE("%{public}s: libusb_get_active_config_descriptor failed ret=%{public}d", __func__, ret);
        return HDF_ERR_INVALID_PARAM;
    }
    if (pipe.intfId < 0 || pipe.intfId >= config_desc->bNumInterfaces) {
        HDF_LOGE("%{public}s: pipe.intfId is failed", __func__);
        return HDF_FAILURE;
    }
    bool findFlag = false;
    const libusb_interface *intf = &config_desc->interface[pipe.intfId];
    for (int j = 0; j < intf->num_altsetting; j++) {
        const libusb_interface_descriptor *intf_desc = &intf->altsetting[j];
        for (int k = 0; k < intf_desc->bNumEndpoints; k++) {
            const libusb_endpoint_descriptor *endpoint_desc_tmp = &intf_desc->endpoint[k];
            if (endpoint_desc_tmp->bEndpointAddress == pipe.endpointId) {
                *endpoint_desc = (libusb_endpoint_descriptor *)endpoint_desc_tmp;
                findFlag = true;
                break;
            }
        }
        if (findFlag) {
            break;
        }
    }
    
    if (findFlag) {
        HDF_LOGD("%{public}s leave", __func__);
        return HDF_SUCCESS;
    } else {
        HDF_LOGE("%{public}s: LibUSBGetEndpointDesc is failed", __func__);
        return HDF_FAILURE;
    }
}

int32_t LibusbAdapter::InterruptTransferRead(
    const UsbDev &dev, const UsbPipe &pipe, int32_t timeout, std::vector<uint8_t> &data)
{
    HDF_LOGI("%{public}s enter", __func__);
    libusb_device_handle* deviceHandle = nullptr;
    libusb_endpoint_descriptor* endpointDes = nullptr;
    int32_t ret = GetEndpointDesc(dev, pipe, &endpointDes, &deviceHandle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: InterruptTransferRead_lhx LibUSBGetEndpointDesc failed ret:%{public}d", __func__, ret);
        return ret;
    }
    if ((endpointDes->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) != LIBUSB_ENDPOINT_TRANSFER_TYPE_INTERRUPT ||
        (endpointDes->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) != LIBUSB_ENDPOINT_IN) {
        HDF_LOGE("%{public}s: InterruptTransferRead_lhx invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    
    uint8_t tbuf[INTERRUPT_READ_BUF_SIZE] = {0};
    uint32_t tsize = INTERRUPT_READ_BUF_SIZE;
    uint32_t actlength = 0;
    ret = libusb_interrupt_transfer(deviceHandle, pipe.endpointId, tbuf, tsize, (int *)&actlength, timeout);
    if (ret < 0) {
        HDF_LOGE("%{public}s: failed", __func__);
        return HDF_FAILURE;
    }
    data.assign(tbuf, tbuf + actlength);
    HDF_LOGI("%{public}s leave", __func__);
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::InterruptTransferWrite(
    const UsbDev &dev, const UsbPipe &pipe, int32_t timeout, const std::vector<uint8_t> &data)
{
    HDF_LOGI("%{public}s enter", __func__);
    libusb_device_handle* deviceHandle = nullptr;
    libusb_endpoint_descriptor* endpointDes = nullptr;
    int32_t ret = GetEndpointDesc(dev, pipe, &endpointDes, &deviceHandle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: InterruptTransferRead_lhx LibUSBGetEndpointDesc failed ret:%{public}d", __func__, ret);
        return ret;
    }
    if ((endpointDes->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) != LIBUSB_ENDPOINT_TRANSFER_TYPE_INTERRUPT ||
        (endpointDes->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) != LIBUSB_ENDPOINT_OUT) {
        HDF_LOGE("%{public}s: InterruptTransferWrite invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    int transferred = 0;
    ret = libusb_interrupt_transfer(deviceHandle, pipe.endpointId, (unsigned char *)data.data(), data.size(),
        &transferred, timeout);
    if (ret == 0 && transferred > 0) {
        HDF_LOGI("%{public}s: InterruptTransferWrite_lhx libusb_interrupt_transfer ok transferred:%{public}d",
            __func__, transferred);
    } else {
        HDF_LOGE("%{public}s: ret:%{public}d error", __func__, ret);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s leave", __func__);
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::GetStringDescriptor(const UsbDev &dev, uint8_t descId, std::vector<uint8_t> &descriptor)
{
    HDF_LOGI("%{public}s enter", __func__);
    libusb_device_handle *devHandle = nullptr;
    libusb_device *device = nullptr;
    uint8_t data[USB_MAX_DESCRIPTOR_SIZE] = {0};
    int32_t ret = GetUsbDevice(dev, &device);
    if (device == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: GetUsbDevice is failed, ret=%{public}d", __func__, ret);
        return HDF_DEV_ERR_NO_DEVICE;
    }
    ret = FindHandleByDev(dev, &devHandle);
    if (devHandle == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: FindHandleByDev is failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    int32_t length = sizeof(data);
    ret = libusb_get_string_descriptor(devHandle, descId, ENGLISH_US_LANGUAGE_ID, data, length);
    if (ret <= 0) {
        HDF_LOGE("%{public}s: libusb_get_string_descriptor is failed, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    descriptor.resize(USB_MAX_DESCRIPTOR_SIZE);
    std::copy(data, data + USB_MAX_DESCRIPTOR_SIZE, descriptor.begin());
    HDF_LOGI("%{public}s leave", __func__);
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::ClaimInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t force)
{
    HDF_LOGI("%{public}s enter", __func__);
    libusb_device_handle *devHandle = nullptr;
    int32_t ret = FindHandleByDev(dev, &devHandle);
    if (devHandle == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: FindHandleByDev failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    if (force) {
        if (libusb_kernel_driver_active(devHandle, interfaceId) != 1) {
            HDF_LOGW("This interface is not occupied by the kernel driver,interfaceId : %{public}d", interfaceId);
        } else {
            ret = libusb_detach_kernel_driver(devHandle, interfaceId);
            if (ret < HDF_SUCCESS) {
                HDF_LOGE("libusb_detach_kernel_driver is error, ret: %{public}d", ret);
            }
        }
    }

    ret = libusb_claim_interface(devHandle, interfaceId);
    HDF_LOGI("Interface claim ret : %{public}d, force : %{public}d", ret, force);
    if (ret != LIBUSB_SUCCESS) {
        HDF_LOGE("%{public}s: ClaimInterface failed, busNum=%{public}u, devAddr=%{public}u, ret=%{public}d",
            __func__, dev.busNum, dev.devAddr, ret);
        return HDF_FAILURE;
    }
    if (!CheckDeviceAndConfiguration(devHandle)) {
        HDF_LOGE("CheckDeviceAndConfiguration failed");
        return HDF_FAILURE;
    }
    {
        std::unique_lock<std::shared_mutex> lock(g_mapMutexDeviceSettingsMap);
        g_deviceSettingsMap[devHandle].interfaceNumber = static_cast<int32_t>(interfaceId);
        g_deviceSettingsMap[devHandle].alternateSetting = 0;
    }
    {
        std::unique_lock<std::shared_mutex> lock(g_mapMutexInterfaceIdMap);
        uint32_t result = (static_cast<uint32_t>(dev.busNum) << DISPLACEMENT_NUMBER) |
            static_cast<uint32_t>(dev.devAddr);
        g_InterfaceIdMap[result] = interfaceId;
    }
    HDF_LOGI("%{public}s leave", __func__);
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::ControlTransferRead(const UsbDev &dev, const UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data)
{
    HDF_LOGI("%{public}s enter", __func__);
    if ((static_cast<uint32_t>(ctrl.requestType) & USB_ENDPOINT_DIR_MASK) == USB_ENDPOINT_DIR_OUT) {
        HDF_LOGE("%{public}s: this function is read, not write", __func__);
        return HDF_FAILURE;
    }
    std::vector<uint8_t> buffer(MAX_CONTROL_BUFF_SIZE);
    int32_t ret = DoControlTransfer(dev, ctrl, buffer);
    if (ret < 0) {
        HDF_LOGE("%{public}s:libusb_control_transfer failed with error: %{public}d", __func__, ret);
        return ret;
    }
    data.assign(buffer.begin(), buffer.begin() + ret);
    HDF_LOGI("%{public}s leave", __func__);
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::ControlTransferWrite(const UsbDev &dev, const UsbCtrlTransfer &ctrl,
    const std::vector<uint8_t> &data)
{
    HDF_LOGI("%{public}s enter", __func__);
    if ((static_cast<uint32_t>(ctrl.requestType) & USB_ENDPOINT_DIR_MASK) == USB_ENDPOINT_DIR_IN) {
        HDF_LOGE("%{public}s: this function is read, not write", __func__);
        return HDF_FAILURE;
    }
    std::vector<uint8_t> buffer(data);
    int32_t ret = DoControlTransfer(dev, ctrl, buffer);
    if (ret < 0) {
        HDF_LOGE("%{public}s:libusb_control_transfer failed with error: %{public}d", __func__, ret);
        return ret;
    }
    HDF_LOGI("%{public}s leave", __func__);
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::ControlTransferReadwithLength(
    const UsbDev &dev, const UsbCtrlTransferParams &ctrlParams, std::vector<uint8_t> &data)
{
    HDF_LOGI("%{public}s enter", __func__);
    if ((static_cast<uint32_t>(ctrlParams.requestType) & USB_ENDPOINT_DIR_MASK) == USB_ENDPOINT_DIR_OUT) {
        HDF_LOGE("%{public}s: this function is read, not write", __func__);
        return HDF_FAILURE;
    }
    int32_t size = (ctrlParams.length <= 0 || ctrlParams.length > MAX_CONTROL_BUFF_SIZE)
        ? MAX_CONTROL_BUFF_SIZE : ctrlParams.length;
    std::vector<uint8_t> buffer(size);

    const UsbCtrlTransfer ctrl = {
        .requestType = ctrlParams.requestType,
        .requestCmd = ctrlParams.requestCmd,
        .value = ctrlParams.value,
        .index = ctrlParams.index,
        .timeout = ctrlParams.timeout
    };

    int32_t ret = DoControlTransfer(dev, ctrl, buffer);
    if (ret < 0) {
        HDF_LOGE("%{public}s: libusb_control_transfer failed, ret: %{public}d",
            __func__, ret);
        return ret;
    }
    data.assign(buffer.begin(), buffer.begin() + ret);
    HDF_LOGI("%{public}s leave", __func__);
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::DoControlTransfer(const UsbDev &dev, const UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data)
{
    HDF_LOGD("%{public}s enter", __func__);
    libusb_device_handle *devHandle = nullptr;
    int32_t ret = FindHandleByDev(dev, &devHandle);
    if (devHandle == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Find UsbHandle failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    uint8_t reqType = static_cast<uint8_t>(ctrl.requestType);
    uint8_t reqCmd = static_cast<uint8_t>(ctrl.requestCmd);
    uint16_t wValue = static_cast<uint16_t>(ctrl.value);
    uint16_t wIndex = static_cast<uint16_t>(ctrl.index);
    unsigned char *wData = (unsigned char *)data.data();
    uint16_t wLength = static_cast<uint16_t>(data.size());

    if (ctrl.requestCmd == LIBUSB_REQUEST_SYNCH_FRAME) {
        wIndex = reqType | LIBUSB_RECIPIENT_ENDPOINT;
    }

    if (reqType == LIBUSB_ENDPOINT_OUT) {
        reqType = LIBUSB_ENDPOINT_OUT | LIBUSB_REQUEST_TYPE_STANDARD | LIBUSB_RECIPIENT_DEVICE;
    } else if ((reqType & LIBUSB_RECIPIENT_ENDPOINT) == LIBUSB_RECIPIENT_ENDPOINT) {
        wIndex = reqType;
    }

    ret = libusb_control_transfer(devHandle, reqType, reqCmd, wValue, wIndex, wData, wLength, ctrl.timeout);
    if (ret < 0) {
        int32_t apiVersion = 0;
        GetApiVersion(apiVersion);
        HDF_LOGD("%{public}s: apiVersion %{public}d", __func__, apiVersion);
        if (apiVersion < API_VERSION_ID) {
            HDF_LOGD("%{public}s: The version number is smaller than 16 apiVersion %{public}d",
                __func__, apiVersion);
            ret = HDF_SUCCESS;
        }
    }

    HDF_LOGD("%{public}s leave", __func__);
    return ret;
}

int32_t LibusbAdapter::GetFileDescriptor(const UsbDev &dev, int32_t &fd)
{
    HDF_LOGI("%{public}s enter", __func__);
    uint32_t result = (static_cast<uint32_t>(dev.busNum) << DISPLACEMENT_NUMBER) |
        static_cast<uint32_t>(dev.devAddr);
    {
        std::shared_lock<std::shared_mutex> lock(g_mapMutexUsbOpenFdMap);
        auto info = g_usbOpenFdMap.find(result);
        if (info != g_usbOpenFdMap.end()) {
            fd = info->second;
            HDF_LOGI("%{public}s open is already on, fd: %{public}d", __func__, info->second);
            return HDF_SUCCESS;
        }
    }
    char path[LIBUSB_PATH_LENGTH] = {'\0'};
    int32_t ret = sprintf_s(path, sizeof(path), "%s/%03u/%03u", USB_DEV_FS_PATH, dev.busNum, dev.devAddr);
    if (ret < 0) {
        HDF_LOGE("%{public}s:sprintf_s path failed, ret:%{public}d", __func__, ret);
        return ret;
    }
    int32_t fileFd = open(path, O_RDWR);
    if (fileFd < 0) {
        HDF_LOGE("%{public}s: open device failed errno = %{public}d %{public}s", __func__, errno, strerror(errno));
        return HDF_FAILURE;
    }
    fd = fileFd;
    {
        std::unique_lock<std::shared_mutex> lock(g_mapMutexUsbOpenFdMap);
        g_usbOpenFdMap[result] = fd;
    }
    HDF_LOGI("%{public}s leave", __func__);
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::GetDeviceSpeed(const UsbDev &dev, uint8_t &speed)
{
    HDF_LOGI("%{public}s enter", __func__);
    libusb_device *device = nullptr;
    int32_t ret = GetUsbDevice(dev, &device);
    if (device == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: GetUsbDevice failed, ret=%{public}d", __func__, ret);
        return HDF_DEV_ERR_NO_DEVICE;
    }
    int deviceSpeed = libusb_get_device_speed(device);
    if (deviceSpeed < 0) {
        HDF_LOGE("%{public}s: Failed to get device speed, error: %{public}d", __func__, deviceSpeed);
        return HDF_FAILURE;
    }
    speed = static_cast<uint8_t>(deviceSpeed);
    HDF_LOGI("%{public}s Device speed retrieved successfully leave", __func__);
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::GetInterfaceActiveStatus(const UsbDev &dev, uint8_t interfaceId, bool &unactivated)
{
    HDF_LOGI("%{public}s enter", __func__);
    libusb_device *device = nullptr;
    int32_t ret = GetUsbDevice(dev, &device);
    if (device == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("GetUsbDevice failed, ret=%{public}d", ret);
        return HDF_DEV_ERR_NO_DEVICE;
    }

    libusb_device_handle *devHandle = nullptr;
    ret = FindHandleByDev(dev, &devHandle);
    if (devHandle == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: FindHandleByDev failed, ret=%{public}d", __func__, ret);
        return HDF_DEV_ERR_NO_DEVICE;
    }

    ret = libusb_kernel_driver_active(devHandle, interfaceId);
    if (ret != HDF_SUCCESS) {
        unactivated = false;
        HDF_LOGE("%{public}s unactivated:%{public}d", __func__, unactivated);
        return ret;
    }
    unactivated = true;
    HDF_LOGI("%{public}s leave", __func__);

    return ret;
}

int32_t LibusbAdapter::GetCurrentInterfaceSetting(const UsbDev &dev, uint8_t &settingIndex)
{
    HDF_LOGI("%{public}s leave", __func__);
    libusb_device *device = nullptr;
    int32_t ret = GetUsbDevice(dev, &device);
    if (device == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("GetUsbDevice failed, ret=%{public}d", ret);
        return HDF_DEV_ERR_NO_DEVICE;
    }
    libusb_device_handle *devHandle = nullptr;
    ret = FindHandleByDev(dev, &devHandle);
    if (devHandle == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s FindHandleByDev failed, ret=%{public}d", __func__, ret);
        return HDF_DEV_ERR_NO_DEVICE;
    }
    if (!CheckDeviceAndConfiguration(devHandle)) {
        HDF_LOGE("CheckDeviceAndConfiguration failed");
        return HDF_FAILURE;
    }
    std::shared_lock<std::shared_mutex> lock(g_mapMutexDeviceSettingsMap);
    if (g_deviceSettingsMap[devHandle].alternateSetting < 0) {
        HDF_LOGE("%{public}s: Current Interface Setting Invalid, settingIndex = :%{public}d",
            __func__, g_deviceSettingsMap[devHandle].alternateSetting);
        return HDF_FAILURE;
    }
    settingIndex = g_deviceSettingsMap[devHandle].alternateSetting;
    HDF_LOGI("%{public}s leave", __func__);
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::GetInterfaceIdByUsbDev(const UsbDev &dev, uint8_t &interfaceId)
{
    HDF_LOGD("%{public}s enter", __func__);
    std::shared_lock<std::shared_mutex> lock(g_mapMutexInterfaceIdMap);
    uint32_t result = (static_cast<uint32_t>(dev.busNum) << DISPLACEMENT_NUMBER) | static_cast<uint32_t>(dev.devAddr);
    auto info = g_InterfaceIdMap.find(result);
    if (info == g_InterfaceIdMap.end()) {
        HDF_LOGE("%{public}s not found", __func__);
        return HDF_FAILURE;
    }
    interfaceId = g_InterfaceIdMap[result];
    HDF_LOGD("%{public}s leave", __func__);
    return HDF_SUCCESS;
}

unsigned char *LibusbAdapter::GetMmapBufferByFd(int32_t fd, size_t len)
{
    HDF_LOGD("%{public}s enter", __func__);
    if (fd < 0 || len < 0) {
        HDF_LOGE("%{public}s Invalid parameter", __func__);
        return nullptr;
    }

    void *memBuf = nullptr;
    ftruncate(fd, len);
    memBuf = mmap(nullptr, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (memBuf == MAP_FAILED) {
        HDF_LOGE("%{public}s fd:%{public}d mmap failed, errno=%{public}d, len=%{public}zu",
            __func__, fd, errno, len);
        return nullptr;
    }
    HDF_LOGD("%{public}s leave", __func__);
    return static_cast<unsigned char *>(memBuf);
}

unsigned char *LibusbAdapter::GetMmapFdAndBuffer(uint8_t busNumber, uint8_t busAddress, int32_t *fd, size_t len)
{
    HDF_LOGD("%{public}s enter", __func__);
    if (len < 0) {
        HDF_LOGE("%{public}s Invalid parameter", __func__);
        return nullptr;
    }
    char path[LIBUSB_PATH_LENGTH] = {'\0'};
    int32_t ret = sprintf_s(path, LIBUSB_PATH_LENGTH, "%s%03u_%03u", LIBUSB_DEVICE_MMAP_PATH, busNumber, busAddress);
    if (ret < HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d path error", __func__, __LINE__);
        return nullptr;
    }
    int32_t mmapFd = open(path, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (mmapFd < 0) {
        HDF_LOGE("%{public}s: open error:%{public}s", __func__, path);
        return nullptr;
    }
    *fd = mmapFd;
    unsigned char *memBuf = GetMmapBufferByFd(mmapFd, len);
    if (memBuf == nullptr) {
        close(mmapFd);
        HDF_LOGE("%{public}s: GetMmapBufferByFd failed",  __func__);
        return nullptr;
    }
    HDF_LOGD("%{public}s Get mmap fd: %{public}d and memBuf: %{public}p success", __func__, mmapFd, memBuf);
    return memBuf;
}

int32_t LibusbAdapter::CloseMmapBuffer(void *mmapBuf, size_t length)
{
    HDF_LOGD("%{public}s enter", __func__);
    if (mmapBuf == nullptr) {
        HDF_LOGE("%{public}s mmapBuf is nullptr", __func__);
        return HDF_FAILURE;
    }

    if (munmap(mmapBuf, length) != 0) {
        HDF_LOGE("%{public}s:%{public}d munmap failed, errno=%{public}d", __func__, __LINE__, errno);
        return HDF_ERR_IO;
    }
    HDF_LOGD("%{public}s leave", __func__);
    return HDF_SUCCESS;
}
int32_t LibusbAdapter::SendPipeRequest(const UsbDev &dev, unsigned char endpointAddr, uint32_t size,
    uint32_t &transferedLength, unsigned int timeout)
{
    HDF_LOGI("%{public}s enter", __func__);
    int actlength = 0;
    libusb_device *device = nullptr;
    libusb_device_handle *devHandle = nullptr;

    int32_t ret = GetUsbDevice(dev, &device);
    if (device == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("Search device does not exist, ret=%{public}d", ret);
        return HDF_FAILURE;
    }
    ret = FindHandleByDev(dev, &devHandle);
    if (devHandle == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:FindHandleByDev failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    struct libusb_endpoint_descriptor endpoint;
    ret = GetEndpointByAddr(endpointAddr, device, &endpoint);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get endpoint failed ", __func__);
        return HDF_FAILURE;
    }

    int32_t mmapFd = HDF_FAILURE;
    unsigned char *buffer = nullptr;
    buffer = GetMmapFdAndBuffer(dev.busNum, dev.devAddr, &mmapFd, size);
    if (buffer == nullptr) {
        HDF_LOGE("%{public}s: GetMmapFdAndBuffer is error ", __func__);
        return HDF_FAILURE;
    }
    SyncTranfer syncTranfer = {size, &actlength, timeout};
    ret = DoSyncPipeTranfer(devHandle, &endpoint, buffer, syncTranfer);
    HDF_LOGD("SendPipeRequest DoSyncPipeTranfer ret :%{public}d", ret);
    if (ret < 0) {
        CloseMmapBuffer(buffer, size);
        close(mmapFd);
        HDF_LOGE("%{public}s: is error ", __func__);
        return HDF_FAILURE;
    }
    transferedLength = actlength;
    CloseMmapBuffer(buffer, size);
    close(mmapFd);
    HDF_LOGI("%{public}s leave", __func__);
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::SendPipeRequestWithAshmem(const UsbDev &dev, unsigned char endpointAddr,
    SendRequestAshmemParameter sendRequestAshmemParameter, uint32_t &transferredLength, unsigned int timeout)
{
    HDF_LOGI("%{public}s enter", __func__);
    int actlength = 0;
    libusb_device *device = nullptr;
    int32_t ret = GetUsbDevice(dev, &device);
    if (device == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("Search device does not exist, ret=%{public}d", ret);
        return HDF_FAILURE;
    }
    libusb_device_handle *devHandle = nullptr;
    ret = FindHandleByDev(dev, &devHandle);
    if (devHandle == nullptr || ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s:FindHandleByDev failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    struct libusb_endpoint_descriptor endpoint;
    ret = GetEndpointByAddr(endpointAddr, device, &endpoint);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get endpoint failed ", __func__);
        return HDF_FAILURE;
    }

    unsigned char *buffer = GetMmapBufferByFd(sendRequestAshmemParameter.ashmemFd,
        sendRequestAshmemParameter.ashmemSize);
    if (buffer == nullptr) {
        HDF_LOGE("%{public}s: GetMmapBufferByFd failed",  __func__);
        return HDF_FAILURE;
    }
    SyncTranfer syncTranfer = {sendRequestAshmemParameter.ashmemSize, &actlength, timeout};
    ret = DoSyncPipeTranfer(devHandle, &endpoint, buffer, syncTranfer);
    HDF_LOGI("SendPipeRequestWithAshmem DoSyncPipeTranfer ret :%{public}d", ret);
    if (ret < 0) {
        CloseMmapBuffer(buffer, sendRequestAshmemParameter.ashmemSize);
        HDF_LOGE("%{public}s: is error ", __func__);
        return HDF_FAILURE;
    }
    transferredLength = actlength;
    CloseMmapBuffer(buffer, sendRequestAshmemParameter.ashmemSize);
    HDF_LOGI("%{public}s leaves", __func__);
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::GetRawDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor)
{
    HDF_LOGI("%{public}s enter", __func__);
    char pathBuf[LIBUSB_PATH_LENGTH] = {'\0'};
    int32_t ret = GetUsbDevicePath(dev, pathBuf, LIBUSB_PATH_LENGTH);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get usb device path failed:%{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    int32_t fd = open(pathBuf, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        HDF_LOGE("%{public}s: failed to open file: %{public}s, errno: %{public}d",
            __func__, pathBuf, errno);
        return HDF_FAILURE;
    }
    void *descriptors = nullptr;
    size_t descriptorsLength = 0;
    if (ReadDescriptors(fd, &descriptors, descriptorsLength) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: ReadDescriptors failed", __func__);
        return HDF_FAILURE;
    }
    uint8_t *ptr = static_cast<uint8_t *>(descriptors);
    uint32_t length = descriptorsLength;
    descriptor.resize(length);
    std::copy(ptr, ptr + length, descriptor.begin());
    close(fd);
    HDF_LOGI("%{public}s leave", __func__);
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::ReadDescriptors(int32_t fd, void **descriptors, size_t &descriptorsLength)
{
    HDF_LOGD("%{public}s enter", __func__);
    size_t allocLen = 0;
    do {
        size_t oldLen = allocLen;
        allocLen += USB_MAX_DESCRIPTOR_SIZE;
        *descriptors = AdapterRealloc(*descriptors, oldLen, allocLen);
        if (*descriptors == nullptr) {
            HDF_LOGE("%{public}s:%{public}d", __func__, __LINE__);
            return HDF_ERR_MALLOC_FAIL;
        }

        uint8_t *ptr = (uint8_t *)*descriptors + oldLen;
        if (memset_s(ptr, USB_MAX_DESCRIPTOR_SIZE, 0, USB_MAX_DESCRIPTOR_SIZE) != EOK) {
            HDF_LOGE("%{public}s:%{public}d memset_s failed", __func__, __LINE__);
            return HDF_FAILURE;
        }

        int32_t len = read(fd, ptr, USB_MAX_DESCRIPTOR_SIZE);
        if (len < 0) {
            HDF_LOGE("read descriptor failed, errno=%{public}d", errno);
            return HDF_ERR_IO;
        }
        descriptorsLength += static_cast<size_t>(len);
    } while (descriptorsLength == allocLen);
    HDF_LOGD("%{public}s leave", __func__);
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::GetUsbDevicePath(const UsbDev &dev, char *pathBuf, size_t length)
{
    HDF_LOGD("%{public}s enter", __func__);
    char path[PATH_MAX] = {'\0'};
    int32_t ret = sprintf_s(path, sizeof(path), "%s/%03u/%03u", USB_DEV_FS_PATH, dev.busNum, dev.devAddr);
    if (ret < HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d path error", __func__, __LINE__);
        return HDF_FAILURE;
    }
    char resolvedPath[PATH_MAX] = {'\0'};
    char *ptr = realpath(path, resolvedPath);
    if (ptr == nullptr) {
        HDF_LOGE("%{public}s: path conversion failed, resolvedPath: %{public}s", __func__, resolvedPath);
        return HDF_FAILURE;
    }
    uint32_t len = strlen(resolvedPath);
    if (len >= PATH_MAX) {
        HDF_LOGE("%{public}s: path too long, resolvedPath: %{public}s", __func__, resolvedPath);
        return HDF_FAILURE;
    }
    if (length < (len + 1)) {
        HDF_LOGE("%{public}s: invalid length", __func__);
        return HDF_FAILURE;
    }
    ret = memcpy_s(pathBuf, length, resolvedPath, len + 1);
    if (ret != EOK) {
        HDF_LOGE("%{public}s: memcpy_s failed", __func__);
        return HDF_FAILURE;
    }
    if (strncmp(USB_DEV_FS_PATH, pathBuf, strlen(USB_DEV_FS_PATH)) != 0) {
        HDF_LOGE("%{public}s: The file path is incorrect, path: %{public}s", __func__, path);
        return HDF_FAILURE;
    }
    HDF_LOGD("%{public}s leave", __func__);

    return HDF_SUCCESS;
}

void *LibusbAdapter::AdapterRealloc(void *ptr, size_t oldSize, size_t newSize)
{
    HDF_LOGD("%{public}s enter", __func__);
    void *mem = AllocateUsbDescriptorsMemory(newSize);
    if (mem == nullptr) {
        HDF_LOGE("%{public}s:%{public}d RawUsbMemAlloc failed.", __func__, __LINE__);
        return nullptr;
    }

    if (oldSize > 0) {
        if (memmove_s(mem, newSize, ptr, oldSize) != EOK) {
            HDF_LOGE("%{public}s:%{public}d", __func__, __LINE__);
            FreeUsbDescriptorsMemory(mem);
            mem = nullptr;
            return nullptr;
        }
    }
    FreeUsbDescriptorsMemory(ptr);
    ptr = nullptr;
    HDF_LOGD("%{public}s leave", __func__);
    return mem;
}

void *LibusbAdapter::AllocateUsbDescriptorsMemory(size_t size)
{
    HDF_LOGD("%{public}s enter", __func__);
    if (size == 0) {
        HDF_LOGE("%{public}s:%{public}d size is 0", __func__, __LINE__);
        return nullptr;
    }
    if (size > MAX_TOTAL_SIZE) {
        HDF_LOGE("%{public}s:%{public}d size is exceeded the maximum MAX_TOTAL_SIZE", __func__, __LINE__);
        return nullptr;
    }
    void* buf = calloc(size, 1);
    if (buf == nullptr) {
        HDF_LOGE("%{public}s: %{public}d, AllocateUsbDescriptorsMemory failed", __func__, __LINE__);
        return nullptr;
    }
    HDF_LOGD("%{public}s leave", __func__);
    return buf;
}

void LibusbAdapter::FreeUsbDescriptorsMemory(void *mem)
{
    HDF_LOGD("%{public}s enter", __func__);
    if (mem == nullptr) {
        HDF_LOGW("%{public}s:%{public}d mem is null.", __func__, __LINE__);
        return;
    }
    free(mem);
    HDF_LOGD("%{public}s leave", __func__);
    mem = nullptr;
}

int32_t LibusbAdapter::GetConfigDescriptor(libusb_device *dev, uint8_t descId, std::vector<uint8_t> &descriptor)
{
    HDF_LOGI("%{public}s enter", __func__);
    if (dev == nullptr) {
        HDF_LOGE("%{public}s: Dev is null", __func__);
        return HDF_FAILURE;
    }
    struct libusb_config_descriptor* config = FindConfigDescriptorById(dev, descId);
    if (config == nullptr) {
        HDF_LOGE("%{public}s: Config descriptor not found for descId: %{public}d", __func__, descId);
        return HDF_FAILURE;
    }
    size_t currentOffset = descriptor.size();
    descriptor.resize(descriptor.size() + config->bLength);
    int32_t ret = memcpy_s(descriptor.data() + currentOffset, descriptor.size(), config, config->bLength);
    if (ret != EOK) {
        HDF_LOGE("%{public}s: memcpy_s failed", __func__);
        return HDF_FAILURE;
    }
    currentOffset += config->bLength;
    ProcessExtraData(descriptor, currentOffset, config->extra, config->extra_length);
    const libusb_interface *interfaces = config->interface;
    if (config->bNumInterfaces > 0 && interfaces != nullptr) {
        for (int j = 0; j < config->bNumInterfaces; ++j) {
            const libusb_interface &iface = interfaces[j];
            if (ProcessInterfaceDescriptors(&iface, descriptor, currentOffset) != HDF_SUCCESS) {
                HDF_LOGE("%{public}s: Interface descriptors find error", __func__);
                libusb_free_config_descriptor(config);
                return HDF_FAILURE;
            }
        }
    }
    libusb_free_config_descriptor(config);
    HDF_LOGI("%{public}s leave", __func__);
    return HDF_SUCCESS;
}

struct libusb_config_descriptor* LibusbAdapter::FindConfigDescriptorById(libusb_device *dev, uint8_t descId)
{
    HDF_LOGD("%{public}s enter", __func__);
    if (dev == nullptr) {
        HDF_LOGE("%{public}s: dev is null.", __func__);
        return nullptr;
    }
    struct libusb_device_descriptor deviceDescriptor;
    int ret = libusb_get_device_descriptor(dev, &deviceDescriptor);
    if (ret != LIBUSB_SUCCESS) {
        HDF_LOGE("%{public}s:libusb_get_device_descriptor failed. ret:%{public}d", __func__, ret);
        return nullptr;
    }
    uint8_t numConfig = deviceDescriptor.bNumConfigurations;
    if ((deviceDescriptor.bNumConfigurations >= 1) && (descId == 0)) {
        struct libusb_config_descriptor* configDescriptor = nullptr;
        ret = libusb_get_config_descriptor(dev, 0, &configDescriptor);
        if (ret != LIBUSB_SUCCESS) {
            HDF_LOGE("%{public}s: libusb_get_config_descriptor failed. ret:%{public}d", __func__, ret);
            return nullptr;
        }
        return configDescriptor;
    }
    for (uint8_t i = 0; i < numConfig; ++i) {
        struct libusb_config_descriptor* config = nullptr;
        ret = libusb_get_config_descriptor(dev, i, &config);
        if (ret != LIBUSB_SUCCESS) {
            HDF_LOGE("%{public}s: libusb_get_config_descriptor failed for i:%{public}d. ret:%{public}d",
                __func__, i, ret);
            return nullptr;
        }
        if (config->bConfigurationValue == descId) {
            return config;
        }
        libusb_free_config_descriptor(config);
    }
    HDF_LOGD("%{public}s: leave, No matching configuration descriptor found for descId: %{public}d", __func__, descId);
    return nullptr;
}

int32_t LibusbAdapter::ProcessInterfaceDescriptors(const libusb_interface *iface, std::vector<uint8_t> &descriptor,
    size_t &currentOffset)
{
    HDF_LOGD("%{public}s enter", __func__);
    if (iface == nullptr) {
        HDF_LOGE("%{public}s: iface is nullptr", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    for (int32_t i = 0; i < iface->num_altsetting; ++i) {
        const libusb_interface_descriptor &altSetting = iface->altsetting[i];
        descriptor.resize(descriptor.size() + altSetting.bLength);
        int32_t ret = memcpy_s(descriptor.data() + currentOffset, descriptor.size(), &altSetting, altSetting.bLength);
        if (ret != EOK) {
            HDF_LOGE("%{public}s: memcpy_s failed", __func__);
            return HDF_FAILURE;
        }
        currentOffset += altSetting.bLength;
        ProcessExtraData(descriptor, currentOffset, altSetting.extra, altSetting.extra_length);
        for (int32_t j = 0; j < altSetting.bNumEndpoints; ++j) {
            const libusb_endpoint_descriptor &endpoint = altSetting.endpoint[j];
            descriptor.resize(descriptor.size() + endpoint.bLength);
            ret = memcpy_s(descriptor.data() + currentOffset, descriptor.size(), &endpoint, endpoint.bLength);
            if (ret != EOK) {
                HDF_LOGE("%{public}s: memcpy_s failed", __func__);
                return HDF_FAILURE;
            }
            currentOffset += endpoint.bLength;
            ProcessExtraData(descriptor, currentOffset, endpoint.extra, endpoint.extra_length);
        }
    }
    HDF_LOGD("%{public}s leave", __func__);
    return HDF_SUCCESS;
}

void LibusbAdapter::ProcessExtraData(std::vector<uint8_t> &descriptor, size_t &currentOffset,
    const unsigned char *extra, int32_t extraLength)
{
    HDF_LOGD("%{public}s enter", __func__);
    if (extra != nullptr && extraLength > 0) {
        descriptor.resize(descriptor.size() + extraLength);
        int32_t ret = memcpy_s(descriptor.data() + currentOffset, descriptor.size(), extra, extraLength);
        if (ret != EOK) {
            HDF_LOGE("%{public}s: memcpy_s failed", __func__);
            return;
        }
        currentOffset += extraLength;
    }
    HDF_LOGD("%{public}s leave", __func__);
}

int32_t LibusbAdapter::GetEndpointByAddr(const unsigned char endpointAddr, libusb_device *device,
    struct libusb_endpoint_descriptor *endpoint)
{
    HDF_LOGD("%{public}s enter", __func__);
    if (device == nullptr) {
        HDF_LOGE("%{public}s: libusb_device is nullptr", __func__);
        return HDF_FAILURE;
    }
    struct libusb_config_descriptor *config = nullptr;
    libusb_get_active_config_descriptor(device, &config);
    if (config == nullptr) {
        HDF_LOGE("%{public}s: config is nullptr", __func__);
        return HDF_FAILURE;
    }
    for (int j = 0; j < config->bNumInterfaces; j++) {
        const struct libusb_interface *interface = &config->interface[j];
        const struct libusb_interface_descriptor *interfaceDesc = interface->altsetting;
        HDF_LOGD("%{public}s: interface bInterfaceNumber: %{public}d", __func__, interfaceDesc->bInterfaceNumber);
        for (int k = 0; k < interfaceDesc->bNumEndpoints; k++) {
            if (interfaceDesc->endpoint[k].bEndpointAddress != endpointAddr) {
                continue;
            }
            int32_t ret = memcpy_s(endpoint, sizeof(struct libusb_endpoint_descriptor),
                    &interfaceDesc->endpoint[k], sizeof(struct libusb_endpoint_descriptor));
            if (ret != EOK) {
                HDF_LOGE("%{public}s: memcpy_s failed", __func__);
                return HDF_FAILURE;
            }
            break;
        }
    }
    libusb_free_config_descriptor(config);
    HDF_LOGD("%{public}s leave", __func__);
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::DoSyncPipeTranfer(libusb_device_handle *devHandle, struct libusb_endpoint_descriptor *endpoint,
    unsigned char *buffer, SyncTranfer &syncTranfer)
{
    HDF_LOGD("%{public}s enter", __func__);
    int32_t ret = HDF_FAILURE;
    if ((endpoint->bmAttributes & LIBUSB_TRANSFER_TYPE_INTERRUPT) == LIBUSB_TRANSFER_TYPE_INTERRUPT) {
        HDF_LOGD("%{public}s: DoSyncPipeTranfer call libusb_interrupt_transfer", __func__);
        ret = libusb_interrupt_transfer(devHandle, endpoint->bEndpointAddress, buffer, syncTranfer.length,
            syncTranfer.transferred, syncTranfer.timeout);
    } else {
        HDF_LOGD("%{public}s: DoSyncPipeTranfer call libusb_bulk_transfer", __func__);
        ret = libusb_bulk_transfer(devHandle, endpoint->bEndpointAddress, buffer,
            syncTranfer.length, syncTranfer.transferred, syncTranfer.timeout);
    }

    if (ret < 0 && (*(syncTranfer.transferred)) <= 0) {
        HDF_LOGE("%{public}s: DoSyncPipeTranfer failed:%{public}d ret:%{public}d, error:%{public}s",
            __func__, *(syncTranfer.transferred), ret, libusb_strerror(ret));
        return HDF_FAILURE;
    }
    HDF_LOGD("%{public}s: leave DoSyncPipeTranfer success:%{public}d", __func__, *(syncTranfer.transferred));
    return ret;
}

int32_t LibusbAdapter::GetDeviceMemMapFd(const UsbDev &dev, int &fd)
{
    HDF_LOGD("%{public}s enter", __func__);
    uint32_t result = (static_cast<uint32_t>(dev.busNum) << DISPLACEMENT_NUMBER) |
        static_cast<uint32_t>(dev.devAddr);
    {
        std::shared_lock<std::shared_mutex> lock(g_mapMutexUsbOpenFdMap);
        auto info = g_usbOpenFdMap.find(result);
        if (info != g_usbOpenFdMap.end()) {
            fd = info->second;
            HDF_LOGI("%{public}s open is already on, fd: %{public}d", __func__, info->second);
            return HDF_SUCCESS;
        }
    }
    char path[LIBUSB_PATH_LENGTH] = {'\0'};
    int32_t ret = sprintf_s(path, LIBUSB_PATH_LENGTH, "%s%03u_%03u", LIBUSB_DEVICE_MMAP_PATH, dev.busNum, dev.devAddr);
    if (ret < HDF_SUCCESS) {
        HDF_LOGE("%{public}s:%{public}d path error ret=%{public}d", __func__, __LINE__, ret);
        return HDF_FAILURE;
    }

    ret = open(path, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (ret < 0) {
        HDF_LOGE("%{public}s: open error: ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    fd = ret;
    {
        std::unique_lock<std::shared_mutex> lock(g_mapMutexUsbOpenFdMap);
        g_usbOpenFdMap[result] = fd;
    }
    HDF_LOGD("%{public}s leave :%{public}d fd:%{public}d", __func__, __LINE__, fd);
    return HDF_SUCCESS;
}

bool LibusbAdapter::CheckDeviceAndConfiguration(libusb_device_handle *handle)
{
    HDF_LOGD("%{public}s: enter", __func__);
    if (handle == nullptr) {
        HDF_LOGE("Device handle is null");
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(g_mapMutexDeviceSettingsMap);
    auto it = g_deviceSettingsMap.find(handle);
    if (it == g_deviceSettingsMap.end()) {
        HDF_LOGE("No device handle found");
        return false;
    }

    int32_t currentConfig = -1;
    int32_t ret = GetCurrentConfiguration(handle, currentConfig);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: GetCurrentConfiguration failed", __func__);
        return false;
    }
    if ((currentConfig < 0) || (currentConfig != it->second.configurationIndex)) {
        HDF_LOGE("Current configuration does not match");
        return false;
    }
    HDF_LOGD("%{public}s: leave ", __func__);

    return true;
}

int32_t LibusbAdapter::GetCurrentConfiguration(libusb_device_handle *handle, int32_t &currentConfig)
{
    HDF_LOGD("%{public}s: enter", __func__);
    if (handle == nullptr) {
        HDF_LOGE("Device handle is null");
        return HDF_FAILURE;
    }
    int32_t ret = libusb_get_configuration(handle, &currentConfig);
    if (ret < 0) {
        HDF_LOGE("Failed to get current configuration, ret=%{public}d", ret);
        return HDF_FAILURE;
    }
    HDF_LOGD("%{public}s: leave ", __func__);
    return HDF_SUCCESS;
}
} // namespace V1_1
} // namespace Usb
} // namespace HDI
} // namespace OHOS
