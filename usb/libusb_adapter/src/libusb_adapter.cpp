/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include "hitrace_meter.h"

namespace OHOS {
namespace HDI {
namespace Usb {
namespace V1_2 {
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
constexpr int32_t API_VERSION_ID_18 = 18;
constexpr int32_t API_VERSION_ID_20 = 20;
constexpr int32_t LIBUSB_IO_ERROR = -1;
constexpr int32_t LIBUSB_IO_ERROR_INVALID = 0;
constexpr uint32_t ACT_DEVUP = 0;
constexpr uint32_t ACT_DEVDOWN = 1;
constexpr uint8_t ENDPOINTID = 128;
constexpr const char* USB_DEV_FS_PATH = "/dev/bus/usb";
constexpr const char* LIBUSB_DEVICE_MMAP_PATH = "/data/service/el1/public/usb/";
constexpr uint32_t MIN_NUM_OF_ISO_PACKAGE = 1;
constexpr uint32_t SHIFT_32 = 32;
const uint8_t INVALID_NUM = 222;
static libusb_context *g_libusb_context = nullptr;
static std::shared_ptr<LibusbAdapter> g_LibusbAdapter = std::make_shared<LibusbAdapter>();
struct CurrentUsbSetting {
    int32_t configurationIndex = -1;
    int32_t interfaceNumber = -1;
    int32_t alternateSetting = -1;
};
struct HandleCount {
    libusb_device_handle* handle = nullptr;
    int32_t count = 0;
};
std::map<uint32_t, HandleCount> g_handleMap;
std::map<uint32_t, std::map<int32_t, std::vector<uint8_t>>> g_InterfaceIdMap;
std::map<libusb_device_handle*, CurrentUsbSetting> g_deviceSettingsMap;
std::map<uint32_t, int32_t> g_usbOpenFdMap;
std::shared_mutex g_mapMutexInterfaceIdMap;
std::shared_mutex g_mapMutexDeviceSettingsMap;
std::shared_mutex g_mapMutexContext;
std::shared_mutex g_mapMutexUsbOpenFdMap;
std::shared_mutex g_mapMutexHandleMap;
static LibusbAsyncManager g_asyncManager;
static LibusbBulkManager g_bulkManager;
#define USB_CTRL_SET_TIMEOUT 5000

static uint64_t ToDdkDeviceId(int32_t busNum, int32_t devNum)
{
    return (static_cast<uint64_t>(busNum) << SHIFT_32) + devNum;
}
} // namespace

std::list<sptr<V2_0::IUsbdSubscriber>> LibusbAdapter::subscribers_;
sptr<V1_2::LibUsbSaSubscriber> LibusbAdapter::libUsbSaSubscriber_ {nullptr};

std::shared_ptr<LibusbAdapter> LibusbAdapter::GetInstance()
{
    return g_LibusbAdapter;
}

LibusbAdapter::LibusbAdapter()
{
    HDF_LOGI("%{public}s libusbadapter constructer", __func__);
    if ((LibUSBInit() == HDF_SUCCESS) && (!eventThread.joinable())) {
        isRunning = true;
        eventThread = std::thread(&LibusbAdapter::LibusbEventHandling, this);
    }
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
    isRunning = false;
    if (eventThread.joinable()) {
        eventThread.join();
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
    ssize_t count = libusb_get_device_list(g_libusb_context, &devs);
    if (count <= 0 || devs == nullptr) {
        HDF_LOGE("%{public}s: No device", __func__);
        return HDF_DEV_ERR_NO_DEVICE;
    }
    for (ssize_t i = 0; i < count; i++) {
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
    std::shared_lock<std::shared_mutex> lock(g_mapMutexHandleMap);
    uint32_t result = (static_cast<uint32_t>(dev.busNum) << DISPLACEMENT_NUMBER) |
            static_cast<uint32_t>(dev.devAddr);
    auto it = g_handleMap.find(result);
    if (it != g_handleMap.end()) {
        *handle = it->second.handle;
        HDF_LOGI("%{public}s Search handle success leave", __func__);
        return HDF_SUCCESS;
    }
    HDF_LOGE("%{public}s Search handle failed leave", __func__);
    return HDF_DEV_ERR_NO_DEVICE;
}

void LibusbAdapter::DeleteSettingsMap(libusb_device_handle* handle)
{
    HDF_LOGD("%{public}s enter", __func__);
    {
        std::unique_lock<std::shared_mutex> lock(g_mapMutexDeviceSettingsMap);
        auto entry = g_deviceSettingsMap.find(handle);
        if (entry != g_deviceSettingsMap.end()) {
            g_deviceSettingsMap.erase(entry);
        }
    }
    HDF_LOGD("%{public}s leave", __func__);
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
    if (ret != HDF_SUCCESS || device == nullptr) {
        HDF_LOGE("%{public}s:GetUsbDevice is failed ret=%{public}d", __func__, ret);
        return HDF_DEV_ERR_NO_DEVICE;
    }

    libusb_device_handle* devHandle = nullptr;
    uint32_t result = (static_cast<uint32_t>(dev.busNum) << DISPLACEMENT_NUMBER) |
        static_cast<uint32_t>(dev.devAddr);
    ret = FindHandleByDev(dev, &devHandle);
    if (ret != HDF_SUCCESS || devHandle == nullptr) {
        ret = libusb_open(device, &devHandle);
        if (ret != HDF_SUCCESS || devHandle == nullptr) {
            HDF_LOGE("%{public}s:Opening device failed ret = %{public}d", __func__, ret);
            return HDF_FAILURE;
        }
        std::unique_lock<std::shared_mutex> lock(g_mapMutexHandleMap);
        g_handleMap[result] = {devHandle, 1};
    } else {
        std::unique_lock<std::shared_mutex> lock(g_mapMutexHandleMap);
        auto it = g_handleMap.find(result);
        if (it != g_handleMap.end() && (it->second.handle != nullptr)) {
            it->second.count++;
        }
    }
    TransferInit(dev);
    BulkTransferInit(dev);
    int32_t currentConfig = -1;
    ret = GetCurrentConfiguration(devHandle, currentConfig);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: GetCurrentConfiguration failed", __func__);
        return HDF_FAILURE;
    }
    std::unique_lock<std::shared_mutex> lock(g_mapMutexDeviceSettingsMap);
    g_deviceSettingsMap[devHandle].configurationIndex = currentConfig;
    if (!eventThread.joinable()) {
        isRunning = true;
        eventThread = std::thread(&LibusbAdapter::LibusbEventHandling, this);
    }
    HDF_LOGI("%{public}s succeeded", __func__);
    return HDF_SUCCESS;
}

void LibusbAdapter::CloseOpenedFd(const UsbDev &dev)
{
    std::lock_guard<std::mutex> lock(openedFdsMutex_);
    auto iter = openedFds_.find({dev.busNum, dev.devAddr});
    if (iter != openedFds_.end()) {
        int32_t fd = iter->second;
        int res = close(fd);
        openedFds_.erase(iter);
        HDF_LOGI("%{public}s:%{public}d close %{public}d ret = %{public}d",
            __func__, __LINE__, iter->second, res);
    } else {
        HDF_LOGI("%{public}s:%{public}d not opened", __func__, __LINE__);
    }
}

int32_t LibusbAdapter::CloseDevice(const UsbDev &dev)
{
    HDF_LOGI("%{public}s enter", __func__);
    libusb_device_handle *devHandle = nullptr;
    int32_t ret = FindHandleByDev(dev, &devHandle);
    if (ret != HDF_SUCCESS || devHandle == nullptr) {
        HDF_LOGE("%{public}s:FindHandleByDev is failed ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    uint32_t result = (static_cast<uint32_t>(dev.busNum) << DISPLACEMENT_NUMBER) |
        static_cast<uint32_t>(dev.devAddr);
    std::unique_lock<std::shared_mutex> lock(g_mapMutexHandleMap);
    auto info = g_handleMap.find(result);
    if (info == g_handleMap.end()) {
        HDF_LOGE("%{public}s:Failed to find the handle", __func__);
        return HDF_FAILURE;
    }
    info->second.count--;
    HDF_LOGI("%{public}s Number of devices that are opened=%{public}d", __func__, info->second.count);
    if (info->second.count == 0 && (info->second.handle != nullptr)) {
        CloseOpenedFd(dev);
        {
            std::unique_lock<std::shared_mutex> lock(g_mapMutexUsbOpenFdMap);
            auto it = g_usbOpenFdMap.find(result);
            if (it != g_usbOpenFdMap.end()) {
                close(it->second);
                g_usbOpenFdMap.erase(it);
            }
        }
        {
            std::unique_lock<std::shared_mutex> lock(g_mapMutexInterfaceIdMap);
            auto InterfaceIt = g_InterfaceIdMap.find(result);
            if (InterfaceIt != g_InterfaceIdMap.end()) {
                g_InterfaceIdMap.erase(result);
            }
        }
        DeleteSettingsMap(devHandle);
        libusb_close(devHandle);
        TransferRelease(dev);
        BulkTransferRelease(dev);
        g_handleMap.erase(info);
    }
    HDF_LOGI("%{public}s leave", __func__);
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::ResetDevice(const UsbDev &dev)
{
    HDF_LOGI("%{public}s enter", __func__);
    libusb_device_handle *devHandle = nullptr;
    int32_t ret = FindHandleByDev(dev, &devHandle);
    if (ret != HDF_SUCCESS || devHandle == nullptr) {
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
    if (ret != HDF_SUCCESS || device == nullptr) {
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
    if (ret != HDF_SUCCESS || device == nullptr) {
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
    libusb_device *device = nullptr;
    int32_t ret = GetUsbDevice(dev, &device);
    if (ret != HDF_SUCCESS || device == nullptr) {
        HDF_LOGE("Search device does not exist, ret=%{public}d", ret);
        return HDF_FAILURE;
    }
    libusb_device_handle *devHandle = nullptr;
    ret = FindHandleByDev(dev, &devHandle);
    if (ret != HDF_SUCCESS || devHandle == nullptr) {
        HDF_LOGE("%{public}s: FindHandleByDev is failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    char path[LIBUSB_PATH_LENGTH] = {"\0"};
    ret = sprintf_s(path, sizeof(path), "%s/%03u/%03u", USB_DEV_FS_PATH, dev.busNum, dev.devAddr);
    if (ret < 0) {
        HDF_LOGE("%{public}s: sprintf_s path failed, ret:%{public}d", __func__, ret);
        return ret;
    }
    fd = open(path, O_RDWR);
    if (fd < 0) {
        HDF_LOGE("%{public}s: open device failed errno = %{public}d %{public}s", __func__, errno, strerror(errno));
        return HDF_FAILURE;
    } else {
        std::lock_guard<std::mutex> lock(openedFdsMutex_);
        auto iter = openedFds_.find({dev.busNum, dev.devAddr});
        if (iter != openedFds_.end()) {
            int32_t oldFd = iter->second;
            if (oldFd != fd) {
                int res = close(oldFd);
                HDF_LOGI("%{public}s:%{public}d close old %{public}d ret = %{public}d",
                    __func__, __LINE__, iter->second, res);
            }
        } else {
            HDF_LOGI("%{public}s:%{public}d first time get fd", __func__, __LINE__);
        }
        openedFds_[{dev.busNum, dev.devAddr}] = fd;
        HDF_LOGI("%{public}s:%{public}d opened %{public}d", __func__, __LINE__, fd);
    }
    HDF_LOGI("%{public}s leave", __func__);
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::SetConfig(const UsbDev &dev, uint8_t configIndex)
{
    HDF_LOGI("%{public}s:enter", __func__);
    libusb_device_handle *devHandle = nullptr;
    int32_t ret = FindHandleByDev(dev, &devHandle);
    if (ret != HDF_SUCCESS || devHandle == nullptr) {
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
    if (ret != HDF_SUCCESS || device == nullptr) {
        HDF_LOGE("%{public}s: Find device failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    ret = FindHandleByDev(dev, &devHandle);
    if (ret != HDF_SUCCESS || devHandle == nullptr) {
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
    if (ret != HDF_SUCCESS || device == nullptr) {
        HDF_LOGE("%{public}s: GetUsbDevice failed, ret=%{public}d", __func__, ret);
        return HDF_DEV_ERR_NO_DEVICE;
    }
    if (interfaceId >= USB_MAX_INTERFACES) {
        HDF_LOGE("%{public}s:interfaceId larger then max num", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    libusb_device_handle *devHandle = nullptr;
    ret = FindHandleByDev(dev, &devHandle);
    if (ret != HDF_SUCCESS || devHandle == nullptr) {
        HDF_LOGE("%{public}s: FindHandleByDev failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    if (disable) {
        ret = libusb_detach_kernel_driver(devHandle, interfaceId);
    } else {
        ret = libusb_attach_kernel_driver(devHandle, interfaceId);
    }
    if (ret == LIBUSB_ERROR_NOT_FOUND || ret == LIBUSB_ERROR_BUSY) {
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
    libusb_device_handle *devHandle = nullptr;
    int32_t ret = FindHandleByDev(dev, &devHandle);
    if (ret != HDF_SUCCESS || devHandle == nullptr) {
        HDF_LOGE("%{public}s: FindHandleByDev failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    if (interfaceId >= USB_MAX_INTERFACES) {
        HDF_LOGE("%{public}s: interfaceId failed busNum:%{public}u devAddr:%{public}u interfaceId:%{public}u",
            __func__, dev.busNum, dev.devAddr, interfaceId);
        return HDF_FAILURE;
    }
    ret = RemoveInterfaceFromMap(dev, devHandle, interfaceId);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: RemoveInterfaceFromMap failed", __func__);
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
    StartTrace(HITRACE_TAG_USB, "FindHandleByDev");
    int32_t ret = FindHandleByDev(dev, &devHandle);
    FinishTrace(HITRACE_TAG_USB);
    if (ret != HDF_SUCCESS || devHandle == nullptr) {
        HDF_LOGE("%{public}s: FindHandleByDev failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    StartTrace(HITRACE_TAG_USB, "libusb_bulk_transfer");
    ret = libusb_bulk_transfer(devHandle, pipe.endpointId, tbuf, tsize, &actlength, timeout);
    FinishTrace(HITRACE_TAG_USB);
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
    StartTrace(HITRACE_TAG_USB, "GetEndpointDesc");
    int32_t ret = GetEndpointDesc(dev, pipe, &endpointDes, &devHandle);
    FinishTrace(HITRACE_TAG_USB);
    if (ret != HDF_SUCCESS || devHandle == nullptr) {
        HDF_LOGE("%{public}s:GetEndpointDesc failed ret:%{public}d", __func__, ret);
        return ret;
    }
    if (!IsInterfaceIdByUsbDev(dev, pipe.intfId)) {
        HDF_LOGE("%{public}s: IsInterfaceIdByUsbDev failed", __func__);
        return HDF_FAILURE;
    }
    std::vector<uint8_t> buffer(length);
    int32_t transferred = 0;
    StartTrace(HITRACE_TAG_USB, "libusb_bulk_transfer");
    ret = libusb_bulk_transfer(devHandle, (pipe.endpointId | LIBUSB_ENDPOINT_IN), (unsigned char *)buffer.data(),
        length, &transferred, timeout);
    FinishTrace(HITRACE_TAG_USB);
    if (ret < 0) {
        if (ret == LIBUSB_IO_ERROR) {
            HDF_LOGD("%{public}s: pipe.intfId=%{public}d", __func__, pipe.intfId);
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
    StartTrace(HITRACE_TAG_USB, "GetEndpointDesc");
    int32_t ret = GetEndpointDesc(dev, pipe, &endpointDes, &devHandle);
    FinishTrace(HITRACE_TAG_USB);
    if (ret != HDF_SUCCESS || devHandle == nullptr) {
        HDF_LOGE("%{public}s:GetEndpointDesc failed ret:%{public}d", __func__, ret);
        return ret;
    }
    if (!IsInterfaceIdByUsbDev(dev, pipe.intfId)) {
        HDF_LOGE("%{public}s: IsInterfaceIdByUsbDev failed", __func__);
        return HDF_FAILURE;
    }
    StartTrace(HITRACE_TAG_USB, "libusb_bulk_transfer");
    ret = libusb_bulk_transfer(devHandle, pipe.endpointId, (unsigned char *)data.data(), data.size(),
        &actlength, timeout);
    FinishTrace(HITRACE_TAG_USB);
    if (ret < 0) {
        if (ret == LIBUSB_IO_ERROR) {
            HDF_LOGE("%{public}s: pipe.intfId=%{public}d", __func__, pipe.intfId);
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
    StartTrace(HITRACE_TAG_USB, "FindHandleByDev");
    int32_t ret = FindHandleByDev(dev, &devHandle);
    FinishTrace(HITRACE_TAG_USB);
    if (ret != HDF_SUCCESS || devHandle == nullptr) {
        HDF_LOGE("%{public}s: FindHandleByDev failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    StartTrace(HITRACE_TAG_USB, "libusb_bulk_transfer");
    ret = libusb_bulk_transfer(devHandle, pipe.endpointId, tbuf, tsize, &actlength, timeout);
    FinishTrace(HITRACE_TAG_USB);
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
    int32_t actlength = static_cast<int32_t>(data.size());
    libusb_device_handle *devHandle = nullptr;
    StartTrace(HITRACE_TAG_USB, "FindHandleByDev");
    int32_t ret = FindHandleByDev(dev, &devHandle);
    FinishTrace(HITRACE_TAG_USB);
    if (ret != HDF_SUCCESS || devHandle == nullptr) {
        HDF_LOGE("%{public}s: FindHandleByDev failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    StartTrace(HITRACE_TAG_USB, "libusb_bulk_transfer");
    ret = libusb_bulk_transfer(devHandle, pipe.endpointId, (unsigned char *)data.data(),
        data.size(), &actlength, timeout);
    FinishTrace(HITRACE_TAG_USB);
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
    if (ret != HDF_SUCCESS || devHandle == nullptr) {
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
    if (ret != HDF_SUCCESS || devHandle == nullptr) {
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
    if (ret != HDF_SUCCESS || device == nullptr) {
        HDF_LOGE("%{public}s: LibusbFindDevice is failed, ret=%{public}d", __func__, ret);
        return HDF_DEV_ERR_NO_DEVICE;
    }
    libusb_device_handle *devHandle = nullptr;
    ret = FindHandleByDev(dev, &devHandle);
    if (ret != HDF_SUCCESS || devHandle == nullptr) {
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
    StartTrace(HITRACE_TAG_USB, "GetEndpointDesc");
    int32_t ret = GetEndpointDesc(dev, pipe, &endpointDes, &deviceHandle);
    FinishTrace(HITRACE_TAG_USB);
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
    StartTrace(HITRACE_TAG_USB, "libusb_interrupt_transfer");
    ret = libusb_interrupt_transfer(deviceHandle, pipe.endpointId, tbuf, tsize, (int *)&actlength, timeout);
    FinishTrace(HITRACE_TAG_USB);
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
    StartTrace(HITRACE_TAG_USB, "GetEndpointDesc");
    int32_t ret = GetEndpointDesc(dev, pipe, &endpointDes, &deviceHandle);
    FinishTrace(HITRACE_TAG_USB);
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
    StartTrace(HITRACE_TAG_USB, "libusb_interrupt_transfer");
    ret = libusb_interrupt_transfer(deviceHandle, pipe.endpointId, (unsigned char *)data.data(), data.size(),
        &transferred, timeout);
    FinishTrace(HITRACE_TAG_USB);
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
    if (ret != HDF_SUCCESS || device == nullptr) {
        HDF_LOGE("%{public}s: GetUsbDevice is failed, ret=%{public}d", __func__, ret);
        return HDF_DEV_ERR_NO_DEVICE;
    }
    ret = FindHandleByDev(dev, &devHandle);
    if (ret != HDF_SUCCESS || devHandle == nullptr) {
        HDF_LOGE("%{public}s: FindHandleByDev is failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    int32_t length = sizeof(data);
    uint16_t descLength = USB_MAX_DESCRIPTOR_SIZE;
    ret = libusb_get_string_descriptor(devHandle, descId, ENGLISH_US_LANGUAGE_ID, data, length);
    if (ret <= 0) {
        if (descId == INVALID_NUM) {
            return HDF_SUCCESS;
        }
        HDF_LOGE("%{public}s: libusb_get_string_descriptor is failed, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    descriptor.resize(USB_MAX_DESCRIPTOR_SIZE);
    std::copy(data, data + std::min(USB_MAX_DESCRIPTOR_SIZE, static_cast<int>(descLength)), descriptor.begin());
    HDF_LOGI("%{public}s leave", __func__);
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::ClaimInterface(const UsbDev &dev, uint8_t interfaceId, uint8_t force)
{
    HDF_LOGI("%{public}s enter", __func__);
    libusb_device_handle *devHandle = nullptr;
    int32_t ret = FindHandleByDev(dev, &devHandle);
    if (ret != HDF_SUCCESS || devHandle == nullptr) {
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
        int32_t currentConfig = -1;
        ret = GetCurrentConfiguration(devHandle, currentConfig);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: GetCurrentConfiguration failed", __func__);
            return HDF_FAILURE;
        }
        g_InterfaceIdMap[result][currentConfig].push_back(interfaceId);
    }
    HDF_LOGI("%{public}s leave", __func__);
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::ControlTransferRead(const UsbDev &dev, const UsbCtrlTransfer &ctrl, std::vector<uint8_t> &data)
{
    HITRACE_METER_NAME(HITRACE_TAG_USB, "LibusbAdapter::ControlTransferRead");
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
    HITRACE_METER_NAME(HITRACE_TAG_USB, "LibusbAdapter::ControlTransferWrite");
    HDF_LOGI("%{public}s enter", __func__);
    if ((static_cast<uint32_t>(ctrl.requestType) & USB_ENDPOINT_DIR_MASK) == USB_ENDPOINT_DIR_IN) {
        HDF_LOGE("%{public}s: this function is write, not read", __func__);
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
    HITRACE_METER_NAME(HITRACE_TAG_USB, "LibusbAdapter::ControlTransferReadwithLength");
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
    StartTrace(HITRACE_TAG_USB, "FindHandleByDev");
    int32_t ret = FindHandleByDev(dev, &devHandle);
    FinishTrace(HITRACE_TAG_USB);
    if (ret != HDF_SUCCESS || devHandle == nullptr) {
        HDF_LOGE("%{public}s: Find UsbHandle failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    uint8_t reqType = static_cast<uint8_t>(ctrl.requestType);
    uint8_t reqCmd = static_cast<uint8_t>(ctrl.requestCmd);
    uint16_t wValue = static_cast<uint16_t>(ctrl.value);
    uint16_t wIndex = static_cast<uint16_t>(ctrl.index);
    unsigned char *wData = (unsigned char *)data.data();
    uint16_t wLength = static_cast<uint16_t>(data.size());
    HDF_LOGD("%{public}s: wLength=%{public}d", __func__, wLength);
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
        if (apiVersion < API_VERSION_ID_18) {
            HDF_LOGD("%{public}s: The version number is smaller than 18 apiVersion %{public}d",
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
    libusb_device *device = nullptr;
    int32_t ret = GetUsbDevice(dev, &device);
    if (ret != HDF_SUCCESS || device == nullptr) {
        HDF_LOGE("Search device does not exist, ret=%{public}d", ret);
        return HDF_FAILURE;
    }
    libusb_device_handle *devHandle = nullptr;
    ret = FindHandleByDev(dev, &devHandle);
    if (ret != HDF_SUCCESS || devHandle == nullptr) {
        HDF_LOGE("%{public}s: FindHandleByDev is failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
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
    ret = sprintf_s(path, sizeof(path), "%s/%03u/%03u", USB_DEV_FS_PATH, dev.busNum, dev.devAddr);
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
    if (ret != HDF_SUCCESS || device == nullptr) {
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
    if (ret != HDF_SUCCESS || device == nullptr) {
        HDF_LOGE("GetUsbDevice failed, ret=%{public}d", ret);
        return HDF_DEV_ERR_NO_DEVICE;
    }

    libusb_device_handle *devHandle = nullptr;
    ret = FindHandleByDev(dev, &devHandle);
    if (ret != HDF_SUCCESS || devHandle == nullptr) {
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
    if (ret != HDF_SUCCESS || device == nullptr) {
        HDF_LOGE("GetUsbDevice failed, ret=%{public}d", ret);
        return HDF_DEV_ERR_NO_DEVICE;
    }
    libusb_device_handle *devHandle = nullptr;
    ret = FindHandleByDev(dev, &devHandle);
    if (ret != HDF_SUCCESS || devHandle == nullptr) {
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

bool LibusbAdapter::IsInterfaceIdByUsbDev(const UsbDev &dev, const uint8_t intfId)
{
    HDF_LOGD("%{public}s enter", __func__);
    libusb_device_handle *devHandle = nullptr;
    int32_t ret = FindHandleByDev(dev, &devHandle);
    if (ret != HDF_SUCCESS || devHandle == nullptr) {
        HDF_LOGE("%{public}s: FindHandleByDev failed, ret=%{public}d", __func__, ret);
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(g_mapMutexInterfaceIdMap);
    uint32_t result = (static_cast<uint32_t>(dev.busNum) << DISPLACEMENT_NUMBER) |
        static_cast<uint32_t>(dev.devAddr);
    auto deviceIt = g_InterfaceIdMap.find(result);
    if (deviceIt == g_InterfaceIdMap.end()) {
        HDF_LOGE("%{public}s device not found", __func__);
        return false;
    }
    int32_t currentConfig = -1;
    ret = GetCurrentConfiguration(devHandle, currentConfig);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: GetCurrentConfiguration failed", __func__);
        return false;
    }
    auto configIt = deviceIt->second.find(currentConfig);
    if (configIt == deviceIt->second.end()) {
        HDF_LOGE("%{public}s config not found", __func__);
        return false;
    }
    std::vector<uint8_t> interfaceIds = configIt->second;
    if (std::find(interfaceIds.begin(), interfaceIds.end(), intfId) == interfaceIds.end()) {
        HDF_LOGE("%{public}s: Interface %{public}u is not claimed", __func__, intfId);
        return false;
    }

    HDF_LOGD("%{public}s leave", __func__);
    return true;
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

unsigned char *LibusbAdapter::GetMmapFdAndBuffer(uint8_t busNumber, uint8_t busAddress, int32_t &fd, size_t len)
{
    HDF_LOGD("%{public}s enter", __func__);
    if (len < 0) {
        HDF_LOGE("%{public}s Invalid parameter", __func__);
        return nullptr;
    }
    uint32_t result = (static_cast<uint32_t>(busNumber) << DISPLACEMENT_NUMBER) |
        static_cast<uint32_t>(busAddress);
    {
        std::shared_lock<std::shared_mutex> lock(g_mapMutexUsbOpenFdMap);
        auto info = g_usbOpenFdMap.find(result);
        if (info == g_usbOpenFdMap.end()) {
            HDF_LOGE("%{public}s not open fd", __func__);
            return nullptr;
        }
        fd = info->second;
        HDF_LOGD("%{public}s open is already on, fd: %{public}d", __func__, info->second);
    }
    unsigned char *memBuf = GetMmapBufferByFd(fd, len);
    if (memBuf == nullptr) {
        HDF_LOGE("%{public}s: GetMmapBufferByFd failed",  __func__);
        return nullptr;
    }
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
    libusb_device_handle *devHandle = nullptr;
    int32_t ret = FindHandleByDev(dev, &devHandle);
    if (ret != HDF_SUCCESS || devHandle == nullptr) {
        HDF_LOGE("%{public}s:FindHandleByDev failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    int32_t mmapFd = HDF_FAILURE;
    unsigned char *buffer = nullptr;
    buffer = GetMmapFdAndBuffer(dev.busNum, dev.devAddr, mmapFd, size);
    if (buffer == nullptr) {
        HDF_LOGE("%{public}s: GetMmapFdAndBuffer is error ", __func__);
        return HDF_FAILURE;
    }
    SyncTranfer syncTranfer = {size, &actlength, timeout};
    ret = DoSyncPipeTranfer(devHandle, endpointAddr, buffer, syncTranfer);
    if (ret < 0) {
        if (ret != LIBUSB_ERROR_OVERFLOW) {
            ret = HDF_FAILURE;
        } else {
            ret = HDF_ERR_INVALID_PARAM;
        }
        int32_t apiVersion = 0;
        GetApiVersion(apiVersion);
        HDF_LOGI("%{public}s: apiVersion %{public}d", __func__, apiVersion);
        if (apiVersion < API_VERSION_ID_20) {
            HDF_LOGI("%{public}s: The version number is smaller than 20 apiVersion %{public}d",
                __func__, apiVersion);
            ret = HDF_SUCCESS;
        }
    }
    transferedLength = static_cast<uint32_t>(actlength);
    CloseMmapBuffer(buffer, size);
    HDF_LOGI("%{public}s leave", __func__);
    return ret;
}

int32_t LibusbAdapter::SendPipeRequestWithAshmem(const UsbDev &dev, unsigned char endpointAddr,
    SendRequestAshmemParameter sendRequestAshmemParameter, uint32_t &transferredLength, unsigned int timeout)
{
    HDF_LOGI("%{public}s enter", __func__);
    int actlength = 0;
    libusb_device_handle *devHandle = nullptr;
    int32_t ret = FindHandleByDev(dev, &devHandle);
    if (ret != HDF_SUCCESS || devHandle == nullptr) {
        HDF_LOGE("%{public}s:FindHandleByDev failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    unsigned char *buffer = GetMmapBufferByFd(sendRequestAshmemParameter.ashmemFd,
        sendRequestAshmemParameter.ashmemSize);
    if (buffer == nullptr) {
        HDF_LOGE("%{public}s: GetMmapBufferByFd failed",  __func__);
        return HDF_FAILURE;
    }
    SyncTranfer syncTranfer = {sendRequestAshmemParameter.ashmemSize, &actlength, timeout};
    ret = DoSyncPipeTranfer(devHandle, endpointAddr, buffer, syncTranfer);
    HDF_LOGI("SendPipeRequestWithAshmem DoSyncPipeTranfer ret :%{public}d", ret);
    if (ret < 0) {
        if (ret != LIBUSB_ERROR_OVERFLOW) {
            ret = HDF_FAILURE;
        } else {
            ret = HDF_ERR_INVALID_PARAM;
        }
        int32_t apiVersion = 0;
        GetApiVersion(apiVersion);
        HDF_LOGI("%{public}s: apiVersion %{public}d", __func__, apiVersion);
        if (apiVersion < API_VERSION_ID_20) {
            HDF_LOGI("%{public}s: The version number is smaller than 20 apiVersion %{public}d",
                __func__, apiVersion);
            ret = HDF_SUCCESS;
        }
    }
    transferredLength = static_cast<uint32_t>(actlength);
    CloseMmapBuffer(buffer, sendRequestAshmemParameter.ashmemSize);
    close(sendRequestAshmemParameter.ashmemFd);
    return ret;
}

int32_t LibusbAdapter::GetRawDescriptor(const UsbDev &dev, std::vector<uint8_t> &descriptor)
{
    HDF_LOGI("%{public}s enter", __func__);
    libusb_device *device = nullptr;
    int32_t ret = GetUsbDevice(dev, &device);
    if (ret != HDF_SUCCESS || device == nullptr) {
        HDF_LOGE("Search device does not exist, ret=%{public}d", ret);
        return HDF_FAILURE;
    }
    libusb_device_handle *devHandle = nullptr;
    ret = FindHandleByDev(dev, &devHandle);
    if (ret != HDF_SUCCESS || devHandle == nullptr) {
        HDF_LOGE("%{public}s: FindHandleByDev is failed, ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    char pathBuf[LIBUSB_PATH_LENGTH] = {'\0'};
    ret = GetUsbDevicePath(dev, pathBuf, LIBUSB_PATH_LENGTH);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get usb device path failed:%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    char resolvedPath[PATH_MAX] = {'\0'};
    char *ptrBuf = realpath(pathBuf, resolvedPath);
    if (ptrBuf == nullptr) {
        HDF_LOGE("%{public}s: path conversion failed, ptr: %{public}s", __func__, ptrBuf);
        return HDF_FAILURE;
    }
    int32_t fd = open(ptrBuf, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        HDF_LOGE("%{public}s: failed to open file: %{public}s, errno: %{public}d",
            __func__, ptrBuf, errno);
        return HDF_FAILURE;
    }
    void *descriptors = nullptr;
    size_t descriptorsLength = 0;
    if (ReadDescriptors(fd, &descriptors, descriptorsLength) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: ReadDescriptors failed", __func__);
        close(fd);
        return HDF_FAILURE;
    }
    uint8_t *ptr = static_cast<uint8_t *>(descriptors);
    uint32_t length = descriptorsLength;
    descriptor.resize(length);
    std::copy(ptr, ptr + length, descriptor.begin());
    FreeUsbDescriptorsMemory(descriptors);
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
            FreeUsbDescriptorsMemory(*descriptors);
            return HDF_FAILURE;
        }

        int32_t len = read(fd, ptr, USB_MAX_DESCRIPTOR_SIZE);
        if (len < 0) {
            HDF_LOGE("read descriptor failed, errno=%{public}d", errno);
            FreeUsbDescriptorsMemory(*descriptors);
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
        libusb_free_config_descriptor(config);
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
        currentOffset += static_cast<size_t>(extraLength);
    }
    HDF_LOGD("%{public}s leave", __func__);
}

int32_t LibusbAdapter::DoSyncPipeTranfer(libusb_device_handle *devHandle, unsigned char endpoint,
    unsigned char *buffer, SyncTranfer &syncTranfer)
{
    HDF_LOGD("%{public}s enter", __func__);
    int32_t ret = HDF_FAILURE;
    uint32_t endpointAttributes = endpoint & LIBUSB_TRANSFER_TYPE_INTERRUPT;
    if (endpointAttributes == LIBUSB_TRANSFER_TYPE_INTERRUPT) {
        HDF_LOGD("%{public}s: DoSyncPipeTranfer call libusb_interrupt_transfer", __func__);
        ret = libusb_interrupt_transfer(devHandle, endpoint, buffer, syncTranfer.length,
            syncTranfer.transferred, syncTranfer.timeout);
    } else {
        HDF_LOGD("%{public}s: DoSyncPipeTranfer call libusb_bulk_transfer", __func__);
        ret = libusb_bulk_transfer(devHandle, endpoint, buffer,
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

int32_t LibusbAdapter::RemoveInterfaceFromMap(const UsbDev &dev, libusb_device_handle *devHandle, uint8_t interfaceId)
{
    HDF_LOGD("%{public}s enter", __func__);
    std::shared_lock<std::shared_mutex> lock(g_mapMutexInterfaceIdMap);
    uint32_t result = (static_cast<uint32_t>(dev.busNum) << DISPLACEMENT_NUMBER) |
        static_cast<uint32_t>(dev.devAddr);
    auto deviceIt = g_InterfaceIdMap.find(result);
    if (deviceIt != g_InterfaceIdMap.end()) {
        int32_t currentConfig = -1;
        int32_t ret = GetCurrentConfiguration(devHandle, currentConfig);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: GetCurrentConfiguration failed", __func__);
            return HDF_FAILURE;
        }
        auto configIt = deviceIt->second.find(currentConfig);
        if (configIt != deviceIt->second.end()) {
            auto& interfaceIds = configIt->second;
            interfaceIds.erase(std::remove(interfaceIds.begin(), interfaceIds.end(),
                interfaceId), interfaceIds.end());
            HDF_LOGD("%{public}s erase interfaceId=%{public}u from, configIndex=%{public}u", __func__,
                interfaceId, currentConfig);
            if (interfaceIds.empty()) {
                deviceIt->second.erase(configIt);
            }
            if (deviceIt->second.empty()) {
                g_InterfaceIdMap.erase(deviceIt);
            }
        }
    }
    HDF_LOGD("%{public}s leave", __func__);
    return HDF_SUCCESS;
}

/* Async Transfer */

int32_t LibusbAdapter::AsyncSubmitTransfer(const UsbDev &dev, const V1_2::USBTransferInfo &info,
    const sptr<V1_2::IUsbdTransferCallback> &cb, const sptr<Ashmem> &ashmem)
{
    HDF_LOGI("%{public}s: params endpoint: 0x%{public}x, type: %{public}d, length: %{public}d, timeout: %{public}d",
        __func__, info.endpoint, info.type, info.length, info.timeOut);
    // 1.get device handle
    libusb_device_handle *devHandle = nullptr;
    StartTrace(HITRACE_TAG_USB, "FindHandleByDev");
    int32_t ret = FindHandleByDev(dev, &devHandle);
    FinishTrace(HITRACE_TAG_USB);
    if (ret < 0 || devHandle == nullptr) {
        HDF_LOGE("%{public}s: find libusb device handle failed, ret = %{public}d", __func__, ret);
        return LIBUSB_ERROR_NO_DEVICE;
    }
    // 2.get buffer
    unsigned char *buffer = AllocAsyncBuffer(info, ashmem);
    if (buffer == nullptr) {
        HDF_LOGE("%{public}s: alloc async buffer failed", __func__);
        return LIBUSB_ERROR_NO_MEM;
    }
    // 3.create LibusbAsyncTransfer
    LibusbAsyncTransfer *asyncTransfer = CreateAsyncTransfer(dev, info, ashmem, cb);
    if (asyncTransfer == nullptr) {
        HDF_LOGE("%{public}s: create libusb async transfer failed", __func__);
        OsalMemFree(buffer);
        buffer = nullptr;
        return LIBUSB_ERROR_NO_MEM;
    }
    // 4.fill and submit libusb transfer
    StartTrace(HITRACE_TAG_USB, "FillAndSubmitTransfer");
    ret = FillAndSubmitTransfer(asyncTransfer, devHandle, buffer, info);
    FinishTrace(HITRACE_TAG_USB);
    if (ret < 0) {
        HDF_LOGE("%{public}s: libusb submit transfer failed, ret: %{public}d", __func__, ret);
        OsalMemFree(buffer);
        buffer = nullptr;
        delete asyncTransfer;
        asyncTransfer = nullptr;
        return ret;
    }
    // 5.save transfer
    AddTransferToList(asyncTransfer);
    HDF_LOGI("%{public}s: handle async transfer success", __func__);
    return LIBUSB_SUCCESS;
}

int32_t LibusbAdapter::AsyncCancelTransfer(const UsbDev &dev, const int32_t endpoint)
{
    HITRACE_METER_NAME(HITRACE_TAG_USB, "LibusbAdapter::AsyncCancelTransfer");
    HDF_LOGI("%{public}s: cancel transfer start", __func__);
    int ret = HDF_FAILURE;
    std::lock_guard<std::mutex> managerLock(g_asyncManager.transferVecLock);
    auto asyncWrapper = GetAsyncWrapper(dev);
    if (!asyncWrapper) {
        HDF_LOGE("%{public}s: get async wrapper failed", __func__);
        return LIBUSB_ERROR_NO_DEVICE;
    }
    std::lock_guard guard(asyncWrapper->transferLock);
    if (asyncWrapper->transferList.empty()) {
        HDF_LOGE("%{public}s: transfer list is empty", __func__);
        return LIBUSB_ERROR_NOT_FOUND;
    }
    for (auto it = asyncWrapper->transferList.begin(); it != asyncWrapper->transferList.end();) {
        auto asyncTransfer = *it;
        if (asyncTransfer->transferRef == nullptr || asyncTransfer->transferRef->endpoint != endpoint) {
            ++it;
            continue;
        }
        ret = libusb_cancel_transfer(asyncTransfer->transferRef);
        if (ret == LIBUSB_ERROR_NOT_FOUND) {
            HDF_LOGE("%{public}s: the transfer is already complete, or already cancelled", __func__);
            return ret;
        }
        if (ret != LIBUSB_SUCCESS) {
            HDF_LOGE("%{public}s: libusb cancel transfer failed, error: %{public}d", __func__, ret);
            return ret;
        }
        it = asyncWrapper->transferList.erase(it);
        break;
    }
    HDF_LOGI("%{public}s: cancel transfer end", __func__);
    return ret;
}

void LibusbAdapter::LibusbEventHandling()
{
    HDF_LOGI("%{public}s: libusb event handling thread started.", __func__);
    while (isRunning) {
        if (g_libusb_context != nullptr) {
            int rc = libusb_handle_events_completed(g_libusb_context, nullptr);
            if (rc != LIBUSB_SUCCESS) {
                HDF_LOGE("%{public}s: libusb handle events failed: %{public}d", __func__, rc);
            }
        }
    }
}

int32_t LibusbAdapter::FillAndSubmitTransfer(LibusbAsyncTransfer *asyncTransfer, libusb_device_handle *devHandle,
    unsigned char *buffer, const V1_2::USBTransferInfo &info)
{
    HDF_LOGI("%{public}s: endpoint: 0x%{public}x, timeout: %{public}d, numIsoPackets: %{public}d",
        __func__, info.endpoint, info.timeOut, info.numIsoPackets);
    if (info.type == LIBUSB_TRANSFER_TYPE_ISOCHRONOUS) {
        libusb_fill_iso_transfer(asyncTransfer->transferRef, devHandle, info.endpoint, buffer, info.length,
            info.numIsoPackets, HandleAsyncResult, asyncTransfer, info.timeOut);
        if (info.numIsoPackets > 0) {
            uint32_t packetLength = info.length / info.numIsoPackets;
            uint32_t maxIsoPacketLength =
                static_cast<uint32_t>(libusb_get_max_iso_packet_size(libusb_get_device(devHandle), info.endpoint));
            packetLength = packetLength >= maxIsoPacketLength ? maxIsoPacketLength : packetLength;
            HDF_LOGI("%{public}s: iso pkg len: %{public}d, max iso pkg len: %{public}d",
                __func__, packetLength, maxIsoPacketLength);
            libusb_set_iso_packet_lengths(asyncTransfer->transferRef, packetLength);
        }
    } else {
        libusb_fill_bulk_transfer(asyncTransfer->transferRef, devHandle, info.endpoint, buffer, info.length,
            HandleAsyncResult, asyncTransfer, info.timeOut);
        asyncTransfer->transferRef->type = info.type;
    }
    HDF_LOGI("%{public}s: libusb submit transfer", __func__);
    int ret = libusb_submit_transfer(asyncTransfer->transferRef);
    if (ret < 0) {
        HDF_LOGE("%{public}s: libusb submit transfer failed, ret: %{public}d", __func__, ret);
        return ret;
    }
    return LIBUSB_SUCCESS;
}

void LIBUSB_CALL LibusbAdapter::HandleAsyncResult(struct libusb_transfer *transfer)
{
    HDF_LOGI("%{public}s: start handle async transfer result", __func__);
    if (transfer == nullptr || transfer->user_data == nullptr) {
        HDF_LOGE("%{public}s: async transfer or user_data is null", __func__);
        return;
    }
    HDF_LOGI("%{public}s: transfer status: %{public}d, actual length: %{public}d", __func__,
        transfer->status, transfer->actual_length);
    LibusbAsyncTransfer *asyncTransfer = reinterpret_cast<LibusbAsyncTransfer *>(transfer->user_data);
    // handle failed transfer
    if (transfer->status == LIBUSB_TRANSFER_CANCELLED) {
        HDF_LOGE("%{public}s: async transfer has been canceled", __func__);
        HandleAsyncFailure(transfer);
        return;
    }
    if (transfer->status != LIBUSB_TRANSFER_COMPLETED && transfer->actual_length <= 0) {
        HDF_LOGE("%{public}s: libusb async transfer failed", __func__);
        FeedbackToBase(transfer);
        HandleAsyncFailure(transfer);
        return;
    }
    // write data to ashmem when direction is in
    if ((transfer->endpoint & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_IN) {
        HDF_LOGI("%{public}s: write data to ashmem", __func__);
        if (transfer->type == LIBUSB_TRANSFER_TYPE_ISOCHRONOUS) {
            transfer->actual_length = transfer->length;
        }
        int32_t ret = WriteAshmem(asyncTransfer->ashmemRef, transfer->actual_length, transfer->buffer);
        if (ret != HDF_SUCCESS) {
            HandleAsyncFailure(transfer);
            return;
        }
    }
    // call V1_2::IUsbdTransferCallback
    FeedbackToBase(transfer);
    // close resource
    if (transfer->buffer != nullptr) {
        OsalMemFree(transfer->buffer);
        transfer->buffer = nullptr;
    }
    DeleteTransferFromList(asyncTransfer);
    HDF_LOGI("%{public}s: handle async transfer result success", __func__);
}

void LibusbAdapter::FeedbackToBase(struct libusb_transfer *transfer)
{
    HDF_LOGI("%{public}s: call feedback callback, actual length: %{public}d", __func__, transfer->actual_length);
    LibusbAsyncTransfer *asyncTransfer = reinterpret_cast<LibusbAsyncTransfer *>(transfer->user_data);
    sptr<V1_2::IUsbdTransferCallback> callback = asyncTransfer->cbRef;
    std::vector<V1_2::UsbIsoPacketDescriptor> isoPkgDescVec;

    if (transfer->type == LIBUSB_TRANSFER_TYPE_ISOCHRONOUS) {
        ParseIsoPacketDesc(transfer, isoPkgDescVec);
    }

    int32_t ret = 0;
    if ((transfer->endpoint & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_IN) {
        ret = callback->OnTransferReadCallback(transfer->status, transfer->actual_length, isoPkgDescVec,
            asyncTransfer->userData);
    } else {
        ret = callback->OnTransferWriteCallback(transfer->status, transfer->actual_length, isoPkgDescVec,
            asyncTransfer->userData);
    }
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: feedback callback failed", __func__);
        return;
    }
    HDF_LOGI("%{public}s: call feedback callback success", __func__);
}

void LibusbAdapter::ParseIsoPacketDesc(libusb_transfer *transfer,
    std::vector<V1_2::UsbIsoPacketDescriptor> &isoPkgDescs)
{
    HDF_LOGI("%{public}s: start parse iso package desc", __func__);
    for (int i = 0; i < transfer->num_iso_packets; ++i) {
        struct libusb_iso_packet_descriptor *pack = &transfer->iso_packet_desc[i];
        HDF_LOGI("%{public}s: iso pack %{public}d, status: %{public}d, length:%{public}u, actual length:%{public}u",
            __func__, i, pack->status, pack->length, pack->actual_length);
        
        V1_2::UsbIsoPacketDescriptor desc;
        desc.isoLength = static_cast<int32_t>(pack->length);
        desc.isoActualLength = static_cast<int32_t>(pack->actual_length);
        desc.isoStatus = pack->status;
        isoPkgDescs.push_back(desc);
    }
}

LibusbAsyncTransfer *LibusbAdapter::CreateAsyncTransfer(const UsbDev &dev, const V1_2::USBTransferInfo &info,
    const sptr<Ashmem> &ashmem, const sptr<V1_2::IUsbdTransferCallback> &cb)
{
    uint32_t pkgNum = 0;
    if (info.type == LIBUSB_TRANSFER_TYPE_ISOCHRONOUS) {
        pkgNum = info.numIsoPackets > 0 ? info.numIsoPackets : MIN_NUM_OF_ISO_PACKAGE;
    }
    LibusbAsyncTransfer *asyncTransfer = new(std::nothrow) LibusbAsyncTransfer(pkgNum);
    if (asyncTransfer == nullptr) {
        return nullptr;
    }
    asyncTransfer->ashmemRef = ashmem;
    asyncTransfer->cbRef = cb;
    asyncTransfer->busNum = dev.busNum;
    asyncTransfer->devAddr = dev.devAddr;
    asyncTransfer->userData = info.userData;
    return asyncTransfer;
}

void LibusbAdapter::HandleAsyncFailure(struct libusb_transfer *transfer)
{
    if (transfer == nullptr) {
        return;
    }
    if (transfer->buffer != nullptr) {
        OsalMemFree(transfer->buffer);
        transfer->buffer = nullptr;
    }
    libusb_cancel_transfer(transfer);
    if (transfer->user_data != nullptr) {
        LibusbAsyncTransfer *asyncTransfer = reinterpret_cast<LibusbAsyncTransfer *>(transfer->user_data);
        DeleteTransferFromList(asyncTransfer);
    }
}

void LibusbAdapter::DeleteTransferFromList(LibusbAsyncTransfer *asyncTransfer)
{
    if (asyncTransfer == nullptr) {
        return;
    }
    HDF_LOGI("%{public}s: enter delete transfer from list, bus num: %{public}d, dev addr: %{public}d",
        __func__, asyncTransfer->busNum, asyncTransfer->devAddr);

    std::lock_guard<std::mutex> managerLock(g_asyncManager.transferVecLock);
    LibusbAsyncWrapper *asyncWrapper = GetAsyncWrapper({asyncTransfer->busNum, asyncTransfer->devAddr});
    if (asyncWrapper == nullptr) {
        HDF_LOGE("%{public}s: get async wrapper failed", __func__);
        return;
    }

    std::lock_guard<std::mutex> lock(asyncWrapper->transferLock);
    if (asyncWrapper->transferList.size() <= 0) {
        HDF_LOGI("%{public}s: transfer list is empty", __func__);
        return;
    }
    if (asyncTransfer != nullptr) {
        asyncWrapper->transferList.remove(asyncTransfer);
        delete asyncTransfer;
        asyncTransfer = nullptr;
    }
    HDF_LOGI("%{public}s: delete transfer from list end", __func__);
}

LibusbAsyncWrapper *LibusbAdapter::GetAsyncWrapper(const UsbDev &dev)
{
    LibusbAsyncWrapper *asyncWrapper = nullptr;

    for (size_t i = 0; i < g_asyncManager.transferVec.size(); ++i) {
        if (g_asyncManager.transferVec[i].first.busNum == dev.busNum
                && g_asyncManager.transferVec[i].first.devAddr == dev.devAddr) {
            asyncWrapper = g_asyncManager.transferVec[i].second;
        }
    }

    return asyncWrapper;
}

uint8_t *LibusbAdapter::AllocAsyncBuffer(const V1_2::USBTransferInfo &info, const sptr<Ashmem> &ashmem)
{
    if (info.length <= 0) {
        HDF_LOGE("%{public}s: invalid buffer length", __func__);
        return nullptr;
    }
    HDF_LOGI("%{public}s: malloc buffer", __func__);
    uint8_t *buffer = static_cast<uint8_t *>(OsalMemCalloc(info.length));
    if (buffer == nullptr) {
        HDF_LOGE("%{public}s: malloc buffer failed", __func__);
        return nullptr;
    }
    uint32_t endpointId = static_cast<uint32_t>(info.endpoint) & LIBUSB_ENDPOINT_DIR_MASK;
    if (endpointId == LIBUSB_ENDPOINT_OUT) {
        HDF_LOGI("%{public}s: read from ashmem", __func__);
        int32_t ret = ReadAshmem(ashmem, info.length, buffer);
        if (ret != HDF_SUCCESS) {
            OsalMemFree(buffer);
            return nullptr;
        }
    }
    return buffer;
}

void LibusbAdapter::AddTransferToList(LibusbAsyncTransfer *asyncTransfer)
{
    HDF_LOGI("%{public}s: start add transfer to list", __func__);
    if (asyncTransfer == nullptr || asyncTransfer->transferRef == nullptr) {
        HDF_LOGW("%{public}s: async transfer or libusb transfer is nullptr", __func__);
        return;
    }
    std::lock_guard<std::mutex> managerLock(g_asyncManager.transferVecLock);
    LibusbAsyncWrapper *asyncWrapper = GetAsyncWrapper({asyncTransfer->busNum, asyncTransfer->devAddr});
    if (asyncWrapper == nullptr) {
        HDF_LOGE("%{public}s: get async wrapper failed", __func__);
        return;
    }

    HDF_LOGI("%{public}s: push async transfer", __func__);
    std::lock_guard<std::mutex> lock(asyncWrapper->transferLock);
    asyncWrapper->transferList.push_back(asyncTransfer);
}

void LibusbAdapter::TransferInit(const UsbDev &dev)
{
    // init LibusbAsyncManager
    HDF_LOGI("%{public}s: start init libusb async manager", __func__);
    LibusbAsyncWrapper *asyncWrapper = new(std::nothrow) LibusbAsyncWrapper();
    if (asyncWrapper == nullptr) {
        HDF_LOGE("%{public}s:create libusb async manager failed", __func__);
        return;
    }
    std::pair<UsbDev, LibusbAsyncWrapper*> asyncWrapperPair = std::make_pair(dev, asyncWrapper);
    std::lock_guard<std::mutex> lock(g_asyncManager.transferVecLock);
    g_asyncManager.transferVec.push_back(asyncWrapperPair);
}

void LibusbAdapter::TransferRelease(const UsbDev &dev)
{
    // release LibusbAsyncManager
    std::lock_guard<std::mutex> lock(g_asyncManager.transferVecLock);
    DeleteAsyncDevRequest(dev);
}

void LibusbAdapter::DeleteAsyncDevRequest(const UsbDev &dev)
{
    int32_t deleteId = -1;
    int32_t number = static_cast<int32_t>(g_asyncManager.transferVec.size());
    for (int32_t i = 0; i < number; ++i) {
        if (g_asyncManager.transferVec[i].first.busNum == dev.busNum
                && g_asyncManager.transferVec[i].first.devAddr == dev.devAddr) {
            HDF_LOGI("%{public}s: delete async dev request device found", __func__);
            if (g_asyncManager.transferVec[i].second != nullptr) {
                ClearAsyncTranfer(g_asyncManager.transferVec[i].second);
            }
            deleteId = i;
            break;
        }
    }
    if (deleteId >= 0 && deleteId < static_cast<int32_t>(g_asyncManager.transferVec.size())) {
        g_asyncManager.transferVec.erase(g_asyncManager.transferVec.begin() + deleteId);
    }
}

void LibusbAdapter::ClearAsyncTranfer(LibusbAsyncWrapper *asyncWrapper)
{
    HDF_LOGI("%{public}s: clear async tranfer enter", __func__);
    if (asyncWrapper == nullptr) {
        return;
    }
    if (asyncWrapper->transferList.size() <= 0) {
        HDF_LOGI("%{public}s: clear async tranfer transfer list is empty", __func__);
        return;
    }

    for (auto &asyncTransfer : asyncWrapper->transferList) {
        if (asyncTransfer == nullptr) {
            continue;
        }
        if (asyncTransfer->transferRef != nullptr) {
            HDF_LOGI("%{public}s: clear async tranfer libusb free transfer", __func__);
            libusb_free_transfer(asyncTransfer->transferRef);
            asyncTransfer->transferRef = nullptr;
        }
        delete asyncTransfer;
        asyncTransfer = nullptr;
    }
    delete asyncWrapper;
    asyncWrapper = nullptr;
}

int32_t LibusbAdapter::ReadAshmem(const sptr<Ashmem> &ashmem, int32_t length, uint8_t *buffer)
{
    if (!ashmem->MapReadAndWriteAshmem()) {
        HDF_LOGE("%{public}s: map read and write ashmem failed", __func__);
        return HDF_FAILURE;
    }
    const void *content = ashmem->ReadFromAshmem(length, 0);
    if (content == nullptr) {
        HDF_LOGE("%{public}s: read from ashmem failed", __func__);
        ashmem->UnmapAshmem();
        return HDF_FAILURE;
    }
    if (memcpy_s(buffer, length, content, length) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s failed", __func__);
        ashmem->UnmapAshmem();
        return HDF_FAILURE;
    }
    ashmem->UnmapAshmem();
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::WriteAshmem(const sptr<Ashmem> &ashmem, int32_t length, uint8_t *buffer)
{
    if (!ashmem->MapReadAndWriteAshmem()) {
        HDF_LOGE("%{public}s: map read and write ashmem failed", __func__);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s: libusb async read actual_length: %{public}d", __func__, length);
    bool ret = ashmem->WriteToAshmem(buffer, length, 0);
    if (!ret) {
        HDF_LOGE("%{public}s: write to ashmem failed", __func__);
        ashmem->UnmapAshmem();
        return HDF_FAILURE;
    }
    ashmem->UnmapAshmem();
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::GetDevices(std::vector<struct DeviceInfo> &devices)
{
    HDF_LOGD("%{public}s: enter", __func__);
    if (g_libusb_context == nullptr) {
        HDF_LOGE("%{public}s: g_libusb_context is nullptr", __func__);
        return HDF_FAILURE;
    }
    libusb_device **devs = nullptr;
    ssize_t count = libusb_get_device_list(g_libusb_context, &devs);
    HDF_LOGI("%{public}s: libusb_get_device_list return count: %{public}zu", __func__, count);
    for (ssize_t i = 0; i < count; ++i) {
        libusb_device *device = devs[i];
        struct libusb_device_descriptor desc;
        if (libusb_get_device_descriptor(device, &desc) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: libusb_get_device_descriptor failed", __func__);
            continue;
        }
        uint64_t deviceId = ToDdkDeviceId(libusb_get_bus_number(device), libusb_get_device_address(device));
        devices.emplace_back(DeviceInfo{deviceId, desc.idVendor});
    }
    libusb_free_device_list(devs, 1);
    return HDF_SUCCESS;
}

uint8_t *LibusbAdapter::AllocBulkBuffer(const UsbPipe &pipe, const int32_t &length, const sptr<Ashmem> &ashmem)
{
    HDF_LOGI("%{public}s: enter", __func__);
    if (length <= 0) {
        HDF_LOGE("%{public}s: invalid buffer length", __func__);
        return nullptr;
    }

    uint8_t *buffer = static_cast<uint8_t *>(OsalMemCalloc(length));
    if (buffer == nullptr) {
        HDF_LOGE("%{public}s: malloc buffer failed", __func__);
        return nullptr;
    }
    if ((pipe.endpointId & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_OUT) {
        HDF_LOGI("%{public}s: read from ashmem", __func__);
        int32_t ret = ReadAshmem(ashmem, length, buffer);
        if (ret != HDF_SUCCESS) {
            OsalMemFree(buffer);
            return nullptr;
        }
    }
    return buffer;
}

void LibusbAdapter::DeleteBulkTransferFromList(LibusbBulkTransfer *bulkTransfer)
{
    HDF_LOGI("%{public}s: enter", __func__);
    if (bulkTransfer == nullptr) {
        HDF_LOGE("%{public}s: bulkTransfer is nullptr", __func__);
        return;
    }
    HDF_LOGI("%{public}s: enter delete transfer, bus num: %{public}d, dev addr: %{public}d", __func__,
        bulkTransfer->busNum, bulkTransfer->devAddr);

    LibusbBulkWrapper *bulkWrapper = GetBulkWrapper({bulkTransfer->busNum, bulkTransfer->devAddr});
    if (bulkWrapper == nullptr) {
        HDF_LOGE("%{public}s: bulkWrapper is nullptr", __func__);
        return;
    }

    std::lock_guard<std::mutex> lock(bulkWrapper->bulkTransferLock);
    if (bulkWrapper->bulkTransferList.size() <= 0) {
        HDF_LOGE("%{public}s: transfer list is empty", __func__);
        return;
    }
    if (bulkTransfer != nullptr) {
        bulkWrapper->bulkTransferList.remove(bulkTransfer);
    }
    HDF_LOGI("%{public}s: delete transfer from list end", __func__);
}

LibusbBulkWrapper *LibusbAdapter::GetBulkWrapper(const UsbDev &dev)
{
    HDF_LOGI("%{public}s: enter", __func__);
    std::lock_guard<std::mutex> lock(g_bulkManager.bulkTransferVecLock);
    LibusbBulkWrapper *bulkWrapper = nullptr;

    for (size_t i = 0; i < g_bulkManager.bulktransferVec.size(); ++i) {
        if (g_bulkManager.bulktransferVec[i].first.busNum == dev.busNum
                && g_bulkManager.bulktransferVec[i].first.devAddr == dev.devAddr) {
            bulkWrapper = g_bulkManager.bulktransferVec[i].second;
        }
    }

    return bulkWrapper;
}

void LibusbAdapter::HandleBulkFail(struct libusb_transfer *transfer)
{
    HDF_LOGI("%{public}s: enter", __func__);
    if (transfer == nullptr) {
        HDF_LOGE("%{public}s: transfer is nullptr", __func__);
        return;
    }
    if (transfer->buffer != nullptr) {
        OsalMemFree(transfer->buffer);
        transfer->buffer = nullptr;
    }
    libusb_cancel_transfer(transfer);
    if (transfer->user_data != nullptr) {
        LibusbBulkTransfer *bulkTransfer = reinterpret_cast<LibusbBulkTransfer *>(transfer->user_data);
        DeleteBulkTransferFromList(bulkTransfer);
        if (bulkTransfer != nullptr) {
            delete bulkTransfer;
            bulkTransfer = nullptr;
        }
    }
}

void LibusbAdapter::BulkFeedbackToBase(struct libusb_transfer *transfer)
{
    HDF_LOGI("%{public}s: enter, actual_length=%{public}d", __func__, transfer->actual_length);
    LibusbBulkTransfer *bulkTransfer = reinterpret_cast<LibusbBulkTransfer *>(transfer->user_data);
    sptr<V2_0::IUsbdBulkCallback> callback = bulkTransfer->bulkCbRef;

    int32_t ret = 0;
    if ((transfer->endpoint & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_IN) {
        ret = callback->OnBulkReadCallback(transfer->status, transfer->actual_length);
    } else {
        ret = callback->OnBulkWriteCallback(transfer->status, transfer->actual_length);
    }
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: feedback callback failed", __func__);
        return;
    }
    bulkTransfer->isTransferring = false;
    HDF_LOGI("%{public}s: call feedback callback success", __func__);
}

void LIBUSB_CALL LibusbAdapter::HandleBulkResult(struct libusb_transfer *transfer)
{
    HDF_LOGI("%{public}s: enter", __func__);
    if (transfer == nullptr || transfer->user_data == nullptr) {
        HDF_LOGE("%{public}s: bulk transfer or user_data is null", __func__);
        return;
    }
    HDF_LOGI("%{public}s: transfer status: %{public}d, actual length: %{public}d", __func__,
        transfer->status, transfer->actual_length);
    LibusbBulkTransfer *bulkTransfer = reinterpret_cast<LibusbBulkTransfer *>(transfer->user_data);

    if (transfer->status == LIBUSB_TRANSFER_CANCELLED) {
        HDF_LOGE("%{public}s: bulk transfer has been canceled", __func__);
        return;
    }
    if (transfer->status != LIBUSB_TRANSFER_COMPLETED && transfer->actual_length <= 0) {
        HDF_LOGE("%{public}s: libusb bulk transfer failed", __func__);
        BulkFeedbackToBase(transfer);
        HandleBulkFail(transfer);
        return;
    }

    if ((transfer->endpoint & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_IN) {
        HDF_LOGI("%{public}s: write data to ashmem", __func__);
        int32_t ret = WriteAshmem(bulkTransfer->buikAshmemRef, transfer->actual_length, transfer->buffer);
        if (ret != HDF_SUCCESS) {
            HandleBulkFail(transfer);
            return;
        }
    }

    BulkFeedbackToBase(transfer);
    HDF_LOGI("%{public}s: handle bulk transfer success", __func__);
}

int32_t LibusbAdapter::BulkRead(const UsbDev &dev, const UsbPipe &pipe, const sptr<Ashmem> &ashmem)
{
    HDF_LOGI("%{public}s: enter", __func__);
    if (pipe.endpointId < ENDPOINTID) {
        HDF_LOGE("%{public}s: endpointId is not expect", __func__);
        return HDF_FAILURE;
    }

    libusb_device_handle *devHandle = nullptr;
    int32_t ret = FindHandleByDev(dev, &devHandle);
    if (devHandle == nullptr) {
        HDF_LOGE("%{public}s: find libusb device handle failed", __func__);
        return HDF_FAILURE;
    }

    LibusbBulkTransfer *bulkTransfer = FindBulkTransfer(dev, pipe, ashmem);
    if (bulkTransfer == nullptr) {
        HDF_LOGE("%{public}s: create libusb bulk transfer failed", __func__);
        return HDF_FAILURE;
    }
    int32_t length = libusb_get_max_packet_size(libusb_get_device(devHandle), pipe.endpointId);
    unsigned char *buffer = AllocBulkBuffer(pipe, length, ashmem);
    if (buffer == nullptr) {
        HDF_LOGE("%{public}s: alloc bulk buffer failed", __func__);
        return HDF_FAILURE;
    }

    libusb_fill_bulk_transfer(bulkTransfer->bulkTransferRef, devHandle, pipe.endpointId, buffer, length,
        HandleBulkResult, bulkTransfer, USB_CTRL_SET_TIMEOUT);
    HDF_LOGI("%{public}s: libusb submit transfer", __func__);
    ret = libusb_submit_transfer(bulkTransfer->bulkTransferRef);
    if (ret < 0) {
        HDF_LOGE("%{public}s: libusb submit transfer failed, ret: %{public}d", __func__, ret);
        return ret;
    }
    bulkTransfer->isTransferring = true;
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::BulkWrite(const UsbDev &dev, const UsbPipe &pipe, const sptr<Ashmem> &ashmem)
{
    HDF_LOGI("%{public}s: enter", __func__);
    if (pipe.endpointId >= ENDPOINTID) {
        HDF_LOGE("%{public}s: endpointId is not expect", __func__);
        return HDF_FAILURE;
    }
    libusb_device_handle *devHandle = nullptr;
    int32_t ret = FindHandleByDev(dev, &devHandle);
    if (devHandle == nullptr) {
        HDF_LOGE("%{public}s: find handle failed", __func__);
        return HDF_FAILURE;
    }

    LibusbBulkTransfer *bulkTransfer = FindBulkTransfer(dev, pipe, ashmem);
    if (bulkTransfer == nullptr) {
        HDF_LOGE("%{public}s: create libusb bulk transfer failed", __func__);
        return HDF_FAILURE;
    }
    int32_t length = libusb_get_max_packet_size(libusb_get_device(devHandle), pipe.endpointId);
    unsigned char *buffer = AllocBulkBuffer(pipe, length, ashmem);
    if (buffer == nullptr) {
        HDF_LOGE("%{public}s: alloc bulk buffer failed", __func__);
        return HDF_FAILURE;
    }

    libusb_fill_bulk_transfer(bulkTransfer->bulkTransferRef, devHandle, pipe.endpointId, buffer, length,
        HandleBulkResult, bulkTransfer, USB_CTRL_SET_TIMEOUT);
    HDF_LOGI("%{public}s: libusb submit transfer", __func__);
    ret = libusb_submit_transfer(bulkTransfer->bulkTransferRef);
    if (ret < 0) {
        HDF_LOGE("%{public}s: libusb submit transfer failed, ret: %{public}d", __func__, ret);
        return ret;
    }
    bulkTransfer->isTransferring = true;
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::BulkCancel(const UsbDev &dev, const UsbPipe &pipe)
{
    HDF_LOGI("%{public}s: enter", __func__);
    std::lock_guard<std::mutex> lock(g_bulkManager.bulkTransferVecLock);
    auto it = std::find_if(
        g_bulkManager.bulktransferVec.begin(), g_bulkManager.bulktransferVec.end(),
        [&dev](const auto& pair) {
            return pair.first.busNum == dev.busNum && pair.first.devAddr == dev.devAddr;
    });
    if (it == g_bulkManager.bulktransferVec.end()) {
        HDF_LOGE("%{public}s: wrapper is nullptr, dev is not exist", __func__);
        return HDF_FAILURE;
    }
    LibusbBulkWrapper* wrapper = it->second;
    if (wrapper == nullptr) {
        HDF_LOGE("%{public}s: wrapper is nullptr", __func__);
        return HDF_FAILURE;
    }
    std::lock_guard<std::mutex> listLock(wrapper->bulkTransferLock);
    auto transferIt = std::find_if(
        wrapper->bulkTransferList.begin(), wrapper->bulkTransferList.end(),
        [&pipe](const auto& pair) {
            return pair->bulkTransferRef->endpoint == pipe.endpointId;
    });
    if (transferIt == wrapper->bulkTransferList.end()) {
        HDF_LOGE("%{public}s: transferCancle is nullptr", __func__);
        return HDF_FAILURE;
    }
    LibusbBulkTransfer* transferCancle = *transferIt;
    if (transferCancle == nullptr) {
        HDF_LOGE("%{public}s: transferCancle is nullptr", __func__);
        return HDF_FAILURE;
    }
    int32_t ret = libusb_cancel_transfer(transferCancle->bulkTransferRef);
    if (ret != LIBUSB_SUCCESS && ret != LIBUSB_ERROR_NOT_FOUND) {
        HDF_LOGE("%{public}s: libusb cancel transfer fail ret=%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    if (transferCancle->bulkTransferRef->buffer != nullptr) {
        OsalMemFree(transferCancle->bulkTransferRef->buffer);
        transferCancle->bulkTransferRef->buffer = nullptr;
    }
    wrapper->bulkTransferList.remove(transferCancle);
    delete transferCancle;
    transferCancle = nullptr;
    return HDF_SUCCESS;
}

void LibusbAdapter::BulkTransferInit(const UsbDev &dev)
{
    HDF_LOGI("%{public}s: enter", __func__);
    LibusbBulkWrapper *bulkWrapper = new(std::nothrow) LibusbBulkWrapper();
    if (bulkWrapper == nullptr) {
        HDF_LOGE("%{public}s:bulkWrapper is nullptr", __func__);
        return;
    }
    std::pair<UsbDev, LibusbBulkWrapper*> bulkWrapperPair = std::make_pair(dev, bulkWrapper);
    std::lock_guard<std::mutex> lock(g_bulkManager.bulkTransferVecLock);
    g_bulkManager.bulktransferVec.push_back(bulkWrapperPair);
}

void LibusbAdapter::BulkTransferRelease(const UsbDev &dev)
{
    HDF_LOGI("%{public}s: enter", __func__);
    std::lock_guard<std::mutex> lock(g_bulkManager.bulkTransferVecLock);
    DeleteBulkDevRequest(dev);
}

void LibusbAdapter::DeleteBulkDevRequest(const UsbDev &dev)
{
    HDF_LOGI("%{public}s: enter", __func__);
    int32_t deleteId = -1;
    int32_t number = static_cast<int32_t>(g_bulkManager.bulktransferVec.size());
    for (int32_t i = 0; i < number; ++i) {
        if (g_bulkManager.bulktransferVec[i].first.busNum == dev.busNum
                && g_bulkManager.bulktransferVec[i].first.devAddr == dev.devAddr) {
            HDF_LOGI("%{public}s: delete bulk dev request device found", __func__);
            if (g_bulkManager.bulktransferVec[i].second != nullptr) {
                ClearBulkTranfer(g_bulkManager.bulktransferVec[i].second);
            }
            deleteId = i;
            break;
        }
    }
    if (deleteId >= 0) {
        g_bulkManager.bulktransferVec.erase(g_bulkManager.bulktransferVec.begin() + deleteId);
    }
}

void LibusbAdapter::ClearBulkTranfer(LibusbBulkWrapper *bulkWrapper)
{
    HDF_LOGI("%{public}s: enter", __func__);
    if (bulkWrapper == nullptr) {
        HDF_LOGE("%{public}s: bulkWrapper is nullptr", __func__);
        return;
    }
    if (bulkWrapper->bulkTransferList.size() <= 0) {
        HDF_LOGI("%{public}s: clear bulk tranfer transfer list is empty", __func__);
        return;
    }

    for (auto &bulkTransfer : bulkWrapper->bulkTransferList) {
        if (bulkTransfer == nullptr) {
            continue;
        }
        if (bulkTransfer->bulkTransferRef != nullptr) {
            HDF_LOGI("%{public}s: clear bulk tranfer libusb free transfer", __func__);
            libusb_free_transfer(bulkTransfer->bulkTransferRef);
            bulkTransfer->bulkTransferRef = nullptr;
        }
        delete bulkTransfer;
        bulkTransfer = nullptr;
    }
    delete bulkWrapper;
    bulkWrapper = nullptr;
}

LibusbBulkTransfer *LibusbAdapter::FindBulkTransfer(const UsbDev &dev, const UsbPipe &pipe,
    const sptr<Ashmem> &ashmem)
{
    HDF_LOGI("%{public}s: enter", __func__);
    std::lock_guard<std::mutex> lock(g_bulkManager.bulkTransferVecLock);
    auto it = std::find_if(
        g_bulkManager.bulktransferVec.begin(), g_bulkManager.bulktransferVec.end(),
        [&dev](const auto& pair) {
            return pair.first.busNum == dev.busNum && pair.first.devAddr == dev.devAddr;
    });
    if (it == g_bulkManager.bulktransferVec.end()) {
        HDF_LOGE("%{public}s: wrapper is nullptr", __func__);
        return nullptr;
    }
    LibusbBulkWrapper* wrapper = it->second;
    if (wrapper == nullptr) {
        HDF_LOGE("%{public}s: wrapper is nullptr", __func__);
        return nullptr;
    }
    std::lock_guard<std::mutex> listLock(wrapper->bulkTransferLock);

    auto bulkPair = std::find_if(
        wrapper->bulkTransferList.begin(), wrapper->bulkTransferList.end(),
        [&pipe](const auto& pair) {
            return pair->bulkTransferRef->endpoint == pipe.endpointId;
    });
    if (bulkPair != wrapper->bulkTransferList.end()) {
        LibusbBulkTransfer* transferCancle = *bulkPair;
        transferCancle->buikAshmemRef = ashmem;
        return transferCancle;
    }
    HDF_LOGI("%{public}s:not find BulkTransfer", __func__);
    return nullptr;
}

int32_t LibusbAdapter::RegBulkCallback(const UsbDev &dev, const UsbPipe &pipe, const sptr<V2_0::IUsbdBulkCallback> &cb)
{
    HDF_LOGI("%{public}s: enter", __func__);
    if (cb == nullptr) {
        HDF_LOGE("%{public}s: cb is nullptr", __func__);
        return HDF_FAILURE;
    }
    LibusbBulkTransfer *bulkTransfer = new(std::nothrow) LibusbBulkTransfer();
    if (bulkTransfer == nullptr) {
        HDF_LOGE("%{public}s: bulkTransfer is nullptr", __func__);
        return HDF_FAILURE;
    }
    std::lock_guard<std::mutex> lock(g_bulkManager.bulkTransferVecLock);
    auto it = std::find_if(
        g_bulkManager.bulktransferVec.begin(), g_bulkManager.bulktransferVec.end(),
        [&dev](const auto& pair) {
            return pair.first.busNum == dev.busNum && pair.first.devAddr == dev.devAddr;
    });
    if (it == g_bulkManager.bulktransferVec.end()) {
        HDF_LOGE("%{public}s: Wrapper not found, device does not exist", __func__);
        return HDF_FAILURE;
    }
    LibusbBulkWrapper* wrapper = it->second;
    if (wrapper == nullptr) {
        HDF_LOGE("%{public}s: Wrapper is nullptr", __func__);
        return HDF_FAILURE;
    }
    bulkTransfer->busNum = dev.busNum;
    bulkTransfer->devAddr = dev.devAddr;
    bulkTransfer->bulkCbRef = cb;
    bulkTransfer->bulkTransferRef->endpoint = pipe.endpointId;
    std::lock_guard<std::mutex> listLock(wrapper->bulkTransferLock);
    wrapper->bulkTransferList.push_back(bulkTransfer);
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::UnRegBulkCallback(const UsbDev &dev, const UsbPipe &pipe)
{
    HDF_LOGI("%{public}s: enter", __func__);
    std::lock_guard<std::mutex> lock(g_bulkManager.bulkTransferVecLock);
    auto it = std::find_if(
        g_bulkManager.bulktransferVec.begin(), g_bulkManager.bulktransferVec.end(),
        [&dev](const auto& pair) {
            return pair.first.busNum == dev.busNum && pair.first.devAddr == dev.devAddr;
    });
    if (it == g_bulkManager.bulktransferVec.end()) {
        HDF_LOGE("%{public}s: wrapper is nullptr, dev is not exist", __func__);
        return HDF_FAILURE;
    }
    LibusbBulkWrapper* wrapper = it->second;
    if (wrapper == nullptr) {
        HDF_LOGE("%{public}s: Wrapper is nullptr", __func__);
        return HDF_FAILURE;
    }
    std::lock_guard<std::mutex> listLock(wrapper->bulkTransferLock);
    auto transferIt = std::find_if(
        wrapper->bulkTransferList.begin(), wrapper->bulkTransferList.end(),
        [&pipe](const auto& pair) {
            return pair->bulkTransferRef->endpoint == pipe.endpointId;
    });
    if (transferIt == wrapper->bulkTransferList.end()) {
        HDF_LOGE("%{public}s: transferCancle is nullptr", __func__);
        return HDF_FAILURE;
    }
    LibusbBulkTransfer* transferCancle = *transferIt;
    if (transferCancle == nullptr) {
        HDF_LOGE("%{public}s:transferCancle is nullptr", __func__);
        return HDF_FAILURE;
    }
    if (transferCancle->isTransferring) {
        HDF_LOGE("%{public}s:Data is being transmitted and cancellation of regist is not allowed", __func__);
        return HDF_FAILURE;
    }
    transferCancle->bulkCbRef = nullptr;
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::RemoveSubscriber(sptr<V2_0::IUsbdSubscriber> subscriber)
{
    HDF_LOGI("%{public}s: enter RemoveSubscriber.", __func__);
    auto tempSize = subscribers_.size();
    subscribers_.remove(subscriber);
    if (tempSize == subscribers_.size()) {
        HDF_LOGE("%{public}s: subsciber not exist.", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

void LibusbAdapter::GetCurrentDeviceList(libusb_context *ctx, sptr<V2_0::IUsbdSubscriber> subscriber)
{
    int r;
    ssize_t cnt = 0;
    libusb_device **devs;
    cnt = libusb_get_device_list(ctx, &devs);
    if (cnt < 0) {
        HDF_LOGW("%{public}s ctx not init", __func__);
        return;
    }
    int busNum = 0;
    int devAddr = 0;
    for (ssize_t i = 0; i < cnt; i++) {
        libusb_device *dev = devs[i];
        struct libusb_device_descriptor desc;
        r = libusb_get_device_descriptor(dev, &desc);
        if (r < 0) {
            continue;
        }
        busNum = libusb_get_bus_number(dev);
        devAddr = libusb_get_device_address(dev);
        if (busNum == 0 || devAddr == 0) {
            HDF_LOGW("%{public}s Invalid parameter", __func__);
            continue;
        }
        if (desc.bDeviceClass == LIBUSB_CLASS_HUB) {
            continue;
        }
        HDF_LOGI("%{public}s:busNum: %{public}d, devAddr: %{public}d", __func__, busNum, devAddr);
        V2_0::USBDeviceInfo info = {ACT_DEVUP, busNum, devAddr};
        subscriber->DeviceEvent(info);
    }
    libusb_free_device_list(devs, 1);
}

int32_t LibusbAdapter::SetSubscriber(sptr<V2_0::IUsbdSubscriber> subscriber)
{
    HDF_LOGI("%{public}s: enter", __func__);
    if (subscriber == nullptr || g_libusb_context == nullptr) {
        HDF_LOGE("%{public}s subsriber or g_libusb_context is nullptr", __func__);
        return HDF_FAILURE;
    }
    if (subscribers_.size() == 0) {
        HDF_LOGI("%{public}s: rigister callback.", __func__);
        int rc = libusb_hotplug_register_callback(g_libusb_context,
            static_cast<libusb_hotplug_event>(LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED | LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT),
            LIBUSB_HOTPLUG_NO_FLAGS,
            LIBUSB_HOTPLUG_MATCH_ANY,
            LIBUSB_HOTPLUG_MATCH_ANY,
            LIBUSB_HOTPLUG_MATCH_ANY,
            HotplugCallback,
            this,
            &hotplug_handle_);
        if (rc != LIBUSB_SUCCESS) {
            HDF_LOGE("%{public}s: Failed to register hotplug callback: %{public}d", __func__, rc);
            libusb_exit(g_libusb_context);
            g_libusb_context = nullptr;
            return HDF_FAILURE;
        }
    }
    GetCurrentDeviceList(g_libusb_context, subscriber);
    subscribers_.push_back(subscriber);
    HDF_LOGI("%{public}s: hotpluginit success", __func__);
    return HDF_SUCCESS;
}

void NotifyAllSubscriber(std::list<sptr<V2_0::IUsbdSubscriber>> subscribers, V2_0::USBDeviceInfo info)
{
    HDF_LOGI("%{public}s: enter", __func__);
    for (auto subscriber: subscribers) {
        subscriber->DeviceEvent(info);
    }
}

void RunHotplugTask(std::list<sptr<V2_0::IUsbdSubscriber>> subscribers, V2_0::USBDeviceInfo info)
{
    HDF_LOGI("%{public}s: enter.", __func__);
    std::thread hotplugThread([subscribers, info]() {
        NotifyAllSubscriber(subscribers, info);
    });
    hotplugThread.detach();
}

int32_t LibusbAdapter::HotplugCallback(libusb_context* ctx, libusb_device* device,
    libusb_hotplug_event event, void* user_data)
{
    HDF_LOGI("%{public}s: enter.", __func__);
    struct libusb_device_descriptor devDesc;
    libusb_get_device_descriptor(device, &devDesc);
    if (devDesc.bDeviceClass == LIBUSB_CLASS_HUB) {
        HDF_LOGW("%{public}s: do not handle hub class device", __func__);
        return HDF_SUCCESS;
    }
    if (event == LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED) {
        HDF_LOGD("%{public}s: event=%{public}d arrival device", __func__, event);
        V2_0::USBDeviceInfo info = {ACT_DEVUP, libusb_get_bus_number(device),
            libusb_get_device_address(device)};
        RunHotplugTask(LibusbAdapter::subscribers_, info);
    } else if (event == LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT) {
        HDF_LOGD("%{public}s: event=%{public}d remove device", __func__, event);
        V2_0::USBDeviceInfo info = {ACT_DEVDOWN, libusb_get_bus_number(device),
            libusb_get_device_address(device)};
        RunHotplugTask(LibusbAdapter::subscribers_, info);
    }
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::SetLoadUsbSaSubscriber(sptr<V1_2::LibUsbSaSubscriber> libUsbSaSubscriber)
{
    HDF_LOGI("%{public}s: enter", __func__);
    if (libUsbSaSubscriber == nullptr || g_libusb_context == nullptr) {
        HDF_LOGE("%{public}s subsriber or g_libusb_context is nullptr", __func__);
        return HDF_FAILURE;
    }
    int rc = libusb_hotplug_register_callback(g_libusb_context,
        static_cast<libusb_hotplug_event>(LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED | LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT),
        LIBUSB_HOTPLUG_NO_FLAGS,
        LIBUSB_HOTPLUG_MATCH_ANY,
        LIBUSB_HOTPLUG_MATCH_ANY,
        LIBUSB_HOTPLUG_MATCH_ANY,
        LoadUsbSaCallback,
        this,
        &hotplug_handle_);
    if (rc != LIBUSB_SUCCESS) {
        HDF_LOGE("%{public}s: Failed to register hotplug callback: %{public}d", __func__, rc);
        libusb_exit(g_libusb_context);
        g_libusb_context = nullptr;
        return HDF_FAILURE;
    }

    GetCurrentDevList(g_libusb_context, libUsbSaSubscriber);
    libUsbSaSubscriber_ = libUsbSaSubscriber;
    return HDF_SUCCESS;
}

int32_t LibusbAdapter::LoadUsbSaCallback(libusb_context* ctx, libusb_device* device,
    libusb_hotplug_event event, void* user_data)
{
    HDF_LOGI("%{public}s: enter.", __func__);
    if (event == LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED) {
        if (libUsbSaSubscriber_ == nullptr) {
            HDF_LOGE("%{public}s: libUsbSaSubscriber is nullptr", __func__);
            return HDF_FAILURE;
        }
        libUsbSaSubscriber_->LoadUsbSa(LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED);
    }
    return HDF_SUCCESS;
}

void LibusbAdapter::GetCurrentDevList(libusb_context *ctx, sptr<V1_2::LibUsbSaSubscriber> libUsbSaSubscriber)
{
    HDF_LOGI("%{public}s: enter.", __func__);
    ssize_t cnt = 0;
    libusb_device **devs;
    cnt = libusb_get_device_list(ctx, &devs);
    if (cnt < 0) {
        HDF_LOGW("%{public}s ctx not init", __func__);
        return;
    }
    int busNum = 0;
    int devAddr = 0;
    for (ssize_t i = 0; i < cnt; i++) {
        libusb_device *dev = devs[i];
        struct libusb_device_descriptor desc;
        int ret = libusb_get_device_descriptor(dev, &desc);
        if (ret < 0) {
            continue;
        }
        busNum = libusb_get_bus_number(dev);
        devAddr = libusb_get_device_address(dev);
        if (busNum == 0 || devAddr == 0) {
            HDF_LOGW("%{public}s Invalid parameter", __func__);
            continue;
        }
        if (desc.bDeviceClass == LIBUSB_CLASS_HUB) {
            continue;
        }
        HDF_LOGI("%{public}s:busNum: %{public}d, devAddr: %{public}d", __func__, busNum, devAddr);
        libUsbSaSubscriber->LoadUsbSa(LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED);
    }
    libusb_free_device_list(devs, 1);
}
} // namespace V1_2
} // namespace Usb
} // namespace HDI
} // namespace OHOS
