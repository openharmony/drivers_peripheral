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

#include "usb_serial_ddk_service.h"

#include <cerrno>
#include <fcntl.h>
#include <hdf_base.h>
#include <hdf_log.h>
#include <iproxy_broker.h>
#include <cstdlib>
#include <cstring>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include "ddk_sysfs_dev_node.h"
#include "usb_serial_ddk_permission.h"
#include "usbd_wrapper.h"
#ifdef __LITEOS__
#include "usb_serial_liteos_adapter.h"
#else
#include "usb_serial_linux_adapter.h"
#endif

#define HDF_LOG_TAG usb_serial_ddk_service

namespace OHOS {
namespace HDI {
namespace Usb {
namespace UsbSerialDdk {
namespace V1_0 {

constexpr uint8_t THIRTY_TWO_BIT = 32;
constexpr size_t MAX_BUFFER_LENGTH = 4096;

inline uint32_t GetBusNum(uint64_t devId)
{
    return static_cast<uint32_t>(devId >> THIRTY_TWO_BIT);
}

inline uint32_t GetDevNum(uint64_t devId)
{
    return static_cast<uint32_t>(devId & 0xFFFFFFFF);
}

static const std::string PERMISSION_NAME = "ohos.permission.ACCESS_DDK_USB_SERIAL";
extern "C" IUsbSerialDdk *UsbSerialDdkImplGetInstance(void)
{
    std::shared_ptr<UsbSerialOsAdapter> osAdapter;
#ifdef __LITEOS__
    osAdapter = std::make_shared<LiteosUsbSerialOsAdapter>();
#else
    osAdapter = std::make_shared<LinuxUsbSerialOsAdapter>();
#endif
    return new (std::nothrow) UsbSerialDdkService(osAdapter);
}

int32_t UsbSerialDdkService::Init()
{
    HDF_LOGI("Usb serial ddk init.");
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return USB_SERIAL_DDK_NO_PERM;
    }
    return HDF_SUCCESS;
}

int32_t UsbSerialDdkService::Release()
{
    HDF_LOGI("Usb serial ddk exit.");
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return USB_SERIAL_DDK_NO_PERM;
    }
    return HDF_SUCCESS;
}

int32_t UsbSerialDdkService::Open(uint64_t deviceId, uint64_t interfaceIndex,
    OHOS::HDI::Usb::UsbSerialDdk::V1_0::UsbSerialDeviceHandle &dev)
{
    HDF_LOGI("Usb serial ddk Open.");
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return USB_SERIAL_DDK_NO_PERM;
    }

    uint16_t busNum = GetBusNum(deviceId);
    uint16_t devNum = GetDevNum(deviceId);
    SysfsDevNode devNode(busNum, devNum, interfaceIndex, "ttyUSB");
    std::string path;
    int32_t ret = devNode.FindPath(path);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("Get devNodePath ret: %{public}d\n", ret);
        return USB_SERIAL_DDK_DEVICE_NOT_FOUND;
    }
    int fd = open(path.c_str(), O_RDWR | O_NOCTTY | O_SYNC);
    if (fd < 0) {
        HDF_LOGE("error %{public}zu opening devNodePath: %{public}s\n", errno, strerror(errno));
        return USB_SERIAL_DDK_IO_ERROR;
    }
    dev.fd = fd;
    return HDF_SUCCESS;
}

int32_t UsbSerialDdkService::Close(const OHOS::HDI::Usb::UsbSerialDdk::V1_0::UsbSerialDeviceHandle &dev)
{
    HDF_LOGI("Usb serial ddk Close.");
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return USB_SERIAL_DDK_NO_PERM;
    }

    int ret = close(dev.fd);
    if (ret != 0) {
        HDF_LOGE("Failed to close device: %{public}s.\n", strerror(errno));
        if (errno == EBADF) {
            return USB_SERIAL_DDK_INVALID_OPERATION;
        }
        return USB_SERIAL_DDK_IO_ERROR;
    }
    return HDF_SUCCESS;
}

int32_t UsbSerialDdkService::Read(const OHOS::HDI::Usb::UsbSerialDdk::V1_0::UsbSerialDeviceHandle &dev,
    uint32_t bufferSize, std::vector<uint8_t> &buff)
{
    HDF_LOGI("Usb serial ddk Read.");
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return USB_SERIAL_DDK_NO_PERM;
    }

    if (bufferSize <= 0) {
        HDF_LOGE("BufferSize error.\n");
        return USB_SERIAL_DDK_INVALID_PARAMETER;
    }
    if (osAdapter_ == nullptr) {
        HDF_LOGE("%{public}s: osAdapter_ is null.", __func__);
        return USB_SERIAL_DDK_INVALID_OPERATION;
    }
    uint32_t readBuffMaxSize = bufferSize;
    if (readBuffMaxSize > MAX_BUFFER_LENGTH) {
        readBuffMaxSize = MAX_BUFFER_LENGTH;
    }
    buff.resize(readBuffMaxSize);
    ssize_t bytesRead = read(dev.fd, &buff[0], readBuffMaxSize);
    if (bytesRead < 0) {
        HDF_LOGE("bytesRead error %{public}s.\n", strerror(errno));
        if (errno == EBADF) {
            return USB_SERIAL_DDK_INVALID_OPERATION;
        } else {
            return USB_SERIAL_DDK_IO_ERROR;
        }
    } else if (bytesRead == 0) {
        bool ret = osAdapter_->IsDeviceDisconnect(dev.fd);
        if (ret) {
            return USB_SERIAL_DDK_IO_ERROR;
        }
        return HDF_SUCCESS;
    }
    buff.resize(bytesRead);
    return HDF_SUCCESS;
}

int32_t UsbSerialDdkService::Write(const OHOS::HDI::Usb::UsbSerialDdk::V1_0::UsbSerialDeviceHandle &dev,
    const std::vector<uint8_t> &buff, uint32_t &bytesWritten)
{
    HDF_LOGI("Usb serial ddk Write.");
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return USB_SERIAL_DDK_NO_PERM;
    }

    if (buff.empty()) {
        HDF_LOGW("Buffer is empty. Nothing to write.");
        bytesWritten = 0;
        return HDF_SUCCESS;
    }

    ssize_t result = write(dev.fd, buff.data(), buff.size());
    if (result < 0) {
        HDF_LOGE("Error writing to device: %{public}s", strerror(errno));
        if (errno == EBADF) {
            return USB_SERIAL_DDK_INVALID_OPERATION;
        }
        return USB_SERIAL_DDK_IO_ERROR;
    } else {
        bytesWritten = static_cast<uint32_t>(result);
        HDF_LOGI("Successfully write %{public}u bytes.", bytesWritten);
    }
    return HDF_SUCCESS;
}

int32_t UsbSerialDdkService::SetBaudRate(const OHOS::HDI::Usb::UsbSerialDdk::V1_0::UsbSerialDeviceHandle &dev,
    uint32_t baudRate)
{
    HDF_LOGI("Usb serial ddk SetBaudRate.");
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return USB_SERIAL_DDK_NO_PERM;
    }
    if (osAdapter_ == nullptr) {
        HDF_LOGE("%{public}s: osAdapter_ is null.", __func__);
        return USB_SERIAL_DDK_INVALID_OPERATION;
    }
    return osAdapter_->SetBaudRate((int32_t)dev.fd, baudRate);
}

int32_t UsbSerialDdkService::SetParams(const OHOS::HDI::Usb::UsbSerialDdk::V1_0::UsbSerialDeviceHandle &dev,
    const OHOS::HDI::Usb::UsbSerialDdk::V1_0::UsbSerialParams& params)
{
    HDF_LOGI("Usb serial ddk SetParams.");
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return USB_SERIAL_DDK_NO_PERM;
    }
    if (osAdapter_ == nullptr) {
        HDF_LOGE("%{public}s: osAdapter_ is null.", __func__);
        return USB_SERIAL_DDK_INVALID_OPERATION;
    }
    return osAdapter_->SetParams((int32_t)dev.fd, params);
}

int32_t UsbSerialDdkService::SetTimeout(const OHOS::HDI::Usb::UsbSerialDdk::V1_0::UsbSerialDeviceHandle &dev,
    int32_t timeout)
{
    HDF_LOGI("Usb serial ddk SetTimeout.");
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return USB_SERIAL_DDK_NO_PERM;
    }
    const int max_timeout_val = 25500;
    if (timeout < -1 || timeout > max_timeout_val) {
        HDF_LOGE("timeout value %d error\n", timeout);
        return USB_SERIAL_DDK_INVALID_PARAMETER;
    }
    if (osAdapter_ == nullptr) {
        HDF_LOGE("%{public}s: osAdapter_ is null.", __func__);
        return USB_SERIAL_DDK_INVALID_OPERATION;
    }
    return osAdapter_->SetTimeout((int32_t)dev.fd, timeout);
}

int32_t UsbSerialDdkService::SetFlowControl(const OHOS::HDI::Usb::UsbSerialDdk::V1_0::UsbSerialDeviceHandle &dev,
    OHOS::HDI::Usb::UsbSerialDdk::V1_0::UsbSerialFlowControl flowControl)
{
    HDF_LOGI("Usb serial ddk SetFlowControl.");
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return USB_SERIAL_DDK_NO_PERM;
    }
    if (flowControl < USB_SERIAL_NO_FLOW_CONTROL || flowControl > USB_SERIAL_HARDWARE_FLOW_CONTROL) {
        HDF_LOGE("Param flowControl err.\n");
        return USB_SERIAL_DDK_INVALID_PARAMETER;
    }
    if (osAdapter_ == nullptr) {
        HDF_LOGE("%{public}s: osAdapter_ is null.", __func__);
        return USB_SERIAL_DDK_INVALID_OPERATION;
    }
    return osAdapter_->SetFlowControl((int32_t)dev.fd, flowControl);
}

int32_t UsbSerialDdkService::Flush(const OHOS::HDI::Usb::UsbSerialDdk::V1_0::UsbSerialDeviceHandle &dev)
{
    HDF_LOGI("Usb serial ddk Flush.");
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return USB_SERIAL_DDK_NO_PERM;
    }
    if (osAdapter_ == nullptr) {
        HDF_LOGE("%{public}s: osAdapter_ is null.", __func__);
        return USB_SERIAL_DDK_INVALID_OPERATION;
    }
    return osAdapter_->Flush((int32_t)dev.fd);
}

int32_t UsbSerialDdkService::FlushInput(const OHOS::HDI::Usb::UsbSerialDdk::V1_0::UsbSerialDeviceHandle &dev)
{
    HDF_LOGI("Usb serial ddk FlushInput.");
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return USB_SERIAL_DDK_NO_PERM;
    }
    if (osAdapter_ == nullptr) {
        HDF_LOGE("%{public}s: osAdapter_ is null.", __func__);
        return USB_SERIAL_DDK_INVALID_OPERATION;
    }
    return osAdapter_->FlushInput((int32_t)dev.fd);
}

int32_t UsbSerialDdkService::FlushOutput(const OHOS::HDI::Usb::UsbSerialDdk::V1_0::UsbSerialDeviceHandle &dev)
{
    HDF_LOGI("Usb serial ddk FlushOutput.");
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return USB_SERIAL_DDK_NO_PERM;
    }
    if (osAdapter_ == nullptr) {
        HDF_LOGE("%{public}s: osAdapter_ is null.", __func__);
        return USB_SERIAL_DDK_INVALID_OPERATION;
    }
    return osAdapter_->FlushOutput((int32_t)dev.fd);
}

} // namespace V1_0
} // namespace UsbSerialDdk
} // namespace Usb
} // namespace HDI
} // namespace OHOS
