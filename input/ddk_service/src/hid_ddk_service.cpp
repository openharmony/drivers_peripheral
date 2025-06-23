/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "hid_ddk_service.h"
#include <hdf_base.h>
#include "emit_event_manager.h"
#include "hid_ddk_permission.h"
#include "input_uhdf_log.h"
#include <unistd.h>
#include <fcntl.h>
#include <iostream>
#include <sys/ioctl.h>
#include <linux/hiddev.h>
#include <linux/hidraw.h>
#include <poll.h>
#include <memory.h>
#include <securec.h>
#include "ddk_sysfs_dev_node.h"
#ifdef __LITEOS__
#include "hid_liteos_adapter.h"
#else
#include "hid_linux_adapter.h"
#endif

#define HDF_LOG_TAG hid_ddk_service

namespace OHOS {
namespace HDI {
namespace Input {
namespace Ddk {
namespace V1_1 {
const uint8_t THIRTY_TWO_BIT = 32;
const uint32_t MAX_REPORT_BUFFER_SIZE = 16 * 1024 - 1;

inline uint32_t GetBusNum(uint64_t devHandle)
{
    return static_cast<uint32_t>(devHandle >> THIRTY_TWO_BIT);
}

inline uint32_t GetDevNum(uint64_t devHandle)
{
    return static_cast<uint32_t>(devHandle & 0xFFFFFFFF);
}

static const std::string PERMISSION_NAME = "ohos.permission.ACCESS_DDK_HID";

extern "C" IHidDdk *HidDdkImplGetInstance(void)
{
    std::shared_ptr<HidOsAdapter> osAdapter;
#ifdef __LITEOS__
    osAdapter = std::make_shared<LiteosHidOsAdapter>();
#else
    osAdapter = std::make_shared<LinuxHidOsAdapter>();
#endif
    return new (std::nothrow) HidDdkService(osAdapter);
}

int32_t HidDdkService::CreateDevice(const Hid_Device &hidDevice,
    const Hid_EventProperties &hidEventProperties, uint32_t &deviceId)
{
    HDF_LOGI("%{public}s create device enter", __func__);
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HDF_ERR_NOPERM;
    }

    int32_t ret = OHOS::ExternalDeviceManager::EmitEventManager::GetInstance()
        .CreateDevice(hidDevice, hidEventProperties);
    if (ret < 0) {
        HDF_LOGE("%{public}s create device faild, ret=%{public}d", __func__, ret);
        return ret;
    }

    deviceId = static_cast<uint32_t>(ret);
    return Hid_DdkErrCode::HID_DDK_SUCCESS;
}

int32_t HidDdkService::EmitEvent(uint32_t deviceId, const std::vector<Hid_EmitItem> &items)
{
    HDF_LOGI("%{public}s emit event enter, the id of device = %{public}d", __func__, deviceId);
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HDF_ERR_NOPERM;
    }

    return OHOS::ExternalDeviceManager::EmitEventManager::GetInstance().EmitEvent(deviceId, items);
}

int32_t HidDdkService::DestroyDevice(uint32_t deviceId)
{
    HDF_LOGI("%{public}s destroy device enter, the id of device = %{public}d", __func__, deviceId);
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HDF_ERR_NOPERM;
    }
    
    return OHOS::ExternalDeviceManager::EmitEventManager::GetInstance().DestroyDevice(deviceId);
}

int32_t HidDdkService::Init()
{
    HDF_LOGD("%{public}s init enter", __func__);
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HID_DDK_NO_PERM;
    }

    return HID_DDK_SUCCESS;
}

int32_t HidDdkService::Release()
{
    HDF_LOGD("%{public}s release enter", __func__);
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HID_DDK_NO_PERM;
    }

    return HID_DDK_SUCCESS;
}

int32_t HidDdkService::Open(uint64_t deviceId, uint8_t interfaceIndex, HidDeviceHandle& dev)
{
    HDF_LOGD("%{public}s open enter", __func__);
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HID_DDK_NO_PERM;
    }

    uint32_t busNum = GetBusNum(deviceId);
    uint32_t devNum = GetDevNum(deviceId);
    SysfsDevNode devNode(busNum, devNum, interfaceIndex, "hidraw");
    std::string path;
    int32_t ret = devNode.FindPath(path);
    if (ret != HID_DDK_SUCCESS) {
        HDF_LOGE("%{public}s device not found, path=%{public}s", __func__, path.c_str());
        return HID_DDK_DEVICE_NOT_FOUND;
    }

    char realpathStr[PATH_MAX] = {'\0'};
    if (realpath(path.c_str(), realpathStr) == nullptr) {
        HDF_LOGE("%{public}s:realpath failed.ret = %{public}s", __func__, strerror(errno));
        return HID_DDK_IO_ERROR;
    }

    FILE* file = fopen(realpathStr, "r+");
    if (file == nullptr) {
        HDF_LOGE("%{public}s fopen failed, path=%{public}s, errno=%{public}d", __func__, path.c_str(), errno);
        return HID_DDK_IO_ERROR;
    }
    dev.fd = fileno(file);
    {
        std::lock_guard<std::mutex> lock(fileDescriptorLock_);
        fileDescriptorMap_[dev.fd] = file;
    }

    return HID_DDK_SUCCESS;
}

int32_t HidDdkService::Close(const HidDeviceHandle& dev)
{
    HDF_LOGD("%{public}s close enter", __func__);
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HID_DDK_NO_PERM;
    }

    {
        std::lock_guard<std::mutex> lock(fileDescriptorLock_);
        if (fileDescriptorMap_.find(dev.fd) == fileDescriptorMap_.end()) {
            HDF_LOGE("%{public}s file not found, fd=%{public}d", __func__, dev.fd);
            return HID_DDK_IO_ERROR;
        }
        int32_t ret = fclose(fileDescriptorMap_[dev.fd]);
        if (ret == EOF) {
            HDF_LOGE("%{public}s fclose failed, errno=%{public}d", __func__, errno);
            return HID_DDK_IO_ERROR;
        }
        fileDescriptorMap_.erase(dev.fd);
    }

    return HID_DDK_SUCCESS;
}

int32_t HidDdkService::Write(const HidDeviceHandle& dev, const std::vector<uint8_t>& data, uint32_t& bytesWritten)
{
    HDF_LOGD("%{public}s write enter", __func__);
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HID_DDK_NO_PERM;
    }

    int32_t ret = write(dev.fd, data.data(), data.size());
    if (ret < 0) {
        HDF_LOGE("%{public}s write failed, errno=%{public}d", __func__, errno);
        bytesWritten = 0;
        return HID_DDK_IO_ERROR;
    }

    bytesWritten = ret;
    return HID_DDK_SUCCESS;
}

int32_t HidDdkService::ReadTimeout(const HidDeviceHandle& dev, std::vector<uint8_t>& data, uint32_t buffSize,
    int32_t timeout, uint32_t& bytesRead)
{
    HDF_LOGD("%{public}s read timeout enter", __func__);
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HID_DDK_NO_PERM;
    }

    if (buffSize > MAX_REPORT_BUFFER_SIZE) {
        HDF_LOGE("%{public}s: invalid parameter", __func__);
        return HID_DDK_INVALID_PARAMETER;
    }

    if (timeout >= 0) {
        int32_t ret;
        struct pollfd fds;

        fds.fd = dev.fd;
        fds.events = POLLIN;
        fds.revents = 0;
        ret = poll(&fds, 1, timeout);
        if (ret == 0) {
            return HID_DDK_TIMEOUT;
        } else if (ret == -1) {
            HDF_LOGE("%{public}s poll failed, errno=%{public}d", __func__, errno);
            return HID_DDK_IO_ERROR;
        }
        if ((unsigned int)fds.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            HDF_LOGE("%{public}s poll failed, revents=%{public}u", __func__, (unsigned int)fds.revents);
            return HID_DDK_IO_ERROR;
        }
    }

    data.resize(buffSize);
    int32_t readRet = read(dev.fd, data.data(), data.size());
    if (readRet < 0) {
        HDF_LOGE("%{public}s read failed, errno=%{public}d", __func__, errno);
        bytesRead = 0;
        return HID_DDK_IO_ERROR;
    }

    bytesRead = static_cast<uint32_t>(readRet);
    return HID_DDK_SUCCESS;
}

int32_t HidDdkService::SetNonBlocking(const HidDeviceHandle& dev, int32_t nonBlock)
{
    HDF_LOGD("%{public}s enter", __func__);
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HID_DDK_NO_PERM;
    }

    return HID_DDK_SUCCESS;
}

int32_t HidDdkService::GetRawInfo(const HidDeviceHandle& dev, HidRawDevInfo& rawDevInfo)
{
    HDF_LOGD("%{public}s enter", __func__);
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HID_DDK_NO_PERM;
    }

    return osAdapter_->GetRawInfo(dev.fd, rawDevInfo);
}

int32_t HidDdkService::GetRawName(const HidDeviceHandle& dev, std::vector<uint8_t>& data, uint32_t buffSize)
{
    HDF_LOGD("%{public}s enter", __func__);
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HID_DDK_NO_PERM;
    }

    if (buffSize > MAX_REPORT_BUFFER_SIZE) {
        HDF_LOGE("%{public}s: invalid parameter", __func__);
        return HID_DDK_INVALID_PARAMETER;
    }

    data.resize(buffSize);

    return osAdapter_->GetRawName(dev.fd, data);
}

int32_t HidDdkService::GetPhysicalAddress(const HidDeviceHandle& dev, std::vector<uint8_t>& data, uint32_t buffSize)
{
    HDF_LOGD("%{public}s enter", __func__);
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HID_DDK_NO_PERM;
    }

    if (buffSize > MAX_REPORT_BUFFER_SIZE) {
        HDF_LOGE("%{public}s: invalid parameter", __func__);
        return HID_DDK_INVALID_PARAMETER;
    }

    data.resize(buffSize);

    return osAdapter_->GetPhysicalAddress(dev.fd, data);
}

int32_t HidDdkService::GetRawUniqueId(const HidDeviceHandle& dev, std::vector<uint8_t>& data, uint32_t buffSize)
{
    HDF_LOGD("%{public}s enter", __func__);
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HID_DDK_NO_PERM;
    }

    if (buffSize > MAX_REPORT_BUFFER_SIZE) {
        HDF_LOGE("%{public}s: invalid parameter", __func__);
        return HID_DDK_INVALID_PARAMETER;
    }

    data.resize(buffSize);

    return osAdapter_->GetRawUniqueId(dev.fd, data);
}

int32_t HidDdkService::SendReport(const HidDeviceHandle& dev, HidReportType reportType,
    const std::vector<uint8_t>& data)
{
    HDF_LOGD("%{public}s enter", __func__);
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HID_DDK_NO_PERM;
    }

    return osAdapter_->SendReport(dev.fd, reportType, data);
}

int32_t HidDdkService::GetReport(const HidDeviceHandle& dev, HidReportType reportType, uint8_t reportNumber,
    std::vector<uint8_t>& data, uint32_t buffSize)
{
    HDF_LOGD("%{public}s enter", __func__);
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HID_DDK_NO_PERM;
    }

    if (buffSize > MAX_REPORT_BUFFER_SIZE) {
        HDF_LOGE("%{public}s: invalid parameter", __func__);
        return HID_DDK_INVALID_PARAMETER;
    }

    data.resize(buffSize);
    data[0] = reportNumber;

    return osAdapter_->GetReport(dev.fd, reportType, data);
}

int32_t HidDdkService::GetReportDescriptor(const HidDeviceHandle& dev, std::vector<uint8_t>& buf, uint32_t buffSize,
    uint32_t& bytesRead)
{
    HDF_LOGD("%{public}s enter", __func__);
    if (!DdkPermissionManager::VerifyPermission(PERMISSION_NAME)) {
        HDF_LOGE("%{public}s: no permission", __func__);
        return HID_DDK_NO_PERM;
    }

    if (buffSize > MAX_REPORT_BUFFER_SIZE) {
        HDF_LOGE("%{public}s: invalid parameter", __func__);
        return HID_DDK_INVALID_PARAMETER;
    }

    buf.resize(buffSize);

    return osAdapter_->GetReportDescriptor(dev.fd, buf, bytesRead);
}

} // V1_1
} // Ddk
} // Input
} // HDI
} // OHOS
