/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "serial_device_manager.h"
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include "serial_hcb_util.h"
#include <hdf_base.h>
#include <hdf_log.h>
#include <fcntl.h>
#include <unistd.h>

#undef LOG_TAG
#define LOG_TAG "SERIAL_IMPL"
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002519

namespace OHOS {
namespace HDI {
namespace Serials {
namespace V1_0 {

SerialDeviceManager::SerialDeviceManager()
{
    HDF_LOGD("%{public}s called!", __func__);
    Init();
}

SerialDeviceManager::~SerialDeviceManager()
{
    HDF_LOGD("%{public}s called!", __func__);
    Deinit();
}

int32_t SerialDeviceManager::Init()
{
    std::lock_guard<std::mutex> lock(mutex_);
    supportTtyhws_.clear();
    GetOnboardSerialConfigs(supportTtyhws_);

    ueventQueue_ = std::make_unique<SerialUeventQueue>();
    ueventQueue_->SetCallback([this](const SerialUeventInfo& info) {
        OnUeventReceived(info);
    });

    int32_t ret = ueventQueue_->Init();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: ueventQueue Init failed", __func__);
        ueventQueue_.reset();
        return ret;
    }

    ueventHandle_ = std::make_unique<SerialUeventHandle>(ueventQueue_.get());
    ret = ueventHandle_->Init();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: ueventHandle Init failed", __func__);
        ueventQueue_->Stop();
        ueventHandle_.reset();
        ueventQueue_.reset();
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t SerialDeviceManager::Deinit()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (ueventHandle_) {
        ueventHandle_->Stop();
        ueventHandle_.reset();
    }
    if (ueventQueue_) {
        ueventQueue_->Stop();
        ueventQueue_.reset();
    }

    for (auto& pair : openDevices_) {
        if (pair.second == nullptr) {
            continue;
        }
        sptr<SerialDevice> device = pair.second.promote();
        if (device == nullptr) {
            continue;
        }
        device->Close();
    }
    supportTtyhws_.clear();
    openDevices_.clear();
    availableDevices_.clear();
    return HDF_SUCCESS;
}

void SerialDeviceManager::OnUeventReceived(const SerialUeventInfo& info)
{
    HDF_LOGI("%{public}s: action=%{public}s, devName=%{public}s, subSystem=%{public}s",
        __func__, info.action.c_str(), info.devName.c_str(), info.subSystem.c_str());

    if (info.action.empty() || info.devName.empty()) {
        return;
    }

    if (info.action != "remove" && info.devType != "usb_device") {
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    std::string portName = "/dev/" + info.devName;
    auto elem = openDevices_.find(portName);
    if (elem != openDevices_.end()) {
        sptr<SerialDevice> device = elem->second.promote();
        if (device != nullptr) {
            HDF_LOGI("%{public}s: device removed, notifying offline, portName=%{public}s",
                __func__, portName.c_str());
            device->NotifyDeviceOffline();
        }
        openDevices_.erase(elem);
    }
}

std::string SerialDeviceManager::ReadSysfsFile(const std::string& path)
{
    FILE* fp = fopen(path.c_str(), "r");
    if (fp == NULL) {
        return "";
    }

    char buffer[MAX_SYS_FILE_BUFF];
    if (fgets(buffer, sizeof(buffer), fp) == NULL) {
        fclose(fp);
        return "";
    }

    fclose(fp);

    std::string result(buffer);
    if (!result.empty() && result[result.length() - 1] == '\n') {
        result.erase(result.length() - 1);
    }
    if (!result.empty() && result[result.length() - 1] == '\r') {
        result.erase(result.length() - 1);
    }

    return result;
}

static void HexStrToInt(const std::string& hexStr, int32_t& result)
{
    if (hexStr.empty()) {
        return;
    }
    char* endStr = nullptr;
    errno = 0;
    result = (int32_t)std::strtol(hexStr.c_str(), &endStr, BASE_HEX);
    if (errno == ERANGE || endStr == hexStr.c_str()) {
        result = 0;
    }
}

void SerialDeviceManager::AddVirtualUsbDevice(std::vector<SerialDeviceInfo>& devices,
    const std::string& name, const std::string& fullPath)
{
    std::string basePath = "/sys/class/tty/" + name + "/device/../../";
    std::string manufacturer = ReadSysfsFile(basePath + "manufacturer");
    std::string serialNumber = ReadSysfsFile(basePath + "serial");
    std::string vendorId = ReadSysfsFile(basePath + "idVendor");
    std::string productId = ReadSysfsFile(basePath + "idProduct");
    HDF_LOGI(" [MF: %{public}s, SN: %{public}s, VID: 0x%{public}s, PID: 0x%{public}s]",
        manufacturer.empty() ? "UN" : manufacturer.c_str(),
        serialNumber.empty() ? "UN" : serialNumber.c_str(),
        vendorId.empty() ? "UN" : vendorId.c_str(),
        productId.empty() ? "UN" : productId.c_str());

    SerialDeviceInfo info{fullPath, manufacturer, serialNumber, 0, 0};
    HexStrToInt(productId, info.productId);
    HexStrToInt(vendorId, info.vendorId);
    devices.push_back(info);
    availableDevices_[fullPath] = info;
    HDF_LOGI("found device:%{public}s!", fullPath.c_str());
}

void SerialDeviceManager::AddNormalSerialDevice(std::vector<SerialDeviceInfo>& devices, const std::string& fullPath)
{
    auto elem = supportTtyhws_.find(fullPath);
    if (elem == supportTtyhws_.end()) {
        HDF_LOGW("not support this device:%{public}s!", fullPath.c_str());
        return;
    }
    struct stat st;
    if (stat(fullPath.c_str(), &st) == 0 && S_ISCHR(st.st_mode)) {
        SerialDeviceInfo info{fullPath, "", "", 0, 0};
        devices.push_back(info);
        availableDevices_[fullPath] = info;
        HDF_LOGI("found device:%{public}s!", fullPath.c_str());
    }
}

int32_t SerialDeviceManager::QueryDevices(std::vector<SerialDeviceInfo>& devices)
{
    HDF_LOGD("%{public}s called!", __func__);
    std::lock_guard<std::mutex> lock(mutex_);
    const char* devPath = "/dev";
    DIR* dir = opendir(devPath);
    if (dir == NULL) {
        return HDF_ERR_IO;
    }

    availableDevices_.clear();
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        std::string name = entry->d_name;
        if (name.find("ttyUSB") == 0) {
            std::string fullPath = std::string(devPath) + "/" + name;
            AddVirtualUsbDevice(devices, name, fullPath);
        } else {
            std::string fullPath = std::string(devPath) + "/" + name;
            AddNormalSerialDevice(devices, fullPath);
        }
    }
    closedir(dir);
    HDF_LOGI("found %{public}zu devices!", availableDevices_.size());
    return HDF_SUCCESS;
}

int32_t SerialDeviceManager::OpenDevice(const std::string& portName, const SerialConfig& config,
    const sptr<ISerialDeviceCallback>& cb, sptr<ISerialDevice>& device)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto elem = openDevices_.find(portName);
    if (elem != openDevices_.end() && elem->second.promote() != nullptr) {
        HDF_LOGE("%{public}s exist!", portName.c_str());
        return HDF_ERR_DEVICE_BUSY;
    }
    auto it = availableDevices_.find(portName);
    if (it == availableDevices_.end()) {
        HDF_LOGE("%{public}s not found!", portName.c_str());
        return HDF_ERR_INVALID_PARAM;
    }
    sptr<SerialDevice> dv(new SerialDevice(it->second.portName, cb, config));
    int32_t ret = dv->Open();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s open failed!", portName.c_str());
        return ret;
    }
    device = dv;
    openDevices_[portName] = dv;
    return HDF_SUCCESS;
}

SerialDeviceManager& SerialDeviceManager::GetInstance()
{
    static SerialDeviceManager instance;
    return instance;
}

} // V1_0
} // Serials
} // HDI
} // OHOS