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
#include <fcntl.h>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <algorithm>
#include <cstdio>
#include "hdf_base.h"
#include "hdf_log.h"
#include "serial_hcb_util.h"


#undef LOG_TAG
#define LOG_TAG "SERIAL_IMPL"
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002519

namespace OHOS {
namespace HDI {
namespace Serial {
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
    pcieSerialPrefixOffsets_.clear();
    GetOnboardSerialConfigs(supportTtyhws_);
    GetPcieSerialConfigs(pcieSerialPrefixOffsets_);

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
    if (info.action.empty() || info.devName.empty()) {
        return;
    }

    if (info.action != "remove" && info.devType != "usb_device") {
        return;
    }
    HDF_LOGI("%{public}s: action=%{public}s, devName=%{public}s, subSystem=%{public}s",
        __func__, info.action.c_str(), info.devName.c_str(), info.subSystem.c_str());
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
    result = static_cast<int32_t>(std::strtol(hexStr.c_str(), &endStr, BASE_HEX));
    if (errno == ERANGE || endStr == hexStr.c_str()) {
        result = 0;
    }
}

std::string SerialDeviceManager::FindUsbDeviceSysfsPath(const std::string& name)
{
    std::string devicePath = "/sys/class/tty/" + name + "/device";
    char realPath[PATH_MAX] = {0};
    if (realpath(devicePath.c_str(), realPath) == nullptr) {
        HDF_LOGE("%{public}s: realpath failed for %{public}s, errno=%{public}d", __func__, devicePath.c_str(), errno);
        return "";
    }

    std::string current = realPath;
    while (!current.empty() && current != "/") {
        if (access((current + "/manufacturer").c_str(), F_OK) == 0) {
            if (current.back() != '/') {
                current += '/';
            }
            return current;
        }
        size_t pos = current.rfind('/');
        if (pos == std::string::npos) {
            break;
        }
        current = current.substr(0, pos);
    }
    HDF_LOGE("%{public}s: cannot find usb device sysfs path for %{public}s", __func__, name.c_str());
    return "";
}

void SerialDeviceManager::AddVirtualUsbDevice(std::vector<SerialDeviceInfo>& devices,
    const std::string& name, const std::string& fullPath)
{
    std::string basePath = FindUsbDeviceSysfsPath(name);
    std::string manufacturer = ReadSysfsFile(basePath + "manufacturer");
    std::string serialNumber = ReadSysfsFile(basePath + "serial");
    std::string vendorId = ReadSysfsFile(basePath + "idVendor");
    std::string productId = ReadSysfsFile(basePath + "idProduct");

    SerialDeviceInfo info{fullPath, manufacturer, serialNumber, 0, 0};
    HexStrToInt(productId, info.productId);
    HexStrToInt(vendorId, info.vendorId);
    devices.push_back(info);
    availableDevices_[fullPath] = info;
    HDF_LOGD("found device:%{public}s!", fullPath.c_str());
}

void SerialDeviceManager::AddNormalSerialDevice(std::vector<SerialDeviceInfo>& devices, const std::string& fullPath)
{
    auto elem = supportTtyhws_.find(fullPath);
    if (elem == supportTtyhws_.end()) {
        HDF_LOGD("not support this device:%{public}s!", fullPath.c_str());
        return;
    }
    SerialDeviceInfo info{fullPath, "", "", 0, 0};
    devices.push_back(info);
    availableDevices_[fullPath] = info;
    HDF_LOGD("found device:%{public}s!", fullPath.c_str());
}

bool SerialDeviceManager::IsPcieSerialName(const std::string& name)
{
    // ttyS* is linux standard serial port - auto-detected as PCIE serial
    if (name.find("ttyS") == 0) {
        return true;
    }
    // Match against PCIE serial port prefixes from CCM config
    for (const auto& [prefix, offset] : pcieSerialPrefixOffsets_) {
        if (name.find(prefix) == 0) {
            return true;
        }
    }
    return false;
}

static constexpr int32_t SERIAL_LINE_BUF_SIZE = 512;
static constexpr const char* PROC_SERIAL_PATH = "/proc/devhost/root/tty/driver/serial";

bool SerialDeviceManager::IsTtySerialValid(int32_t serialIndex)
{
    if (serialIndex < 0) {
        return false;
    }
    FILE* fp = fopen(PROC_SERIAL_PATH, "r");
    if (fp == nullptr) {
        HDF_LOGW("%{public}s: cannot open %{public}s, errno=%{public}d", __func__, PROC_SERIAL_PATH, errno);
        return false;
    }
    char lineBuf[SERIAL_LINE_BUF_SIZE] = {0};
    while (fgets(lineBuf, sizeof(lineBuf), fp) != nullptr) {
        std::string line(lineBuf);
        int32_t idx = 0;
        char colon = '\0';
        if (sscanf_s(line.c_str(), "%d%c", &idx, &colon, static_cast<unsigned>(sizeof(colon))) < 2 ||
            colon != ':' || idx != serialIndex) {
            continue;
        }
        size_t pos = line.find("uart:");
        if (pos == std::string::npos || line.substr(pos + strlen("uart:"), strlen("unknown")) == "unknown") {
            break;
        }
        if ((pos = line.find("mmio:")) != std::string::npos) {
            if (std::strtol(line.c_str() + pos + strlen("mmio:"), nullptr, 0) == 0) {
                break;
            }
        } else if ((pos = line.find("port:")) != std::string::npos) {
            if (line.substr(pos + strlen("port:")).find("00000000") == 0) {
                break;
            }
        } else {
            break;
        }
        if ((pos = line.find("irq:")) == std::string::npos ||
            std::strtol(line.c_str() + pos + strlen("irq:"), nullptr, 10) == 0) {
            break;
        }
        fclose(fp);
        return true;
    }
    fclose(fp);
    HDF_LOGW("%{public}s: ttyS%{public}d invalid or not found in %{public}s", __func__, serialIndex, PROC_SERIAL_PATH);
    return false;
}

void SerialDeviceManager::AddPcieSerialDevice(std::vector<SerialDeviceInfo>& devices,
    const std::string& name, const std::string& fullPath)
{
    // Read PCI sysfs for vendor/device ID
    std::string pciDevicePath = "/sys/class/tty/" + name + "/device/";
    std::string vendorIdStr = ReadSysfsFile(pciDevicePath + "vendor");
    std::string productIdStr = ReadSysfsFile(pciDevicePath + "device");

    // Strip "0x"/"0X" prefix and convert to lowercase for consistency
    auto stripHexPrefix = [](std::string& s) {
        if (s.size() > 2 && (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))) {
            s = s.substr(2);
        }
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {return std::tolower(c);});
    };
    stripHexPrefix(vendorIdStr);
    stripHexPrefix(productIdStr);

    SerialDeviceInfo info{fullPath, "", "", 0, 0};
    HexStrToInt(productIdStr, info.productId);
    HexStrToInt(vendorIdStr, info.vendorId);
    devices.push_back(info);
    availableDevices_[fullPath] = info;
    HDF_LOGI("found PCIE device:%{public}s, vendorId=0x%{public}04x, productId=0x%{public}04x",
        fullPath.c_str(), info.vendorId, info.productId);
}

static bool IsUsbSerialName(const std::string& name)
{
    return (name.find("ttyUSB") == 0 || name.find("ttyACM") == 0);
}

static int32_t ExtractSerialIndex(const std::string& name)
{
    size_t digitStart = name.find_first_of("0123456789");
    if (digitStart == std::string::npos) {
        return -1;
    }
    char* endPtr = nullptr;
    errno = 0;
    int32_t index = static_cast<int32_t>(std::strtol(name.c_str() + digitStart, &endPtr, 10));
    if (errno == ERANGE || endPtr == name.c_str() + digitStart) {
        return -1;
    }
    return index;
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
        if (IsUsbSerialName(name)) {
            std::string fullPath = std::string(devPath) + "/" + name;
            AddVirtualUsbDevice(devices, name, fullPath);
        } else if (IsPcieSerialName(name)) {
            // ttyS* devices need validity check via /proc/devhost/root/tty/driver/serial
            if (name.find("ttyS") == 0 && !IsTtySerialValid(ExtractSerialIndex(name))) {
                continue;
            }
            std::string fullPath = std::string(devPath) + "/" + name;
            AddPcieSerialDevice(devices, name, fullPath);
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
} // Serial
} // HDI
} // OHOS