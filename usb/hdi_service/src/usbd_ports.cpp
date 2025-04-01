/*
* Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include <iostream>
#include <sstream>

#include "usbd_ports.h"
#include "hdf_base.h"
#include "hdf_log.h"
#include "usbd_function.h"
#include "usb_portInfo.h"

using namespace OHOS::HDI::Usb::Port;

namespace OHOS {
namespace HDI {
namespace Usb {
namespace V1_2 {
constexpr int32_t NONE = 0;
constexpr int32_t SUPPORT_MODE_DRP = 1;
constexpr int32_t SUPPORT_MODE_UFP = 2;
constexpr int32_t SUPPORT_MODE_DFP = 3;
constexpr int32_t STRING_PORT = 4;

UsbdPorts &UsbdPorts::GetInstance()
{
    static UsbdPorts instance;
    return instance;
}

UsbdPorts::UsbdPorts()
{
    InitMap();
}

void UsbdPorts::InitMap()
{
    portAttributeMap_[PORT_CONFIG_NONE] = NONE;
    portAttributeMap_[PORT_MODE_UFP] = static_cast<int32_t>(Port::PortMode::UFP);
    portAttributeMap_[PORT_MODE_DFP] = static_cast<int32_t>(Port::PortMode::DFP);
    portAttributeMap_[PORT_MODE_DRP] = static_cast<int32_t>(Port::PortMode::DRP);
    portAttributeMap_[POWER_ROLE_SOURCE] = static_cast<int32_t>(PowerRole::SOURCE);
    portAttributeMap_[POWER_ROLE_SINK] = static_cast<int32_t>(PowerRole::SINK);
    portAttributeMap_[DATA_ROLE_HOST] = static_cast<int32_t>(DataRole::HOST);
    portAttributeMap_[DATA_ROLE_DEVICE] = static_cast<int32_t>(DataRole::DEVICE);
    portAttributeMap_[SUPPORTED_MODE_DRP] = SUPPORT_MODE_DRP;
    portAttributeMap_[SUPPORTED_MODE_UFP] = SUPPORT_MODE_UFP;
    portAttributeMap_[SUPPORTED_MODE_DFP] = SUPPORT_MODE_DFP;
}

void UsbdPorts::setPortPath(const std::string &path)
{
    path_ = path;
    HDF_LOGI("%{public}s: port_file_path = %{public}s", __func__, path_.c_str());
}

int32_t UsbdPorts::QueryPort(int32_t &portId, int32_t &powerRole, int32_t &dataRole, int32_t &mode)
{
    HDF_LOGI("%{public}s: QueryPort start", __func__);
    if (portCacheDataMap_.empty()) {
        std::vector<V2_0::UsbPort> portList;
        int32_t ret = QueryPorts(portList);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: QueryPorts failed!", __func__);
            return HDF_FAILURE;
        }
    }

    auto usbPort = portCacheDataMap_.begin();
    portId = usbPort->first;
    powerRole = usbPort->second.usbPortStatus.currentPowerRole;
    dataRole = usbPort->second.usbPortStatus.currentDataRole;
    mode = usbPort->second.usbPortStatus.currentMode;
    return HDF_SUCCESS;
}

int32_t UsbdPorts::QueryPorts(std::vector<V2_0::UsbPort>& portList)
{
    HDF_LOGI("%{public}s: start", __func__);
    std::vector<std::string> portIds;
    int32_t ret = ParseDirectory(path_, portIds, true);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: ParseDirectory failed! ret:%{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    for (auto portId : portIds) {
        V2_0::UsbPort usbPort;
        if (ReadPortInfo(portId, usbPort) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: ReadPortInfo failed! ret:%{public}d", __func__, ret);
            return HDF_FAILURE;
        }

        usbPort.id = std::stoi(portId);
        portList.emplace_back(usbPort);
        AddPort(usbPort);
    }

    return HDF_SUCCESS;
}

int32_t UsbdPorts::ParseDirectory(const std::string& path, std::vector<std::string>& portIds, bool flag)
{
    HDF_LOGI("%{public}s start", __func__);
    DIR* dir = opendir(path.c_str());
    if (dir == nullptr) {
        HDF_LOGE("%{public}s: directory open error! path: %{public}s", __func__, path.c_str());
        return HDF_FAILURE;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string value = entry->d_name;
        if (value == "." || value == "..") {
            continue;
        }

        if (flag) {
            if (ParsePortId(value) != HDF_SUCCESS) {
                HDF_LOGE("%{public}s: Parse portid failed! ", __func__);
                closedir(dir);
                return HDF_FAILURE;
            }
            portIds.push_back(value);
            continue;
        }

        if (!IsFileFormat(entry->d_name)) {
            continue;
        }
        portIds.push_back(entry->d_name);
    }
    closedir(dir);

    return HDF_SUCCESS;
}

bool UsbdPorts::IsFileFormat(const std::string& dName)
{
    if (dName != "port_mode" && dName != "power_role"
        && dName != "data_role" && dName != "supported_mode") {
        return false;
    }

    return true;
}

int32_t UsbdPorts::ParsePortId(std::string& value)
{
    std::string str = value;
    if (str.substr(0, STRING_PORT) != "port") {
        HDF_LOGE("%{public}s: The portid node is incorrect! portId: %{public}s", __func__, str.c_str());
        return HDF_FAILURE;
    }

    value = str.substr(STRING_PORT);
    if (value.empty()) {
        HDF_LOGE("%{public}s: The portid node is incorrect! portId: %{public}s", __func__, str.c_str());
        return HDF_FAILURE;
    }

    for (size_t i = 0; i < value.size(); i++) {
        if (value.at(i) > '9' || value.at(i) < '0') {
            HDF_LOGE("%{public}s: this node name incorrect! portId: %{public}s.", __func__, str.c_str());
            return HDF_FAILURE;
        }
    }

    return HDF_SUCCESS;
}

int32_t UsbdPorts::ReadPortInfo(const std::string& portId, V2_0::UsbPort& usbPort)
{
    HDF_LOGI("%{public}s start", __func__);
    std::vector<std::string> portAttributeFileList;
    const std::string portAttributeDir = path_ + "port" + portId;

    int32_t ret = ParseDirectory(portAttributeDir, portAttributeFileList, false);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: ParseDirectory failed! ret:%{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    for (auto it : portAttributeFileList) {
        std::string portAttributeFile;
        char buff[PATH_MAX] = {'\0'};

        portAttributeFile = portAttributeDir + "/" + it;
        int32_t fd = OpenFile(portAttributeFile, O_RDONLY);
        if (fd < 0) {
            HDF_LOGE("%{public}s: file open error fd = %{public}d", __func__, fd);
            return HDF_FAILURE;
        }

        ret = read(fd, buff, PATH_MAX - 1);
        close(fd);
        if (ret < 0) {
            HDF_LOGE("%{public}s: read error: %{public}s", __func__, portAttributeFile.c_str());
            return HDF_FAILURE;
        }

        ret = ParsePortAttribute(it, buff, usbPort);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: ParsePortAttribute failed! ret:%{public}d", __func__, ret);
            return HDF_FAILURE;
        }
    }

    return HDF_SUCCESS;
}

int32_t UsbdPorts::OpenFile(const std::string& path, int32_t flags)
{
    if (path.empty()) {
        HDF_LOGE("%{public}s: The path cannot be empty", __func__);
        return HDF_FAILURE;
    }

    return open(path.c_str(), flags);
}

int32_t UsbdPorts::ParsePortAttribute(const std::string& portAttributeFileName,
    const std::string& buff, V2_0::UsbPort& usbPort)
{
    HDF_LOGI("%{public}s start", __func__);
    if (portAttributeFileName == "port_mode") {
        return GetAttributeValue(buff, usbPort.usbPortStatus.currentMode);
    } else if (portAttributeFileName == "power_role") {
        return GetAttributeValue(buff, usbPort.usbPortStatus.currentPowerRole);
    } else if (portAttributeFileName == "data_role") {
        return GetAttributeValue(buff, usbPort.usbPortStatus.currentDataRole);
    } else if (portAttributeFileName == "supported_mode") {
        return GetAttributeValue(buff, usbPort.supportedModes);
    }

    return HDF_SUCCESS;
}

int32_t UsbdPorts::GetAttributeValue(const std::string& buff, int32_t& outEnumValue)
{
    if (portAttributeMap_.find(buff) == portAttributeMap_.end()) {
        HDF_LOGE("%{public}s: %{public}s is invalid value", __func__, buff.c_str());
        return HDF_FAILURE;
    }

    outEnumValue = portAttributeMap_[buff];
    return HDF_SUCCESS;
}

void UsbdPorts::AddPort(const V2_0::UsbPort &port)
{
    portCacheDataMap_[port.id] = port;
}

bool UsbdPorts::IsSupportedMode(int32_t portId)
{
    auto it = portCacheDataMap_.find(portId);
    if (it == portCacheDataMap_.end()) {
        HDF_LOGE("%{public}s: portId not exist, set failed", __func__);
        return false;
    }

    if (it->second.supportedModes == NONE) {
        HDF_LOGE("%{public}s The mode does not support settings", __func__);
        return false;
    }

    return true;
}

int32_t UsbdPorts::SetPort(int32_t portId, int32_t powerRole, int32_t dataRole,
    UsbdSubscriber *usbdSubscribers, uint32_t len)
{
    HDF_LOGI("%{public}s: SetPort start", __func__);
    auto usbPort = portCacheDataMap_.begin();
    if (portId != usbPort->first) {
        HDF_LOGE("%{public}s: portId not exist, set failed", __func__);
        return HDF_FAILURE;
    }

    if (!IsSupportedMode(portId)) {
        return HDF_FAILURE;
    }

    V2_0::UsbPort port;
    int32_t ret = SetPortInfo(portId, powerRole, dataRole, port);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: SetPortInfo failed", __func__);
        return HDF_FAILURE;
    }

    for (uint32_t i = 0; i < len; i++) {
        if (usbdSubscribers[i].subscriber != nullptr) {
            PortInfo portInfo;
            ReportData(port, portInfo);
            usbdSubscribers[i].subscriber->PortChangedEvent(portInfo);
        }
    }

    AddPort(port);
    return HDF_SUCCESS;
}

int32_t UsbdPorts::SetPort(int32_t portId, int32_t powerRole, int32_t dataRole,
    V2_0::UsbdSubscriber *usbdSubscribers, uint32_t len)
{
    HDF_LOGI("%{public}s: SetPort start", __func__);
    if (!IsSupportedMode(portId)) {
        return HDF_FAILURE;
    }

    V2_0::UsbPort port;
    int32_t ret = SetPortInfo(portId, powerRole, dataRole, port);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: SetPortInfo failed", __func__);
        return HDF_FAILURE;
    }

    for (uint32_t i = 0; i < len; i++) {
        if (usbdSubscribers[i].subscriber != nullptr) {
            V2_0::PortInfo portInfo;
            ReportData(port, portInfo);
            usbdSubscribers[i].subscriber->PortChangedEvent(portInfo);
        }
    }

    AddPort(port);
    return HDF_SUCCESS;
}

int32_t UsbdPorts::SetPortInfo(int32_t portId, int32_t powerRole, int32_t dataRole, V2_0::UsbPort& port)
{
    if (path_ == "/data/service/el1/public/usb/mode") {
        HDF_LOGE("%{public}s: not support", __func__);
        return HDF_ERR_NOT_SUPPORT;
    }
    
    if (!IsRoleValueLegality(powerRole, dataRole)) {
        HDF_LOGE("%{public}s: invalid powerRole or dataRole", __func__);
        return HDF_FAILURE;
    }

    port = portCacheDataMap_[portId];
    const std::string portIdNode = std::to_string(portId);
    std::string data;
    GetRoleStrValue(powerRole, data, true);
    int32_t ret = WritePortInfo(portIdNode, "power_role", data);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Execute WritePortInfo failed", __func__);
        return HDF_FAILURE;
    }

    GetRoleStrValue(dataRole, data, false);
    WritePortInfo(portIdNode, "data_role", data);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Execute WritePortInfo failed", __func__);
        return HDF_FAILURE;
    }

    if (portCacheDataMap_.find(portId) == portCacheDataMap_.end()) {
        HDF_LOGE("%{public}s: portId not found", __func__);
        return HDF_FAILURE;
    }

    port.usbPortStatus.currentPowerRole = powerRole;
    port.usbPortStatus.currentDataRole = dataRole;

    return HDF_SUCCESS;
}

bool UsbdPorts::IsRoleValueLegality(int32_t powerRole, int32_t dataRole)
{
    if (powerRole < (int32_t)PowerRole::NONE || powerRole >= (int32_t)PowerRole::NUM_POWER_ROLES
        || dataRole < (int32_t)DataRole::NONE || dataRole >= (int32_t)DataRole::NUM_DATA_ROLES) {
        return false;
    }

    return true;
}

int32_t UsbdPorts::WritePortInfo(const std::string& portId, const std::string& portAttributeFilePath, std::string& data)
{
    HDF_LOGI("%{public}s: start", __func__);
    std::lock_guard<std::mutex> lock(mutex_);
    std::string writePath = path_ + "port" + portId + "/" + portAttributeFilePath;

    int32_t fd = OpenFile(writePath, O_WRONLY | O_TRUNC);
    if (fd < 0) {
        HDF_LOGE("%{public}s: file open error! ret:%{public}s", __func__, writePath.c_str());
        return HDF_FAILURE;
    }

    int32_t ret = write(fd, data.c_str(), data.size());
    close(fd);
    if (ret <= 0) {
        HDF_LOGE("%{public}s: write file failed! ret:%{public}d path: %{public}s",
            __func__, ret, writePath.c_str());
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

void UsbdPorts::GetRoleStrValue(int32_t role, std::string& strRole, bool flag)
{
    for (auto it : portAttributeMap_) {
        if (flag) {
            // powerRole
            if ((it.first != POWER_ROLE_SOURCE) && (it.first != POWER_ROLE_SINK)) {
                continue;
            }
            if (it.second == role) {
                strRole = it.first;
                break;
            }
        } else {
            //dataRole
            if ((it.first != DATA_ROLE_HOST) && (it.first != DATA_ROLE_DEVICE)) {
                continue;
            }
            if (it.second == role) {
                strRole = it.first;
                break;
            }
        }
    }
}

bool UsbdPorts::IsUpdate(const V2_0::UsbPort& usbPortInfo)
{
    HDF_LOGI("%{public}s: start", __func__);
    if (portCacheDataMap_.find(usbPortInfo.id) == portCacheDataMap_.end()) {
        return true;
    }

    V2_0::UsbPort usbPort = portCacheDataMap_[usbPortInfo.id];
    if (usbPort.usbPortStatus.currentMode != usbPortInfo.usbPortStatus.currentMode
    || usbPort.usbPortStatus.currentPowerRole != usbPortInfo.usbPortStatus.currentPowerRole
    || usbPort.usbPortStatus.currentDataRole != usbPortInfo.usbPortStatus.currentDataRole
    || usbPort.supportedModes != usbPortInfo.supportedModes) {
        return true;
    }

    return false;
}

void UsbdPorts::ReportData(const V2_0::UsbPort& usbPort, V2_0::PortInfo& portInfo)
{
    HDF_LOGI("%{public}s: start", __func__);
    portInfo.portId = usbPort.id;
    portInfo.supportedModes = usbPort.supportedModes;
    portInfo.powerRole = usbPort.usbPortStatus.currentPowerRole;
    portInfo.dataRole = usbPort.usbPortStatus.currentDataRole;
    portInfo.mode = usbPort.usbPortStatus.currentMode;
}

void UsbdPorts::ReportData(const V2_0::UsbPort& usbPort, PortInfo& portInfo)
{
    HDF_LOGI("%{public}s: start", __func__);
    portInfo.portId = usbPort.id;
    portInfo.powerRole = usbPort.usbPortStatus.currentPowerRole;
    portInfo.dataRole = usbPort.usbPortStatus.currentDataRole;
    portInfo.mode = usbPort.usbPortStatus.currentMode;
}

int32_t UsbdPorts::UpdatePort(int32_t mode, const sptr<IUsbdSubscriber>& subscriber)
{
    (void)mode;
    std::vector<V2_0::UsbPort> portList;
    int32_t ret = QueryPorts(portList);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: data update failuer", __func__);
        return HDF_FAILURE;
    }

    for (size_t i = 0; i < portList.size(); i++) {
        if (IsUpdate(portList.at(i))) {
            PortInfo portInfo;
            ReportData(portList.at(i), portInfo);
            subscriber->PortChangedEvent(portInfo);
        }
    }

    return HDF_SUCCESS;
}

int32_t UsbdPorts::UpdatePort(int32_t mode, const sptr<OHOS::HDI::Usb::V2_0::IUsbdSubscriber>& subscriber)
{
    (void)mode;
    std::vector<V2_0::UsbPort> portList;
    int32_t ret = QueryPorts(portList);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: data update failuer", __func__);
        return HDF_FAILURE;
    }

    for (size_t i = 0; i < portList.size(); i++) {
        if (IsUpdate(portList.at(i))) {
            V2_0::PortInfo portInfo;
            ReportData(portList.at(i), portInfo);
            subscriber->PortChangedEvent(portInfo);
        }
    }

    return HDF_SUCCESS;
}
} // namespace V1_2
} // namespace Usb
} // namespace HDI
} // namespace OHOS
