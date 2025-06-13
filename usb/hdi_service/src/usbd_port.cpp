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

#include "usbd_port.h"
#include <dirent.h>
#include <string>
#include "hdf_base.h"
#include "hdf_log.h"
#include "usbd_function.h"
#include "usbd_wrapper.h"
#include "usb_report_sys_event.h"

namespace OHOS {
namespace HDI {
namespace Usb {
namespace V1_2 {

UsbdPort &UsbdPort::GetInstance()
{
    static UsbdPort instance;
    return instance;
}

int32_t UsbdPort::IfCanSwitch(int32_t portId, int32_t powerRole, int32_t dataRole)
{
    if (portId != DEFAULT_PORT_ID) {
        HDF_LOGE("%{public}s: portId error", __func__);
        return HDF_FAILURE;
    }

    if (powerRole <= POWER_ROLE_NONE || powerRole >= POWER_ROLE_MAX) {
        HDF_LOGE("%{public}s: powerRole error", __func__);
        return HDF_FAILURE;
    }

    if (dataRole <= DATA_ROLE_NONE || dataRole >= DATA_ROLE_MAX) {
        HDF_LOGE("%{public}s: dataRole error", __func__);
        return HDF_FAILURE;
    }
    if (!isPdV2_0) {
        int32_t supported_modes = 0;
        int32_t ret = GetSupportedModes(supported_modes);
        if (supported_modes == 0 && ret >= 0) {
            HDF_LOGE("%{public}s: supported_modes is none not support", __func__);
            return HDF_ERR_NOT_SUPPORT;
        }
    }
    if (path_ == "/data/service/el1/public/usb/mode") {
        HDF_LOGE("%{public}s: not support", __func__);
        return HDF_ERR_NOT_SUPPORT;
    }
    return HDF_SUCCESS;
}

int32_t UsbdPort::OpenPortFile(int32_t flags, const std::string &subPath)
{
    std::string fullPath;
    if (isPdV2_0) {
        fullPath = path_;
    } else {
        fullPath = path_ + subPath;
    }
    if (fullPath.empty()) {
        HDF_LOGE("%{public}s: Empty path provided", __func__);
        return HDF_FAILURE;
    }

    char pathBuf[PATH_MAX] = {'\0'};
    if (realpath(fullPath.c_str(), pathBuf) == nullptr) {
        HDF_LOGE("%{public}s: Path conversion failed for: %{public}s", __func__, fullPath.c_str());
        return HDF_FAILURE;
    }

    int32_t fd = open(pathBuf, flags);
    if (fd < 0) {
        HDF_LOGE("%{public}s: Failed to open file: %{public}s, errno: %{public}d", __func__, pathBuf, errno);
        return fd;
    }

    fdsan_exchange_owner_tag(fd, 0, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
    return fd;
}

int32_t UsbdPort::WritePortFile(int32_t role, const std::string &subPath)
{
    std::string modeStr;
    static const std::unordered_map<std::string, std::unordered_map<int32_t, std::string>> roleWriteMaps = {
        {DATA_ROLE_PATH, {
            {DATA_ROLE_HOST,    DATA_ROLE_UFP_STR},
            {DATA_ROLE_DEVICE,  DATA_ROLE_DFP_STR},
            {DATA_ROLE_NONE,    DATA_ROLE_NONE_STR}
        }},
        {POWER_ROLE_PATH, {
            {POWER_ROLE_SOURCE, POWER_ROLE_SOURCE_STR},
            {POWER_ROLE_SINK,   POWER_ROLE_SINK_STR},
            {POWER_ROLE_NONE,   POWER_ROLE_NONE_STR}
        }}
    };
    auto pathIt = roleWriteMaps.find(subPath);
    if (pathIt == roleWriteMaps.end()) {
        HDF_LOGE("%{public}s: Invalid subPath: %{public}s", __func__, subPath.c_str());
        return HDF_FAILURE;
    }
    auto roleIt = pathIt->second.find(role);
    if (roleIt == pathIt->second.end()) {
        HDF_LOGE("%{public}s: Invalid role: %{public}d for path: %{public}s",
            __func__, role, subPath.c_str());
        return HDF_FAILURE;
    }
    modeStr = roleIt->second;
    int32_t fd = OpenPortFile(O_WRONLY | O_TRUNC, subPath);
    if (fd < 0) {
        return HDF_FAILURE;
    }
    int32_t ret = write(fd, modeStr.c_str(), modeStr.size());
    fdsan_close_with_tag(fd, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
    
    if (ret < 0) {
        HDF_LOGE("%{public}s: Write failed for: %{public}s, errno: %{public}d", __func__, modeStr.c_str(), errno);
        return HDF_FAILURE;
    }
    
    return HDF_SUCCESS;
}

int32_t UsbdPort::ReadPortFile(int32_t &role, const std::string &subPath)
{
    int32_t fd = OpenPortFile(O_RDONLY, subPath);
    if (fd < 0) {
        return HDF_FAILURE;
    }
    char modeBuf[PATH_MAX] = {'\0'};
    int32_t ret = read(fd, modeBuf, sizeof(modeBuf) - 1);
    fdsan_close_with_tag(fd, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
    if (ret <= 0) {
        HDF_LOGE("%{public}s: Read failed for: %{public}s, errno: %{public}d", __func__, path_.c_str(), errno);
        return HDF_FAILURE;
    }
    std::string modeStr = std::string(modeBuf).substr(0, ret); // Trim to actual read length
    modeStr.erase(modeStr.find_last_not_of(" \n\r\t") + 1); // Trim whitespace
    static const std::unordered_map<std::string, std::unordered_map<std::string, int32_t>> roleReadMaps = {
        {DATA_ROLE_PATH, {
            {DATA_ROLE_NONE_STR, DATA_ROLE_NONE},
            {DATA_ROLE_UFP_STR,  DATA_ROLE_HOST},
            {DATA_ROLE_DFP_STR,  DATA_ROLE_DEVICE}
        }},
        {POWER_ROLE_PATH, {
            {POWER_ROLE_NONE_STR,   POWER_ROLE_NONE},
            {POWER_ROLE_SOURCE_STR, POWER_ROLE_SOURCE},
            {POWER_ROLE_SINK_STR,   POWER_ROLE_SINK}
            }},
        {MODE_PATH, {
            {MODES_NONE_STR, MODES_NONE},
            {MODES_UFP_STR,  MODES_UFP},
            {MODES_DFP_STR,  MODES_DFP},
            {MODES_DRP_STR,  MODES_DRP}
        }}
    };
    auto pathIt = roleReadMaps.find(subPath);
    if (pathIt == roleReadMaps.end()) {
        HDF_LOGE("%{public}s: Invalid subPath: %{public}s", __func__, subPath.c_str());
        return HDF_FAILURE;
    }
    auto roleIt = pathIt->second.find(modeStr);
    if (roleIt == pathIt->second.end()) {
        role = 0;
        HDF_LOGE("%{public}s: Invalid mode: %{public}s", __func__, modeStr.c_str());
        return HDF_FAILURE;
    }
    role = roleIt->second;
    return HDF_SUCCESS;
}

void UsbdPort::setPortPath(const std::string &path)
{
    path_ = DEFAULT_USB_MODE_PATH;
    if (path == DEFAULT_USB_MODE_PATH) {
        isPdV2_0 = true;
        HDF_LOGE("%{public}s: not support", __func__);
        return;
    }
    if (path == PD_V2_0) {
        isPdV2_0 = true;
        path_ = PD_V2_0;
        HDF_LOGE("%{public}s: default path", __func__);
        return;
    }
    DIR *dir = opendir(path.c_str());
    if (dir == nullptr) {
        HDF_LOGE("%{public}s: Failed to open directory: %{public}s", __func__, path.c_str());
    }
    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        } else {
            path_ = path + entry->d_name;
            HDF_LOGE("%{public}s: Full path: %{public}s", __func__, path_.c_str());
            break;
        }
    }
    closedir(dir);
}

int32_t UsbdPort::SetPortInit(int32_t portId, int32_t powerRole, int32_t dataRole)
{
    auto ret = IfCanSwitch(portId, powerRole, dataRole);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: can not switch function", __func__);
        return ret;
    }
    if (isPdV2_0) {
        if (WritePdPortFile(powerRole, dataRole)) {
            HDF_LOGE("%{public}s: WritePdPortFile failed", __func__);
            return HDF_FAILURE;
        }
        currentPortInfo_.portId = portId;
        return HDF_SUCCESS;
    }

    if (currentProtInfo_.powerRole != powerRole) {    
        ret = WritePortFile(powerRole, POWER_ROLE_PATH);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: write powerRole failed, ret: %{public}d", __func__, ret);
            return ret;
        }
    }
    if (currentPortInfo_.dataRole != dataRole) {
        ret = WritePortFile(dataRole, DATA_ROLE_PATH);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: write dataRole failed, ret: %{public}d", __func__, ret);
            return ret;
        }
	if (currentPortInfo_.dataRole == DATA_ROLE_DEVICE && dataRole == DATA_ROLE_HOST) {
	    ret = SwitchFunction(DATA_ROLE_HOST);
	}
	if (currentPortInfo_.dataRole == DATA_ROLE_HOST && dataRole == DATA_ROLE_DEVICE) {
	    ret = SwitchFunction(DATA_ROLE_DEVICE);
	}
    }
    currentPortInfo_.portId = portId;
    currentPortInfo_.powerRole = powerRole;
    currentPortInfo_.dataRole = dataRole;
    return HDF_SUCCESS;
}

int32_t UsbdPort::SwitchFunction(int32_t dataRole)
{
    int32_t ret = HDF_FAILURE;
    if (dataRole == DATA_ROLE_HOST) {
        ret = UsbdFunction::UsbdSetFunction(USB_FUNCTION_NONE);
    }
    if (dataRole == DATA_ROLE_DEVICE) {
        if (usbdFunction::IsHdcOpen()) {
	    ret = UsbdFunction::UsbdSetFunction(USB_FUNCTION_HDC);
	} else {
	    ret = UsbdFunction::UsbdSetFunction(USB_FUNCTION_STORAGE);
	}
    }
    return ret;
}

int32_t UsbdPort::SetPort(
    int32_t portId, int32_t powerRole, int32_t dataRole, UsbdSubscriber *usbdSubscribers, uint32_t len)
{
    int32_t ret = SetPortInit(portId, powerRole, dataRole);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: SetPortInit failed! ret:%{public}d", __func__, ret);
        return ret;
    }
    for (uint32_t i = 0; i < len; i++) {
        if (usbdSubscribers[i].subscriber != nullptr) {
            usbdSubscribers[i].subscriber->PortChangedEvent(currentPortInfo_);
        }
    }

    return HDF_SUCCESS;
}

int32_t UsbdPort::SetUsbPort(int32_t portId, int32_t powerRole, int32_t dataRole,
    HDI::Usb::V2_0::UsbdSubscriber *usbdSubscribers, uint32_t len)
{
    int32_t ret = SetPortInit(portId, powerRole, dataRole);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: SetPortInit failed! ret:%{public}d", __func__, ret);
        UsbReportSysEvent::ReportUsbRecognitionFailSysEvent("SetUsbPort", HDF_FAILURE, "UsbdWaitUdc error");
        return ret;
    }
    currentPortInfos_ = {currentPortInfo_.portId,
        currentPortInfo_.powerRole, currentPortInfo_.dataRole, currentPortInfo_.mode};
    for (uint32_t i = 0; i < len; i++) {
        if (usbdSubscribers[i].subscriber != nullptr) {
            usbdSubscribers[i].subscriber->PortChangedEvent(currentPortInfos_);
        }
    }

    return HDF_SUCCESS;
}

int32_t UsbdPort::QueryPort(int32_t &portId, int32_t &powerRole, int32_t &dataRole, int32_t &mode)
{
    if (path_ == DEFAULT_USB_MODE_PATH) {
        HDF_LOGE("%{public}s: not support", __func__);
        return HDF_SUCCESS;
    }

    portId = currentPortInfo_.portId;
    if (isPdV2_0) {
        QueryPdPort(powerRole, dataRole, mode);
        return HDF_SUCCESS;
    }
    int32_t ret = ReadPortFile(powerRole, POWER_ROLE_PATH);
    if (ret < 0) {
        HDF_LOGE("%{public}s: read power_role failed ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    ret = ReadPortFile(dataRole, DATA_ROLE_PATH);
    if (ret < 0) {
        HDF_LOGE("%{public}s: read data_role failed ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    ret = ReadPortFile(mode, MODE_PATH);
    if (ret < 0) {
        HDF_LOGE("%{public}s: read mode failed ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t UsbdPort::GetSupportedModes(int32_t &supported_modes)
{
    if (isPdV2_0) {
        supported_modes = SUPPORTED_MODES_UFP_DFP;
        return true;
    }

    int32_t fd = OpenPortFile(O_RDONLY, SUPPORTED_MODES_PATH);
    if (fd < 0) {
        HDF_LOGE("%{public}s: file open error fd = %{public}d", __func__, fd);
        return HDF_FAILURE;
    }
    char modeBuf[PATH_MAX] = {'\0'};
    int32_t ret = read(fd, modeBuf, PATH_MAX - 1);
    fdsan_close_with_tag(fd, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));

    if (ret < 0) {
        HDF_LOGE("%{public}s: read error: %{public}s, errno: %{public}d", __func__, path_.c_str(), errno);
        return HDF_FAILURE;
    }
    modeBuf[ret] = '\0';
    static const std::unordered_map<std::string, int32_t> supportedModesMap = {
        {SUPPORTED_MODES_NONE_STR,    SUPPORTED_MODES_NONE},
        {SUPPORTED_MODES_UFP_STR,     SUPPORTED_MODES_UFP},
        {SUPPORTED_MODES_DFP_STR,     SUPPORTED_MODES_DFP},
        {SUPPORTED_MODES_UFP_DFP_STR, SUPPORTED_MODES_UFP_DFP}
    };
    for (const auto& [str, mode] : supportedModesMap) {
        if (strncmp(modeBuf, str.data(), str.length()) == 0) {
            supported_modes = mode;
            HDF_LOGE("%{public}s: read supported_modes: %{public}d", __func__, mode);
            return HDF_SUCCESS;
        }
    }
    HDF_LOGE("%{public}s: read invalid supported_modes: %{public}s", __func__, modeBuf);
    return HDF_FAILURE;
}

int32_t UsbdPort::UpdatePort(int32_t mode, const sptr<IUsbdSubscriber> &subscriber)
{
    if (subscriber == nullptr) {
        HDF_LOGE("%{public}s subscriber is nullptr", __func__);
        return HDF_FAILURE;
    }
    if (isPdV2_0) {
        UpdatePdPort(mode, subscriber);
        return HDF_SUCCESS;
    }
    if (mode > 0 && mode <= PORT_MODE_HOST) {
        int32_t ret = QueryPort(currentPortInfo_.portId,
            currentPortInfo_.powerRole, currentPortInfo_.dataRole, currentPortInfo_.mode);
        if (ret < 0) {
            HDF_LOGE("%{public}s: QueryPort failed ret = %{public}d", __func__, ret);
            return HDF_FAILURE;
        }
        currentPortInfo_.mode = mode;
    } else {
        HDF_LOGE("%{public}s invalid mode:%{public}d", __func__, mode);
        return HDF_FAILURE;
    }
    subscriber->PortChangedEvent(currentPortInfo_);
    return HDF_SUCCESS;
}

int32_t UsbdPort::UpdateUsbPort(int32_t mode, const sptr<V2_0::IUsbdSubscriber> &subscriber)
{
    if (subscriber == nullptr) {
        HDF_LOGE("%{public}s subscriber is nullptr", __func__);
        return HDF_FAILURE;
    }
    if (isPdV2_0) {
        UpdatePdPorts(mode, subscriber);
        return HDF_SUCCESS;
    }
    if (mode > 0 && mode <= PORT_MODE_HOST) {
        int32_t ret = QueryPort(currentPortInfo_.portId,
            currentPortInfo_.powerRole, currentPortInfo_.dataRole, currentPortInfo_.mode);
        if (ret < 0) {
            HDF_LOGE("%{public}s: QueryPort failed ret = %{public}d", __func__, ret);
            return HDF_FAILURE;
        }
        currentPortInfo_.mode = mode;
    } else {
        HDF_LOGE("%{public}s invalid mode:%{public}d", __func__, mode);
        return HDF_FAILURE;
    }

    currentPortInfos_ = {currentPortInfo_.portId,
        currentPortInfo_.powerRole, currentPortInfo_.dataRole, currentPortInfo_.mode};
    subscriber->PortChangedEvent(currentPortInfos_);
    HDF_LOGD("%{public}s exit", __func__);
    return HDF_SUCCESS;
}

int32_t UsbdPort::WritePdPortFile(int32_t powerRole, int32_t dataRole)
{
    std::string modeStr;
    int32_t mode = PORT_MODE_DEVICE;
    if (powerRole == POWER_ROLE_SOURCE && dataRole == DATA_ROLE_HOST) {
        mode = PORT_MODE_HOST;
        modeStr = DATA_ROLE_UFP_STR;
        UsbdFunction::UsbdSetFunction(USB_FUNCTION_NONE);
    }
 
    if (powerRole == POWER_ROLE_SINK && dataRole == DATA_ROLE_DEVICE) {
        mode = PORT_MODE_DEVICE;
        modeStr = DATA_ROLE_DFP_STR;
        UsbdFunction::UsbdSetFunction(USB_FUNCTION_HDC);
    }
    uint32_t len = modeStr.size();
    int32_t fd = OpenPortFile(O_WRONLY | O_TRUNC, "");
    if (fd < 0) {
        HDF_LOGE("%{public}s: file open error fd = %{public}d", __func__, fd);
        return HDF_FAILURE;
    }
    int32_t ret = write(fd, modeStr.c_str(), len);
    close(fd);
    if (ret < 0) {
        HDF_LOGE("%{public}s: write  error", __func__);
        return HDF_FAILURE;
    }
    currentPortInfo_.powerRole = powerRole;
    currentPortInfo_.dataRole = dataRole;
    currentPortInfo_.mode = mode;

    return HDF_SUCCESS;
}

void UsbdPort::QueryPdPort(int32_t &powerRole, int32_t &dataRole, int32_t &mode)
{
    int32_t fd = OpenPortFile(O_RDONLY, "");
    if (fd < 0) {
        return;
    }
    char modeBuf[PATH_MAX] = {'\0'};
    int32_t ret = read(fd, modeBuf, PATH_MAX - 1);
    close(fd);
 
    if (ret < 0) {
        HDF_LOGE("%{public}s: read error: %{public}s", __func__, path_.c_str());
        return;
    }
    if (strcmp(modeBuf, DATA_ROLE_UFP_STR) == 0) {
        powerRole = POWER_ROLE_SOURCE;
        dataRole = DATA_ROLE_HOST;
        mode = PORT_MODE_HOST;
        return;
    }
 
    if (strcmp(modeBuf, DATA_ROLE_DFP_STR) == 0) {
        powerRole = POWER_ROLE_SINK;
        dataRole = DATA_ROLE_DEVICE;
        mode = PORT_MODE_DEVICE;
        return;
    }
 
    HDF_LOGE("%{public}s: read invalid mode: %{public}s", __func__, modeBuf);
    return;
}

void UsbdPort::UpdatePdPort(int32_t mode, const sptr<IUsbdSubscriber> &subscriber)
{
    switch (mode) {
        case PORT_MODE_HOST:
            currentPortInfo_.powerRole = POWER_ROLE_SOURCE;
            currentPortInfo_.dataRole = DATA_ROLE_HOST;
            currentPortInfo_.mode = PORT_MODE_HOST;
            break;
        case PORT_MODE_DEVICE:
            currentPortInfo_.powerRole = POWER_ROLE_SINK;
            currentPortInfo_.dataRole = DATA_ROLE_DEVICE;
            currentPortInfo_.mode = PORT_MODE_DEVICE;
            break;
        default:
            HDF_LOGE("%{public}s invalid mode:%{public}d", __func__, mode);
            return;
    }
    subscriber->PortChangedEvent(currentPortInfo_);
    return;
}

void UsbdPort::UpdatePdPorts(int32_t mode, const sptr<V2_0::IUsbdSubscriber> &subscriber)
{
    switch (mode) {
        case PORT_MODE_HOST:
            currentPortInfo_.powerRole = POWER_ROLE_SOURCE;
            currentPortInfo_.dataRole = DATA_ROLE_HOST;
            currentPortInfo_.mode = PORT_MODE_HOST;
            break;
        case PORT_MODE_DEVICE:
            currentPortInfo_.powerRole = POWER_ROLE_SINK;
            currentPortInfo_.dataRole = DATA_ROLE_DEVICE;
            currentPortInfo_.mode = PORT_MODE_DEVICE;
            break;
        default:
            HDF_LOGE("%{public}s invalid mode:%{public}d", __func__, mode);
            return;
    }
    currentPortInfos_ = {currentPortInfo_.portId,
         currentPortInfo_.powerRole, currentPortInfo_.dataRole, currentPortInfo_.mode};
    subscriber->PortChangedEvent(currentPortInfos_);
    return;
}
} // namespace V1_2
} // namespace Usb
} // namespace HDI
} // namespace OHOS
