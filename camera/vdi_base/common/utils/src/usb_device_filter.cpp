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

#include "usb_device_filter.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <dirent.h>
#include <unistd.h>
#include <camera.h>

#ifdef CAMERA_BUILT_ON_OHOS_LITE
#include "parameter.h"
#else
#include "parameters.h"
#endif

namespace OHOS::Camera {

namespace {
constexpr uint8_t HEX_DIGIT_SHIFT = 4;
constexpr uint8_t HEX_DIGIT_OFFSET = 10;
} // anonymous namespace

UsbDeviceFilter& UsbDeviceFilter::GetInstance()
{
    static UsbDeviceFilter instance;
    return instance;
}

UsbDeviceFilter::UsbDeviceFilter()
{
    // Read system parameter on construction
#ifdef CAMERA_BUILT_ON_OHOS_LITE
    std::string config = OHOS::GetParameter("const.camera.setting.usb_device_filter.config", "");
#else
    std::string config = OHOS::system::GetParameter("const.camera.setting.usb_device_filter.config", "");
#endif
    ParseConfig(config);
}

uint16_t UsbDeviceFilter::HexToUint16(const std::string& hexStr)
{
    if (hexStr.empty()) {
        return 0;
    }
    std::string lowerStr = hexStr;
    // Convert to lowercase for consistent parsing
    std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    uint16_t result = 0;
    for (char c : lowerStr) {
        result <<= HEX_DIGIT_SHIFT;
        if (c >= '0' && c <= '9') {
            result |= (c - '0');
        } else if (c >= 'a' && c <= 'f') {
            result |= (c - 'a' + HEX_DIGIT_OFFSET);
        } else {
            return 0; // Invalid hex character
        }
    }
    return result;
}

void UsbDeviceFilter::ParseConfig(const std::string& config)
{
    std::lock_guard<std::mutex> lock(mutex_);

    // Cache config to avoid re-parsing if unchanged
    if (config == cachedConfig_) {
        return;
    }
    cachedConfig_ = config;
    filterList_.clear();

    if (config.empty()) {
        CAMERA_LOGI("USB filter config is empty, no devices will be blocked");
        return;
    }

    // Parse "vid:pid,vid:pid" format
    std::istringstream ss(config);
    std::string token;
    while (std::getline(ss, token, ',')) {
        // Trim whitespace
        token.erase(0, token.find_first_not_of(" \t"));
        token.erase(token.find_last_not_of(" \t") + 1);

        size_t colonPos = token.find(':');
        if (colonPos == std::string::npos || colonPos == 0 || colonPos == token.length() - 1) {
            CAMERA_LOGW("Invalid filter token: %{public}s", token.c_str());
            continue;
        }

        std::string vidStr = token.substr(0, colonPos);
        std::string pidStr = token.substr(colonPos + 1);

        uint16_t vid = HexToUint16(vidStr);
        uint16_t pid = HexToUint16(pidStr);
        if (vid != 0 || pid != 0) {
            filterList_.push_back({vid, pid});
            CAMERA_LOGI("Added USB filter: VID=0x%{public}04x, PID=0x%{public}04x", vid, pid);
        }
    }

    CAMERA_LOGI("Parsed %{public}zu USB device filters", filterList_.size());
}

std::string UsbDeviceFilter::GetSysfsDevicePath(const std::string& videoPath)
{
    // Extract video device name from path (e.g. "video0" from "/dev/video0")
    std::string videoName;
    size_t lastSlash = videoPath.find_last_of('/');
    if (lastSlash != std::string::npos) {
        videoName = videoPath.substr(lastSlash + 1);
    } else {
        videoName = videoPath;
    }

    // Build sysfs path: /sys/class/video4linux/videoX/device
    std::string sysfsPath = "/sys/class/video4linux/" + videoName + "/device";
    return sysfsPath;
}

std::pair<uint16_t, uint16_t> UsbDeviceFilter::ReadVidPidFromSysfs(const std::string& videoDevPath)
{
    std::string sysfsPath;
    if (videoDevPath.find("/dev/") == 0) {
        sysfsPath = GetSysfsDevicePath(videoDevPath);
    } else {
        // videoDevPath is like /sys/class/video4linux/video10
        sysfsPath = videoDevPath + "/device";
    }
    // sysfsPath now points to .../device (USB Interface)
    // Going up one level from the interface gives us the USB Device
    sysfsPath += "/..";

    std::string vidPath = sysfsPath + "/idVendor";
    std::string pidPath = sysfsPath + "/idProduct";

    uint16_t vid = 0;
    uint16_t pid = 0;

    // Read idVendor
    std::ifstream vidFile(vidPath);
    if (vidFile.is_open()) {
        std::string vidStr;
        vidFile >> vidStr;
        vid = HexToUint16(vidStr);
        vidFile.close();
    }

    // Read idProduct
    std::ifstream pidFile(pidPath);
    if (pidFile.is_open()) {
        std::string pidStr;
        pidFile >> pidStr;
        pid = HexToUint16(pidStr);
        pidFile.close();
    }

    return {vid, pid};
}

bool UsbDeviceFilter::IsBlocked(uint16_t vid, uint16_t pid)
{
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& filter : filterList_) {
        if (filter.first == vid && filter.second == pid) {
            CAMERA_LOGI("Device blocked: VID=0x%{public}04x, PID=0x%{public}04x", vid, pid);
            return true;
        }
    }
    return false;
}

bool UsbDeviceFilter::IsBlockedByVideoPath(const std::string& videoPath)
{
    auto [vid, pid] = ReadVidPidFromSysfs(videoPath);
    if (vid == 0 && pid == 0) {
        CAMERA_LOGD("Could not read VID/PID from %{public}s", videoPath.c_str());
        return false;
    }

    // Log VID/PID for every detected USB camera for debugging
    CAMERA_LOGI("USB camera detected: VID=0x%{public}04x, PID=0x%{public}04x", vid, pid);
    return IsBlocked(vid, pid);
}

void UsbDeviceFilter::Reset()
{
    std::lock_guard<std::mutex> lock(mutex_);
    filterList_.clear();
    cachedConfig_.clear();
}

} // namespace OHOS::Camera
