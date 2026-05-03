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

#ifndef USB_DEVICE_FILTER_H
#define USB_DEVICE_FILTER_H

#include <string>
#include <vector>
#include <cstdint>
#include <mutex>
#include <map>

namespace OHOS::Camera {

class UsbDeviceFilter {
public:
    static UsbDeviceFilter& GetInstance();

    // Parse config string like "1214:5678,abcd:1234"
    void ParseConfig(const std::string& config);

    // Read VID/PID from sysfs path (e.g. /sys/class/video4linux/video0/device)
    // Returns pair<vid, pid>, or pair<0,0> if not found
    std::pair<uint16_t, uint16_t> ReadVidPidFromSysfs(const std::string& videoDevPath);

    // Check if device with given VID/PID should be blocked
    bool IsBlocked(uint16_t vid, uint16_t pid);

    // Check device by uevent PRODUCT string (format: "vid/pid/bcd")
    // This is the uevent-based approach, no sysfs access needed
    bool IsBlockedByProduct(const std::string& product);

    // Convenience method: check device by video device path (e.g. /dev/video0)
    bool IsBlockedByVideoPath(const std::string& videoPath);

    // Uevent processing functions (static, thread-safe)
    static void ProcessUsbInterfaceUevent(char* buf, unsigned int len, const std::string& action);
    static std::string GetProductFromInterfaceMapping(const std::string& devPath);
    static std::string ParseUeventAction(char* buf, unsigned int len);
    static bool CheckUeventField(char* buf, unsigned int len, const std::string& field);
    static std::string ParseUeventDevPath(char* buf, unsigned int len);

    // For unit test: reset filter list and cached config
    void Reset();

    // Convert hex string to uint16_t (handles lowercase like "0bda")
    // Public for unit test access
    uint16_t HexToUint16(const std::string& hexStr);

private:
    UsbDeviceFilter();
    ~UsbDeviceFilter() = default;

    // Get sysfs device path from video device path
    std::string GetSysfsDevicePath(const std::string& videoPath);

    // Parse PRODUCT string "vid/pid/bcd" to vid/pid pair
    std::pair<uint16_t, uint16_t> ParseProductString(const std::string& product);

    // Private static members for uevent processing
    static std::map<std::string, std::string> usbInterfaceProductMap_;
    static std::mutex usbInterfaceMapLock_;

    std::vector<std::pair<uint16_t, uint16_t>> filterList_;
    std::mutex mutex_;
    std::string cachedConfig_;
};

} // namespace OHOS::Camera

#endif // USB_DEVICE_FILTER_H