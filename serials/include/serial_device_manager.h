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

#ifndef OHOS_HDI_SERIALS_V1_0_SERIAL_DEVICE_MANAGER_H
#define OHOS_HDI_SERIALS_V1_0_SERIAL_DEVICE_MANAGER_H

#include "serial_device.h"
#include "serial_uevent_queue.h"
#include "serial_uevent_handle.h"
#include <memory>
#include <map>
#include <set>
#include <mutex>
#include <unordered_map>

namespace OHOS {
namespace HDI {
namespace Serials {
namespace V1_0 {
class SerialDeviceManager {
public:
    SerialDeviceManager(const SerialDeviceManager&) = delete;
    SerialDeviceManager& operator=(const SerialDeviceManager&) = delete;
    static SerialDeviceManager& GetInstance();
    int32_t Init();
    int32_t Deinit();

    int32_t QueryDevices(std::vector<SerialDeviceInfo>& devices);

    int32_t OpenDevice(const std::string& portName, const SerialConfig& config, const sptr<ISerialDeviceCallback>& cb,
        sptr<ISerialDevice>& device);

private:
    SerialDeviceManager();
    ~SerialDeviceManager();
    std::string ReadSysfsFile(const std::string& path);
    void AddVirtualUsbDevice(
        std::vector<SerialDeviceInfo>& devices, const std::string& name, const std::string& fullPath);
    void AddNormalSerialDevice(std::vector<SerialDeviceInfo>& devices, const std::string& fullPath);
    void OnUeventReceived(const SerialUeventInfo& info);
    std::map<std::string, wptr<SerialDevice>> openDevices_;
    std::map<std::string, SerialDeviceInfo> availableDevices_;
    std::set<std::string> supportTtyhws_;
    std::unique_ptr<SerialUeventQueue> ueventQueue_;
    std::unique_ptr<SerialUeventHandle> ueventHandle_;
    std::mutex mutex_;
};
} // V1_0
} // Serials
} // HDI
} // OHOS

#endif // OHOS_HDI_SERIALS_V1_0_SERIAL_DEVICE_MANAGER_H