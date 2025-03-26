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

#ifndef HID_DDK_SERVICE_H
#define HID_DDK_SERVICE_H

#include "hid_adapter.h"
#include "v1_1/ihid_ddk.h"
#include <mutex>
#include <unordered_map>

namespace OHOS {
namespace HDI {
namespace Input {
namespace Ddk {
namespace V1_1 {
class HidDdkService : public IHidDdk {
public:
    HidDdkService(std::shared_ptr<HidOsAdapter>& osAdapter) : osAdapter_(osAdapter) {}
    virtual ~HidDdkService() = default;

    int32_t CreateDevice(const Hid_Device& hidDevice,
         const Hid_EventProperties& hidEventProperties, uint32_t& deviceId) override;

    int32_t EmitEvent(uint32_t deviceId, const std::vector<Hid_EmitItem>& items) override;

    int32_t DestroyDevice(uint32_t deviceId) override;

    int32_t Init() override;

    int32_t Release() override;

    int32_t Open(uint64_t deviceId, uint8_t interfaceIndex, HidDeviceHandle& dev) override;

    int32_t Close(const HidDeviceHandle& dev) override;

    int32_t Write(const HidDeviceHandle& dev, const std::vector<uint8_t>& data, uint32_t& bytesWritten) override;

    int32_t ReadTimeout(const HidDeviceHandle& dev, std::vector<uint8_t>& data, uint32_t buffSize, int32_t timeout,
        uint32_t& bytesRead) override;

    int32_t SetNonBlocking(const HidDeviceHandle& dev, int32_t nonBlock) override;

    int32_t GetRawInfo(const HidDeviceHandle& dev, HidRawDevInfo& rawDevInfo) override;

    int32_t GetRawName(const HidDeviceHandle& dev, std::vector<uint8_t>& data, uint32_t buffSize) override;

    int32_t GetPhysicalAddress(const HidDeviceHandle& dev, std::vector<uint8_t>& data, uint32_t buffSize) override;

    int32_t GetRawUniqueId(const HidDeviceHandle& dev, std::vector<uint8_t>& data, uint32_t buffSize) override;

    int32_t SendReport(const HidDeviceHandle& dev, HidReportType reportType, const std::vector<uint8_t>& data) override;

    int32_t GetReport(const HidDeviceHandle& dev, HidReportType reportType, uint8_t reportNumber,
        std::vector<uint8_t>& data, uint32_t buffSize) override;

    int32_t GetReportDescriptor(const HidDeviceHandle& dev, std::vector<uint8_t>& buf, uint32_t buffSize,
        uint32_t& bytesRead) override;

private:
    std::shared_ptr<HidOsAdapter> osAdapter_;
    std::mutex fileDescriptorLock_;
    std::unordered_map<uint32_t, FILE*> fileDescriptorMap_;
};
} // V1_1
} // Ddk
} // Input
} // HDI
} // OHOS

#endif // HID_DDK_SERVICE_H