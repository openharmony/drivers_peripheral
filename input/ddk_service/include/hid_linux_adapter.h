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

#ifndef HID_LINUX_ADAPTER_H
#define HID_LINUX_ADAPTER_H

#include <stdint.h>
#include <vector>

#include "hid_adapter.h"
#include "v1_0/ihid_ddk.h"

namespace OHOS {
namespace HDI {
namespace Input {
namespace Ddk {
namespace V1_1 {
class LinuxHidOsAdapter : public HidOsAdapter {
public:
    int32_t GetRawInfo(int32_t fd, HidRawDevInfo& rawDevInfo) override;
    int32_t GetRawName(int32_t fd, std::vector<uint8_t>& data) override;
    int32_t GetPhysicalAddress(int32_t fd, std::vector<uint8_t>& data) override;
    int32_t GetRawUniqueId(int32_t fd, std::vector<uint8_t>& data) override;
    int32_t SendReport(int32_t fd, HidReportType reportType, const std::vector<uint8_t>& data) override;
    int32_t GetReport(int32_t fd, HidReportType reportType, std::vector<uint8_t>& data) override;
    int32_t GetReportDescriptor(int32_t fd, std::vector<uint8_t>& data, uint32_t& bytesRead) override;
    virtual ~LinuxHidOsAdapter() = default;
};
} // V1_1
} // Ddk
} // Input
} // HDI
} // OHOS

#endif // HID_LINUX_ADAPTER_H