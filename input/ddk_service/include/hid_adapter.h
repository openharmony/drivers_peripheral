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

#ifndef HID_ADAPTER_H
#define HID_ADAPTER_H

#include <stdint.h>
#include <vector>

#include "v1_1/ihid_ddk.h"

namespace OHOS {
namespace HDI {
namespace Input {
namespace Ddk {
namespace V1_1 {
class HidOsAdapter {
public:
    virtual int32_t GetRawInfo(int32_t fd, HidRawDevInfo& rawDevInfo) = 0;
    virtual int32_t GetRawName(int32_t fd, std::vector<uint8_t>& data) = 0;
    virtual int32_t GetPhysicalAddress(int32_t fd, std::vector<uint8_t>& data) = 0;
    virtual int32_t GetRawUniqueId(int32_t fd, std::vector<uint8_t>& data) = 0;
    virtual int32_t SendReport(int32_t fd, HidReportType reportType, const std::vector<uint8_t>& data) = 0;
    virtual int32_t GetReport(int32_t fd, HidReportType reportType, std::vector<uint8_t>& data) = 0;
    virtual int32_t GetReportDescriptor(int32_t fd, std::vector<uint8_t>& data, uint32_t& bytesRead) = 0;
};
} // V1_1
} // Ddk
} // Input
} // HDI
} // OHOS

#endif // HID_ADAPTER_H