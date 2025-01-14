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

#include "hid_liteos_adapter.h"

#include <hdf_base.h>
#include "input_uhdf_log.h"
#include <unistd.h>
#include <fcntl.h>
#include <iostream>
#include <sys/ioctl.h>
#include <poll.h>
#include <memory.h>
#include <securec.h>

#define HDF_LOG_TAG hid_liteos_adapter

namespace OHOS {
namespace HDI {
namespace Input {
namespace Ddk {
namespace V1_1 {

int32_t LiteosHidOsAdapter::GetRawInfo(int32_t fd, HidRawDevInfo& rawDevInfo)
{
    return HID_DDK_INVALID_OPERATION;
}

int32_t LiteosHidOsAdapter::GetRawName(int32_t fd, std::vector<uint8_t>& data)
{
    return HID_DDK_INVALID_OPERATION;
}

int32_t LinuxHidOsAdapter::GetPhysicalAddress(int32_t fd, std::vector<uint8_t>& data)
{
    return HID_DDK_INVALID_OPERATION;
}

int32_t LinuxHidOsAdapter::GetRawUniqueId(int32_t fd, std::vector<uint8_t>& data)
{
    return HID_DDK_INVALID_OPERATION;
}

int32_t SendReport(int32_t fd, HidReportType reportType, const std::vector<uint8_t>& data)
{
    return HID_DDK_INVALID_OPERATION;
}

int32_t GetReport(int32_t fd, HidReportType reportType, std::vector<uint8_t>& data)
{
    return HID_DDK_INVALID_OPERATION;
}

int32_t GetReportDescriptor(int32_t fd, std::vector<uint8_t>& data, uint32_t& bytesRead)
{
    return HID_DDK_INVALID_OPERATION;
}

} // V1_1
} // Ddk
} // Input
} // HDI
} // OHOS
