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

#include "serialread_fuzzer.h"
#include "v1_0/iserial_interface.h"

using namespace OHOS::HDI::Usb::Serial::V1_0;

namespace {
    constexpr int32_t OK = 0;
}

namespace OHOS {
namespace SERIAL {
    bool SerialReadFuzzTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t) + sizeof(uint32_t) + sizeof(uint32_t)) {
            return false;
        }
        auto serialInterface = ISerialInterface::Get("serial_interface_service", true);
        const int32_t portId = *reinterpret_cast<const int32_t *>(data);
        const uint32_t readSize = *reinterpret_cast<const uint32_t *>(data + sizeof(uint32_t));
        const uint32_t timeOut = *reinterpret_cast<const uint32_t *>(data + sizeof(uint32_t) + sizeof(uint32_t));
        std::vector<uint8_t> buffer;
        if (serialInterface->SerialRead(portId, buffer, readSize, timeOut) != OK) {
            return false;
        }
        return true;
    }
} // SERIAL
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SERIAL::SerialReadFuzzTest(data, size);
    return 0;
}

