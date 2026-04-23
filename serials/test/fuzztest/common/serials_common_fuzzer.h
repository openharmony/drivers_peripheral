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

#ifndef SERIALS_COMMON_FUZZER_H
#define SERIALS_COMMON_FUZZER_H

#include "v1_0/serial_types.h"
#include "hdf_log.h"
#include <cstdint>
#include <cstdlib>
#include <vector>
#include <string>

namespace OHOS {
namespace HDI {
namespace Serials {
namespace V1_0 {

const size_t FUZZ_THRESHOLD = 10;
constexpr int32_t FUZZ_MAX_DATA_SIZE = 4096;
constexpr int32_t FUZZ_MAX_PORT_NAME_LEN = 256;
constexpr int32_t FUZZ_DEFAULT_BAUD_RATE = 115200;
constexpr int32_t FUZZ_DEFAULT_DATA_BITS = 8;
constexpr int32_t FUZZ_DEFAULT_STOP_BITS = 1;
constexpr int32_t FUZZ_DEFAULT_PARITY = 0;

const int32_t VALID_BAUD_RATES[] = {
    50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800,
    9600, 19200, 38400, 57600, 115200, 230400, 460800, 500000,
    576000, 921600, 1000000, 1152000, 1500000, 2000000, 2500000,
    3000000, 3500000, 4000000
};

const int32_t VALID_DATA_BITS[] = {5, 6, 7, 8};
const int32_t VALID_STOP_BITS[] = {1, 2};
const int32_t VALID_PARITY[] = {0, 1, 2};

template<class T>
uint32_t GetArrLength(const T& arr)
{
    return sizeof(arr) / sizeof(arr[0]);
}

inline int32_t GetValidBaudRate(int32_t index)
{
    uint32_t len = GetArrLength(VALID_BAUD_RATES);
    if (len == 0) {
        return 115200;
    }
    uint32_t safeIndex = static_cast<uint32_t>(std::abs(index)) % len;
    return VALID_BAUD_RATES[safeIndex];
}

inline int32_t GetValidDataBits(int32_t index)
{
    uint32_t len = GetArrLength(VALID_DATA_BITS);
    if (len == 0) {
        return 8;
    }
    uint32_t safeIndex = static_cast<uint32_t>(std::abs(index)) % len;
    return VALID_DATA_BITS[safeIndex];
}

inline int32_t GetValidStopBits(int32_t index)
{
    uint32_t len = GetArrLength(VALID_STOP_BITS);
    if (len == 0) {
        return 1;
    }
    uint32_t safeIndex = static_cast<uint32_t>(std::abs(index)) % len;
    return VALID_STOP_BITS[safeIndex];
}

inline int32_t GetValidParity(int32_t index)
{
    uint32_t len = GetArrLength(VALID_PARITY);
    if (len == 0) {
        return 0;
    }
    uint32_t safeIndex = static_cast<uint32_t>(std::abs(index)) % len;
    return VALID_PARITY[safeIndex];
}

inline SerialConfig GetDefaultConfig()
{
    SerialConfig config;
    config.baudRate = FUZZ_DEFAULT_BAUD_RATE;
    config.dataBits = FUZZ_DEFAULT_DATA_BITS;
    config.stopBits = FUZZ_DEFAULT_STOP_BITS;
    config.parity = FUZZ_DEFAULT_PARITY;
    config.rtscts = false;
    config.xon = false;
    config.xoff = false;
    config.xany = false;
    return config;
}

inline std::string GetFuzzPortName(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return "/dev/ttyUSB0";
    }
    size_t maxLen = static_cast<size_t>(FUZZ_MAX_PORT_NAME_LEN);
    size_t len = (size > maxLen) ? maxLen : size;
    std::string portName(reinterpret_cast<const char*>(data), len);
    return "/dev/" + portName;
}

} // V1_0
} // Serials
} // HDI
} // OHOS

#endif // SERIALS_COMMON_FUZZER_H