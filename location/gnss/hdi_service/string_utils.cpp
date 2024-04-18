/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "string_utils.h"

namespace OHOS {
namespace HDI {
namespace Location {
static constexpr uint8_t HEX_OFFSET = 4;
static constexpr uint8_t STEP_2BIT = 2;

StringUtils::StringUtils() {}

StringUtils::~StringUtils() {}

uint16_t StringUtils::HexCharToInt(char c)
{
    const uint8_t decimal = 10;
    if (c >= '0' && c <= '9') {
        return (c - '0');
    }
    if (c >= 'A' && c <= 'F') {
        return (c - 'A' + decimal);
    }
    if (c >= 'a' && c <= 'f') {
        return (c - 'a' + decimal);
    }
    return 0;
}

std::vector<uint8_t> StringUtils::HexToByteVector(const std::string &str)
{
    std::vector<uint8_t> ret;
    int sz = static_cast<int>(str.length());
    if (sz <= 0) {
        return ret;
    }
    for (int i = 0; i < (sz - 1); i += STEP_2BIT) {
        auto temp = static_cast<uint8_t>((HexCharToInt(str.at(i)) << HEX_OFFSET) | HexCharToInt(str.at(i + 1)));
        ret.push_back(temp);
    }
    return ret;
}

} // namespace Location
} // namespace HDI
} // namespace OHOS