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

#include <iostream>
#include <sstream>
#include "usb_device_info_parser.h"

typedef enum {
    POSTION_ONE = 1,
    POSTION_TWO = 2,
} POSITION;

UsbDeviceInfoParser::UsbDeviceInfoParser()
    : devInfoRegex_(".*Bus=([0-9]+).*Dev#=\\s*([0-9]+).*")
{
}

std::optional<UsbDeviceInfo> UsbDeviceInfoParser::Find(const std::string& productRegex)
{
    std::ifstream filePath("/sys/kernel/debug/usb/devices");
    std::string line;
    UsbDeviceInfo deviceInfo;
    const std::string prefix = "S:  Product=";
    while (std::getline(filePath, line)) {
        if (line.empty()) {
            continue;
        }

        if (line[0] == 'T') {
            std::smatch match;
            if (!std::regex_match(line, match, devInfoRegex_)) {
                std::cout << __func__ << ":" << __LINE__ << " regex_match failed" << std::endl;
                return std::nullopt;
            }

            deviceInfo.busNum = std::stoi(match.str(POSTION_ONE));
            deviceInfo.devNum = std::stoi(match.str(POSTION_TWO));
        }

        if (line.find(prefix) == std::string::npos) {
            continue;
        }

        auto product = line.substr(prefix.size(), line.size());
        std::smatch match;
        if (!std::regex_match(product, match, std::regex(productRegex))) {
            std::cout << __func__ << ":" << __LINE__ << " regex_match [" << product << "] with ["
                << productRegex << "] failed" << std::endl;
            continue;
        }
        deviceInfo.productNum = product;
        return std::optional<UsbDeviceInfo>(deviceInfo);
    }

    return std::nullopt;
}
