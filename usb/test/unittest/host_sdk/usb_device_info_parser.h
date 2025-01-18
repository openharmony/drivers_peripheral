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

#ifndef USB_DEVICE_INFO_PARSER_H
#define USB_DEVICE_INFO_PARSER_H

#include <fstream>
#include <regex>
#include <optional>
#include <string>

struct UsbDeviceInfo {
    uint32_t busNum;
    uint32_t devNum;
    std::string productNum;
};

class UsbDeviceInfoParser {
public:
    UsbDeviceInfoParser();
    std::optional<UsbDeviceInfo> Find(const std::string& productRegex);

private:
    std::regex devInfoRegex_;
};
#endif
