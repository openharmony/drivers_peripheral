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

#ifndef DDK_SYSFS_DEVICES_PARSER_H
#define DDK_SYSFS_DEVICES_PARSER_H

#include <filesystem>
#include <optional>
#include <regex>

namespace fs = std::filesystem;

class SysfsDevNode {
public:
    SysfsDevNode(uint32_t busNum, uint32_t devNum, uint8_t intfNum, const std::string& prefix) noexcept;
    int32_t FindPath(std::string& path);

private:
    std::optional<std::string> GetContent(const std::string& filePath);

private:
    static const std::filesystem::path devDir_;
    static const std::regex intfPathRegex_;

    uint32_t busNum_;
    uint32_t devNum_;
    uint8_t intfNum_;
    std::string prefix_;
    std::regex fileNameRegex_;
};

#endif
