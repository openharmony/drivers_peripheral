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

#include <fstream>
#include <iostream>
#include <sstream>
#include <hdf_base.h>
#include "hdf_log.h"
#include "usbd_wrapper.h"
#include "ddk_sysfs_dev_node.h"

#define HDF_LOG_TAG      ddk_sysfs_dev_node

const std::filesystem::path SysfsDevNode::devDir_("/sys/bus/usb/devices");
const std::regex SysfsDevNode::intfPathRegex_("([0-9]+)-([^:]+):[0-9]+\\.([0-9]+)");

const int GROUP_ONE = 1;
const int GROUP_TWO = 2;
const int GROUP_THREE = 3;

SysfsDevNode::SysfsDevNode(uint32_t busNum, uint32_t devNum, uint8_t intfNum, const std::string& prefix) noexcept
{
    busNum_ = busNum;
    devNum_ = devNum;
    intfNum_ = intfNum;
    prefix_ = prefix;
}

int32_t SysfsDevNode::FindPath(std::string& devNodePath)
{
    for (const auto& entry : fs::directory_iterator(devDir_)) {
        if (!fs::is_directory(entry.status())) {
            continue;
        }

        std::string intfDirName = entry.path().filename().string();
        std::smatch match;
        if (!std::regex_match(intfDirName, match, intfPathRegex_)) {
            continue;
        }

        if (match.str(GROUP_ONE) != std::to_string(busNum_) || match.str(GROUP_THREE) != std::to_string(intfNum_)) {
            continue;
        }

        auto devPath = std::filesystem::path(devDir_).append(match.str(GROUP_ONE) + "-" + match.str(GROUP_TWO))
            .append("devnum");
        std::optional<std::string> devNumInfo = GetContent(devPath);
        if (!devNumInfo.has_value() || devNumInfo.value().find(std::to_string(devNum_)) == std::string::npos) {
            continue;
        }

        std::error_code errorCode;
        for (fs::recursive_directory_iterator iter(entry, errorCode), end; iter != end; ++iter) {
            if (errorCode) {
                HDF_LOGE("Error: %{public}s, at %{public}s", errorCode.message().c_str(),
                    iter->path().string().c_str());
                errorCode.clear();
                continue;
            }

            std::string filename = iter->path().filename().string();
            size_t pos = filename.find(prefix_);
            if (pos == 0 && filename != prefix_) {
                devNodePath = "/dev/" + filename;
                return HDF_SUCCESS;
            }
        }
    }

    return HDF_FAILURE;
}

std::optional<std::string> SysfsDevNode::GetContent(const std::string& filePath)
{
    std::ifstream file(filePath);
    if (!file.is_open()) {
        return std::nullopt;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();
    return buffer.str();
}
