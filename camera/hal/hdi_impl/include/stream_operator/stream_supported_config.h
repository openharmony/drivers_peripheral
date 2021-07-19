/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef CAMERA_HOST_HCS_DEAL_H
#define CAMERA_HOST_HCS_DEAL_H

#include <string>
#include <vector>
#include "utils.h"
#include "device_resource_if.h"

namespace OHOS::Camera {
class StreamSupportedConfig {
public:
    StreamSupportedConfig(const std::string &pathName);
    virtual ~StreamSupportedConfig();
    StreamSupportedConfig(const StreamSupportedConfig &other) = delete;
    StreamSupportedConfig(StreamSupportedConfig &&other) = delete;
    StreamSupportedConfig& operator=(const StreamSupportedConfig &other) = delete;
    StreamSupportedConfig& operator=(StreamSupportedConfig &&other) = delete;

public:
    void SetHcsPathName(const std::string &pathName);
    RetCode Init();
    void GetStreamSupporteds(std::vector<std::shared_ptr<StreamSupported>> &streamSupporteds) const;

private:
    RetCode DealHcsData();
    RetCode DealSteamSupported(const struct DeviceResourceNode &node);
    RetCode DealSteamInfo(const struct DeviceResourceNode &node,
        std::vector<std::shared_ptr<StreamInfo>> &streamInfos);
    void FullStreamInfo(uint32_t value, int index,
        std::shared_ptr<StreamInfo> &streamInfo);

private:
    std::string pathName_;
    std::vector<std::shared_ptr<StreamSupported>> streamSupporteds_;
    const struct DeviceResourceIface *devResInstance_ = nullptr;
    const struct DeviceResourceNode *rootNode_ = nullptr;
};
} // namespace OHOS::CameraHost
#endif /* CAMERA_HOST_HCS_DEAL_H */
