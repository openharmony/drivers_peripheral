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

#include "stream_supported_config.h"
#include "hcs_dm_parser.h"

namespace OHOS::Camera {
StreamSupportedConfig::StreamSupportedConfig(const std::string &pathName)
    : pathName_(pathName)
{
}

StreamSupportedConfig::~StreamSupportedConfig()
{
    ReleaseHcsTree();
    devResInstance_ = nullptr;
    rootNode_ = nullptr;
    CAMERA_LOGI("StreamSupportedConfig::~StreamSupportedConfig()");
}

void StreamSupportedConfig::SetHcsPathName(const std::string &pathName)
{
    pathName_ = pathName;
}

RetCode StreamSupportedConfig::Init()
{
    devResInstance_ = DeviceResourceGetIfaceInstance(HDF_CONFIG_SOURCE);
    if (devResInstance_ == nullptr) {
        CAMERA_LOGE("get hcs interface failed.");
        return RC_ERROR;
    }
    SetHcsBlobPath(pathName_.c_str());
    rootNode_ = devResInstance_->GetRootNode();
    if (rootNode_ == nullptr) {
        CAMERA_LOGE("GetRootNode failed");
        return RC_ERROR;
    }

    if (rootNode_->name != nullptr) {
        CAMERA_LOGI("rootNode_ = %s", rootNode_->name);
    }

    DealHcsData();

    return RC_OK;
}

RetCode StreamSupportedConfig::DealHcsData()
{
    const struct DeviceResourceNode *streamSupportedConfig =
        devResInstance_->GetChildNode(rootNode_, "stream_supported_config");
    if (streamSupportedConfig == nullptr) {
        return RC_ERROR;
    }
    if (streamSupportedConfig->name != nullptr) {
        CAMERA_LOGI("streamSupportedConfig = %s", streamSupportedConfig->name);
    }

    const struct DeviceResourceNode *childNodeTmp = nullptr;
    DEV_RES_NODE_FOR_EACH_CHILD_NODE(streamSupportedConfig, childNodeTmp) {
        if (childNodeTmp != nullptr && childNodeTmp->name != nullptr) {
            std::string nodeName = std::string(childNodeTmp->name);
            CAMERA_LOGI("streamSupportedConfig subnode name = %s", nodeName.c_str());
            if (nodeName.find(std::string("supported"), 0) != std::string::npos) {
                DealSteamSupported(*childNodeTmp);
            }
        }
    }

    return RC_OK;
}

RetCode StreamSupportedConfig::DealSteamSupported(const struct DeviceResourceNode &node)
{
    if (node.name != nullptr) {
        CAMERA_LOGI("DealSteamSupported entry nodeName = %s", node.name);
    }

    std::shared_ptr<StreamSupported> streamSupported = std::make_shared<StreamSupported>();
    const char *operationMode = nullptr;
    int ret = devResInstance_->GetString(&node, "operationMode", &operationMode, nullptr);
    if (ret != 0) {
        CAMERA_LOGW("####deal operationMode failed.");
        return RC_ERROR;
    }
    if (strcmp(operationMode, "NORMAL") == 0) {
        streamSupported->operationMode_ = NORMAL;
    } else { // 预留其他模式
        streamSupported->operationMode_ = NORMAL;
    }

    const char *streamSupportType = nullptr;
    ret = devResInstance_->GetString(&node, "streamSupportType", &streamSupportType, nullptr);
    if (ret != 0) {
        CAMERA_LOGW("####deal streamSupportType failed.");
        return RC_ERROR;
    }
    if (strcmp(streamSupportType, "DYNAMIC_SUPPORTED") == 0) {
        streamSupported->streamSupportType_ = DYNAMIC_SUPPORTED;
    } else if (strcmp(streamSupportType, "RE_CONFIGURED_REQUIRED") == 0) {
        streamSupported->streamSupportType_ = RE_CONFIGURED_REQUIRED;
    } else {
        streamSupported->streamSupportType_ = NOT_SUPPORTED;
    }

    const struct DeviceResourceNode *streamInfoNode = nullptr;
    DEV_RES_NODE_FOR_EACH_CHILD_NODE(&node, streamInfoNode) {
        if (streamInfoNode != nullptr && streamInfoNode->name != nullptr) {
            std::string nodeName = std::string(streamInfoNode->name);
            CAMERA_LOGI("streamInfo node name = %s", nodeName.c_str());
            if (nodeName.find(std::string("streamInfo"), 0) != std::string::npos) {
                DealSteamInfo(*streamInfoNode, streamSupported->streamInfos_);
            }
        }
    }
    streamSupporteds_.push_back(streamSupported);

    return RC_OK;
}

RetCode StreamSupportedConfig::DealSteamInfo(const struct DeviceResourceNode &node,
    std::vector<std::shared_ptr<StreamInfo>> &streamInfos)
{
    const std::vector<std::string> streamInfoFiled = {
        "width",
        "height",
        "format",
        "dataspace",
        "intent",
        "tunneledMode",
        "minFrameDuration"
    };
    std::shared_ptr<StreamInfo> streamInfo = std::make_unique<StreamInfo>();
    uint32_t value = 0;
    int ret = 0;
    for (int i = 0; i < streamInfoFiled.size(); i++) {
        auto &filed = streamInfoFiled.at(i);
        ret = devResInstance_->GetUint32(&node, filed.c_str(), &value, 0);
        if (ret != 0) {
            return RC_ERROR;
        }
        FullStreamInfo(value, i, streamInfo);
    }
    streamInfos.push_back(streamInfo);

    return RC_OK;
}

using StreamInfoIdx = enum _StreamInfoIdx : int {
    WIDTH = 0,
    HEIGHT = 1,
    FORMAT = 2,
    DATA_SPACE = 3,
    INTEMT = 4,
    TUNNELED_MODE = 5,
    MIN_FRAME_DURATION = 6,
};
void StreamSupportedConfig::FullStreamInfo(uint32_t value, int index,
    std::shared_ptr<StreamInfo> &streamInfo)
{
    switch (index) {
        case WIDTH:
            streamInfo->width_ = value;
            break;
        case HEIGHT:
            streamInfo->height_ = value;
            break;
        case FORMAT:
            streamInfo->format_ = value;
            break;
        case DATA_SPACE:
            streamInfo->datasapce_ = value;
            break;
        case INTEMT:
            streamInfo->intent_ = static_cast<StreamIntent>(value);
            break;
        case TUNNELED_MODE:
            streamInfo->tunneledMode_ = value;
            break;
        case MIN_FRAME_DURATION:
            streamInfo->minFrameDuration_ = value;
            break;
        default:
            break;
    }
}

void StreamSupportedConfig::GetStreamSupporteds(
    std::vector<std::shared_ptr<StreamSupported>> &streamSupporteds) const
{
    streamSupporteds = streamSupporteds_;
}
} // namespace OHOS::CameraHost
