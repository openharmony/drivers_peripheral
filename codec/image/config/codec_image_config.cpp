/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <array>
#include "codec_image_config.h"
#include "codec_log_wrapper.h"
namespace {
    constexpr char NODE_IMAGE_HARDWARE_ENCODERS[] = "ImageHwEncoders";
    constexpr char NODE_IMAGE_HARDWARE_DECODERS[] = "ImageHwDecoders";

    constexpr char CODEC_CONFIG_KEY_ROLE[] = "role";
    constexpr char CODEC_CONFIG_KEY_TYPE[] = "type";
    constexpr char CODEC_CONFIG_KEY_NAME[] = "name";
    constexpr char CODEC_CONFIG_KEY_MAX_SAMPLE[] = "maxSample";
    constexpr char CODEC_CONFIG_KEY_MAX_WIDTH[] = "maxWidth";
    constexpr char CODEC_CONFIG_KEY_MAX_HEIGHT[] = "maxHeight";
    constexpr char CODEC_CONFIG_KEY_MIN_WIDTH[] = "minWidth";
    constexpr char CODEC_CONFIG_KEY_MIN_HEIGHT[] = "minHeight";
    constexpr char CODEC_CONFIG_KEY_MAX_INST[] = "maxInst";
    constexpr char CODEC_CONFIG_KEY_WIDTH_ALIGNMENT[] = "widthAlignment";
    constexpr char CODEC_CONFIG_KEY_HEIGHT_ALIGNMENT[] = "heightAlignment";
    constexpr char CODEC_CONFIG_KEY_IS_SOFTWARE_CODEC[] = "isSoftwareCodec";
    constexpr char CODEC_CONFIG_KEY_SUPPORT_PIXEL_FMTS[] = "supportPixelFmts";
}
namespace OHOS {
namespace HDI {
namespace Codec {
namespace Image {
namespace V2_1 {
CodecImageConfig CodecImageConfig::config_;

CodecImageConfig::CodecImageConfig()
{
    node_.name = nullptr;
    node_.hashValue = 0;
    node_.attrData = nullptr;
    node_.parent = nullptr;
    node_.child = nullptr;
    node_.sibling = nullptr;
}

void CodecImageConfig::Init(const struct DeviceResourceNode &node)
{
    node_ = node;
    const uint32_t count = 2; // encoder and decoder
    const static std::array<std::string, count> codecGroupsNodeName = {
        NODE_IMAGE_HARDWARE_ENCODERS,
        NODE_IMAGE_HARDWARE_DECODERS
    };
    for (uint32_t index = 0; index < count; index++) {
        if (GetGroupCapabilities(codecGroupsNodeName[index]) != HDF_SUCCESS) {
            continue;
        }
    }
    CODEC_LOGI("Init Run....capList_.size=%{public}zu", capList_.size());
}

CodecImageConfig *CodecImageConfig::GetInstance()
{
    return &config_;
}

int32_t CodecImageConfig::GetImageCapabilityList(std::vector<CodecImageCapability> &capList)
{
    size_t size = capList_.size();
    CODEC_LOGI("size[%{public}zu]", size);
    if (size == 0) {
        return HDF_FAILURE;
    }
    auto first = capList_.begin();
    auto last = capList_.end();
    capList.assign(first, last);
    return HDF_SUCCESS;
}

int32_t CodecImageConfig::GetGroupCapabilities(const std::string &nodeName)
{
    const struct DeviceResourceNode *codecGroupNode = nullptr;
    struct DeviceResourceNode *childNode = nullptr;
    struct DeviceResourceIface *iface = DeviceResourceGetIfaceInstance(HDF_CONFIG_SOURCE);
    CHECK_AND_RETURN_RET_LOG(iface != nullptr, HDF_ERR_INVALID_PARAM, "iface is nullptr");

    codecGroupNode = iface->GetChildNode(&node_, nodeName.c_str());
    CHECK_AND_RETURN_RET_LOG(codecGroupNode != nullptr, HDF_FAILURE, "failed to get child node: %{public}s!",
        nodeName.c_str());

    DEV_RES_NODE_FOR_EACH_CHILD_NODE(codecGroupNode, childNode)
    {
        CodecImageCapability cap;
        if (GetOneCapability(*iface, *childNode, cap) != HDF_SUCCESS) {
            CODEC_LOGE("GetOneCapability failed, name is %{public}s!", cap.name.c_str());
        }
        capList_.push_back(cap);
    }

    return HDF_SUCCESS;
}

int32_t CodecImageConfig::GetOneCapability(const struct DeviceResourceIface &iface,
                                           const struct DeviceResourceNode &childNode, CodecImageCapability &cap)
{
    const char *name = nullptr;
    auto ret = iface.GetString(&childNode, CODEC_CONFIG_KEY_NAME, &name, "");
    CHECK_AND_RETURN_RET_LOG(ret == HDF_SUCCESS, HDF_FAILURE, "get attr %{public}s err!", CODEC_CONFIG_KEY_NAME);
    CHECK_AND_RETURN_RET_LOG(name != nullptr && strlen(name) != 0, HDF_FAILURE, "compName is nullptr or empty!");
    cap.name = name;

    if (iface.GetUint32(&childNode, CODEC_CONFIG_KEY_ROLE, reinterpret_cast<uint32_t *>(&cap.role),
                        CODEC_IMAGE_INVALID) != HDF_SUCCESS) {
        cap.role = CODEC_IMAGE_INVALID;
        CODEC_LOGE("failed to get role for: %{public}s! Discarded", childNode.name);
        return HDF_FAILURE;
    }

    if (iface.GetUint32(&childNode, CODEC_CONFIG_KEY_TYPE, reinterpret_cast<uint32_t *>(&cap.type),
                        CODEC_IMAGE_TYPE_INVALID) != HDF_SUCCESS) {
        cap.role = CODEC_IMAGE_INVALID;
        cap.type = CODEC_IMAGE_TYPE_INVALID;
        CODEC_LOGE("failed to get type for: %{public}s! Discarded", childNode.name);
        return HDF_FAILURE;
    }

    cap.isSoftwareCodec = iface.GetBool(&childNode, CODEC_CONFIG_KEY_IS_SOFTWARE_CODEC);

    ConfigUintNodeAttr nodeAttrs[] = {
        {CODEC_CONFIG_KEY_MIN_WIDTH, cap.minWidth, 0},
        {CODEC_CONFIG_KEY_MIN_HEIGHT, cap.minHeight, 0},
        {CODEC_CONFIG_KEY_MAX_WIDTH, cap.maxWidth, 0},
        {CODEC_CONFIG_KEY_MAX_HEIGHT, cap.maxHeight, 0},
        {CODEC_CONFIG_KEY_MAX_INST, cap.maxInst, 0},
        {CODEC_CONFIG_KEY_MAX_SAMPLE, cap.maxSample, 0},
        {CODEC_CONFIG_KEY_WIDTH_ALIGNMENT, cap.widthAlignment, 0},
        {CODEC_CONFIG_KEY_HEIGHT_ALIGNMENT, cap.heightAlignment, 0}};

    int32_t count = sizeof(nodeAttrs) / sizeof(ConfigUintNodeAttr);
    for (int32_t i = 0; i < count; i++) {
        auto err = iface.GetUint32(&childNode, nodeAttrs[i].attrName.c_str(),
            reinterpret_cast<uint32_t *>(&nodeAttrs[i].value), nodeAttrs[i].defaultValue);

        CHECK_AND_RETURN_RET_LOG(err == HDF_SUCCESS, HDF_FAILURE, "failed to get %{public}s.%{public}s!",
            childNode.name, nodeAttrs[i].attrName.c_str());
    }

    ConfigUintArrayNodeAttr attr = {CODEC_CONFIG_KEY_SUPPORT_PIXEL_FMTS, cap.supportPixFmts};
    ret = GetUintTableConfig(iface, childNode, attr);
    CHECK_AND_RETURN_RET_LOG(ret == HDF_SUCCESS, HDF_FAILURE, "get uint table config [%{public}s] err!",
        attr.attrName.c_str());

    return HDF_SUCCESS;
}

int32_t CodecImageConfig::GetUintTableConfig(const struct DeviceResourceIface &iface,
    const struct DeviceResourceNode &node, ConfigUintArrayNodeAttr &attr)
{
    CHECK_AND_RETURN_RET_LOG(!attr.attrName.empty(), HDF_ERR_INVALID_PARAM, "failed, invalid attr");

    int32_t count = iface.GetElemNum(&node, attr.attrName.c_str());
    CHECK_AND_RETURN_RET_LOG(count >= 0, HDF_FAILURE, "%{public}s table size: count[%{public}d] < 0!",
        attr.attrName.c_str(), count);

    if (count > 0) {
        std::unique_ptr<int32_t[]> array = std::make_unique<int32_t[]>(count);
        iface.GetUint32Array(&node, attr.attrName.c_str(), reinterpret_cast<uint32_t *>(array.get()), count, 0);
        attr.vec.assign(array.get(), array.get() + count);
    }
    return HDF_SUCCESS;
}
} // V2_1
} // Image
} // Codec
} // HDI
} // OHOS
