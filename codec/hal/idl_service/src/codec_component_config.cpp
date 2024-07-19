/*
 * Copyright (c) 2022-2023 Shenzhen Kaihong DID Co., Ltd..
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "codec_component_config.h"
#include <cinttypes>
#include <osal_mem.h>
#include "codec_log_wrapper.h"
#include "codec_hcb_util.h"

#define CODEC_CONFIG_NAME "media_codec_capabilities"

namespace {
    constexpr int32_t MASK_NUM_LIMIT = 32;
    constexpr char NODE_VIDEO_HARDWARE_ENCODERS[] = "VideoHwEncoders";
    constexpr char NODE_VIDEO_HARDWARE_DECODERS[] = "VideoHwDecoders";
    constexpr char NODE_VIDEO_SOFTWARE_ENCODERS[] = "VideoSwEncoders";
    constexpr char NODE_VIDEO_SOFTWARE_DECODERS[] = "VideoSwDecoders";
    constexpr char NODE_AUDIO_HARDWARE_ENCODERS[] = "AudioHwEncoders";
    constexpr char NODE_AUDIO_HARDWARE_DECODERS[] = "AudioHwDecoders";
    constexpr char NODE_AUDIO_SOFTWARE_ENCODERS[] = "AudioSwEncoders";
    constexpr char NODE_AUDIO_SOFTWARE_DECODERS[] = "AudioSwDecoders";
    
    constexpr char CODEC_CONFIG_KEY_ROLE[] = "role";
    constexpr char CODEC_CONFIG_KEY_TYPE[] = "type";
    constexpr char CODEC_CONFIG_KEY_NAME[] = "name";
    constexpr char CODEC_CONFIG_KEY_SUPPORT_PROFILES[] = "supportProfiles";
    constexpr char CODEC_CONFIG_KEY_MAX_INST[] = "maxInst";
    constexpr char CODEC_CONFIG_KEY_IS_SOFTWARE_CODEC[] = "isSoftwareCodec";
    constexpr char CODEC_CONFIG_KEY_PROCESS_MODE_MASK[] = "processModeMask";
    constexpr char CODEC_CONFIG_KEY_CAPS_MASK[] = "capsMask";
    constexpr char CODEC_CONFIG_KEY_MIN_BITRATE[] = "minBitRate";
    constexpr char CODEC_CONFIG_KEY_MAX_BITRATE[] = "maxBitRate";
    
    constexpr char CODEC_CONFIG_KEY_MIN_WIDTH[] = "minWidth";
    constexpr char CODEC_CONFIG_KEY_MIN_HEIGHT[] = "minHeight";
    constexpr char CODEC_CONFIG_KEY_MAX_WIDTH[] = "maxWidth";
    constexpr char CODEC_CONFIG_KEY_MAX_HEIGHT[] = "maxHeight";
    constexpr char CODEC_CONFIG_KEY_WIDTH_ALIGNMENT[] = "widthAlignment";
    constexpr char CODEC_CONFIG_KEY_HEIGHT_ALIGNMENT[] = "heightAlignment";
    constexpr char CODEC_CONFIG_KEY_MIN_BLOCK_COUNT[] = "minBlockCount";
    constexpr char CODEC_CONFIG_KEY_MAX_BLOCK_COUNT[] = "maxBlockCount";
    constexpr char CODEC_CONFIG_KEY_MIN_BLOCKS_PER_SECOND[] = "minBlocksPerSecond";
    constexpr char CODEC_CONFIG_KEY_MAX_BLOCKS_PER_SECOND[] = "maxBlocksPerSecond";
    constexpr char CODEC_CONFIG_KEY_SUPPORT_PIXEL_FMTS[] = "supportPixelFmts";
    constexpr char CODEC_CONFIG_KEY_BLOCK_SIZE_WIDTH[] = "blockSizeWidth";
    constexpr char CODEC_CONFIG_KEY_BLOCK_SIZE_HEIGHT[] = "blockSizeHeight";
    constexpr char CODEC_CONFIG_KEY_MIN_FRAME_RATE[] = "minFrameRate";
    constexpr char CODEC_CONFIG_KEY_MAX_FRAME_RATE[] = "maxFrameRate";
    constexpr char CODEC_CONFIG_KEY_BITE_RATE_MODE[] = "bitRateMode";
    constexpr char CODEC_CONFIG_KEY_MESURED_FRAME_RATE[] = "measuredFrameRate";
    constexpr char CODEC_CONFIG_KEY_CAN_SWAP_WIDTH_HEIGHT[] = "canSwapWidthHeight";

    constexpr char CODEC_CONFIG_KEY_IS_SUPPORT_PASSTHROUGH[] = "isSupportPassthrough";
    constexpr char CODEC_CONFIG_KEY_IS_SUPPORT_LOW_LATENCY[] = "isSupportLowLatency";
    constexpr char CODEC_CONFIG_KEY_IS_SUPPORT_TSVC[] = "isSupportTSVC";
    constexpr char CODEC_CONFIG_KEY_IS_SUPPORT_LTR[] = "isSupportLTR";
    constexpr char CODEC_CONFIG_KEY_MAX_LTR_FRAME_NUM[] = "maxLTRFrameNum";
    constexpr char CODEC_CONFIG_KEY_IS_SUPPORT_WATERMARK[] = "isSupportWaterMark";

    constexpr char CODEC_CONFIG_KEY_SAMPLE_FORMATS[] = "sampleFormats";
    constexpr char CODEC_CONFIG_KEY_SAMPLE_RATE[] = "sampleRate";
    constexpr char CODEC_CONFIG_KEY_CHANNEL_LAYOUTS[] = "channelLayouts";
    constexpr char CODEC_CONFIG_KEY_CHANNEL_COUNT[] = "channelCount";
}

using namespace OHOS::HDI::Codec::V3_0;
namespace OHOS {
namespace Codec {
namespace Omx {
CodecComponentConfig CodecComponentConfig::config_;
CodecComponentConfig::CodecComponentConfig()
{
    node_.name = nullptr;
    node_.hashValue = 0;
    node_.attrData = nullptr;
    node_.parent = nullptr;
    node_.child = nullptr;
    node_.sibling = nullptr;
}

void CodecComponentConfig::Init(const DeviceResourceNode &node)
{
    node_ = node;
    const std::string codecGroupsNodeName[] = { NODE_VIDEO_HARDWARE_ENCODERS, NODE_VIDEO_HARDWARE_DECODERS,
                                                NODE_VIDEO_SOFTWARE_ENCODERS, NODE_VIDEO_SOFTWARE_DECODERS,
                                                NODE_AUDIO_HARDWARE_ENCODERS, NODE_AUDIO_HARDWARE_DECODERS,
                                                NODE_AUDIO_SOFTWARE_ENCODERS, NODE_AUDIO_SOFTWARE_DECODERS };
    int count = sizeof(codecGroupsNodeName) / sizeof(std::string);
    for (int index = 0; index < count; index++) {
        GetGroupCapabilities(codecGroupsNodeName[index]);
    }
    CODEC_LOGD("Init Run....capList_.size=%{public}zu", capList_.size());
}

int32_t CodecComponentConfig::CodecCompCapabilityInit()
{
    const struct DeviceResourceNode *rootNode = HdfGetHcsRootNode();
    if (rootNode == nullptr) {
        CODEC_LOGE("GetRootNode failed");
        return HDF_FAILURE;
    }
    const struct DeviceResourceNode *codecNode = HcsGetNodeByMatchAttr(rootNode, CODEC_CONFIG_NAME);
    if (codecNode == nullptr) {
        CODEC_LOGE("codecNode is nullptr");
        return HDF_FAILURE;
    }
    OHOS::Codec::Omx::CodecComponentConfig::GetInstance()->Init(*codecNode);
    return HDF_SUCCESS;
}

CodecComponentConfig *CodecComponentConfig::GetInstance()
{
    return &config_;
}

int32_t CodecComponentConfig::GetComponentNum(int32_t &count)
{
    count = static_cast<int32_t>(capList_.size());
    CODEC_LOGD("enter, count = %{public}d", count);
    return HDF_SUCCESS;
}

int32_t CodecComponentConfig::GetComponentCapabilityList(std::vector<CodecCompCapability> &capList, int32_t count)
{
    CODEC_LOGD("count[%{public}d], size[%{public}zu]", count, capList_.size());
    if (count <= 0) {
        CODEC_LOGE("count[%{public}d] is invalid", count);
        return HDF_FAILURE;
    }
    if (count > static_cast<int32_t>(capList_.size())) {
        CODEC_LOGW("count[%{public}d] is too large", count);
        count = static_cast<int32_t>(capList_.size());
    }
    auto first = capList_.begin();
    auto last = capList_.begin() + count;
    capList.assign(first, last);
    return HDF_SUCCESS;
}

int32_t CodecComponentConfig::GetGroupCapabilities(const std::string &nodeName)
{
    bool isVideoGroup = true;
    const struct DeviceResourceNode *codecGroupNode = nullptr;
    struct DeviceResourceNode *childNode = nullptr;
    struct DeviceResourceIface *iface = DeviceResourceGetIfaceInstance(HDF_CONFIG_SOURCE);
    if ((iface == nullptr) || (iface->GetUint32 == nullptr) || (iface->GetBool == nullptr) || (iface->GetString == nullptr)) {
        CODEC_LOGE(" failed, iface or its GetUint32 or GetBool or GetString is nullptr!");
        return HDF_ERR_INVALID_PARAM;
    }

    codecGroupNode = iface->GetChildNode(&node_, nodeName.c_str());
    if (codecGroupNode == nullptr) {
        CODEC_LOGE("failed to get child node: %{public}s!", nodeName.c_str());
        return HDF_FAILURE;
    }

    if (nodeName.find("Video") == std::string::npos) {
        isVideoGroup = false;
    }

    DEV_RES_NODE_FOR_EACH_CHILD_NODE(codecGroupNode, childNode)
    {
        CodecCompCapability cap;
        if (GetOneCapability(*iface, *childNode, cap, isVideoGroup) != HDF_SUCCESS) {
            CODEC_LOGE("GetOneCapability failed, role is %{public}d!", cap.role);
        }
        capList_.push_back(cap);
    }

    return HDF_SUCCESS;
}

int32_t CodecComponentConfig::GetOneCapability(const struct DeviceResourceIface &iface,
                                               const struct DeviceResourceNode &childNode, CodecCompCapability &cap, bool isVideoGroup)
{
    if (iface.GetUint32(&childNode, CODEC_CONFIG_KEY_ROLE, reinterpret_cast<uint32_t *>(&cap.role),
                        MEDIA_ROLETYPE_INVALID) != HDF_SUCCESS) {
        cap.role = MEDIA_ROLETYPE_INVALID;
        CODEC_LOGE("failed to get mime for: %{public}s! Discarded", childNode.name);
        return HDF_FAILURE;
    }
    if (iface.GetUint32(&childNode, CODEC_CONFIG_KEY_TYPE, reinterpret_cast<uint32_t *>(&cap.type), INVALID_TYPE) !=
        HDF_SUCCESS) {
        cap.role = MEDIA_ROLETYPE_INVALID;
        cap.type = INVALID_TYPE;
        CODEC_LOGE("failed to get type for: %{public}s! Discarded", childNode.name);
        return HDF_FAILURE;
    }

    const char *compName = nullptr;
    if (iface.GetString(&childNode, CODEC_CONFIG_KEY_NAME, &compName, "") != HDF_SUCCESS) {
        cap.role = MEDIA_ROLETYPE_INVALID;
        CODEC_LOGE("get attr %{public}s err!", CODEC_CONFIG_KEY_NAME);
        return HDF_FAILURE;
    }
    if (compName == nullptr || strlen(compName) == 0) {
        cap.role = MEDIA_ROLETYPE_INVALID;
        CODEC_LOGE("compName is nullptr or empty!");
        return HDF_FAILURE;
    }
    cap.compName = compName;

    cap.isSoftwareCodec = iface.GetBool(&childNode, CODEC_CONFIG_KEY_IS_SOFTWARE_CODEC);
    cap.canSwapWidthHeight = iface.GetBool(&childNode, CODEC_CONFIG_KEY_CAN_SWAP_WIDTH_HEIGHT);

    if (GetMiscOfCapability(iface, childNode, cap) != HDF_SUCCESS) {
        cap.role = MEDIA_ROLETYPE_INVALID;
        CODEC_LOGE("get misc cap  err!");
        return HDF_FAILURE;
    }
    if (isVideoGroup) {
        if (GetVideoPortCapability(iface, childNode, cap) != HDF_SUCCESS) {
            cap.role = MEDIA_ROLETYPE_INVALID;
            CODEC_LOGE("get video port cap  err!");
            return HDF_FAILURE;
        }
    } else {
        if (GetAudioPortCapability(iface, childNode, cap) != HDF_SUCCESS) {
            cap.role = MEDIA_ROLETYPE_INVALID;
            CODEC_LOGE("get audio port cap  err!");
            return HDF_FAILURE;
        }
    }

    return HDF_SUCCESS;
}

int32_t CodecComponentConfig::GetMiscOfCapability(const struct DeviceResourceIface &iface,
                                                  const struct DeviceResourceNode &childNode, CodecCompCapability &cap)
{
    ConfigUintArrayNodeAttr attr = {CODEC_CONFIG_KEY_SUPPORT_PROFILES, cap.supportProfiles};
    if (GetUintTableConfig(iface, childNode, attr) != HDF_SUCCESS) {
        CODEC_LOGE("get uint table config [%{public}s] err!", attr.attrName.c_str());
        return HDF_FAILURE;
    }

    if (iface.GetUint32(&childNode, CODEC_CONFIG_KEY_MAX_INST, reinterpret_cast<uint32_t *>(&cap.maxInst), 0) !=
        HDF_SUCCESS) {
        CODEC_LOGE("get uint32 config [%{public}s] err!", attr.attrName.c_str());
        return HDF_FAILURE;
    }
    if (GetMaskedConfig(iface, childNode, CODEC_CONFIG_KEY_PROCESS_MODE_MASK,
                        reinterpret_cast<uint32_t &>(cap.processModeMask)) != HDF_SUCCESS) {
        CODEC_LOGE("get masked config [%{public}s] err!", attr.attrName.c_str());
        return HDF_FAILURE;
    }
    if (GetMaskedConfig(iface, childNode, CODEC_CONFIG_KEY_CAPS_MASK, static_cast<uint32_t &>(cap.capsMask)) !=
        HDF_SUCCESS) {
        CODEC_LOGE("get masked config [%{public}s] err!", attr.attrName.c_str());
        return HDF_FAILURE;
    }
    if (iface.GetUint32(&childNode, CODEC_CONFIG_KEY_MIN_BITRATE, reinterpret_cast<uint32_t *>(&cap.bitRate.min), 0) !=
        HDF_SUCCESS) {
        CODEC_LOGE("get uin32 config [%{public}s] err!", attr.attrName.c_str());
        return HDF_FAILURE;
    }
    if (iface.GetUint32(&childNode, CODEC_CONFIG_KEY_MAX_BITRATE, reinterpret_cast<uint32_t *>(&cap.bitRate.max), 0) !=
        HDF_SUCCESS) {
        CODEC_LOGE("get uin32 config [%{public}s] err!", attr.attrName.c_str());
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t CodecComponentConfig::GetUintTableConfig(const struct DeviceResourceIface &iface,
                                                 const struct DeviceResourceNode &node, ConfigUintArrayNodeAttr &attr)
{
    if (attr.attrName.empty()) {
        CODEC_LOGE("failed, invalid attr!");
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t count = iface.GetElemNum(&node, attr.attrName.c_str());
    if (count < 0) {
        CODEC_LOGE("%{public}s table size: count[%{public}d] < 0!", attr.attrName.c_str(), count);
        return HDF_FAILURE;
    }
    if (count > 0) {
        std::unique_ptr<int32_t[]> array = std::make_unique<int32_t[]>(count);
        iface.GetUint32Array(&node, attr.attrName.c_str(), reinterpret_cast<uint32_t *>(array.get()), count, 0);
        attr.vec.assign(array.get(), array.get() + count);
    }
    return HDF_SUCCESS;
}

int32_t CodecComponentConfig::GetMaskedConfig(const struct DeviceResourceIface &iface,
                                              const struct DeviceResourceNode &node, const std::string &attrName,
                                              uint32_t &mask)
{
    int32_t count = iface.GetElemNum(&node, attrName.c_str());

    mask = 0;
    if (count < 0 || count > MASK_NUM_LIMIT) {
        CODEC_LOGE("failed, count %{public}d incorrect!", count);
        return HDF_FAILURE;
    }

    if (count > 0) {
        std::unique_ptr<uint32_t[]> values = std::make_unique<uint32_t[]>(count);
        iface.GetUint32Array(&node, attrName.c_str(), values.get(), count, 0);
        for (int32_t index = 0; index < count; index++) {
            mask |= values[index];
        }
    }

    return HDF_SUCCESS;
}

int32_t CodecComponentConfig::GetVideoPortCapability(const struct DeviceResourceIface &iface,
                                                     const struct DeviceResourceNode &childNode,
                                                     CodecCompCapability &cap)
{
    ConfigUintNodeAttr nodeAttrs[] = {
        {CODEC_CONFIG_KEY_MIN_WIDTH, cap.port.video.minSize.width, 0},
        {CODEC_CONFIG_KEY_MIN_HEIGHT, cap.port.video.minSize.height, 0},
        {CODEC_CONFIG_KEY_MAX_WIDTH, cap.port.video.maxSize.width, 0},
        {CODEC_CONFIG_KEY_MAX_HEIGHT, cap.port.video.maxSize.height, 0},
        {CODEC_CONFIG_KEY_WIDTH_ALIGNMENT, cap.port.video.whAlignment.widthAlignment, 0},
        {CODEC_CONFIG_KEY_HEIGHT_ALIGNMENT, cap.port.video.whAlignment.heightAlignment, 0},
        {CODEC_CONFIG_KEY_MIN_BLOCK_COUNT, cap.port.video.blockCount.min, 0},
        {CODEC_CONFIG_KEY_MAX_BLOCK_COUNT, cap.port.video.blockCount.max, 0},
        {CODEC_CONFIG_KEY_MIN_BLOCKS_PER_SECOND, cap.port.video.blocksPerSecond.min, 0},
        {CODEC_CONFIG_KEY_MAX_BLOCKS_PER_SECOND, cap.port.video.blocksPerSecond.max, 0},
        {CODEC_CONFIG_KEY_BLOCK_SIZE_WIDTH, cap.port.video.blockSize.width, 0},
        {CODEC_CONFIG_KEY_BLOCK_SIZE_HEIGHT, cap.port.video.blockSize.height, 0},
        {CODEC_CONFIG_KEY_MIN_FRAME_RATE, cap.port.video.frameRate.min, 0},
        {CODEC_CONFIG_KEY_MAX_FRAME_RATE, cap.port.video.frameRate.max, 0}};

    int32_t count = sizeof(nodeAttrs) / sizeof(ConfigUintNodeAttr);
    for (int32_t i = 0; i < count; i++) {
        if (iface.GetUint32(&childNode, nodeAttrs[i].attrName.c_str(),
                            reinterpret_cast<uint32_t *>(&nodeAttrs[i].value),
                            nodeAttrs[i].defaultValue) != HDF_SUCCESS) {
            CODEC_LOGE("failed to get %{public}s.%{public}s!", childNode.name, nodeAttrs[i].attrName.c_str());
            return HDF_FAILURE;
        }
    }
    ConfigUintArrayNodeAttr arrayAttrs[] = {
        {CODEC_CONFIG_KEY_SUPPORT_PIXEL_FMTS, cap.port.video.supportPixFmts},
        {CODEC_CONFIG_KEY_BITE_RATE_MODE, reinterpret_cast<std::vector<int32_t> &>(cap.port.video.bitRatemode)},
        {CODEC_CONFIG_KEY_MESURED_FRAME_RATE, cap.port.video.measuredFrameRate}};

    count = sizeof(arrayAttrs) / sizeof(ConfigUintArrayNodeAttr);
    for (int32_t i = 0; i < count; i++) {
        if (GetUintTableConfig(iface, childNode, arrayAttrs[i]) != HDF_SUCCESS) {
            CODEC_LOGE("failed to get %{public}s.%{public}s!", childNode.name, nodeAttrs[i].attrName.c_str());
            return HDF_FAILURE;
        }
    }
    cap.port.video.isSupportPassthrough = iface.GetBool(&childNode, CODEC_CONFIG_KEY_IS_SUPPORT_PASSTHROUGH);
    cap.port.video.isSupportLowLatency = iface.GetBool(&childNode, CODEC_CONFIG_KEY_IS_SUPPORT_LOW_LATENCY);
    cap.port.video.isSupportTSVC = iface.GetBool(&childNode, CODEC_CONFIG_KEY_IS_SUPPORT_TSVC);
    cap.port.video.isSupportLTR = iface.GetBool(&childNode, CODEC_CONFIG_KEY_IS_SUPPORT_LTR);
    if (cap.port.video.isSupportLTR) {
        if (iface.GetUint32(&childNode, CODEC_CONFIG_KEY_MAX_LTR_FRAME_NUM,
                            reinterpret_cast<uint32_t *>(&cap.port.video.maxLTRFrameNum), 0) != HDF_SUCCESS) {
            CODEC_LOGE("failed to get %{public}s maxLTRFrameNum!", childNode.name);
        }
    }
    cap.port.video.isSupportWaterMark = iface.GetBool(&childNode, CODEC_CONFIG_KEY_IS_SUPPORT_WATERMARK);
    return HDF_SUCCESS;
}

int32_t CodecComponentConfig::GetAudioPortCapability(const struct DeviceResourceIface &iface,
                                                     const struct DeviceResourceNode &childNode,
                                                     CodecCompCapability &cap)
{
    ConfigUintArrayNodeAttr arrayAttrs[] = {{CODEC_CONFIG_KEY_SAMPLE_FORMATS, cap.port.audio.sampleFormats},
                                            {CODEC_CONFIG_KEY_SAMPLE_RATE, cap.port.audio.sampleRate},
                                            {CODEC_CONFIG_KEY_CHANNEL_LAYOUTS, cap.port.audio.channelLayouts},
                                            {CODEC_CONFIG_KEY_CHANNEL_COUNT, cap.port.audio.channelCount}};

    int32_t count = sizeof(arrayAttrs) / sizeof(ConfigUintArrayNodeAttr);
    for (int32_t i = 0; i < count; i++) {
        if (GetUintTableConfig(iface, childNode, arrayAttrs[i]) != HDF_SUCCESS) {
            CODEC_LOGE("failed to get %{public}s.%{public}s!", childNode.name, arrayAttrs[i].attrName.c_str());
            return HDF_FAILURE;
        }
    }

    return HDF_SUCCESS;
}
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS