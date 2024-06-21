/*
 * Copyright (c) 2022-2023 Shenzhen Kaihong DID Co., Ltd.
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

#include "codec_config_parser.h"
#include <osal_mem.h>
#include <securec.h>
#include <OMX_IVCommon.h>
#include "codec_log_wrapper.h"

#ifdef __ARCH64__
#define MASK_NUM_LIMIT  64
#else
#define MASK_NUM_LIMIT  32
#endif

static int32_t GetGroupCapabilitiesNumber(const struct DeviceResourceNode *node,
    const char *nodeName, int32_t *num)
{
    if (node == NULL || nodeName == NULL || num == NULL) {
        CODEC_LOGE("failed for codec %{public}s, invalid param!", nodeName);
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t result = 0;
    *num = result;
    const struct DeviceResourceNode *codecGroupNode = NULL;
    struct DeviceResourceNode *childNode = NULL;
    struct DeviceResourceIface *iface = DeviceResourceGetIfaceInstance(HDF_CONFIG_SOURCE);
    if (iface == NULL) {
        CODEC_LOGE("failed, iface NULL!");
        return HDF_FAILURE;
    }

    codecGroupNode = iface->GetChildNode(node, nodeName);
    if (codecGroupNode == NULL) {
        CODEC_LOGE("failed to get child node %{public}s!", nodeName);
        return HDF_FAILURE;
    }
    DEV_RES_NODE_FOR_EACH_CHILD_NODE(codecGroupNode, childNode) {
        result++;
    }
    *num = result;

    return HDF_SUCCESS;
}

static int32_t GetUintTableConfig(const struct DeviceResourceIface *iface,
    const struct DeviceResourceNode *node, ConfigUintArrayNodeAttr *attr)
{
    if (iface == NULL || node == NULL || attr == NULL) {
        CODEC_LOGE("invalid param!");
        return HDF_ERR_INVALID_PARAM;
    }
    if (attr->array == NULL || attr->attrName == NULL) {
        CODEC_LOGE("invalid attr!");
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t count = iface->GetElemNum(node, attr->attrName);
    if (count < 0 || count >= attr->length) {
        CODEC_LOGE("%{public}s table size: %{public}d incorrect or exceed max size %{public}d!", attr->attrName,
            count, attr->length - 1);
        return HDF_FAILURE;
    }

    if (count > 0) {
        iface->GetUint32Array(node, attr->attrName, (uint32_t *)attr->array, count, 0);
    }
    attr->array[count] = attr->endValue;

    return HDF_SUCCESS;
}

static int32_t GetMaskedConfig(const struct DeviceResourceIface *iface,
    const struct DeviceResourceNode *node, const char *attrName, uint32_t *mask)
{
    if (iface == NULL || node == NULL || attrName == NULL || mask == NULL) {
        CODEC_LOGE("invalid param!");
        return HDF_ERR_INVALID_PARAM;
    }

    uint32_t *values = NULL;
    int32_t count = iface->GetElemNum(node, attrName);

    *mask = 0;
    if (count < 0 || count > MASK_NUM_LIMIT) {
        CODEC_LOGE("count %{public}d incorrect!", count);
        return HDF_FAILURE;
    }

    if (count > 0) {
        values = (uint32_t *)OsalMemAlloc(sizeof(uint32_t) * count);
        if (values == NULL) {
            CODEC_LOGE("failed to allocate mem for %{public}s!", attrName);
            return HDF_FAILURE;
        }
        iface->GetUint32Array(node, attrName, values, count, 0);
        for (int32_t index = 0; index < count; index++) {
            *mask |= values[index];
        }
        OsalMemFree(values);
    }

    return HDF_SUCCESS;
}

static int32_t GetVideoPortCapability(const struct DeviceResourceIface *iface,
    const struct DeviceResourceNode *childNode, CodecCompCapability *cap)
{
    if (iface == NULL || childNode == NULL || cap == NULL) {
        CODEC_LOGE("invalid param!");
        return HDF_ERR_INVALID_PARAM;
    }

    ConfigUintNodeAttr nodeAttrs[] = {
        {CODEC_CONFIG_KEY_MIN_WIDTH,             (uint32_t*)&cap->port.video.minSize.width,               0},
        {CODEC_CONFIG_KEY_MIN_HEIGHT,            (uint32_t*)&cap->port.video.minSize.height,              0},
        {CODEC_CONFIG_KEY_MAX_WIDTH,             (uint32_t*)&cap->port.video.maxSize.width,               0},
        {CODEC_CONFIG_KEY_MAX_HEIGHT,            (uint32_t*)&cap->port.video.maxSize.height,              0},
        {CODEC_CONFIG_KEY_WIDTH_ALIGNMENT,       (uint32_t*)&cap->port.video.whAlignment.widthAlignment,  0},
        {CODEC_CONFIG_KEY_HEIGHT_ALIGNMENT,      (uint32_t*)&cap->port.video.whAlignment.heightAlignment, 0},
        {CODEC_CONFIG_KEY_MIN_BLOCK_COUNT,       (uint32_t*)&cap->port.video.blockCount.min,              0},
        {CODEC_CONFIG_KEY_MAX_BLOCK_COUNT,       (uint32_t*)&cap->port.video.blockCount.max,              0},
        {CODEC_CONFIG_KEY_MIN_BLOCKS_PER_SECOND, (uint32_t*)&cap->port.video.blocksPerSecond.min,         0},
        {CODEC_CONFIG_KEY_MAX_BLOCKS_PER_SECOND, (uint32_t*)&cap->port.video.blocksPerSecond.max,         0},
        {CODEC_CONFIG_KEY_BLOCK_SIZE_WIDTH,      (uint32_t*)&cap->port.video.blockSize.width,             0},
        {CODEC_CONFIG_KEY_BLOCK_SIZE_HEIGHT,     (uint32_t*)&cap->port.video.blockSize.height,            0},
        {CODEC_CONFIG_KEY_MIN_FRAME_RATE,        (uint32_t *)&cap->port.video.frameRate.min,              0},
        {CODEC_CONFIG_KEY_MAX_FRAME_RATE,        (uint32_t *)&cap->port.video.frameRate.max,              0}
    };

    int32_t count = sizeof(nodeAttrs) / sizeof(ConfigUintNodeAttr);
    for (int32_t i = 0; i < count; i++) {
        if (iface->GetUint32(childNode, nodeAttrs[i].attrName, nodeAttrs[i].valueAddr,
            nodeAttrs[i].defaultValue) != HDF_SUCCESS) {
            CODEC_LOGE("failed to get %{public}s.%{public}s!", childNode->name, nodeAttrs[i].attrName);
            return HDF_FAILURE;
        }
    }

    ConfigUintArrayNodeAttr arrayAttrs[] = {
        {CODEC_CONFIG_KEY_SUPPORT_PIXEL_FMTS, cap->port.video.supportPixFmts, PIX_FORMAT_NUM, OMX_COLOR_FormatUnused},
        {CODEC_CONFIG_KEY_BITE_RATE_MODE, (int32_t *)cap->port.video.bitRatemode, BIT_RATE_MODE_NUM,
         BIT_RATE_MODE_INVALID},
        {CODEC_CONFIG_KEY_MESURED_FRAME_RATE, cap->port.video.measuredFrameRate, MEASURED_FRAME_RATE_NUM, 0}
    };

    count = sizeof(arrayAttrs) / sizeof(ConfigUintArrayNodeAttr);
    for (int32_t i = 0; i < count; i++) {
        if (GetUintTableConfig(iface, childNode, &arrayAttrs[i]) != HDF_SUCCESS) {
            CODEC_LOGE("failed to get %{public}s.%{public}s!", childNode->name, nodeAttrs[i].attrName);
            return HDF_FAILURE;
        }
    }
    return HDF_SUCCESS;
}

static int32_t GetAudioPortCapability(const struct DeviceResourceIface *iface,
    const struct DeviceResourceNode *childNode, CodecCompCapability *cap)
{
    if (iface == NULL || childNode == NULL || cap == NULL) {
        CODEC_LOGE("invalid param!");
        return HDF_ERR_INVALID_PARAM;
    }

    ConfigUintArrayNodeAttr arrayAttrs[] = {
        {CODEC_CONFIG_KEY_SAMPLE_FORMATS,  cap->port.audio.sampleFormats,  SAMPLE_FMT_NUM,  AUDIO_SAMPLE_FMT_INVALID},
        {CODEC_CONFIG_KEY_SAMPLE_RATE,     cap->port.audio.sampleRate,     SAMPLE_RATE_NUM, AUD_SAMPLE_RATE_INVALID},
        {CODEC_CONFIG_KEY_CHANNEL_LAYOUTS, cap->port.audio.channelLayouts, CHANNEL_NUM,     -1},
        {CODEC_CONFIG_KEY_CHANNEL_COUNT,   cap->port.audio.channelCount,   CHANNEL_NUM,     -1}
    };

    int32_t count = sizeof(arrayAttrs) / sizeof(ConfigUintArrayNodeAttr);
    for (int32_t i = 0; i < count; i++) {
        if (GetUintTableConfig(iface, childNode, &arrayAttrs[i]) != HDF_SUCCESS) {
            CODEC_LOGE("failed to get %{public}s.%{public}s!", childNode->name, arrayAttrs[i].attrName);
            return HDF_FAILURE;
        }
    }

    return HDF_SUCCESS;
}

static int32_t GetMiscOfCapability(const struct DeviceResourceIface *iface,
    const struct DeviceResourceNode *childNode, CodecCompCapability *cap)
{
    if (iface == NULL || childNode == NULL || cap == NULL) {
        CODEC_LOGE("invalid param!");
        return HDF_ERR_INVALID_PARAM;
    }

    ConfigUintArrayNodeAttr attr = {CODEC_CONFIG_KEY_SUPPORT_PROFILES,
        cap->supportProfiles, PROFILE_NUM, INVALID_PROFILE};
    if (GetUintTableConfig(iface, childNode, &attr) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    if (iface->GetUint32(childNode, CODEC_CONFIG_KEY_MAX_INST, (uint32_t*)&cap->maxInst, 0) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    if (GetMaskedConfig(iface, childNode, CODEC_CONFIG_KEY_PROCESS_MODE_MASK,
        (uint32_t *)&cap->processModeMask) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    if (GetMaskedConfig(iface, childNode, CODEC_CONFIG_KEY_CAPS_MASK, &cap->capsMask) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    if (iface->GetUint32(childNode, CODEC_CONFIG_KEY_MIN_BITRATE, (uint32_t*)&(cap->bitRate.min), 0) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    if (iface->GetUint32(childNode, CODEC_CONFIG_KEY_MAX_BITRATE, (uint32_t*)&(cap->bitRate.max), 0) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t GetOneCapability(const struct DeviceResourceIface *iface,
    const struct DeviceResourceNode *childNode, CodecCompCapability *cap, bool isVideoGroup)
{
    if (iface == NULL || childNode == NULL || cap == NULL) {
        CODEC_LOGE("invalid param!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (iface->GetUint32(childNode, CODEC_CONFIG_KEY_ROLE,
        (uint32_t*)&cap->role, MEDIA_ROLETYPE_INVALID) != HDF_SUCCESS) {
        cap->role = MEDIA_ROLETYPE_INVALID;
        CODEC_LOGE("failed to get mime for: %{public}s! Discarded", childNode->name);
        return HDF_FAILURE;
    }

    if (iface->GetUint32(childNode, CODEC_CONFIG_KEY_TYPE, (uint32_t*)&cap->type, INVALID_TYPE) != HDF_SUCCESS) {
        cap->role = MEDIA_ROLETYPE_INVALID;
        cap->type = INVALID_TYPE;
        CODEC_LOGE("failed to get type for: %{public}s! Discarded", childNode->name);
        return HDF_FAILURE;
    }

    const char *compName = NULL;
    if (iface->GetString(childNode, CODEC_CONFIG_KEY_NAME, &compName, "") != HDF_SUCCESS) {
        cap->role = MEDIA_ROLETYPE_INVALID;
        return HDF_FAILURE;
    }
    if (compName == NULL || strlen(compName) >= NAME_LENGTH || strlen(compName) == 0) {
        cap->role = MEDIA_ROLETYPE_INVALID;
        return HDF_FAILURE;
    }
    int32_t ret = strcpy_s(cap->compName, NAME_LENGTH, compName);
    if (ret != EOK) {
        CODEC_LOGE("strcpy_s is failed, error code: %{public}d!", ret);
        return HDF_FAILURE;
    }
    cap->isSoftwareCodec = iface->GetBool(childNode, CODEC_CONFIG_KEY_IS_SOFTWARE_CODEC);
    cap->canSwapWidthHeight = iface->GetBool(childNode, CODEC_CONFIG_KEY_CAN_SWAP_WIDTH_HEIGHT);

    if (GetMiscOfCapability(iface, childNode, cap) != HDF_SUCCESS) {
        cap->role = MEDIA_ROLETYPE_INVALID;
        return HDF_FAILURE;
    }

    if (isVideoGroup) {
        if (GetVideoPortCapability(iface, childNode, cap) != HDF_SUCCESS) {
            cap->role = MEDIA_ROLETYPE_INVALID;
            return HDF_FAILURE;
        }
    } else {
        if (GetAudioPortCapability(iface, childNode, cap) != HDF_SUCCESS) {
            cap->role = MEDIA_ROLETYPE_INVALID;
            return HDF_FAILURE;
        }
    }

    return HDF_SUCCESS;
}

static int32_t GetGroupCapabilities(const struct DeviceResourceNode *node,
    const char *nodeName, CodecCapablityGroup *capsGroup)
{
    if (node == NULL || nodeName == NULL || capsGroup == NULL) {
        CODEC_LOGE("invalid param!");
        return HDF_ERR_INVALID_PARAM;
    }

    CodecCompCapability *cap = NULL;
    int32_t index = 0;
    bool isVideoGroup = true;
    const struct DeviceResourceNode *codecGroupNode = NULL;
    struct DeviceResourceNode *childNode = NULL;
    struct DeviceResourceIface *iface = DeviceResourceGetIfaceInstance(HDF_CONFIG_SOURCE);
    if (iface == NULL) {
        CODEC_LOGE("iface NULL!");
        return HDF_ERR_INVALID_PARAM;
    }

    codecGroupNode = iface->GetChildNode(node, nodeName);
    if (codecGroupNode == NULL) {
        CODEC_LOGE("failed to get child node: %{public}s!", nodeName);
        return HDF_FAILURE;
    }

    if (strstr(nodeName, "Video") == NULL) {
        isVideoGroup = false;
    }
    DEV_RES_NODE_FOR_EACH_CHILD_NODE(codecGroupNode, childNode) {
        cap = &(capsGroup->capablitis[index++]);
        if (cap == NULL) {
            continue;
        }
        if (GetOneCapability(iface, childNode, cap, isVideoGroup) != HDF_SUCCESS) {
            CODEC_LOGE("GetOneCapability failed, role is %{public}d!", cap->role);
        }
    }

    return HDF_SUCCESS;
}

int32_t LoadCodecCapabilityFromHcs(const struct DeviceResourceNode *node, CodecCapablites *caps)
{
    if (node == NULL || caps == NULL) {
        CODEC_LOGE("invalid param!");
        return HDF_ERR_INVALID_PARAM;
    }
    CodecCapablityGroup *codecCapGroup = NULL;
    int32_t index;
    int32_t codecNum = 0;

    char *codecGroupsNodeName[] = {
        NODE_VIDEO_HARDWARE_ENCODERS, NODE_VIDEO_HARDWARE_DECODERS, NODE_VIDEO_SOFTWARE_ENCODERS,
        NODE_VIDEO_SOFTWARE_DECODERS, NODE_AUDIO_HARDWARE_ENCODERS, NODE_AUDIO_HARDWARE_DECODERS,
        NODE_AUDIO_SOFTWARE_ENCODERS, NODE_AUDIO_SOFTWARE_DECODERS
    };
    CodecCapablityGroup *codecCapGroups[] = {
        &(caps->videoHwEncoderGroup), &(caps->videoHwDecoderGroup),
        &(caps->videoSwEncoderGroup), &(caps->videoSwDecoderGroup),
        &(caps->audioHwEncoderGroup), &(caps->audioHwDecoderGroup),
        &(caps->audioSwEncoderGroup), &(caps->audioSwDecoderGroup)
    };

    for (index = 0; index < CODEC_CAPABLITY_GROUP_NUM; index++) {
        if (GetGroupCapabilitiesNumber(node, codecGroupsNodeName[index], &codecNum) == HDF_SUCCESS) {
            codecCapGroup = codecCapGroups[index];
            if (codecNum > 0) {
                codecCapGroup->num = codecNum;
                codecCapGroup->capablitis
                    = (CodecCompCapability *)OsalMemAlloc(sizeof(CodecCompCapability) * codecNum);
            } else {
                codecCapGroup->capablitis = NULL;
                codecCapGroup->num = 0;
            }
            if (codecNum > 0 && codecCapGroup->capablitis == NULL) {
                codecCapGroup->num = 0;
                CODEC_LOGE("MemAlloc for capability group failed!");
                return HDF_FAILURE;
            }
            caps->total += codecCapGroup->num;
        }
    }

    for (index = 0; index < CODEC_CAPABLITY_GROUP_NUM; index++) {
        if (GetGroupCapabilities(node, codecGroupsNodeName[index], codecCapGroups[index]) != HDF_SUCCESS) {
            CODEC_LOGE("GetGroupCapabilities failed index: %{public}d!", index);
            return HDF_FAILURE;
        }
    }
    caps->inited = true;
    return HDF_SUCCESS;
}

int32_t ClearCapabilityGroup(CodecCapablites *caps)
{
    if (caps == NULL) {
        CODEC_LOGE("invalid param!");
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t index;
    CodecCapablityGroup *codecCapGroup = NULL;
    CodecCapablityGroup *codecCapGroups[] = {
        &(caps->videoHwEncoderGroup), &(caps->videoHwDecoderGroup),
        &(caps->videoSwEncoderGroup), &(caps->videoSwDecoderGroup),
        &(caps->audioHwEncoderGroup), &(caps->audioHwDecoderGroup),
        &(caps->audioSwEncoderGroup), &(caps->audioSwDecoderGroup)
    };
    for (index = 0; index < CODEC_CAPABLITY_GROUP_NUM; index++) {
        codecCapGroup = codecCapGroups[index];
        if (codecCapGroup->capablitis != NULL) {
            OsalMemFree(codecCapGroup->capablitis);
            codecCapGroup->num = 0;
            codecCapGroup->capablitis = NULL;
        }
    }
    caps->inited = false;
    caps->total = 0;
    return HDF_SUCCESS;
}
