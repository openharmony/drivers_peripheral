/*
 * Copyright (c) 2021 Shenzhen Kaihong DID Co., Ltd.
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
#include "hdf_base.h"
#include "hdf_log.h"

#define HDF_LOG_TAG "codec_config_parser"
#ifdef __ARM64__
#define MASK_NUM_LIMIT  64
#else
#define MASK_NUM_LIMIT  32
#endif

static CodecCapablites g_codecCapabilites = {0};
static const struct DeviceResourceNode *g_resourceNode;

static int32_t GetGroupCapabilitiesNumber(const struct DeviceResourceNode *node,
    const char *nodeName, int32_t *num)
{
    int result = 0;
    const struct DeviceResourceNode *codecGroupNode = NULL;
    struct DeviceResourceNode *childNode = NULL;
    struct DeviceResourceIface *iface = DeviceResourceGetIfaceInstance(HDF_CONFIG_SOURCE);

    *num = 0;
    if (iface == NULL || node == NULL || nodeName == NULL) {
        HDF_LOGE("%{public}s, failed for codecs %{public}s, variable NULL!", __func__, nodeName);
        return HDF_FAILURE;
    }

    codecGroupNode = iface->GetChildNode(node, nodeName);
    if (codecGroupNode == NULL) {
        HDF_LOGE("%{public}s, failed to get child node %{public}s,!", __func__, nodeName);
        return HDF_FAILURE;
    }
    DEV_RES_NODE_FOR_EACH_CHILD_NODE(codecGroupNode, childNode) {
        result++;
    }
    *num = result;

    return HDF_SUCCESS;
}

static int32_t GetCapabilityBase(const struct DeviceResourceIface *iface,
    const struct DeviceResourceNode *childNode, CodecCapability *cap)
{
    if (iface->GetUint32(childNode, CODEC_CONFIG_KEY_MIME,
        (uint32_t*)&cap->mime, MEDIA_MIMETYPE_INVALID) != HDF_SUCCESS) {
        cap->mime = MEDIA_MIMETYPE_INVALID;
        HDF_LOGE("%{public}s, failed to get mime for: %{public}s! Discarded", __func__, childNode->name);
        return HDF_FAILURE;
    }
    if (iface->GetUint32(childNode, CODEC_CONFIG_KEY_TYPE, (uint32_t*)&cap->type, INVALID_TYPE) != HDF_SUCCESS) {
        cap->mime = MEDIA_MIMETYPE_INVALID;
        cap->type = INVALID_TYPE;
        HDF_LOGE("%{public}s, failed to get type for: %{public}s! Discarded", __func__, childNode->name);
        return HDF_FAILURE;
    }
    const char *name = NULL;
    if (iface->GetString(childNode, CODEC_CONFIG_KEY_NAME, &name, "") != HDF_SUCCESS) {
        cap->mime = MEDIA_MIMETYPE_INVALID;
        HDF_LOGE("%{public}s, failed to get name for: %{public}s! Discarded", __func__, childNode->name);
        return HDF_FAILURE;
    }
    if (name == NULL || strlen(name) >= NAME_LENGTH || strlen(name) == 0) {
        cap->mime = MEDIA_MIMETYPE_INVALID;
        HDF_LOGE("%{public}s, name(%{public}s) is illegal", __func__, childNode->name);
        return HDF_FAILURE;
    }
    int32_t ret = strcpy_s(cap->name, NAME_LENGTH, name);
    if (ret != EOK) {
        cap->mime = MEDIA_MIMETYPE_INVALID;
        HDF_LOGE("%{public}s, strcpy_s is failed, error code: %{public}d!", __func__, ret);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t GetUintTableConfig(const struct DeviceResourceIface *iface,
    const struct DeviceResourceNode *node, ConfigUintArrayNodeAttr *attr)
{
    if (iface == NULL || node == NULL || attr == NULL) {
        HDF_LOGE("%{public}s, failed, invalid param!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (attr->array == NULL || attr->attrName == NULL) {
        HDF_LOGE("%{public}s, failed, invalid attr!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t count = iface->GetElemNum(node, attr->attrName);
    if (count < 0 || count >= attr->length) {
        HDF_LOGE("%{public}s, %{public}s table size: %{public}d incorrect or exceed max size %{public}d!",
            __func__, attr->attrName, count, attr->length - 1);
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
        HDF_LOGE("%{public}s, failed, invalid param!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    uint32_t *values = NULL;
    int32_t count = iface->GetElemNum(node, attrName);

    *mask = 0;
    if (count < 0 || count > MASK_NUM_LIMIT) {
        HDF_LOGE("%{public}s, failed, %{public}s count %{public}d incorrect!", __func__, attrName, count);
        return HDF_FAILURE;
    } else if (count == 0) {
        // mask is not set, do not need to read
        return HDF_SUCCESS;
    }

    values = (uint32_t *)OsalMemAlloc(sizeof(uint32_t) * count);
    if (values == NULL) {
        HDF_LOGE("%{public}s, failed to allocate mem for %{public}s!", __func__, attrName);
        return HDF_FAILURE;
    }
    iface->GetUint32Array(node, attrName, values, count, 0);
    for (int32_t index = 0; index < count; index++) {
        *mask |= values[index];
    }
    OsalMemFree(values);

    return HDF_SUCCESS;
}

static int32_t GetBufferConfig(const struct DeviceResourceIface *iface,
    const struct DeviceResourceNode *childNode, CodecCapability *cap)
{
    if (iface->GetUint32(childNode, CODEC_CONFIG_KEY_MIN_INPUT_BUFFER_NUM, (uint32_t*)&cap->inputBufferNum.min, 0)
        != HDF_SUCCESS) {
        cap->mime = MEDIA_MIMETYPE_INVALID;
        HDF_LOGE("%{public}s,  %{public}s:min%{public}s not config.",
            __func__, childNode->name, CODEC_CONFIG_KEY_MIN_INPUT_BUFFER_NUM);
        return HDF_FAILURE;
    }
    if (iface->GetUint32(childNode, CODEC_CONFIG_KEY_MAX_INPUT_BUFFER_NUM, (uint32_t*)&cap->inputBufferNum.max, 0)
        != HDF_SUCCESS) {
        cap->mime = MEDIA_MIMETYPE_INVALID;
        HDF_LOGE("%{public}s,  %{public}s:max%{public}s not config.",
            __func__, childNode->name, CODEC_CONFIG_KEY_MAX_INPUT_BUFFER_NUM);
        return HDF_FAILURE;
    }
    if (iface->GetUint32(childNode, CODEC_CONFIG_KEY_MIN_OUTPUT_BUFFER_NUM, (uint32_t*)&cap->outputBufferNum.min, 0)
        != HDF_SUCCESS) {
        cap->mime = MEDIA_MIMETYPE_INVALID;
        HDF_LOGE("%{public}s, %{public}s:min%{public}s not config.",
            __func__, childNode->name, CODEC_CONFIG_KEY_MIN_OUTPUT_BUFFER_NUM);
        return HDF_FAILURE;
    }
    if (iface->GetUint32(childNode, CODEC_CONFIG_KEY_MAX_OUTPUT_BUFFER_NUM, (uint32_t*)&cap->outputBufferNum.max, 0)
        != HDF_SUCCESS) {
        cap->mime = MEDIA_MIMETYPE_INVALID;
        HDF_LOGE("%{public}s, %{public}s:max%{public}s not config.",
            __func__, childNode->name, CODEC_CONFIG_KEY_MAX_OUTPUT_BUFFER_NUM);
        return HDF_FAILURE;
    }
    if (iface->GetUint32(childNode, CODEC_CONFIG_KEY_INPUT_BUFFER_SIZE, (uint32_t*)&cap->inputBufferSize, 0)
        != HDF_SUCCESS) {
        cap->mime = MEDIA_MIMETYPE_INVALID;
        HDF_LOGE("%{public}s, %{public}s:%{public}s not config.",
            __func__, childNode->name, CODEC_CONFIG_KEY_INPUT_BUFFER_SIZE);
        return HDF_FAILURE;
    }
    if (iface->GetUint32(childNode, CODEC_CONFIG_KEY_OUTPUT_BUFFER_SIZE, (uint32_t*)&cap->outputBufferSize, 0)
        != HDF_SUCCESS) {
        cap->mime = MEDIA_MIMETYPE_INVALID;
        HDF_LOGE("%{public}s, %{public}s:%{public}s not config.",
            __func__, childNode->name, CODEC_CONFIG_KEY_OUTPUT_BUFFER_SIZE);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t GetBitRateConfig(const struct DeviceResourceIface *iface,
    const struct DeviceResourceNode *childNode, CodecCapability *cap)
{
    if (iface->GetUint32(childNode, CODEC_CONFIG_KEY_MIN_BITRATE, (uint32_t*)&cap->bitRate.min, 0)
        != HDF_SUCCESS) {
        cap->mime = MEDIA_MIMETYPE_INVALID;
        HDF_LOGE("%{public}s,  %{public}s:min%{public}s not config.",
            __func__, childNode->name, CODEC_CONFIG_KEY_MIN_BITRATE);
        return HDF_FAILURE;
    }
    if (iface->GetUint32(childNode, CODEC_CONFIG_KEY_MAX_BITRATE, (uint32_t*)&cap->bitRate.max, 0)
        != HDF_SUCCESS) {
        cap->mime = MEDIA_MIMETYPE_INVALID;
        HDF_LOGE("%{public}s,  %{public}s:max%{public}s not config.",
            __func__, childNode->name, CODEC_CONFIG_KEY_MAX_BITRATE);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t GetAudioOfCapability(const struct DeviceResourceIface *iface,
    const struct DeviceResourceNode *childNode, CodecCapability *cap)
{
    ConfigUintArrayNodeAttr sampleFormatsAttr = {CODEC_CONFIG_KEY_SAMPLE_FORMATS, cap->port.audio.sampleFormats,
        SAMPLE_FORMAT_NUM, 0};
    if (GetUintTableConfig(iface, childNode, &sampleFormatsAttr) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s, failed to get %{public}s for: %{public}s!",
            __func__, CODEC_CONFIG_KEY_SAMPLE_FORMATS, childNode->name);
        return HDF_FAILURE;
    }

    ConfigUintArrayNodeAttr sampleRateAttr = {CODEC_CONFIG_KEY_SAMPLE_RATE, cap->port.audio.sampleRate,
        SAMPLE_RATE_NUM, 0};
    if (GetUintTableConfig(iface, childNode, &sampleRateAttr) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s, failed to get %{public}s for: %{public}s!",
            __func__, CODEC_CONFIG_KEY_SAMPLE_RATE, childNode->name);
        return HDF_FAILURE;
    }

    ConfigUintArrayNodeAttr channelLayoutsAttr = {CODEC_CONFIG_KEY_CHANNEL_LAYOUTS, cap->port.audio.channelLayouts,
        CHANNEL_NUM, 0};
    if (GetUintTableConfig(iface, childNode, &channelLayoutsAttr) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s, failed to get %{public}s for: %{public}s!",
            __func__, CODEC_CONFIG_KEY_CHANNEL_LAYOUTS, childNode->name);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t GetVideoOfCapability(const struct DeviceResourceIface *iface,
    const struct DeviceResourceNode *childNode, CodecCapability *cap)
{
    if (iface->GetUint32(childNode, CODEC_CONFIG_KEY_MIN_WIDTH, (uint32_t*)&cap->port.video.minSize.width, 0)
        != HDF_SUCCESS) {
        cap->mime = MEDIA_MIMETYPE_INVALID;
        HDF_LOGE("%{public}s, failed to get %{public}s for: %{public}s! Discarded",
            __func__, CODEC_CONFIG_KEY_MIN_WIDTH, childNode->name);
        return HDF_FAILURE;
    }
    if (iface->GetUint32(childNode, CODEC_CONFIG_KEY_MIN_HEIGHT, (uint32_t*)&cap->port.video.minSize.height, 0)
        != HDF_SUCCESS) {
        cap->mime = MEDIA_MIMETYPE_INVALID;
        HDF_LOGE("%{public}s, failed to get %{public}s for: %{public}s! Discarded",
            __func__, CODEC_CONFIG_KEY_MIN_HEIGHT, childNode->name);
        return HDF_FAILURE;
    }
    if (iface->GetUint32(childNode, CODEC_CONFIG_KEY_MAX_WIDTH, (uint32_t*)&cap->port.video.maxSize.width, 0)
        != HDF_SUCCESS) {
        cap->mime = MEDIA_MIMETYPE_INVALID;
        HDF_LOGE("%{public}s, failed to get %{public}s for: %{public}s! Discarded",
            __func__, CODEC_CONFIG_KEY_MAX_WIDTH, childNode->name);
        return HDF_FAILURE;
    }
    if (iface->GetUint32(childNode, CODEC_CONFIG_KEY_MAX_HEIGHT, (uint32_t*)&cap->port.video.maxSize.height, 0)
        != HDF_SUCCESS) {
        cap->mime = MEDIA_MIMETYPE_INVALID;
        HDF_LOGE("%{public}s, failed to get %{public}s for: %{public}s! Discarded",
            __func__, CODEC_CONFIG_KEY_MAX_HEIGHT, childNode->name);
        return HDF_FAILURE;
    }
    if (iface->GetUint32(childNode, CODEC_CONFIG_KEY_WIDTH_ALIGNMENT,
        (uint32_t*)&cap->port.video.whAlignment.widthAlignment, 0) != HDF_SUCCESS) {
        cap->mime = MEDIA_MIMETYPE_INVALID;
        HDF_LOGE("%{public}s, failed to get %{public}s for: %{public}s! Discarded",
            __func__, CODEC_CONFIG_KEY_WIDTH_ALIGNMENT, childNode->name);
        return HDF_FAILURE;
    }
    if (iface->GetUint32(childNode, CODEC_CONFIG_KEY_HEIGHT_ALIGNMENT,
        (uint32_t*)&cap->port.video.whAlignment.heightAlignment, 0) != HDF_SUCCESS) {
        cap->mime = MEDIA_MIMETYPE_INVALID;
        HDF_LOGE("%{public}s, failed to get %{public}s for: %{public}s! Discarded",
            __func__, CODEC_CONFIG_KEY_HEIGHT_ALIGNMENT, childNode->name);
        return HDF_FAILURE;
    }
    ConfigUintArrayNodeAttr attr = {CODEC_CONFIG_KEY_SUPPORT_PIXELF_MTS, cap->port.video.supportPixFmts,
        PIX_FMT_NUM, INVALID_PROFILE};
    if (GetUintTableConfig(iface, childNode, &attr) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
static int32_t GetOneCapability(const struct DeviceResourceIface *iface,
    const struct DeviceResourceNode *childNode, CodecCapability *cap, bool isVideoGroup)
{
    if (iface == NULL || childNode == NULL || cap == NULL) {
        HDF_LOGE("%{public}s, failed, invalid param!", __func__);
        return HDF_FAILURE;
    }
    if (GetCapabilityBase(iface, childNode, cap) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    ConfigUintArrayNodeAttr attr = {CODEC_CONFIG_KEY_SUPPORT_PROFILES,
        cap->supportProfiles, PROFILE_NUM, INVALID_PROFILE};
    if (GetUintTableConfig(iface, childNode, &attr) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    cap->isSoftwareCodec = iface->GetBool(childNode, CODEC_CONFIG_KEY_IS_SOFTWARE_CODEC);
    if (GetMaskedConfig(iface, childNode, CODEC_CONFIG_KEY_PROCESS_MODE_MASK,
        (uint32_t *)&cap->processModeMask) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    if (GetMaskedConfig(iface, childNode, CODEC_CONFIG_KEY_CAPS_MASK, &cap->capsMask) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    if (GetMaskedConfig(iface, childNode, CODEC_CONFIG_KEY_ALLOCATE_MASK, &cap->allocateMask) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    if (GetBufferConfig(iface, childNode, cap) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    if (GetBitRateConfig(iface, childNode, cap) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    if (isVideoGroup) {
        if (GetVideoOfCapability(iface, childNode, cap) != HDF_SUCCESS) {
            return HDF_FAILURE;
        }
    } else {
        if (GetAudioOfCapability(iface, childNode, cap) != HDF_SUCCESS) {
            return HDF_FAILURE;
        }
    }
    return HDF_SUCCESS;
}

static int32_t GetGroupCapabilities(const struct DeviceResourceNode *node,
    const char *nodeName, CodecCapablityGroup *capsGroup)
{
    int32_t index = 0;
    bool isVideoGroup = true;
    const struct DeviceResourceNode *codecGroupNode = NULL;
    struct DeviceResourceNode *childNode = NULL;
    struct DeviceResourceIface *iface = DeviceResourceGetIfaceInstance(HDF_CONFIG_SOURCE);

    if (iface == NULL || node == NULL || nodeName == NULL) {
        HDF_LOGE("%{public}s, failed for node %{public}s, variable NULL!", __func__, nodeName);
        return HDF_FAILURE;
    }

    codecGroupNode = iface->GetChildNode(node, nodeName);
    if (codecGroupNode == NULL) {
        HDF_LOGE("%{public}s, failed to get child node: %{public}s!", __func__, nodeName);
        return HDF_FAILURE;
    }
    if (strstr(nodeName, "Video") == NULL) {
        isVideoGroup = false;
    }
    DEV_RES_NODE_FOR_EACH_CHILD_NODE(codecGroupNode, childNode) {
        if (index >= capsGroup->num) {
            HDF_LOGE("%{public}s, failed to get child node: %{public}s, index error!", __func__, nodeName);
            return HDF_FAILURE;
        }
        GetOneCapability(iface, childNode, &(capsGroup->capablitis[index++]), isVideoGroup);
    }
    return HDF_SUCCESS;
}

int32_t LoadCodecCapabilityFromHcs(const struct DeviceResourceNode *node)
{
    CodecCapablityGroup *codecCapGroup = NULL;
    int32_t index;
    int32_t codecNum = 0;

    if (node == NULL) {
        HDF_LOGE("%{public}s, load capability failed, node is null!", __func__);
        return HDF_FAILURE;
    }
    g_resourceNode = node;

    char *codecGroupsNodeName[] = {
        NODE_VIDEO_HARDWARE_ENCODERS, NODE_VIDEO_HARDWARE_DECODERS,
        NODE_VIDEO_SOFTWARE_ENCODERS, NODE_VIDEO_SOFTWARE_DECODERS,
        NODE_AUDIO_HARDWARE_ENCODERS, NODE_AUDIO_HARDWARE_DECODERS,
        NODE_AUDIO_SOFTWARE_ENCODERS, NODE_AUDIO_SOFTWARE_DECODERS
    };
    for (index = 0; index < CODEC_CAPABLITY_GROUP_NUM; index++) {
        codecCapGroup = GetCapablityGroup(index);
        if (codecCapGroup == NULL) {
            continue;
        }
        if (GetGroupCapabilitiesNumber(node, codecGroupsNodeName[index], &codecNum) == HDF_SUCCESS) {
            codecCapGroup->num = codecNum;
            if (codecNum <= 0) {
                codecCapGroup->capablitis = NULL;
                continue;
            }
            size_t capablitisSize = sizeof(CodecCapability) * codecNum;
            codecCapGroup->capablitis = (CodecCapability *)OsalMemAlloc(capablitisSize);
            if (codecCapGroup->capablitis == NULL) {
                codecCapGroup->num = 0;
                HDF_LOGE("%{public}s, MemAlloc for capability group failed!", __func__);
                return HDF_FAILURE;
            }
            int32_t ret = memset_s(codecCapGroup->capablitis, capablitisSize, 0, capablitisSize);
            if (ret != EOK) {
                codecCapGroup->num = 0;
                OsalMemFree(codecCapGroup->capablitis);
                HDF_LOGE("%{public}s, memset_s for capability group failed!", __func__);
                return HDF_FAILURE;
            }
        } else {
            codecCapGroup->num = 0;
        }
    }
    for (index = 0; index < CODEC_CAPABLITY_GROUP_NUM; index++) {
        if (GetGroupCapabilities(node, codecGroupsNodeName[index], GetCapablityGroup(index)) != HDF_SUCCESS) {
            return HDF_FAILURE;
        }
    }

    g_codecCapabilites.inited = true;
    return HDF_SUCCESS;
}

int32_t ClearCapabilityGroup()
{
    int32_t index;
    CodecCapablityGroup *codecCapGroup = NULL;
    for (index = 0; index < CODEC_CAPABLITY_GROUP_NUM; index++) {
        codecCapGroup = GetCapablityGroup(index);
        if (codecCapGroup == NULL) {
            continue;
        }
        if (codecCapGroup->capablitis != NULL) {
            OsalMemFree(codecCapGroup->capablitis);
            codecCapGroup->num = 0;
            codecCapGroup->capablitis = NULL;
        }
    }
    g_codecCapabilites.inited = false;
    return HDF_SUCCESS;
}

CodecCapablityGroup *GetCapablityGroup(int32_t groupIndex)
{
    CodecCapablityGroup *codecCapGroups[] = {
        &(g_codecCapabilites.videoHwEncoderGroup), &(g_codecCapabilites.videoHwDecoderGroup),
        &(g_codecCapabilites.videoSwEncoderGroup), &(g_codecCapabilites.videoSwDecoderGroup),
        &(g_codecCapabilites.audioHwEncoderGroup), &(g_codecCapabilites.audioHwDecoderGroup),
        &(g_codecCapabilites.audioSwEncoderGroup), &(g_codecCapabilites.audioSwDecoderGroup)
    };
    if (groupIndex < 0) {
        return NULL;
    }
    if (groupIndex >= CODEC_CAPABLITY_GROUP_NUM) {
        return NULL;
    }
    return codecCapGroups[groupIndex];
}

bool CodecCapablitesInited()
{
    return g_codecCapabilites.inited;
}

int32_t ReloadCapabilities()
{
    ClearCapabilityGroup();
    LoadCodecCapabilityFromHcs(g_resourceNode);
    return HDF_SUCCESS;
}