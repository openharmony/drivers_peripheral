/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "codec_capability_parser.h"
#include <hdf_log.h>
#include <OMX_IVCommon.h>
#include <osal_mem.h>
#include <securec.h>

#define HDF_LOG_TAG codec_capability_parser
#ifdef __ARM64__
#define MASK_NUM_LIMIT 64
#else
#define MASK_NUM_LIMIT 32
#endif

static int32_t GetGroupExInfosNumber(const struct DeviceResourceNode *node, const char *nodeName, int32_t *num)
{
    if (node == NULL || nodeName == NULL || num == NULL) {
        HDF_LOGE("%{public}s, failed for codec %{public}s, invalid param!", __func__, nodeName);
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t result = 0;
    *num = result;
    const struct DeviceResourceNode *codecGroupNode = NULL;
    struct DeviceResourceNode *childNode = NULL;
    struct DeviceResourceIface *iface = DeviceResourceGetIfaceInstance(HDF_CONFIG_SOURCE);
    if (iface == NULL) {
        HDF_LOGE("%{public}s, failed, iface NULL!", __func__);
        return HDF_FAILURE;
    }

    codecGroupNode = iface->GetChildNode(node, nodeName);
    if (codecGroupNode == NULL) {
        HDF_LOGE("%{public}s, failed to get child node %{public}s!", __func__, nodeName);
        return HDF_FAILURE;
    }
    DEV_RES_NODE_FOR_EACH_CHILD_NODE(codecGroupNode, childNode) {
        result++;
    }
    *num = result;

    return HDF_SUCCESS;
}

static int32_t GetBasicInfo(
    const struct DeviceResourceIface *iface, const struct DeviceResourceNode *childNode, CodecExInfo *info)
{
    if (iface->GetUint32(childNode, CODEC_CONFIG_KEY_TYPE, (uint32_t *)&info->type, INVALID_TYPE) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s, failed to get type.", __func__);
        return HDF_FAILURE;
    }

    const char *compName = NULL;
    if (iface->GetString(childNode, CODEC_CONFIG_KEY_NAME, &compName, "") != HDF_SUCCESS) {
        HDF_LOGE("%{public}s, failed to get compName.", __func__);
        return HDF_FAILURE;
    }
    if (compName == NULL || strlen(compName) >= NAME_LENGTH || strlen(compName) == 0) {
        HDF_LOGE("%{public}s, compName is invalid.", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = strcpy_s(info->compName, NAME_LENGTH, compName);
    if (ret != EOK) {
        HDF_LOGE("%{public}s, failed to strcpy_s compName.", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t GetBufferInfo(
    const struct DeviceResourceIface *iface, const struct DeviceResourceNode *childNode, CodecExInfo *info)
{
    if (iface->GetUint32(childNode, CODEC_CONFIG_KEY_INPUT_BUFFER_COUNT, (uint32_t *)&info->inputBufferCount, 0) !=
        HDF_SUCCESS) {
        HDF_LOGE("%{public}s, failed to get inputBufferCount.", __func__);
        return HDF_FAILURE;
    }
    if (iface->GetUint32(childNode, CODEC_CONFIG_KEY_INPUT_BUFFER_SIZE, (uint32_t *)&info->inputBufferSize, 0) !=
        HDF_SUCCESS) {
        HDF_LOGE("%{public}s, failed to get inputBufferSize.", __func__);
        return HDF_FAILURE;
    }
    if (iface->GetUint32(childNode, CODEC_CONFIG_KEY_OUTPUT_BUFFER_COUNT, (uint32_t *)&info->outputBufferCount, 0) !=
        HDF_SUCCESS) {
        HDF_LOGE("%{public}s, failed to get outputBufferCount.", __func__);
        return HDF_FAILURE;
    }
    if (iface->GetUint32(childNode, CODEC_CONFIG_KEY_OUTPUT_BUFFER_SIZE, (uint32_t *)&info->outputBufferSize, 0) !=
        HDF_SUCCESS) {
        HDF_LOGE("%{public}s, failed to get outputBufferSize.", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t GetOneExInfo(
    const struct DeviceResourceIface *iface, const struct DeviceResourceNode *childNode, CodecExInfo *info)
{
    if (iface == NULL || childNode == NULL || info == NULL) {
        HDF_LOGE("%{public}s, failed, invalid param!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (GetBasicInfo(iface, childNode, info) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s, GetBasicInfo failed!", __func__);
        return HDF_FAILURE;
    }
    if (GetBufferInfo(iface, childNode, info) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s, GetBufferInfo failed!", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t GetGroupExInfos(
    const struct DeviceResourceNode *node, const char *nodeName, CodecExInfoGroup *exInfoGroup)
{
    if (node == NULL || nodeName == NULL || exInfoGroup == NULL) {
        HDF_LOGE("%{public}s, failed, invalid param!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    CodecExInfo *info = NULL;
    int32_t index = 0;
    const struct DeviceResourceNode *codecGroupNode = NULL;
    struct DeviceResourceNode *childNode = NULL;
    struct DeviceResourceIface *iface = DeviceResourceGetIfaceInstance(HDF_CONFIG_SOURCE);
    if (iface == NULL) {
        HDF_LOGE("%{public}s, failed, iface NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    codecGroupNode = iface->GetChildNode(node, nodeName);
    if (codecGroupNode == NULL) {
        HDF_LOGE("%{public}s, failed to get child node: %{public}s!", __func__, nodeName);
        return HDF_FAILURE;
    }

    DEV_RES_NODE_FOR_EACH_CHILD_NODE(codecGroupNode, childNode) {
        info = &(exInfoGroup->exInfo[index++]);
        if (GetOneExInfo(iface, childNode, info) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s, GetOneExInfo failed !", __func__);
        }
    }

    return HDF_SUCCESS;
}

int32_t LoadCodecExInfoFromHcs(const struct DeviceResourceNode *node, CodecExInfoGroups *exInfos)
{
    if (node == NULL || exInfos == NULL) {
        HDF_LOGE("%{public}s, failed, invalid param!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    CodecExInfoGroup *codecExInfoGroup = NULL;
    int32_t index;
    int32_t codecNum = 0;

    char *codecGroupsNodeName[] = {
        NODE_VIDEO_HARDWARE_ENCODERS, NODE_VIDEO_HARDWARE_DECODERS,
        NODE_VIDEO_SOFTWARE_ENCODERS, NODE_VIDEO_SOFTWARE_DECODERS,
        NODE_AUDIO_HARDWARE_ENCODERS, NODE_AUDIO_HARDWARE_DECODERS,
        NODE_AUDIO_SOFTWARE_ENCODERS, NODE_AUDIO_SOFTWARE_DECODERS
    };
    CodecExInfoGroup *codecExInfoGroups[] = {
        &(exInfos->videoHwEncoderGroup), &(exInfos->videoHwDecoderGroup),
        &(exInfos->videoSwEncoderGroup), &(exInfos->videoSwDecoderGroup),
        &(exInfos->audioHwEncoderGroup), &(exInfos->audioHwDecoderGroup),
        &(exInfos->audioSwEncoderGroup), &(exInfos->audioSwDecoderGroup)
    };

    for (index = 0; index < CODEC_CAPABLITY_GROUP_NUM; index++) {
        if (GetGroupExInfosNumber(node, codecGroupsNodeName[index], &codecNum) == HDF_SUCCESS) {
            codecExInfoGroup = codecExInfoGroups[index];
            if (codecNum > 0) {
                codecExInfoGroup->num = codecNum;
                codecExInfoGroup->exInfo = (CodecExInfo *)OsalMemAlloc(sizeof(CodecExInfo) * codecNum);
            } else {
                codecExInfoGroup->exInfo = NULL;
                codecExInfoGroup->num = 0;
            }
            if (codecNum > 0 && codecExInfoGroup->exInfo == NULL) {
                codecExInfoGroup->num = 0;
                HDF_LOGE("%{public}s, MemAlloc for capability group failed!", __func__);
                return HDF_FAILURE;
            }
        }
    }

    for (index = 0; index < CODEC_CAPABLITY_GROUP_NUM; index++) {
        if (GetGroupExInfos(node, codecGroupsNodeName[index], codecExInfoGroups[index]) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s, GetGroupExInfos failed index: %{public}d!", __func__, index);
            return HDF_FAILURE;
        }
    }

    exInfos->inited = true;
    return HDF_SUCCESS;
}

int32_t ClearExInfoGroup(CodecExInfoGroups *exInfos)
{
    if (exInfos == NULL) {
        HDF_LOGE("%{public}s, failed, invalid param!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t index;
    CodecExInfoGroup *codecExInfoGroup = NULL;
    CodecExInfoGroup *codecExInfoGroups[] = {
        &(exInfos->videoHwEncoderGroup), &(exInfos->videoHwDecoderGroup),
        &(exInfos->videoSwEncoderGroup), &(exInfos->videoSwDecoderGroup),
        &(exInfos->audioHwEncoderGroup), &(exInfos->audioHwDecoderGroup),
        &(exInfos->audioSwEncoderGroup), &(exInfos->audioSwDecoderGroup)
    };
    for (index = 0; index < CODEC_CAPABLITY_GROUP_NUM; index++) {
        codecExInfoGroup = codecExInfoGroups[index];
        if (codecExInfoGroup->exInfo != NULL) {
            OsalMemFree(codecExInfoGroup->exInfo);
            codecExInfoGroup->exInfo = NULL;
        }
    }
    exInfos->inited = false;
    return HDF_SUCCESS;
}
