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

#include "codec_component_capability_config.h"
#include "codec_log_wrapper.h"

static CodecCapablites g_codecCapabilites = {0};
static const struct DeviceResourceNode *g_resourceNode = NULL;

int32_t InitDataNode(const struct DeviceResourceNode *node)
{
    if (node == NULL) {
        CODEC_LOGE("data node is null!");
        return HDF_FAILURE;
    }
    g_resourceNode = node;
    return HDF_SUCCESS;
}

int32_t ClearCapabilityData()
{
    return ClearCapabilityGroup(&g_codecCapabilites);
}

int32_t LoadCapabilityData()
{
    return LoadCodecCapabilityFromHcs(g_resourceNode, &g_codecCapabilites);
}

int32_t GetComponentNum(int32_t *num)
{
    if (!g_codecCapabilites.inited) {
        CODEC_LOGE("g_codecCapabilites not init!");
        return HDF_FAILURE;
    }
    *num = g_codecCapabilites.total;
    return HDF_SUCCESS;
}

int32_t GetComponentCapabilityList(CodecCompCapability *capList, int32_t count)
{
    if (!g_codecCapabilites.inited) {
        CODEC_LOGE("g_codecCapabilites not init!");
        return HDF_FAILURE;
    }
    if (count != g_codecCapabilites.total) {
        CODEC_LOGE("The length does not match!");
        return HDF_FAILURE;
    }
    int32_t groupIndex;
    int32_t capIndex;
    int32_t curCount = 0;
    CodecCapablityGroup *group = NULL;
    CodecCompCapability *cap = NULL;
    CodecCapablityGroup *codeCapGroups[] = {
        &(g_codecCapabilites.videoHwEncoderGroup), &(g_codecCapabilites.videoHwDecoderGroup),
        &(g_codecCapabilites.audioHwEncoderGroup), &(g_codecCapabilites.audioHwDecoderGroup),
        &(g_codecCapabilites.videoSwEncoderGroup), &(g_codecCapabilites.videoSwDecoderGroup),
        &(g_codecCapabilites.audioSwEncoderGroup), &(g_codecCapabilites.audioSwDecoderGroup)};

    for (groupIndex = 0; groupIndex < CODEC_CAPABLITY_GROUP_NUM; groupIndex++) {
        group = codeCapGroups[groupIndex];
        if (group == NULL) {
            continue;
        }
        for (capIndex = 0; (capIndex < group->num) && (count > 0); capIndex++) {
            cap = &group->capablitis[capIndex];
            capList[curCount++] = *cap;
        }
    }
    return HDF_SUCCESS;
}
