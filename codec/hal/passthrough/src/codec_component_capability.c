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

#include "codec_component_capability.h"
#include <hdf_log.h>
#include <securec.h>
#include "codec_capability_parser.h"

#define HDF_LOG_TAG codec_hdi_capability

static CodecExInfoGroups g_codecExInfoGroups = {0};

int32_t ClearExInfoData()
{
    return ClearExInfoGroup(&g_codecExInfoGroups);
}

int32_t LoadExInfoData(const struct DeviceResourceNode *node)
{
    return LoadCodecExInfoFromHcs(node, &g_codecExInfoGroups);
}

int32_t GetBasicInfoByCompName(uint8_t *info, const char *compName)
{
    int32_t groupIndex;
    int32_t infoIndex;
    bool isFind = false;
    CodecExInfoGroup *group = NULL;
    CodecExInfo *exInfo = NULL;
    CodecExInfo *exInfoDest = (CodecExInfo *)info;
    CodecExInfoGroup *codeExInfoGroups[] = {
        &(g_codecExInfoGroups.videoHwEncoderGroup), &(g_codecExInfoGroups.videoHwDecoderGroup),
        &(g_codecExInfoGroups.audioHwEncoderGroup), &(g_codecExInfoGroups.audioHwDecoderGroup),
        &(g_codecExInfoGroups.videoSwEncoderGroup), &(g_codecExInfoGroups.videoSwDecoderGroup),
        &(g_codecExInfoGroups.audioSwEncoderGroup), &(g_codecExInfoGroups.audioSwDecoderGroup)
    };

    for (groupIndex = 0; groupIndex < CODEC_CAPABLITY_GROUP_NUM; groupIndex++) {
        group = codeExInfoGroups[groupIndex];
        for (infoIndex = 0; infoIndex < group->num; infoIndex++) {
            exInfo = &group->exInfo[infoIndex];
            if (strcmp(compName, exInfo->compName) == 0) {
                memcpy_s(exInfoDest, sizeof(CodecExInfo), exInfo, sizeof(CodecExInfo));
                isFind = true;
                break;
            }
        }
        if (isFind) {
            break;
        }
    }

    return isFind ? HDF_SUCCESS : HDF_FAILURE;
}
