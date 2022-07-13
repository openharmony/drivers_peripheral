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

#include "hdf_audio_events.h"
#include <stdlib.h>
#include <string.h>
#include "securec.h"
#include "hdf_base.h"
#include "audio_uhdf_log.h"

#define HDF_LOG_TAG HDF_AUDIO_HAL_HOST

#define STRTOL_FORMART_HEX 16

int32_t AudioPnpMsgReadValue(const char *pnpInfo, const char *typeName, uint32_t *value)
{
    char pnpInfoTemp[AUDIO_PNP_MSG_LEN_MAX] = {0};
    char *typeNameTepm = NULL;
    char *outTemp = NULL;

    if (pnpInfo == NULL || typeName == NULL || value == NULL) {
        AUDIO_FUNC_LOGE("pnpInfo || typeName || value is null!");
        return HDF_FAILURE;
    }
    if (strlen(pnpInfo) > AUDIO_PNP_MSG_LEN_MAX || strlen(typeName) > AUDIO_PNP_MSG_LEN_MAX) {
        AUDIO_FUNC_LOGE("pnpInfo or typeName length error!");
        return HDF_FAILURE;
    }
    if (memcpy_s(pnpInfoTemp, AUDIO_PNP_MSG_LEN_MAX, pnpInfo, strlen(pnpInfo)) != 0) {
        AUDIO_FUNC_LOGE("memcpy_s info fail!");
        return HDF_FAILURE;
    }
    typeNameTepm = strtok_s(pnpInfoTemp, ";", &outTemp);
    while (typeNameTepm) {
        if (!strncmp(typeNameTepm, typeName, strlen(typeName))) {
            typeNameTepm += strlen(typeName) + 1; // 1 is "="
            *value = strtol(typeNameTepm, NULL, STRTOL_FORMART_HEX);
            break;
        }
        typeNameTepm = strtok_s(NULL, ";", &outTemp);
    };

    return HDF_SUCCESS;
}
