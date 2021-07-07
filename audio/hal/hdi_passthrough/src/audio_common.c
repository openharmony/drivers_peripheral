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

#include "audio_internal.h"
#include "osal_time.h"

void AudioDlClose(void **ppHandleSo)
{
    if ((ppHandleSo != NULL) && ((*ppHandleSo) != NULL)) {
        dlclose(*ppHandleSo);
        *ppHandleSo = NULL;
    }
    return;
}

void AudioMemFree(void **ppMem)
{
    if ((ppMem != NULL) && ((*ppMem) != NULL)) {
        free(*ppMem);
        *ppMem = NULL;
    }
    return;
}

int32_t AudioGetSysTime(char *s, int32_t len)
{
    OsalTimespec time;
    if (s == NULL) {
        return -1;
    }
    OsalGetTime(&time);
    s[0] = 0;
    int32_t ret = snprintf_s(s, len, len - 1, "[%llu.%llu]", time.sec, time.usec);
    return ret;
}

int32_t AudioCheckParaAttr(const struct AudioSampleAttributes *attrs)
{
    if (NULL == attrs) {
        return HDF_FAILURE;
    }
    enum AudioCategory audioCategory = attrs->type;
    if (AUDIO_IN_MEDIA != audioCategory && AUDIO_IN_COMMUNICATION != audioCategory) {
        return HDF_ERR_NOT_SUPPORT;
    }
    enum AudioFormat audioFormat = attrs->format;
    switch (audioFormat) {
        case AUDIO_FORMAT_PCM_8_BIT:
        case AUDIO_FORMAT_PCM_16_BIT:
        case AUDIO_FORMAT_PCM_24_BIT:
        case AUDIO_FORMAT_PCM_32_BIT:
        case AUDIO_FORMAT_AAC_MAIN:
        case AUDIO_FORMAT_AAC_LC:
        case AUDIO_FORMAT_AAC_LD:
        case AUDIO_FORMAT_AAC_ELD:
        case AUDIO_FORMAT_AAC_HE_V1:
        case AUDIO_FORMAT_AAC_HE_V2:
            break;
        default:
            return HDF_ERR_NOT_SUPPORT;
    }
    uint32_t sampleRateTemp = attrs->sampleRate;
    switch (sampleRateTemp) {
        case TELHPONE_RATE:
        case BROADCAST_AM_RATE:
        case BROADCAST_FM_RATE:
        case MINI_CAM_DV_RATE:
        case MUSIC_RATE:
        case HIGHT_MUSIC_RATE:
            return HDF_SUCCESS;
        default:
            return HDF_ERR_NOT_SUPPORT;
    }
}
