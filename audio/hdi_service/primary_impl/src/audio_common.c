/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "audio_common.h"
#include <dlfcn.h>
#include "hdf_types.h"
#include "osal_mem.h"
#include "osal_time.h"
#include "securec.h"
#include "audio_uhdf_log.h"
#include "audio_internal.h"
#include "v5_0/audio_types.h"

#define FILE_NAME_LEN 256
#define TIME_LEN      32

#define HDF_LOG_TAG HDF_AUDIO_PRIMARY_IMPL

void AudioDlClose(void **ppHandlePassthrough)
{
    if ((ppHandlePassthrough != NULL) && ((*ppHandlePassthrough) != NULL)) {
        dlclose(*ppHandlePassthrough);
        *ppHandlePassthrough = NULL;
    }
    return;
}

void AudioMemFree(void **ppMem)
{
    if ((ppMem != NULL) && ((*ppMem) != NULL)) {
        OsalMemFree(*ppMem);
        *ppMem = NULL;
    }
    return;
}

int32_t AudioGetSysTime(char *s, int32_t len)
{
    OsalTimespec time;
    if (s == NULL) {
        return HDF_FAILURE;
    }
    OsalGetTime(&time);
    s[0] = 0;

    int32_t ret = snprintf_s(s, len, len - 1, "[%llu.%llu]", time.sec, time.usec);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("snprintf_s failed!");
        return HDF_FAILURE;
    }
    return ret;
}

int32_t CheckAttrSamplingRate(uint32_t param)
{
    switch (param) {
        case TELHPONE_RATE:
        case BROADCAST_AM_RATE:
        case BROADCAST_FM_RATE:
        case MINI_CAM_DV_RATE:
        case MUSIC_RATE:
        case HIGHT_MUSIC_RATE:
        case AUDIO_SAMPLE_RATE_12000:
        case AUDIO_SAMPLE_RATE_16000:
        case AUDIO_SAMPLE_RATE_24000:
        case AUDIO_SAMPLE_RATE_64000:
        case AUDIO_SAMPLE_RATE_96000:
            return HDF_SUCCESS;
        default:
            return HDF_ERR_NOT_SUPPORT;
    }
}

int32_t CheckAttrFormat(enum AudioFormat param)
{
    switch (param) {
        case AUDIO_FORMAT_TYPE_PCM_8_BIT:
        case AUDIO_FORMAT_TYPE_PCM_16_BIT:
        case AUDIO_FORMAT_TYPE_PCM_24_BIT:
        case AUDIO_FORMAT_TYPE_PCM_32_BIT:
        case AUDIO_FORMAT_TYPE_AAC_MAIN:
        case AUDIO_FORMAT_TYPE_AAC_LC:
        case AUDIO_FORMAT_TYPE_AAC_LD:
        case AUDIO_FORMAT_TYPE_AAC_ELD:
        case AUDIO_FORMAT_TYPE_AAC_HE_V1:
        case AUDIO_FORMAT_TYPE_AAC_HE_V2:
            break;
        default:
            return HDF_ERR_NOT_SUPPORT;
    }
    return HDF_SUCCESS;
}

int32_t AudioCheckParaAttr(const struct AudioSampleAttributes *attrs)
{
    if (attrs == NULL) {
        AUDIO_FUNC_LOGE("param is null!");
        return HDF_FAILURE;
    }

    enum AudioCategory audioCategory = attrs->type;
    if (audioCategory != AUDIO_IN_MEDIA && audioCategory != AUDIO_IN_COMMUNICATION) {
        AUDIO_FUNC_LOGE("audioCategory error!");
        return HDF_ERR_NOT_SUPPORT;
    }

    enum AudioFormat audioFormat = attrs->format;
    int32_t ret = CheckAttrFormat(audioFormat);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("CheckAttrFormat error!");
        return ret;
    }

    uint32_t sampleRateTemp = attrs->sampleRate;
    return CheckAttrSamplingRate(sampleRateTemp);
}

int32_t TimeToAudioTimeStamp(uint64_t bufferFrameSize, struct AudioTimeStamp *time, uint32_t sampleRate)
{
    if (time == NULL || sampleRate == 0) {
        AUDIO_FUNC_LOGE("param is null!");
        return HDF_FAILURE;
    }

    time->tvSec += (int64_t)(bufferFrameSize / sampleRate);

    int64_t lastBufFrames = ((int64_t)bufferFrameSize) % ((int64_t)sampleRate);

    time->tvNSec += (lastBufFrames * SEC_TO_NSEC) / ((int64_t)sampleRate);
    if (time->tvNSec >= SEC_TO_NSEC) {
        time->tvSec += 1;
        time->tvNSec -= SEC_TO_NSEC;
    }
    return HDF_SUCCESS;
}

void AudioLogRecord(int32_t errorLevel, const char *format, ...)
{
    va_list args;
    FILE *fp = NULL;
    char timeStr[TIME_LEN];
    char fileName[FILE_NAME_LEN];

    va_start(args, format);

    time_t timeLog = time(NULL);
    if (timeLog < 0) {
        va_end(args);
        return;
    }

    struct tm *tmInfo = localtime(&timeLog);
    if (tmInfo == NULL) {
        AUDIO_FUNC_LOGE("localtime failed!");
        va_end(args);
        return;
    }

    (void)strftime(fileName, sizeof(fileName), "//data/%Y-%m-%d_audio_history.log", tmInfo);
    if (fileName[0] == '\0') {
        va_end(args);
        return;
    }

    if ((fp = fopen(fileName, "a+")) != NULL) {
        (void)strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", tmInfo);
        if (errorLevel == (int)AUDIO_INFO) {
            fprintf(fp, "[%s]-[%s]", timeStr, "INFO");
            vfprintf(fp, format, args);
            fprintf(fp, "\n");
        }
        fclose(fp);
    }
    va_end(args);
    return;
}
