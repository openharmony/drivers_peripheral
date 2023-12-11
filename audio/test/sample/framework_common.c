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

#include "framework_common.h"
#include <string.h>
#include "securec.h"
#include "hdf_base.h"

#define MOVE_LEFT_NUM        8
#define WAV_HEAD_RIFF_OFFSET 8

int32_t SwitchAudioPort(
    struct AudioAdapterDescriptor *descs, enum AudioPortDirection portFlag, struct AudioPort *renderPort)
{
    uint32_t port;
    uint32_t portNum;

    if (descs == NULL || renderPort == NULL) {
        return HDF_FAILURE;
    }
#ifdef IDL_SAMPLE
    portNum = descs->portsLen;
#else
    portNum = descs->portNum;
#endif
    for (port = 0; port < portNum; port++) {
        if (descs->ports[port].dir == portFlag) {
            *renderPort = descs->ports[port];
            return HDF_SUCCESS;
        }
    }

    AUDIO_FUNC_LOGE("AudioPort Switch fail");
    return HDF_ERR_NOT_SUPPORT;
}

int32_t SelectAudioCard(struct AudioAdapterDescriptor *descs, int32_t size, int32_t *adapterIndex)
{
    int32_t i;
    errno_t ret;

    if (descs == NULL || adapterIndex == NULL || size <= 0) {
        return HDF_ERR_INVALID_PARAM;
    }

    printf(" ================= Select Audio Card ==================\n");
    for (i = 0; i < size; i++) {
        printf(" %d. %s\n", i + 1, descs[i].adapterName);
    }
    printf(" ======================================================\n");
    printf("Please enter your choice:\n");
    ret = scanf_s("%d", adapterIndex);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Input error occurs!");
        return HDF_FAILURE;
    }
    if (*adapterIndex <= 0 || *adapterIndex > size) {
        *adapterIndex = 1; // 1 for default audio card
        printf("Input error, Default audio card selected: %s\n", descs[*adapterIndex - 1].adapterName);
    }

    return HDF_SUCCESS;
}

void PrintLoadModeMenu(void)
{
    printf(" ==================== Loading Mode =================== \n");
    printf("| 1. Passthrough Loading                               |\n");
    printf("| 2. IPC Loading                                       |\n");
    printf(" ====================================================== \n");
}

int32_t CheckWavFileHeader(FILE *file, struct AudioHeadInfo *wavHeadInfo, struct AudioSampleAttributes *attrs)
{
    if (file == NULL || wavHeadInfo == NULL || attrs == NULL) {
        AUDIO_FUNC_LOGE("params is null\n");
        return HDF_FAILURE;
    }

    if (fread(wavHeadInfo, sizeof(struct AudioHeadInfo), 1, file) != 1) {
        AUDIO_FUNC_LOGE("fread fail\n");
        return HDF_FAILURE;
    }

    uint32_t audioRiffId = StringToInt("RIFF");
    uint32_t audioFileFmt = StringToInt("WAVE");
    if (wavHeadInfo->riffId != audioRiffId || wavHeadInfo->waveType != audioFileFmt) {
        AUDIO_FUNC_LOGE("wav file head check fail\n");
        return HDF_FAILURE;
    }
    printf("Music channels = %u\n", wavHeadInfo->audioChannelNum);
    printf("Music Rate     = %u Hz\n", wavHeadInfo->audioSampleRate);
    printf("Music Bit      = %u bit\n", wavHeadInfo->audioBitsPerSample);

    attrs->channelCount = wavHeadInfo->audioChannelNum;
    attrs->sampleRate = wavHeadInfo->audioSampleRate;
    switch (wavHeadInfo->audioBitsPerSample) {
        case PCM_8_BIT: {
            attrs->format = AUDIO_FORMAT_TYPE_PCM_8_BIT;
            break;
        }
        case PCM_16_BIT: {
            attrs->format = AUDIO_FORMAT_TYPE_PCM_16_BIT;
            break;
        }
        case PCM_24_BIT: {
            attrs->format = AUDIO_FORMAT_TYPE_PCM_24_BIT;
            break;
        }
        case PCM_32_BIT: {
            attrs->format = AUDIO_FORMAT_TYPE_PCM_32_BIT;
            break;
        }
        default:
            AUDIO_FUNC_LOGE("wav format not in (8-bit|16-bit|24-bit|32-bit)\n");
            return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AddWavFileHeader(FILE *file, const struct StrParaCapture *strParam)
{
    struct AudioHeadInfo headInfo;

    if (strParam == NULL) {
        AUDIO_FUNC_LOGE("params is NULL");
        return HDF_FAILURE;
    }

    (void)fseek(file, 0, SEEK_END);
    headInfo.riffId = StringToInt("RIFF");
    headInfo.riffSize = (uint32_t)ftell(file) - WAV_HEAD_RIFF_OFFSET;
    headInfo.waveType = StringToInt("WAVE");
    headInfo.audioFileFmtId = StringToInt("fmt ");
    headInfo.audioFileFmtSize = PcmFormatToBits(strParam->attrs.format);
    headInfo.audioFileFormat = 1;
    headInfo.audioChannelNum = strParam->attrs.channelCount;
    headInfo.audioSampleRate = strParam->attrs.sampleRate;
    headInfo.audioByteRate =
        headInfo.audioSampleRate * headInfo.audioChannelNum * headInfo.audioFileFmtSize / PCM_8_BIT;
    headInfo.audioBlockAlign = (uint16_t)(headInfo.audioChannelNum * headInfo.audioFileFmtSize / PCM_8_BIT);
    headInfo.audioBitsPerSample = (uint16_t)headInfo.audioFileFmtSize;
    headInfo.dataId = StringToInt("data");
    headInfo.dataSize = (uint32_t)ftell(file) - WAV_HEAD_OFFSET;
    rewind(file);

    if (fwrite(&headInfo, sizeof(struct AudioHeadInfo), 1, file) != 1) {
        AUDIO_FUNC_LOGE("write wav file head error");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

void SystemInputFail(void)
{
    printf("please ENTER to go on...\n");
    while (getchar() != '\n') {
    }
}

uint32_t StringToInt(const char *flag)
{
    if (flag == NULL) {
        return 0;
    }
    uint32_t temp = flag[0];
    for (int32_t i = (int32_t)strlen(flag) - 1; i >= 0; i--) {
        temp <<= MOVE_LEFT_NUM;
        temp += flag[i];
    }
    return temp;
}

int32_t CheckPcmFormat(int32_t val, uint32_t *audioPcmFormat)
{
    if (audioPcmFormat == NULL) {
        AUDIO_FUNC_LOGE("fomat is null!");
        return HDF_FAILURE;
    }
    switch (val) {
        case AUDIO_FORMAT_TYPE_PCM_8_BIT:
            *audioPcmFormat = AUDIO_FORMAT_TYPE_PCM_8_BIT;
            break;
        case AUDIO_FORMAT_TYPE_PCM_16_BIT:
            *audioPcmFormat = AUDIO_FORMAT_TYPE_PCM_16_BIT;
            break;
        case AUDIO_FORMAT_TYPE_PCM_24_BIT:
            *audioPcmFormat = AUDIO_FORMAT_TYPE_PCM_24_BIT;
            break;
        case AUDIO_FORMAT_TYPE_PCM_32_BIT:
            *audioPcmFormat = AUDIO_FORMAT_TYPE_PCM_32_BIT;
            break;
        default:
            *audioPcmFormat = AUDIO_FORMAT_TYPE_PCM_16_BIT;
            break;
    }

    return HDF_SUCCESS;
}

uint32_t PcmFormatToBits(enum AudioFormat formatBit)
{
    switch (formatBit) {
        case AUDIO_FORMAT_TYPE_PCM_16_BIT:
            return PCM_16_BIT;
        case AUDIO_FORMAT_TYPE_PCM_8_BIT:
            return PCM_8_BIT;
        default:
            return PCM_16_BIT;
    }
}

void CleanStdin(void)
{
    int c;
    do {
        c = getchar();
    } while (c != '\n' && c != EOF);
}

void FileClose(FILE **file)
{
    if ((file != NULL) && ((*file) != NULL)) {
        (void)fclose(*file);
        *file = NULL;
    }
    return;
}

void PrintAudioInputTypeMenu(void)
{
    printf(" ================= Audio Input Type =============== \n");
    printf("| 0. mic input type                                |\n");
    printf("| 1. speech wakeup input type                      |\n");
    printf("| 2. voice communication input typ                 |\n");
    printf("| 3. voice recognition input type                  |\n");
    printf("| 4. voice uplink input type                       |\n");
    printf("| 5. voice downlink input type                     |\n");
    printf("| 6. voice call input type                         |\n");
    printf("| 7. camcorder input type                          |\n");
    printf("| other. default input type                        |\n");
    printf(" ================================================== \n");
}