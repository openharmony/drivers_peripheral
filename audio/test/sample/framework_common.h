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

#ifndef FRAMEWORK_COMMON_H
#define FRAMEWORK_COMMON_H

#include <stdio.h>
#include <stdlib.h>

#ifdef IDL_SAMPLE
#include "v5_0/iaudio_manager.h"
#else
#include "audio_manager.h"
#endif

#define AUDIO_FUNC_LOGE(fmt, arg...)                                                     \
    do {                                                                                 \
        printf("%s: [%s]: [%d]:[ERROR]:" fmt "\n", __FILE__, __func__, __LINE__, ##arg); \
    } while (0)

#define WAV_HEAD_OFFSET 44

struct AudioHeadInfo {
    uint32_t riffId;
    uint32_t riffSize;
    uint32_t waveType;
    uint32_t audioFileFmtId;
    uint32_t audioFileFmtSize;
    uint16_t audioFileFormat;
    uint16_t audioChannelNum;
    uint32_t audioSampleRate;
    uint32_t audioByteRate;
    uint16_t audioBlockAlign;
    uint16_t audioBitsPerSample;
    uint32_t dataId;
    uint32_t dataSize;
};

enum AudioPcmBit {
    PCM_8_BIT = 8,   /* 8-bit PCM */
    PCM_16_BIT = 16, /* 16-bit PCM */
    PCM_24_BIT = 24, /* 24-bit PCM */
    PCM_32_BIT = 32, /* 32-bit PCM */
};

struct StrParaCapture {
#ifdef IDL_SAMPLE
    struct IAudioCapture *capture;
#else
    struct AudioCapture *capture;
#endif
    FILE *file;
    struct AudioSampleAttributes attrs;
    uint64_t *replyBytes;
    char *frame;
    int32_t bufferSize;
};

void SystemInputFail(void);
uint32_t StringToInt(const char *flag);
int32_t CheckPcmFormat(int32_t val, uint32_t *audioPcmFormat);
uint32_t PcmFormatToBits(enum AudioFormat formatBit);
void CleanStdin(void);
void FileClose(FILE **file);
int32_t FormatLoadLibPath(char *resolvedPath, int32_t pathLen, int choice);
int32_t SelectAudioCard(struct AudioAdapterDescriptor *descs, int32_t size, int32_t *adapterIndex);
int32_t SwitchAudioPort(
    struct AudioAdapterDescriptor *descs, enum AudioPortDirection portFlag, struct AudioPort *renderPort);
void PrintLoadModeMenu(void);
void PrintAudioInputTypeMenu(void);
int32_t CheckWavFileHeader(FILE *file, struct AudioHeadInfo *wavHeadInfo, struct AudioSampleAttributes *attrs);
int32_t AddWavFileHeader(FILE *file, const struct StrParaCapture *strParam);
#endif
