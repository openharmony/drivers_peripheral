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

#ifndef AUDIO_COMMON_H
#define AUDIO_COMMON_H

#include "v4_0/audio_types.h"

#ifdef __cplusplus
extern "C" {
#endif

enum AudioLogRecordType {
    AUDIO_INFO,
    AUDIO_DEBUG,
    AUDIO_WARING,
    AUDIO_ERROR,
};

void AudioDlClose(void **ppHandlePassthrough);
void AudioMemFree(void **ppMem);
int32_t AudioGetSysTime(char *s, int32_t len);
int32_t CheckAttrFormat(enum AudioFormat param);
int32_t CheckAttrSamplingRate(uint32_t param);
int32_t AudioCheckParaAttr(const struct AudioSampleAttributes *attrs);
int32_t TimeToAudioTimeStamp(uint64_t bufferFrameSize, struct AudioTimeStamp *time, uint32_t sampleRate);
void AudioLogRecord(int32_t errorLevel, const char *format, ...);
#ifdef __cplusplus
    }
#endif
#endif /* AUDIO_COMMON_H */
