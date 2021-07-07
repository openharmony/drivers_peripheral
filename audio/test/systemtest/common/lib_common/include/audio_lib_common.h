/**
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

/**
 * @addtogroup Audio
 * @{
 *
 * @brief Test audio-related APIs, including custom data types and functions for loading drivers,
 * accessing a driver ADM interface lib.
 *
 * @since 1.0
 * @version 1.0
 */

/**
 * @file audio_lib_common.h
 *
 * @brief Declares APIs for operations related to the audio ADM interface lib.
 *
 * @since 1.0
 * @version 1.0
 */

#ifndef AUDIO_LIB_COMMON_H
#define AUDIO_LIB_COMMON_H

#include <gtest/gtest.h>
#include "audio_internal.h"

namespace HMOS {
namespace Audio {
const std::string AUDIO_RIFF = "RIFF";
const std::string AUDIO_WAVE = "WAVE";
const std::string AUDIO_DATA = "data";
const uint32_t INDEX_END = 555;
const int G_CHANNELCOUNT = 2;
const int G_SAMPLERATE = 48000;
const int G_PCM16BIT = 16;
const int G_PCM8BIT = 8;
const int G_PCM24BIT = 24;
const int G_PCM32BIT = 32;
const int G_PERIODSIZE = 4096;
const int G_PERIODCOUNT = 8;
const int G_BYTERATE = 48000;
const int G_BUFFERFRAMESIZE = 0;
const int G_BUFFERSIZE1 = 128;
const int G_SILENCETHRESHOLE = 0;
const int G_PORTID = 0;
const int MOVE_LEFT_NUM = 8;
const int DEEP_BUFFER_RENDER_PERIOD_SIZE = 4096;
const int STOP_THRESHOLD = 32;
const int START_THRESHOLD = 8;

enum AudioPCMBit {
    PCM_8_BIT  = 8,
    PCM_16_BIT = 16,
    PCM_24_BIT = 24,
    PCM_32_BIT = 32,
};

struct AudioHeadInfo {
    uint32_t testFileRiffId;
    uint32_t testFileRiffSize;
    uint32_t testFileFmt;
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

int32_t InitAttrs(struct AudioSampleAttributes& attrs);

int32_t InitRenderFramepara(struct AudioFrameRenderMode& frameRenderMode);

int32_t InitHwCaptureFramepara(struct AudioFrameCaptureMode& frameCaptureMode);

int32_t InitHwRenderMode(struct AudioHwRenderMode& renderMode);

int32_t InitHwCaptureMode(struct AudioHwCaptureMode& captureMode);

int32_t WavHeadAnalysis(struct AudioHeadInfo& wavHeadInfo, FILE *file, struct AudioSampleAttributes& attrs);
}
}
#endif // AUDIO_LIB_COMMON_H

