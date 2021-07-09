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

#include "audio_lib_common.h"

using namespace std;

namespace HMOS {
namespace Audio {
int32_t InitAttrs(struct AudioSampleAttributes& attrs)
{
    attrs.format = AUDIO_FORMAT_PCM_16_BIT;
    attrs.channelCount = G_CHANNELCOUNT;
    attrs.sampleRate = G_SAMPLERATE;
    attrs.interleaved = 0;
    attrs.type = AUDIO_IN_MEDIA;
    attrs.period = DEEP_BUFFER_RENDER_PERIOD_SIZE;
    attrs.frameSize = G_PCM16BIT * G_CHANNELCOUNT / MOVE_LEFT_NUM;
    attrs.isBigEndian = true;
    attrs.isSignedData = true;
    attrs.startThreshold = DEEP_BUFFER_RENDER_PERIOD_SIZE / (G_PCM16BIT * attrs.channelCount / MOVE_LEFT_NUM);
    attrs.stopThreshold = STOP_THRESHOLD;
    attrs.silenceThreshold = 0;
    return HDF_SUCCESS;
}

int32_t InitRenderFramepara(struct AudioFrameRenderMode& frameRenderMode)
{
    InitAttrs(frameRenderMode.attrs);
    frameRenderMode.frames = AUDIO_FORMAT_PCM_16_BIT;
    frameRenderMode.mode = AUDIO_CHANNEL_BOTH_RIGHT;
    frameRenderMode.periodSize = G_PERIODSIZE;
    frameRenderMode.periodCount = G_PERIODCOUNT;
    frameRenderMode.byteRate = G_BYTERATE;
    frameRenderMode.bufferFrameSize = G_BUFFERFRAMESIZE;
    frameRenderMode.bufferSize = G_BUFFERSIZE1;
    frameRenderMode.buffer = NULL;
    frameRenderMode.silenceThreshold = frameRenderMode.periodSize * frameRenderMode.periodCount;
    frameRenderMode.silenceSize = G_SILENCETHRESHOLE;
    frameRenderMode.startThreshold = frameRenderMode.periodSize;
    frameRenderMode.stopThreshold = frameRenderMode.periodSize * frameRenderMode.periodCount;
    return HDF_SUCCESS;
}

int32_t InitHwCaptureFramepara(struct AudioFrameCaptureMode& frameCaptureMode)
{
    InitAttrs(frameCaptureMode.attrs);
    frameCaptureMode.mode = AUDIO_CHANNEL_BOTH_RIGHT;
    frameCaptureMode.byteRate = G_BYTERATE;
    frameCaptureMode.periodSize = G_PERIODSIZE;
    frameCaptureMode.periodCount = G_PERIODCOUNT;
    frameCaptureMode.startThreshold = frameCaptureMode.periodSize;
    frameCaptureMode.stopThreshold = frameCaptureMode.periodSize * frameCaptureMode.periodCount;
    frameCaptureMode.silenceThreshold = frameCaptureMode.periodSize * frameCaptureMode.periodCount;
    frameCaptureMode.silenceSize = G_SILENCETHRESHOLE;
    frameCaptureMode.buffer = NULL;
    frameCaptureMode.bufferFrameSize = G_BUFFERFRAMESIZE;
    frameCaptureMode.bufferSize = G_BUFFERSIZE1;
    return HDF_SUCCESS;
}

int32_t InitHwRenderMode(struct AudioHwRenderMode& renderMode)
{
    renderMode.hwInfo.card = AUDIO_SERVICE_IN;
    renderMode.hwInfo.portDescript.dir = PORT_OUT;
    renderMode.hwInfo.portDescript.portId = G_PORTID;
    renderMode.hwInfo.portDescript.portName = "AOP";
    renderMode.hwInfo.deviceDescript.portId = G_PORTID;
    renderMode.hwInfo.deviceDescript.pins = PIN_OUT_SPEAKER;
    renderMode.hwInfo.deviceDescript.desc = nullptr;
    return HDF_SUCCESS;
}

int32_t InitHwCaptureMode(struct AudioHwCaptureMode& captureMode)
{
    captureMode.hwInfo.card = AUDIO_SERVICE_IN;
    captureMode.hwInfo.portDescript.dir = PORT_IN;
    captureMode.hwInfo.portDescript.portId = 0;
    captureMode.hwInfo.portDescript.portName = "AIP";
    captureMode.hwInfo.deviceDescript.portId = 0;
    captureMode.hwInfo.deviceDescript.pins = PIN_IN_MIC;
    captureMode.hwInfo.deviceDescript.desc = nullptr;
    return HDF_SUCCESS;
}

uint32_t StringToInt(std::string flag)
{
    uint32_t temp = flag[0];
    for (int i = flag.size() - 1; i >= 0; i--) {
        temp <<= MOVE_LEFT_NUM;
        temp += flag[i];
    }
    return temp;
}

int32_t WavHeadAnalysis(struct AudioHeadInfo& wavHeadInfo, FILE *file, struct AudioSampleAttributes& attrs)
{
    int32_t ret = 0;
    if (file == nullptr) {
        return HDF_FAILURE;
    }
    ret = fread(&wavHeadInfo, sizeof(wavHeadInfo), 1, file);
    if (ret != 1) {
        return HDF_FAILURE;
    }
    uint32_t audioRiffId = StringToInt(AUDIO_RIFF);
    uint32_t audioFileFmt = StringToInt(AUDIO_WAVE);
    uint32_t aduioDataId = StringToInt(AUDIO_DATA);
    if (wavHeadInfo.testFileRiffId != audioRiffId || wavHeadInfo.testFileFmt != audioFileFmt ||
        wavHeadInfo.dataId != aduioDataId) {
        return HDF_FAILURE;
    }
    attrs.channelCount = wavHeadInfo.audioChannelNum;
    attrs.sampleRate = wavHeadInfo.audioSampleRate;
    switch (wavHeadInfo.audioBitsPerSample) {
        case PCM_8_BIT: {
            attrs.format = AUDIO_FORMAT_PCM_8_BIT;
            break;
        }
        case PCM_16_BIT: {
            attrs.format = AUDIO_FORMAT_PCM_16_BIT;
            break;
        }
        case PCM_24_BIT: {
            attrs.format = AUDIO_FORMAT_PCM_24_BIT;
            break;
        }
        case PCM_32_BIT: {
            attrs.format = AUDIO_FORMAT_PCM_32_BIT;
            break;
        }
        default:
            return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
}
}