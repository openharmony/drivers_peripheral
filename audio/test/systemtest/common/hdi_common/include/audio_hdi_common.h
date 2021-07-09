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
 * @brief Defines audio-related APIs, including custom data types and functions for loading drivers,
 * accessing a driver adapter, and rendering and capturing audios.
 *
 * @since 1.0
 * @version 1.0
 */

/**
 * @file audio_adapter.h
 *
 * @brief Declares APIs for operations related to the audio adapter.
 *
 * @since 1.0
 * @version 1.0
 */

#ifndef AUDIO_HDI_COMMON_H
#define AUDIO_HDI_COMMON_H

#include <gtest/gtest.h>
#include "audio_adapter.h"
#include "audio_internal.h"
#include "audio_types.h"
#include "hdf_io_service_if.h"
#include "hdf_sbuf.h"

namespace HMOS {
namespace Audio {
const std::string AUDIO_RIFF = "RIFF";
const std::string AUDIO_WAVE = "WAVE";
const std::string AUDIO_DATA = "data";
const uint32_t INT_32_MAX = 0x7fffffff;
const uint32_t INDEX_END = 555;
const int MOVE_LEFT_NUM = 8;
const int CHANNELCOUNT = 2;
const int SAMPLERATE = 48000;
const int DEEP_BUFFER_RENDER_PERIOD_SIZE = 4096;
const float GAIN_MIN = 0;
const float GAIN_MAX = 15;
const uint64_t INITIAL_VALUE = 0;
const int BUFFER_LENTH = 1024 * 16;
const uint64_t MEGABYTE = 1024;
const int FRAME_SIZE = 1024;
const std::string HDF_CONTROL_SERVICE = "hdf_audio_control";
const int AUDIODRV_CTL_ELEM_IFACE_DAC = 0; /* virtual dac device */
const int AUDIODRV_CTL_ELEM_IFACE_PGA = 5;
enum ControlDispMethodCmd {
    AUDIODRV_CTRL_IOCTRL_ELEM_INFO,
    AUDIODRV_CTRL_IOCTRL_ELEM_READ,
    AUDIODRV_CTRL_IOCTRL_ELEM_WRITE,
    AUDIODRV_CTRL_IOCTRL_ELEM_BUTT,
};

enum AudioPCMBit {
    PCM_8_BIT  = 8,
    PCM_16_BIT = 16,
    PCM_24_BIT = 24,
    PCM_32_BIT = 32,
};

struct AudioCtlElemId {
    const char *cardServiceName;
    int32_t iface;
    const char *itemName; /* ASCII name of item */
};

struct AudioCtlElemValue {
    struct AudioCtlElemId id;
    int32_t value[2];
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

int32_t InitDevDesc(struct AudioDeviceDescriptor& devDesc, const uint32_t portId, enum AudioPortPin pins);

int32_t SwitchAdapter(struct AudioAdapterDescriptor *descs, const std::string adapterNameCase,
    enum AudioPortDirection portFlag, struct AudioPort& audioPort, int size);

uint32_t PcmFormatToBits(enum AudioFormat format);

uint32_t PcmFramesToBytes(const struct AudioSampleAttributes attrs);

int32_t WavHeadAnalysis(struct AudioHeadInfo& wavHeadInfo, FILE *file, struct AudioSampleAttributes& attrs);

int32_t FrameStart(struct AudioHeadInfo wavHeadInfo, struct AudioRender *render, FILE *file,
    struct AudioSampleAttributes attrs);

int32_t FrameStartCapture(struct AudioCapture *capture, FILE *file, const struct AudioSampleAttributes attrs);

uint32_t PcmFormatToBitsCapture(enum AudioFormat format);

int32_t RenderFramePrepare(const std::string path, char *&frame, uint64_t& numRead);

void CaptureFrameStatus(int status);

int32_t StartRecord(struct AudioCapture *capture, FILE *file, uint64_t filesize);

int32_t PowerOff(struct AudioCtlElemValue firstElemValue, struct AudioCtlElemValue secondElemValue);

int32_t CheckRegisterStatus(const struct AudioCtlElemId firstId, const struct AudioCtlElemId secondId,
    const int firstStatus, const int secondStatus);
}
}
#endif // AUDIO_HDI_COMMON_H

