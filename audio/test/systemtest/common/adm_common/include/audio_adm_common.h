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
 * @brief Defines audio ADM test-related APIs, including data types and functions for writting data
to buffer
 *
 * @since 1.0
 * @version 1.0
 */

/**
 * @file audio_adm_common.h
 *
 * @brief Declares APIs for operations related to the audio ADM testing.
 *
 * @since 1.0
 * @version 1.0
 */

#ifndef AUDIO_ADM_COMMON_H
#define AUDIO_ADM_COMMON_H

#include <gtest/gtest.h>
#include "audio_adapter.h"
#include "audio_internal.h"
#include "audio_types.h"
#include "hdf_io_service_if.h"
#include "osal_mem.h"
#include "hdf_sbuf.h"

namespace HMOS {
namespace Audio {
const std::string HDF_CONTROL_SERVICE = "hdf_audio_control";
const std::string HDF_RENDER_SERVICE = "hdf_audio_render";
const std::string HDF_CAPTURE_SERVICE = "hdf_audio_capture";
const int AUDIODRV_CTL_ELEM_IFACE_DAC = 0; /* virtual dac device */
const int AUDIODRV_CTL_ELEM_IFACE_ADC = 1; /* virtual adc device */
const int AUDIODRV_CTL_ELEM_IFACE_GAIN = 2; /* virtual adc device */
const int AUDIODRV_CTL_ELEM_IFACE_MIXER = 3; /* virtual mixer device */
const int AUDIODRV_CTL_ELEM_IFACE_ACODEC = 4; /* Acodec device */
const int AUDIODRV_CTL_ELEM_IFACE_PGA = 5; /* PGA device */
const int AUDIODRV_CTL_ELEM_IFACE_AIAO = 6; /* AIAO device */
const std::string AUDIO_RIFF = "RIFF";
const std::string AUDIO_WAVE = "WAVE";
const std::string AUDIO_DATA = "data";
const int REGISTER_STATUS_ON = 0;
const int REGISTER_STATUS_OFF = 1;
const int MOVE_LEFT_NUM = 8;
const int G_CHANNELCOUNT = 2;
const int G_SAMPLERATE = 2;
const int G_PCM16BIT = 16;
const int G_PCM8BIT = 8;
const int G_PCM24BIT = 24;
const int Move_Right = 3;

enum ControlDispMethodCmd {
    AUDIODRV_CTL_IOCTL_ELEM_INFO,
    AUDIODRV_CTL_IOCTL_ELEM_READ,
    AUDIODRV_CTL_IOCTL_ELEM_WRITE,
    AUDIODRV_CTL_IOCTL_ELEM_BUTT,
};

enum StreamDispMethodCmd {
    AUDIO_DRV_PCM_IOCTRL_HW_PARAMS,
    AUDIO_DRV_PCM_IOCTRL_RENDER_PREPARE,
    AUDIO_DRV_PCM_IOCTRL_CAPTURE_PREPARE,
    AUDIO_DRV_PCM_IOCTRL_WRITE,
    AUDIO_DRV_PCM_IOCTRL_READ,
    AUDIO_DRV_PCM_IOCTRL_RENDER_START,
    AUDIO_DRV_PCM_IOCTRL_RENDER_STOP,
    AUDIO_DRV_PCM_IOCTRL_CAPTURE_START,
    AUDIO_DRV_PCM_IOCTRL_CAPTURE_STOP,
    AUDIO_DRV_PCM_IOCTRL_RENDER_PAUSE,
    AUDIO_DRV_PCM_IOCTRL_CAPTURE_PAUSE,
    AUDIO_DRV_PCM_IOCTRL_RENDER_RESUME,
    AUDIO_DRV_PCM_IOCTRL_CAPTURE_RESUME,
    AUDIO_DRV_PCM_IOCTRL_BUTT,
};

struct AudioPcmHwParams {
    enum AudioStreamType streamType;
    uint32_t channels;
    uint32_t rate;
    uint32_t periodSize;
    uint32_t periodCount;
    enum AudioFormat format;
    const char *cardServiceName;
    uint32_t period;
    uint32_t frameSize;
    bool isBigEndian;
    bool isSignedData;
    uint32_t startThreshold;
    uint32_t stopThreshold;
    uint32_t silenceThreshold;
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

struct AudioXferi {
    char *buf;
    unsigned long bufsize;
    unsigned long frameSize;
};

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

int32_t WriteIdToBuf(struct HdfSBuf *sBuf, struct AudioCtlElemId id);

int32_t WriteEleValueToBuf(struct HdfSBuf *sBuf, struct AudioCtlElemValue elemvalue);

int32_t WriteHwParamsToBuf(struct HdfSBuf *sBuf, struct AudioPcmHwParams hwParams);

int32_t WavHeadAnalysis(struct AudioHeadInfo& wavHeadInfo, FILE *file, struct AudioSampleAttributes& attrs);

uint32_t PcmFormatToBitsCapture(enum AudioFormat format);

int32_t InitAttrs(struct AudioSampleAttributes& attrs);

int32_t AdmRenderFramePrepare(const std::string path, char *&frame, unsigned long& numRead, unsigned long& frameSize);

uint32_t FormatToBits(enum AudioFormat format);

uint32_t PcmBytesToFrames(const struct AudioFrameRenderMode& frameRenderMode, uint64_t bytes);

int32_t WriteFrameToSBuf(struct HdfSBuf *&sBufT, char *buf, unsigned long bufsize,
    unsigned long frameSize, const std::string path);

int32_t ObtainBuf(struct HdfSBuf *&writeBuf, struct HdfSBuf *&readBuf, struct HdfSBuf *&readReply);
}
}
#endif // AUDIO_ADM_COMMON_H

