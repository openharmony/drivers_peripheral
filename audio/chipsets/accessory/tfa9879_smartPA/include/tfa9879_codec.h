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

#ifndef _TFA9879_CODEC_H
#define _TFA9879_CODEC_H

#include "osal_mem.h"
#include "osal_time.h"
#include "osal_io.h"
#include "securec.h"
#include <linux/types.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

/* Hi35xx IO register address */
#define HI35XX_I2C_REG_BASE_ADDR 0x114F0000
#define HI35XX_I2S_REG_BASE_ADDR 0x112F0000

typedef enum Hi35xxRegAddr {
    IOCFG_REG36_ADDR = 0x114F0048,     // I2C6_SCL
    IOCFG_REG37_ADDR = 0x114F004C,     // I2C6_SDA
    IOCFG_REG73_ADDR = 0x112F0020,     // I2S_MCLK
    IOCFG_REG74_ADDR = 0x112F0024,     // I2S_BCLK_TX
    IOCFG_REG75_ADDR = 0x112F0028,     // I2S_WS_TX
    IOCFG_REG76_ADDR = 0x112F002C,     // I2S_SD_TX
    IOCFG_REG77_ADDR = 0x112F0030      // I2S_SD_RX
} Hi35xxRegAddr;

/* TFA9879 I2C Device address 1 1 0 1 1 A2 A1 R/W */
typedef enum Tfa9879I2cDevAddr {
    TFA9879_I2C_DEV_ADDR_ADSEL1        =    0x6D,         // 1101101
    TFA9879_I2C_DEV_ADDR_ADSEL2        =    0x6E,         // 1101110
    TFA9879_I2C_DEV_ADDR_ADSEL1_READ   =    0xDB,         // 1101 1011
    TFA9879_I2C_DEV_ADDR_ADSEL1_WRITE  =    0xDA,         // 1101 1010
    TFA9879_I2C_DEV_ADDR_ADSEL2_READ   =    0xDD,         // 1101 1101
    TFA9879_I2C_DEV_ADDR_ADSEL2_WRITE  =    0xDC          // 1101 1100
} Tfa9879I2cDevAddr;

/* TFA9879 register address */
#define TFA9879_REG_BASE_ADDR 0x00;
typedef enum Tfa9879RegAddr {
    DEVICE_CONTROL_REG_ADDR               =   0x00,
    SERIAL_INTERFACE_INPUT1_REG_ADDR      =   0x01,
    PCM_IOM2_FMT_INPUT1_REG_ADDR          =   0x02,
    SERIAL_INTERFACE_INPUT2_REG_ADDR      =   0x03,
    PCM_IOM2_FMT_INPUT2_REG_ADDR          =   0x04,
    EQUALIZER_A_WORD1_REG_ADDR            =   0x05,
    EQUALIZER_A_WORD2_REG_ADDR            =   0x06,
    EQUALIZER_B_WORD1_REG_ADDR            =   0x07,
    EQUALIZER_B_WORD2_REG_ADDR            =   0x08,
    EQUALIZER_C_WORD1_REG_ADDR            =   0x09,
    EQUALIZER_C_WORD2_REG_ADDR            =   0x0A,
    EQUALIZER_D_WORD1_REG_ADDR            =   0x0B,
    EQUALIZER_D_WORD2_REG_ADDR            =   0x0C,
    EQUALIZER_E_WORD1_REG_ADDR            =   0x0D,
    EQUALIZER_E_WORD2_REG_ADDR            =   0x0E,
    BYPASS_CONTROL_REG_ADDR               =   0x0F,
    DYNAMIC_RANGE_COMP_REG_ADDR           =   0x10,
    BASS_TREBLE_REG_ADDR                  =   0x11,
    HIGH_PASS_FILTER_REG_ADDR             =   0x12,
    VOLUME_CONTROL_REG_ADDR               =   0x13,
    DE_EMPHASIS_REG_ADDR                  =   0x14,
    MISCELLANEOUS_STATUS_REG_ADDR         =   0x15
} Tfa9879RegAddr;

enum I2sFrequency {
    I2S_SAMPLE_FREQUENCY_8000  = 8000,    /* 8kHz sample_rate */
    I2S_SAMPLE_FREQUENCY_11025 = 11025,   /* 11.025kHz sample_rate */
    I2S_SAMPLE_FREQUENCY_12000 = 12000,   /* 12kHz sample_rate */
    I2S_SAMPLE_FREQUENCY_16000 = 16000,   /* 16kHz sample_rate */
    I2S_SAMPLE_FREQUENCY_22050 = 22050,   /* 22.050kHz sample_rate */
    I2S_SAMPLE_FREQUENCY_24000 = 24000,   /* 24kHz sample_rate */
    I2S_SAMPLE_FREQUENCY_32000 = 32000,   /* 32kHz sample_rate */
    I2S_SAMPLE_FREQUENCY_44100 = 44100,   /* 44.1kHz sample_rate */
    I2S_SAMPLE_FREQUENCY_48000 = 48000,   /* 48kHz sample_rate */
    I2S_SAMPLE_FREQUENCY_64000 = 64000,   /* 64kHz sample_rate */
    I2S_SAMPLE_FREQUENCY_88200 = 88200,   /* 88.2kHz sample_rate */
    I2S_SAMPLE_FREQUENCY_96000 = 96000    /* 96kHz sample_rate */
};

enum I2sFrequencyRegVal {
    I2S_SAMPLE_FREQUENCY_REG_VAL_8000  = 0x0,   /* 8kHz sample_rate */
    I2S_SAMPLE_FREQUENCY_REG_VAL_11025 = 0x1,   /* 11.025kHz sample_rate */
    I2S_SAMPLE_FREQUENCY_REG_VAL_12000 = 0x2,   /* 12kHz sample_rate */
    I2S_SAMPLE_FREQUENCY_REG_VAL_16000 = 0x3,   /* 16kHz sample_rate */
    I2S_SAMPLE_FREQUENCY_REG_VAL_22050 = 0x4,   /* 22.050kHz sample_rate */
    I2S_SAMPLE_FREQUENCY_REG_VAL_24000 = 0x5,   /* 24kHz sample_rate */
    I2S_SAMPLE_FREQUENCY_REG_VAL_32000 = 0x6,   /* 32kHz sample_rate */
    I2S_SAMPLE_FREQUENCY_REG_VAL_44100 = 0x7,   /* 44.1kHz sample_rate */
    I2S_SAMPLE_FREQUENCY_REG_VAL_48000 = 0x8,   /* 48kHz sample_rate */
    I2S_SAMPLE_FREQUENCY_REG_VAL_64000 = 0x9,   /* 64kHz sample_rate */
    I2S_SAMPLE_FREQUENCY_REG_VAL_88200 = 0xA,   /* 88.2kHz sample_rate */
    I2S_SAMPLE_FREQUENCY_REG_VAL_96000 = 0xB    /* 96kHz sample_rate */
};

enum I2sFormatRegVal {
    I2S_SAMPLE_FORMAT_REG_VAL_MSB_24    = 0x2,    /*  MSB-justified data up to 24 bits */
    I2S_SAMPLE_FORMAT_REG_VAL_24        = 0x3,    /*  I2S data up to 24 bits */
    I2S_SAMPLE_FORMAT_REG_VAL_LSB_16    = 0x4,    /*  LSB-justified 16-bit data */
    I2S_SAMPLE_FORMAT_REG_VAL_LSB_18    = 0x5,    /*  LSB-justified 18-bit data */
    I2S_SAMPLE_FORMAT_REG_VAL_LSB_20    = 0x6,    /*  LSB-justified 20-bit data */
    I2S_SAMPLE_FORMAT_REG_VAL_LSB_24    = 0x7,    /*  LSB-justified 24-bit data */
};

enum CodecInputSel {
    ADSEL1 = 0,
    ADSEL2 = 1
};

enum CodecOpMode {
    OFF_MODE = 0,
    AMPLIFIER_MODE = 1
};

struct Tfa9879RegAttr {
    uint8_t regAddr;
    uint16_t regValue; // 16bit
};

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif
