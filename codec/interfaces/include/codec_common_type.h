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

/**
 * @addtogroup Codec
 * @{
 *
 * @brief Defines APIs related to the Codec module.
 *
 * The Codec module provides APIs for initializing the custom data and audio and video codecs,
 * setting codec parameters, and controlling and transferring data.
 *
 * @since 3.1
 */

/**
 * @file codec_common_type.h
 *
 * @brief Declares custom data types used in the Codec module APIs, including the codec types,
 * audio and video parameters, and buffers.
 *
 * @since 3.1
 */

#ifndef CODEC_COMMON_TYPE_H
#define CODEC_COMMON_TYPE_H

#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

/**
 * @brief Enumerates the codec types.
 */
typedef enum {
    /** Video decoder */
    VIDEO_DECODER,
    /** Video encoder */
    VIDEO_ENCODER,
    /** Audio decoder */
    AUDIO_DECODER,
    /** Audio encoder */
    AUDIO_ENCODER,
    /** Invalid type */
    INVALID_TYPE
} CodecType;

/**
 * @brief Enumerates the codec profiles.
 */
typedef enum {
    /** Invalid profile */
    INVALID_PROFILE = 0,
    /** AAC-Low Complex */
    AAC_LC_PROFILE = 0x1000,
    /** AAC-Main */
    AAC_MAIN_PROFILE,
    /** HEAAC, AAC+, or AACPlusV1 */
    AAC_HE_V1_PROFILE,
    /** AAC++ or AACPlusV2 */
    AAC_HE_V2_PROFILE,
    /** AAC-Low Delay */
    AAC_LD_PROFILE,
    /** AAC-Enhanced Low Delay */
    AAC_ELD_PROFILE,
    /** H.264 Baseline */
    AVC_BASELINE_PROFILE = 0x2000,
    /** H.264 Main */
    AVC_MAIN_PROFILE,
    /** H.264 High */
    AVC_HIGH_PROFILE,
    /** H.265 Main */
    HEVC_MAIN_PROFILE = 0x3000,
    /** H.265 Main 10 */
    HEVC_MAIN_10_PROFILE,
} Profile;

/**
 * @brief Enumerates the audio sampling rates.
 */
typedef enum {
    /** 8 kHz */
    AUD_SAMPLE_RATE_8000   = 8000,
    /** 12 kHz */
    AUD_SAMPLE_RATE_12000  = 12000,
    /** 11.025 kHz */
    AUD_SAMPLE_RATE_11025  = 11025,
    /** 16 kHz */
    AUD_SAMPLE_RATE_16000  = 16000,
    /** 22.050 kHz */
    AUD_SAMPLE_RATE_22050  = 22050,
    /** 24 kHz */
    AUD_SAMPLE_RATE_24000  = 24000,
    /** 32 kHz */
    AUD_SAMPLE_RATE_32000  = 32000,
    /** 44.1 kHz */
    AUD_SAMPLE_RATE_44100  = 44100,
    /** 48 kHz */
    AUD_SAMPLE_RATE_48000  = 48000,
    /** 64 kHz */
    AUD_SAMPLE_RATE_64000  = 64000,
    /** 96 kHz */
    AUD_SAMPLE_RATE_96000  = 96000,
    /** Invalid sampling rate */
    AUD_SAMPLE_RATE_INVALID,
} AudioSampleRate;

/**
* @brief Defines the alignment.
 */
typedef struct {
    int32_t widthAlignment; /** Value to align with the width */
    int32_t heightAlignment; /** Value to align with the height */
} Alignment;

/**
 * @brief Defines a rectangle.
 */
typedef struct {
    int32_t width;  /** Width of the rectangle */
    int32_t height; /** Height of the rectangle */
} Rect;

/**
 * @brief Defines a value range.
 */
typedef struct {
    int32_t min; /** Minimum value */
    int32_t max; /** Maximum value */
} RangeValue;

/**
 * @brief Enumerates the playback capabilities.
 */
typedef enum {
    /** Adaptive playback */
    CODEC_CAP_ADAPTIVE_PLAYBACK = 0x1,
    /** Secure playback */
    CODEC_CAP_SECURE_PLAYBACK = 0x2,
    /** Tunnel playback */
    CODEC_CAP_TUNNEL_PLAYBACK = 0x4,
    /** Multi-plane (video image plane and audio tunnel plane) playback */
    CODEC_CAP_MULTI_PLANE = 0x10000,
} CodecCapsMask;

/**
 * @brief Enumerates the codec processing modes.
 */
typedef enum {
    /** Input buffer in sync mode */
    PROCESS_BLOCKING_INPUT_BUFFER     = 0X1,
    /** Output buffer in sync mode */
    PROCESS_BLOCKING_OUTPUT_BUFFER    = 0X2,
    /** Control flow in sync mode */
    PROCESS_BLOCKING_CONTROL_FLOW     = 0X4,
    /** Input buffer in async mode */
    PROCESS_NONBLOCKING_INPUT_BUFFER  = 0X100,
    /** Output buffer in async mode */
    PROCESS_NONBLOCKING_OUTPUT_BUFFER = 0X200,
    /** Control flow in async mode */
    PROCESS_NONBLOCKING_CONTROL_FLOW  = 0X400,
} CodecProcessMode;

/**
 * @brief Enumerate the audio sampling formats.
 *
 * For the planar sampling format, the data of each channel is independently stored in data.
 * For the packed sampling format, only the first data is used, and the data of each channel is interleaved.
 */
typedef enum {
    /** Unsigned 8 bits, packed */
    AUDIO_SAMPLE_FMT_U8,
    /** Signed 16 bits, packed */
    AUDIO_SAMPLE_FMT_S16,
    /** Signed 32 bits, packed */
    AUDIO_SAMPLE_FMT_S32,
    /** Float, packed */
    AUDIO_SAMPLE_FMT_FLOAT,
    /** Double, packed */
    AUDIO_SAMPLE_FMT_DOUBLE,
    /** Unsigned 8 bits, planar */
    AUDIO_SAMPLE_FMT_U8P,
    /** Signed 16 bits, planar */
    AUDIO_SAMPLE_FMT_S16P,
    /** Signed 32 bits, planar */
    AUDIO_SAMPLE_FMT_S32P,
    /** Float, planar */
    AUDIO_SAMPLE_FMT_FLOATP,
    /** Double, planar */
    AUDIO_SAMPLE_FMT_DOUBLEP,
    /** Invalid sampling format */
    AUDIO_SAMPLE_FMT_INVALID,
} CodecAudioSampleFormat;

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* CODEC_COMMON_TYPE_H */
/** @} */