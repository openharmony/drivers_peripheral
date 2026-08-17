/*
 * Copyright (c) 2020-2022 Huawei Device Co., Ltd.
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
 * @brief Defines common data types shared between codec_common_type.h and codec_lite_type.h.
 *
 * @since 1.0
 * @version 1.0
 */

/**
 * @file codec_common_lite_type.h
 *
 * @brief Declares common data types used by MEDIA_INTERFACE_V1_0 (lite),
 * which share names with types in codec_common_type.h.
 *
 * @since 1.0
 * @version 1.0
 */

#ifndef CODEC_COMMON_LITE_TYPE_H
#define CODEC_COMMON_LITE_TYPE_H

#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

/**
 * @brief Enumerates codec types.
 */
typedef enum {
    VIDEO_DECODER, /**< Video decoding */
    VIDEO_ENCODER, /**< Video encoding */
    AUDIO_DECODER, /**< Audio decoding */
    AUDIO_ENCODER, /**< Audio encoding */
    INVALID_TYPE   /**< Invalid type */
} CodecType;

/**
 * @brief Enumerates codec profiles.
 */
typedef enum {
    INVALID_PROFILE = 0,               /**< Invalid profile */
    AAC_LC_PROFILE = 0x1000,           /**< AAC-Low Complex */
    AAC_MAIN_PROFILE,                  /**< AAC-Main */
    AAC_HE_V1_PROFILE,                 /**< HEAAC,  AAC+, or AACPlusV1 */
    AAC_HE_V2_PROFILE,                 /**< AAC++ or AACPlusV2 */
    AAC_LD_PROFILE,                    /**< AAC-Low Delay */
    AAC_ELD_PROFILE,                   /**< AAC-Enhanced Low Delay */
    AVC_BASELINE_PROFILE = 0x2000,     /**< H.264 Baseline */
    AVC_MAIN_PROFILE,                  /**< H.264 Main */
    AVC_HIGH_PROFILE,                  /**< H.264 High */
    HEVC_MAIN_PROFILE = 0x3000,        /**< H.265 Main */
    HEVC_MAIN_10_PROFILE,              /**< H.265 Main 10 */
} Profile;

/**
 * @brief Enumerates audio sampling rates.
 */
typedef enum {
    AUD_SAMPLE_RATE_8000   = 8000,    /**< 8 KHz */
    AUD_SAMPLE_RATE_12000  = 12000,   /**< 12 KHz */
    AUD_SAMPLE_RATE_11025  = 11025,   /**< 11.025 KHz */
    AUD_SAMPLE_RATE_16000  = 16000,   /**< 16 KHz */
    AUD_SAMPLE_RATE_22050  = 22050,   /**< 22.050 KHz */
    AUD_SAMPLE_RATE_24000  = 24000,   /**< 24 KHz */
    AUD_SAMPLE_RATE_32000  = 32000,   /**< 32 KHz  */
    AUD_SAMPLE_RATE_44100  = 44100,   /**< 44.1 KHz */
    AUD_SAMPLE_RATE_48000  = 48000,   /**< 48 KHz */
    AUD_SAMPLE_RATE_64000  = 64000,   /**< 64 KHz */
    AUD_SAMPLE_RATE_96000  = 96000,   /**< 96 KHz */
    AUD_SAMPLE_RATE_INVALID,          /**< Invalid sampling rate */
} AudioSampleRate;

/**
 * @brief Defines a rectangle.
 */
typedef struct {
    int32_t width;  /**< Width */
    int32_t height; /**< Height */
} Rect;

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* CODEC_COMMON_LITE_TYPE_H */
/** @} */
