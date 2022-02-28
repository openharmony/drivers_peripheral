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

#ifndef CODEC_COMPONENT_TYPE_H
#define CODEC_COMPONENT_TYPE_H

#include <stdint.h>
#include <stdbool.h>
#include "OMX_Types.h"
#include "OMX_Index.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

#define SAMPLE_FMT_NUM 32

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
 * @brief Enumerates role types.
 */
typedef enum {
    MEDIA_ROLETYPE_IMAGE_JPEG = 0,        /**< JPEG image */
    MEDIA_ROLETYPE_VIDEO_AVC,             /**< H.264 video */
    MEDIA_ROLETYPE_VIDEO_HEVC,            /**< H.265 video */

    MEDIA_ROLETYPE_AUDIO_FIRST = 0x10000, /**< Dummy id pointing at the start of audio codecs */
    MEDIA_ROLETYPE_AUDIO_AAC = 0x10000,   /**< AAC audio */
    MEDIA_ROLETYPE_AUDIO_G711A,           /**< G711A audio */
    MEDIA_ROLETYPE_AUDIO_G711U,           /**< G711U audio */
    MEDIA_ROLETYPE_AUDIO_G726,            /**< G726 audio */
    MEDIA_ROLETYPE_AUDIO_PCM,             /**< PCM audio */
    MEDIA_ROLETYPE_AUDIO_MP3,             /**< MP3 audio */
    MEDIA_ROLETYPE_INVALID,               /**< Invalid role type */
} AvCodecRole;

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
* @brief Defines the alignment.
 */
typedef struct {
    int widthAlginment;  /**< Value to align with the width */
    int heightAlginment; /**< Value to align with the height */
} Alginment;

/**
 * @brief Defines a rectangle.
 */
typedef struct {
    int32_t width;  /**< Width */
    int32_t height; /**< Height */
} Rect;

/**
 * @brief Defines a range.
 */
typedef struct {
    int32_t min; /**< Lower end of the range. */
    int32_t max; /**< Upper end of the range. */
} RangeValue;

/**
 * @brief Enumerates playback capabilities.
 */
typedef enum {
    CODEC_CAP_ADAPTIVE_PLAYBACK = 0x1, /**< Adaptive playback */
    CODEC_CAP_SECURE_PLAYBACK   = 0x2, /**< Secure playback */
    CODEC_CAP_TUNNEL_PLAYBACK   = 0x4, /**< Tunnel playback */

    CODEC_CAP_MULTI_PLANE = 0x10000,    /**< Video picture planes/audio channel planar */
} CodecCapsMask;

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
 * @brief Enumerates audio sample formats.
 * For planar sample formats, each audio channel is in a seperate data plane.
 * For packed sample formats, only the first data plane is used, and samples for each channel are interleaved.
 */
typedef enum {
    AUDIO_SAMPLE_FMT_U8,      /**< Unsigned 8 bits, packed */
    AUDIO_SAMPLE_FMT_S16,     /**< Signed 16 bits, packed */
    AUDIO_SAMPLE_FMT_S32,     /**< Signed 32 bits, packed */
    AUDIO_SAMPLE_FMT_FLOAT,   /**< Float, packed */
    AUDIO_SAMPLE_FMT_DOUBLE,  /**< Double, packed */
    AUDIO_SAMPLE_FMT_U8P,     /**< Unsigned 8 bits, planar */
    AUDIO_SAMPLE_FMT_S16P,    /**< Signed 16 bits, planar */
    AUDIO_SAMPLE_FMT_S32P,    /**< Signed 32 bits, planar */
    AUDIO_SAMPLE_FMT_FLOATP,  /**< Float, planar */
    AUDIO_SAMPLE_FMT_DOUBLEP, /**< Double, planar */
    AUDIO_SAMPLE_FMT_INVALID, /**< Invalid sampling format */
} AudioSampleFormat;

/**
 * @brief Defines the video codec port capability.
 */
#define PIX_FORMAT_NUM 16 /**< Indicates the array size of supported pixel formats */
typedef struct {
    Rect minSize;                            /**< Minimum resolution supported */
    Rect maxSize;                            /**< Maximum resolution supported */
    Alginment whAlignment;                   /**< Value to align with the width and height */
    RangeValue blockCount;
    RangeValue blocksPerSecond;
    Rect blockSize;
    int32_t supportPixFmts[PIX_FORMAT_NUM];    /**< Supported pixel formats, array is terminated by
                                                    <b> OMX_COLOR_FORMATTYPE</b> */
} VideoPortCap;

/**
 * @brief Defines the audio codec port capability.
 */
#define SAMPLE_FORMAT_NUM 12 /**< Indicates the array size of supported audio sample formats */
#define SAMPLE_RATE_NUM 16 /**< Indicates the array size of supported audio sample rate */
#define CHANNEL_NUM 16 /**< Indicates the array size of supported audio channel count */
typedef struct {
    int32_t sampleFormats[SAMPLE_FMT_NUM]; /**< Supported audio sample formats, array is terminated by
                                                <b> AUDIO_SAMPLE_FMT_INVALID</b> */
    int32_t sampleRate[SAMPLE_RATE_NUM];   /**< Supported audio sample rate, array is terminated by
                                                <b> AUD_SAMPLE_RATE_INVALID</b> */
    int32_t channelLayouts[CHANNEL_NUM];   /**< Supported count of audio channel layouts,
                                                array is terminated by <b> -1</b> */

    int32_t channelCount[CHANNEL_NUM];     /**< Supported audio channel count, array is terminated by <b> -1</b> */
} AudioPortCap;

typedef union {
    VideoPortCap video;               /**< Video codec port capability */
    AudioPortCap audio;               /**< Audio codec port capability */
} PortCap;

typedef enum {
    PROCESS_BLOCKING_INPUT_BUFFER       = 0X1,
    PROCESS_BLOCKING_OUTPUT_BUFFER      = 0X2,
    PROCESS_BLOCKING_CONTROL_FLOW       = 0X4,

    PROCESS_NONBLOCKING_INPUT_BUFFER    = 0X100,
    PROCESS_NONBLOCKING_OUTPUT_BUFFER   = 0X200,
    PROCESS_NONBLOCKING_CONTROL_FLOW    = 0X400,
} CodecProcessMode;

/**
 * @brief Defines the codec capability.
 */
#define NAME_LENGTH 32  /**< Indicates the array size of component name */
#define PROFILE_NUM 256  /**< Indicates the array size of supported profile */
typedef struct {
    AvCodecRole role;                     /**< Role type */
    CodecType type;                       /**< Codec type */
    char compName[NAME_LENGTH];           /**< Codec name char string */
    int32_t supportProfiles[PROFILE_NUM]; /**< Supported profiles, array is terminated by <b> INVALID_PROFILE</b> */
    int32_t maxInst;                      /**< max instances */
    bool isSoftwareCodec;                 /**< Software codec or hardware codec */
    int32_t processModeMask;              /**< Codec process mode mask. For details, see {@link CodecProcessMode}. */
    uint32_t capsMask;                    /**< Capability mask. For details, see {@link CodecCapsMask}. */
    RangeValue bitRate;                   /**< Range bit rate supported */
    PortCap port;
} CodecCompCapability;

enum BufferType {
    BUFFER_TYPE_INVALID = 0,
    BUFFER_TYPE_VIRTUAL_ADDR = 0x1,
    BUFFER_TYPE_AVSHARE_MEM_FD = 0x2,
    BUFFER_TYPE_HANDLE = 0x4,
    BUFFER_TYPE_DYNAMIC_HANDLE = 0x8,
};

enum ShareMemTypes {
    READ_WRITE_TYPE = 0x1,
    READ_ONLY_TYPE = 0x2,
};

struct OmxCodecBuffer {
    uint32_t bufferId;
	uint32_t size;                   /**< size of the structure in bytes */
    union OMX_VERSIONTYPE version;   /**< OMX specification version information */
    enum BufferType bufferType;
    uint8_t *buffer;            /**< Pointer to actual block of memory that is acting as the buffer */
    uint32_t bufferLen;         /**< size of buffer */
    uint32_t allocLen;          /**< size of the buffer allocated, in bytes */
    uint32_t filledLen;         /**< number of bytes currently in the buffer */
    uint32_t offset;            /**< start offset of valid data in bytes from the start of the buffer */
    int32_t fenceFd;
    enum ShareMemTypes type;
    int64_t pts;
    uint32_t flag;
};

enum OMX_INDEXCODECEXTYPE {
    OMX_IndexExtBufferTypeStartUnused = OMX_IndexKhronosExtensions + 0x00a00000,
    OMX_IndexParamSupportBufferType,
    OMX_IndexParamUseBufferType,
    OMX_IndexParamGetBufferHandleUsage,
};

struct SupportBufferType {
    uint32_t size;
    union OMX_VERSIONTYPE version;
    uint32_t portIndex;
    uint32_t bufferTypes;
};

struct UseBufferType {
    uint32_t size;
    union OMX_VERSIONTYPE version;
    uint32_t portIndex;
    uint32_t bufferType;
} ;

struct GetBufferHandleUsageParams {
    uint32_t size;
    union OMX_VERSIONTYPE version;
    uint32_t portIndex;
    uint32_t usage;
};

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* CODEC_COMPONENT_TYPE_H */
/** @} */