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
 * @file codec_component_type.h
 *
 * @brief Declares custom data types used in the Codec module APIs, including the codec types,
 * audio and video parameters, and buffers.
 *
 * @since 3.1
 */

#ifndef CODEC_COMPONENT_TYPE_H
#define CODEC_COMPONENT_TYPE_H

#include <stdint.h>
#include <stdbool.h>
#include "OMX_Types.h"
#include "OMX_Index.h"
#include "codec_common_type.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

/**
 * @brief Defines the maximum value of the sampling format.
 */
#define SAMPLE_FMT_NUM 32
#define UUID_LENGTH 128

/**
 * @brief Enumerates the types of audio and video encoding/decoding components.
 */
typedef enum {
    /** JPEG image */
    MEDIA_ROLETYPE_IMAGE_JPEG = 0,
    /** H.264 video */
    MEDIA_ROLETYPE_VIDEO_AVC,
    /** H.265 video */
    MEDIA_ROLETYPE_VIDEO_HEVC,
    /** MPEG4 video */
    MEDIA_ROLETYPE_VIDEO_MPEG4,
    /** VP9 video */
    MEDIA_ROLETYPE_VIDEO_VP9,
    /** Audio codec */
    MEDIA_ROLETYPE_AUDIO_FIRST = 0x10000,
    /** Advanced Audio Coding (AAC) */
    MEDIA_ROLETYPE_AUDIO_AAC = 0x10000,
    /** G711A audio */
    MEDIA_ROLETYPE_AUDIO_G711A,
    /** G711U audio */
    MEDIA_ROLETYPE_AUDIO_G711U,
    /** G726 audio */
    MEDIA_ROLETYPE_AUDIO_G726,
    /** Pulse-Code Modulation (PCM) audio */
    MEDIA_ROLETYPE_AUDIO_PCM,
    /** MP3 */
    MEDIA_ROLETYPE_AUDIO_MP3,
    /** Invalid type */
    MEDIA_ROLETYPE_INVALID,
} AvCodecRole;

/**
 * @brief Defines the video encoding and decoding capabilities.
 */
#define PIX_FORMAT_NUM 16 /** Size of the supported pixel format array */
#define BIT_RATE_MODE_NUM 5 /* Size of the array bit rate mode. */
#define MEASURED_FRAME_RATE_NUM 32 /* Size of the array measured frame rate. */

typedef enum {
    BIT_RATE_MODE_INVALID,
    /** Variable Bit Rate. */
    BIT_RATE_MODE_VBR,
    /* Constant Bit Rate. */
    BIT_RATE_MODE_CBR,
    /* Constant Quality. */
    BIT_RATE_MODE_CQ,
     /* Constrained VariableBit Rate. */
    BIT_RATE_MODE_VCBR,
    /* Average Bit Rate. */
    BIT_RATE_MODE_ABR,
} BitRateMode;

typedef struct {
    Rect minSize;                            /** Minimum resolution supported. */
    Rect maxSize;                            /** Maximum resolution supported. */
    Alignment whAlignment;                   /** Values to align with the width and height. */
    RangeValue blockCount;                   /** Number of blocks supported. */
    RangeValue blocksPerSecond;              /** Number of blocks processed per second. */
    Rect blockSize;                          /** Block size supported. */
    int32_t supportPixFmts[PIX_FORMAT_NUM];  /** Supported pixel format. For details,
                                                 see {@link OMX_COLOR_FORMATTYPE}. */
    BitRateMode bitRatemode[BIT_RATE_MODE_NUM]; /* Bit Rate Mode. For details, see {@link BitRateMode}. */
    RangeValue frameRate;                       /* Frame Rate. */
    int32_t measuredFrameRate[MEASURED_FRAME_RATE_NUM]; /* Measured Frame Rate.  */
} CodecVideoPortCap;

/**
 * @brief Defines the video encoding and decoding capabilities.
 */
#define SAMPLE_FORMAT_NUM 12 /** Size of the audio sampling format array supported. */
#define SAMPLE_RATE_NUM 16 /** Size of the audio sampling rate array supported. */
#define CHANNEL_NUM 16 /** Size of the audio channel array supported. */
typedef struct {
    int32_t sampleFormats[SAMPLE_FMT_NUM]; /** Supported audio sampling formats. For details,
                                               see {@link CodecAudioSampleFormat}. */
    int32_t sampleRate[SAMPLE_RATE_NUM];   /** Supported audio sampling rates. For details,
                                               see {@link AudioSampleRate}. */
    int32_t channelLayouts[CHANNEL_NUM];   /** Supported audio channel layouts. */
    int32_t channelCount[CHANNEL_NUM];     /** Supported audio channels. */
} CodecAudioPortCap;

/**
 * @brief Defines the audio and video encoding and decoding capabilities.
 */
typedef union {
    CodecVideoPortCap video;               /** Video encoding and decoding capabilities */
    CodecAudioPortCap audio;               /** Audio encoding and decoding capabilities */
} PortCap;

/**
 * @brief Defines the codec capabilities.
 */
#define NAME_LENGTH 32  /** Size of the component name. */
#define PROFILE_NUM 256  /** Size of the profile array supported. */
typedef struct {
    AvCodecRole role;                     /** Media type. */
    CodecType type;                       /** Codec type. */
    char compName[NAME_LENGTH];           /** Codec component name. */
    int32_t supportProfiles[PROFILE_NUM]; /** Supported profiles. For details, see {@link Profile}. */
    int32_t maxInst;                      /** Maximum instance. */
    bool isSoftwareCodec;                 /** Whether it is software codec or hardware codec. */
    int32_t processModeMask;              /** Codec processing mode mask. For details,
                                              see {@link CodecProcessMode}. */
    uint32_t capsMask;                    /** Codec playback capability mask. For details,
                                              see {@link CodecCapsMask}. */
    RangeValue bitRate;                   /** Supported bit rate range. */
    PortCap port;                         /** Supported audio and video encoding/decoding capabilities. */
    bool canSwapWidthHeight;              /** Whether width and height verification is supported. */
} CodecCompCapability;

/**
 * @brief Enumerate the shared memory types.
 */
enum ShareMemTypes {
    /** Readable and writable shared memory */
    READ_WRITE_TYPE = 0x1,
    /** Readable shared memory */
    READ_ONLY_TYPE = 0x2,
};

/**
 * @brief Defines the codec buffer information.
 */
struct OmxCodecBuffer {
    uint32_t bufferId;               /** Buffer ID. */
    uint32_t size;                   /** Size of the structure. */
    union OMX_VERSIONTYPE version;   /** Component version. */
    uint32_t bufferType;             /** Codec buffer type. For details,
                                         see {@link CodecBufferType}. */
    uint8_t *buffer;                 /** Buffer used for encoding or decoding. */
    uint32_t bufferLen;              /** Size of the buffer. */
    uint32_t allocLen;               /** Size of the buffer allocated. */
    uint32_t filledLen;              /** Size of the buffer filled. */
    uint32_t offset;                 /** Offset to the start position of the valid data in the buffer. */
    int32_t fenceFd;                 /** Fence file descriptor used to signal when the input or
                                         output buffer is ready to consume. */
    enum ShareMemTypes type;         /** Shared memory type. */
    int64_t pts;                     /** Timestamp. */
    uint32_t flag;                   /** Flag. */
};

/**
 * @brief Defines the <b>CompVerInfo</b>.
 */
struct CompVerInfo {
    char compName[NAME_LENGTH];         /** The name of the component */
    uint8_t compUUID[UUID_LENGTH];      /** The UUID of the component */
    union OMX_VERSIONTYPE compVersion;  /** The version of the component. For details, see {@link OMX_VERSIONTYPE}. */
    union OMX_VERSIONTYPE specVersion;  /** The spec version of the component. */
};

/**
 * @brief Defines the <b>EventInfo</b>.
 */
struct EventInfo {
    int64_t appData;                /** The pointer to the upper-layer instance passed to the callback */
    uint32_t data1;                 /** Data 1 carried in the event. */
    uint32_t data2;                 /** Data 2 carried in the event. */
    int8_t *eventData;              /** The pointer of data carried in the event. */
    uint32_t eventDataLen;          /** The length of <b>eventData</b>, in bytes. */
};

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* CODEC_COMPONENT_TYPE_H */
/** @} */