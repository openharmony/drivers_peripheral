/*
 * Copyright (c) 2020-2021 Huawei Device Co., Ltd.
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
 * @brief Defines codec-related APIs
 *
 * including custom data types and functions for initializing audio and video codecs,
 * setting parameters, and controlling and transferring data.
 *
 * @since 1.0
 * @version 1.0
 */

/**
 * @file codec_type.h
 *
 * @brief Declares custom data types used in API declarations for the Codec module,
 * including the codec types, audio and video parameters, input and output data, and callbacks.
 *
 * @since 1.0
 * @version 1.0
 */

#ifndef CODEC_TYPE_H
#define CODEC_TYPE_H

#ifdef MEDIA_INTERFACE_V1_0
#include "codec_lite_type.h"
#else
#include <stdint.h>
#include <stdbool.h>
#include "codec_common_type.h"
#include "display_type.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

/**
 * @brief Defines the pointer to the codec handle, which is the context information for function calls.
 */
typedef void *CODEC_HANDLETYPE;

/**
 * @brief Enumerates indexes of parameter types.
 */
typedef enum {
    KEY_CODEC_START_NONE = 0,
    KEY_MIMETYPE,             /**< MIME type. For the value type, see {@link AvCodecMime}. */
    KEY_BUFFERSIZE,           /**< Buffer size. The value type is uint32_t. */
    KEY_CODEC_TYPE,           /**< Codec type. For the value type, see {@link CodecType}. */
    KEY_INIT_PARAM_KEYS,      /**< Get the minimum initialization param keys, see {@link ParamKey}(read only). */
    KEY_INPUT_BUFFERS,        /**< External input buffer in preset mode, see {@link CodecBufferInfo}. */
    KEY_OUTPUT_BUFFERS,       /**< External output buffer in preset mode, see {@link CodecBufferInfo}. */
    KEY_DEVICE_ID,            /**< Device ID. The value type is uint32_t. */
    KEY_INPUT_BUFFER_COUNT,   /**< Input Buffer count. The value type is uint32_t. */
    KEY_OUTPUT_BUFFER_COUNT,  /**< Output Buffer count. The value type is uint32_t. */
    KEY_BITRATE = 0x500,      /**< Bit rate. The value type is uint32_t. */

    KEY_VIDEO_START_NONE = 0x1000,
    KEY_VIDEO_WIDTH,          /**< Width. The value type is uint32_t. */
    KEY_VIDEO_HEIGHT,         /**< Hight. The value type is uint32_t. */
    KEY_VIDEO_STRIDE,         /**< Stride. The value type is uint32_t. */
    KEY_VIDEO_FIELD,          /**< Video field. For the value type, see {@link VideoField}. */
    KEY_PIXEL_FORMAT,         /**< Pixel format. For the value type, see {@link CodecPixelFormat}. */
    KEY_VIDEO_RC_MODE,        /**< Rate control mode. For the value type, see {@link VideoCodecRcMode}. */
    KEY_VIDEO_GOP_MODE,       /**< GOP mode. For the value type, see {@link VideoCodecGopMode}. */
    KEY_VIDEO_PIC_SIZE,       /**< Image resolution. */
    KEY_VIDEO_PROFILE,        /**< Codec profile. The value type is uint32_t. */
    KEY_VIDEO_FRAME_RATE,     /**< Frame rate. The value type is uint32_t. */
    KEY_IMAGE_Q_FACTOR,       /**< Quality factor, range is [1, 99]. The value type is uint32_t */
    KEY_VIDEO_LEVEL,          /**< Codec level. The value type is uint32_t. */

    KEY_SAMPLE_RATE = 0x1500,
    KEY_AUDIO_PROFILE,        /**< Audio encoding profile. The value type is uint32_t. */
    KEY_CHANNEL_COUNT,        /**< Number of channels. The value type is uint32_t. */
    KEY_BITWITH,              /**< Bit width. For the value type, see {@link AudioBitWidth}. */
    KEY_SOUND_MODE,           /**< Audio channel mode. For the value type, see {@link AudioSoundMode}. */
    KEY_POINT_NUM_PER_FRAME,  /**< Number of sampling points per frame. The value type is uint32_t. */
    KEY_DEBREATHE_EFFECT,     /**< DeBreathe Effect. The value type is uint32_t. */
    KEY_VIDEO_DST_FRAME_RATE,
    KEY_REF_FRAME_NUM,        /**< DeBreathe Effect. The value type is uint32_t. */
    KEY_ADEC_CACHE_FRAME_NUM, /**< DeBreathe Effect. The value type is uint32_t. */
    KEY_AUDIO_SAMPLE_RATE,    /**< Sampling rate. The value type is uint32_t. */
    KEY_AUDIO_CHANNEL_COUNT,  /**< Number of channels. The value type is uint32_t. */
    KEY_AUDIO_SOUND_MODE,     /**< Audio channel mode. For the value type, see {@link AudioSoundMode}. */
    KEY_AUDIO_POINTS_PER_FRAME,  /**< Number of sampling points per frame. The value type is uint32_t. */
    KEY_AUDIO_SAMPLE_FORMAT,  /**< Audio sample format. For the value type, see {@link CodecAudioSampleFormat}. */

    KEY_VENDOR_START_NONE = 0x60000000,

    KEY_PARAM_MAX = 0x7FFFFFFF
} ParamKey;

/**
 * @brief Enumerates control modes of the channel encoding rate.
 */
typedef enum {
    VENCOD_RC_CBR = 0, /**< Fixed bit rate*/
    VENCOD_RC_VBR,     /**< Variable bit rate */
    VENCOD_RC_AVBR,    /**< Adaptive variable bit rate */
    VENCOD_RC_QVBR,    /**< Quality-defined variable bit rate */
    VENCOD_RC_CVBR,    /**< Constrained variable bit rate */
    VENCOD_RC_QPMAP,   /**< Configuration-mapped quantization parameters */
    VENCOD_RC_FIXQP    /**< Fixed quantization parameters */
} VenCodeRcMode;

typedef enum {
    VID_CODEC_RC_CBR = 0, /**< Fixed bit rate*/
    VID_CODEC_RC_VBR,     /**< Variable bit rate */
    VID_CODEC_RC_AVBR,    /**< Adaptive variable bit rate */
    VID_CODEC_RC_QVBR,    /**< Quality-defined variable bit rate */
    VID_CODEC_RC_CVBR,    /**< Constrained variable bit rate */
    VID_CODEC_RC_QPMAP,   /**< Configuration-mapped quantization parameters */
    VID_CODEC_RC_FIXQP    /**< Fixed quantization parameters */
} VideoCodecRcMode;

/**
 * @brief Enumerates resolutions.
 */
typedef enum {
    RESOLUTION_CIF,     /**< 352x288 */
    RESOLUTION_360P,    /**< 640x360 */
    RESOLUTION_D1_PAL,  /**< 720x576 */
    RESOLUTION_D1_NTSC, /**< 720x480 */
    RESOLUTION_720P,    /**< 1280x720 */
    RESOLUTION_1080P,   /**< 1920x1080 */
    RESOLUTION_2560X1440, /**< 2560x1440 */
    RESOLUTION_2592X1520, /**< 2592x1520 */
    RESOLUTION_2592X1536, /**< 2592x1536 */
    RESOLUTION_2592X1944, /**< 2592x1944 */
    RESOLUTION_2688X1536, /**< 2688x1536 */
    RESOLUTION_2716X1524, /**< 2716x1524 */
    RESOLUTION_3840X2160, /**< 3840x2160 */
    RESOLUTION_4096X2160, /**< 4096x2160 */
    RESOLUTION_3000X3000, /**< 3000x3000 */
    RESOLUTION_4000X3000, /**< 4000x3000 */
    RESOLUTION_7680X4320, /**< 7680x4320 */
    RESOLUTION_3840X8640, /**< 3840x8640 */
    RESOLUTION_INVALID  /**< Invalid resolution */
} PicSize;

/**
 * @brief Enumerates types of group of pictures (GOP).
 */
typedef enum {
    VENCOD_GOPMODE_NORMALP = 0,   /**< P-frames using only one reference frame during encoding */
    VENCOD_GOPMODE_DUALP = 1,     /**< P-frames using two reference frames during encoding */
    VENCOD_GOPMODE_SMARTP = 2,    /**< Smart P-frames for encoding */
    VENCOD_GOPMODE_ADVSMARTP = 3, /**< Advanced smart P-frames for encoding */
    VENCOD_GOPMODE_BIPREDB = 4,   /**< B-frames for encoding */
    VENCOD_GOPMODE_LOWDELAYB = 5, /**< B-frames using only previous frames as references during encoding. */
    VENCOD_GOPMODE_INVALID,       /**< Invalid type */
} VenCodeGopMode;

/**
 * @brief Enumerates types of group of pictures (GOP).
 */
typedef enum {
    VID_CODEC_GOPMODE_NORMALP = 0,   /**< P-frames using only one reference frame during encoding */
    VID_CODEC_GOPMODE_DUALP = 1,     /**< P-frames using two reference frames during encoding */
    VID_CODEC_GOPMODE_SMARTP = 2,    /**< Smart P-frames for encoding */
    VID_CODEC_GOPMODE_ADVSMARTP = 3, /**< Advanced smart P-frames for encoding */
    VID_CODEC_GOPMODE_BIPREDB = 4,   /**< B-frames for encoding */
    VID_CODEC_GOPMODE_LOWDELAYB = 5, /**< B-frames using only previous frames as references during encoding. */
    VID_CODEC_GOPMODE_INVALID,       /**< Invalid type */
} VideoCodecGopMode;

/**
 * @brief Defines the pointer to the type of the dynamic parameter value.
 */
typedef void *ValueType;

/**
 * @brief Describes the dynamic parameter structure, which is mainly used
 * by {@link CodecCreate} and {@link CodecSetParameter}.
 */
typedef struct {
    ParamKey  key;    /**< Parameter type index */
    void      *val; /**< Pointer to the parameter value */
    int       size; /**< Parameter value size */
} Param;

/**
 * @brief Enumerates video frame fields.
 */
typedef enum {
    VID_FIELD_TOP         = 0x1,    /**< Top fields on even-number lines */
    VID_FIELD_BOTTOM      = 0x2,    /**< Bottom fields on odd-number lines */
    VID_FIELD_INTERLACED  = 0x3,    /**< Interlaced fields */
    VID_FIELD_FRAME       = 0x4,    /**< Non-interlaced frames */
    VID_FIELD_INVALID               /**< Invalid fields */
} VideoField;

/**
 * @brief Enumerates pixel formats.
 */
typedef enum {
    PIXEL_FORMAT_NONE,
    PIXEL_FORMAT_YUV_422_I,                /**< YUV422 interleaved format */
    PIXEL_FORMAT_YCBCR_422_SP,             /**< YCBCR422 semi-planar format */
    PIXEL_FORMAT_YCRCB_422_SP,             /**< YCRCB422 semi-planar format */
    PIXEL_FORMAT_YCBCR_420_SP,             /**< YCBCR420 semi-planar format */
    PIXEL_FORMAT_YCRCB_420_SP,             /**< YCRCB420 semi-planar format */
    PIXEL_FORMAT_YCBCR_422_P,              /**< YCBCR422 planar format */
    PIXEL_FORMAT_YCRCB_422_P,              /**< YCRCB422 planar format */
    PIXEL_FORMAT_YCBCR_420_P,              /**< YCBCR420 planar format */
    PIXEL_FORMAT_YCRCB_420_P,              /**< YCRCB420 planar format */
    PIXEL_FORMAT_YUYV_422_PKG,             /**< YUYV422 packed format */
    PIXEL_FORMAT_UYVY_422_PKG,             /**< UYVY422 packed format */
    PIXEL_FORMAT_YVYU_422_PKG,             /**< YVYU422 packed format */
    PIXEL_FORMAT_VYUY_422_PKG,             /**< VYUY422 packed format */

    PIXEL_FORMAT_VENDOR_MASK = 0x7F000000, /**< Reserved region for introducting Vendor Extensions, eg.
                                              PIX_FORMAT_VENDOR_MASK | PIXEL_FORMAT_YCBCR_420_SP. */
    PIXEL_FORMAT_MAX = 0x7FFFFFFF,         /**< Invalid format */
} CodecPixelFormat;

/**
 * @brief Enumerates audio channel modes.
 */
typedef enum {
    AUD_CHANNEL_FRONT_LEFT  = 0x1, /**< Front left channel */
    AUD_CHANNEL_FRONT_RIGHT = 0x2, /**< Front right channel */

    AUD_SOUND_MODE_INVALID  = 0x0, /**< Invalid mode */
    AUD_SOUND_MODE_MONO     = 0x1, /**< Mono channel */
    AUD_SOUND_MODE_STEREO   = 0x3, /**< Stereo channel, consisting of front left and front right channels */
} AudioSoundMode;

/**
* @brief Enumerates stream flags.
 */
typedef enum {
    STREAM_FLAG_KEYFRAME           = 0x1, /**< Keyframe */
    STREAM_FLAG_CODEC_SPECIFIC_INF = 0x2, /**< Codec specifications */
    STREAM_FLAG_EOS                = 0x4, /**< End of streams */
    STREAM_FLAG_PART_OF_FRAME      = 0x8, /**< Partial frame */
    STREAM_FLAG_END_OF_FRAME       = 0x10, /**< End of frames, used in pair with <b> STREAM_FLAG_PART_OF_FRAME</b> */
    STREAM_FLAG_OUTPUT_CHANGED     = 0x20,
} StreamFlagType;

/**
 * @brief Defines the codec buffer handle type. The virtual address of a handle maps to its physical address.
 */
typedef struct {
    uint8_t *virAddr;   /**< Virtual address */
    uintptr_t handle;   /**< Physical address */
} CodecBufferHandle;

/**
* @brief Enumerates buffer types.
 */
typedef enum {
    BUFFER_TYPE_VIRTUAL = 0, /**< Data described by this buffer */
    BUFFER_TYPE_FD,          /**< Share mem file descriptor, which can be used cross processes */
    BUFFER_TYPE_HANDLE,      /**< Video frame buffer handle, For details, see {@link BufferHandle} */
} BufferType;

/**
 * @brief Describes buffer information.
 */
typedef struct {
    BufferType type;          /**< Buffer type */
    /**
     * @brief Describes the buffer address.
     */
    union {
        uint8_t       *addr;  /**< Virtual address */
        int32_t       fd;     /**< File descriptor */
        CodecBufferHandle  handle; /**< Data handle. For details, see {@link CodecBufferHandle} */
    };
    uint32_t offset;          /**< Buffer offset */
    uint32_t length;          /**< Length of valid data */
    uint32_t size;            /**< Total size of buffer blocks*/
} CodecBufferInfo;

/**
 * @brief Describes input information.
 */
typedef struct {
    uint32_t bufferId;    /**< Corresponding buffer index number */
    int64_t timeStamp;    /**< buffer timestamp */
    uint32_t flag;        /**< buffer flag. For details, see {@link StreamFlagType}. */
    uint32_t bufferCnt;   /**< Number of buffers */
    CodecBufferInfo buffers[0]; /**< Pointer to the buffer description. For details, see {@link CodecBufferInfo} */
} InputInfo;

/**
 * @brief Describes output information.
 */
typedef struct {
    uint32_t bufferId;    /**< Corresponding buffer index number */
    int64_t timeStamp;    /**< buffer timestamp */
    uint32_t flag;        /**< buffer flag. For details, see {@link StreamFlagType}. */
    uint32_t bufferCnt;   /**< Number of buffers */
    CodecBufferInfo buffers[0]; /**< Pointer to the buffer description. For details, see {@link CodecBufferInfo} */
} OutputInfo;

/**
 * @brief Describes buffer information.
 */
typedef struct {
    BufferType type;   /**< Buffer type */
    intptr_t buf;      /**< A reference to a data buffer */
    uint32_t offset;   /**< Buffer offset */
    uint32_t length;   /**< Length of valid data */
    uint32_t capacity; /**< Total size of buffer blocks*/
} CodecBuffersInfo;

/**
 * @brief Describes input and output codec buffer.
 */
typedef struct {
    uint32_t bufferId;    /**< Corresponding buffer index number */
    int64_t timeStamp;    /**< buffer timestamp */
    uint32_t flag;        /**< buffer flag. For details, see {@link StreamFlagType}. */
    uint32_t bufferCnt;   /**< Number of buffers */
    CodecBuffersInfo buffer[0]; /**< Pointer to the buffer description. For details, see {@link CodecBufferInfo} */
} CodecBuffer;

/**
 * @brief Enumerates MIME types.
 */
typedef enum {
    MEDIA_MIMETYPE_IMAGE_JPEG = 0,        /**< JPEG image */
    MEDIA_MIMETYPE_VIDEO_AVC,             /**< H.264 video */
    MEDIA_MIMETYPE_VIDEO_HEVC,            /**< H.265 video */
    MEDIA_MIMETYPE_VIDEO_MPEG4,           /**< MPEG4 video */
    MEDIA_MIMETYPE_AUDIO_FIRST = 0x10000, /**< Dummy id pointing at the start of audio codecs */
    MEDIA_MIMETYPE_AUDIO_AAC = 0x10000,   /**< AAC audio */
    MEDIA_MIMETYPE_AUDIO_G711A,           /**< G711A audio */
    MEDIA_MIMETYPE_AUDIO_G711U,           /**< G711U audio */
    MEDIA_MIMETYPE_AUDIO_G726,            /**< G726 audio */
    MEDIA_MIMETYPE_AUDIO_PCM,             /**< PCM audio */
    MEDIA_MIMETYPE_AUDIO_MP3,             /**< MP3 audio */
    MEDIA_MIMETYPE_INVALID,               /**< Invalid MIME type */
} AvCodecMime;

/**
 * @brief Enumerates codec levels.
 */
typedef enum {
    INVALID_LEVEL = 0,                 /**< Invalid level */
    AVC_LEVEL_1 = 0x1000,              /**< H.264 level 1 */
    HEVC_LEVEL_MAIN_1 = 0x2000,        /**< H.265 Main level 1 */
    HEVC_LEVEL_MAIN_2,                 /**< H.265 Main level 2 */
} Level;

/**
 * @brief Enumerates allocation modes of input and output buffers.
 */
typedef enum {
    ALLOCATE_INPUT_BUFFER_CODEC_PRESET   = 0x0001, /**< Preset input buffer allocated within the Codec module */
    ALLOCATE_INPUT_BUFFER_CODEC_DYNAMIC  = 0x0002, /**< Dynamic input buffer allocated within the Codec module */

    ALLOCATE_INPUT_BUFFER_USER_PRESET    = 0x0010, /**< Preset input buffer allocated by an external user */
    ALLOCATE_INPUT_BUFFER_USER_DYNAMIC   = 0x0020, /**< Dynamic input buffer allocated by an external user */

    ALLOCATE_OUTPUT_BUFFER_CODEC_PRESET  = 0x0100, /**< Preset output buffer allocated within the Codec module */
    ALLOCATE_OUTPUT_BUFFER_CODEC_DYNAMIC = 0x0200, /**< Dynamic output buffer allocated within the Codec module */

    ALLOCATE_OUTPUT_BUFFER_USER_PRESET   = 0x1000, /**< Preset output buffer allocated by an external user */
    ALLOCATE_OUTPUT_BUFFER_USER_DYNAMIC  = 0x2000, /**< Dynamic output buffer allocated by an external user */
} AllocateBufferMode;

/**
 * @brief Enumerates playback capabilities.
 */
typedef enum {
    ADAPTIVE_PLAYBACK  = 0x1, /**< Adaptive playback */
    SECURE_PLAYBACK   = 0x2,  /**< Secure playback */
} CapsMask;

/**
 * @brief Defines the video codec capabilities.
 */
#define PIX_FMT_NUM 16 /** Size of the supported pixel format array */
typedef struct {
    Rect minSize;                            /** Minimum resolution supported. */
    Rect maxSize;                            /** Maximum resolution supported. */
    Alignment whAlignment;                   /** Values to align with the width and height. */
    int32_t supportPixFmts[PIX_FMT_NUM];  /** Supported pixel formats, array is terminated by PIXEL_FORMAT_NONE. */
} VideoPortCap;

/**
 * @brief Defines the audio codec port capabilities.
 */
#define SAMPLE_FORMAT_NUM 12 /** Size of the audio sampling format array supported. */
#define SAMPLE_RATE_NUM 16   /** Size of the audio sampling rate array supported. */
#define CHANNEL_NUM 16       /** Size of the audio channel array supported. */
typedef struct {
    int32_t sampleFormats[SAMPLE_FORMAT_NUM]; /** Supported audio sampling formats. For details,
                                                  see {@link CodecAudioSampleFormat}. */
    int32_t sampleRate[SAMPLE_RATE_NUM];      /** Supported audio sampling rates. For details,
                                                  see {@link AudioSampleRate}. */
    int32_t channelLayouts[CHANNEL_NUM];      /** Supported audio channel layouts. */
} AudioPortCap;

#define PROFILE_NUM 256 /** Size of the profile array supported. */
#define NAME_LENGTH 32  /** Size of the component name. */

/**
 * @brief Defines the codec capability.
 */
typedef struct {
    AvCodecMime mime;                     /**< MIME type */
    CodecType type;                       /**< Codec type */
    char name[NAME_LENGTH];               /**< Codec name char string */
    int32_t supportProfiles[PROFILE_NUM]; /**< Supported profiles. For details, see {@link Profile}. */
    bool isSoftwareCodec;                 /**< Whether it is software codec or hardware codec. */
    int32_t processModeMask;              /**< Codec processing mode mask. For details,
                                              see {@link CodecProcessMode}. */
    uint32_t capsMask;                    /**< Capability mask. For details, see {@link CapsMask}. */
    uint32_t allocateMask;                /**< Buffer allocation mode. For details, see {@link AllocateBufferMode}. */
    RangeValue inputBufferNum;            /**< Range number of input buffers required for running */
    RangeValue outputBufferNum;           /**< Range number of output buffers required for running */
    RangeValue bitRate;                   /** Supported bit rate range. */
    int32_t inputBufferSize;              /** Min size of external input buffer. */
    int32_t outputBufferSize;             /** Min size of external output buffer. */
    union {
        VideoPortCap video;               /** Video encoding and decoding capabilities */
        AudioPortCap audio;               /** Audio encoding and decoding capabilities */
    } port;
} CodecCapability;

/**
 * @brief Enumerates input and output types.
 */
typedef enum {
    INPUT_TYPE,  /**< Input */
    OUTPUT_TYPE, /**< Output */
    ALL_TYPE,    /**< Input and output */
} DirectionType;

/**
 * @brief Enumerates event types.
 */
typedef enum {
    EVENT_ERROR,              /**< Event error */
    EVENT_FLUSH_COMPLETE,     /**< Buffer flush completed */
    EVENT_STOP_COMPLETE,      /**< Codec stopped */
    EVENT_OUT_FORMAT_CHANGED, /**< Output format changed. For details, see {@link FormatChange}. */
    EVENT_START_COMPLETE,     /**< Codec started */
    EVENT_EOS_COMPLETE,

    EVENT_MAX = 0x7FFFFFFF     /**< Maximum event value */
} EventType;

/**
 * @brief Redefines the unsigned pointer type, which is used for pointer conversion.
 */
typedef uintptr_t UINTPTR;

/**
 * @brief Defines format change reporting information.
 */
typedef struct {
    DirectionType direct;  /**< Input or output type. */
    RangeValue bufferNum;  /**< Range number of output buffers. Report when decode the first frame,
                                or report when the bit stream resolution changed. */
    int32_t width;         /**< Width. */
    int32_t height;        /**< Height. */
    int32_t widthStride;   /**< Image width stride. */
    int32_t heightStride;  /**< Image height stride. */
    PixelFormat format;    /**< Pixel format. For details, see {@link PixelFormat}. */
    Rect outputRect;
} FormatChange;

/**
 * @brief Defines callbacks and their parameters.
 */
typedef struct {
    /**
     * @brief Reports an event.
     *
     * Reports event errors and output format changes.
     *
     * @param userData Indicates upper-layer data, which is generally
     * an upper-layer instance passed when this callback is set.
     * @param EVENTTYPE Indicates the event type.
     * @param length Indicates the length of eventData array.
     * @param eventData Indicates the pointer to data contained in the reported event.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero {@link CodecResult} value otherwise.
     */
    int32_t (*OnEvent)(UINTPTR userData, EventType event, uint32_t length, int32_t eventData[]);

    /**
     * @brief Reports that the input data has been used.
     *
     * This callback is invoked in asynchronous mode.
     *
     * @param userData Indicates upper-layer data, which is generally
     * an upper-layer instance passed when this callback is set.
     * @param inBuf Indicates the pointer to the input data that has been used.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero {@link CodecResult} value otherwise.
     */
    int32_t (*InputBufferAvailable)(UINTPTR userData, CodecBuffer *inBuf, int32_t *acquireFd);

    /**
     * @brief Reports that the output is complete.
     *
     * This callback is invoked in asynchronous mode.
     *
     * @param userData Indicates upper-layer data, which is generally
     * an upper-layer instance passed when this callback is registered.
     * @param pBuffer Indicates the pointer to the output data that has been generated.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero {@link CodecResult} value otherwise.
     */
    int32_t (*OutputBufferAvailable)(UINTPTR userData, CodecBuffer *outBuf, int32_t *acquireFd);
} CodecCallback;

/**
 * @brief Enumerates allocation types.
 */
typedef enum {
    INTERNAL, /**< Internal */
    EXTERNAL, /**< External */
} BufferMode;

/**
 * @brief Enumerates codec result types.
 */
typedef enum {
    CODEC_SUCCESS = 0,                               /**< Success */
    CODEC_RECEIVE_EOS,                               /**< End of streams */
    CODEC_ERR_UNKOWN = (int32_t)0x80001000,          /**< Unknown error */
    CODEC_ERR_INVALID_NAME = (int32_t)0x80001001,    /**< The codec name was not valid */
    CODEC_ERR_INVALID_MIME = (int32_t)0x80001002,    /**< The codec mime was not valid */
    CODEC_ERR_INVALID_PARAM = (int32_t)0x80001003,   /**< One or more parameters were not valid */
    CODEC_ERR_INVALID_CODEC = (int32_t)0x80001004,   /**< The codec handle was not valid */
    CODEC_ERR_INVALID_OP = (int32_t)0x80001005,      /**< Invalid operation */
    CODEC_ERR_UNSUPPORT_PARAM = (int32_t)0x80001006, /**< One or more parameters were not supported */
    CODEC_ERR_NOT_INIT = (int32_t)0x80001007,        /**< The codec was not initialized */
    CODEC_ERR_NOT_READY = (int32_t)0x80001008,       /**< The codec was not ready */
    CODEC_ERR_NOT_FOUND = (int32_t)0x80001009,       /**< The codec was not found */
    CODEC_ERR_NO_MEMORY = (int32_t)0x8000100A,       /**< The codec memory allocation failed */
    CODEC_ERR_TIMEOUT = (int32_t)0x8000100B,         /**< There was a timeout that occurred */
    CODEC_ERR_INVALID_BUFFER = (int32_t)0x8000100C,  /**< The buffer was not valid */
    CODEC_ERR_UNDER_FLOW = (int32_t)0x8000100D,      /**< The buffer was emptied before the next buffer was ready */
    CODEC_ERR_OVER_FLOW = (int32_t)0x8000100E,       /**< The buffer was not available when it was needed */
    CODEC_ERR_MAX = 0x7FFFFFFF
} CodecResult;

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* !MEDIA_INTERFACE_V1_0 */

#endif /* CODEC_TYPE_H */
/** @} */
