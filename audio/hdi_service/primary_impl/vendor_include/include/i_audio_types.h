/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
 * @file i_audio_types.h
 *
 * @brief Defines custom data types used in API declarations for the audio module, including audio ports,
 * adapter descriptors, device descriptors, scene descriptors, sampling attributes, and timestamp.
 *
 * @since 1.0
 * @version 1.0
 */

#ifndef I_AUDIO_TYPES_H
#define I_AUDIO_TYPES_H

#include <stdint.h>
#include <stdbool.h>

#define AUDIO_HW_ADAPTER_NUM_MAX        8 // Limit the number of sound cards supported to a maximum of 8
#define AUDIO_HW_PORT_NUM_MAX    10
#define AUDIO_HW_STREAM_NUM_MAX  10
/**
 * @brief Defines the audio handle.
 */
typedef void *AudioHandle;

/**
 * @brief Enumerates the audio port type.
 */
enum AudioHwiPortDirection {
    HW_PORT_OUT    = 0x1u, /**< Output port */
    HW_PORT_IN     = 0x2u, /**< Input port */
    HW_PORT_OUT_IN = 0x3u, /**< Input/output port, supporting both audio input and output */
};

/**
 * @brief Defines the audio port.
 */
struct AudioHwiPort {
    enum AudioHwiPortDirection dir; /**< Audio port type. For details, see {@link AudioHwiPortDirection} */
    uint32_t portId;             /**< Audio port ID */
    const char *portName;        /**< Audio port name */
};

/**
 * @brief Defines the audio adapter descriptor.
 *
 * An audio adapter is a set of port drivers for a sound card, including the output and input ports.
 * One port corresponds to multiple pins, and each pin belongs to a physical component (such as a
 * speaker or a wired headset).
 */
struct AudioAdapterHwiDescriptor {
    const char *adapterName; /**< Name of the audio adapter */
    uint32_t portNum;        /**< Number of ports supported by an audio adapter */
    struct AudioHwiPort *ports; /**< List of ports supported by an audio adapter */
};

/**
 * @brief Enumerates the pin of an audio adapter.
 */
enum AudioHwiPortPin {
    HW_PIN_NONE                     = 0x0u,       /**< Invalid pin */
    HW_PIN_OUT_SPEAKER              = 0x1u,       /**< Speaker output pin */
    HW_PIN_OUT_HEADSET              = 0x2u,       /**< Wired headset pin for output */
    HW_PIN_OUT_LINEOUT              = 0x4u,       /**< Line-out pin */
    HW_PIN_OUT_HDMI                 = 0x8u,       /**< HDMI output pin */
    HW_PIN_OUT_USB                  = 0x10u,      /**< USB output pin */
    HW_PIN_OUT_USB_EXT              = 0x20u,      /**< Extended USB output pin*/
    HW_PIN_OUT_EARPIECE             = 0x30u,      /**< Earpiece output pin */
    HW_PIN_OUT_BLUETOOTH_SCO        = 0x40u,      /**< Bluetooth SCO output pin */
    HW_PIN_OUT_DAUDIO_DEFAULT       = 0x80u,
    HW_PIN_OUT_HEADPHONE            = 0x100u,     /**< Wired headphone output pin*/
    HW_PIN_OUT_BLUETOOTH_A2DP       = 0x200u,     /**< ABluetooth a2dp output pin */
    HW_PIN_IN_MIC                   = 0x8000001u, /**< Microphone input pin */
    HW_PIN_IN_HS_MIC                = 0x8000002u, /**< Wired headset microphone pin for input */
    HW_PIN_IN_LINEIN                = 0x8000004u, /**< Line-in pin */
    HW_PIN_IN_USB_EXT               = 0x8000008u, /**< Extended USB input pin*/
    HW_PIN_IN_BLUETOOTH_SCO_HEADSET = 0x8000010u, /**< Bluetooth SCO headset input pin */
};

/**
 * @brief Defines the audio device descriptor.
 */
struct AudioHwiDeviceDescriptor {
    uint32_t portId;        /**< Audio port ID */
    enum AudioHwiPortPin pins; /**< Pins of audio ports (input and output). For details, see {@link AudioHwiPortPin}. */
    const char *desc;       /**< Audio device name */
};

/**
 * @brief Enumerates the audio category.
 */
enum AudioHwiCategory {
    HW_AUDIO_IN_MEDIA = 0,     /**< Media */
    HW_AUDIO_IN_COMMUNICATION, /**< Communications */
    HW_AUDIO_IN_RINGTONE,      /**< Ringtone */
    HW_AUDIO_IN_CALL,          /**< Call */
    HW_AUDIO_MMAP_NOIRQ,       /**< Mmap mode */
};

/**
 * @brief Defines the audio scene descriptor.
 */
struct AudioHwiSceneDescriptor {
    /**
     * @brief Describes the audio scene.
     */
    union SceneDescHwi {
        uint32_t id;                   /**< Audio scene ID */
        const char *desc;              /**< Name of the audio scene */
    } scene;                           /**< The <b>scene</b> object */
    struct AudioHwiDeviceDescriptor desc; /**< Audio device descriptor */
};

/**
 * @brief Enumerates the audio format.
 */
enum AudioHwiFormat {
    AUDIO_HW_FORMAT_TYPE_PCM_8_BIT  = 0x1u,       /**< 8-bit PCM */
    AUDIO_HW_FORMAT_TYPE_PCM_16_BIT = 0x2u,       /**< 16-bit PCM */
    AUDIO_HW_FORMAT_TYPE_PCM_24_BIT = 0x3u,       /**< 24-bit PCM */
    AUDIO_HW_FORMAT_TYPE_PCM_32_BIT = 0x4u,       /**< 32-bit PCM */
    AUDIO_HW_FORMAT_TYPE_AAC_MAIN   = 0x1000001u, /**< AAC main */
    AUDIO_HW_FORMAT_TYPE_AAC_LC     = 0x1000002u, /**< AAC LC */
    AUDIO_HW_FORMAT_TYPE_AAC_LD     = 0x1000003u, /**< AAC LD */
    AUDIO_HW_FORMAT_TYPE_AAC_ELD    = 0x1000004u, /**< AAC ELD */
    AUDIO_HW_FORMAT_TYPE_AAC_HE_V1  = 0x1000005u, /**< AAC HE_V1 */
    AUDIO_HW_FORMAT_TYPE_AAC_HE_V2  = 0x1000006u, /**< AAC HE_V2 */
    AUDIO_HW_FORMAT_TYPE_G711A      = 0x2000001u, /**< G711A */
    AUDIO_HW_FORMAT_TYPE_G711U      = 0x2000002u, /**< G711u */
    AUDIO_HW_FORMAT_TYPE_G726       = 0x2000003u, /**< G726 */
};

/**
 * @brief Enumerates the audio channel mask.
 *
 * A mask describes an audio channel position.
 */
enum AudioHwiChannelMask {
    AUDIO_HW_CHANNEL_MONO           = 1u,      /**< Mono channel */
    AUDIO_HW_CHANNEL_FRONT_LEFT     = 1u,      /**< Front left channel */
    AUDIO_HW_CHANNEL_FRONT_RIGHT    = 2u,      /**< Front right channel */
    AUDIO_HW_CHANNEL_FRONT_CENTER   = 4u,      /**< Front right channel */
    AUDIO_HW_CHANNEL_LOW_FREQUENCY  = 8u,      /**< 0x8 */
    AUDIO_HW_CHANNEL_BACK_LEFT      = 16u,     /**< 0x10 */
    AUDIO_HW_CHANNEL_BACK_RIGHT     = 32u,     /**< 0x20 */
    AUDIO_HW_CHANNEL_BACK_CENTER    = 256u,    /**< 0x100 */
    AUDIO_HW_CHANNEL_SIDE_LEFT      = 512u,    /**< 0x200 */
    AUDIO_HW_CHANNEL_SIDE_RIGHT     = 1024u,   /**< 0x400 */
    AUDIO_HW_CHANNEL_TOP_SIDE_LEFT  = 262144u, /**< 0x40000 */
    AUDIO_HW_CHANNEL_TOP_SIDE_RIGHT = 524288u, /**< 0x80000 */
    AUDIO_HW_CHANNEL_STEREO         = 3u,      /**< FRONT_LEFT | FRONT_RIGHT */
    AUDIO_HW_CHANNEL_2POINT1        = 11u,     /**< STEREO | LOW_FREQUENCY */
    AUDIO_HW_CHANNEL_QUAD           = 51u,     /**< STEREO | BACK_LEFT | BACK_RIGHT */
    AUDIO_HW_CHANNEL_3POINT0POINT2  = 786439u, /**< STEREO | FRONT_CENTER | TOP_SIDE_LEFT | TOP_SIDE_RIGHT */
    AUDIO_HW_CHANNEL_5POINT1        = 63u,     /**< QUAD | FRONT_CENTER | LOW_FREQUENCY */
    AUDIO_HW_CHANNEL_6POINT1        = 319u,    /**< AUDIO_CHANNEL_5POINT1 | BACK_CENTER */
    AUDIO_HW_CHANNEL_7POINT1        = 1599u,   /**< AUDIO_CHANNEL_5POINT1 | SIDE_LEFT | SIDE_RIGHT */
};

/**
 * @brief Enumerates masks of audio sampling rates.
 */
enum AudioHwiSampleRatesMask {
    AUDIO_HW_SAMPLE_RATE_MASK_8000    = 0x1u,        /**< 8 kHz */
    AUDIO_HW_SAMPLE_RATE_MASK_12000   = 0x2u,        /**< 12 kHz */
    AUDIO_HW_SAMPLE_RATE_MASK_11025   = 0x4u,        /**< 11.025 kHz */
    AUDIO_HW_SAMPLE_RATE_MASK_16000   = 0x8u,        /**< 16 kHz */
    AUDIO_HW_SAMPLE_RATE_MASK_22050   = 0x10u,       /**< 22.050 kHz */
    AUDIO_HW_SAMPLE_RATE_MASK_24000   = 0x20u,       /**< 24 kHz */
    AUDIO_HW_SAMPLE_RATE_MASK_32000   = 0x40u,       /**< 32 kHz */
    AUDIO_HW_SAMPLE_RATE_MASK_44100   = 0x80u,       /**< 44.1 kHz */
    AUDIO_HW_SAMPLE_RATE_MASK_48000   = 0x100u,      /**< 48 kHz */
    AUDIO_HW_SAMPLE_RATE_MASK_64000   = 0x200u,      /**< 64 kHz */
    AUDIO_HW_SAMPLE_RATE_MASK_96000   = 0x400u,      /**< 96 kHz */
    AUDIO_HW_SAMPLE_RATE_MASK_INVALID = 0xFFFFFFFFu, /**< Invalid sampling rate */
};

enum AudioHwiInputType {
    AUDIO_HW_INPUT_DEFAULT_TYPE             = 0,
    AUDIO_HW_INPUT_MIC_TYPE                 = 1 << 0,
    AUDIO_HW_INPUT_SPEECH_WAKEUP_TYPE       = 1 << 1,
    AUDIO_HW_INPUT_VOICE_COMMUNICATION_TYPE = 1 << 2,
    AUDIO_HW_INPUT_VOICE_RECOGNITION_TYPE   = 1 << 3,
};
/**
 * @brief Defines audio sampling attributes.
 */
struct AudioHwiSampleAttributes {
    enum AudioHwiCategory type;   /**< Audio type. For details, see {@link AudioHwiCategory} */
    bool interleaved;          /**< Interleaving flag of audio data */
    enum AudioHwiFormat format;   /**< Audio data format. For details, see {@link AudioHwiFormat}. */
    uint32_t sampleRate;       /**< Audio sampling rate */
    uint32_t channelCount;     /**< Number of audio channels. For example, for the mono channel, the value is 1,
                                * and for the stereo channel, the value is 2.
                                */
    uint32_t period;           /**< Audio sampling period */
    uint32_t frameSize;        /**< Frame size of the audio data */
    bool isBigEndian;          /**< Big endian flag of audio data */
    bool isSignedData;         /**< Signed or unsigned flag of audio data */
    uint32_t startThreshold;   /**< Audio render start threshold. */
    uint32_t stopThreshold;    /**< Audio render stop threshold. */
    uint32_t silenceThreshold; /**< Audio capture buffer threshold. */
    int32_t streamId;          /**< Audio Identifier of render or capture */
    int32_t sourceType;
};

/**
 * @brief Defines the audio timestamp, which is a substitute for POSIX <b>timespec</b>.
 */
struct AudioHwiTimeStamp {
    int64_t tvSec;  /**< Seconds */
    int64_t tvNSec; /**< Nanoseconds */
};

/**
 * @brief Enumerates the passthrough data transmission mode of an audio port.
 */
enum AudioHwiPortPassthroughMode {
    HW_PORT_PASSTHROUGH_LPCM    = 0x1, /**< Stereo PCM */
    HW_PORT_PASSTHROUGH_RAW     = 0x2, /**< HDMI passthrough */
    HW_PORT_PASSTHROUGH_HBR2LBR = 0x4, /**< Blu-ray next-generation audio output with reduced specifications */
    HW_PORT_PASSTHROUGH_AUTO    = 0x8, /**< Mode automatically matched based on the HDMI EDID */
};

/**
 * @brief Defines the sub-port capability.
 */
struct AudioHwiSubPortCapability {
    uint32_t portId;                    /**< Sub-port ID */
    const char *desc;                   /**< Sub-port name */
    enum AudioHwiPortPassthroughMode mask; /**< Passthrough mode of data transmission. For details,
                                         * see {@link AudioHwiPortPassthroughMode}.
                                         */
};

/**
 * @brief Defines formats of raw audio samples.
 */
enum AudioHwiSampleFormat {
    /* 8 bits */
    AUDIO_HW_SAMPLE_FORMAT_S8,   /**< signed 8 bit sample */
    AUDIO_HW_SAMPLE_FORMAT_S8P,  /**< signed 8 bit planar sample */
    AUDIO_HW_SAMPLE_FORMAT_U8,   /**< unsigned 8 bit sample */
    AUDIO_HW_SAMPLE_FORMAT_U8P,  /**< unsigned 8 bit planar sample */
    /* 16 bits */
    AUDIO_HW_SAMPLE_FORMAT_S16,  /**< signed 16 bit sample */
    AUDIO_HW_SAMPLE_FORMAT_S16P, /**< signed 16 bit planar sample */
    AUDIO_HW_SAMPLE_FORMAT_U16,  /**< unsigned 16 bit sample */
    AUDIO_HW_SAMPLE_FORMAT_U16P, /**< unsigned 16 bit planar sample */
    /* 24 bits */
    AUDIO_HW_SAMPLE_FORMAT_S24,  /**< signed 24 bit sample */
    AUDIO_HW_SAMPLE_FORMAT_S24P, /**< signed 24 bit planar sample */
    AUDIO_HW_SAMPLE_FORMAT_U24,  /**< unsigned 24 bit sample */
    AUDIO_HW_SAMPLE_FORMAT_U24P, /**< unsigned 24 bit planar sample */
    /* 32 bits */
    AUDIO_HW_SAMPLE_FORMAT_S32,  /**< signed 32 bit sample */
    AUDIO_HW_SAMPLE_FORMAT_S32P, /**< signed 32 bit planar sample */
    AUDIO_HW_SAMPLE_FORMAT_U32,  /**< unsigned 32 bit sample */
    AUDIO_HW_SAMPLE_FORMAT_U32P, /**< unsigned 32 bit planar sample */
    /* 64 bits */
    AUDIO_HW_SAMPLE_FORMAT_S64,  /**< signed 64 bit sample */
    AUDIO_HW_SAMPLE_FORMAT_S64P, /**< signed 64 bit planar sample */
    AUDIO_HW_SAMPLE_FORMAT_U64,  /**< unsigned 64 bit sample */
    AUDIO_HW_SAMPLE_FORMAT_U64P, /**< unsigned 64 bit planar sample */
    /* float double */
    AUDIO_HW_SAMPLE_FORMAT_F32,  /**< float 32 bit sample */
    AUDIO_HW_SAMPLE_FORMAT_F32P, /**< float 32 bit planar sample */
    AUDIO_HW_SAMPLE_FORMAT_F64,  /**< double 64 bit sample */
    AUDIO_HW_SAMPLE_FORMAT_F64P, /**< double 64 bit planar sample */
};

/**
 * @brief Defines the audio port capability.
 */
struct AudioHwiPortCapability {
    uint32_t deviceType;                     /**< Device type (output or input) */
    uint32_t deviceId;                       /**< Device ID used for device binding */
    bool hardwareMode;                       /**< Whether to support device binding */
    uint32_t formatNum;                      /**< Number of the supported audio formats */
    enum AudioHwiFormat *formats;            /**< Supported audio formats. For details, see {@link AudioHwiFormat}. */
    uint32_t sampleRateMasks;                /**< Supported audio sampling rates (8 kHz, 16 kHz, 32 kHz, and 48 kHz) */
    enum AudioHwiChannelMask channelMasks;   /**< Audio channel layout mask of the device. For details,
                                              * see {@link AudioHwiChannelMask}.
                                              */
    uint32_t channelCount;                   /**< Supported maximum number of audio channels */
    uint32_t subPortsNum;                    /**< Number of supported sub-ports (for output devices only) */
    struct AudioHwiSubPortCapability *subPorts; /**< List of supported sub-ports */
    uint32_t supportSampleFormatNum;         /**< Number of the supported audio sample format enum. */
    enum AudioHwiSampleFormat *supportSampleFormats; /**< Supported audio sample formats. For details,
                                                   * see {@link AudioHwiSampleFormat}.
                                                   */
};

/**
 * @brief Enumerates channel modes for audio rendering.
 *
 * @attention The following modes are set for rendering dual-channel audios. Others are not supported.
 */
enum AudioHwiChannelMode {
    AUDIO_HW_CHANNEL_NORMAL = 0, /**< Normal mode. No processing is required. */
    AUDIO_HW_CHANNEL_BOTH_LEFT,  /**< Two left channels */
    AUDIO_HW_CHANNEL_BOTH_RIGHT, /**< Two right channels */
    AUDIO_HW_CHANNEL_EXCHANGE, /**< Data exchange between the left and right channels. The left channel takes the audio
                               * stream of the right channel, and the right channel takes that of the left channel.
                               */
    AUDIO_HW_CHANNEL_MIX,        /**< Mix of streams of the left and right channels */
    AUDIO_HW_CHANNEL_LEFT_MUTE,  /**< Left channel muted. The stream of the right channel is output. */
    AUDIO_HW_CHANNEL_RIGHT_MUTE, /**< Right channel muted. The stream of the left channel is output. */
    AUDIO_HW_CHANNEL_BOTH_MUTE,  /**< Both left and right channels muted */
};

/**
 * @brief Enumerates the execution types of the <b>DrainBuffer</b> function.
 */
enum AudioHwiDrainNotifyType {
    AUDIO_HW_DRAIN_NORMAL_MODE, /**< The <b>DrainBuffer</b> function returns after all data finishes playback. */
    AUDIO_HW_DRAIN_EARLY_MODE,  /**< The <b>DrainBuffer</b> function returns before all the data of the current track
                              * finishes playback to reserve time for a smooth track switch by the audio service.
                              */
};

/**
 * @brief Enumerates callback notification events.
 */
enum AudioHwiCallbackType {
    AUDIO_HW_NONBLOCK_WRITE_COMPLETED, /**< The non-block write is complete. */
    AUDIO_HW_DRAIN_COMPLETED,          /**< The draining is complete. */
    AUDIO_HW_FLUSH_COMPLETED,           /**< The flush is complete. */
    AUDIO_HW_RENDER_FULL,               /**< The render buffer is full.*/
    AUDIO_HW_ERROR_OCCUR,               /**< An error occurs.*/
};

/**
 * @brief Describes a mmap buffer.
 */
struct AudioHwiMmapBufferDescriptor {
    void *memoryAddress;                 /**< Pointer to the mmap buffer */
    int32_t memoryFd;                    /**< File descriptor of the mmap buffer */
    int32_t totalBufferFrames;           /**< Total size of the mmap buffer (unit: frame )*/
    int32_t transferFrameSize;           /**< Transfer size (unit: frame) */
    int32_t isShareable;                 /**< Whether the mmap buffer can be shared among processes */
    uint32_t offset;
};

/**
 * @brief Describes AudioHwiPortRole.
 */
enum AudioHwiPortRole {
    AUDIO_HW_PORT_UNASSIGNED_ROLE = 0, /**< Unassigned port role */
    AUDIO_HW_PORT_SOURCE_ROLE = 1,     /**< Assigned source role */
    AUDIO_HW_PORT_SINK_ROLE = 2,       /**< Assigned sink role */
};

/**
 * @brief Describes AudioHwiPortType.
 */
enum AudioHwiPortType {
    AUDIO_HW_PORT_UNASSIGNED_TYPE = 0, /**< Unassigned port type */
    AUDIO_HW_PORT_DEVICE_TYPE = 1,     /**< Assigned device type */
    AUDIO_HW_PORT_MIX_TYPE = 2,        /**< Assigned mix type */
    AUDIO_HW_PORT_SESSION_TYPE = 3,    /**< Assigned session type */
};

/**
 * @brief Describes AudioHwiDevExtInfo.
 */
struct AudioHwiDevExtInfo {
    int32_t moduleId;       /**< Identifier of the module stream is attached to */
    enum AudioHwiPortPin type; /**< Device type For details, see {@link AudioHwiPortPin}. */
    const char *desc;       /**< Address  */
};

/**
 * @brief Describes AudioMixInfo.
 */
struct AudioHwiMixExtInfo {
    int32_t moduleId;     /**< Identifier of the module stream is attached to */
    int32_t streamId;     /**< Identifier of the capture or render passed by caller */
};

/**
 * @brief Describes AudioHwiSessionType.
 */
enum AudioHwiSessionType {
    AUDIO_HW_OUTPUT_STAGE_SESSION = 0,
    AUDIO_HW_OUTPUT_MIX_SESSION,
    AUDIO_HW_ALLOCATE_SESSION,
    AUDIO_HW_INVALID_SESSION,
};

/**
 * @brief Describes AudioHwiSessionExtInfo.
 */
struct AudioHwiSessionExtInfo {
    enum AudioHwiSessionType sessionType;
};

/**
 * @brief Describes AudioHwiRouteNode.
 */
struct AudioHwiRouteNode {
    int32_t portId;                      /**< Audio port ID */
    enum AudioHwiPortRole role;             /**< Audio port as a sink or a source */
    enum AudioHwiPortType type;             /**< device, mix ... */
    union {
        struct AudioHwiDevExtInfo device;   /* Specific Device Ext info */
        struct AudioHwiMixExtInfo mix;      /* Specific mix info */
        struct AudioHwiSessionExtInfo session; /* session specific info */
    } ext;
};

/**
 * @brief Describes AudioHwiRoute.
 */
struct AudioHwiRoute {
    uint32_t sourcesNum;
    struct AudioHwiRouteNode *sources;
    uint32_t sinksNum;
    struct AudioHwiRouteNode *sinks;
};

/**
 * @brief Enumerates the restricted key type of the parameters
 */
enum AudioHwiExtParamKey {
    AUDIO_HW_EXT_PARAM_KEY_NONE = 0,     /**< Distributed audio extra param key none */
    AUDIO_HW_EXT_PARAM_KEY_VOLUME = 1,   /**< Distributed audio extra param key volume event */
    AUDIO_HW_EXT_PARAM_KEY_FOCUS = 2,    /**< Distributed audio extra param key focus event */
    AUDIO_HW_EXT_PARAM_KEY_BUTTON = 3,   /**< Distributed audio extra param key media button event */
    AUDIO_HW_EXT_PARAM_KEY_EFFECT = 4,   /**< Distributed audio extra param key audio effect event */
    AUDIO_HW_EXT_PARAM_KEY_STATUS = 5,   /**< Distributed audio extra param key device status event */
    AUDIO_HW_EXT_PARAM_KEY_LOWPOWER = 1000, /**< Low power event type */
};
/**
 * @brief Describes status of audio deivce.@link enum AudioHwiDeviceType
 */
struct AudioHwiDeviceStatus {
    uint32_t pnpStatus;
};
/**
 * @brief Called when an event defined in {@link AudioHwiCallbackType} occurs.
 *
 * @param AudioHwiCallbackType Indicates the occurred event that triggers this callback.
 * @param reserved Indicates the pointer to a reserved field.
 * @param cookie Indicates the pointer to the cookie for data transmission.
 * @return Returns <b>0</b> if the callback is successfully executed; returns a negative value otherwise.
 * @see RegCallback
 */
typedef int32_t (*RenderHwiCallback)(enum AudioHwiCallbackType, void *reserved, void *cookie);

/**
 * @brief Register audio extra param callback that will be invoked during audio param event.
 *
 * @param key Indicates param change event.
 * @param condition Indicates the param condition.
 * @param value Indicates the param value.
 * @param reserved Indicates reserved param.
 * @param cookie Indicates the pointer to the callback parameters;
 * @return Returns <b>0</b> if the operation is successful; returns a negative value otherwise.
 */
typedef int32_t (*ParamHwiCallback)(enum AudioHwiExtParamKey key, const char *condition,
    const char *value, void *reserved, void *cookie);

#endif /* I_AUDIO_TYPES_H */