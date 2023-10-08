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

#ifndef HDF_I_AUDIO_TYPES_H
#define HDF_I_AUDIO_TYPES_H

#include <string>
#include <vector>

namespace OHOS {
namespace DistributedHardware {
enum AudioChannelModeHAL {
    AUDIO_CHANNEL_NORMAL = 0,
    AUDIO_CHANNEL_BOTH_LEFT,
    AUDIO_CHANNEL_BOTH_RIGHT,
    AUDIO_CHANNEL_EXCHANGE,

    AUDIO_CHANNEL_MIX,
    AUDIO_CHANNEL_LEFT_MUTE,
    AUDIO_CHANNEL_RIGHT_MUTE,
    AUDIO_CHANNEL_BOTH_MUTE,
};

enum AudioDrainNotifyTypeHAL {
    AUDIO_DRAIN_NORMAL_MODE,
    AUDIO_DRAIN_EARLY_MODE,
};

enum AudioPortPassthroughModeHAL {
    PORT_PASSTHROUGH_LPCM = 0x1,
    PORT_PASSTHROUGH_RAW = 0x2,
    PORT_PASSTHROUGH_HBR2LBR = 0x4,
    PORT_PASSTHROUGH_AUTO = 0x8,
};

struct AudioDeviceDescriptorHAL {
    uint32_t portId;
    uint32_t pins;
    std::string desc;
};

struct AudioSceneDescriptorHAL {
    uint32_t id;
    AudioDeviceDescriptorHAL desc;
};

struct AudioPortHAL {
    uint32_t dir;
    uint32_t portId;
    std::string portName;
};

struct AudioAdapterDescriptorHAL {
    std::string adapterName;
    std::vector<AudioPortHAL> ports;
};

struct AudioTimeStampHAL {
    uint64_t tvSec;
    uint64_t tvNSec;
};

struct AudioSampleAttributesHAL {
    uint32_t type;
    uint32_t interleaved;
    uint32_t format;
    uint32_t sampleRate;
    uint32_t channelCount;

    uint32_t period;
    uint32_t frameSize;
    uint32_t isBigEndian;
    uint32_t isSignedData;
    uint32_t startThreshold;
    uint32_t stopThreshold;
    uint32_t silenceThreshold;
    uint32_t streamId;
};

struct AudioSubPortCapabilityHAL {
    uint32_t portId;
    uint32_t mask;
    std::string desc;
};

struct AudioPortCapabilityHAL {
    uint32_t deviceType;
    uint32_t deviceId;
    uint32_t hardwareMode;
    uint32_t formatNum;
    std::vector<uint32_t> formats;
    uint32_t sampleRateMasks;
    uint32_t channelMasks;
    uint32_t channelCount;
    uint32_t subPortsNum;
    AudioSubPortCapabilityHAL subPorts;
};

struct AudioDevExtInfoHAL {
    int32_t moduleId;
    uint32_t type;
    uint8_t desc[32];
};

struct AudioMixExtInfoHAL {
    int32_t moduleId;
    int32_t streamId;
};

struct AudioSessionInfoHAL {
    uint32_t sessionType;
};

struct AudioRouteNodeHAL {
    int32_t portId;
    uint32_t role;
    uint32_t type;
    struct AudioDevExtInfoHAL device;
    struct AudioMixExtInfoHAL mix;
    struct AudioSessionInfoHAL session;
};

struct AudioRouteHAL {
    std::vector<AudioRouteNodeHAL> sources;
    std::vector<AudioRouteNodeHAL> sinks;
};

struct AudioParameter {
    uint32_t paramType;
    uint32_t value;
    std::string content;
};

struct AudioMmapBufferDescriptorHAL {
    int32_t memoryFd;
    int32_t totalBufferFrames;
    int32_t transferFrameSize;
    int32_t isShareable;
};

} // namespace DistributedHardware
} // namespace OHOS
#endif