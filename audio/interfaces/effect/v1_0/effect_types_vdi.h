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

#ifndef OHOS_VDI_AUDIO_V1_0_EFFECTTYPES_H
#define OHOS_VDI_AUDIO_V1_0_EFFECTTYPES_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct EffectInfoVdi {
    char *libName;
    char *effectId;
    int32_t ioDirection;
};

struct ControllerIdVdi {
    char *libName;
    char *effectId;
};

struct EffectControllerDescriptorVdi {
    char *effectId;
    char *effectName;
    char *libName;
    char *supplier;
};

enum AudioEffectBufferVdiTag {
    EFFECT_BUFFER_VDI_VOID_TYPE = 0x0,
    EFFECT_BUFFER_VDI_FLOAT_SIGNED_32 = 0x1,
    EFFECT_BUFFER_VDI_SINGED_32 = 0x2,
    EFFECT_BUFFER_VDI_SIGNED_16 = 0x4,
    EFFECT_BUFFER_VDI_UNSIGNED_8 = 0x8,
};

struct AudioEffectBufferVdi {
    uint32_t frameCount;
    int32_t datatag;
    int8_t *rawData;
    uint32_t rawDataLen;
};

enum EffectCommandTableIndexVdi {
    AUDIO_EFFECT_COMMAND_VDI_INIT_CONTOLLER,
    AUDIO_EFFECT_COMMAND_VDI_SET_CONFIG,
    AUDIO_EFFECT_COMMAND_VDI_GET_CONFIG,
    AUDIO_EFFECT_COMMAND_VDI_RESET,
    AUDIO_EFFECT_COMMAND_VDI_ENABLE,
    AUDIO_EFFECT_COMMAND_VDI_DISABLE,
    AUDIO_EFFECT_COMMAND_VDI_SET_PARAM,
    AUDIO_EFFECT_COMMAND_VDI_GET_PARAM,
};

enum AudioEffectHDICommandVdi {
    EFFECT_INIT = 0,
    EFFECT_BYPASS = 1,
    EFFECT_HEAD_MODE = 2,
    EFFECT_ROOM_MODE = 3,
    EFFECT_BLUETOOTH_MODE = 4,
    EFFECT_DESTROY = 5,
    EFFECT_SPATIAL_DEVICE_TYPE = 6,
};

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* OHOS_VDI_AUDIO_EFFECTTYPES_H */