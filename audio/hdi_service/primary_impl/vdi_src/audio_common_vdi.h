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

#ifndef AUDIO_COMMON_VDI_H
#define AUDIO_COMMON_VDI_H

#include "audio_types_vdi.h"
#include "v3_0/audio_types.h"

#define AUDIO_VDI_ADAPTER_NUM_MAX        20 // Limit the number of sound cards supported to a maximum of 20
#define AUDIO_VDI_PORT_NUM_MAX    10
#define AUDIO_VDI_STREAM_NUM_MAX  10

void AudioCommonDevDescToVdiDevDescVdi(const struct AudioDeviceDescriptor *desc,
    struct AudioDeviceDescriptorVdi *vdiDesc);
void AudioCommonAttrsToVdiAttrsVdi(const struct AudioSampleAttributes *attrs,
    struct AudioSampleAttributesVdi *vdiAttrs);
int32_t AudioCommonPortToVdiPortVdi(const struct AudioPort *port, struct AudioPortVdi *vdiPort);
void AudioCommonVdiPortCapToPortCapVdi(const struct AudioPortCapabilityVdi *vdiPortCap,
    struct AudioPortCapability *portCap);
int32_t AudioCommonRouteToVdiRouteVdi(const struct AudioRoute *route, struct AudioRouteVdi *vdiRoute);
void AudioCommonFreeVdiRouteVdi(struct AudioRouteVdi *vdiRoute);
int32_t AudioCommonSceneToVdiSceneVdi(const struct AudioSceneDescriptor *scene,
    struct AudioSceneDescriptorVdi *vdiScene);
int32_t AudioCommonSampleAttrToVdiSampleAttrVdi(const struct AudioSampleAttributes *attrs,
    struct AudioSampleAttributesVdi *vdiAttrs);
int32_t AudioCommonVdiSampleAttrToSampleAttrVdi(const struct AudioSampleAttributesVdi *vdiAttrs,
    struct AudioSampleAttributes *attrs);
int32_t AudioCommonFrameInfoToVdiFrameInfoVdi(const struct AudioFrameLen *frameLen,
    struct AudioCaptureFrameInfoVdi *frameInfoVdi);
int32_t AudioCommonVdiFrameInfoToFrameInfoVdi(struct AudioCaptureFrameInfoVdi *frameInfoVdi,
    struct AudioCaptureFrameInfo *frameInfo);

#endif // AUDIO_COMMON_VDI_H