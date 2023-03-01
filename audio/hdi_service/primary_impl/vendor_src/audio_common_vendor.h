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

#ifndef AUDIO_COMMON_VENDOR_H
#define AUDIO_COMMON_VENDOR_H

#include "i_audio_types.h"
#include "v1_0/audio_types.h"

void AudioHwiCommonDescToHwiDesc(const struct AudioDeviceDescriptor *desc,
    struct AudioHwiDeviceDescriptor *hwiDesc);
void AudioHwiCommonAttrsToHwiAttrs(const struct AudioSampleAttributes *attrs,
    struct AudioHwiSampleAttributes *hwiAttrs);
int32_t AudioHwiCommonPortToHwiPort(const struct AudioPort *port, struct AudioHwiPort *hwiPort);
int32_t AudioHwiCommonHwiPortCapToPortCap(const struct AudioHwiPortCapability *hwiPortCap,
    struct AudioPortCapability *portCap);
int32_t AudioHwiCommonRouteToHwiRoute(const struct AudioRoute *route, struct AudioHwiRoute *hwiRoute);
void AudioHwiCommonFreeHwiRoute(struct AudioHwiRoute *hwiRoute);

#endif // AUDIO_COMMON_VENDOR_H