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

#ifndef OHOS_VDI_AUDIO_V1_0_IAUDIOADAPTER_H
#define OHOS_VDI_AUDIO_V1_0_IAUDIOADAPTER_H

#include <stdbool.h>
#include <stdint.h>
#include "audio_types_vdi.h"
#include "iaudio_callback_vdi.h"
#include "iaudio_capture_vdi.h"
#include "iaudio_render_vdi.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define IAUDIO_VDI_ADAPTER_MAJOR_VERSION 1
#define IAUDIO_VDI_ADAPTER_MINOR_VERSION 0

struct IAudioAdapterVdi {
    int32_t (*InitAllPorts)(struct IAudioAdapterVdi *self);
    int32_t (*CreateRender)(struct IAudioAdapterVdi *self, const struct AudioDeviceDescriptorVdi *desc,
        const struct AudioSampleAttributesVdi *attrs, struct IAudioRenderVdi **render);
    int32_t (*DestroyRender)(struct IAudioAdapterVdi *self, struct IAudioRenderVdi *render);
    int32_t (*CreateCapture)(struct IAudioAdapterVdi *self, const struct AudioDeviceDescriptorVdi *desc,
        const struct AudioSampleAttributesVdi *attrs, struct IAudioCaptureVdi **capture);
    int32_t (*DestroyCapture)(struct IAudioAdapterVdi *self, struct IAudioCaptureVdi *capture);
    int32_t (*GetPortCapability)(struct IAudioAdapterVdi *self, const struct AudioPortVdi *port,
        struct AudioPortCapabilityVdi *capability);
    int32_t (*SetPassthroughMode)(struct IAudioAdapterVdi *self, const struct AudioPortVdi *port,
        enum AudioPortPassthroughModeVdi mode);
    int32_t (*GetPassthroughMode)(struct IAudioAdapterVdi *self, const struct AudioPortVdi *port,
        enum AudioPortPassthroughModeVdi *mode);
    int32_t (*GetDeviceStatus)(struct IAudioAdapterVdi *self, struct AudioDeviceStatusVdi *status);
    int32_t (*UpdateAudioRoute)(struct IAudioAdapterVdi *self, const struct AudioRouteVdi *route, int32_t *routeHandle);
    int32_t (*ReleaseAudioRoute)(struct IAudioAdapterVdi *self, int32_t routeHandle);
    int32_t (*SetMicMute)(struct IAudioAdapterVdi *self, bool mute);
    int32_t (*GetMicMute)(struct IAudioAdapterVdi *self, bool *mute);
    int32_t (*SetVoiceVolume)(struct IAudioAdapterVdi *self, float volume);
    int32_t (*SetExtraParams)(struct IAudioAdapterVdi *self, enum AudioExtParamKeyVdi key, const char *condition,
        const char *value);
    int32_t (*GetExtraParams)(struct IAudioAdapterVdi *self, enum AudioExtParamKeyVdi key, const char *condition,
        char *value, uint32_t valueLen);
    int32_t (*RegExtraParamObserver)(struct IAudioAdapterVdi *self,
        struct IAudioCallbackVdi *audioCallback, int8_t cookie);
};

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* OHOS_VDI_AUDIO_V1_0_IAUDIOADAPTER_H */