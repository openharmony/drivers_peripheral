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

#ifndef OHOS_VDI_AUDIO_V1_0_IAUDIOMANAGER_H
#define OHOS_VDI_AUDIO_V1_0_IAUDIOMANAGER_H

#include <stdbool.h>
#include <stdint.h>
#include "audio_types_vdi.h"
#include "iaudio_adapter_vdi.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define IAUDIO_VDI_MANAGER_MAJOR_VERSION 1
#define IAUDIO_VDI_MANAGER_MINOR_VERSION 0
#define AUDIO_VDI_ADAPTER_NUM_MAX  20

struct IAudioManagerVdi {
    int32_t (*GetAllAdapters)(struct IAudioManagerVdi *self,
        struct AudioAdapterDescriptorVdi *descs, uint32_t *descsLen);
    int32_t (*LoadAdapter)(struct IAudioManagerVdi *self, const struct AudioAdapterDescriptorVdi *desc,
        struct IAudioAdapterVdi **adapter);
    int32_t (*UnloadAdapter)(struct IAudioManagerVdi *self, struct IAudioAdapterVdi *adapter);
    int32_t (*ReleaseAudioManagerObject)(struct IAudioManagerVdi *self);
};

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* OHOS_VDI_AUDIO_V1_0_IAUDIOMANAGER_H */