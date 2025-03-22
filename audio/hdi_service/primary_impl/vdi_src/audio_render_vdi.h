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

#ifndef AUDIO_RENDER_VDI_H
#define AUDIO_RENDER_VDI_H

#include "iaudio_render_vdi.h"
#include "v4_0/iaudio_render.h"
#include <pthread.h>

pthread_rwlock_t* GetRenderLock(void);
struct IAudioRender *AudioCreateRenderByIdVdi(const struct AudioSampleAttributes *attrs, uint32_t *renderId,
    struct IAudioRenderVdi *vdiRender, const struct AudioDeviceDescriptor *desc, char *adapterName);
void AudioDestroyRenderByIdVdi(uint32_t renderId);
struct IAudioRenderVdi *AudioGetVdiRenderByIdVdi(uint32_t renderId);
struct IAudioRender *FindRenderCreated(enum AudioPortPin pin, const struct AudioSampleAttributes *attrs,
    uint32_t *rendrId, const char *adapterName);
uint32_t DecreaseRenderUsrCount(uint32_t renderId);

#endif // AUDIO_RENDER_VDI_H
