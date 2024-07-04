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

#ifndef AUDIO_ADAPTER_VDI_H
#define AUDIO_ADAPTER_VDI_H

#include "iaudio_adapter_vdi.h"
#include "v4_0/iaudio_adapter.h"
#include <pthread.h>

struct IAudioAdapter *AudioCreateAdapterVdi(uint32_t descIndex, struct IAudioAdapterVdi *vdiAdapter);
void AudioReleaseAdapterVdi(uint32_t descIndex);
struct IAudioAdapterVdi *AudioGetVdiAdapterByDescIndexVdi(uint32_t descIndex);
int32_t AudioIncreaseAdapterRefVdi(uint32_t descIndex, struct IAudioAdapter **adapter);
void AudioDecreaseAdapterRefVdi(uint32_t descIndex);
uint32_t AudioGetAdapterRefCntVdi(uint32_t descIndex);
void AudioEnforceClearAdapterRefCntVdi(uint32_t descIndex);
int32_t InitAdapterMutex(void);
void DeinitAdapterMutex(void);

#endif // AUDIO_ADAPTER_VDI_H