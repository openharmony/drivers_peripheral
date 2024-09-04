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

#ifndef AUDIO_MANAGER_VDI_H
#define AUDIO_MANAGER_VDI_H

#include "iaudio_manager_vdi.h"
#include "v3_0/iaudio_manager.h"

#define AUDIO_VDI_ADAPTER_NUM_MAX  20 // Limit the number of sound cards supported to a maximum of 20
#define AUDIO_VDI_PORT_NUM_MAX    10
#define AUDIO_VDI_STREAM_NUM_MAX  10

struct IAudioManager *AudioManagerCreateIfInstance(void);
int32_t AudioManagerDestroyIfInstance(struct IAudioManager *manager);

#endif // AUDIO_MANAGER_VDI_H