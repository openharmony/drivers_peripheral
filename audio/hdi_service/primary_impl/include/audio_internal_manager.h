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

#ifndef AUDIO_INTERNAL_MANAGER_H
#define AUDIO_INTERNAL_MANAGER_H

#include "v3_0/iaudio_manager.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

int32_t AudioManagerGetAllAdapters(struct IAudioManager *manager, struct AudioAdapterDescriptor *descs, uint32_t *size);

int32_t AudioManagerLoadAdapter(
    struct IAudioManager *manager, const struct AudioAdapterDescriptor *desc, struct IAudioAdapter **adapter);

int32_t AudioManagerUnloadAdapter(struct IAudioManager *manager, const char *adapterName);

int32_t ReleaseAudioManagerObject(struct IAudioManager *object);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // AUDIO_INTERNAL_MANAGER_H
