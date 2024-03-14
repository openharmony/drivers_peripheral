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

#ifndef AUDIO_ADAPTER_VENDOR_H
#define AUDIO_ADAPTER_VENDOR_H

#include "i_audio_adapter.h"
#include "v1_0/iaudio_adapter.h"

struct IAudioAdapter *AudioHwiCreateAdapter(uint32_t descIndex, struct AudioHwiAdapter *hwiAdapter);
void AudioHwiReleaseAdapter(uint32_t descIndex);
struct AudioHwiAdapter *AudioHwiGetHwiAdapterByDescIndex(uint32_t descIndex);
int32_t AudioHwiIncreaseAdapterRef(uint32_t descIndex, struct IAudioAdapter **adapter);
void AudioHwiDecreaseAdapterRef(uint32_t descIndex);
uint32_t AudioHwiGetAdapterRefCnt(uint32_t descIndex);
void AudioHwiEnforceClearAdapterRefCnt(uint32_t descIndex);

#endif // AUDIO_ADAPTER_VENDOR_H