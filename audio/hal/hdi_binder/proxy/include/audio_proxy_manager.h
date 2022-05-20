/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

/**
 * @addtogroup Audio
 * @{
 *
 * @brief Defines audio-related APIs, including custom data types and functions for loading drivers,
 * accessing a driver adapter, and rendering and capturing audios.
 *
 * @since 1.0
 * @version 1.0
 */

/**
 * @file audio_manager.h
 *
 * @brief Declares APIs for audio adapter management and loading.
 *
 * @since 1.0
 * @version 1.0
 */

#ifndef AUDIO_PROXY_MANAGER_H
#define AUDIO_PROXY_MANAGER_H
#include "audio_adapter.h"
#include "audio_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

struct AudioProxyManager {
    uint32_t audioMagic;
    struct HdfRemoteService *remote;
    struct HdfRemoteService *usbRemote;
    struct HdfRemoteService *a2dpRemote;
    struct AudioManager impl;
};

int32_t AudioProxyManagerGetAllAdapters(struct AudioManager *manager,
                                        struct AudioAdapterDescriptor **descs,
                                        int *size);
int32_t AudioProxyManagerLoadAdapter(struct AudioManager *manager, const struct AudioAdapterDescriptor *desc,
                                     struct AudioAdapter **adapter);
void AudioProxyManagerUnloadAdapter(struct AudioManager *manager, struct AudioAdapter *adapter);

#ifdef __cplusplus
}
#endif

#endif /* AUDIO_MANAGER_H */
/** @} */
