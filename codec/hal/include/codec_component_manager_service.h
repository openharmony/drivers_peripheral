/*
 * Copyright (c) 2022 Shenzhen Kaihong DID Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CODEC_COMPONENT_MANAGER_SERVICE_H
#define CODEC_COMPONENT_MANAGER_SERVICE_H

#include <hdf_dlist.h>
#include <hdf_remote_service.h>
#include <pthread.h>
#include "codec_component_if.h"
#include "codec_component_manager_stub.h"
#include "codec_component_type_service.h"
#include "codec_internal.h"
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct ComponentTypeNode {
    uint32_t componentId;
    struct CodecComponentType *service;
    struct DListHead node;
};

struct CodecComponentManagerSerivce {
    struct CodecComponentManagerStub stub;
    pthread_mutex_t listMute;
    struct DListHead head;
};

struct RemoteServiceDeathRecipient {
    struct HdfDeathRecipient recipient;
};

struct CodecComponentManagerSerivce *CodecComponentManagerSerivceGet(void);
void OmxComponentManagerSeriveRelease(struct CodecComponentManagerSerivce *instance);
void CleanRemoteServiceResource(struct HdfDeathRecipient *deathRecipient, struct HdfRemoteService *remote);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  // CODEC_COMPONENT_MANAGER_SERVICE_H