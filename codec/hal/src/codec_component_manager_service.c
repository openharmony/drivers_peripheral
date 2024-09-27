/*
 * Copyright (c) 2022-2023 Shenzhen Kaihong DID Co., Ltd.
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
#include "codec_component_manager_service.h"
#include <hdf_base.h>
#include <osal_mem.h>
#include <securec.h>
#include <unistd.h>
#include "codec_adapter_interface.h"
#include "codec_component_capability_config.h"
#include "codec_component_manager_stub.h"
#include "codec_component_type_service.h"
#include "codec_death_recipient.h"
#include "codec_log_wrapper.h"

#define MAX_COMPONENT_SIZE 32
struct CodecComponentManagerSerivce *g_service = NULL;
uint32_t g_componentId = 0;

static void OnRemoteServiceDied(struct HdfDeathRecipient *deathRecipient, struct HdfRemoteService *remote)
{
    CleanRemoteServiceResource(deathRecipient, remote);
}

static struct RemoteServiceDeathRecipient g_deathRecipient = {
    .recipient = {
        .OnRemoteDied = OnRemoteServiceDied,
    }
};

static void AddDeathRecipientForService(struct CodecCallbackType *callbacks, uint32_t componentId,
                                        struct CodecComponentNode *codecNode)
{
    if (callbacks == NULL) {
        CODEC_LOGE("invalid parameter");
        return;
    }
    bool needAdd = RegisterService(callbacks, componentId, codecNode);
    if (needAdd) {
        CODEC_LOGI("add deathRecipient for remoteService!");
        HdfRemoteServiceAddDeathRecipient(callbacks->remote, &g_deathRecipient.recipient);
    }
}

static uint32_t GetNextComponentId()
{
    uint32_t tempId = 0;
    if (g_service == NULL) {
        return tempId;
    }
    struct ComponentTypeNode *pos = NULL;
    struct ComponentTypeNode *next = NULL;
    bool find = false;

    do {
        tempId = ++g_componentId;
        find = false;
        DLIST_FOR_EACH_ENTRY_SAFE(pos, next, &g_service->head, struct ComponentTypeNode, node)
        {
            if (pos != NULL && tempId == pos->componentId) {
                find = true;
                break;
            }
        }
    } while (find);
    return tempId;
}

static int32_t OmxManagerGetComponentNum()
{
    int32_t num = 0;
    if (GetComponentNum(&num) != HDF_SUCCESS) {
        CODEC_LOGE("GetComponentNum error!");
    }
    return num;
}

static int32_t OmxManagerGetComponentCapabilityList(CodecCompCapability *capList, int32_t count)
{
    int32_t err = GetComponentCapabilityList(capList, count);
    if (err != HDF_SUCCESS) {
        CODEC_LOGE("GetComponentNum error!");
    }
    return err;
}

static int32_t OmxManagerDestroyComponent(uint32_t componentId)
{
    CODEC_LOGI("service impl, %{public}d!", componentId);
    if (g_service == NULL) {
        CODEC_LOGE("g_service is not init!");
        return HDF_ERR_INVALID_PARAM;
    }

    struct ComponentTypeNode *pos = NULL;
    struct ComponentTypeNode *next = NULL;
    int32_t err = HDF_SUCCESS;
    pthread_mutex_lock(&g_service->listMute);

    DLIST_FOR_EACH_ENTRY_SAFE(pos, next, &g_service->head, struct ComponentTypeNode, node)
    {
        if (pos == NULL || componentId != pos->componentId) {
            continue;
        }

        struct CodecComponentNode *codecNode = CodecComponentTypeServiceGetCodecNode(pos->service);
        if (codecNode != NULL) {
            err = OmxAdapterDestroyComponent(codecNode);
            if (err != HDF_SUCCESS) {
                CODEC_LOGE("OmxAdapterDestroyComponent ret err[%{public}d]!", err);
                break;
            }
            RemoveDestoryedComponent(componentId);
        }

        DListRemove(&pos->node);
        CodecComponentTypeServiceRelease(pos->service);
        OsalMemFree(pos);
        pos = NULL;
        break;
    }

    pthread_mutex_unlock(&g_service->listMute);
    return err;
}

static int32_t OmxManagerCreateComponent(struct CodecComponentType **component, uint32_t *componentId, char *compName,
                                         int64_t appData, struct CodecCallbackType *callbacks)
{
    CODEC_LOGI("service impl!");
    if (g_service == NULL) {
        CODEC_LOGE("g_service is not init!");
        return HDF_ERR_INVALID_PARAM;
    }

    struct CodecComponentType *comp = CodecComponentTypeServiceGet();
    if (comp == NULL) {
        CODEC_LOGE("CodecComponentTypeServiceGet ret null!");
        return HDF_ERR_INVALID_PARAM;
    }

    struct ComponentTypeNode *node = (struct ComponentTypeNode *)OsalMemCalloc(sizeof(struct ComponentTypeNode));
    if (node == NULL) {
        CODEC_LOGE("CodecComponentTypeServiceGet ret null!");
        CodecComponentTypeServiceRelease(comp);
        return HDF_ERR_INVALID_PARAM;
    }

    struct CodecComponentNode *codecNode = NULL;
    int32_t err = OMXAdapterCreateComponent(&codecNode, compName, appData, callbacks);
    if (err != HDF_SUCCESS) {
        CODEC_LOGE("OMXAdapterCreateComponent err [%{public}x]", err);
        CodecComponentTypeServiceRelease(comp);
        OsalMemFree(node);
        return HDF_ERR_INVALID_PARAM;
    }
    *component = comp;
    pthread_mutex_lock(&g_service->listMute);
    *componentId = GetNextComponentId();
    CodecComponentTypeServiceSetCodecNode(comp, codecNode);
    DListInsertTail(&node->node, &g_service->head);
    pthread_mutex_unlock(&g_service->listMute);
    node->componentId = *componentId;
    node->service = comp;
#ifdef SUPPORT_ROLE
    err = OmxAdapterSetComponentRole(codecNode, compName);
    if (err != HDF_SUCCESS) {
        CODEC_LOGE("OMXAdapterSetComponentRole err [%{public}x]", err);
        OmxManagerDestroyComponent(*componentId);
        CodecComponentTypeServiceRelease(comp);
        OsalMemFree(node);
        return HDF_ERR_INVALID_PARAM;
    }
#endif
    CODEC_LOGI("componentId:%{public}d", node->componentId);
    AddDeathRecipientForService(callbacks, *componentId, codecNode);
    return err;
}

static void CodecComponentManagerServiceConstruct(struct CodecComponentManager *manager)
{
    if (manager != NULL) {
        manager->GetComponentNum = OmxManagerGetComponentNum;
        manager->GetComponentCapabilityList = OmxManagerGetComponentCapabilityList;
        manager->CreateComponent = OmxManagerCreateComponent;
        manager->DestroyComponent = OmxManagerDestroyComponent;
    }
}

struct CodecComponentManagerSerivce *CodecComponentManagerSerivceGet(void)
{
    if (g_service == NULL) {
        g_service = (struct CodecComponentManagerSerivce *)OsalMemCalloc(sizeof(struct CodecComponentManagerSerivce));
        if (g_service == NULL) {
            CODEC_LOGE("malloc OmxComponentManagerService obj failed!");
            return NULL;
        }
        DListHeadInit(&g_service->head);
        if (!CodecComponentManagerStubConstruct(&g_service->stub)) {
            CODEC_LOGE("construct SampleStub obj failed!");
            OmxComponentManagerSeriveRelease(g_service);
            g_service = NULL;
        }
        CodecComponentManagerServiceConstruct(&g_service->stub.interface);
    }
    return g_service;
}

void OmxComponentManagerSeriveRelease(struct CodecComponentManagerSerivce *instance)
{
    if (instance == NULL) {
        return;
    }
    if (g_service == instance) {
        g_service = NULL;
    }
    OsalMemFree(instance);
}

void CleanRemoteServiceResource(struct HdfDeathRecipient *deathRecipient, struct HdfRemoteService *remote)
{
    uint32_t compIds[MAX_COMPONENT_SIZE];
    uint32_t size = 0;
    int32_t ret = CleanMapperOfDiedService(remote, compIds, &size);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("clearn remote resource error!");
        return;
    }

    if (size == 0) {
        CODEC_LOGE("remoteService no componment resource need to be release!");
        return;
    }
    for (uint32_t i = 0; i < size; i++) {
        OmxManagerDestroyComponent(compIds[i]);
        CODEC_LOGI("destroyComponent done, compId=[%{public}d]", compIds[i]);
    }

    CODEC_LOGI("remote service died , clean resource success!");
}