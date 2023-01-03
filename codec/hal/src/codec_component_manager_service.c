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
#include "codec_component_manager_service.h"
#include <hdf_base.h>
#include <hdf_log.h>
#include <osal_mem.h>
#include <securec.h>
#include <unistd.h>
#include "codec_adapter_interface.h"
#include "codec_component_capability_config.h"
#include "codec_component_manager_stub.h"
#include "codec_component_type_service.h"

#define HDF_LOG_TAG codec_hdi_server

struct CodecComponentManagerSerivce *g_service = NULL;
uint32_t g_componentId = 0;
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
        HDF_LOGE("%{public}s, GetComponentNum error!", __func__);
    }
    return num;
}

static int32_t OmxManagerGetComponentCapabilityList(CodecCompCapability *capList, int32_t count)
{
    int32_t err = GetComponentCapabilityList(capList, count);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s, GetComponentNum error!", __func__);
    }
    return err;
}

static int32_t OmxManagerCreateComponent(struct CodecComponentType **component, uint32_t *componentId, char *compName,
                                         int64_t appData, struct CodecCallbackType *callbacks)
{
    HDF_LOGI("%{public}s, service impl!", __func__);
    if (g_service == NULL) {
        HDF_LOGE("%{public}s, g_service is not init!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct CodecComponentType *comp = CodecComponentTypeServiceGet();
    if (comp == NULL) {
        HDF_LOGE("%{public}s, CodecComponentTypeServiceGet ret null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct ComponentTypeNode *node = (struct ComponentTypeNode *)OsalMemCalloc(sizeof(struct ComponentTypeNode));
    if (node == NULL) {
        HDF_LOGE("%{public}s, CodecComponentTypeServiceGet ret null!", __func__);
        CodecComponentTypeServiceRelease(comp);
        return HDF_ERR_INVALID_PARAM;
    }

    struct CodecComponentNode *codecNode = NULL;
    int32_t err = OMXAdapterCreateComponent(&codecNode, compName, appData, callbacks);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s, OMXAdapterCreateComponent err [%{public}x]", __func__, err);
        CodecComponentTypeServiceRelease(comp);
        OsalMemFree(node);
        return HDF_ERR_INVALID_PARAM;
    }
#ifdef SUPPORT_ROLE
    err = OmxAdapterSetComponentRole(codecNode, compName);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s, OMXAdapterSetComponentRole err [%{public}x]", __func__, err);
        CodecComponentTypeServiceRelease(comp);
        OsalMemFree(node);
        return HDF_ERR_INVALID_PARAM;
    }
#endif
    *component = comp;
    pthread_mutex_lock(&g_service->listMute);
    *componentId = GetNextComponentId();
    CodecComponentTypeServiceSetCodecNode(comp, codecNode);
    DListInsertTail(&node->node, &g_service->head);
    pthread_mutex_unlock(&g_service->listMute);

    node->componentId = *componentId;
    node->service = comp;
    HDF_LOGI("%{public}s: comp is %{public}p, componentId:%{public}d", __func__, comp, node->componentId);
    return err;
}

static int32_t OmxManagerDestroyComponent(uint32_t componentId)
{
    HDF_LOGI("%{public}s, service impl, %{public}d!", __func__, componentId);
    if (g_service == NULL) {
        HDF_LOGE("%{public}s, g_service is not init!", __func__);
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
                HDF_LOGE("%{public}s, OmxAdapterDestroyComponent ret err[%{public}d]!", __func__, err);
                break;
            }
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
            HDF_LOGE("%{public}s: malloc OmxComponentManagerService obj failed!", __func__);
            return NULL;
        }
        DListHeadInit(&g_service->head);
        if (!CodecComponentManagerStubConstruct(&g_service->stub)) {
            HDF_LOGE("%{public}s: construct SampleStub obj failed!", __func__);
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
