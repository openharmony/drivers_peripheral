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

#include "codec_component_manager.h"
#include <hdf_dlist.h>
#include <hdf_base.h>
#include <hdf_log.h>
#include <osal_mem.h>
#include "hcs_dm_parser.h"
#include "codec_adapter_if.h"
#include "codec_component_capability_config.h"
#include "codec_component_capability.h"

#define HDF_LOG_TAG codec_hdi_passthrough

#define CONFIG_PATH_NAME HDF_CONFIG_DIR"/codec_adapter_capabilities.hcb"

struct ComponentManagerList *g_list = NULL;
uint32_t g_componentId = 0;
static uint32_t GetNextComponentId()
{
    uint32_t tempId = 0;
    if (g_list == NULL) {
        return tempId;
    }
    struct ComponentIdElement *pos = NULL;
    bool find = false;

    do {
        tempId = ++g_componentId;
        find = false;
        DLIST_FOR_EACH_ENTRY(pos, &g_list->head, struct ComponentIdElement, node) {
            if (pos != NULL && tempId == pos->componentId) {
                find = true;
                break;
            }
        }
    } while (find);
    return tempId;
}

static int32_t ComponentManagerGetComponentNum()
{
    int32_t num = 0;
    if (GetComponentNum(&num) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s, GetComponentNum error!", __func__);
    }
    return num;
}

static int32_t ComponentManagerGetComponentCapabilityList(CodecCompCapability *capList, int32_t count)
{
    if (capList == NULL || count <= 0) {
        HDF_LOGE("%{public}s, capList is null or count[%{public}d] <= 0!", __func__, count);
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret = GetComponentCapabilityList(capList, count);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s, GetComponentCapabilityList error!", __func__);
    }
    return ret;
}

static int32_t ComponentManagerCreateComponent(struct CodecComponentType **component, uint32_t *componentId,
                                               char *compName, int64_t appData, struct CodecCallbackType *callbacks)
{
    if (g_list == NULL) {
        HDF_LOGE("%{public}s, g_list is not init!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    struct ComponentIdElement *node = (struct ComponentIdElement *)OsalMemCalloc(sizeof(struct ComponentIdElement));
    if (node == NULL) {
        HDF_LOGE("%{public}s, CodecComponentTypeServiceGet ret null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    struct CodecComponentNode *codecNode = NULL;
    int32_t ret = CodecAdapterCreateComponent(&codecNode, compName, appData, callbacks);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s CodecAdapterCreateComponent error", __func__);
        OsalMemFree(node);
        return ret;
    }

    *component = CodecComponentTypeGet(NULL);
    if (*component == NULL) {
        HDF_LOGE("%{public}s: component is null", __func__);
        CodecAdapterDestroyComponent(codecNode);
        OsalMemFree(node);
        return HDF_FAILURE;
    }

    struct CodecComponentTypeInfo *info = CONTAINER_OF(*component, struct CodecComponentTypeInfo, instance);
    if (info == NULL) {
        HDF_LOGE("%{public}s: info is null", __func__);
        CodecAdapterDestroyComponent(codecNode);
        CodecComponentTypeRelease(*component);
        OsalMemFree(node);
        return HDF_FAILURE;
    }
    info->codecNode = codecNode;
    pthread_mutex_lock(&g_list->listMute);
    *componentId = GetNextComponentId();
    DListInsertTail(&node->node, &g_list->head);
    pthread_mutex_unlock(&g_list->listMute);
    node->componentId = *componentId;
    node->info = info;
    node->comp = &*component;
    return HDF_SUCCESS;
}

static int32_t ComponentManagerDestoryComponent(uint32_t componentId)
{
    if (g_list == NULL) {
        HDF_LOGE("%{public}s, g_list is not init!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    struct ComponentIdElement *pos = NULL;
    struct ComponentIdElement *next = NULL;
    int32_t ret = HDF_FAILURE;
    pthread_mutex_lock(&g_list->listMute);
    DLIST_FOR_EACH_ENTRY_SAFE(pos, next, &g_list->head, struct ComponentIdElement, node) {
        if (pos == NULL || componentId != pos->componentId) {
            continue;
        }
        if (pos->info == NULL) {
            HDF_LOGE("%{public}s: info is null", __func__);
            ret = HDF_FAILURE;
            break;
        }
        ret = CodecAdapterDestroyComponent(pos->info->codecNode);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s CodecAdapterDestroyComponent error", __func__);
            break;
        }
        CodecComponentTypeRelease(&pos->info->instance);
        *pos->comp = NULL;
        DListRemove(&pos->node);
        OsalMemFree(pos);
        pos = NULL;
        break;
    }
    pthread_mutex_unlock(&g_list->listMute);

    return ret;
}

static int32_t InitComponentConfig(void)
{
    ReleaseHcsTree();
    const struct DeviceResourceIface *pDevResIns = DeviceResourceGetIfaceInstance(HDF_CONFIG_SOURCE);
    if (pDevResIns == NULL) {
        HDF_LOGE("get hcs interface failed.");
        return HDF_FAILURE;
    }

    SetHcsBlobPath(CONFIG_PATH_NAME);
    const struct DeviceResourceNode *pRootNode = pDevResIns->GetRootNode();
    if (pRootNode == NULL) {
        HDF_LOGE("GetRootNode failed");
        return HDF_FAILURE;
    }

    const struct DeviceResourceNode *codecConfig = pDevResIns->GetChildNode(pRootNode, "codec_adapter_config");
    if (codecConfig == NULL) {
        HDF_LOGE("codecConfig failed");
        return HDF_FAILURE;
    }

    InitDataNode(codecConfig);
    if (LoadCapabilityData() != HDF_SUCCESS) {
        ClearCapabilityData();
    }
    if (LoadExInfoData(codecConfig) != HDF_SUCCESS) {
        ClearExInfoData();
    }
    return HDF_SUCCESS;
}

static struct CodecComponentManager g_codecComponentManager = {
    .GetComponentNum = ComponentManagerGetComponentNum,
    .GetComponentCapabilityList = ComponentManagerGetComponentCapabilityList,
    .CreateComponent = ComponentManagerCreateComponent,
    .DestroyComponent = ComponentManagerDestoryComponent,
};

struct CodecComponentManager *GetCodecComponentManager(void)
{
    if (g_list == NULL) {
        g_list = (struct ComponentManagerList *)OsalMemCalloc(sizeof(struct ComponentManagerList));
        if (g_list == NULL) {
            HDF_LOGE("%{public}s: malloc ComponentManagerList obj failed!", __func__);
            return NULL;
        }
        DListHeadInit(&g_list->head);
    }
    if (CodecAdapterCodecInit() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s CodecAdapterCodecInit error", __func__);
        return NULL;
    }
    if (InitComponentConfig() != HDF_SUCCESS) {
        CodecAdapterCodecDeinit();
        HDF_LOGE("%{public}s InitComponentConfig error", __func__);
        return NULL;
    }
    return &g_codecComponentManager;
}

void CodecComponentManagerRelease(void)
{
    if (ClearCapabilityData() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s ClearCapabilityData failed !", __func__);
    }
    if (ClearExInfoData() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s ClearExInfoData failed !", __func__);
    }
    if (CodecAdapterCodecDeinit() != HDF_SUCCESS) {
        HDF_LOGE("%{public}s CodecAdapterCodecDeinit error", __func__);
        return;
    }
    if (g_list != NULL) {
        OsalMemFree(g_list);
        g_list = NULL;
    }

    HDF_LOGI("%{public}s end", __func__);
}
