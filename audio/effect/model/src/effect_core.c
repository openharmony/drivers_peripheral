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

/**
 * @addtogroup Effect
 * @{
 *
 * @brief defines the effect core methods
 *
 * @since 4.0
 * @version 1.0
 */

#include "effect_core.h"
#include "hdf_base.h"
#include "osal_mem.h"
#include "audio_uhdf_log.h"

#define HDF_LOG_TAG HDF_AUDIO_EFFECT

/* list to manager the effect factory libs */
AEM_GET_INITED_DLIST(g_libList);

/* list to manager the effect controller */
AEM_GET_INITED_DLIST(g_controllerList);

/* reist the effect lib */
/*
int32_t RegisterEffectLibToList(void *handle, struct EffectFactory *factLib)
{
    struct EffectFactoryLibListNode *node = NULL;
    if (factLib == NULL) {
        HDF_LOGE("%{public}s: input params is null", __func__);
        return HDF_FAILURE;
    }

    node = (struct EffectFactoryLibListNode *)OsalMemCalloc(sizeof(struct EffectFactoryLibListNode));
    if (node == NULL) {
        HDF_LOGE("%{public}s: memlloc failed", __func__);
        return HDF_FAILURE;
    }

    node->factLib = factLib;
    node->handle = handle;
    DListInsertHead(&node->list, &g_libList);

    return HDF_SUCCESS;
}

// release the effect lib using at the release process
void ReleaseLibFromList(void)
{
    struct EffectFactoryLibListNode *targetNode;
    struct EffectFactoryLibListNode *tmpNode;

    DLIST_FOR_EACH_ENTRY_SAFE(targetNode, tmpNode, &g_libList, struct EffectFactoryLibListNode, list) {
        DListRemove(&targetNode->list);
        dlclose(targetNode->handle);
        OsalMemFree(targetNode);
    }

    HDF_LOGI("lib remove from the list successfully");
}

// get the lib by libname
struct EffectFactory *GetEffectLibFromList(const char *effectLibName)
{
    struct EffectFactoryLibListNode *tmpNode = NULL;
    if (effectLibName == NULL) {
        HDF_LOGE("effectLibName is NULL.");
        return NULL;
    }

    if (DListIsEmpty(&g_libList)) {
        HDF_LOGE("g_libList is empty.");
        return NULL;
    }

    DLIST_FOR_EACH_ENTRY(tmpNode, &g_libList, struct EffectFactoryLibListNode, list) {
        if (tmpNode->factLib != NULL && tmpNode->factLib->effectLibName != NULL) {
            if (strcmp(tmpNode->factLib->effectLibName, effectLibName) == 0) {
                return tmpNode->factLib;
            }
        }
    }

    HDF_LOGE("effectLibName %{public}s not exit in list", effectLibName);
    return NULL;
}
*/
bool IsEffectLibExist(void)
{
    bool isSupply = true;

    if (DListIsEmpty(&g_libList)) {
        HDF_LOGE("effect lib list is empty, no effect lib");
        isSupply = false;
    }

    return isSupply;
}

/*
// effect controller；
int32_t RegisterControllerToList(struct ControllerManager *ctrlMgr)
{
    struct ControllerManagerNode *node = NULL;
    if (ctrlMgr == NULL) {
        HDF_LOGE("%{public}s: input params is null", __func__);
        return HDF_FAILURE;
    }

    node = (struct ControllerManagerNode *)OsalMemCalloc(sizeof(struct ControllerManagerNode));
    if (node == NULL) {
        HDF_LOGE("%{public}s: OsalMemCalloc failed", __func__);
        return HDF_FAILURE;
    }

    node->ctrlMgr = ctrlMgr;
    DListInsertHead(&node->list, &g_controllerList);

    return HDF_SUCCESS;
}

// get the contoller using at the desroy process
struct ControllerManager *GetControllerFromList(char *effectId)
{
    struct ControllerManagerNode *getNode = NULL;
    struct ControllerManagerNode *tmpNode = NULL;
    struct ControllerManager *ctrlMgr = NULL;
    if (effectId == NULL) {
        HDF_LOGE("effectLibName is NULL.");
        return NULL;
    }

    if (DListIsEmpty(&g_controllerList)) {
        HDF_LOGE("g_controllerList is empty.");
        return NULL;
    }
    // get the ctrlMgr and remove it from the list and release the node
    DLIST_FOR_EACH_ENTRY_SAFE(getNode, tmpNode, &g_controllerList, struct ControllerManagerNode, list) {
        if (getNode->ctrlMgr != NULL && getNode->ctrlMgr->effectId != NULL) {
            if (strcmp(getNode->ctrlMgr->effectId, effectId) == 0) {
                ctrlMgr = getNode->ctrlMgr;
                DListRemove(&getNode->list);
                OsalMemFree(getNode);
                return ctrlMgr;
            }
        }
    }

    HDF_LOGE("effectId %s not exit in list", effectId);
    return NULL;
}
*/