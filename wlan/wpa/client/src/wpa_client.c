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

#include <string.h>
#include <stdlib.h>
#include <osal_mem.h>
#include <pthread.h>
#include "hdf_log.h"
#include "securec.h"
#include "wpa_client.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif


#ifndef EOK
#define EOK 0
#endif

#define MAX_CALL_BACK_COUNT 10
static struct WpaCallbackEvent *g_wpaCallbackEventMap[MAX_CALL_BACK_COUNT] = {NULL};
static pthread_rwlock_t g_wpaCallbackMutex = PTHREAD_RWLOCK_INITIALIZER;


int32_t WpaRegisterEventCallback(OnReceiveFunc onRecFunc, uint32_t eventType, const char *ifName)
{
    uint32_t i;
    struct WpaCallbackEvent *callbackEvent = NULL;

    if (onRecFunc == NULL || ifName == NULL) {
        HDF_LOGE("%s: input parameter invalid, line: %d", __FUNCTION__, __LINE__);
        return -1;
    }
    pthread_rwlock_wrlock(&g_wpaCallbackMutex);
    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (g_wpaCallbackEventMap[i] != NULL  &&(strcmp(g_wpaCallbackEventMap[i]->ifName, ifName) == 0)
            && g_wpaCallbackEventMap[i]->onRecFunc == onRecFunc) {
            HDF_LOGI("%s the onRecFunc has been registered!", __FUNCTION__);
            pthread_rwlock_unlock(&g_wpaCallbackMutex);
            return 0;
        }
    }
    callbackEvent = (struct WpaCallbackEvent *)malloc(sizeof(struct WpaCallbackEvent));
    if (callbackEvent == NULL) {
        HDF_LOGE("%s fail: malloc fail!", __FUNCTION__);
        pthread_rwlock_unlock(&g_wpaCallbackMutex);
        return -1;
    }
    callbackEvent->eventType = eventType;
    if (strcpy_s(callbackEvent->ifName, IFNAMSIZ, ifName) != 0) {
        free(callbackEvent);
        HDF_LOGE("%s: ifName strcpy_s fail", __FUNCTION__);
        pthread_rwlock_unlock(&g_wpaCallbackMutex);
        return -1;
    }
    callbackEvent->onRecFunc = onRecFunc;
    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (g_wpaCallbackEventMap[i] == NULL) {
            g_wpaCallbackEventMap[i] = callbackEvent;
            HDF_LOGD("%s: WifiRegisterEventCallback successful", __FUNCTION__);
            HDF_LOGD("%s: callbackEvent->eventType =%d ", __FUNCTION__, callbackEvent->eventType);
            pthread_rwlock_unlock(&g_wpaCallbackMutex);
            return 0;
        }
    }
    pthread_rwlock_unlock(&g_wpaCallbackMutex);
    free(callbackEvent);
    HDF_LOGE("%s fail: register onRecFunc num more than %d!", __FUNCTION__, MAX_CALL_BACK_COUNT);
    return -1;
}

int32_t WpaUnregisterEventCallback(OnReceiveFunc onRecFunc, uint32_t eventType, const char *ifName)
{
    uint32_t i;

    if (onRecFunc == NULL || ifName == NULL) {
        HDF_LOGE("%s: input parameter invalid, line: %d", __FUNCTION__, __LINE__);
        return HDF_FAILURE;
    }
    pthread_rwlock_wrlock(&g_wpaCallbackMutex);
    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (g_wpaCallbackEventMap[i] != NULL && g_wpaCallbackEventMap[i]->eventType == eventType &&
            (strcmp(g_wpaCallbackEventMap[i]->ifName, ifName) == 0) &&
            g_wpaCallbackEventMap[i]->onRecFunc == onRecFunc) {
            g_wpaCallbackEventMap[i]->onRecFunc = NULL;
            free(g_wpaCallbackEventMap[i]);
            g_wpaCallbackEventMap[i] = NULL;
            pthread_rwlock_unlock(&g_wpaCallbackMutex);
            return HDF_SUCCESS;
        }
    }
    pthread_rwlock_unlock(&g_wpaCallbackMutex);
    return HDF_FAILURE;
}

void ReleaseEventCallback(void)
{
    pthread_rwlock_wrlock(&g_wpaCallbackMutex);
    for (uint32_t i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (g_wpaCallbackEventMap[i] != NULL) {
            g_wpaCallbackEventMap[i]->onRecFunc = NULL;
            free(g_wpaCallbackEventMap[i]);
            g_wpaCallbackEventMap[i] = NULL;
            break;
        }
    }
    pthread_rwlock_unlock(&g_wpaCallbackMutex);
}

void WpaEventReport(const char *ifName, uint32_t event, void *data)
{
    uint32_t i;
    OnReceiveFunc callbackEventMap[MAX_CALL_BACK_COUNT] = {NULL};

    pthread_rwlock_rdlock(&g_wpaCallbackMutex);
    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (g_wpaCallbackEventMap[i] != NULL && ((strstr(ifName, g_wpaCallbackEventMap[i]->ifName))
            || (strcmp(g_wpaCallbackEventMap[i]->ifName, ifName) == 0)) &&
            (((1 << event) & g_wpaCallbackEventMap[i]->eventType) != 0)) {
            HDF_LOGI("%s: send event = %u, ifName = %s", __FUNCTION__, event, ifName);
            callbackEventMap[i] = g_wpaCallbackEventMap[i]->onRecFunc;
        }
    }
    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (callbackEventMap[i] != NULL) {
            HDF_LOGI("%s: call event = %u, ifName = %s", __FUNCTION__, event, ifName);
            callbackEventMap[i](event, data, ifName);
        }
    }
    pthread_rwlock_unlock(&g_wpaCallbackMutex);
}
