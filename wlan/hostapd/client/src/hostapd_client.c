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
#include "hostapd_client.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#ifndef EOK
#define EOK 0
#endif

#define MAX_CALL_BACK_COUNT 10
static struct HostapdCallbackEvent *g_hostapdCallbackEventMap[MAX_CALL_BACK_COUNT] = {NULL};
static pthread_mutex_t g_hostapdCallbackMutex = PTHREAD_MUTEX_INITIALIZER;

int32_t HostapdRegisterEventCallback(OnReceiveFunc onRecFunc, uint32_t eventType, const char *ifName)
{
    uint32_t i;
    struct HostapdCallbackEvent *callbackEvent = NULL;
    int ifNameLen = 0;

    if (ifName != NULL) {
        ifNameLen = (int)strnlen(ifName, IFNAMSIZ + 1);
    }
    if (onRecFunc == NULL || ifName == NULL || ifNameLen == (IFNAMSIZ + 1)) {
        HDF_LOGE("%s: input parameter invalid, line: %d", __FUNCTION__, __LINE__);
        return -1;
    }
    pthread_mutex_lock(&g_hostapdCallbackMutex);
    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (g_hostapdCallbackEventMap[i] != NULL  && (strcmp(g_hostapdCallbackEventMap[i]->ifName, ifName) == 0)
            && g_hostapdCallbackEventMap[i]->onRecFunc == onRecFunc) {
            HDF_LOGI("%s the onRecFunc has been registered!", __FUNCTION__);
            pthread_mutex_unlock(&g_hostapdCallbackMutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&g_hostapdCallbackMutex);
    callbackEvent = (struct HostapdCallbackEvent *)malloc(sizeof(struct HostapdCallbackEvent));
    if (callbackEvent == NULL) {
        HDF_LOGE("%s fail: malloc fail!", __FUNCTION__);
        return -1;
    }
    callbackEvent->eventType = eventType;
    if (memcpy_s(callbackEvent->ifName, IFNAMSIZ, ifName, ifNameLen) != 0) {
        free(callbackEvent);
        HDF_LOGE("%s: ifName memcpy_s fail", __FUNCTION__);
        return -1;
    }
    callbackEvent->ifName[ifNameLen] = '\0';
    callbackEvent->onRecFunc = onRecFunc;
    pthread_mutex_lock(&g_hostapdCallbackMutex);
    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (g_hostapdCallbackEventMap[i] == NULL) {
            g_hostapdCallbackEventMap[i] = callbackEvent;
            HDF_LOGD("%s: WifiRegisterEventCallback successful", __FUNCTION__);
            HDF_LOGD("%s: callbackEvent->eventType =%d ", __FUNCTION__, callbackEvent->eventType);
            pthread_mutex_unlock(&g_hostapdCallbackMutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&g_hostapdCallbackMutex);
    free(callbackEvent);
    HDF_LOGE("%s fail: register onRecFunc num more than %d!", __FUNCTION__, MAX_CALL_BACK_COUNT);
    return -1;
}

int32_t HostapdUnregisterEventCallback(OnReceiveFunc onRecFunc, uint32_t eventType, const char *ifName)
{
    uint32_t i;

    if (onRecFunc == NULL || ifName == NULL) {
        HDF_LOGE("%s: input parameter invalid, line: %d", __FUNCTION__, __LINE__);
        return HDF_FAILURE;
    }
    pthread_mutex_lock(&g_hostapdCallbackMutex);
    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (g_hostapdCallbackEventMap[i] != NULL && g_hostapdCallbackEventMap[i]->eventType == eventType &&
            (strcmp(g_hostapdCallbackEventMap[i]->ifName, ifName) == 0) &&
            g_hostapdCallbackEventMap[i]->onRecFunc == onRecFunc) {
            g_hostapdCallbackEventMap[i]->onRecFunc = NULL;
            free(g_hostapdCallbackEventMap[i]);
            g_hostapdCallbackEventMap[i] = NULL;
            pthread_mutex_unlock(&g_hostapdCallbackMutex);
            return HDF_SUCCESS;
        }
    }
    pthread_mutex_unlock(&g_hostapdCallbackMutex);
    return HDF_FAILURE;
}

void HostapdEventReport(const char *ifName, uint32_t event, void *data)
{
    uint32_t i;

    OnReceiveFunc callbackEventMap[MAX_CALL_BACK_COUNT] = {NULL};
    pthread_mutex_lock(&g_hostapdCallbackMutex);
    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (g_hostapdCallbackEventMap[i] != NULL && (strcmp(g_hostapdCallbackEventMap[i]->ifName, ifName) == 0) &&
            (((1 << event) & g_hostapdCallbackEventMap[i]->eventType) != 0)) {
            HDF_LOGI("%s: send event = %u, ifName = %s", __FUNCTION__, event, ifName);
            callbackEventMap[i] = g_hostapdCallbackEventMap[i]->onRecFunc;
        }
    }
    pthread_mutex_unlock(&g_hostapdCallbackMutex);
    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (callbackEventMap[i] != NULL) {
            HDF_LOGI("%s: call event = %u, ifName = %s", __FUNCTION__, event, ifName);
            callbackEventMap[i](event, data, ifName);
        }
    }
}
