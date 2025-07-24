/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "ethernet_eap_client.h"
 
#include "v1_0/iethernet.h"
#include "v1_0/iethernet_callback.h"
 
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif
 
#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "EthernetEapClient"
#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif
#define LOG_DOMAIN 0xD0015b0
 
#define MAX_CALL_BACK_COUNT 10
static struct EthEapCallback *g_ethEapCallbackMap[MAX_CALL_BACK_COUNT] = {NULL};
static pthread_rwlock_t g_eapCallbackMutex = PTHREAD_RWLOCK_INITIALIZER;
 
int32_t EthEapClientRegisterCallback(struct IEthernetCallback* callback, const char *ifName)
{
    uint32_t i;
    int ifNameLen = 0;
    if (ifName != NULL) {
        ifNameLen = strnlen(ifName, IFNAMSIZE + 1);
    }
    if (callback == NULL || ifName == NULL || ifNameLen == (IFNAMSIZE + 1)) {
        HDF_LOGE("%s: input param invalid", __FUNCTION__);
        return HDF_FAILURE;
    }
    pthread_rwlock_wrlock(&g_eapCallbackMutex);
    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (g_ethEapCallbackMap[i] != NULL  &&(strcmp(g_ethEapCallbackMap[i]->ifName, ifName) == 0)
            && g_ethEapCallbackMap[i]->callback == callback) {
            HDF_LOGI("%s callback has been registered!", __FUNCTION__);
            pthread_rwlock_unlock(&g_eapCallbackMutex);
            return HDF_SUCCESS;
        }
    }
    struct EthEapCallback *ethEapCallback = (struct EthEapCallback *)malloc(sizeof(struct EthEapCallback));
    if (ethEapCallback == NULL) {
        HDF_LOGE("%s malloc fail", __FUNCTION__);
        pthread_rwlock_unlock(&g_eapCallbackMutex);
        return HDF_FAILURE;
    }
    if (memcpy_s(ethEapCallback->ifName, IFNAMSIZE, ifName, ifNameLen) != 0) {
        free(ethEapCallback);
        HDF_LOGE("%s ifName memcpy_s fail", __FUNCTION__);
        pthread_rwlock_unlock(&g_eapCallbackMutex);
        return HDF_FAILURE;
    }
    ethEapCallback->ifName[ifNameLen] = '\0';
    ethEapCallback->callback = callback;
    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (g_ethEapCallbackMap[i] == NULL) {
            g_ethEapCallbackMap[i] = ethEapCallback;
            HDF_LOGI("%s success", __FUNCTION__);
            pthread_rwlock_unlock(&g_eapCallbackMutex);
            return HDF_SUCCESS;
        }
    }
    pthread_rwlock_unlock(&g_eapCallbackMutex);
    free(callback);
    HDF_LOGE("%s fail", __FUNCTION__);
    return HDF_FAILURE;
}
 
int32_t EthEapClientUnregisterCallback(struct IEthernetCallback* callback, const char *ifName)
{
    uint32_t i;
    if (callback == NULL || ifName == NULL) {
        HDF_LOGE("%s: input param invalid", __FUNCTION__);
        return HDF_FAILURE;
    }
    pthread_rwlock_wrlock(&g_eapCallbackMutex);
    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (g_ethEapCallbackMap[i] != NULL && (strcmp(g_ethEapCallbackMap[i]->ifName, ifName) == 0) &&
            g_ethEapCallbackMap[i]->callback == callback) {
            g_ethEapCallbackMap[i]->callback = NULL;
            free(g_ethEapCallbackMap[i]);
            g_ethEapCallbackMap[i] = NULL;
            pthread_rwlock_unlock(&g_eapCallbackMutex);
            return HDF_SUCCESS;
        }
    }
    pthread_rwlock_unlock(&g_eapCallbackMutex);
    return HDF_FAILURE;
}
 
void EthEapClientReleaseCallback(void)
{
    pthread_rwlock_wrlock(&g_eapCallbackMutex);
    for (uint32_t i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (g_ethEapCallbackMap[i] != NULL) {
            g_ethEapCallbackMap[i]->callback = NULL;
            free(g_ethEapCallbackMap[i]);
            g_ethEapCallbackMap[i] = NULL;
            break;
        }
    }
    pthread_rwlock_unlock(&g_eapCallbackMutex);
}
 
void EthEapClientEventReport(const char *ifName, const char *data)
{
    uint32_t i;
    struct IEthernetCallback* callbackEventMap[MAX_CALL_BACK_COUNT] = { NULL };
    pthread_rwlock_rdlock(&g_eapCallbackMutex);
    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (g_ethEapCallbackMap[i] != NULL && ((strstr(ifName, g_ethEapCallbackMap[i]->ifName))
            || (strcmp(g_ethEapCallbackMap[i]->ifName, ifName) == 0))) {
            HDF_LOGI("%s: EapEventReport ifName = %s", __FUNCTION__, ifName);
            callbackEventMap[i] = g_ethEapCallbackMap[i]->callback;
        }
    }
    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (callbackEventMap[i] != NULL) {
            callbackEventMap[i]->OnEapEventNotify(callbackEventMap[i], ifName, data);
        }
    }
    pthread_rwlock_unlock(&g_eapCallbackMutex);
}
 
#ifdef __cplusplus
}
#endif
