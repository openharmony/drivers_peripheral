/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "wifi_common_cmd.h"
#include "hdf_log.h"
#include "securec.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#ifndef EOK
#define EOK 0
#endif

#define MAX_CALL_BACK_COUNT 10
static struct CallbackEvent *g_callbackEventMap[MAX_CALL_BACK_COUNT] = {NULL};
static struct Hid2dEvent *g_hid2dEventMap[MAX_CALL_BACK_COUNT] = {NULL};
static pthread_mutex_t g_callbackMutex;
static pthread_mutex_t g_hid2dEventMutex;

int32_t InitEventcallbackMutex(void)
{
    if (pthread_mutex_init(&g_callbackMutex, NULL) != RET_CODE_SUCCESS) {
        HDF_LOGE("%s: init g_callbackMutex failed.", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    if (pthread_mutex_init(&g_hid2dEventMutex, NULL) != RET_CODE_SUCCESS) {
        HDF_LOGE("%s: init g_hid2dEventMutex failed.", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    return RET_CODE_SUCCESS;
}

void DeinitEventcallbackMutex(void)
{
    pthread_mutex_destroy(&g_callbackMutex);
    pthread_mutex_destroy(&g_hid2dEventMutex);
}

void WifiEventReport(const char *ifName, uint32_t event, void *data)
{
    uint32_t i;
    OnReceiveFunc callbackEventMap[MAX_CALL_BACK_COUNT] = {NULL};

    pthread_mutex_lock(&g_callbackMutex);
    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (g_callbackEventMap[i] != NULL && (strcmp(g_callbackEventMap[i]->ifName, ifName) == 0) &&
            (((1 << event) & g_callbackEventMap[i]->eventType) != 0)) {
            HDF_LOGI("%s: send event = %u, ifName = %s", __FUNCTION__, event, ifName);
            callbackEventMap[i] = g_callbackEventMap[i]->onRecFunc;
        }
    }
    pthread_mutex_unlock(&g_callbackMutex);
    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (callbackEventMap[i] != NULL) {
            callbackEventMap[i](event, data, ifName);
        }
    }
}

int32_t WifiRegisterEventCallback(OnReceiveFunc onRecFunc, uint32_t eventType, const char *ifName)
{
    uint32_t i;
    struct CallbackEvent *callbackEvent = NULL;

    if (onRecFunc == NULL || ifName == NULL) {
        HDF_LOGE("%s: input parameter invalid, line: %d", __FUNCTION__, __LINE__);
        return RET_CODE_INVALID_PARAM;
    }
    pthread_mutex_lock(&g_callbackMutex);
    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (g_callbackEventMap[i] != NULL && g_callbackEventMap[i]->eventType == eventType &&
            (strcmp(g_callbackEventMap[i]->ifName, ifName) == 0) && g_callbackEventMap[i]->onRecFunc == onRecFunc) {
            HDF_LOGI("%s the onRecFunc has been registered!", __FUNCTION__);
            pthread_mutex_unlock(&g_callbackMutex);
            return RET_CODE_SUCCESS;
        }
    }
    pthread_mutex_unlock(&g_callbackMutex);
    callbackEvent = (struct CallbackEvent *)malloc(sizeof(struct CallbackEvent));
    if (callbackEvent == NULL) {
        HDF_LOGE("%s fail: malloc fail!", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    callbackEvent->eventType = eventType;
    if (strcpy_s(callbackEvent->ifName, IFNAMSIZ, ifName) != RET_CODE_SUCCESS) {
        free(callbackEvent);
        HDF_LOGE("%s: ifName strcpy_s fail", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    callbackEvent->onRecFunc = onRecFunc;
    pthread_mutex_lock(&g_callbackMutex);
    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (g_callbackEventMap[i] == NULL) {
            g_callbackEventMap[i] = callbackEvent;
            HDF_LOGD("%s: WifiRegisterEventCallback successful", __FUNCTION__);
            pthread_mutex_unlock(&g_callbackMutex);
            return RET_CODE_SUCCESS;
        }
    }
    pthread_mutex_unlock(&g_callbackMutex);
    free(callbackEvent);
    HDF_LOGE("%s fail: register onRecFunc num more than %d!", __FUNCTION__, MAX_CALL_BACK_COUNT);
    return RET_CODE_FAILURE;
}

void WifiUnregisterEventCallback(OnReceiveFunc onRecFunc, uint32_t eventType, const char *ifName)
{
    uint32_t i;

    if (onRecFunc == NULL || ifName == NULL) {
        HDF_LOGE("%s: input parameter invalid, line: %d", __FUNCTION__, __LINE__);
        return;
    }
    pthread_mutex_lock(&g_callbackMutex);
    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (g_callbackEventMap[i] != NULL && g_callbackEventMap[i]->eventType == eventType &&
            (strcmp(g_callbackEventMap[i]->ifName, ifName) == 0) && g_callbackEventMap[i]->onRecFunc == onRecFunc) {
            g_callbackEventMap[i]->onRecFunc = NULL;
            free(g_callbackEventMap[i]);
            g_callbackEventMap[i] = NULL;
            pthread_mutex_unlock(&g_callbackMutex);
            return;
        }
    }
    pthread_mutex_unlock(&g_callbackMutex);
}

void Hid2dEventReport(const char *ifName, const uint8_t *msg, uint32_t msgLen)
{
    uint32_t i;
    Hid2dCallback hid2dEventMap[MAX_CALL_BACK_COUNT] = {NULL};

    pthread_mutex_lock(&g_hid2dEventMutex);
    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (g_hid2dEventMap[i] != NULL && (strcmp(g_hid2dEventMap[i]->ifName, ifName) == 0)) {
            HDF_LOGI("%s: Hid2dEventReport ifName = %s", __FUNCTION__, ifName);
            hid2dEventMap[i] = g_hid2dEventMap[i]->func;
        }
    }
    pthread_mutex_unlock(&g_hid2dEventMutex);
    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (hid2dEventMap[i] != NULL) {
            hid2dEventMap[i](msg, msgLen);
        }
    }
}

int32_t WifiRegisterHid2dCallback(Hid2dCallback func, const char *ifName)
{
    struct Hid2dEvent *event = NULL;
    uint32_t i;

    if (func == NULL || ifName == NULL) {
        HDF_LOGE("%s: input parameter invalid, line: %d", __FUNCTION__, __LINE__);
        return RET_CODE_INVALID_PARAM;
    }
    pthread_mutex_lock(&g_hid2dEventMutex);
    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (g_hid2dEventMap[i] != NULL && (strcmp(g_hid2dEventMap[i]->ifName, ifName) == 0) &&
            g_hid2dEventMap[i]->func == func) {
            HDF_LOGI("%s the callback function has been registered!", __FUNCTION__);
            pthread_mutex_unlock(&g_hid2dEventMutex);
            return RET_CODE_SUCCESS;
        }
    }
    pthread_mutex_unlock(&g_hid2dEventMutex);
    event = (struct Hid2dEvent *)OsalMemCalloc(sizeof(struct Hid2dEvent));
    if (event == NULL) {
        HDF_LOGE("%s fail: OsalMemCalloc fail!", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    do {
        if (strcpy_s(event->ifName, IFNAMSIZ + 1, ifName) != RET_CODE_SUCCESS) {
            HDF_LOGE("%s: ifName strcpy_s fail", __FUNCTION__);
            break;
        }
        event->func = func;
        pthread_mutex_lock(&g_hid2dEventMutex);
        for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
            if (g_hid2dEventMap[i] == NULL) {
                g_hid2dEventMap[i] = event;
                HDF_LOGD("%s: WifiRegisterHid2dCallback successful", __FUNCTION__);
                pthread_mutex_unlock(&g_hid2dEventMutex);
                return RET_CODE_SUCCESS;
            }
        }
        pthread_mutex_unlock(&g_hid2dEventMutex);
    } while (0);

    OsalMemFree(event);
    HDF_LOGE("%s fail: register onRecFunc num more than %d!", __FUNCTION__, MAX_CALL_BACK_COUNT);
    return RET_CODE_FAILURE;
}

void WifiUnregisterHid2dCallback(Hid2dCallback func, const char *ifName)
{
    uint32_t i;

    if (func == NULL || ifName == NULL) {
        HDF_LOGE("%s: input parameter invalid, line: %d", __FUNCTION__, __LINE__);
        return;
    }
    pthread_mutex_lock(&g_hid2dEventMutex);
    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (g_hid2dEventMap[i] != NULL && (strcmp(g_hid2dEventMap[i]->ifName, ifName) == 0) &&
            g_hid2dEventMap[i]->func == func) {
            g_hid2dEventMap[i]->func = NULL;
            OsalMemFree(g_hid2dEventMap[i]);
            g_hid2dEventMap[i] = NULL;
            pthread_mutex_unlock(&g_hid2dEventMutex);
            return;
        }
    }
    pthread_mutex_unlock(&g_hid2dEventMutex);
}

void FreeScanResult(WifiScanResult *res)
{
    if (res == NULL) {
        return;
    }
    if (res->bssid != NULL) {
        OsalMemFree(res->bssid);
        res->bssid = NULL;
    }
    if (res->ie != NULL) {
        OsalMemFree(res->ie);
        res->ie = NULL;
    }
    if (res->beaconIe != NULL) {
        OsalMemFree(res->beaconIe);
        res->beaconIe = NULL;
    }
}

void FreeScanResults(WifiScanResults *res)
{
    uint32_t i;
    if (res == NULL) {
        return;
    }
    for (i = 0; i < res->num; i++) {
        FreeScanResult(&res->scanResult[i]);
    }
    OsalMemFree(res->scanResult);
    res->scanResult = NULL;
}

int32_t InitScanResults(WifiScanResults *scanResults)
{
    if (scanResults == NULL) {
        HDF_LOGE("%s: scanResults is NULL", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    scanResults->scanResultCapacity = INIT_SCAN_RES_NUM;
    scanResults->num = 0;
    scanResults->scanResult = (WifiScanResult *)OsalMemCalloc(sizeof(WifiScanResult) * scanResults->scanResultCapacity);
    if (scanResults->scanResult == NULL) {
        HDF_LOGE("%s: scanResults->scanResult is NULL", __FUNCTION__);
        return RET_CODE_NOMEM;
    }
    return RET_CODE_SUCCESS;
}
#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
