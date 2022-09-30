/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

void WifiEventReport(const char *ifName, uint32_t event, void *data)
{
    uint32_t i;

    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (g_callbackEventMap[i] != NULL && (strcmp(g_callbackEventMap[i]->ifName, ifName) == 0) &&
            (((1 << event) & g_callbackEventMap[i]->eventType) != 0)) {
            HDF_LOGI("%s: WifiEventReport send event = %u, ifName = %s",
                __FUNCTION__, event, ifName);
            g_callbackEventMap[i]->onRecFunc(event, data, ifName);
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
    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (g_callbackEventMap[i] != NULL && g_callbackEventMap[i]->eventType == eventType &&
            (strcmp(g_callbackEventMap[i]->ifName, ifName) == 0) && g_callbackEventMap[i]->onRecFunc == onRecFunc) {
            HDF_LOGI("%s the onRecFunc has been registered!", __FUNCTION__);
            return RET_CODE_SUCCESS;
        }
    }
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
    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (g_callbackEventMap[i] == NULL) {
            g_callbackEventMap[i] = callbackEvent;
            HDF_LOGD("%s: WifiRegisterEventCallback successful", __FUNCTION__);
            return RET_CODE_SUCCESS;
        }
    }
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
    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (g_callbackEventMap[i] != NULL && g_callbackEventMap[i]->eventType == eventType &&
            (strcmp(g_callbackEventMap[i]->ifName, ifName) == 0) && g_callbackEventMap[i]->onRecFunc == onRecFunc) {
            g_callbackEventMap[i]->onRecFunc = NULL;
            free(g_callbackEventMap[i]);
            g_callbackEventMap[i] = NULL;
            return;
        }
    }
}

void Hid2dEventReport(const char *ifName, const uint8_t *msg, uint32_t msgLen)
{
    uint32_t i;

    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (g_hid2dEventMap[i] != NULL && (strcmp(g_hid2dEventMap[i]->ifName, ifName) == 0)) {
            HDF_LOGI("%s: Hid2dEventReport ifName = %s", __FUNCTION__, ifName);
            g_hid2dEventMap[i]->func(msg, msgLen);
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
    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (g_hid2dEventMap[i] != NULL && (strcmp(g_hid2dEventMap[i]->ifName, ifName) == 0) &&
            g_hid2dEventMap[i]->func == func) {
            HDF_LOGI("%s the callback function has been registered!", __FUNCTION__);
            return RET_CODE_SUCCESS;
        }
    }
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
        for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
            if (g_hid2dEventMap[i] == NULL) {
                g_hid2dEventMap[i] = event;
                HDF_LOGD("%s: WifiRegisterHid2dCallback successful", __FUNCTION__);
                return RET_CODE_SUCCESS;
            }
        }
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
    for (i = 0; i < MAX_CALL_BACK_COUNT; i++) {
        if (g_hid2dEventMap[i] != NULL && (strcmp(g_hid2dEventMap[i]->ifName, ifName) == 0) &&
            g_hid2dEventMap[i]->func == func) {
            g_hid2dEventMap[i]->func = NULL;
            OsalMemFree(g_hid2dEventMap[i]);
            g_hid2dEventMap[i] = NULL;
            return;
        }
    }
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
