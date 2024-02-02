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
 
#ifndef HOSTAPD_CLIENT_H
#define HOSTAPD_CLIENT_H
 
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif

#define IFNAMSIZ 16
#define WIFI_HOSTAPD_CB_CONTENT_LENGTH 1024

typedef enum {
    HOSTAPD_EVENT_STA_JOIN = 0,
    HOSTAPD_EVENT_AP_STATE,
    HOSTAPD_EVENT_HOSTAPD_NOTIFY
} HostapdCallBackEventType;

enum HostapdClientType {
    /* 1<<0 | 1<<1 | 1<<2 | 1<<3 | 1<<4 | 1<<5 | 1<<6 | 1<<7 | 1<<8 | 1<<9 | 1<<10 */
    WIFI_HOSTAPD_TO_HAL_CLIENT = 33554431,
    WIFI_HOSTAPD_CLIENT_BUTT
};

typedef int32_t (*OnReceiveFunc)(uint32_t event, void *data, const char *ifName);

struct HostapdApCbParm {
    unsigned char content[WIFI_HOSTAPD_CB_CONTENT_LENGTH];
    int id;
};
 
struct HostapdCallbackEvent {
    uint32_t eventType; /* eventmap */
    char ifName[IFNAMSIZ + 1];
    OnReceiveFunc onRecFunc;
};

void HostapdEventReport(const char *ifName, uint32_t event, void *data);
int32_t HostapdRegisterEventCallback(OnReceiveFunc onRecFunc, uint32_t eventType, const char *ifName);
int32_t  HostapdUnregisterEventCallback(OnReceiveFunc onRecFunc,  uint32_t eventType, const char *ifName);

#endif
