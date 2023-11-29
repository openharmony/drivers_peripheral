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

#ifndef WPA_CLIENT_H
#define WPA_CLIENT_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define ETH_ADDR_LEN 6
#define IFNAMSIZ 16
#define WIFI_REASON_LENGTH 32
#define WIFI_SSID_LENGTH 132
#define WIFI_BSSID_LEN 6

typedef enum {
    WPA_EVENT_DISCONNECT = 0,
    WPA_EVENT_CONNECT,
    WPA_EVENT_BSSID_CHANGE,
    WPA_EVENT_STATE_CHANGED,
    WPA_EVENT_TEMP_DISABLE,
    WPA_EVENT_ASSOCIATE_REJECT,
    WPA_EVENT_WPS_OVERLAP,
    WPA_EVENT_WPS_TIMEMOUT,
    WPA_EVENT_RECV_SCAN_RESULT,
} WpaCallBackEventType;

enum WpaClientType {
    /* 1<<0 | 1<<1 | 1<<2 | 1<<3 | 1<<4 | 1<<5 | 1<<6 | 1<<7 | 1<<8 | 1<<9 | 1<<10 */
    WIFI_WPA_TO_HAL_CLIENT = 1023,
    WIFI_WPA_CLIENT_BUTT
};

struct WpaDisconnectParam {
    unsigned char bssid[WIFI_BSSID_LEN];
    int  reasonCode;
    int locallyGenerated;
};

struct WpaConnectParam {
    unsigned char bssid[WIFI_BSSID_LEN];
    int  networkId;
};

struct WpaBssidChangedParam {
    unsigned char bssid[WIFI_BSSID_LEN];
    unsigned char reason[WIFI_REASON_LENGTH];
};

struct WpaStateChangedParam {
    int status;
    unsigned char bssid[WIFI_BSSID_LEN];
    int  networkId;
    unsigned char ssid[WIFI_SSID_LENGTH];
};

struct WpaTempDisabledParam {
    int  networkId;
    unsigned char ssid[WIFI_SSID_LENGTH];
    int authFailures;
    int duration;
    unsigned char reason[WIFI_REASON_LENGTH];
};

struct WpaAssociateRejectParam {
    unsigned char bssid[WIFI_BSSID_LEN];
    int statusCode;
    int timeOut;
};

struct WpaRecvScanResultParam {
    unsigned int scanId;
};

typedef int32_t (*OnReceiveFunc)(uint32_t event, void *data, const char *ifName);

struct WpaCallbackEvent {
    uint32_t eventType; /* eventmap */
    char ifName[IFNAMSIZ + 1];
    OnReceiveFunc onRecFunc;
};

void WpaEventReport(const char *ifName, uint32_t event, void *data);
int32_t WpaRegisterEventCallback(OnReceiveFunc onRecFunc, uint32_t eventType, const char *ifName);
int32_t WpaUnregisterEventCallback(OnReceiveFunc onRecFunc, uint32_t eventType, const char *ifName);

#endif
