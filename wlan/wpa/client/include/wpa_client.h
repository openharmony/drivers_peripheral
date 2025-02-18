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
#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif
#define WIFI_REASON_LENGTH 32
#define WIFI_SSID_LENGTH 132

#define WIFI_P2P_DEVICE_TYPE_LENGTH 64
#define WIFI_P2P_DEVICE_NAME_LENGTH 128
#define WIFI_P2P_WFD_DEVICE_INFO_LENGTH 128
#define WIFI_P2P_PASSWORD_SIZE 128
#define WIFI_P2P_GROUP_IFNAME_LENGTH 128
#define WIFI_PIN_CODE_LENGTH 8
#define WIFI_P2P_TLVS_LENGTH 256
#define WIFI_BSSID_LEN 6
#define WPA_VENDOR_DATA_LEN 256
#define WPA_VENDOR_SSID_LEN 32
#define WPA_VENDOR_PSK_LEN 64

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
    WPA_EVENT_DEVICE_FOUND,
    WPA_EVENT_DEVICE_LOST,
    WPA_EVENT_GO_NEGOTIATION_REQUEST,
    WPA_EVENT_GO_NEGOTIATION_COMPLETED,
    WPA_EVENT_INVITATION_RECEIVED,
    WPA_EVENT_INVITATION_RESULT,
    WPA_EVENT_GROUP_FORMATION_SUCCESS,
    WPA_EVENT_GROUP_FORMATION_FAILURE,
    WPA_EVENT_GROUP_START,
    WPA_EVENT_GROUP_REMOVED,
    WPA_EVENT_PROVISION_DISCOVERY_COMPLETED,
    WPA_EVENT_FIND_STOPPED,
    WPA_EVENT_SERV_DISC_REQ,
    WPA_EVENT_SERV_DISC_RESP,
    WPA_EVENT_STA_CONNECT_STATE,
    WPA_EVENT_IFACE_CREATED,
    WPA_EVENT_STA_AUTH_REJECT,
    WPA_EVENT_STA_NOTIFY,
    WPA_EVENT_VENDOR_EXT,
    WPA_EVENT_AUTH_TIMEOUT,
    WPA_EVENT_IFACE_REMOVED,
} WpaCallBackEventType;

enum WpaClientType {
    /* 1<<0 | 1<<1 | 1<<2 | 1<<3 | 1<<4 | 1<<5 | 1<<6 | 1<<7 | 1<<8 | 1<<9 | 1<<10 ... | 1<<29 */
    WIFI_WPA_TO_HAL_CLIENT = (1 << 29) - 1,
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

struct WpaAuthRejectParam {
    unsigned char bssid[WIFI_BSSID_LEN];
    unsigned short authType;
    unsigned short authTransaction;
    unsigned short statusCode;
};

struct WpaRecvScanResultParam {
    unsigned int scanId;
};

struct P2pDeviceInfoParam {
    unsigned char srcAddress[ETH_ADDR_LEN];
    unsigned char p2pDeviceAddress[ETH_ADDR_LEN];
    unsigned char primaryDeviceType[WIFI_P2P_DEVICE_TYPE_LENGTH];
    unsigned char deviceName[WIFI_P2P_DEVICE_NAME_LENGTH];
    int configMethods;
    int deviceCapabilities;
    int groupCapabilities;
    unsigned char wfdDeviceInfo[WIFI_P2P_WFD_DEVICE_INFO_LENGTH];
    unsigned int wfdLength;
    unsigned char operSsid[WIFI_P2P_DEVICE_NAME_LENGTH];
};

struct P2pDeviceLostParam {
    unsigned char p2pDeviceAddress[ETH_ADDR_LEN];
    int  networkId;
};

struct P2pGoNegotiationRequestParam {
    unsigned char srcAddress[ETH_ADDR_LEN];
    int passwordId;
};

struct P2pGoNegotiationCompletedParam {
    int status;
};

struct P2pInvitationReceivedParam {
    int type; /* 0:Received, 1:Accepted */
    int persistentNetworkId;
    int operatingFrequency;
    unsigned char srcAddress[ETH_ADDR_LEN];
    unsigned char goDeviceAddress[ETH_ADDR_LEN];
    unsigned char bssid[ETH_ADDR_LEN];
};

struct P2pInvitationResultParam {
    int status;
    unsigned char bssid[ETH_ADDR_LEN];
};

struct P2pGroupStartedParam {
    int isGo;
    int isPersistent;
    int frequency;
    unsigned char groupIfName[WIFI_P2P_GROUP_IFNAME_LENGTH];
    unsigned char ssid[WIFI_SSID_LENGTH];
    unsigned char psk[WIFI_P2P_PASSWORD_SIZE];
    unsigned char passphrase[WIFI_P2P_PASSWORD_SIZE];
    unsigned char goDeviceAddress[ETH_ADDR_LEN];
    unsigned char goRandomDeviceAddress[ETH_ADDR_LEN];
};

struct P2pGroupRemovedParam {
    int isGo;
    unsigned char groupIfName[WIFI_P2P_GROUP_IFNAME_LENGTH];
};

struct P2pProvisionDiscoveryCompletedParam {
    int isRequest;
    int provDiscStatusCode;
    int configMethods;
    unsigned char p2pDeviceAddress[ETH_ADDR_LEN];
    unsigned char generatedPin[WIFI_PIN_CODE_LENGTH];
};

struct P2pServDiscRespParam {
    int updateIndicator;
    unsigned char srcAddress[ETH_ADDR_LEN];
    unsigned char tlvs[WIFI_P2P_TLVS_LENGTH];
};

struct P2pStaConnectStateParam {
    int state;
    unsigned char srcAddress[ETH_ADDR_LEN];
    unsigned char p2pDeviceAddress[ETH_ADDR_LEN];
};

struct P2pServDiscReqInfoParam {
    int freq;
    int dialogToken;
    int updateIndic;
    unsigned char mac[ETH_ADDR_LEN];
    unsigned char tlvs[WIFI_P2P_TLVS_LENGTH];
};

struct P2pIfaceCreatedParam {
    int isGo;
};

typedef int32_t (*OnReceiveFunc)(uint32_t event, void *data, const char *ifName);

struct WpaCallbackEvent {
    uint32_t eventType; /* eventmap */
    char ifName[IFNAMSIZ + 1];
    OnReceiveFunc onRecFunc;
};

struct WpaVendorExtInfo {
    int type;
    int freq;
    int width;
    int id;
    int status;
    int reason;
    unsigned char ssid[WPA_VENDOR_SSID_LEN];
    unsigned char psk[WPA_VENDOR_PSK_LEN];
    unsigned char devAddr[ETH_ADDR_LEN];
    unsigned char data[WPA_VENDOR_DATA_LEN];
};

void WpaEventReport(const char *ifName, uint32_t event, void *data);
int32_t WpaRegisterEventCallback(OnReceiveFunc onRecFunc, uint32_t eventType, const char *ifName);
int32_t WpaUnregisterEventCallback(OnReceiveFunc onRecFunc, uint32_t eventType, const char *ifName);
void ReleaseEventCallback(void);
#endif
