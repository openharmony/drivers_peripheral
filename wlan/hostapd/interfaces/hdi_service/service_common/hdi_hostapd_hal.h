/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#ifndef HDI_HOSTAPD_HAL_H
#define HDI_HOSTAPD_HAL_H

#include <dirent.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BUFSIZE_CMD 256
#define FILE_NAME_SIZE 256
#define BUFSIZE_REQUEST 4096
#define BUFSIZE_REQUEST_SMALL 64
#define BUFSIZE_RECV 4096
#define PASSWD_MIN_LEN 8
#define FAIL_LENGTH 4
#define UNKNOWN_COMMAND_LENGTH 15
#define REQUEST_FAILED (-2)
#define BUFFER_SIZE_128 128
#define BUFFER_SIZE_64 64
#define BUFFER_SIZE_32 32
#define BUFFER_SIZE_16 16
#define AP_NUM 1

#if (AP_NUM > 1)
typedef enum EnApInstance {
    AP_5G_MAIN_INSTANCE,
    AP_2G_MAIN_INSTANCE,
    AP_MAX_INSTANCE
} ApInstance;
#else
typedef enum EnApInstance {
    AP_2G_MAIN_INSTANCE,
    AP_MAX_INSTANCE
} ApInstance;
#endif

typedef struct StStatusInfo {
    char state[BUFFER_SIZE_16];
    char phy[BUFFER_SIZE_16];
    int freq;
    int channel;
    char supportedRates[BUFFER_SIZE_64];
    char bss[BUFFER_SIZE_16];
    char bssid[BUFFER_SIZE_32];
    char ssid[BUFFER_SIZE_32];
} StatusInfo;

/* AP Band */
typedef enum ApBand {
    AP_NONE_BAND = 0, /* Unknown Band */
    AP_2GHZ_BAND = 1, /* 2.4GHz Band */
    AP_5GHZ_BAND = 2, /* 5GHz Band */
    AP_ANY_BAND = 3,  /* Dual-mode frequency band */
    AP_DFS_BAND = 4   /* Dynamic Frequency Selection band */
} ApBand;

/*  Encryption Mode */
typedef enum KeyMgmt {
    NONE = 0,    /* WPA not used. */
    WPA_PSK = 1, /* WPA pre-shared key ({@ preSharedKey} needs to be specified.) */
    /**
     * WPA with EAP authentication. It is usually used with an external
     * authentication server.
     */
    WPA_EAP = 2,
    /**
     * IEEE 802.1X with EAP authentication and optionally dynamically generated
     * WEP keys.
     */
    IEEE8021X = 3,
    /**
     * WPA2 pre-shared key, which is used for soft APs({@ preSharedKey} needs to
     * be specified).
     */
    WPA2_PSK = 4,
    OSEN = 5,   /* Hotspot 2.0 Rel 2 online signup connection. */
    FT_PSK = 6, /* Fast BSS Transition (IEEE 802.11r) with pre-shared key. */
    FT_EAP = 7  /*  Fast BSS Transition (IEEE 802.11r) with EAP authentication. */
} KeyMgmt;

/* Defines the HAL device structure. */
typedef struct StWifiHostapdHalDevice {
    struct wpa_ctrl *ctrlConn;
    struct wpa_ctrl *ctrlRecv;
    int execDisable;
    int (*stopAp)(int id);
    int (*enableAp)(int id);
    int (*disableAp)(int id);
    int (*addBlocklist)(const char *mac, int id);
    int (*delBlocklist)(const char *mac, int id);
    int (*status)(StatusInfo *info, int id);
    int (*showConnectedDevList)(char *info, int size, int id);
    int (*reloadApConfigInfo)(int id);
    int (*disConnectedDev)(const char *mac, int id);
    int (*setCountryCode)(const char *code, int id);
    int (*setApName)(const char *name, int id);
    int (*setApRsnPairwise)(const char *type, int id);
    int (*setApWpaPairwise)(const char *type, int id);
    int (*setApWpaKeyMgmt)(const char *type, int id);
    int (*setApWpaValue)(int securityType, int id);
    int (*setApPasswd)(const char *pass, int id);
    int (*setApChannel)(int channel, int id);
    int (*setApWmm)(int value, int id);
    int (*setAp80211n)(int value, int id);
    int (*setApBand)(int band, int id);
    int (*setApMaxConnHw)(int maxConn, int channel);
    int (*setApMaxConn)(int maxConn, int id);
} WifiHostapdHalDevice;

typedef struct StWifiHostapdHalDeviceInfo {
    int id;
    WifiHostapdHalDevice *hostapdHalDev;
    char *cfgName;
    char *config;
    char *udpPort;
} WifiHostapdHalDeviceInfo;

const WifiHostapdHalDeviceInfo *GetWifiCfg(int *len);
WifiHostapdHalDevice *GetWifiHostapdDev(int id);
void ReleaseHostapdDev(int id);
void GetDestPort(char *destPort, size_t len, int id);
int InitCfg(const char *ifaceName);
int GetIfaceState(const char *ifaceName);
#ifdef __cplusplus
}
#endif
#endif /* HDI_HOSTAPD_HAL_H */
