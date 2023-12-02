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
#ifndef WPA_COMMON_CMD_H
#define WPA_COMMON_CMD_H

#include "../wpa_impl.h"
#include <pthread.h>

#define WIFI_SSID_LENGTH 132
#define WIFI_BSSID_LENGTH 18
#define KEY_MGMT_LENG 20
#define WIFI_NETWORK_FLAGS_LENGTH 64
#define WIFI_COUNTRY_CODE_MAXLEN 2
#define COLUMN_INDEX_ZERO 0
#define COLUMN_INDEX_ONE 1
#define COLUMN_INDEX_TWO 2
#define COUNTRY_CODE_LENGTH_MAX 2
#define CMD_SIZE 100
#define REPLY_SIZE 1024
#define HDI_POS_TEN 10
#define HDI_POS_FOURTH 4
#define REPLY_SIZE_FACTOR_FIRST 4
#define REPLY_SIZE_FACTOR_SECOND 10
#define WPA_CMD_BUF_LEN 256
#define WPA_SUPPLICANT_NAME "wpa_supplicant"
#ifdef OHOS_EUPDATER
#define CONFIG_ROOR_DIR "/tmp/service/el1/public/wifi"
#else
#define CONFIG_ROOR_DIR "/data/service/el1/public/wifi"
#endif // OHOS_EUPDATER
#define START_CMD "wpa_supplicant -c"CONFIG_ROOR_DIR"/wpa_supplicant/wpa_supplicant.conf"\
    " -g@abstract:"CONFIG_ROOR_DIR"/sockets/wpa/wlan0"
#define WPA_SLEEP_TIME (100 * 1000) /* 100ms */
#define MAX_WPA_MAIN_ARGC_NUM 20
#define MAX_WPA_MAIN_ARGV_LEN 128
#define WIFI_NETWORK_CONFIG_NAME_LENGTH 64
#define WIFI_NETWORK_CONFIG_VALUE_LENGTH 256
#define CMD_LEN 6

int32_t WpaInterfaceStart(struct IWpaInterface *self);
int32_t WpaInterfaceStop(struct IWpaInterface *self);
int32_t WpaInterfaceAddWpaIface(struct IWpaInterface *self, const char *ifName, const char *confName) ;
int32_t WpaInterfaceRemoveWpaIface(struct IWpaInterface *self, const char *ifName);
int32_t WpaInterfaceScan(struct IWpaInterface *self, const char *ifName);
int32_t WpaInterfaceScanResult(struct IWpaInterface *self, const char *ifName, unsigned char *resultBuf,
    uint32_t *resultBufLen);
int32_t WpaInterfaceAddNetwork(struct IWpaInterface *self, const char *ifName, int32_t *networkId);
int32_t WpaInterfaceRemoveNetwork(struct IWpaInterface *self, const char *ifName, int32_t networkId);
int32_t WpaInterfaceDisableNetwork(struct IWpaInterface *self, const char *ifName, const int32_t networkId);
int32_t WpaInterfaceSetNetwork(struct IWpaInterface *self, const char *ifName, const int32_t networkId,
    const char *name, const char *value);
int32_t WpaInterfaceListNetworks(struct IWpaInterface *self, const char *ifName,
    struct HdiWifiWpaNetworkInfo *networkInfo, uint32_t *networkInfoLen);
int32_t WpaInterfaceSelectNetwork(struct IWpaInterface *self, const char *ifName,
    const int32_t networkId);
int32_t WpaInterfaceEnableNetwork(struct IWpaInterface *self, const char *ifName,
    const int32_t networkId);
int32_t WpaInterfaceReconnect(struct IWpaInterface *self, const char *ifName);
int32_t WpaInterfaceDisconnect(struct IWpaInterface *self, const char *ifName);
int32_t WpaInterfaceSetPowerSave(struct IWpaInterface *self, const char *ifName, const int32_t enable);
int32_t  WpaInterfaceAutoConnect(struct IWpaInterface *self, const char *ifName, const int32_t enable);
int32_t WpaInterfaceWifiStatus(struct IWpaInterface *self, const char *ifName,
    struct HdiWpaCmdStatus *status);
int32_t WpaInterfaceSaveConfig(struct IWpaInterface *self, const char *ifName);
int32_t WpaInterfaceWpsPbcMode(struct IWpaInterface *self, const char *ifName,
    const struct HdiWifiWpsParam *wpaParam);
int32_t WpaInterfaceWpsPinMode(struct IWpaInterface *self, const char *ifName,
    const struct HdiWifiWpsParam *wpaParam, int *pinCode);
int32_t WpaInterfaceWpsCancel(struct IWpaInterface *self, const char *ifName);
int32_t WpaInterfaceGetCountryCode(struct IWpaInterface *self, const char *ifName,
    char *countryCode, uint32_t countryCodeLen);
int32_t WpaInterfaceGetNetwork(struct IWpaInterface *self, const char *ifName,
    const int32_t networkId, const char *param, char *value, uint32_t valueLen);
int32_t WpaInterfaceBlocklistClear(struct IWpaInterface *self, const char *ifName);
int32_t WpaInterfaceSetSuspendMode(struct IWpaInterface *self, const char *ifName, const int32_t mode);
int32_t WpaInterfaceRegisterEventCallback(struct IWpaInterface *self, struct IWpaCallback *cbFunc,
    const char *ifName);
int32_t WpaInterfaceUnregisterEventCallback(struct IWpaInterface *self, struct IWpaCallback *cbFunc,
    const char *ifName);
int32_t WpaInterfaceWifiConstruct(void);
int32_t WpaInterfaceWifiDestruct(void);
void WpaEventReport(const char *ifName, uint32_t event, void *data);
int32_t WpaInterfaceGetConnectionCapabilities(struct IWpaInterface *self, const char *ifName,
    struct ConnectionCapabilities *connectionCap);
int32_t WpaInterfaceGetScanSsid(struct IWpaInterface *self, const char *ifName, int32_t *enable);
int32_t WpaInterfaceGetPskPassphrase(struct IWpaInterface *self, const char *ifName, char *psk, uint32_t pskLen);
int32_t WpaInterfaceGetPsk(struct IWpaInterface *self, const char *ifName, uint8_t *psk, uint32_t *pskLen);
int32_t WpaInterfaceGetWepKey(struct IWpaInterface *self, const char *ifName, int keyIdx, uint8_t *wepKey,
    uint32_t *wepKeyLen);
int32_t WpaInterfaceGetWepTxKeyIdx(struct IWpaInterface *self, const char *ifName, int *keyIdx);
int32_t WpaInterfaceGetRequirePmf(struct IWpaInterface *self, const char *ifName, int *enable);
int32_t WpaInterfaceSetCountryCode(struct IWpaInterface *self, const char *ifName, const char *countryCode);

struct StWpaMainParam {
    int argc;
    char argv[MAX_WPA_MAIN_ARGC_NUM][MAX_WPA_MAIN_ARGV_LEN];
};

typedef struct WifiNetworkInfo {
    int id;
    char ssid[WIFI_SSID_LENGTH];
    char bssid[WIFI_BSSID_LENGTH];
    char flags[WIFI_NETWORK_FLAGS_LENGTH];
} WifiNetworkInfo;

typedef enum DeviceConfigType {
    DEVICE_CONFIG_SSID = 0, /* Network Name. */
    DEVICE_CONFIG_PSK = 1,  /* Password. */
    /**
     * Encryption Mode: WPA-PSK - wpa/wp2; NONE - password less network; WPA-EAP, SAE, wpa3.
     */
    DEVICE_CONFIG_KEYMGMT = 2,
    DEVICE_CONFIG_PRIORITY = 3, /* WPA network priority */
    /**
     * Set this bit to 1 and deliver it when the hidden network is connected.
     * In other cases, set this bit to 0 but do not deliver it.
     */
    DEVICE_CONFIG_SCAN_SSID = 4,
    DEVICE_CONFIG_EAP = 5,             /* EPA Mode:/EAP/PEAP. */
    DEVICE_CONFIG_IDENTITY = 6,        /* Account name. */
    DEVICE_CONFIG_PASSWORD = 7,        /* Account password. */
    DEVICE_CONFIG_BSSID = 8,           /* bssid. */
    DEVICE_CONFIG_AUTH_ALGORITHMS = 9, /* auth algorithms */
    DEVICE_CONFIG_WEP_KEY_IDX = 10,    /* wep key idx */
    DEVICE_CONFIG_WEP_KEY_0 = 11,
    DEVICE_CONFIG_WEP_KEY_1 = 12,
    DEVICE_CONFIG_WEP_KEY_2 = 13,
    DEVICE_CONFIG_WEP_KEY_3 = 14,
    DEVICE_CONFIG_EAP_CLIENT_CERT = 15,
    DEVICE_CONFIG_EAP_PRIVATE_KEY = 16,
    DEVICE_CONFIG_EAP_PHASE2METHOD = 17,
    DEVICE_CONFIG_IEEE80211W = 18,
    DEVICE_CONFIG_ALLOW_PROTOCOLS = 19,
    DEVICE_CONFIG_GROUP_CIPHERS = 20,
    DEVICE_CONFIG_PAIRWISE_CIPHERS = 21,
    DEVICE_CONFIG_SAE_PASSWD = 22,
    /**
     * Number of network configuration parameters, which is used as the last
     * parameter.
     */
    DEVICE_CONFIG_END_POS,
} DeviceConfigType;

typedef struct WpaSsidField {
    DeviceConfigType field;
    char fieldName[32];
    int flag; /* 0 need add "" 1 no need */
} WpaSsidField;

#endif
