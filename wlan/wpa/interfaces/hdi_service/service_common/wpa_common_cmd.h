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
#include <hdf_remote_service.h>
#include "utils/common.h"
#include "wpa_supplicant_hal.h"
#include "wpa_client.h"
#include "wpa_common_cmd_ext.h"

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
/* get more than 100 p2p lists */
#define P2P_LIST_REPLY_SIZE 7168
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
#define WIFI_NETWORK_CONFIG_VALUE_LENGTH 2048
#define CMD_LEN 6

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
int32_t WpaInterfaceReassociate(struct IWpaInterface *self, const char *ifName);
int32_t WpaInterfaceStaShellCmd(struct IWpaInterface *self, const char *ifName, const char *cmd);

void HdfWpaDelRemoteObj(struct IWpaCallback *self);
void ClearHdfWpaRemoteObj(void);
int32_t FillData(uint8_t **dst, uint32_t *dstLen, uint8_t *src, uint32_t srcLen);
pthread_mutex_t *GetInterfaceLock();

struct StWpaMainParam {
    int argc;
    char argv[MAX_WPA_MAIN_ARGC_NUM][MAX_WPA_MAIN_ARGV_LEN];
};
struct RemoteServiceDeathRecipient {
    struct HdfDeathRecipient recipient;
};
#endif
