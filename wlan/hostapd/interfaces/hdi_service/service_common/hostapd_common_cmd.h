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
#ifndef HOSTAPD_COMMON_CMD_H
#define HOSTAPD_COMMON_CMD_H

#include "../hostapd_impl.h"
#include <pthread.h>

#define BUFFSIZE_REQUEST 4096
#define CMD_SIZE 100
#define REPLY_SIZE 1024
#define MAX_WPA_MAIN_ARGC_NUM 20
#define MAX_WPA_MAIN_ARGV_LEN 128
#define WPA_HOSTAPD_NAME "hostapd"
#define WPA_SLEEP_TIME (100 * 1000) /* 100ms */
#ifdef OHOS_EUPDATER
#define CONFIG_ROOR_DIR "/tmp/service/el1/public/wifi"
#else
#define CONFIG_ROOR_DIR "/data/service/el1/public/wifi"
#endif // OHOS_EUPDATER
#define START_CMD "hostapd "CONFIG_ROOR_DIR"/wpa_supplicant/hostapd.conf"

int32_t HostapdInterfaceStartAp(struct IHostapdInterface *self);

int32_t HostapdInterfaceStopAp(struct IHostapdInterface *self);

int32_t HostapdInterfaceEnableAp(struct IHostapdInterface *self,
    const char *ifName, int32_t id);

int32_t HostapdInterfaceDisableAp(struct IHostapdInterface *self,
    const char *ifName, int32_t id);

int32_t HostapdInterfaceSetApPasswd(struct IHostapdInterface *self,
    const char *ifName, const char *pass, int32_t id);

int32_t HostapdInterfaceSetApName(struct IHostapdInterface *self,
    const char *ifName, const char *name, int32_t id);

int32_t HostapdInterfaceSetApWpaValue(struct IHostapdInterface *self,
    const char *ifName, int32_t securityType, int32_t id);

int32_t HostapdInterfaceSetApBand(struct IHostapdInterface *self,
    const char *ifName, int32_t band, int32_t id);

int32_t HostapdInterfaceSetAp80211n(struct IHostapdInterface *self,
    const char *ifName, int32_t value, int32_t id);

int32_t HostapdInterfaceSetApWmm(struct IHostapdInterface *self,
    const char *ifName, int32_t value, int32_t id);

int32_t HostapdInterfaceSetApChannel(struct IHostapdInterface *self,
    const char *ifName, int32_t channel, int32_t id);

int32_t HostapdInterfaceSetApMaxConn(struct IHostapdInterface *self,
    const char *ifName, int32_t maxConn, int32_t id);

int32_t HostapdInterfaceSetMacFilter(struct IHostapdInterface *self,
    const char *ifName, const char *mac, int32_t id);

int32_t HostapdInterfaceDelMacFilter(struct IHostapdInterface *self,
    const char *ifName, const char *mac, int32_t id);

int32_t HostapdInterfaceGetStaInfos(struct IHostapdInterface *self,
    const char *ifName, char *buf, uint32_t bufLen, int32_t size, int32_t id);

int32_t HostapdInterfaceDisassociateSta(struct IHostapdInterface *self,
    const char *ifName, const char *mac, int32_t id);

int32_t HostapdInterfaceRegisterEventCallback(struct IHostapdInterface *self,
    struct IHostapdCallback *cbFunc, const char *ifName);

int32_t HostapdInterfaceUnregisterEventCallback(struct IHostapdInterface *self,
    struct IHostapdCallback *cbFunc, const char *ifName);

void HostapdEventReport(const char *ifName, uint32_t event, void *data);

struct StApMainParam {
    int argc;
    char argv[MAX_WPA_MAIN_ARGC_NUM][MAX_WPA_MAIN_ARGV_LEN];
};

typedef enum KeyMgmt {
    /* WPA not used. */
    NONE = 0,
    /* WPA pre-share key ({@ preSharedKey} needs to be specified.) */
    WPA_PSK = 1,
    /**
     * WPA2 pre-shared key, which is used for soft APs({@ preSharedKey} needs to
     * be specified).
     */
    WPA2_PSK = 2
} KeyMgmt;

typedef enum ApBand {
    /* Unknown Band */
    AP_NONE_BAND = 0,
    /* 2.4GHz Band */
    AP_2GHZ_BAND = 1,
    /* 5GHz Band */
    AP_5GHZ_BAND = 2
} ApBand;

#endif
