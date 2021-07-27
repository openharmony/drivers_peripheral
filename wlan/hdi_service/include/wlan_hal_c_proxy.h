/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef HDI_SAMPLE_CLIENT_C_INF_H
#define HDI_SAMPLE_CLIENT_C_INF_H

#include "wifi_hal.h"
#include "wifi_hal_ap_feature.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
struct HdfSBuf;

struct WlanFeatureInfo {
    char *ifName;
    int32_t wlanType;
};

struct IWifiInterface {
    struct HdfRemoteService *remote;

    int32_t (*Construct)(struct IWifiInterface *self);
    int32_t (*Destruct)(struct IWifiInterface *self);
    int32_t (*Start)(struct IWifiInterface *self);
    int32_t (*Stop)(struct IWifiInterface *self);
    int32_t (*GetSupportFeature)(struct IWifiInterface *self, uint8_t *supType);
    int32_t (*GetSupportCombo)(struct IWifiInterface *self, uint64_t *combo);
    int32_t (*CreateFeature)(struct IWifiInterface *self, const int32_t type, struct WlanFeatureInfo **ifeature);
    int32_t (*GetFeatureByIfName)(struct IWifiInterface *self, const char *ifName, struct WlanFeatureInfo **ifeature);
    int32_t (*RegisterEventCallback)(struct IWifiInterface *self, CallbackFunc cbFunc);
    int32_t (*UnregisterEventCallback)(struct IWifiInterface *self);
    int32_t (*DestroyFeature)(struct IWifiInterface *self, struct WlanFeatureInfo *ifeature);
    int32_t (*ResetDriver)(struct IWifiInterface *self, const uint8_t chipId);
    int32_t (*GetAsscociatedStas)(struct IWifiInterface *self, const struct WlanFeatureInfo *ifeature, struct StaInfo *staInfo,
        uint32_t count, uint32_t *num);
    int32_t (*SetCountryCode)(struct IWifiInterface *self, const struct WlanFeatureInfo *ifeature, const char *code, uint32_t len);
    int32_t (*GetNetworkIfaceName)(struct IWifiInterface *self, struct WlanFeatureInfo *ifeature);
    int32_t (*GetFeatureType)(struct IWifiInterface *self, struct WlanFeatureInfo *ifeature);
    int32_t (*SetMacAddress)(struct IWifiInterface *self, const struct WlanFeatureInfo *ifeature, unsigned char *mac, uint8_t len);
    int32_t (*GetDeviceMacAddress)(struct IWifiInterface *self, const struct WlanFeatureInfo *ifeature, unsigned char *mac, uint8_t len);
    int32_t (*GetFreqsWithBand)(struct IWifiInterface *self, const struct WlanFeatureInfo *ifeature, int32_t band, int32_t *freqs,
        uint32_t count, uint32_t *num);
    int32_t (*SetTxPower)(struct IWifiInterface *self, const struct WlanFeatureInfo *ifeature, int32_t power);
    int32_t (*GetChipId)(struct IWifiInterface *self, const struct WlanFeatureInfo *ifeature, uint8_t *chipId);
    int32_t (*GetIfNamesByChipId)(struct IWifiInterface *self, const uint8_t chipId, char **ifNames, uint32_t *num);
    int32_t (*SetScanningMacAddress)(struct IWifiInterface *self, const struct WlanFeatureInfo *ifeature, unsigned char *scanMac, uint8_t len);
};

struct IWifiInterface *HdIWifiInterfaceGet(const char *serviceName);

void HdIWifiInterfaceRelease(struct IWifiInterface *instance);

int32_t CallbackWlanProxy(uint32_t event, void *data, const char *ifName);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // HDI_SAMPLE_CLIENT_C_INF_H