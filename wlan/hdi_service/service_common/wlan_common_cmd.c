/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "wlan_common_cmd.h"
#include <securec.h>
#include <hdf_base.h>
#include <hdf_log.h>
#include <osal_time.h>
#include <osal_mem.h>
#include "wlan_extend_cmd.h"
#include "v1_3/iwlan_callback.h"
#include "v1_3/iwlan_interface.h"

struct IWiFi *g_wifi = NULL;
struct IWiFiAp *g_apFeature = NULL;
struct IWiFiSta *g_staFeature = NULL;
struct IWiFiP2p *g_p2pFeature = NULL;
struct IWiFiBaseFeature *g_baseFeature = NULL;
static uint32_t g_wifiCount = 0;
static uint32_t g_apFeatureCount = 0;
static uint32_t g_staFeatureCount = 0;
static uint32_t g_p2pFeatureCount = 0;
const uint32_t RESET_TIME = 3;
#define DEFAULT_COMBO_SIZE 10
#define WLAN_FREQ_MAX_NUM 14
#define WLAN_MAX_NUM_STA_WITH_AP 4
#define ETH_ADDR_LEN 6

struct HdfWlanStubData *HdfStubDriver(void)
{
    static struct HdfWlanStubData registerManager;
    return &registerManager;
}

int32_t WlanInterfaceStart(struct IWlanInterface *self)
{
    int32_t ret;
    HDF_LOGI("hal enter %{public}s", __FUNCTION__);
    (void)self;
    if (g_wifi == NULL || g_wifi->start == NULL) {
        HDF_LOGE("%{public}s: g_wifi or g_wifi->start is NULL", __func__);
        return HDF_FAILURE;
    }
    ret = g_wifi->start(g_wifi);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s start WiFi failed! error code: %{public}d", __func__, ret);
    } else {
        g_wifiCount++;
    }
    HDF_LOGI("hal exit %{public}s, g_wifiCount:%{public}u", __FUNCTION__, g_wifiCount);
    return ret;
}

int32_t WlanInterfaceStop(struct IWlanInterface *self)
{
    int32_t ret;
    HDF_LOGI("hal enter %{public}s", __FUNCTION__);
    (void)self;
    if (g_wifi == NULL || g_wifi->stop == NULL) {
        HDF_LOGE("%{public}s: g_wifi or g_wifi->stop is NULL", __func__);
        return HDF_FAILURE;
    }
    g_wifiCount--;
    if (g_wifiCount > 0) {
        HDF_LOGE("%{public}s: g_wifi is used!", __func__);
        return HDF_SUCCESS;
    }
    ret = g_wifi->stop(g_wifi);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s stop WiFi failed! error code: %{public}d", __func__, ret);
    }
    HDF_LOGI("hal exit %{public}s, g_wifiCount:%{public}u", __FUNCTION__, g_wifiCount);
    return ret;
}

int32_t WlanInterfaceCreateFeature(struct IWlanInterface *self, int32_t type, struct HdfFeatureInfo *ifeature)
{
    int32_t ret = HDF_FAILURE;
    HDF_LOGI("hal enter %{public}s type:%{public}d", __FUNCTION__, type);
    (void)self;
    if (ifeature == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_wifi == NULL || g_wifi->createFeature == NULL) {
        HDF_LOGE("%{public}s: g_wifi or g_wifi->createFeature is NULL", __func__);
        return HDF_FAILURE;
    }
    if (type == PROTOCOL_80211_IFTYPE_AP) {
        ret = g_wifi->createFeature(type, (struct IWiFiBaseFeature **)&g_apFeature);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: createAPFeature failed, error code: %{public}d", __func__, ret);
            return HDF_FAILURE;
        }
        if (g_apFeature != NULL) {
            g_apFeatureCount++;
            ifeature->type = g_apFeature->baseFeature.type;
            ifeature->ifName = strdup((g_apFeature->baseFeature).ifName);
        }
    } else if (type == PROTOCOL_80211_IFTYPE_STATION) {
        ret = g_wifi->createFeature(type, (struct IWiFiBaseFeature **)&g_staFeature);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: createSTAFeature failed, error code: %{public}d", __func__, ret);
            return HDF_FAILURE;
        }
        if (g_staFeature != NULL) {
            g_staFeatureCount++;
            ifeature->type = g_staFeature->baseFeature.type;
            ifeature->ifName = strdup((g_staFeature->baseFeature).ifName);
        }
    } else if (type == PROTOCOL_80211_IFTYPE_P2P_DEVICE) {
        ret = g_wifi->createFeature(type, (struct IWiFiBaseFeature **)&g_p2pFeature);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: failed to create p2p feature, errorCode: %{public}d", __func__, ret);
            return HDF_FAILURE;
        }
        if (g_p2pFeature != NULL) {
            g_p2pFeatureCount++;
            ifeature->type = g_p2pFeature->baseFeature.type;
            ifeature->ifName = strdup((g_p2pFeature->baseFeature).ifName);
        }
    }
    if (ifeature->ifName == NULL) {
        return HDF_FAILURE;
    }
    HDF_LOGI("ap:%{public}u sta:%{public}u p2p:%{public}u", g_apFeatureCount, g_staFeatureCount, g_p2pFeatureCount);
    return ret;
}

int32_t WlanInterfaceDestroyFeature(struct IWlanInterface *self, const struct HdfFeatureInfo *ifeature)
{
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (ifeature == NULL || ifeature->ifName == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_wifi == NULL || g_wifi->destroyFeature == NULL) {
        HDF_LOGE("%{public}s: g_wifi or g_wifi->destroyFeature is NULL", __func__);
        return HDF_FAILURE;
    }
    HDF_LOGI("hal enter %{public}s type:%{public}d", __FUNCTION__, ifeature->type);
    if (ifeature->type == PROTOCOL_80211_IFTYPE_AP) {
        if (g_apFeature == NULL) {
            HDF_LOGE("%{public}s g_apFeature is NULL!", __func__);
            return HDF_FAILURE;
        }
        g_apFeatureCount--;
        if (g_apFeatureCount > 0) {
            HDF_LOGI("%{public}s: apFeature is used!", __func__);
            return HDF_SUCCESS;
        }
        ret = strcpy_s((g_apFeature->baseFeature).ifName, IFNAMSIZ, ifeature->ifName);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: strcpy_s apFeature ifName is failed!", __func__);
            return HDF_FAILURE;
        }
        ret = g_wifi->destroyFeature(&(g_apFeature->baseFeature));
        g_apFeature = NULL;
    } else if (ifeature->type == PROTOCOL_80211_IFTYPE_STATION) {
        if (g_staFeature == NULL) {
            HDF_LOGE("%{public}s g_staFeature is NULL!", __func__);
            return HDF_FAILURE;
        }
        g_staFeatureCount--;
        if (g_staFeatureCount > 0) {
            HDF_LOGI("%{public}s: staFeature is used!", __func__);
            return HDF_SUCCESS;
        }
        ret = strcpy_s((g_staFeature->baseFeature).ifName, IFNAMSIZ, ifeature->ifName);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: strcpy_s staFeature ifName is failed!", __func__);
            return HDF_FAILURE;
        }
        ret = g_wifi->destroyFeature(&(g_staFeature->baseFeature));
        g_staFeature = NULL;
    } else if (ifeature->type == PROTOCOL_80211_IFTYPE_P2P_DEVICE) {
        if (g_p2pFeature == NULL) {
            HDF_LOGE("%{public}s g_p2pFeature is NULL!", __func__);
            return HDF_FAILURE;
        }
        g_p2pFeatureCount--;
        if (g_p2pFeatureCount > 0) {
            HDF_LOGI("%{public}s: p2pFeature is used!", __func__);
            return HDF_SUCCESS;
        }
        ret = strcpy_s((g_p2pFeature->baseFeature).ifName, IFNAMSIZ, ifeature->ifName);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: failed to copy the ifName! ret: %{public}d", __func__, ret);
            return HDF_FAILURE;
        }
        ret = g_wifi->destroyFeature(&(g_p2pFeature->baseFeature));
        g_p2pFeature = NULL;
    } else {
        HDF_LOGE("%{public}s: wlan type is invalid", __func__);
    }
    HDF_LOGI("hal exit %{public}s, apFeatureCount:%{public}u staFeatureCount:%{public}u p2pFeatureCount:%{public}u",
        __FUNCTION__, g_apFeatureCount, g_staFeatureCount, g_p2pFeatureCount);
    return ret;
}

int32_t WlanInterfaceGetAssociatedStas(struct IWlanInterface *self, const struct HdfFeatureInfo *ifeature,
    struct HdfStaInfo *staInfo, uint32_t *staInfoLen, uint32_t *num)
{
    int32_t ret;

    (void)self;
    if (ifeature == NULL || ifeature->ifName == NULL || staInfo == NULL || staInfoLen == NULL || num == NULL)  {
        HDF_LOGE("%{public}s:input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_apFeature == NULL || g_apFeature->getAssociatedStas == NULL) {
        HDF_LOGE("%{public}s g_apFeature or g_apFeature->getAssociatedStas is NULL!", __func__);
        return HDF_FAILURE;
    }
    ret = strcpy_s((g_apFeature->baseFeature).ifName, IFNAMSIZ, ifeature->ifName);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: strcpy_s apFeature ifName is failed!", __func__);
        return HDF_FAILURE;
    }

    struct StaInfo *wifiStaInfo = (struct StaInfo *)OsalMemCalloc(sizeof(struct StaInfo) * (*staInfoLen));
    if (wifiStaInfo == NULL) {
        HDF_LOGE("%{public}s:OsalMemCalloc failed!", __func__);
        return HDF_FAILURE;
    }
    ret = g_apFeature->getAssociatedStas(g_apFeature, wifiStaInfo, *staInfoLen, num);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s get associated sta failed!, error code: %{public}d", __func__, ret);
        OsalMemFree(wifiStaInfo);
        return ret;
    }
    for (uint32_t i = 0; i < (*num); i++) {
        staInfo[i].mac = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * ETH_ADDR_LEN);
        if (staInfo[i].mac != NULL) {
            if (memcpy_s(staInfo[i].mac, WIFI_MAC_ADDR_LENGTH, wifiStaInfo[i].mac, WIFI_MAC_ADDR_LENGTH) != EOK) {
                HDF_LOGE("%{public}s fail : memcpy_s mac fail!", __func__);
                ret = HDF_FAILURE;
                break;
            }
            staInfo[i].macLen = WIFI_MAC_ADDR_LENGTH;
        }
    }
    OsalMemFree(wifiStaInfo);
    return ret;
}

static int32_t GetBasefeature(const struct HdfFeatureInfo *ifeature, struct IWiFiBaseFeature **baseFeature)
{
    if (ifeature->type == PROTOCOL_80211_IFTYPE_AP) {
        if (g_apFeature == NULL) {
            HDF_LOGE("%{public}s g_apFeature is NULL!", __func__);
            return HDF_FAILURE;
        }
        *baseFeature = &(g_apFeature->baseFeature);
    } else if (ifeature->type == PROTOCOL_80211_IFTYPE_STATION) {
        if (g_staFeature == NULL) {
            HDF_LOGE("%{public}s g_staFeature is NULL!", __func__);
            return HDF_FAILURE;
        }
        *baseFeature = &(g_staFeature->baseFeature);
    } else if (ifeature->type == PROTOCOL_80211_IFTYPE_P2P_DEVICE) {
        if (g_p2pFeature == NULL) {
            HDF_LOGE("%{public}s g_p2pFeature is NULL!", __func__);
            return HDF_FAILURE;
        }
        *baseFeature = &(g_p2pFeature->baseFeature);
    } else {
        HDF_LOGE("%{public}s: wlan type is Invalid, featureType is %{public}d", __func__, ifeature->type);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t WlanInterfaceGetChipId(struct IWlanInterface *self, const struct HdfFeatureInfo *ifeature, uint8_t *chipId)
{
    int32_t ret = HDF_FAILURE;
    struct IWiFiBaseFeature *baseFeature = NULL;

    (void)self;
    if (ifeature == NULL || ifeature->ifName == NULL || chipId == NULL) {
        HDF_LOGE("%{public}s ifeature or ifName is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = GetBasefeature(ifeature, &baseFeature);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s GetBasefeature failed!", __func__);
        return HDF_FAILURE;
    }
    ret = strcpy_s(baseFeature->ifName, IFNAMSIZ, ifeature->ifName);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: strcpy_s is failed!, error code: %{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    return baseFeature->getChipId(baseFeature, chipId);
}

int32_t WlanInterfaceGetDeviceMacAddress(struct IWlanInterface *self, const struct HdfFeatureInfo *ifeature,
    uint8_t *mac, uint32_t *macLen, uint8_t len)
{
    int32_t ret = HDF_FAILURE;
    struct IWiFiBaseFeature *baseFeature = NULL;

    (void)self;
    if (ifeature == NULL || ifeature->ifName == NULL || mac == NULL || macLen == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = GetBasefeature(ifeature, &baseFeature);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s GetBasefeature failed!", __func__);
        return HDF_FAILURE;
    }
    ret = strcpy_s(baseFeature->ifName, IFNAMSIZ, ifeature->ifName);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: strcpy_s is failed!, error code: %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    ret = baseFeature->getDeviceMacAddress(baseFeature, mac, len);
    *macLen = ETH_ADDR_LEN;
    return ret;
}

int32_t WlanInterfaceGetFeatureByIfName(struct IWlanInterface *self, const char *ifName,
    struct HdfFeatureInfo *ifeature)
{
    int32_t ret;
    struct IWiFiBaseFeature *baseFeature = NULL;

    (void)self;
    if (ifName == NULL || ifeature == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_wifi == NULL || g_wifi->getFeatureByIfName == NULL) {
        HDF_LOGE("%{public}s gwifi or g_wifi->getFeatureByIfName is NULL!", __func__);
        return HDF_FAILURE;
    }
    ret = g_wifi->getFeatureByIfName(ifName, (struct IWiFiBaseFeature **)&baseFeature);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s get FeatureByIfName failed!, error code: %{public}d", __func__, ret);
        return ret;
    }
    if (baseFeature == NULL) {
        HDF_LOGE("%{public}s baseFeature is NULL!", __func__);
        return HDF_FAILURE;
    }
    ifeature->type = baseFeature->type;
    ifeature->ifName = strdup(baseFeature->ifName);
    return ret;
}

int32_t WlanInterfaceGetFeatureType(struct IWlanInterface *self, const struct HdfFeatureInfo *ifeature,
    int32_t *featureType)
{
    (void)self;
    int32_t ret;
    int32_t type;
    struct IWiFiBaseFeature *baseFeature = NULL;

    if (ifeature == NULL || featureType == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = GetBasefeature(ifeature, &baseFeature);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s GetBasefeature failed!", __func__);
        return HDF_FAILURE;
    }
    baseFeature->type = ifeature->type;
    type = baseFeature->getFeatureType(baseFeature);
    *featureType = type;
    return HDF_SUCCESS;
}

int32_t WlanInterfaceGetFreqsWithBand(struct IWlanInterface *self, const struct HdfFeatureInfo *ifeature,
    const struct HdfWifiInfo *wifiInfo, int32_t *freq, uint32_t *freqLen)
{
    int32_t ret;
    struct IWiFiBaseFeature *baseFeature = NULL;

    (void)self;
    if (ifeature == NULL || ifeature->ifName == NULL || freq == NULL || freqLen == NULL || wifiInfo == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = GetBasefeature(ifeature, &baseFeature);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s GetBasefeature failed!", __func__);
        return HDF_FAILURE;
    }
    ret = strcpy_s(baseFeature->ifName, IFNAMSIZ, ifeature->ifName);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: strcpy_s is failed!, error code: %{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    return baseFeature->getValidFreqsWithBand(baseFeature, wifiInfo->band, freq, wifiInfo->size, freqLen);
}

int32_t WlanInterfaceGetIfNamesByChipId(struct IWlanInterface *self, uint8_t chipId, char *ifName,
    uint32_t ifNameLen, uint32_t *num)
{
    int32_t ret;

    (void)self;
    if (ifName == NULL || num == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    char *name = NULL;
    
    if (g_staFeature != NULL) {
        HDF_LOGD("%{public}s g_staFeature is not NULL!", __func__);
        ret = g_staFeature->baseFeature.getIfNamesByChipId(chipId, &name, num);
    } else if (g_apFeature != NULL) {
        HDF_LOGD("%{public}s g_apFeature is not NULL!", __func__);
        ret = g_apFeature->baseFeature.getIfNamesByChipId(chipId, &name, num);
    } else if (g_p2pFeature != NULL) {
        HDF_LOGD("%{public}s g_p2pFeature is not NULL!", __func__);
        ret = g_p2pFeature->baseFeature.getIfNamesByChipId(chipId, &name, num);
    } else {
        HDF_LOGE("%{public}s: ap and sta feature is Invalid.", __func__);
        ret = HDF_FAILURE;
    }

    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s get name failed!, error code: %{public}d", __func__, ret);
        return ret;
    }

    if (name != NULL) {
        if (strcpy_s(ifName, ifNameLen, name) != EOK) {
            HDF_LOGE("%{public}s: copy ifName failed!", __func__);
            return HDF_FAILURE;
        }
    }
    return ret;
}

int32_t WlanInterfaceGetNetworkIfaceName(struct IWlanInterface *self, const struct HdfFeatureInfo *ifeature,
    char *ifName, uint32_t ifNameLen)
{
    int32_t ret;
    const char *name = NULL;
    struct IWiFiBaseFeature *baseFeature = NULL;

    (void)self;
    if (ifeature == NULL || ifeature->ifName == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = GetBasefeature(ifeature, &baseFeature);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s GetBasefeature failed!", __func__);
        return HDF_FAILURE;
    }
    ret = strcpy_s(baseFeature->ifName, IFNAMSIZ, ifeature->ifName);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: strcpy_s is failed!, error code: %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    name = baseFeature->getNetworkIfaceName(baseFeature);
    if (name == NULL) {
        HDF_LOGE("%{public}s get network iface name failed!", __func__);
        return HDF_FAILURE;
    }
    if (strcpy_s(ifName, ifNameLen, name) != EOK) {
        HDF_LOGE("%{public}s: copy ifName failed!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t WlanInterfaceGetSupportCombo(struct IWlanInterface *self, uint64_t *combo)
{
    int32_t ret;

    (void)self;
    if (combo == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_wifi == NULL || g_wifi->getSupportCombo == NULL) {
        HDF_LOGE("%{public}s g_wifi or g_wifi->getSupportCombo is NULL!", __func__);
        return HDF_FAILURE;
    }
    ret = g_wifi->getSupportCombo(combo, DEFAULT_COMBO_SIZE);
    if (ret == HDF_ERR_NOT_SUPPORT) {
        HDF_LOGW("%{public}s: not support to getting combo!, error code: %{public}d", __func__, ret);
    }
    return ret;
}

int32_t WlanInterfaceGetSupportFeature(struct IWlanInterface *self, uint8_t *supType, uint32_t *supTypeLen)
{
    int32_t ret;

    (void)self;
    if (supType == NULL || supTypeLen == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_wifi == NULL || g_wifi->getSupportFeature == NULL) {
        HDF_LOGE("%{public}s g_wifi or g_wifi->getSupportFeature is NULL!", __func__);
        return HDF_FAILURE;
    }
    ret = g_wifi->getSupportFeature(supType, *supTypeLen);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s get support feature failed! error code: %{public}d", __func__, ret);
    }
    return ret;
}

static int32_t HdfWlanAddRemoteObj(struct IWlanCallback *self)
{
    struct HdfWlanRemoteNode *pos = NULL;
    struct DListHead *head = &HdfStubDriver()->remoteListHead;

    if (self == NULL) {
        HDF_LOGE("%{public}s:self == NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!DListIsEmpty(head)) {
        DLIST_FOR_EACH_ENTRY(pos, head, struct HdfWlanRemoteNode, node) {
            if (pos->service == self->AsObject(self)) {
                HDF_LOGE("%{public}s: pos->service == self", __func__);
                return HDF_FAILURE;
            }
        }
    }

    struct HdfWlanRemoteNode *newRemoteNode =
        (struct HdfWlanRemoteNode *)OsalMemCalloc(sizeof(struct HdfWlanRemoteNode));
    if (newRemoteNode == NULL) {
        HDF_LOGE("%{public}s:newRemoteNode is NULL", __func__);
        return HDF_FAILURE;
    }

    newRemoteNode->callbackObj = self;
    newRemoteNode->service = self->AsObject(self);
    DListInsertTail(&newRemoteNode->node, head);
    return HDF_SUCCESS;
}

static int32_t FillData(uint8_t **dst, uint32_t *dstLen, uint8_t *src, uint32_t srcLen)
{
    if (src == NULL || dst == NULL || dstLen == NULL) {
        HDF_LOGE("%{public}s: Invalid parameter!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    *dst = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * srcLen);
    if (*dst == NULL) {
        HDF_LOGE("%{public}s: OsalMemCalloc fail!", __func__);
        return HDF_FAILURE;
    }
    if (memcpy_s(*dst, srcLen, src, srcLen) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s fail!", __func__);
        OsalMemFree(*dst);
        *dst = NULL;
        return HDF_FAILURE;
    }
    *dstLen = srcLen;
    return HDF_SUCCESS;
}

static int32_t WlanFillScanResultInfo(WifiScanResult *wifiScanResult, struct HdfWifiScanResult *scanResult)
{
    int32_t ret = HDF_SUCCESS;
    if (wifiScanResult == NULL || scanResult == NULL) {
        HDF_LOGE("%{public}s: wifiScanResult or scanResult is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    scanResult->flags = wifiScanResult->flags;
    scanResult->caps = wifiScanResult->caps;
    scanResult->freq = wifiScanResult->freq;
    scanResult->beaconInt = wifiScanResult->beaconInt;
    scanResult->qual = wifiScanResult->qual;
    scanResult->level = wifiScanResult->level;
    scanResult->age = wifiScanResult->age;
    do {
        if (wifiScanResult->bssid != NULL &&
            FillData(&scanResult->bssid, &scanResult->bssidLen, wifiScanResult->bssid, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if ((wifiScanResult->ie != NULL) && (wifiScanResult->ieLen != 0) &&
            FillData(&scanResult->ie, &scanResult->ieLen, wifiScanResult->ie, wifiScanResult->ieLen) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill ie fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if ((wifiScanResult->beaconIe != NULL) && (wifiScanResult->beaconIeLen != 0) &&
            FillData(&scanResult->beaconIe, &scanResult->beaconIeLen, wifiScanResult->beaconIe,
                wifiScanResult->beaconIeLen) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill beaconIe fail!", __func__);
            ret = HDF_FAILURE;
        }
    } while (0);
    if (ret != HDF_SUCCESS) {
        if (scanResult->bssid != NULL) {
            OsalMemFree(scanResult->bssid);
        }
        if (scanResult->ie != NULL) {
            OsalMemFree(scanResult->ie);
        }
        if (scanResult->beaconIe != NULL) {
            OsalMemFree(scanResult->beaconIe);
        }
    }
    return ret;
}

static int32_t WlanFillScanResultInfoExt(WifiScanResult *wifiScanResult, struct HdfWifiScanResultExt *scanResult)
{
    int32_t ret = HDF_SUCCESS;
    if (wifiScanResult == NULL || scanResult == NULL) {
        HDF_LOGE("%{public}s: wifiScanResult or scanResult is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    scanResult->flags = wifiScanResult->flags;
    scanResult->caps = wifiScanResult->caps;
    scanResult->freq = wifiScanResult->freq;
    scanResult->beaconInt = wifiScanResult->beaconInt;
    scanResult->qual = wifiScanResult->qual;
    scanResult->level = wifiScanResult->level;
    scanResult->age = wifiScanResult->age;
    scanResult->tsf = wifiScanResult->tsf;
    do {
        if (wifiScanResult->bssid != NULL &&
            FillData(&scanResult->bssid, &scanResult->bssidLen, wifiScanResult->bssid, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if ((wifiScanResult->ie != NULL) && (wifiScanResult->ieLen != 0) &&
            FillData(&scanResult->ie, &scanResult->ieLen, wifiScanResult->ie, wifiScanResult->ieLen) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill ie fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if ((wifiScanResult->beaconIe != NULL) && (wifiScanResult->beaconIeLen != 0) &&
            FillData(&scanResult->beaconIe, &scanResult->beaconIeLen, wifiScanResult->beaconIe,
                wifiScanResult->beaconIeLen) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill beaconIe fail!", __func__);
            ret = HDF_FAILURE;
        }
    } while (0);
    if (ret != HDF_SUCCESS) {
        if (scanResult->bssid != NULL) {
            OsalMemFree(scanResult->bssid);
        }
        if (scanResult->ie != NULL) {
            OsalMemFree(scanResult->ie);
        }
        if (scanResult->beaconIe != NULL) {
            OsalMemFree(scanResult->beaconIe);
        }
    }
    return ret;
}

static int32_t WlanFillScanResultsInfo(WifiScanResults *wifiScanResults, struct HdfWifiScanResults *scanResults)
{
    uint32_t i;
    if (wifiScanResults == NULL || scanResults == NULL) {
        HDF_LOGE("%{public}s: wifiScanResults or scanResults is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    for (i = 0; i < wifiScanResults->num; i++) {
        if (WlanFillScanResultInfoExt(&wifiScanResults->scanResult[i], &scanResults->res[i]) != HDF_SUCCESS) {
            return HDF_FAILURE;
        }
    }
    scanResults->resLen = wifiScanResults->num;
    return HDF_SUCCESS;
}

static int32_t ProcessEventScanResult(struct HdfWlanRemoteNode *node, uint32_t event, WifiScanResult *wifiScanResult,
    const char *ifName)
{
    HDF_LOGI("hal enter %{public}s, event:%{public}u ifName:%{public}s", __FUNCTION__, event, ifName);
    struct HdfWifiScanResult *scanResult = NULL;
    int32_t ret = HDF_FAILURE;

    if (node == NULL || node->callbackObj == NULL || node->callbackObj->ScanResult == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    scanResult = (struct HdfWifiScanResult *)OsalMemCalloc(sizeof(struct HdfWifiScanResult));
    if ((scanResult == NULL) || (WlanFillScanResultInfo(wifiScanResult, scanResult) != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: scanResult is NULL or WlanFillScanResultInfo fialed!", __func__);
    } else {
        ret = node->callbackObj->ScanResult(node->callbackObj, event, scanResult, ifName);
    }
    HdfWifiScanResultFree(scanResult, true);
    HDF_LOGI("hal exit %{public}s", __FUNCTION__);
    return ret;
}

static int32_t ProcessEventScanResults(struct HdfWlanRemoteNode *node, uint32_t event,
    WifiScanResults *wifiScanResults, const char *ifName)
{
    HDF_LOGD("hal enter %{public}s, event:%{public}u ifName:%{public}s", __FUNCTION__, event, ifName);
    struct HdfWifiScanResults *scanResults = NULL;
    uint32_t size;
    int32_t ret = HDF_FAILURE;

    if (node == NULL || node->callbackObj == NULL || node->callbackObj->ScanResults == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    scanResults = (struct HdfWifiScanResults *)OsalMemCalloc(sizeof(struct HdfWifiScanResults));
    if (scanResults == NULL) {
        HDF_LOGE("%{public}s: scanResults is NULL!", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    if (wifiScanResults->num == 0) {
        scanResults->res = NULL;
        scanResults->resLen = 0;
        ret = node->callbackObj->ScanResults(node->callbackObj, event, scanResults, ifName);
        HdfWifiScanResultsFree(scanResults, true);
        HDF_LOGD("%{public}s: scanResults num is 0!", __func__);
        return ret;
    }
    scanResults->resLen = wifiScanResults->num;
    size = sizeof(struct HdfWifiScanResultExt);
    scanResults->res = (struct HdfWifiScanResultExt *)OsalMemCalloc(size * scanResults->resLen);
    if ((scanResults->res == NULL) || (WlanFillScanResultsInfo(wifiScanResults, scanResults) != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: scanResults->res is NULL or WlanFillScanResultsInfo fialed!", __func__);
    } else {
        ret = node->callbackObj->ScanResults(node->callbackObj, event, scanResults, ifName);
    }
    HdfWifiScanResultsFree(scanResults, true);
    HDF_LOGI("%{public}s, wifiScanResults num:%{public}u", __FUNCTION__, wifiScanResults->num);
    return ret;
}

static int32_t ProcessEventScanAborted(struct HdfWlanRemoteNode *node, uint32_t event, const char *ifName)
{
    HDF_LOGI("hal enter %{public}s, event:%{public}u ifName:%{public}s", __FUNCTION__, event, ifName);
    int32_t ret = HDF_FAILURE;
    struct HdfWifiScanResults scanResults = {0};

    if (node == NULL || node->callbackObj == NULL || node->callbackObj->ScanResults == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = node->callbackObj->ScanResults(node->callbackObj, event, &scanResults, ifName);
    HDF_LOGI("hal exit %{public}s, ScanResults ret:%{public}d", __FUNCTION__, ret);
    return ret;
}

static int32_t ProcessEventActionReceived(struct HdfWlanRemoteNode *node, uint32_t event,
    WifiActionData *wifiActionData, const char *ifName)
{
    HDF_LOGI("hal enter %{public}s, event:%{public}u ifName:%{public}s", __FUNCTION__, event, ifName);
    int32_t ret = HDF_FAILURE;

    if (node == NULL || wifiActionData == NULL || ifName == NULL || node->callbackObj == NULL ||
        node->callbackObj->WifiNetlinkMessage == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = node->callbackObj->WifiNetlinkMessage(node->callbackObj, wifiActionData->data, wifiActionData->dataLen);
    HDF_LOGI("hal exit %{public}s, WifiNetlinkMessage ret:%{public}d", __FUNCTION__, ret);
    return ret;
}

static int32_t HdfWLanCallbackFun(uint32_t event, void *data, const char *ifName)
{
    HDF_LOGD("%{public}s, event:%{public}u ifName:%{public}s", __FUNCTION__, event, ifName);
    struct HdfWlanRemoteNode *pos = NULL;
    struct DListHead *head = NULL;
    int32_t *code = NULL;
    int32_t ret = HDF_FAILURE;
    (void)OsalMutexLock(&HdfStubDriver()->mutex);
    head = &HdfStubDriver()->remoteListHead;

    if (data == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: data or ifName is NULL!", __func__);
        (void)OsalMutexUnlock(&HdfStubDriver()->mutex);
        return HDF_ERR_INVALID_PARAM;
    }
    DLIST_FOR_EACH_ENTRY(pos, head, struct HdfWlanRemoteNode, node) {
        if (pos == NULL) {
            HDF_LOGE("%{public}s: pos is NULL", __func__);
            break;
        }
        if (pos->service == NULL || pos->callbackObj == NULL) {
            HDF_LOGW("%{public}s: pos->service or pos->callbackObj NULL", __func__);
            continue;
        }
        switch (event) {
            case WIFI_EVENT_RESET_DRIVER:
                code = (int32_t *)data;
                ret = pos->callbackObj->ResetDriverResult(pos->callbackObj, event, *code, ifName);
                break;
            case WIFI_EVENT_SCAN_RESULT:
                ret = ProcessEventScanResult(pos, event, (WifiScanResult *)data, ifName);
                break;
            case WIFI_EVENT_SCAN_RESULTS:
                ret = ProcessEventScanResults(pos, event, (WifiScanResults *)data, ifName);
                break;
            case WIFI_EVENT_SCAN_ABORTED:
                ret = ProcessEventScanAborted(pos, event, ifName);
                break;
            case WIFI_EVENT_ACTION_RECEIVED:
                ret = ProcessEventActionReceived(pos, event, (WifiActionData *)data, ifName);
                break;
            default:
                HDF_LOGE("%{public}s: unknown eventId:%{public}d", __func__, event);
                break;
        }
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: dispatch code fialed, error code: %{public}d", __func__, ret);
        }
    }
    (void)OsalMutexUnlock(&HdfStubDriver()->mutex);
    return ret;
}

static int32_t HdfWlanNetlinkCallbackFun(const uint8_t *recvMsg, uint32_t recvMsgLen)
{
    struct HdfWlanRemoteNode *pos = NULL;
    struct DListHead *head = NULL;
    int32_t ret = HDF_FAILURE;
    (void)OsalMutexLock(&HdfStubDriver()->mutex);
    head = &HdfStubDriver()->remoteListHead;

    if (recvMsg == NULL) {
        HDF_LOGE("%{public}s: recvMsg or ifName is NULL!", __func__);
        (void)OsalMutexUnlock(&HdfStubDriver()->mutex);
        return HDF_ERR_INVALID_PARAM;
    }
    DLIST_FOR_EACH_ENTRY(pos, head, struct HdfWlanRemoteNode, node) {
        if (pos->service == NULL || pos->callbackObj == NULL) {
            HDF_LOGW("%{public}s: pos->service or pos->callbackObj NULL", __func__);
            continue;
        }
        ret = pos->callbackObj->WifiNetlinkMessage(pos->callbackObj, recvMsg, recvMsgLen);
        if (ret != HDF_SUCCESS) {
            HDF_LOGD("%{public}s: dispatch code fialed, error code: %{public}d", __func__, ret);
        }
    }
    (void)OsalMutexUnlock(&HdfStubDriver()->mutex);
    return ret;
}

static void HdfWlanDelRemoteObj(struct IWlanCallback *self)
{
    struct HdfWlanRemoteNode *pos = NULL;
    struct HdfWlanRemoteNode *tmp = NULL;
    struct DListHead *head = &HdfStubDriver()->remoteListHead;

    DLIST_FOR_EACH_ENTRY_SAFE(pos, tmp, head, struct HdfWlanRemoteNode, node) {
        if (pos->service->index == self->AsObject(self)->index) {
            DListRemove(&(pos->node));
            IWlanCallbackRelease(pos->callbackObj);
            OsalMemFree(pos);
            break;
        }
    }
    IWlanCallbackRelease(self);
}

int32_t WlanInterfaceRegisterEventCallback(struct IWlanInterface *self, struct IWlanCallback *cbFunc,
    const char *ifName)
{
    int32_t ret;
    HDF_LOGI("hal enter %{public}s, ifName:%{public}s", __FUNCTION__, ifName);
    (void)self;
    if (cbFunc == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_wifi == NULL || g_wifi->registerEventCallback == NULL) {
        HDF_LOGE("%{public}s g_wifi or g_wifi->registerEventCallback is NULL!", __func__);
        return HDF_FAILURE;
    }
    (void)OsalMutexLock(&HdfStubDriver()->mutex);

    do {
        ret = HdfWlanAddRemoteObj(cbFunc);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: HdfSensorAddRemoteObj false", __func__);
            break;
        }
        ret = g_wifi->registerEventCallback(HdfWLanCallbackFun, ifName);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: Register failed!, error code: %{public}d", __func__, ret);
            HdfWlanDelRemoteObj(cbFunc);
            break;
        }
        ret = WlanInterfaceRegisterHid2dCallback(HdfWlanNetlinkCallbackFun, ifName);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: Register failed!, error code: %{public}d", __func__, ret);
            g_wifi->unregisterEventCallback(HdfWLanCallbackFun, ifName);
            HdfWlanDelRemoteObj(cbFunc);
        }
    } while (0);

    (void)OsalMutexUnlock(&HdfStubDriver()->mutex);
    HDF_LOGI("hal exit %{public}s, ret:%{public}d", __FUNCTION__, ret);
    return ret;
}

int32_t WlanInterfaceUnregisterEventCallback(struct IWlanInterface *self, struct IWlanCallback *cbFunc,
    const char *ifName)
{
    HDF_LOGI("hal enter %{public}s, ifName:%{public}s", __FUNCTION__, ifName);
    int32_t ret;

    (void)self;
    if (cbFunc == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_wifi == NULL || g_wifi->unregisterEventCallback == NULL) {
        HDF_LOGE("%{public}s g_wifi or g_wifi->unregisterEventCallback is NULL!", __func__);
        return HDF_FAILURE;
    }
    (void)OsalMutexLock(&HdfStubDriver()->mutex);
    HdfWlanDelRemoteObj(cbFunc);
    if (DListIsEmpty(&HdfStubDriver()->remoteListHead)) {
        ret = g_wifi->unregisterEventCallback(HdfWLanCallbackFun, ifName);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: Unregister failed!, error code: %{public}d", __func__, ret);
        }
        ret = WlanInterfaceUnregisterHid2dCallback(HdfWlanNetlinkCallbackFun, ifName);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: Unregister Hid2dCallback failed!, error code: %{public}d", __func__, ret);
        }
    }
    (void)OsalMutexUnlock(&HdfStubDriver()->mutex);
    HDF_LOGI("hal exit %{public}s", __FUNCTION__);
    return HDF_SUCCESS;
}

int32_t WlanInterfaceResetDriver(struct IWlanInterface *self, uint8_t chipId, const char *ifName)
{
    int32_t ret;

    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_wifi == NULL || g_wifi->resetDriver == NULL) {
        HDF_LOGE("%{public}s g_wifi or g_wifi->resetDriver is NULL!", __func__);
        return HDF_FAILURE;
    }
    ret = g_wifi->resetDriver(chipId, ifName);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s reset driver failed! error code: %{public}d", __func__, ret);
        return ret;
    }
    OsalMSleep(RESET_TIME);
    return ret;
}

int32_t WlanInterfaceSetCountryCode(struct IWlanInterface *self, const struct HdfFeatureInfo *ifeature,
    const char *code, uint32_t len)
{
    int32_t ret;

    (void)self;
    if (ifeature == NULL || ifeature->ifName == NULL || code == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_apFeature == NULL || g_apFeature->setCountryCode == NULL) {
        HDF_LOGE("%{public}s g_apFeature or g_apFeature->setCountryCode is NULL!", __func__);
        return HDF_FAILURE;
    }
    ret = strcpy_s((g_apFeature->baseFeature).ifName, IFNAMSIZ, ifeature->ifName);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: strcpy_s apFeature ifName is failed!", __func__);
        return HDF_FAILURE;
    }
    ret = g_apFeature->setCountryCode(g_apFeature, code, strlen(code));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s set country code failed!, error code: %{public}d", __func__, ret);
    }
    return ret;
}

int32_t WlanInterfaceSetMacAddress(struct IWlanInterface *self, const struct HdfFeatureInfo *ifeature,
    const uint8_t *mac, uint32_t macLen)
{
    int32_t ret = HDF_FAILURE;
    struct IWiFiBaseFeature *baseFeature = NULL;

    (void)self;
    if (ifeature == NULL || mac == NULL || ifeature->ifName == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = GetBasefeature(ifeature, &baseFeature);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s GetBasefeature failed!", __func__);
        return HDF_FAILURE;
    }
    ret = strcpy_s(baseFeature->ifName, IFNAMSIZ, ifeature->ifName);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: strcpy_s is failed!, error code: %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    return baseFeature->setMacAddress(baseFeature, (uint8_t *)mac, ETH_ADDR_LEN);
}

int32_t WlanInterfaceSetScanningMacAddress(struct IWlanInterface *self, const struct HdfFeatureInfo *ifeature,
    const uint8_t *scanMac, uint32_t scanMacLen)
{
    int32_t ret;

    (void)self;
    if (ifeature == NULL || ifeature->ifName == NULL || scanMac == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_staFeature == NULL || g_staFeature->setScanningMacAddress == NULL) {
        HDF_LOGE("%{public}s g_staFeature or g_staFeature->setScanningMacAddress is NULL!", __func__);
        return HDF_FAILURE;
    }
    ret = strcpy_s((g_staFeature->baseFeature).ifName, IFNAMSIZ, ifeature->ifName);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: strcpy_s is failed!, error code: %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    ret = g_staFeature->setScanningMacAddress(g_staFeature, (uint8_t *)scanMac, (uint8_t)scanMacLen);

    return ret;
}

int32_t WlanInterfaceSetTxPower(struct IWlanInterface *self, const struct HdfFeatureInfo *ifeature, int32_t power)
{
    int32_t ret;
    struct IWiFiBaseFeature *baseFeature = NULL;

    (void)self;
    if (ifeature == NULL || ifeature->ifName == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = GetBasefeature(ifeature, &baseFeature);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s GetBasefeature failed!", __func__);
        return HDF_FAILURE;
    }
    ret = strcpy_s(baseFeature->ifName, IFNAMSIZ, ifeature->ifName);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: strcpy_s is failed!, error code: %{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    return baseFeature->setTxPower(baseFeature, power);
}

int32_t WlanInterfaceGetNetDevInfo(struct IWlanInterface *self, struct HdfNetDeviceInfoResult *netDeviceInfoResult)
{
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (g_wifi == NULL || g_wifi->getNetDevInfo == NULL ||netDeviceInfoResult == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    struct NetDeviceInfoResult *netDeviceInfo =
        (struct NetDeviceInfoResult *)OsalMemCalloc(sizeof(struct NetDeviceInfoResult));
    if (netDeviceInfo == NULL) {
        HDF_LOGE("%{public}s:OsalMemCalloc failed!", __func__);
        return HDF_FAILURE;
    }
    ret = g_wifi->getNetDevInfo(netDeviceInfo);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get netdev info failed!, error code: %{public}d", __func__, ret);
        OsalMemFree(netDeviceInfo);
        return HDF_FAILURE;
    }

    netDeviceInfoResult->deviceInfos =
        (struct HdfNetDeviceInfo *)OsalMemCalloc(sizeof(struct HdfNetDeviceInfo) * MAX_NETDEVICE_COUNT);
    if (netDeviceInfoResult->deviceInfos == NULL) {
        HDF_LOGE("%{public}s:netDeviceInfoResult->deviceInfos OsalMemCalloc failed", __func__);
        OsalMemFree(netDeviceInfo);
        return HDF_FAILURE;
    }
    netDeviceInfoResult->deviceInfosLen = MAX_NETDEVICE_COUNT;
    for (uint32_t i = 0; i < netDeviceInfoResult->deviceInfosLen; i++) {
        netDeviceInfoResult->deviceInfos[i].index = netDeviceInfo->deviceInfos[i].index;
        netDeviceInfoResult->deviceInfos[i].iftype = netDeviceInfo->deviceInfos[i].iftype;
        netDeviceInfoResult->deviceInfos[i].ifName = (char *)OsalMemCalloc(sizeof(char) * IFNAMSIZ);
        if (netDeviceInfoResult->deviceInfos != NULL) {
            if (memcpy_s(netDeviceInfoResult->deviceInfos[i].ifName, IFNAMSIZ, netDeviceInfo->deviceInfos[i].ifName,
                IFNAMSIZ) != EOK) {
                OsalMemFree(netDeviceInfoResult->deviceInfos[i].ifName);
                break;
            }
            netDeviceInfoResult->deviceInfos[i].ifNameLen = IFNAMSIZ;
        }
        netDeviceInfoResult->deviceInfos[i].mac = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * ETH_ADDR_LEN);
        if (netDeviceInfoResult->deviceInfos[i].mac != NULL) {
            if (memcpy_s(netDeviceInfoResult->deviceInfos[i].mac, ETH_ADDR_LEN, netDeviceInfo->deviceInfos[i].mac,
                ETH_ADDR_LEN) != EOK) {
                OsalMemFree(netDeviceInfoResult->deviceInfos[i].mac);
                break;
            }
            netDeviceInfoResult->deviceInfos[i].macLen = ETH_ADDR_LEN;
        }
    }
    OsalMemFree(netDeviceInfo);
    return ret;
}

static int32_t WLanFillSsid(WifiScan *wifiScan, const struct HdfWifiScan *scan)
{
    uint32_t loop;

    for (loop = 0; loop < scan->ssidsLen; loop++) {
        if (scan->ssids[loop].ssidLen > MAX_SSID_LEN) {
            HDF_LOGW("%{public}s fail : ssidLen is invalid!", __func__);
            scan->ssids[loop].ssidLen = MAX_SSID_LEN - 1;
        }
        if (memcpy_s(wifiScan->ssids[loop].ssid, scan->ssids[loop].ssidLen, scan->ssids[loop].ssid,
            scan->ssids[loop].ssidLen) != EOK) {
            HDF_LOGE("%{public}s fail : memcpy_s ssids fail!", __func__);
            return HDF_FAILURE;
        }
        wifiScan->ssids[loop].ssidLen = (uint32_t)(scan->ssids[loop].ssidLen);
    }
    return HDF_SUCCESS;
}

static int32_t WLanFillScanData(WifiScan *wifiScan, const struct HdfWifiScan *scan)
{
    if ((scan->ssids != NULL) && (scan->ssidsLen != 0)) {
        wifiScan->ssids = (WifiDriverScanSsid *)OsalMemCalloc(sizeof(WifiDriverScanSsid) * scan->ssidsLen);
        if (wifiScan->ssids != NULL) {
            if (WLanFillSsid(wifiScan, scan) != HDF_SUCCESS) {
                HDF_LOGE("%{public}s fail : fill ssids fail!", __func__);
                OsalMemFree(wifiScan->ssids);
                return HDF_FAILURE;
            }
            wifiScan->numSsids = scan->ssidsLen;
        }
    }

    if ((scan->freqs != NULL) && (scan->freqsLen != 0)) {
        wifiScan->freqs = (int32_t *)OsalMemCalloc(sizeof(int32_t) * scan->freqsLen);
        if (wifiScan->freqs != NULL) {
            if (memcpy_s(wifiScan->freqs, sizeof(int32_t) * (scan->freqsLen), scan->freqs,
                sizeof(int32_t) * (scan->freqsLen)) != EOK) {
                HDF_LOGE("%{public}s fail : memcpy_s freqs fail!", __func__);
                OsalMemFree(wifiScan->freqs);
                return HDF_FAILURE;
            }
            wifiScan->numFreqs = scan->freqsLen;
        }
    }

    if ((scan->bssid != NULL) && (scan->bssidLen != 0)) {
        wifiScan->bssid = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * scan->bssidLen);
        if (wifiScan->bssid != NULL) {
            if (memcpy_s(wifiScan->bssid, sizeof(uint8_t) * (scan->bssidLen), scan->bssid,
                sizeof(uint8_t) * (scan->bssidLen)) != EOK) {
                HDF_LOGE("%{public}s fail : memcpy_s bssid fail!", __func__);
                OsalMemFree(wifiScan->bssid);
                return HDF_FAILURE;
            }
        }
    }
    if ((scan->extraIes != NULL) && (scan->extraIesLen != 0)) {
        wifiScan->extraIes = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * scan->extraIesLen);
        if (wifiScan->extraIes != NULL) {
            if (memcpy_s(wifiScan->extraIes, sizeof(uint8_t) * (scan->extraIesLen), scan->extraIes,
                sizeof(uint8_t) * (scan->extraIesLen)) != EOK) {
                HDF_LOGE("%{public}s fail : memcpy_s extraIes fail!", __func__);
                OsalMemFree(wifiScan->extraIes);
                return HDF_FAILURE;
            }
            wifiScan->extraIesLen = scan->extraIesLen;
        }
    }

    wifiScan->prefixSsidScanFlag = scan->prefixSsidScanFlag;
    wifiScan->fastConnectFlag = scan->fastConnectFlag;
    return HDF_SUCCESS;
}

static void WifiScanFree(WifiScan *dataBlock)
{
    if (dataBlock == NULL) {
        return;
    }

    if (dataBlock->ssids != NULL) {
        OsalMemFree(dataBlock->ssids);
        dataBlock->ssids = NULL;
    }
    if (dataBlock->freqs != NULL) {
        OsalMemFree(dataBlock->freqs);
        dataBlock->freqs = NULL;
    }
    if (dataBlock->bssid != NULL) {
        OsalMemFree(dataBlock->bssid);
        dataBlock->bssid = NULL;
    }
    if (dataBlock->extraIes != NULL) {
        OsalMemFree(dataBlock->extraIes);
        dataBlock->extraIes = NULL;
    }
    OsalMemFree(dataBlock);
}

int32_t WlanInterfaceStartScan(struct IWlanInterface *self, const struct HdfFeatureInfo *ifeature,
    const struct HdfWifiScan *scan)
{
    HDF_LOGI("hal enter %{public}s", __FUNCTION__);
    int32_t ret = HDF_FAILURE;

    (void)self;
    if (ifeature == NULL || ifeature->ifName == NULL || scan == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    WifiScan *wifiScan = (WifiScan *)OsalMemCalloc(sizeof(WifiScan));
    if (wifiScan == NULL) {
        HDF_LOGE("%{public}s: OsalMemCalloc failed", __func__);
        return HDF_FAILURE;
    }
    if (WLanFillScanData(wifiScan, scan) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s fail : fill scan data fail!", __func__);
        WifiScanFree(wifiScan);
        return HDF_FAILURE;
    }
    if (g_staFeature == NULL || g_staFeature->startScan == NULL) {
        HDF_LOGE("%{public}s g_staFeature or g_staFeature->startScan is NULL!", __func__);
        WifiScanFree(wifiScan);
        return HDF_FAILURE;
    }
    ret = g_staFeature->startScan(ifeature->ifName, wifiScan);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s start scan failed!, error code: %{public}d", __func__, ret);
    }
    WifiScanFree(wifiScan);
    HDF_LOGI("hal exit %{public}s, ret:%{public}d", __FUNCTION__, ret);
    return ret;
}

int32_t WlanInterfaceGetPowerMode(struct IWlanInterface *self, const struct HdfFeatureInfo *ifeature, uint8_t *mode)
{
    int32_t ret;

    (void)self;
    if (ifeature == NULL || ifeature->ifName == NULL || mode == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_wifi == NULL || g_wifi->getPowerMode == NULL) {
        HDF_LOGE("%{public}s g_wifi or g_wifi->getPowerMode is NULL!", __func__);
        return HDF_FAILURE;
    }
    ret = g_wifi->getPowerMode(ifeature->ifName, mode);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get power mode failed!, error code: %{public}d", __func__, ret);
    }
    return ret;
}

int32_t WlanInterfaceSetPowerMode(struct IWlanInterface *self, const struct HdfFeatureInfo *ifeature, uint8_t mode)
{
    int32_t ret;

    (void)self;
    if (ifeature == NULL || ifeature->ifName == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_wifi == NULL || g_wifi->setPowerMode == NULL) {
        HDF_LOGE("%{public}s g_wifi or g_wifi->setPowerMode is NULL!", __func__);
        return HDF_FAILURE;
    }
    ret = g_wifi->setPowerMode(ifeature->ifName, mode);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get power mode failed!, error code: %{public}d", __func__, ret);
    }
    return ret;
}

int32_t WlanInterfaceSetProjectionScreenParam(struct IWlanInterface *self, const char *ifName,
    const struct ProjectionScreenCmdParam *param)
{
    int32_t ret;
    ProjectionScreenParam *projectionScreenParam = NULL;

    (void)self;
    if (ifName == NULL || param == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_wifi == NULL || g_wifi->setProjectionScreenParam == NULL) {
        HDF_LOGE("%{public}s g_wifi or g_wifi->setProjectionScreenParam is NULL!", __func__);
        return HDF_FAILURE;
    }

    projectionScreenParam = OsalMemCalloc(sizeof(ProjectionScreenParam) + param->bufLen);
    if (projectionScreenParam == NULL) {
        HDF_LOGE("%{public}s: OsalMemCalloc failed", __func__);
        return HDF_FAILURE;
    }
    projectionScreenParam->cmdId = param->cmdId;
    projectionScreenParam->bufLen = param->bufLen;
    do {
        if (memcpy_s(projectionScreenParam->buf, projectionScreenParam->bufLen, param->buf, param->bufLen) != EOK) {
            HDF_LOGE("%{public}s: memcpy_s failed", __func__);
            ret = HDF_FAILURE;
            break;
        }
        ret = g_wifi->setProjectionScreenParam(ifName, projectionScreenParam);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: get channel meas result failed!, error code: %{public}d", __func__, ret);
        }
    } while (0);
    
    OsalMemFree(projectionScreenParam);
    return ret;
}

int32_t WlanInterfaceGetStaInfo(struct IWlanInterface *self, const char *ifName, struct WifiStationInfo *info,
    const uint8_t *mac, uint32_t macLen)
{
    int32_t ret;

    (void)self;
    if (ifName == NULL || info == NULL || mac == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_wifi == NULL || g_wifi->getStationInfo == NULL) {
        HDF_LOGE("%{public}s g_wifi or g_wifi->getStationInfo is NULL!", __func__);
        return HDF_FAILURE;
    }
    ret = g_wifi->getStationInfo(ifName, (StationInfo *)info, mac, macLen);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get station information failed!, error code: %{public}d", __func__, ret);
    }
    return ret;
}

static int32_t FillPnoSettings(WifiPnoSettings *wifiPnoSettings, const struct PnoSettings *pnoSettings)
{
    wifiPnoSettings->min2gRssi = pnoSettings->min2gRssi;
    wifiPnoSettings->min5gRssi = pnoSettings->min5gRssi;
    wifiPnoSettings->scanIntervalMs = pnoSettings->scanIntervalMs;
    wifiPnoSettings->scanIterations = pnoSettings->scanIterations;

    if ((pnoSettings->pnoNetworks == NULL) || (pnoSettings->pnoNetworksLen == 0)) {
        HDF_LOGE("%{public}s: scan networks is NULL.", __func__);
        return HDF_FAILURE;
    }

    wifiPnoSettings->pnoNetworksLen = pnoSettings->pnoNetworksLen;
    wifiPnoSettings->pnoNetworks =
        (WifiPnoNetwork *)OsalMemCalloc(sizeof(WifiPnoNetwork) * (pnoSettings->pnoNetworksLen));
    if (wifiPnoSettings->pnoNetworks == NULL) {
        HDF_LOGE("%{public}s: OsalMemCalloc failed", __func__);
        return HDF_FAILURE;
    }
    for (uint32_t i = 0; i < pnoSettings->pnoNetworksLen; i++) {
        wifiPnoSettings->pnoNetworks[i].isHidden = pnoSettings->pnoNetworks[i].isHidden;
        wifiPnoSettings->pnoNetworks[i].ssid.ssidLen = (uint32_t)(pnoSettings->pnoNetworks[i].ssid.ssidLen);
        if (memcpy_s(wifiPnoSettings->pnoNetworks[i].ssid.ssid, MAX_SSID_LEN, pnoSettings->pnoNetworks[i].ssid.ssid,
                pnoSettings->pnoNetworks[i].ssid.ssidLen) != EOK) {
            HDF_LOGE("%{public}s fail : memcpy_s ssids fail!", __func__);
            return HDF_FAILURE;
        }
        if (pnoSettings->pnoNetworks[i].freqsLen != 0) {
            wifiPnoSettings->pnoNetworks[i].freqs =
                (int32_t *)OsalMemCalloc(sizeof(int32_t) * (pnoSettings->pnoNetworks[i].freqsLen));
            if (wifiPnoSettings->pnoNetworks[i].freqs == NULL) {
                HDF_LOGE("%{public}s: OsalMemCalloc failed", __func__);
                return HDF_FAILURE;
            }
            wifiPnoSettings->pnoNetworks[i].freqsLen = pnoSettings->pnoNetworks[i].freqsLen;
            if (memcpy_s(wifiPnoSettings->pnoNetworks[i].freqs,
                    sizeof(int32_t) * (pnoSettings->pnoNetworks[i].freqsLen), pnoSettings->pnoNetworks[i].freqs,
                    sizeof(int32_t) * (pnoSettings->pnoNetworks[i].freqsLen)) != EOK) {
                HDF_LOGE("%{public}s fail : memcpy_s freqs fail!", __func__);
                return HDF_FAILURE;
            }
        }
    }
    return HDF_SUCCESS;
}

static void WifiPnoSettingsFree(WifiPnoSettings *wifiPnoSettings)
{
    if (wifiPnoSettings == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return;
    }
    for (uint32_t i = 0; i < wifiPnoSettings->pnoNetworksLen; i++) {
        if (wifiPnoSettings->pnoNetworks[i].freqs != NULL) {
            OsalMemFree(wifiPnoSettings->pnoNetworks[i].freqs);
            wifiPnoSettings->pnoNetworks[i].freqs = NULL;
        }
    }
    OsalMemFree(wifiPnoSettings->pnoNetworks);
    wifiPnoSettings->pnoNetworks = NULL;
    OsalMemFree(wifiPnoSettings);
}

int32_t WlanInterfaceStartPnoScan(struct IWlanInterface *self, const char *ifName,
    const struct PnoSettings *pnoSettings)
{
    HDF_LOGI("hal enter %{public}s ifName:%{public}s", __FUNCTION__, ifName);
    int32_t ret;
    (void)self;

    if (ifName == NULL || pnoSettings == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_staFeature == NULL || g_staFeature->startPnoScan == NULL) {
        HDF_LOGE("%{public}s g_staFeature or g_staFeature->startPnoScan is NULL!", __func__);
        return HDF_FAILURE;
    }
    WifiPnoSettings *wifiPnoSettings = (WifiPnoSettings *)OsalMemCalloc(sizeof(WifiPnoSettings));
    if (wifiPnoSettings == NULL) {
        HDF_LOGE("%{public}s: OsalMemCalloc failed", __func__);
        return HDF_FAILURE;
    }
    if (FillPnoSettings(wifiPnoSettings, pnoSettings) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s fail : memcpy_s ssids fail!", __func__);
        WifiPnoSettingsFree(wifiPnoSettings);
        return HDF_FAILURE;
    }

    ret = strcpy_s((g_staFeature->baseFeature).ifName, IFNAMSIZ, ifName);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: strcpy_s is failed!, error code: %{public}d", __func__, ret);
        WifiPnoSettingsFree(wifiPnoSettings);
        return HDF_FAILURE;
    }
    ret = g_staFeature->startPnoScan(ifName, wifiPnoSettings);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: startPnoScan failed!, error code: %{public}d", __func__, ret);
    }
    WifiPnoSettingsFree(wifiPnoSettings);
    HDF_LOGI("hal exit %{public}s", __FUNCTION__);
    return ret;
}

int32_t WlanInterfaceStopPnoScan(struct IWlanInterface *self, const char *ifName)
{
    HDF_LOGI("hal enter %{public}s ifName:%{public}s", __FUNCTION__, ifName);
    int32_t ret;
    (void)self;

    if (ifName == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_staFeature == NULL || g_staFeature->stopPnoScan == NULL) {
        HDF_LOGE("%{public}s g_staFeature or g_staFeature->stopPnoScan is NULL!", __func__);
        return HDF_FAILURE;
    }
    ret = strcpy_s((g_staFeature->baseFeature).ifName, IFNAMSIZ, ifName);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: strcpy_s is failed!, error code: %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    ret = g_staFeature->stopPnoScan(ifName);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: stopPnoScan failed!, error code: %{public}d", __func__, ret);
    }
    HDF_LOGI("hal exit %{public}s", __FUNCTION__);
    return ret;
}

int32_t WlanInterfaceGetSignalPollInfo(struct IWlanInterface *self, const char *ifName,
    struct SignalPollResult *signalResult)
{
    int32_t ret;
    (void)self;

    if (ifName == NULL || signalResult == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_staFeature == NULL || g_staFeature->getSignalPollInfo == NULL) {
        HDF_LOGE("%{public}s g_staFeature or g_staFeature->getSignalPollInfo is NULL!", __func__);
        return HDF_FAILURE;
    }
    ret = strcpy_s((g_staFeature->baseFeature).ifName, IFNAMSIZ, ifName);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: strcpy_s is failed!, error code: %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    ret = g_staFeature->getSignalPollInfo(ifName, (struct SignalResult *)signalResult);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get signal information failed!, error code: %{public}d", __func__, ret);
    }
    return ret;
}

int32_t WlanInterfaceGetApBandwidth(struct IWlanInterface *self, const char *ifName,
    uint8_t *bandwidth)
{
    int32_t ret;
    (void)self;

    if (ifName == NULL || bandwidth == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_apFeature == NULL || g_apFeature->getApBandwidth == NULL) {
        HDF_LOGE("%{public}s g_apFeature or g_staFeature->getApBandwidth is NULL!", __func__);
        return HDF_FAILURE;
    }
    ret = g_apFeature->getApBandwidth(ifName, bandwidth);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get signal information failed!, error code: %d", __func__, ret);
    }
    return ret;
}

int32_t WlanInterfaceResetToFactoryMacAddress(struct IWlanInterface *self, const char *ifName)
{
    int32_t ret;

    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (g_staFeature != NULL) {
        HDF_LOGD("%{public}s g_staFeature is not NULL!", __func__);
        ret = g_staFeature->baseFeature.resetToFactoryMacAddress(ifName);
    } else if (g_apFeature != NULL) {
        HDF_LOGD("%{public}s g_apFeature is not NULL!", __func__);
        ret = g_apFeature->baseFeature.resetToFactoryMacAddress(ifName);
    } else {
        HDF_LOGE("%{public}s: ap and sta feature is Invalid.", __func__);
        ret = HDF_FAILURE;
    }

    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s get name failed!, error code: %{public}d", __func__, ret);
    }
    return ret;
}

int32_t WlanInterfaceSendActionFrame(struct IWlanInterface *self, const char *ifName, uint32_t freq,
    const uint8_t *frameData, uint32_t frameDataLen)
{
    int32_t ret;
    (void)self;
    if (ifName == NULL || freq == 0 || frameData == NULL || frameDataLen == 0) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_wifi == NULL || g_wifi->sendActionFrame == NULL) {
        HDF_LOGE("%{public}s g_wifi or g_wifi->sendActionFrame is NULL!", __func__);
        return HDF_FAILURE;
    }
    ret = g_wifi->sendActionFrame(ifName, freq, frameData, frameDataLen);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed!, error code: %{public}d", __func__, ret);
    }
    return ret;
}

int32_t WlanInterfaceRegisterActionFrameReceiver(struct IWlanInterface *self, const char *ifName,
    const uint8_t *match, uint32_t matchLen)
{
    int32_t ret;
    (void)self;
    if (ifName == NULL || match == NULL || matchLen == 0) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (g_wifi == NULL || g_wifi->registerActionFrameReceiver == NULL) {
        HDF_LOGE("%{public}s g_wifi or g_wifi->registerActionFrameReceiver is NULL!", __func__);
        return HDF_FAILURE;
    }
    ret = g_wifi->registerActionFrameReceiver(ifName, match, matchLen);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed!, error code: %{public}d", __func__, ret);
    }
    return ret;
}

int32_t WlanInterfaceSetPowerSaveMode(struct IWlanInterface *self, const char * ifName, int32_t frequency, int32_t mode)
{
    int32_t ret;
    (void)self;

    HDF_LOGI("Enter %{public}s.", __FUNCTION__);
    if (ifName == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (g_wifi == NULL || g_wifi->setPowerSaveMode == NULL) {
        HDF_LOGE("%{public}s g_wifi or g_wifi->setPowerSaveMode is NULL!", __func__);
        return HDF_FAILURE;
    }

    ret = g_wifi->setPowerSaveMode(ifName, frequency, mode);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed!, error code: %{public}d", __func__, ret);
    }
    return ret;
}

int32_t WlanInterfaceSetDpiMarkRule(struct IWlanInterface *self, int32_t uid, int32_t protocol, int32_t enable)
{
    int32_t ret;
    (void)self;

    HDF_LOGI("Enter %{public}s.", __FUNCTION__);
    if (g_wifi == NULL || g_wifi->setDpiMarkRule == NULL) {
        HDF_LOGE("%{public}s g_wifi or g_wifi->setDpiMarkRule is NULL!", __func__);
        return HDF_FAILURE;
    }

    ret = g_wifi->setDpiMarkRule(uid, protocol, enable);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s failed!, error code: %{public}d", __func__, ret);
    }
    return ret;
}

int32_t WlanInterfaceWifiConstruct(void)
{
    int32_t ret;

    ret = WifiConstruct(&g_wifi);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s construct WiFi failed! error code: %{public}d", __func__, ret);
    }
    return ret;
}

int32_t WlanInterfaceWifiDestruct(void)
{
    int32_t ret;

    ret = WifiDestruct(&g_wifi);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s destruct WiFi failed! error code: %{public}d", __func__, ret);
    }
    return ret;
}
