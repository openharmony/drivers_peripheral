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
#include "wpa_common_cmd.h"
#include "wpa_p2p_cmd.h"
#include "hdi_wpa_hal.h"
#include <securec.h>
#include <hdf_base.h>
#include <hdf_log.h>
#include <osal_time.h>
#include <osal_mem.h>
#include <arpa/inet.h>
#include "utils/common.h"
#include "wpa_supplicant_i.h"
#include "ctrl_iface.h"
#include "main.h"
#include "wps_supplicant.h"
#include "bssid_ignore.h"
#include "wpa_supplicant/config.h"
#include "common/defs.h"
#include "v1_1/iwpa_callback.h"
#include "v1_1/iwpa_interface.h"

#include <unistd.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include "hdi_wpa_common.h"

int32_t FillData(uint8_t **dst, uint32_t *dstLen, uint8_t *src, uint32_t srcLen)
{
    if (src == NULL || dst == NULL || dstLen == NULL) {
        HDF_LOGE("%{public}s: Invalid parameter!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGD("%{public}s: srcLen =%{public}d ", __func__, srcLen);
    if (srcLen > 0) {
        *dst = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * srcLen);
        if (*dst == NULL) {
            HDF_LOGE("%{public}s: OsalMemCalloc fail!", __func__);
            return HDF_FAILURE;
        }
        if (memcpy_s(*dst, srcLen, src, srcLen) != EOK) {
            HDF_LOGE("%{public}s: memcpy_s fail!", __func__);
            return HDF_FAILURE;
        }
    }
    *dstLen = srcLen;
    return HDF_SUCCESS;
}

struct HdfWpaStubData *HdfWpaStubDriver(void)
{
    static struct HdfWpaStubData registerManager;
    return &registerManager;
}

int32_t WpaFillWpaListNetworkParam(struct WifiNetworkInfo  *wifiWpaNetworkInfo,
    struct HdiWifiWpaNetworkInfo *hdiWifiWpaNetworkInfo)
{
    int32_t ret = HDF_SUCCESS;
 
    if (wifiWpaNetworkInfo == NULL || hdiWifiWpaNetworkInfo == NULL) {
        HDF_LOGE("%{public}s: wifiWpaNetworkInfo or hdiWifiWpaNetworkInfo is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    do {
        uint8_t tmpBssid[ETH_ADDR_LEN] = {0};
        hwaddr_aton(wifiWpaNetworkInfo->bssid, tmpBssid);
        if (FillData(&hdiWifiWpaNetworkInfo->bssid, &hdiWifiWpaNetworkInfo->bssidLen,
            tmpBssid, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiWifiWpaNetworkInfo->ssid, &hdiWifiWpaNetworkInfo->ssidLen,
            (uint8_t *)wifiWpaNetworkInfo->ssid, strlen(wifiWpaNetworkInfo->ssid)) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill ssid fail!", __func__);
            ret = HDF_FAILURE;
        }
        if (FillData(&hdiWifiWpaNetworkInfo->flags, &hdiWifiWpaNetworkInfo->flagsLen,
            (uint8_t *)wifiWpaNetworkInfo->flags, strlen(wifiWpaNetworkInfo->flags)) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill flags fail!", __func__);
            ret = HDF_FAILURE;
        }
    } while (0);
    if (ret != HDF_SUCCESS) {
        if (hdiWifiWpaNetworkInfo->bssid != NULL) {
            OsalMemFree(hdiWifiWpaNetworkInfo->bssid);
            hdiWifiWpaNetworkInfo->bssid = NULL;
        }
        if (hdiWifiWpaNetworkInfo->ssid != NULL) {
            OsalMemFree(hdiWifiWpaNetworkInfo->ssid);
            hdiWifiWpaNetworkInfo->ssid = NULL;
        }
        if (hdiWifiWpaNetworkInfo->flags != NULL) {
            OsalMemFree(hdiWifiWpaNetworkInfo->flags);
            hdiWifiWpaNetworkInfo->flags = NULL;
        }
    }
    return ret;
}
//swx1355158
static bool GetWpaCmdStatus(uint8_t* dst, uint32_t* dstLen, char* src)
{
    if (strcmp(src, "") != 0) {
        dst = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (strlen(src) + 1));
        if (dst == NULL) {
            HDF_LOGE("%{public}s OsalMemCalloc is NULL", __func__);
            *dstLen = 0;
            return FALSE;
        }
        *dstLen = strlen(src);
        if (strcpy_s((char*)dst, strlen(src) + 1, src) != EOK) {
            HDF_LOGE("%{public}s strcpy failed", __func__);
            return FALSE;
        }
    }
    return TRUE;
}

void WpaProcessWifiStatus(struct WpaHalCmdStatus *halStatus, struct HdiWpaCmdStatus *status)
{
    if (halStatus == NULL) {
        HDF_LOGE("%{public}s halStatus is NULL", __func__);
        return;
    }
    status->id = halStatus->id;
    status->freq = halStatus->freq;
    if (GetWpaCmdStatus(status->keyMgmt, &(status->keyMgmtLen), halStatus->keyMgmt) == FALSE) {
        HDF_LOGI("%{public}s get status->key_mgmt value=%{private}s failed", __func__, halStatus->keyMgmt);
        // status->keyMgmt = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (strlen(halStatus->keyMgmt) + 1));
        // if (status->keyMgmt == NULL) {
        //     HDF_LOGE("%{public}s status->keyMgmt is NULL", __func__);
        //     status->keyMgmtLen = 0;
        //     return;
        // }
        // status->keyMgmtLen = strlen(halStatus->keyMgmt);
        // if (strcpy_s((char *)status->keyMgmt, strlen(halStatus->keyMgmt) + 1, halStatus->keyMgmt) != EOK) {
        //     HDF_LOGE("%{public}s strcpy failed", __func__);
        // }
    }
    // if (strcmp(halStatus->ssid, "") != 0) {
    if (GetWpaCmdStatus(status->ssid, &(status->ssidLen), halStatus->ssid) == FALSE) {
        HDF_LOGI("%{public}s get status->ssid value=%{private}s failed", __func__, halStatus->keyMgmt);
        // status->ssid = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (strlen(halStatus->ssid) + 1));
        // if (status->ssid == NULL) {
        //     HDF_LOGE("%{public}s status->ssid is NULL", __func__);
        //     status->ssidLen = 0;
        //     return;
        // }
        // status->ssidLen = strlen(halStatus->ssid);
        // if (strcpy_s((char *)status->ssid, strlen(halStatus->ssid) + 1, halStatus->ssid) != EOK) {
        //     HDF_LOGE("%{public}s strcpy failed", __func__);
        // }
    }
    if (strcmp(halStatus->address, "") != 0) {
        HDF_LOGI("%{public}s key include address value=%{private}s", __func__, halStatus->address);
        // uint8_t tmpAddress[ETH_ADDR_LEN + 1] = {0};
        // hwaddr_aton(halStatus->address, tmpAddress);
        status->address = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (ETH_ADDR_LEN + 1));
        if (status->address == NULL) {
            HDF_LOGE("%{public}s status->address is NULL", __func__);
            status->addressLen = 0;
            return;
        }
        status->addressLen = ETH_ADDR_LEN + 1 ;
        hwaddr_aton(halStatus->address, status->address);
        // if (memcpy_s((char *)status->address, ETH_ADDR_LEN + 1, (char*)tmpAddress, ETH_ADDR_LEN + 1) != EOK) {
        //     HDF_LOGE("%{public}s strcpy memcpy", __func__);
        // }
    }
    if (strcmp(halStatus->bssid, "") != 0) {
        HDF_LOGI("%{public}s key include bssid value=%{private}s", __func__, halStatus->bssid);
        // uint8_t tmpBssid[ETH_ADDR_LEN + 1] = {0};
        // hwaddr_aton(halStatus->bssid, tmpBssid);
        status->bssid = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (ETH_ADDR_LEN + 1));
        if (status->bssid == NULL) {
            HDF_LOGE("%{public}s status->bssid is NULL", __func__);
            status->bssidLen = 0;
            return;
        }
        status->bssidLen = ETH_ADDR_LEN + 1 ;
        hwaddr_aton(halStatus->bssid, status->bssid);
        // if (strcpy_s((char *)status->bssid, ETH_ADDR_LEN + 1, (char*)tmpBssid) != EOK) {
        //     HDF_LOGE("%{public}s strcpy failed", __func__);
        // }
    }
}

const char *macToStr(const u8 *addr)
{
    const int macAddrIndexOne = 0;
    const int macAddrIndexTwo = 1;
    const int macAddrIndexThree = 2;
    const int macAddrIndexFour = 3;
    const int macAddrIndexFive = 4;
    const int macAddrIndexSix = 5;
    static char macToStr[WIFI_BSSID_LENGTH];
    if (snprintf_s(macToStr, sizeof(macToStr), sizeof(macToStr)-1, "%02x:%02x:%02x:%02x:%02x:%02x",
        addr[macAddrIndexOne], addr[macAddrIndexTwo], addr[macAddrIndexThree], addr[macAddrIndexFour],
        addr[macAddrIndexFive], addr[macAddrIndexSix]) < 0) {
        return NULL;
    }
    return macToStr;
}
 
void HdfWpaDelRemoteObj(struct IWpaCallback *self)
{
    struct HdfWpaRemoteNode *pos = NULL;
    struct HdfWpaRemoteNode *tmp = NULL;
    struct DListHead *head = &HdfWpaStubDriver()->remoteListHead;
 
    DLIST_FOR_EACH_ENTRY_SAFE(pos, tmp, head, struct HdfWpaRemoteNode, node) {
        if (pos->service->index == self->AsObject(self)->index) {
            DListRemove(&(pos->node));
            IWpaCallbackRelease(pos->callbackObj);
            OsalMemFree(pos);
            pos = NULL;
            break;
        }
    }
    IWpaCallbackRelease(self);
}
 
int32_t WpaFillWpaDisconnectParam(struct WpaDisconnectParam *disconnectParam,
    struct HdiWpaDisconnectParam *hdiWpaDisconnectParam)
{
    int32_t ret = HDF_SUCCESS;
 
    if (disconnectParam == NULL || hdiWpaDisconnectParam == NULL) {
        HDF_LOGE("%{public}s: disconnectParam or hdiWpaDisconnectParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiWpaDisconnectParam->locallyGenerated = disconnectParam->locallyGenerated;
    hdiWpaDisconnectParam->reasonCode = disconnectParam->reasonCode;
    if (FillData(&hdiWpaDisconnectParam->bssid, &hdiWpaDisconnectParam->bssidLen,
        disconnectParam->bssid, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
    }
    if (ret != HDF_SUCCESS) {
        if (hdiWpaDisconnectParam->bssid != NULL) {
            OsalMemFree(hdiWpaDisconnectParam->bssid);
            hdiWpaDisconnectParam->bssid = NULL;
        }
    }
    return ret;
}
 
int32_t WpaFillWpaBssidChangedParam(struct WpaBssidChangedParam *bssidChangedParam,
    struct HdiWpaBssidChangedParam *hdiWpaBssidChangedParam)
{
    int32_t ret = HDF_SUCCESS;
 
    if (bssidChangedParam == NULL || hdiWpaBssidChangedParam == NULL) {
        HDF_LOGE("%{public}s: bssidChangedParam or hdiWpaBssidChangedParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    do {
        if (FillData(&hdiWpaBssidChangedParam->bssid, &hdiWpaBssidChangedParam->bssidLen,
            bssidChangedParam->bssid, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiWpaBssidChangedParam->reason, &hdiWpaBssidChangedParam->reasonLen,
            bssidChangedParam->reason, strlen((char*) bssidChangedParam->reason)) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill reason fail!", __func__);
            ret = HDF_FAILURE;
        }
    } while (0);
    if (ret != HDF_SUCCESS) {
        if (hdiWpaBssidChangedParam->bssid != NULL) {
            OsalMemFree(hdiWpaBssidChangedParam->bssid);
            hdiWpaBssidChangedParam->bssid = NULL;
        }
        if (hdiWpaBssidChangedParam->reason != NULL) {
            OsalMemFree(hdiWpaBssidChangedParam->reason);
            hdiWpaBssidChangedParam->reason = NULL;
        }
    }
    return ret;
}
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
#include "wpa_common_cmd.h"
#include "wpa_p2p_cmd.h"
#include "hdi_wpa_hal.h"
#include <securec.h>
#include <hdf_base.h>
#include <hdf_log.h>
#include <osal_time.h>
#include <osal_mem.h>
#include <arpa/inet.h>
#include "utils/common.h"
#include "wpa_supplicant_i.h"
#include "ctrl_iface.h"
#include "main.h"
#include "wps_supplicant.h"
#include "bssid_ignore.h"
#include "wpa_supplicant/config.h"
#include "common/defs.h"
#include "v1_1/iwpa_callback.h"
#include "v1_1/iwpa_interface.h"

#include <unistd.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include "hdi_wpa_common.h"

int32_t FillData(uint8_t **dst, uint32_t *dstLen, uint8_t *src, uint32_t srcLen)
{
    if (src == NULL || dst == NULL || dstLen == NULL) {
        HDF_LOGE("%{public}s: Invalid parameter!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGD("%{public}s: srcLen =%{public}d ", __func__, srcLen);
    if (srcLen > 0) {
        *dst = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * srcLen);
        if (*dst == NULL) {
            HDF_LOGE("%{public}s: OsalMemCalloc fail!", __func__);
            return HDF_FAILURE;
        }
        if (memcpy_s(*dst, srcLen, src, srcLen) != EOK) {
            HDF_LOGE("%{public}s: memcpy_s fail!", __func__);
            return HDF_FAILURE;
        }
    }
    *dstLen = srcLen;
    return HDF_SUCCESS;
}

struct HdfWpaStubData *HdfWpaStubDriver(void)
{
    static struct HdfWpaStubData registerManager;
    return &registerManager;
}

int32_t WpaFillWpaListNetworkParam(struct WifiNetworkInfo  *wifiWpaNetworkInfo,
    struct HdiWifiWpaNetworkInfo *hdiWifiWpaNetworkInfo)
{
    int32_t ret = HDF_SUCCESS;
 
    if (wifiWpaNetworkInfo == NULL || hdiWifiWpaNetworkInfo == NULL) {
        HDF_LOGE("%{public}s: wifiWpaNetworkInfo or hdiWifiWpaNetworkInfo is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    do {
        uint8_t tmpBssid[ETH_ADDR_LEN] = {0};
        hwaddr_aton(wifiWpaNetworkInfo->bssid, tmpBssid);
        if (FillData(&hdiWifiWpaNetworkInfo->bssid, &hdiWifiWpaNetworkInfo->bssidLen,
            tmpBssid, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiWifiWpaNetworkInfo->ssid, &hdiWifiWpaNetworkInfo->ssidLen,
            (uint8_t *)wifiWpaNetworkInfo->ssid, strlen(wifiWpaNetworkInfo->ssid)) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill ssid fail!", __func__);
            ret = HDF_FAILURE;
        }
        if (FillData(&hdiWifiWpaNetworkInfo->flags, &hdiWifiWpaNetworkInfo->flagsLen,
            (uint8_t *)wifiWpaNetworkInfo->flags, strlen(wifiWpaNetworkInfo->flags)) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill flags fail!", __func__);
            ret = HDF_FAILURE;
        }
    } while (0);
    if (ret != HDF_SUCCESS) {
        if (hdiWifiWpaNetworkInfo->bssid != NULL) {
            OsalMemFree(hdiWifiWpaNetworkInfo->bssid);
            hdiWifiWpaNetworkInfo->bssid = NULL;
        }
        if (hdiWifiWpaNetworkInfo->ssid != NULL) {
            OsalMemFree(hdiWifiWpaNetworkInfo->ssid);
            hdiWifiWpaNetworkInfo->ssid = NULL;
        }
        if (hdiWifiWpaNetworkInfo->flags != NULL) {
            OsalMemFree(hdiWifiWpaNetworkInfo->flags);
            hdiWifiWpaNetworkInfo->flags = NULL;
        }
    }
    return ret;
}

void WpaProcessWifiStatus(struct WpaHalCmdStatus *halStatus, struct HdiWpaCmdStatus *status)
{
    if (halStatus == NULL) {
        HDF_LOGE("%{public}s halStatus is NULL", __func__);
        return;
    }
    status->id = halStatus->id;
    status->freq = halStatus->freq;
    if (strcmp(halStatus->keyMgmt, "") != 0) {
        HDF_LOGI("%{public}s key include key_mgmt value=%{private}s", __func__, halStatus->keyMgmt);
        status->keyMgmt = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (strlen(halStatus->keyMgmt) + 1));
        if (status->keyMgmt == NULL) {
            HDF_LOGE("%{public}s status->keyMgmt is NULL", __func__);
            status->keyMgmtLen = 0;
            return;
        }
        status->keyMgmtLen = strlen(halStatus->keyMgmt);
        if (strcpy_s((char *)status->keyMgmt, strlen(halStatus->keyMgmt) + 1, halStatus->keyMgmt) != EOK) {
            HDF_LOGE("%{public}s strcpy failed", __func__);
        }
    }
    if (strcmp(halStatus->ssid, "") != 0) {
        HDF_LOGI("%{public}s key include ssid value=%{private}s", __func__, halStatus->ssid);
        status->ssid = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (strlen(halStatus->ssid) + 1));
        if (status->ssid == NULL) {
            HDF_LOGE("%{public}s status->ssid is NULL", __func__);
            status->ssidLen = 0;
            return;
        }
        status->ssidLen = strlen(halStatus->ssid);
        if (strcpy_s((char *)status->ssid, strlen(halStatus->ssid) + 1, halStatus->ssid) != EOK) {
            HDF_LOGE("%{public}s strcpy failed", __func__);
        }
    }
    if (strcmp(halStatus->address, "") != 0) {
        HDF_LOGI("%{public}s key include address value=%{private}s", __func__, halStatus->address);
        uint8_t tmpAddress[ETH_ADDR_LEN + 1] = {0};
        hwaddr_aton(halStatus->address, tmpAddress);
        status->address = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (ETH_ADDR_LEN + 1));
        if (status->address == NULL) {
            HDF_LOGE("%{public}s status->address is NULL", __func__);
            status->addressLen = 0;
            return;
        }
        status->addressLen = ETH_ADDR_LEN + 1 ;
        if (memcpy_s((char *)status->address, ETH_ADDR_LEN + 1, (char*)tmpAddress, ETH_ADDR_LEN + 1) != EOK) {
            HDF_LOGE("%{public}s strcpy memcpy", __func__);
        }
    }
    if (strcmp(halStatus->bssid, "") != 0) {
        HDF_LOGI("%{public}s key include bssid value=%{private}s", __func__, halStatus->bssid);
        uint8_t tmpBssid[ETH_ADDR_LEN + 1] = {0};
        hwaddr_aton(halStatus->bssid, tmpBssid);
        status->bssid = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (ETH_ADDR_LEN + 1));
        if (status->bssid == NULL) {
            HDF_LOGE("%{public}s status->bssid is NULL", __func__);
            status->bssidLen = 0;
            return;
        }
        status->bssidLen = ETH_ADDR_LEN + 1 ;
        if (strcpy_s((char *)status->bssid, ETH_ADDR_LEN + 1, (char*)tmpBssid) != EOK) {
            HDF_LOGE("%{public}s strcpy failed", __func__);
        }
    }
}

const char *macToStr(const u8 *addr)
{
    const int macAddrIndexOne = 0;
    const int macAddrIndexTwo = 1;
    const int macAddrIndexThree = 2;
    const int macAddrIndexFour = 3;
    const int macAddrIndexFive = 4;
    const int macAddrIndexSix = 5;
    static char macToStr[WIFI_BSSID_LENGTH];
    if (snprintf_s(macToStr, sizeof(macToStr), sizeof(macToStr)-1, "%02x:%02x:%02x:%02x:%02x:%02x",
        addr[macAddrIndexOne], addr[macAddrIndexTwo], addr[macAddrIndexThree], addr[macAddrIndexFour],
        addr[macAddrIndexFive], addr[macAddrIndexSix]) < 0) {
        return NULL;
    }
    return macToStr;
}

void OnRemoteServiceDied(struct HdfDeathRecipient *deathRecipient, struct HdfRemoteService *remote)
{
    HDF_LOGI("enter %{public}s ", __func__);
    WifiWpaInterface *pWpaInterface = GetWifiWpaGlobalInterface();
    if (pWpaInterface == NULL) {
        HDF_LOGE("%{public}s: Get wpa global interface failed!", __func__);
        return;
    }
    int ret = pWpaInterface->wpaCliTerminate();
    if (ret != 0) {
        HDF_LOGE("%{public}s: wpaCliTerminate failed!", __func__);
    } else {
        HDF_LOGI("%{public}s: wpaCliTerminate suc!", __func__);
    }
    ReleaseWpaGlobalInterface();
    HDF_LOGI("%{public}s: call ReleaseWpaGlobalInterface finish", __func__);
}

int32_t HdfWpaAddRemoteObj(struct IWpaCallback *self, const char *ifName)
{
    struct HdfWpaRemoteNode *pos = NULL;
    struct DListHead *head = &HdfWpaStubDriver()->remoteListHead;
 
    if (self == NULL) {
        HDF_LOGE("%{public}s:self == NULL", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!DListIsEmpty(head)) {
        DLIST_FOR_EACH_ENTRY(pos, head, struct HdfWpaRemoteNode, node) {
            if (pos->service == self->AsObject(self)) {
                HDF_LOGE("%{public}s: pos->service == self", __func__);
                return HDF_FAILURE;
            }
        }
    }
    struct HdfWpaRemoteNode *newRemoteNode = (struct HdfWpaRemoteNode *)OsalMemCalloc(sizeof(struct HdfWpaRemoteNode));
    if (newRemoteNode == NULL) {
        HDF_LOGE("%{public}s:newRemoteNode is NULL", __func__);
        return HDF_FAILURE;
    }
    newRemoteNode->callbackObj = self;
    newRemoteNode->service = self->AsObject(self);
    DListInsertTail(&newRemoteNode->node, head);
    if (strncmp(ifName, "wlan", strlen("wlan")) == 0) {
        AddDeathRecipientForService(self);
    }
    return HDF_SUCCESS;
}
 
void HdfWpaDelRemoteObj(struct IWpaCallback *self)
{
    struct HdfWpaRemoteNode *pos = NULL;
    struct HdfWpaRemoteNode *tmp = NULL;
    struct DListHead *head = &HdfWpaStubDriver()->remoteListHead;
 
    DLIST_FOR_EACH_ENTRY_SAFE(pos, tmp, head, struct HdfWpaRemoteNode, node) {
        if (pos->service->index == self->AsObject(self)->index) {
            DListRemove(&(pos->node));
            IWpaCallbackRelease(pos->callbackObj);
            OsalMemFree(pos);
            pos = NULL;
            break;
        }
    }
    IWpaCallbackRelease(self);
}
 
int32_t WpaFillWpaDisconnectParam(struct WpaDisconnectParam *disconnectParam,
    struct HdiWpaDisconnectParam *hdiWpaDisconnectParam)
{
    int32_t ret = HDF_SUCCESS;
 
    if (disconnectParam == NULL || hdiWpaDisconnectParam == NULL) {
        HDF_LOGE("%{public}s: disconnectParam or hdiWpaDisconnectParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiWpaDisconnectParam->locallyGenerated = disconnectParam->locallyGenerated;
    hdiWpaDisconnectParam->reasonCode = disconnectParam->reasonCode;
    if (FillData(&hdiWpaDisconnectParam->bssid, &hdiWpaDisconnectParam->bssidLen,
        disconnectParam->bssid, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
    }
    if (ret != HDF_SUCCESS) {
        if (hdiWpaDisconnectParam->bssid != NULL) {
            OsalMemFree(hdiWpaDisconnectParam->bssid);
            hdiWpaDisconnectParam->bssid = NULL;
        }
    }
    return ret;
}

int32_t WpaFillWpaConnectParam(struct WpaConnectParam *connectParam,
    struct HdiWpaConnectParam *hdiWpaConnectParam)
{
    int32_t ret = HDF_SUCCESS;
 
    if (connectParam == NULL || hdiWpaConnectParam == NULL) {
        HDF_LOGE("%{public}s: connectParam or hdiWpaConnectParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiWpaConnectParam->networkId = connectParam->networkId;
    if (FillData(&hdiWpaConnectParam->bssid, &hdiWpaConnectParam->bssidLen,
        connectParam->bssid, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
    }
    if (ret != HDF_SUCCESS) {
        if (hdiWpaConnectParam->bssid != NULL) {
            OsalMemFree(hdiWpaConnectParam->bssid);
            hdiWpaConnectParam->bssid = NULL;
        }
    }
    return ret;
}
 
int32_t WpaFillWpaBssidChangedParam(struct WpaBssidChangedParam *bssidChangedParam,
    struct HdiWpaBssidChangedParam *hdiWpaBssidChangedParam)
{
    int32_t ret = HDF_SUCCESS;
 
    if (bssidChangedParam == NULL || hdiWpaBssidChangedParam == NULL) {
        HDF_LOGE("%{public}s: bssidChangedParam or hdiWpaBssidChangedParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    do {
        if (FillData(&hdiWpaBssidChangedParam->bssid, &hdiWpaBssidChangedParam->bssidLen,
            bssidChangedParam->bssid, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiWpaBssidChangedParam->reason, &hdiWpaBssidChangedParam->reasonLen,
            bssidChangedParam->reason, strlen((char*) bssidChangedParam->reason)) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill reason fail!", __func__);
            ret = HDF_FAILURE;
        }
    } while (0);
    if (ret != HDF_SUCCESS) {
        if (hdiWpaBssidChangedParam->bssid != NULL) {
            OsalMemFree(hdiWpaBssidChangedParam->bssid);
            hdiWpaBssidChangedParam->bssid = NULL;
        }
        if (hdiWpaBssidChangedParam->reason != NULL) {
            OsalMemFree(hdiWpaBssidChangedParam->reason);
            hdiWpaBssidChangedParam->reason = NULL;
        }
    }
    return ret;
}
