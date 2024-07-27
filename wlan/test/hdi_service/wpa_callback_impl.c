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

#include "wpa_callback_impl.h"
#include <securec.h>
#include <hdf_base.h>
#include <hdf_log.h>
#include <osal_mem.h>

static int32_t WpaCallbackDisconnected(struct IWpaCallback *self,
    const struct HdiWpaDisconnectParam *disconnectParam, const char *ifName)
{
    (void)self;
    if (disconnectParam == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGE("WpaCallbackDisconnected: bssid=" MACSTR, MAC2STR(disconnectParam->bssid));
    HDF_LOGE("WpaCallbackDisconnected: reasonCode=%{public}d, locallyGenerated=%{public}d",
        disconnectParam->reasonCode, disconnectParam->reasonCode);
    return HDF_SUCCESS;
}

static int32_t WpaCallbackOnConnected(struct IWpaCallback *self,
    const struct HdiWpaConnectParam *connectParam, const char *ifName)
{
    (void)self;
    if (connectParam == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGE("WpaCallbackOnConnected: bssid=" MACSTR, MAC2STR(connectParam->bssid));
    HDF_LOGE("WpaCallbackOnConnected: networkId=%{public}d", connectParam->networkId);
    return HDF_SUCCESS;
}

static int32_t WpaCallbackBssidChanged(struct IWpaCallback *self,
    const struct HdiWpaBssidChangedParam *bssidChangedParam, const char *ifName)
{
    (void)self;
    if (bssidChangedParam == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGE("WpaCallbackBssidChanged: bssid=" MACSTR, MAC2STR(bssidChangedParam->bssid));
    HDF_LOGE("WpaCallbackBssidChanged: reason=%{public}s", bssidChangedParam->reason);
    return HDF_SUCCESS;
}

static int32_t WpaCallbackStateChanged(struct IWpaCallback *self,
    const struct HdiWpaStateChangedParam *statechangedParam, const char *ifName)
{
    (void)self;
    if (statechangedParam == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGE("WpaCallbackStateChanged: bssid=" MACSTR, MAC2STR(statechangedParam->bssid));
    HDF_LOGE("WpaCallbackStateChanged: status=%{public}d,networkId=%{public}d,ssid=%{public}s",
        statechangedParam->status, statechangedParam->networkId, statechangedParam->ssid);
    return HDF_SUCCESS;
}

static int32_t WpaCallbackTempDisabled(struct IWpaCallback *self,
    const struct HdiWpaTempDisabledParam *tempDisabledParam, const char *ifName)
{
    (void)self;
    if (tempDisabledParam == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    HDF_LOGE("WpaCallbackTempDisabled: networkid=%{public}d,ssid=%{public}s,authFailures=%{public}d, \
        duration=%{public}d, reason=%{public}s", tempDisabledParam->networkId, tempDisabledParam->ssid,
        tempDisabledParam->authFailures, tempDisabledParam->duration, tempDisabledParam->reason);
    return HDF_SUCCESS;
}

static int32_t WpaCallbackAssociateReject(struct IWpaCallback *self,
    const struct HdiWpaAssociateRejectParam *associateRejectParam, const char *ifName)
{
    (void)self;
    if (associateRejectParam == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGE("WpaCallbackAssociateReject: bssid=" MACSTR, MAC2STR(associateRejectParam->bssid));
    HDF_LOGE("WpaCallbackAssociateReject: statusCode=%{public}d,timeOut=%{public}d",
        associateRejectParam->statusCode, associateRejectParam->timeOut);
    return HDF_SUCCESS;
}

static int32_t WpaCallbackWpsOverlap(struct IWpaCallback *self, const char *ifName)
{
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    HDF_LOGE("WpaCallbackWpsOverlap: input successfully");
    return HDF_SUCCESS;
}

static int32_t WpaCallbackWpsTimeout(struct IWpaCallback *self, const char *ifName)
{
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    HDF_LOGE("WpaCallbackWpsTimeout: input successfully");
    return HDF_SUCCESS;
}

static int32_t WpaCallbackAuthTimeout(struct IWpaCallback *self, const char *ifName)
{
    (void)self;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
 
    HDF_LOGE("WpaCallbackAuthTimeout: input successfully");
    return HDF_SUCCESS;
}

static int32_t WpaCallbackScanResult(struct IWpaCallback *self,
    const struct HdiWpaRecvScanResultParam *recvScanResultParamconst, const char *ifName)
{
    (void)self;
    if (ifName == NULL || recvScanResultParamconst ==NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    HDF_LOGE("WpaCallbackScanResult: scanId=%{public}d", recvScanResultParamconst->scanId);
    return HDF_SUCCESS;
}

static int32_t WpaCallbackAuthReject(struct IWpaCallback *self,
    const struct HdiWpaAuthRejectParam *authRejectParam, const char *ifName)
{
    (void)self;
    if (ifName == NULL || authRejectParam == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGI("WpaCallbackAuthReject: bssid=" MACSTR " statusCode=%{public}hd,authType=%{public}hd,authTransaction="
              "%{public}hd", MAC2STR(authRejectParam->bssid), authRejectParam->statusCode, authRejectParam->authType,
              authRejectParam->authTransaction);
    return HDF_SUCCESS;
}

struct IWpaCallback *WpaCallbackServiceGet(void)
{
    struct WpaCallbackService *service =
        (struct WpaCallbackService *)OsalMemCalloc(sizeof(struct WpaCallbackService));
    if (service == NULL) {
        HDF_LOGE("%{public}s: malloc WpaCallbackService obj failed!", __func__);
        return NULL;
    }

    service->interface.OnEventDisconnected = WpaCallbackDisconnected;
    service->interface.OnEventConnected = WpaCallbackOnConnected;
    service->interface.OnEventBssidChanged = WpaCallbackBssidChanged;
    service->interface.OnEventStateChanged = WpaCallbackStateChanged;
    service->interface.OnEventTempDisabled = WpaCallbackTempDisabled;
    service->interface.OnEventAssociateReject = WpaCallbackAssociateReject;
    service->interface.OnEventWpsOverlap = WpaCallbackWpsOverlap;
    service->interface.OnEventWpsTimeout = WpaCallbackWpsTimeout;
    service->interface.OnEventAuthTimeout = WpaCallbackAuthTimeout;
    service->interface.OnEventScanResult = WpaCallbackScanResult;
    service->interface.OnEventAuthReject = WpaCallbackAuthReject;
    return &service->interface;
}

void WpaCallbackServiceRelease(struct IWpaCallback *instance)
{
    struct WpaCallbackService *service = (struct WpaCallbackService *)instance;
    if (service == NULL) {
        return;
    }

    OsalMemFree(service);
}
