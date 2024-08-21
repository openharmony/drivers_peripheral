static void HdfWpaDelRemoteObj(struct IWpaCallback *self)
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

static int32_t WpaFillWpaDisconnectParam(struct WpaDisconnectParam *disconnectParam,
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

static int32_t WpaFillWpaConnectParam(struct WpaConnectParam *connectParam,
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

static int32_t WpaFillWpaBssidChangedParam(struct WpaBssidChangedParam *bssidChangedParam,
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

static int32_t WpaFillWpaStateChangedParam(struct WpaStateChangedParam *stateChangedParam,
    struct HdiWpaStateChangedParam *hdiWpaStateChangedParam)
{
    int32_t ret = HDF_SUCCESS;

    if (stateChangedParam == NULL || hdiWpaStateChangedParam == NULL) {
        HDF_LOGE("%{public}s: stateChangedParam or hdiWpaStateChangedParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiWpaStateChangedParam->networkId = stateChangedParam->networkId;
    HDF_LOGD("%{public}s: hdiWpaStateChangedParam->networkId =%d", __func__, hdiWpaStateChangedParam->networkId);
    hdiWpaStateChangedParam->status = stateChangedParam->status;
    HDF_LOGD("%{public}s: hdiWpaStateChangedParam->status =%d", __func__, hdiWpaStateChangedParam->status);
    do {
        HDF_LOGD("%{public}s: stateChangedParam->bssid[0] = %x", __func__, stateChangedParam->bssid[0]);
        HDF_LOGD("%{public}s: stateChangedParam->bssid[5] = %x", __func__,
            stateChangedParam->bssid[WIFI_BSSID_LEN - 1]);
        if (FillData(&hdiWpaStateChangedParam->bssid, &hdiWpaStateChangedParam->bssidLen,
            stateChangedParam->bssid, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        HDF_LOGD("%{public}s: stateChangedParam->ssid[0] = %x", __func__, stateChangedParam->ssid[0]);
        HDF_LOGD("%{public}s: stateChangedParam->ssid[WIFI_SSID_LENGTH-1] = %x", __func__,
            stateChangedParam->ssid[WIFI_SSID_LENGTH - 1]);
        if (memcmp(stateChangedParam->ssid, "\0", 1) == 0) {
            hdiWpaStateChangedParam->ssidLen = 0;
            HDF_LOGE("%{public}s: hdiWpaStateChangedParam->ssidLen =%d", __func__, hdiWpaStateChangedParam->ssidLen);
        } else {
            if (FillData(&hdiWpaStateChangedParam->ssid, &hdiWpaStateChangedParam->ssidLen,
            stateChangedParam->ssid, strlen((char*)stateChangedParam->ssid)) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill ssid fail!", __func__);
            ret = HDF_FAILURE;
            }
        }
    } while (0);
    if (ret != HDF_SUCCESS) {
        if (hdiWpaStateChangedParam->bssid != NULL) {
            OsalMemFree(hdiWpaStateChangedParam->bssid);
            hdiWpaStateChangedParam->bssid = NULL;
        }
        if (hdiWpaStateChangedParam->ssid != NULL) {
            OsalMemFree(hdiWpaStateChangedParam->ssid);
            hdiWpaStateChangedParam->ssid = NULL;
        }
    }
    return ret;
}

static int32_t WpaFillWpaTempDisabledParam(struct WpaTempDisabledParam *tempDisabledParam,
    struct HdiWpaTempDisabledParam *hdiWpaTempDisabledParam)
{
    int32_t ret = HDF_SUCCESS;

    if (tempDisabledParam == NULL || hdiWpaTempDisabledParam == NULL) {
        HDF_LOGE("%{public}s: tempDisabledParam or hdiWpaTempDisabledParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiWpaTempDisabledParam->networkId = tempDisabledParam->networkId;
    hdiWpaTempDisabledParam->authFailures = tempDisabledParam->authFailures;
    hdiWpaTempDisabledParam->duration = tempDisabledParam->duration;
    do {
        if (FillData(&hdiWpaTempDisabledParam->reason, &hdiWpaTempDisabledParam->reasonLen,
            tempDisabledParam->reason, strlen((char*)tempDisabledParam->reason)) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiWpaTempDisabledParam->ssid, &hdiWpaTempDisabledParam->ssidLen,
            tempDisabledParam->ssid, strlen((char*)tempDisabledParam->ssid)) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill ssid fail!", __func__);
            ret = HDF_FAILURE;
        }
    } while (0);
    if (ret != HDF_SUCCESS) {
        if (hdiWpaTempDisabledParam->reason != NULL) {
            OsalMemFree(hdiWpaTempDisabledParam->reason);
            hdiWpaTempDisabledParam->reason = NULL;
        }
        if (hdiWpaTempDisabledParam->ssid != NULL) {
            OsalMemFree(hdiWpaTempDisabledParam->ssid);
            hdiWpaTempDisabledParam->ssid = NULL;
        }
    }
    return ret;
}

static int32_t WpaFillWpaAssociateRejectParam(struct WpaAssociateRejectParam *associateRejectParam,
    struct HdiWpaAssociateRejectParam *hdiWpaAssociateRejectParam)
{
    int32_t ret = HDF_SUCCESS;

    if (associateRejectParam == NULL || hdiWpaAssociateRejectParam == NULL) {
        HDF_LOGE("%{public}s: associateRejectParam or hdiWpaAssociateRejectParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiWpaAssociateRejectParam->statusCode = associateRejectParam->statusCode;
    hdiWpaAssociateRejectParam->timeOut = associateRejectParam->timeOut;
    if (FillData(&hdiWpaAssociateRejectParam->bssid, &hdiWpaAssociateRejectParam->bssidLen,
        associateRejectParam->bssid, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
    }
    if (ret != HDF_SUCCESS) {
        if (hdiWpaAssociateRejectParam->bssid != NULL) {
            OsalMemFree(hdiWpaAssociateRejectParam->bssid);
            hdiWpaAssociateRejectParam->bssid = NULL;
        }
    }
    return ret;
}

static int32_t WpaFillWpaRecvScanResultParam(struct WpaRecvScanResultParam *recvScanResultParam,
    struct HdiWpaRecvScanResultParam *hdiWpaRecvScanResultParam)
{
    int32_t ret = HDF_SUCCESS;

    if (recvScanResultParam == NULL || hdiWpaRecvScanResultParam == NULL) {
        HDF_LOGE("%{public}s: recvScanResultParam or hdiWpaRecvScanResultParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiWpaRecvScanResultParam->scanId = recvScanResultParam->scanId;
    return ret;
}

static int32_t WpaFillWpaAuthRejectParam(struct WpaAuthRejectParam *authRejectParam,
    struct HdiWpaAuthRejectParam *hdiWpaAuthRejectParam)
{
    int32_t ret = HDF_SUCCESS;

    if (authRejectParam == NULL || hdiWpaAuthRejectParam == NULL) {
        HDF_LOGE("%{public}s: authRejectParam or hdiWpaAuthRejectParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiWpaAuthRejectParam->statusCode = authRejectParam->statusCode;
    hdiWpaAuthRejectParam->authType = authRejectParam->authType;
    hdiWpaAuthRejectParam->authTransaction = authRejectParam->authTransaction;
    if (FillData(&hdiWpaAuthRejectParam->bssid, &hdiWpaAuthRejectParam->bssidLen,
        authRejectParam->bssid, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
    }
    if (ret != HDF_SUCCESS) {
        if (hdiWpaAuthRejectParam->bssid != NULL) {
            OsalMemFree(hdiWpaAuthRejectParam->bssid);
            hdiWpaAuthRejectParam->bssid = NULL;
        }
    }
    return ret;
}

static int32_t ProcessEventWpaDisconnect(struct HdfWpaRemoteNode *node,
    struct WpaDisconnectParam *disconnectParam, const char *ifName)
{
    struct HdiWpaDisconnectParam *hdiWpaDisconnectParam = NULL;
    int32_t ret = HDF_FAILURE;

    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventDisconnected == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiWpaDisconnectParam = (struct HdiWpaDisconnectParam *)OsalMemCalloc(sizeof(struct HdiWpaDisconnectParam));
    if ((hdiWpaDisconnectParam == NULL) || (WpaFillWpaDisconnectParam(disconnectParam,
        hdiWpaDisconnectParam) != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: hdiWpaDisconnectParam is NULL or disconnectParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventDisconnected(node->callbackObj, hdiWpaDisconnectParam, ifName);
    }
    HdiWpaDisconnectParamFree(hdiWpaDisconnectParam, true);
    return ret;
}

static int32_t ProcessEventWpaConnect(struct HdfWpaRemoteNode *node,
    struct WpaConnectParam *connectParam, const char *ifName)
{
    struct HdiWpaConnectParam *hdiWpaConnectParam = NULL;
    int32_t ret = HDF_FAILURE;

    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventConnected == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiWpaConnectParam = (struct HdiWpaConnectParam *)OsalMemCalloc(sizeof(struct HdiWpaConnectParam));
    if ((hdiWpaConnectParam == NULL) || (WpaFillWpaConnectParam(connectParam, hdiWpaConnectParam) != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: HdiWpaConnectParam is NULL or connectParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventConnected(node->callbackObj, hdiWpaConnectParam, ifName);
    }
    HdiWpaConnectParamFree(hdiWpaConnectParam, true);
    return ret;
}

static int32_t ProcessEventWpaBssidChange(struct HdfWpaRemoteNode *node,
    struct WpaBssidChangedParam *bssidChangeParam, const char *ifName)
{
    struct HdiWpaBssidChangedParam *hdiWpaBssidChangedParam = NULL;
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventBssidChanged == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiWpaBssidChangedParam = (struct HdiWpaBssidChangedParam *)OsalMemCalloc(sizeof(struct HdiWpaBssidChangedParam));
    if ((hdiWpaBssidChangedParam == NULL) || (WpaFillWpaBssidChangedParam(bssidChangeParam,
        hdiWpaBssidChangedParam) != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: hdiWpaBssidChangedParam is NULL or bssidChangeParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventBssidChanged(node->callbackObj, hdiWpaBssidChangedParam, ifName);
    }
    HdiWpaBssidChangedParamFree(hdiWpaBssidChangedParam, true);
    return ret;
}

static int32_t ProcessEventWpaStateChange(struct HdfWpaRemoteNode *node,
    struct WpaStateChangedParam *stateChangeParam, const char *ifName)
{
    struct HdiWpaStateChangedParam *hdiWpaStateChangedParam = NULL;
    int32_t ret = HDF_FAILURE;

    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventStateChanged == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiWpaStateChangedParam = (struct HdiWpaStateChangedParam *)OsalMemCalloc(sizeof(struct HdiWpaStateChangedParam));
    if ((hdiWpaStateChangedParam == NULL) || (WpaFillWpaStateChangedParam(stateChangeParam,
        hdiWpaStateChangedParam) != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: hdiWpaStateChangedParam is NULL or stateChangeParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventStateChanged(node->callbackObj, hdiWpaStateChangedParam, ifName);
    }
    HdiWpaStateChangedParamFree(hdiWpaStateChangedParam, true);
    return ret;
}

static int32_t ProcessEventWpaTempDisable(struct HdfWpaRemoteNode *node,
    struct WpaTempDisabledParam *tempDisabledParam, const char *ifName)
{
    struct HdiWpaTempDisabledParam *hdiWpaTempDisabledParam = NULL;
    int32_t ret = HDF_FAILURE;

    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventTempDisabled == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiWpaTempDisabledParam = (struct HdiWpaTempDisabledParam *)OsalMemCalloc(sizeof(struct HdiWpaTempDisabledParam));
    if ((hdiWpaTempDisabledParam == NULL) || (WpaFillWpaTempDisabledParam(tempDisabledParam,
        hdiWpaTempDisabledParam) != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: hdiWpaTempDisabledParam is NULL or tempDisabledParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventTempDisabled(node->callbackObj, hdiWpaTempDisabledParam, ifName);
    }
    HdiWpaTempDisabledParamFree(hdiWpaTempDisabledParam, true);
    return ret;
}

static int32_t ProcessEventWpaAssociateReject(struct HdfWpaRemoteNode *node,
    struct WpaAssociateRejectParam *associateRejectParam, const char *ifName)
{
    struct HdiWpaAssociateRejectParam *hdiWpaAssociateRejectParam = NULL;
    int32_t ret = HDF_FAILURE;

    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventAssociateReject == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiWpaAssociateRejectParam = (struct HdiWpaAssociateRejectParam *)
        OsalMemCalloc(sizeof(struct HdiWpaAssociateRejectParam));
    if ((hdiWpaAssociateRejectParam == NULL) || (WpaFillWpaAssociateRejectParam(associateRejectParam,
        hdiWpaAssociateRejectParam) != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: hdiWpaAssociateRejectParam is NULL or associateRejectParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventAssociateReject(node->callbackObj, hdiWpaAssociateRejectParam, ifName);
    }
    HdiWpaAssociateRejectParamFree(hdiWpaAssociateRejectParam, true);
    return ret;
}

static int32_t ProcessEventWpaWpsOverlap(struct HdfWpaRemoteNode *node,
     const char *ifName)
{
    int32_t ret = HDF_FAILURE;

    if (node == NULL || node->callbackObj == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = node->callbackObj->OnEventWpsOverlap(node->callbackObj, ifName);
    return ret;
}

static int32_t ProcessEventWpaWpsTimeout(struct HdfWpaRemoteNode *node,
     const char *ifName)
{
    int32_t ret = HDF_FAILURE;

    if (node == NULL || node->callbackObj == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = node->callbackObj->OnEventWpsTimeout(node->callbackObj, ifName);
    return ret;
}

static int32_t ProcessEventWpaAuthTimeout(struct HdfWpaRemoteNode *node, const char *ifName)
{
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = node->callbackObj->OnEventAuthTimeout(node->callbackObj, ifName);
    return ret;
}

static int32_t ProcessEventWpaRecvScanResult(struct HdfWpaRemoteNode *node,
    struct WpaRecvScanResultParam *recvScanResultParam, const char *ifName)
{
    struct HdiWpaRecvScanResultParam *hdiRecvScanResultParam = NULL;
    int32_t ret = HDF_FAILURE;

    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventScanResult == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiRecvScanResultParam  = (struct HdiWpaRecvScanResultParam *)
        OsalMemCalloc(sizeof(struct HdiWpaRecvScanResultParam));
    if ((hdiRecvScanResultParam == NULL) || (WpaFillWpaRecvScanResultParam(recvScanResultParam,
        hdiRecvScanResultParam) != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: hdiWpaAssociateRejectParam is NULL or associateRejectParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventScanResult(node->callbackObj, hdiRecvScanResultParam, ifName);
    }
    HdiWpaRecvScanResultParamFree(hdiRecvScanResultParam, true);
    return ret;
}

static int32_t ProcessEventWpaAuthReject(
    struct HdfWpaRemoteNode *node, struct WpaAuthRejectParam *authRejectParam, const char *ifName)
{
    struct HdiWpaAuthRejectParam *hdiWpaAuthRejectParam = NULL;
    int32_t ret = HDF_FAILURE;

    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventAuthReject == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiWpaAuthRejectParam =
        (struct HdiWpaAuthRejectParam *)OsalMemCalloc(sizeof(struct HdiWpaAuthRejectParam));
    if ((hdiWpaAuthRejectParam == NULL) ||
        (WpaFillWpaAuthRejectParam(authRejectParam, hdiWpaAuthRejectParam) != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: hdiWpaAuthRejectParam is NULL or authRejectParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventAuthReject(node->callbackObj, hdiWpaAuthRejectParam, ifName);
    }
    HdiWpaAuthRejectParamFree(hdiWpaAuthRejectParam, true);
    return ret;
}

int32_t ProcessEventStaNotify(struct HdfWpaRemoteNode *node, char *notifyParam, const char *ifName)
{
    int32_t ret = HDF_FAILURE;
    if (notifyParam == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_FAILURE;
    }
    char *notifyStr = (char*)malloc(BUF_SIZE);
    if (notifyStr == NULL) {
        HDF_LOGE("%{public}s notifyStr malloc failed", __func__);
        return HDF_FAILURE;
    }
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventStaNotify == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        free(notifyStr);
        return HDF_ERR_INVALID_PARAM;
    }
    if (memset_s(notifyStr, BUF_SIZE, 0, BUF_SIZE) != EOK) {
        HDF_LOGE("%{public}s memset failed", __func__);
        free(notifyStr);
        return HDF_FAILURE;
    }
    if (strcpy_s(notifyStr, BUF_SIZE, notifyParam) != EOK) {
        HDF_LOGE("%{public}s strcpy failed", __func__);
        free(notifyStr);
        return HDF_FAILURE;
    }
    ret = node->callbackObj->OnEventStaNotify(node->callbackObj, notifyStr, ifName);
    free(notifyStr);
    return ret;
}

static int32_t WpaFillWpaVendorExtInfo(struct WpaVendorExtInfo *wpaVendorExtInfo,
                                       struct WpaVendorInfo *wpaVendorInfo)
{
    if (wpaVendorExtInfo == NULL || wpaVendorInfo == NULL) {
        HDF_LOGE("%{public}s: wpaVendorExtInfo or wpaVendorInfo is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    wpaVendorInfo->type = wpaVendorExtInfo->type;
    wpaVendorInfo->freq = wpaVendorExtInfo->freq;
    wpaVendorInfo->width = wpaVendorExtInfo->width;
    wpaVendorInfo->id = wpaVendorExtInfo->id;
    wpaVendorInfo->status = wpaVendorExtInfo->status;
    wpaVendorInfo->reason = wpaVendorExtInfo->reason;
    if (FillData(&wpaVendorInfo->ssid, &wpaVendorInfo->ssidLen,
                 wpaVendorExtInfo->ssid, strlen((char *)wpaVendorExtInfo->ssid)) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s ssid fail !", __func__);
        return HDF_FAILURE;
    }

    if (FillData(&wpaVendorInfo->psk, &wpaVendorInfo->pskLen,
                 wpaVendorExtInfo->psk, strlen((char *)wpaVendorExtInfo->psk)) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s psk fail !", __func__);
        return HDF_FAILURE;
    }

    if (FillData(&wpaVendorInfo->devAddr, &wpaVendorInfo->devAddrLen,
                 wpaVendorExtInfo->devAddr, ETH_ADDR_LEN) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s devAddr fail !", __func__);
        return HDF_FAILURE;
    }

    if (FillData(&wpaVendorInfo->data, &wpaVendorInfo->dataLen,
                 wpaVendorExtInfo->data, strlen((char *)wpaVendorExtInfo->data)) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s data fail !", __func__);
        return HDF_FAILURE;
    }

    HDF_LOGI("wpaVendorInfo type %{public}d, freq %{public}d, reason %{public}d, "
             "id %{public}d status %{public}d!",
             wpaVendorInfo->type, wpaVendorInfo->freq, wpaVendorInfo->reason,
             wpaVendorInfo->id, wpaVendorInfo->status);
    return HDF_SUCCESS;
}

static int32_t ProcessEventWpaVendorExt(struct HdfWpaRemoteNode *node,
    struct WpaVendorExtInfo *wpaVendorExtInfo, const char *ifName)
{
    HDF_LOGI("%{public}s: ifName => %{public}s ; ", __func__, ifName);
    struct WpaVendorInfo wpaVendorInfo;
    int32_t ret = HDF_FAILURE;
    if (wpaVendorExtInfo == NULL) {
        HDF_LOGE("%{public}s: wpaVendorExtInfo is NULL !", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventVendorCb == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (WpaFillWpaVendorExtInfo(wpaVendorExtInfo, &wpaVendorInfo) != HDF_SUCCESS) {
        ret = HDF_FAILURE;
        HDF_LOGE("%{public}s: wpaVendorInfo is NULL or associateRejectParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventVendorCb(node->callbackObj, &wpaVendorInfo, ifName);
    }
    HDF_LOGI("%{public}s: res %{public}d!", __func__, ret);
    return ret;
}
static int32_t HdfStaDealEvent(uint32_t event, struct HdfWpaRemoteNode *pos, void *data, const char *ifName)
{
    int32_t ret = HDF_FAILURE;
    switch (event) {
        case WPA_EVENT_DISCONNECT:
            ret = ProcessEventWpaDisconnect(pos, (struct WpaDisconnectParam *)data, ifName);
            break;
        case WPA_EVENT_CONNECT:
            ret = ProcessEventWpaConnect(pos, (struct WpaConnectParam *)data, ifName);
            break;
        case WPA_EVENT_BSSID_CHANGE:
            ret = ProcessEventWpaBssidChange(pos, (struct WpaBssidChangedParam *)data, ifName);
            break;
        case WPA_EVENT_STATE_CHANGED:
            ret = ProcessEventWpaStateChange(pos, (struct WpaStateChangedParam *)data, ifName);
            break;
        case WPA_EVENT_TEMP_DISABLE:
            ret = ProcessEventWpaTempDisable(pos, (struct WpaTempDisabledParam *)data, ifName);
            break;
        case WPA_EVENT_ASSOCIATE_REJECT:
            ret = ProcessEventWpaAssociateReject(pos, (struct WpaAssociateRejectParam *)data, ifName);
            break;
        case WPA_EVENT_WPS_OVERLAP:
            ret = ProcessEventWpaWpsOverlap(pos, ifName);
            break;
        case WPA_EVENT_WPS_TIMEMOUT:
            ret = ProcessEventWpaWpsTimeout(pos, ifName);
            break;
        case WPA_EVENT_AUTH_TIMEOUT:
            ProcessEventWpaAuthTimeout(pos, ifName);
            break;
        case WPA_EVENT_RECV_SCAN_RESULT:
            ret = ProcessEventWpaRecvScanResult(pos, (struct WpaRecvScanResultParam *)data, ifName);
            break;
        case WPA_EVENT_STA_AUTH_REJECT:
            ret = ProcessEventWpaAuthReject(pos, (struct WpaAuthRejectParam *)data, ifName);
            break;
        case WPA_EVENT_STA_NOTIFY:
            ret = ProcessEventStaNotify(pos, (char *)data, ifName);
            break;
        default:
            HDF_LOGE("%{public}s: unknown eventId:%{public}d", __func__, event);
            break;
    }
    return ret;
}

static int32_t HdfP2pDealEvent(uint32_t event, struct HdfWpaRemoteNode *pos, void *data, const char *ifName)
{
    int32_t ret = HDF_FAILURE;
    switch (event) {
        case WPA_EVENT_DEVICE_FOUND:
            ret = ProcessEventP2pDeviceFound(pos, (struct P2pDeviceInfoParam *)data, ifName);
            break;
        case WPA_EVENT_DEVICE_LOST:
            ret = ProcessEventP2pDeviceLost(pos, (struct P2pDeviceLostParam *)data, ifName);
            break;
        case WPA_EVENT_GO_NEGOTIATION_REQUEST:
            ret = ProcessEventP2pGoNegotiationRequest(pos, (struct P2pGoNegotiationRequestParam *)data, ifName);
            break;
        case WPA_EVENT_GO_NEGOTIATION_COMPLETED:
            ret = ProcessEventP2pGoNegotiationCompleted(pos, (struct P2pGoNegotiationCompletedParam *)data, ifName);
            break;
        case WPA_EVENT_INVITATION_RECEIVED:
            ret = ProcessEventP2pInvitationReceived(pos, (struct P2pInvitationReceivedParam *)data, ifName);
            break;
        case WPA_EVENT_INVITATION_RESULT:
            ret = ProcessEventP2pInvitationResult(pos, (struct P2pInvitationResultParam *)data, ifName);
            break;
        case WPA_EVENT_GROUP_FORMATION_SUCCESS:
            ret = ProcessEventP2pGroupFormationSuccess(pos, ifName);
            break;
        case WPA_EVENT_GROUP_FORMATION_FAILURE:
            ret = ProcessEventP2pGroupFormationFailure(pos, (char *)data, ifName);
            break;
        case WPA_EVENT_GROUP_START:
            ret = ProcessEventP2pGroupStarted(pos, (struct P2pGroupStartedParam *)data, ifName);
            break;
        case WPA_EVENT_GROUP_REMOVED:
            ret = ProcessEventP2pGroupRemoved(pos, (struct P2pGroupRemovedParam *)data, ifName);
            break;
        case WPA_EVENT_PROVISION_DISCOVERY_COMPLETED:
            ret = ProcessEventP2pProvisionDiscoveryCompleted(pos, (struct P2pProvisionDiscoveryCompletedParam *)data,
                ifName);
            break;
        case WPA_EVENT_FIND_STOPPED:
            ret = ProcessEventP2pFindStopped(pos, ifName);
            break;
        case WPA_EVENT_SERV_DISC_REQ:
            ret = ProcessEventP2pServDiscReq(pos, (struct P2pServDiscReqInfoParam *)data, ifName);
            break;
        case WPA_EVENT_SERV_DISC_RESP:
            ret = ProcessEventP2pServDiscResp(pos, (struct P2pServDiscRespParam *)data, ifName);
            break;
        case WPA_EVENT_STA_CONNECT_STATE:
            ret = ProcessEventP2pStaConnectState(pos, (struct P2pStaConnectStateParam *)data, ifName);
            break;
        case WPA_EVENT_IFACE_CREATED:
            ret = ProcessEventP2pIfaceCreated(pos, (struct P2pIfaceCreatedParam *)data, ifName);
            break;
        case WPA_EVENT_STA_NOTIFY:
            ret = ProcessEventStaNotify(pos, (char *)data, ifName);
            break;
        default:
            HDF_LOGE("%{public}s: unknown eventId:%{public}d", __func__, event);
            break;
    }
    return ret;
}

static int32_t HdfVendorExtDealEvent(uint32_t event, struct HdfWpaRemoteNode *pos, void *data, const char *ifName)
{
    int32_t ret = HDF_FAILURE;
    switch (event) {
        case WPA_EVENT_VENDOR_EXT:
            ret = ProcessEventWpaVendorExt(pos, (struct WpaVendorExtInfo *)data, ifName);
            break;
        default:
            HDF_LOGE("%{public}s: unknown eventId:%{public}d", __func__, event);
            break;
    }
    return ret;
}


static int32_t HdfWpaCallbackFun(uint32_t event, void *data, const char *ifName)
{
    struct HdfWpaRemoteNode *pos = NULL;
    struct DListHead *head = NULL;
    int32_t ret = HDF_FAILURE;

    (void)OsalMutexLock(&HdfWpaStubDriver()->mutex);
    head = &HdfWpaStubDriver()->remoteListHead;
    HDF_LOGD("%s: enter HdfWpaCallbackFun event =%u", __FUNCTION__, event);
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: data or ifName is NULL!", __func__);
        (void)OsalMutexUnlock(&HdfWpaStubDriver()->mutex);
        return HDF_ERR_INVALID_PARAM;
    }
    DLIST_FOR_EACH_ENTRY(pos, head, struct HdfWpaRemoteNode, node) {
        if (pos == NULL) {
            HDF_LOGE("%{public}s: pos is NULL", __func__);
            break;
        }
        if (pos->callbackObj == NULL) {
            HDF_LOGW("%{public}s: pos->callbackObj NULL", __func__);
            continue;
        }
        if (pos->service == NULL) {
            HDF_LOGW("%{public}s: pos->service NULL", __func__);
            continue;
        }
        if (strncmp(ifName, "wlan", strlen("wlan")) == 0 || strncmp(ifName, "common", strlen("common")) == 0) {
            ret = HdfStaDealEvent(event, pos, data, ifName);
        } else if (strncmp(ifName, "chba", strlen("chba")) == 0 ||
            strncmp(ifName, "p2p-chba", strlen("p2p-chba")) == 0) {
            ret = HdfVendorExtDealEvent(event, pos, data, ifName);
        } else if (strncmp(ifName, "p2p", strlen("p2p")) == 0) {
            ret = HdfP2pDealEvent(event, pos, data, ifName);
        } else {
            HDF_LOGE("%{public}s: ifName is error %{public}s", __func__, ifName);
        }
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: dispatch code fialed, error code: %{public}d", __func__, ret);
        }
    }
    (void)OsalMutexUnlock(&HdfWpaStubDriver()->mutex);
    return ret;
}

int32_t WpaInterfaceRegisterEventCallback(struct IWpaInterface *self, struct IWpaCallback *cbFunc,
    const char *ifName)
{
    int32_t ret = HDF_FAILURE;

    (void)self;
    pthread_mutex_lock(&g_interfaceLock);
    if (cbFunc == NULL || ifName == NULL) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    int nameLen = strlen(ifName);
    if (IsSockRemoved(ifName, nameLen) == 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("invalid opt");
        return HDF_FAILURE;
    }
    do {
        HDF_LOGE("%{public}s: call HdfWpaAddRemoteObj", __func__);
        ret = HdfWpaAddRemoteObj(cbFunc, ifName);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: HdfSensorAddRemoteObj false", __func__);
            break;
        }
        ret = WpaRegisterEventCallback(HdfWpaCallbackFun, WIFI_WPA_TO_HAL_CLIENT, ifName);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: Register failed!, error code: %{public}d", __func__, ret);
            HdfWpaDelRemoteObj(cbFunc);
            break;
        }
    } while (0);
    pthread_mutex_unlock(&g_interfaceLock);
    return ret;
}

int32_t WpaInterfaceUnregisterEventCallback(struct IWpaInterface *self, struct IWpaCallback *cbFunc,
    const char *ifName)
{
    (void)self;
    pthread_mutex_lock(&g_interfaceLock);
    if (cbFunc == NULL || ifName == NULL) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    int nameLen = strlen(ifName);
    if (IsSockRemoved(ifName, nameLen) == 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("invalid opt");
        return HDF_FAILURE;
    }
    HdfWpaDelRemoteObj(cbFunc);
    if (DListIsEmpty(&HdfWpaStubDriver()->remoteListHead)) {
        int32_t ret = WpaUnregisterEventCallback(HdfWpaCallbackFun, WIFI_WPA_TO_HAL_CLIENT, ifName);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: Unregister failed!, error code: %{public}d", __func__, ret);
        }
    }
    pthread_mutex_unlock(&g_interfaceLock);
    return HDF_SUCCESS;
}

static void SplitCmdString(const char *startCmd, struct StWpaMainParam *pParam)
{
    if (pParam == NULL) {
        return;
    }
    if (startCmd == NULL) {
        pParam->argc = 0;
        return;
    }
    const char *p = startCmd;
    int i = 0;
    int j = 0;
    while (*p != '\0') {
        if (*p == ' ') {
            if (j <= MAX_WPA_MAIN_ARGV_LEN - 1) {
                pParam->argv[i][j] = '\0';
            } else {
                pParam->argv[i][MAX_WPA_MAIN_ARGV_LEN - 1] = '\0';
            }
            ++i;
            j = 0;
            if (i >= MAX_WPA_MAIN_ARGC_NUM) {
                break;
            }
        } else {
            if (j < MAX_WPA_MAIN_ARGV_LEN - 1) {
                pParam->argv[i][j] = *p;
                ++j;
            }
        }
        ++p;
    }
    if (i >= MAX_WPA_MAIN_ARGC_NUM) {
        pParam->argc = MAX_WPA_MAIN_ARGC_NUM;
    } else {
        pParam->argc = i + 1;
    }
    return;
}


static void *WpaThreadMain(void *p)
{
    const char *startCmd;
    struct StWpaMainParam param = {0};
    char *tmpArgv[MAX_WPA_MAIN_ARGC_NUM] = {0};

    if (p == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return NULL;
    }
    startCmd = (const char *)p;
    SplitCmdString(startCmd, &param);
    for (int i = 0; i < param.argc; i++) {
        tmpArgv[i] = param.argv[i];
    }
    int ret = wpa_main(param.argc, tmpArgv);
    HDF_LOGI("%{public}s: run wpa_main ret:%{public}d.", __func__, ret);
    return NULL;
}

static int32_t StartWpaSupplicant(const char *moduleName, const char *startCmd)
{
    int32_t ret;

    if (moduleName == NULL || startCmd == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM ;
    }
    ret = pthread_create(&g_tid, NULL, WpaThreadMain, (void *)startCmd);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Create wpa thread failed, error code: %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_setname_np(g_tid, "WpaMainThread");
    HDF_LOGI("%{public}s: pthread_create successfully.", __func__);
    usleep(WPA_SLEEP_TIME);
    WifiWpaInterface *pWpaInterface = GetWifiWpaGlobalInterface();
    if (pWpaInterface == NULL) {
        HDF_LOGE("Get wpa interface failed!");
        return HDF_FAILURE;
    }
    if (pWpaInterface->wpaCliConnect(pWpaInterface) < 0) {
        HDF_LOGE("Failed to connect to wpa!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
int32_t WpaInterfaceAddWpaIface(struct IWpaInterface *self, const char *ifName, const char *confName)
{
    (void)self;
    if (ifName == NULL || confName == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM ;
    }
    HDF_LOGI("enter %{public}s Ready to add iface, ifName: %{public}s, confName: %{public}s",
        __func__, ifName, confName);
    WifiWpaInterface *pWpaInterface = GetWifiWpaGlobalInterface();
    if (pWpaInterface == NULL) {
        HDF_LOGE("Get wpa interface failed!");
        return HDF_FAILURE;
    }
    AddInterfaceArgv addInterface = {0};
    if (strncmp(ifName, "wlan", strlen("wlan")) == 0) {
        if (strcpy_s(addInterface.name, sizeof(addInterface.name) - 1, ifName) != EOK ||
            strcpy_s(addInterface.confName, sizeof(addInterface.confName) - 1,
            CONFIG_ROOR_DIR"/wpa_supplicant/wpa_supplicant.conf") != EOK) {
            return HDF_FAILURE;
        }
    } else if (strncmp(ifName, "p2p", strlen("p2p")) == 0) {
        if (strcpy_s(addInterface.name, sizeof(addInterface.name) - 1, ifName) != EOK ||
            strcpy_s(addInterface.confName, sizeof(addInterface.confName) - 1,
            CONFIG_ROOR_DIR"/wpa_supplicant/p2p_supplicant.conf") != EOK) {
            return HDF_FAILURE;
        }
    }  else if (strncmp(ifName, "chba0", strlen("chba0")) == 0) {
        if (strcpy_s(addInterface.name, sizeof(addInterface.name) - 1, ifName) != EOK ||
            strcpy_s(addInterface.confName, sizeof(addInterface.confName) - 1,
                     CONFIG_ROOR_DIR"/wpa_supplicant/p2p_supplicant.conf") != EOK) {
            return HDF_FAILURE;
        }
    } else {
        HDF_LOGE("%{public}s Wrong ifname!", __func__);
        return HDF_FAILURE;
    }
    if (pWpaInterface->wpaCliAddIface(pWpaInterface, &addInterface, true) < 0) {
        HDF_LOGE("%{public}s Failed to add wpa iface!", __func__);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s Add interface finish", __func__);
    return HDF_SUCCESS;
}


int32_t WpaInterfaceRemoveWpaIface(struct IWpaInterface *self, const char *ifName)
{
    (void)self;
    HDF_LOGI("enter %{public}s", __func__);
    pthread_mutex_lock(&g_interfaceLock);
    if (ifName == NULL) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM ;
    }
    HDF_LOGI("enter %{public}s Ready to Remove iface, ifName: %{public}s", __func__, ifName);
    int ret = -1;
    WifiWpaInterface *pWpaInterface = GetWifiWpaGlobalInterface();
    if (pWpaInterface == NULL) {
        HDF_LOGE("Get wpa interface failed!");
        return HDF_FAILURE;
    }
    ret = pWpaInterface->wpaCliRemoveIface(pWpaInterface, ifName);
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s Remove wpa iface finish, ifName: %{public}s ret = %{public}d", __func__, ifName, ret);
    return (ret == 0 ? HDF_SUCCESS : HDF_FAILURE);
}

static int32_t StopWpaSupplicant(void)
{
    /*Do nothing here,waiting for IWpaInterfaceReleaseInstance to destroy the wpa service. */
    WifiWpaInterface *pWpaInterface = GetWifiWpaGlobalInterface();
    if (pWpaInterface == NULL) {
        HDF_LOGE("%{public}s: Get wpa global interface failed!", __func__);
        return HDF_FAILURE;
    }
    int ret = pWpaInterface->wpaCliTerminate();
    if (ret != 0) {
        HDF_LOGE("%{public}s: wpaCliTerminate failed!", __func__);
    } else {
        HDF_LOGI("%{public}s: wpaCliTerminate suc!", __func__);
    }
    return HDF_SUCCESS;
}

int32_t WpaInterfaceStart(struct IWpaInterface *self)
{
    int32_t ret;

    (void)self;
    HDF_LOGI("enter %{public}s: wpa_supplicant begin to start", __func__);
    InitWifiWpaGlobalInterface();
    WifiWpaInterface *pWpaInterface = GetWifiWpaGlobalInterface();
    if (pWpaInterface == NULL) {
        HDF_LOGI("fail get global interface");
        return HDF_FAILURE;
    }
    pthread_mutex_lock(&g_interfaceLock);
    ret = StartWpaSupplicant(WPA_SUPPLICANT_NAME, START_CMD);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: StartWpaSupplicant failed, error code: %{public}d", __func__, ret);
        pthread_mutex_unlock(&g_interfaceLock);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: wpa_supplicant start successfully!", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceStop(struct IWpaInterface *self)
{
    int32_t ret;

    (void)self;
    pthread_mutex_lock(&g_interfaceLock);
    HDF_LOGI("enter %{public}s: wpa_supplicant begin to stop", __func__);
    ret = StopWpaSupplicant();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Wifi stop failed, error code: %{public}d", __func__, ret);
        pthread_mutex_unlock(&g_interfaceLock);
        return HDF_FAILURE;
    }
    ReleaseWifiStaInterface(0);
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: wpa_supplicant stop successfully!", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceReassociate(struct IWpaInterface *self, const char *ifName)
{
    (void)self;
    HDF_LOGI("enter %{public}s ", __func__);
    pthread_mutex_lock(&g_interfaceLock);
    if (ifName == NULL) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdReassociate(pStaIfc);
    if (ret < 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: wpaCliCmdReassociate fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: wpaCliCmdReassociate success ret = %{public}d", __func__, ret);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceStaShellCmd(struct IWpaInterface *self, const char *ifName, const char *cmd)
{
    (void)self;
    HDF_LOGI("enter %{public}s", __func__);
    pthread_mutex_lock(&g_interfaceLock);
    if (ifName == NULL || cmd == NULL) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    WifiWpaStaInterface *pStaIfc = GetWifiStaInterface(ifName);
    if (pStaIfc == NULL) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: pStaIfc = NULL", __func__);
        return HDF_FAILURE;
    }
    int ret = pStaIfc->wpaCliCmdStaShellCmd(pStaIfc, cmd);
    if (ret < 0) {
        pthread_mutex_unlock(&g_interfaceLock);
        HDF_LOGE("%{public}s: fail ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(&g_interfaceLock);
    HDF_LOGI("%{public}s: success", __func__);
    return HDF_SUCCESS;
}
