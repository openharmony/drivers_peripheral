int32_t WpaInterfaceP2pGetPeer(struct IWpaInterface *self, const char *ifName, const char *bssid,
    struct HdiP2pDeviceInfo *info)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    if (ifName == NULL || info == NULL || bssid == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(GetInterfaceLock());
    char *reply;
    const int replySize = REPLY_SIZE;
    char cmd[CMD_SIZE];

    reply = (char *)malloc(replySize);
    if (reply == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s reply is NULL!", __func__);
        return HDF_FAILURE;
    }
    
    int32_t ret = 0;
    (void)self;

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s P2P_PEER %s", ifName, bssid);
    if (ret < 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{private}s, count = %{public}d", __func__, cmd, ret);
        free(reply);
        return HDF_FAILURE;
    }

    if (WpaCliCmd(cmd, reply, REPLY_SIZE) != 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("P2P_PEER command failed!");
        free(reply);
        return HDF_FAILURE;
    }

    if (strstr(reply, "\n") == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s reply is error", __func__);
        free(reply);
        return HDF_FAILURE;
    }
    char *savedPtr = NULL;
    char *token = strtok_r(reply, "\n", &savedPtr);
    info->srcAddress = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (ETH_ADDR_LEN + 1));
    if (info->srcAddress == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("malloc srcAddress failed!");
        free(reply);
        HdiP2pDeviceInfoFree(info, false);
        return HDF_FAILURE;
    }
    info->p2pDeviceAddress = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (ETH_ADDR_LEN + 1));
    if (info->p2pDeviceAddress == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("malloc p2pDeviceAddress failed!");
        free(reply);
        HdiP2pDeviceInfoFree(info, false);
        return HDF_FAILURE;
    }
    info->primaryDeviceType = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * WIFI_P2P_DEVICE_TYPE_LENGTH);
    if (info->primaryDeviceType == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("malloc primaryDeviceType failed!");
        free(reply);
        HdiP2pDeviceInfoFree(info, false);
        return HDF_FAILURE;
    }
    info->deviceName = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * WIFI_P2P_DEVICE_NAME_LENGTH);
    if (info->deviceName == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("malloc deviceName failed!");
        free(reply);
        HdiP2pDeviceInfoFree(info, false);
        return HDF_FAILURE;
    }
    info->wfdDeviceInfo = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * WIFI_P2P_WFD_DEVICE_INFO_LENGTH);
    if (info->wfdDeviceInfo == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("malloc wfdDeviceInfo failed!");
        free(reply);
        HdiP2pDeviceInfoFree(info, false);
        return HDF_FAILURE;
    }
    info->operSsid = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * WIFI_P2P_DEVICE_NAME_LENGTH);
    if (info->operSsid == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("malloc operSsid failed!");
        free(reply);
        HdiP2pDeviceInfoFree(info, false);
        return HDF_FAILURE;
    }
    info->srcAddressLen = ETH_ADDR_LEN + 1;
    info->p2pDeviceAddressLen = ETH_ADDR_LEN + 1;
    info->primaryDeviceTypeLen = WIFI_P2P_DEVICE_TYPE_LENGTH;
    info->deviceNameLen = WIFI_P2P_DEVICE_NAME_LENGTH;
    info->wfdDeviceInfoLen = WIFI_P2P_WFD_DEVICE_INFO_LENGTH;
    info->operSsidLen = WIFI_P2P_DEVICE_NAME_LENGTH;
    uint8_t tmpBssid[ETH_ADDR_LEN] = {0};
    hwaddr_aton(token, tmpBssid);
    if (strcpy_s((char *)info->p2pDeviceAddress, ETH_ADDR_LEN + 1, (char *)tmpBssid) != EOK) {
        HDF_LOGE("%{public}s strcpy failed", __func__);
    }
    while (token != NULL) {
        struct HdiWpaKeyValue retMsg = {{0}, {0}};
        GetStrKeyVal(token, "=", &retMsg);
        if (strncmp(retMsg.key, "pri_dev_type", strlen("pri_dev_type")) == 0) {
            if (strcpy_s((char *)info->primaryDeviceType, WIFI_P2P_DEVICE_TYPE_LENGTH + 1, retMsg.value) != EOK) {
                HDF_LOGE("%{public}s strcpy failed", __func__);
            }
        } else if (strncmp(retMsg.key, "device_name", strlen("device_name")) == 0) {
            if (strcpy_s((char *)info->deviceName, WIFI_P2P_DEVICE_NAME_LENGTH + 1, retMsg.value) != EOK) {
                HDF_LOGE("%{public}s strcpy failed", __func__);
            }
        } else if (strncmp(retMsg.key, "config_methods", strlen("config_methods")) == 0) {
            info->configMethods = Hex2Dec(retMsg.value);
        } else if (strncmp(retMsg.key, "dev_capab", strlen("dev_capab")) == 0) {
            info->deviceCapabilities = Hex2Dec(retMsg.value);
        } else if (strncmp(retMsg.key, "group_capab", strlen("group_capab")) == 0) {
            info->groupCapabilities = Hex2Dec(retMsg.value);
        } else if (strncmp(retMsg.key, "oper_ssid", strlen("oper_ssid")) == 0) {
            if (strcpy_s((char *)info->operSsid, WIFI_P2P_DEVICE_NAME_LENGTH + 1, retMsg.value) != EOK) {
                HDF_LOGE("%{public}s strcpy failed", __func__);
            }
        }
        token = strtok_r(NULL, "\n", &savedPtr);
    }
    pthread_mutex_unlock(GetInterfaceLock());
    free(reply);
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pGetGroupCapability(struct IWpaInterface *self, const char *ifName,
    const char *bssid, int32_t *cap)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    if (ifName == NULL || bssid == NULL || cap == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(GetInterfaceLock());
    char *reply;
    const int replySize = REPLY_SIZE;
    char cmd[CMD_SIZE];

    reply = (char *)malloc(replySize);
    if (reply == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s reply is NULL!", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = 0;
    (void)self;

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s P2P_PEER %s", ifName, bssid);
    if (ret < 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{private}s, count = %{public}d", __func__, cmd, ret);
        free(reply);
        return HDF_FAILURE;
    }

    if (WpaCliCmd(cmd, reply, REPLY_SIZE) != 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("P2P_PEER command failed!");
        free(reply);
        return HDF_FAILURE;
    }

    if (strstr(reply, "\n") == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s reply is error", __func__);
        free(reply);
        return HDF_FAILURE;
    }
    char *savedPtr = NULL;
    char *token = strtok_r(reply, "\n", &savedPtr);

    while (token != NULL) {
        struct HdiWpaKeyValue retMsg = {{0}, {0}};
        GetStrKeyVal(token, "=", &retMsg);
        if (strncmp(retMsg.key, "group_capab", strlen("group_capab")) == 0) {
            *cap = Hex2Dec(retMsg.value);
        }
        token = strtok_r(NULL, "\n", &savedPtr);
    }
    pthread_mutex_unlock(GetInterfaceLock());
    free(reply);
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pListNetworks(struct IWpaInterface *self, const char *ifName,
    struct HdiP2pNetworkList *infoList)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    if (ifName == NULL || infoList == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(GetInterfaceLock());
    char *reply;
    const int replySize = REPLY_SIZE;
    char cmd[CMD_SIZE];
    reply = (char *)malloc(replySize);
    if (reply == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s reply is NULL!", __func__);
        return HDF_FAILURE;
    }

    (void)self;
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s LIST_NETWORKS", ifName) < 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("snprintf err");
        free(reply);
        return HDF_FAILURE;
    }
    if (WpaCliCmd(cmd, reply, REPLY_SIZE) != 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("LIST_NETWORKS command failed!");
        free(reply);
        return HDF_FAILURE;
    }

    char *token = strstr(reply, "\n");
    if (token == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s token is NULL!", __func__);
        free(reply);
        return HDF_FAILURE;
    }
    char *tmpPos = token + 1;
    while ((tmpPos = strstr(tmpPos, "\n")) != NULL) {
        infoList->infoNum += 1;
        ++tmpPos;
    }
    if (infoList->infoNum <= 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s infoList->infoNum <= 0", __func__);
        free(reply);
        return HDF_FAILURE;
    }
    infoList->infos = (struct HdiP2pNetworkInfo *)OsalMemCalloc(sizeof(struct HdiP2pNetworkInfo) * infoList->infoNum);
    if (infoList->infos == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("malloc infos failed!");
        free(reply);
        return HDF_FAILURE;
    }
    infoList->infosLen = (uint32_t)infoList->infoNum;
    char *tmpBuf = token + 1;
    char *savedPtr = NULL;
    token = strtok_r(tmpBuf, "\n", &savedPtr);
    int index = 0;
    while (token != NULL) {
        if (index >= infoList->infoNum) {
            break;
        }
        infoList->infos[index].ssid = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * WIFI_SSID_LENGTH);
        if (infoList->infos[index].ssid == NULL) {
            HDF_LOGE("malloc ssid failed!");
            HdiP2pNetworkInfoFree(&(infoList->infos[index]), true);
            break;
        }
        infoList->infos[index].ssidLen = WIFI_SSID_LENGTH;
        infoList->infos[index].bssid = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * (ETH_ADDR_LEN + 1));
        if (infoList->infos[index].bssid == NULL) {
            HDF_LOGE("malloc bssid failed!");
            HdiP2pNetworkInfoFree(&(infoList->infos[index]), true);
            break;
        }
        infoList->infos[index].bssidLen = ETH_ADDR_LEN + 1;
        infoList->infos[index].flags = (uint8_t *)OsalMemCalloc(sizeof(uint8_t) * WIFI_NETWORK_FLAGS_LENGTH);
        if (infoList->infos[index].flags == NULL) {
            HDF_LOGE("malloc flags failed!");
            HdiP2pNetworkInfoFree(&(infoList->infos[index]), true);
            break;
        }
        infoList->infos[index].flagsLen = WIFI_NETWORK_FLAGS_LENGTH;
        GetHalNetworkInfos(token, &(infoList->infos[index]));
        index++;
        token = strtok_r(NULL, "\n", &savedPtr);
    }
    pthread_mutex_unlock(GetInterfaceLock());
    free(reply);
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceP2pSaveConfig(struct IWpaInterface *self, const char *ifName)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    (void)ifName;
    pthread_mutex_lock(GetInterfaceLock());
    WifiWpaP2pInterface *pMainIfc = GetWifiWapP2pInterface(ifName);
    if (pMainIfc == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: pMainIfc is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    P2pSupplicantErrCode ret = pMainIfc->wpaP2pCliCmdStoreConfig(pMainIfc);
    if (ret != P2P_SUP_ERRCODE_SUCCESS) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: fail, ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceDeliverP2pData(struct IWpaInterface *self, const char *ifName,
    int32_t cmdType, int32_t dataType, const char *carryData)
{
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    (void)self;
    (void)ifName;
    char cmd[CMD_SIZE] = {0};
    char buf[CMD_SIZE] = {0};

    int32_t ret = 0;
    if (ifName == NULL) {
        HDF_LOGE("%{public}s: input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    pthread_mutex_lock(GetInterfaceLock());
    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1,
        "IFNAME=%s P2P_DELIVER_DATA cmdType=%d dataType=%d carryData=%s", ifName, cmdType, dataType, carryData);
    if (ret < 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s snprintf_s failed, cmd: %{private}s, count = %{public}d", __func__, cmd, ret);
        return HDF_FAILURE;
    }
    if (WpaCliCmd(cmd, buf, sizeof(buf)) != 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s command failed!", __func__);
        return HDF_FAILURE;
    }
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t WpaInterfaceVendorExtProcessCmd(struct IWpaInterface *self, const char *ifName, const char *cmd)
{
#define NEW_CMD_MAX_LEN 400
    HDF_LOGI("Ready to enter hdi %{public}s", __func__);
    int32_t ret = 0;
    (void)self;
    if (cmd == NULL || ifName == NULL) {
        HDF_LOGE("%{public}s input parameter invalid!", __func__);
        return HDF_ERR_INVALID_PARAM ;
    }
    pthread_mutex_lock(GetInterfaceLock());
    char *reply;
    const int replySize = REPLY_SIZE;
    reply = (char *)malloc(replySize);
    if (reply == NULL) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s reply is NULL!", __func__);
        return HDF_FAILURE;
    }

    char newCmd[NEW_CMD_MAX_LEN] = {0};
    if (snprintf_s(newCmd, sizeof(newCmd), sizeof(newCmd) - 1, "IFNAME=%s %s", ifName, cmd) < 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s: snprintf_s is failed, error code: %{public}d", __func__, ret);
        free(reply);
        return HDF_FAILURE;
    }
 
    if (WpaCliCmd(newCmd, reply, replySize) < 0) {
        pthread_mutex_unlock(GetInterfaceLock());
        HDF_LOGE("%{public}s WpaCliCmd failed!", __func__);
        free(reply);
        return HDF_FAILURE;
    }
<<<<<<< HEAD

    HDF_LOGI("%{public}s reply %{public}s !", __func__, reply);
=======
    pthread_mutex_unlock(GetInterfaceLock());
    HDF_LOGI("%{public}s cmd %{public}s reply %{public}s !", __func__, newCmd, reply);
>>>>>>> da9bf65ec (TicketNo:DTS2024081411562)
    ret = atoi(reply);
    free(reply);
    return ret;
}

static int32_t WpaFillP2pDeviceFoundParam(struct P2pDeviceInfoParam *deviceInfoParam,
    struct HdiP2pDeviceInfoParam *hdiP2pDeviceInfoParam)
{
    int32_t ret = 0;
    if (deviceInfoParam == NULL || hdiP2pDeviceInfoParam == NULL) {
        HDF_LOGE("%{public}s: deviceInfoParam or hdiP2pDeviceInfo is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pDeviceInfoParam->configMethods = deviceInfoParam->configMethods;
    hdiP2pDeviceInfoParam->deviceCapabilities = deviceInfoParam->deviceCapabilities;
    hdiP2pDeviceInfoParam->groupCapabilities = deviceInfoParam->groupCapabilities;
    hdiP2pDeviceInfoParam->wfdLength = deviceInfoParam->wfdLength;

    do {
        if (FillData(&hdiP2pDeviceInfoParam->srcAddress, &hdiP2pDeviceInfoParam->srcAddressLen,
            deviceInfoParam->srcAddress, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pDeviceInfoParam->p2pDeviceAddress, &hdiP2pDeviceInfoParam->p2pDeviceAddressLen,
            deviceInfoParam->p2pDeviceAddress, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pDeviceInfoParam->primaryDeviceType, &hdiP2pDeviceInfoParam->primaryDeviceTypeLen,
            deviceInfoParam->primaryDeviceType, WIFI_P2P_DEVICE_TYPE_LENGTH) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pDeviceInfoParam->deviceName, &hdiP2pDeviceInfoParam->deviceNameLen,
            deviceInfoParam->deviceName, WIFI_P2P_DEVICE_NAME_LENGTH) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (deviceInfoParam->wfdLength != 0 &&
            FillData(&hdiP2pDeviceInfoParam->wfdDeviceInfo, &hdiP2pDeviceInfoParam->wfdDeviceInfoLen,
            deviceInfoParam->wfdDeviceInfo, deviceInfoParam->wfdLength) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pDeviceInfoParam->operSsid, &hdiP2pDeviceInfoParam->operSsidLen,
            deviceInfoParam->operSsid, WIFI_P2P_DEVICE_NAME_LENGTH) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill reason fail!", __func__);
            ret = HDF_FAILURE;
        }
    } while (0);

    if (ret != HDF_SUCCESS) {
        if (hdiP2pDeviceInfoParam->srcAddress != NULL) {
            OsalMemFree(hdiP2pDeviceInfoParam->srcAddress);
            hdiP2pDeviceInfoParam->srcAddress = NULL;
        }
        if (hdiP2pDeviceInfoParam->p2pDeviceAddress != NULL) {
            OsalMemFree(hdiP2pDeviceInfoParam->p2pDeviceAddress);
            hdiP2pDeviceInfoParam->p2pDeviceAddress = NULL;
        }
        if (hdiP2pDeviceInfoParam->primaryDeviceType != NULL) {
            OsalMemFree(hdiP2pDeviceInfoParam->primaryDeviceType);
            hdiP2pDeviceInfoParam->primaryDeviceType = NULL;
        }
        if (hdiP2pDeviceInfoParam->deviceName != NULL) {
            OsalMemFree(hdiP2pDeviceInfoParam->deviceName);
            hdiP2pDeviceInfoParam->deviceName = NULL;
        }
        if (hdiP2pDeviceInfoParam->wfdDeviceInfo != NULL) {
            OsalMemFree(hdiP2pDeviceInfoParam->wfdDeviceInfo);
            hdiP2pDeviceInfoParam->wfdDeviceInfo = NULL;
        }
        if (hdiP2pDeviceInfoParam->operSsid != NULL) {
            OsalMemFree(hdiP2pDeviceInfoParam->operSsid);
            hdiP2pDeviceInfoParam->operSsid = NULL;
        }
    }
    return ret;
}

static int32_t WpaFillP2pDeviceLostParam(struct P2pDeviceLostParam  *deviceLostParam,
    struct HdiP2pDeviceLostParam *hdiP2pDeviceLostParam)
{
    int32_t ret = 0;
    if (deviceLostParam == NULL || hdiP2pDeviceLostParam == NULL) {
        HDF_LOGE("%{public}s: deviceLostParam or hdiP2pDeviceLostParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pDeviceLostParam->networkId = deviceLostParam->networkId;

    if (FillData(&hdiP2pDeviceLostParam->p2pDeviceAddress, &hdiP2pDeviceLostParam->p2pDeviceAddressLen,
        deviceLostParam->p2pDeviceAddress, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
    }
    if (ret != HDF_SUCCESS) {
        if (hdiP2pDeviceLostParam->p2pDeviceAddress != NULL) {
            OsalMemFree(hdiP2pDeviceLostParam->p2pDeviceAddress);
            hdiP2pDeviceLostParam->p2pDeviceAddress = NULL;
        }
    }
    return ret;
}

static int32_t WpaFillP2pGoNegotiationRequestParam(struct P2pGoNegotiationRequestParam *goNegotiationRequestParam,
    struct HdiP2pGoNegotiationRequestParam *hdiP2pGoNegotiationRequestParam)
{
    int32_t ret = 0;
    if (goNegotiationRequestParam == NULL || hdiP2pGoNegotiationRequestParam == NULL) {
        HDF_LOGE("%{public}s: goNegotiationRequestParam or hdiP2pGoNegotiationRequestParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pGoNegotiationRequestParam->passwordId = goNegotiationRequestParam->passwordId;

    if (FillData(&hdiP2pGoNegotiationRequestParam->srcAddress, &hdiP2pGoNegotiationRequestParam->srcAddressLen,
        goNegotiationRequestParam->srcAddress, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
    }
    if (ret != HDF_SUCCESS) {
        if (hdiP2pGoNegotiationRequestParam->srcAddress != NULL) {
            OsalMemFree(hdiP2pGoNegotiationRequestParam->srcAddress);
            hdiP2pGoNegotiationRequestParam->srcAddress = NULL;
        }
    }
    return ret;
}

static int32_t WpaFillP2pGoNegotiationCompletedParam(struct P2pGoNegotiationCompletedParam
    *goNegotiationCompletedParam, struct HdiP2pGoNegotiationCompletedParam *hdiP2pGoNegotiationCompletedParam)
{
    int32_t ret = 0;
    if (goNegotiationCompletedParam == NULL || hdiP2pGoNegotiationCompletedParam == NULL) {
        HDF_LOGE("%{public}s: goNegotiationCompletedParam or hdiP2pGoNegotiationCompletedParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pGoNegotiationCompletedParam->status = goNegotiationCompletedParam->status;
    return ret;
}

static int32_t WpaFillP2pInvitationReceivedParam(struct P2pInvitationReceivedParam *invitationReceivedParam,
    struct HdiP2pInvitationReceivedParam *hdiP2pInvitationReceivedParam)
{
    int32_t ret = HDF_SUCCESS;
    if (invitationReceivedParam == NULL || hdiP2pInvitationReceivedParam == NULL) {
        HDF_LOGE("%{public}s: invitationReceivedParam or hdiP2pInvitationReceivedParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pInvitationReceivedParam->type = invitationReceivedParam->type;
    hdiP2pInvitationReceivedParam->persistentNetworkId = invitationReceivedParam->persistentNetworkId;
    hdiP2pInvitationReceivedParam->operatingFrequency = invitationReceivedParam->operatingFrequency;

    do {
        if (FillData(&hdiP2pInvitationReceivedParam->srcAddress, &hdiP2pInvitationReceivedParam->srcAddressLen,
            invitationReceivedParam->srcAddress, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pInvitationReceivedParam->goDeviceAddress,
            &hdiP2pInvitationReceivedParam->goDeviceAddressLen,
            invitationReceivedParam->goDeviceAddress, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pInvitationReceivedParam->bssid, &hdiP2pInvitationReceivedParam->bssidLen,
            invitationReceivedParam->bssid, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill ssid fail!", __func__);
            ret = HDF_FAILURE;
        }
    } while (0);

    if (ret != HDF_SUCCESS) {
        if (hdiP2pInvitationReceivedParam->srcAddress != NULL) {
            OsalMemFree(hdiP2pInvitationReceivedParam->srcAddress);
            hdiP2pInvitationReceivedParam->srcAddress = NULL;
        }
        if (hdiP2pInvitationReceivedParam->goDeviceAddress != NULL) {
            OsalMemFree(hdiP2pInvitationReceivedParam->goDeviceAddress);
            hdiP2pInvitationReceivedParam->goDeviceAddress = NULL;
        }
        if (hdiP2pInvitationReceivedParam->bssid != NULL) {
            OsalMemFree(hdiP2pInvitationReceivedParam->bssid);
            hdiP2pInvitationReceivedParam->bssid = NULL;
        }
    }
    return ret;
}

static int32_t WpaFillP2pInvitationResultParam(struct P2pInvitationResultParam *invitationResultParam,
    struct HdiP2pInvitationResultParam *hdiP2pInvitationResultParam)
{
    int32_t ret = HDF_SUCCESS;
    if (invitationResultParam == NULL || hdiP2pInvitationResultParam == NULL) {
        HDF_LOGE("%{public}s: invitationResultParam or hdiP2pInvitationResultParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pInvitationResultParam->status = invitationResultParam->status;

    if (FillData(&hdiP2pInvitationResultParam->bssid, &hdiP2pInvitationResultParam->bssidLen,
        invitationResultParam->bssid, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
    }
    if (ret != HDF_SUCCESS) {
        if (hdiP2pInvitationResultParam->bssid != NULL) {
            OsalMemFree(hdiP2pInvitationResultParam->bssid);
            hdiP2pInvitationResultParam->bssid = NULL;
        }
    }
    return ret;
}

static int32_t FillHdiP2pGroupInfoStartedParam(struct P2pGroupStartedParam *groupStartedParam,
    struct HdiP2pGroupInfoStartedParam *hdiP2pGroupStartedParam)
{
    int32_t ret = HDF_SUCCESS;
    if (groupStartedParam == NULL || hdiP2pGroupStartedParam == NULL) {
        HDF_LOGE("%{public}s: groupStartedParam or hdiP2pGroupStartedParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    do {
        if (FillData(&hdiP2pGroupStartedParam->groupIfName, &hdiP2pGroupStartedParam->groupIfNameLen,
            groupStartedParam->groupIfName, WIFI_P2P_GROUP_IFNAME_LENGTH) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill groupIfName fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pGroupStartedParam->ssid, &hdiP2pGroupStartedParam->ssidLen,
            groupStartedParam->ssid, WIFI_SSID_LENGTH) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill ssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pGroupStartedParam->psk, &hdiP2pGroupStartedParam->pskLen,
            groupStartedParam->psk, WIFI_P2P_PASSWORD_SIZE) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill psk fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pGroupStartedParam->passphrase, &hdiP2pGroupStartedParam->passphraseLen,
            groupStartedParam->passphrase, WIFI_P2P_PASSWORD_SIZE) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill passphrase fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pGroupStartedParam->goDeviceAddress, &hdiP2pGroupStartedParam->goDeviceAddressLen,
            groupStartedParam->goDeviceAddress, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill goDeviceAddress fail!", __func__);
            ret = HDF_FAILURE;
        }
        if (FillData(&hdiP2pGroupStartedParam->goRandomDeviceAddress,
            &hdiP2pGroupStartedParam->goRandomDeviceAddressLen,
            groupStartedParam->goRandomDeviceAddress, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill goRandomDeviceAddress fail!", __func__);
            ret = HDF_FAILURE;
        }
    } while (0);
    return ret;
}

static int32_t WpaFillP2pGroupInfoStartedParam(struct P2pGroupStartedParam *groupStartedParam,
    struct HdiP2pGroupInfoStartedParam *hdiP2pGroupStartedParam)
{
    int32_t ret = HDF_SUCCESS;
    if (groupStartedParam == NULL || hdiP2pGroupStartedParam == NULL) {
        HDF_LOGE("%{public}s: groupStartedParam or hdiP2pGroupStartedParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pGroupStartedParam->isGo = groupStartedParam->isGo;
    hdiP2pGroupStartedParam->isPersistent = groupStartedParam->isPersistent;
    hdiP2pGroupStartedParam->frequency = groupStartedParam->frequency;
    ret = FillHdiP2pGroupInfoStartedParam(groupStartedParam, hdiP2pGroupStartedParam);
    if (ret != HDF_SUCCESS) {
        if (hdiP2pGroupStartedParam->groupIfName != NULL) {
            OsalMemFree(hdiP2pGroupStartedParam->groupIfName);
            hdiP2pGroupStartedParam->groupIfName = NULL;
        }
        if (hdiP2pGroupStartedParam->ssid != NULL) {
            OsalMemFree(hdiP2pGroupStartedParam->ssid);
            hdiP2pGroupStartedParam->ssid = NULL;
        }
        if (hdiP2pGroupStartedParam->psk != NULL) {
            OsalMemFree(hdiP2pGroupStartedParam->psk);
            hdiP2pGroupStartedParam->psk = NULL;
        }
        if (hdiP2pGroupStartedParam->passphrase != NULL) {
            OsalMemFree(hdiP2pGroupStartedParam->passphrase);
            hdiP2pGroupStartedParam->passphrase = NULL;
        }
        if (hdiP2pGroupStartedParam->goDeviceAddress != NULL) {
            OsalMemFree(hdiP2pGroupStartedParam->goDeviceAddress);
            hdiP2pGroupStartedParam->goDeviceAddress = NULL;
        }
        if (hdiP2pGroupStartedParam->goRandomDeviceAddress != NULL) {
            OsalMemFree(hdiP2pGroupStartedParam->goRandomDeviceAddress);
            hdiP2pGroupStartedParam->goRandomDeviceAddress = NULL;
        }
    }
    return ret;
}

static int32_t WpaFillP2pGroupRemovedParam(struct P2pGroupRemovedParam *groupRemovedParam,
    struct HdiP2pGroupRemovedParam *hdiP2pGroupRemovedParam)
{
    int32_t ret = HDF_SUCCESS;
    if (groupRemovedParam == NULL || hdiP2pGroupRemovedParam == NULL) {
        HDF_LOGE("%{public}s: groupStartedParam or hdiP2pGroupRemovedParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pGroupRemovedParam->isGo = groupRemovedParam->isGo;

    if (FillData(&hdiP2pGroupRemovedParam->groupIfName, &hdiP2pGroupRemovedParam->groupIfNameLen,
        groupRemovedParam->groupIfName, WIFI_P2P_GROUP_IFNAME_LENGTH) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
    }
    if (ret != HDF_SUCCESS) {
        if (hdiP2pGroupRemovedParam->groupIfName != NULL) {
            OsalMemFree(hdiP2pGroupRemovedParam->groupIfName);
            hdiP2pGroupRemovedParam->groupIfName = NULL;
        }
    }
    return ret;
}

static int32_t WpaFillP2pProvisionDiscoveryCompletedParam(struct P2pProvisionDiscoveryCompletedParam
    *provisionDiscoveryCompletedParam,
    struct HdiP2pProvisionDiscoveryCompletedParam *hdiP2pProvisionDiscoveryCompletedParam)
{
    int32_t ret = HDF_SUCCESS;
    if (provisionDiscoveryCompletedParam == NULL || hdiP2pProvisionDiscoveryCompletedParam == NULL) {
        HDF_LOGE("%{public}s: provisionDiscoveryCompletedParam or hdiP2pProvisionDiscoveryCompletedParam is NULL!",
            __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pProvisionDiscoveryCompletedParam->isRequest = provisionDiscoveryCompletedParam->isRequest;
    hdiP2pProvisionDiscoveryCompletedParam->provDiscStatusCode = provisionDiscoveryCompletedParam->provDiscStatusCode;
    hdiP2pProvisionDiscoveryCompletedParam->configMethods = provisionDiscoveryCompletedParam->configMethods;

    do {
        if (FillData(&hdiP2pProvisionDiscoveryCompletedParam->p2pDeviceAddress,
            &hdiP2pProvisionDiscoveryCompletedParam->p2pDeviceAddressLen,
            provisionDiscoveryCompletedParam->p2pDeviceAddress, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pProvisionDiscoveryCompletedParam->generatedPin,
            &hdiP2pProvisionDiscoveryCompletedParam->generatedPinLen,
            provisionDiscoveryCompletedParam->generatedPin, WIFI_PIN_CODE_LENGTH) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill ssid fail!", __func__);
            ret = HDF_FAILURE;
        }
    } while (0);

    if (ret != HDF_SUCCESS) {
        if (hdiP2pProvisionDiscoveryCompletedParam->p2pDeviceAddress != NULL) {
            OsalMemFree(hdiP2pProvisionDiscoveryCompletedParam->p2pDeviceAddress);
            hdiP2pProvisionDiscoveryCompletedParam->p2pDeviceAddress = NULL;
        }
        if (hdiP2pProvisionDiscoveryCompletedParam->generatedPin != NULL) {
            OsalMemFree(hdiP2pProvisionDiscoveryCompletedParam->generatedPin);
            hdiP2pProvisionDiscoveryCompletedParam->generatedPin = NULL;
        }
    }
    return ret;
}

static int32_t WpaFillP2pServDiscReqParam(struct P2pServDiscReqInfoParam *servDiscReqInfo,
    struct HdiP2pServDiscReqInfoParam *hdiP2pServDiscReqInfo)
{
    int32_t ret = HDF_SUCCESS;
    if (servDiscReqInfo == NULL || hdiP2pServDiscReqInfo == NULL) {
        HDF_LOGE("%{public}s: servDiscReqInfo or hdiP2pServDiscReqInfo is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pServDiscReqInfo->freq = servDiscReqInfo->freq;
    hdiP2pServDiscReqInfo->dialogToken = servDiscReqInfo->dialogToken;
    hdiP2pServDiscReqInfo->updateIndic = servDiscReqInfo->updateIndic;

    do {
        if (FillData(&hdiP2pServDiscReqInfo->mac, &hdiP2pServDiscReqInfo->macLen,
            servDiscReqInfo->mac, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pServDiscReqInfo->tlvs, &hdiP2pServDiscReqInfo->tlvsLen,
            servDiscReqInfo->tlvs, WIFI_P2P_TLVS_LENGTH) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill ssid fail!", __func__);
            ret = HDF_FAILURE;
        }
    } while (0);

    if (ret != HDF_SUCCESS) {
        if (hdiP2pServDiscReqInfo->mac != NULL) {
            OsalMemFree(hdiP2pServDiscReqInfo->mac);
            hdiP2pServDiscReqInfo->mac = NULL;
        }
        if (hdiP2pServDiscReqInfo->tlvs != NULL) {
            OsalMemFree(hdiP2pServDiscReqInfo->tlvs);
            hdiP2pServDiscReqInfo->tlvs = NULL;
        }
    }
    return ret;
}

static int32_t WpaFillP2pServDiscRespParam(struct P2pServDiscRespParam *servDiscRespParam,
    struct HdiP2pServDiscRespParam *hdiP2pServDiscRespParam)
{
    int32_t ret = HDF_SUCCESS;
    if (servDiscRespParam == NULL || hdiP2pServDiscRespParam == NULL) {
        HDF_LOGE("%{public}s: servDiscRespParam or hdiP2pServDiscRespParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pServDiscRespParam->updateIndicator = servDiscRespParam->updateIndicator;

    do {
        if (FillData(&hdiP2pServDiscRespParam->srcAddress, &hdiP2pServDiscRespParam->srcAddressLen,
            servDiscRespParam->srcAddress, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pServDiscRespParam->tlvs, &hdiP2pServDiscRespParam->tlvsLen,
            servDiscRespParam->tlvs, WIFI_P2P_TLVS_LENGTH) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill ssid fail!", __func__);
            ret = HDF_FAILURE;
        }
    } while (0);

    if (ret != HDF_SUCCESS) {
        if (hdiP2pServDiscRespParam->srcAddress != NULL) {
            OsalMemFree(hdiP2pServDiscRespParam->srcAddress);
            hdiP2pServDiscRespParam->srcAddress = NULL;
        }
        if (hdiP2pServDiscRespParam->tlvs != NULL) {
            OsalMemFree(hdiP2pServDiscRespParam->tlvs);
            hdiP2pServDiscRespParam->tlvs = NULL;
        }
    }
    return ret;
}

static int32_t WpaFillP2pStaConnectStateParam(struct P2pStaConnectStateParam *staConnectStateParam,
    struct HdiP2pStaConnectStateParam *hdiP2pStaConnectStateParam)
{
    int32_t ret = HDF_SUCCESS;
    if (staConnectStateParam == NULL || hdiP2pStaConnectStateParam == NULL) {
        HDF_LOGE("%{public}s: staConnectStateParam or hdiP2pStaConnectStateParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pStaConnectStateParam->state = staConnectStateParam->state;
    do {
        if (FillData(&hdiP2pStaConnectStateParam->srcAddress, &hdiP2pStaConnectStateParam->srcAddressLen,
            staConnectStateParam->srcAddress, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill bssid fail!", __func__);
            ret = HDF_FAILURE;
            break;
        }
        if (FillData(&hdiP2pStaConnectStateParam->p2pDeviceAddress, &hdiP2pStaConnectStateParam->p2pDeviceAddressLen,
            staConnectStateParam->p2pDeviceAddress, ETH_ADDR_LEN) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: fill ssid fail!", __func__);
            ret = HDF_FAILURE;
        }
    } while (0);

    if (ret != HDF_SUCCESS) {
        if (hdiP2pStaConnectStateParam->srcAddress != NULL) {
            OsalMemFree(hdiP2pStaConnectStateParam->srcAddress);
            hdiP2pStaConnectStateParam->srcAddress = NULL;
        }
        if (hdiP2pStaConnectStateParam->p2pDeviceAddress != NULL) {
            OsalMemFree(hdiP2pStaConnectStateParam->p2pDeviceAddress);
            hdiP2pStaConnectStateParam->p2pDeviceAddress = NULL;
        }
    }
    return ret;
}

static int32_t WpaFillP2pIfaceCreatedParam(struct P2pIfaceCreatedParam *ifaceCreatedParam,
    struct HdiP2pIfaceCreatedParam *hdiP2pIfaceCreatedParam)
{
    int32_t ret = HDF_SUCCESS;
    if (ifaceCreatedParam == NULL || hdiP2pIfaceCreatedParam == NULL) {
        HDF_LOGE("%{public}s: ifaceCreatedParam or hdiP2pIfaceCreatedParam is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiP2pIfaceCreatedParam->isGo = ifaceCreatedParam->isGo;
    return ret;
}

int32_t ProcessEventP2pDeviceFound(struct HdfWpaRemoteNode *node,
    struct P2pDeviceInfoParam *deviceInfoParam, const char *ifName)
{
    struct HdiP2pDeviceInfoParam hdiP2pDeviceInfo = {0};
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventDeviceFound == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (WpaFillP2pDeviceFoundParam(deviceInfoParam, &hdiP2pDeviceInfo) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: hdiP2pDeviceInfo is NULL or deviceInfoParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventDeviceFound(node->callbackObj, &hdiP2pDeviceInfo, ifName);
    }
    HdiP2pDeviceInfoParamFree(&hdiP2pDeviceInfo, false);
    return ret;
}

int32_t ProcessEventP2pDeviceLost(struct HdfWpaRemoteNode *node,
    struct P2pDeviceLostParam *deviceLostParam, const char *ifName)
{
    struct HdiP2pDeviceLostParam hdiP2pDeviceLostParam = {0};
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventDeviceLost == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (WpaFillP2pDeviceLostParam(deviceLostParam, &hdiP2pDeviceLostParam) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: hdiP2pDeviceLostParam is NULL or deviceLostParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventDeviceLost(node->callbackObj, &hdiP2pDeviceLostParam, ifName);
    }
    HdiP2pDeviceLostParamFree(&hdiP2pDeviceLostParam, false);
    return ret;
}

int32_t ProcessEventP2pGoNegotiationRequest(struct HdfWpaRemoteNode *node,
    struct P2pGoNegotiationRequestParam *goNegotiationRequestParam, const char *ifName)
{
    struct HdiP2pGoNegotiationRequestParam hdiP2pGoNegotiationRequestParam = {0};
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventGoNegotiationRequest == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (WpaFillP2pGoNegotiationRequestParam(goNegotiationRequestParam,
        &hdiP2pGoNegotiationRequestParam) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: hdiP2pGoNegotiationRequestParam is NULL or goNegotiationRequestParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventGoNegotiationRequest(node->callbackObj,
            &hdiP2pGoNegotiationRequestParam, ifName);
    }
    HdiP2pGoNegotiationRequestParamFree(&hdiP2pGoNegotiationRequestParam, false);
    return ret;
}

int32_t ProcessEventP2pGoNegotiationCompleted(struct HdfWpaRemoteNode *node, struct P2pGoNegotiationCompletedParam
    *goNegotiationCompletedParam, const char *ifName)
{
    struct HdiP2pGoNegotiationCompletedParam hdiP2pGoNegotiationCompletedParam = {0};
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventGoNegotiationCompleted == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (WpaFillP2pGoNegotiationCompletedParam(goNegotiationCompletedParam,
        &hdiP2pGoNegotiationCompletedParam) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: hdiP2pGoNegotiationCompletedParam is NULL or goNegotiationCompletedParam fialed!",
            __func__);
    } else {
        ret = node->callbackObj->OnEventGoNegotiationCompleted(node->callbackObj,
            &hdiP2pGoNegotiationCompletedParam, ifName);
    }
    HdiP2pGoNegotiationCompletedParamFree(&hdiP2pGoNegotiationCompletedParam, false);
    return ret;
}

int32_t ProcessEventP2pInvitationReceived(struct HdfWpaRemoteNode *node,
    struct P2pInvitationReceivedParam *invitationReceivedParam, const char *ifName)
{
    struct HdiP2pInvitationReceivedParam hdiP2pInvitationReceivedParam = {0};
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventInvitationReceived == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (WpaFillP2pInvitationReceivedParam(invitationReceivedParam, &hdiP2pInvitationReceivedParam) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: hdiP2pInvitationReceivedParam is NULL or invitationReceivedParam fialed!", __func__);
        return ret;
    } else {
        ret = node->callbackObj->OnEventInvitationReceived(node->callbackObj, &hdiP2pInvitationReceivedParam, ifName);
    }
    HdiP2pInvitationReceivedParamFree(&hdiP2pInvitationReceivedParam, false);
    return ret;
}

int32_t ProcessEventP2pInvitationResult(struct HdfWpaRemoteNode *node,
    struct P2pInvitationResultParam *invitationResultParam, const char *ifName)
{
    struct HdiP2pInvitationResultParam hdiP2pInvitationResultParam = {0};
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventInvitationResult == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (WpaFillP2pInvitationResultParam(invitationResultParam, &hdiP2pInvitationResultParam) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: hdiP2pInvitationResultParam is NULL or invitationResultParam fialed!", __func__);
        return ret;
    } else {
        ret = node->callbackObj->OnEventInvitationResult(node->callbackObj, &hdiP2pInvitationResultParam, ifName);
    }
    HdiP2pInvitationResultParamFree(&hdiP2pInvitationResultParam, false);
    return ret;
}

int32_t ProcessEventP2pGroupFormationSuccess(struct HdfWpaRemoteNode *node,
    const char *ifName)
{
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = node->callbackObj->OnEventGroupFormationSuccess(node->callbackObj, ifName);
    return ret;
}

int32_t ProcessEventP2pGroupFormationFailure(struct HdfWpaRemoteNode *node, char *reason,
    const char *ifName)
{
    char *hdiReason = NULL;
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventGroupFormationFailure == NULL ||
        reason == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    hdiReason = (char *)OsalMemCalloc(WIFI_REASON_LENGTH);
    if ((hdiReason == NULL) || (strncpy_s(hdiReason, WIFI_REASON_LENGTH, reason, strlen(reason)) != HDF_SUCCESS)) {
        HDF_LOGE("%{public}s: hdiReason is NULL or reason fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventGroupFormationFailure(node->callbackObj, hdiReason, ifName);
    }
    OsalMemFree(hdiReason);
    hdiReason = NULL;
    return ret;
}

int32_t ProcessEventP2pGroupStarted(struct HdfWpaRemoteNode *node,
    struct P2pGroupStartedParam *groupStartedParam, const char *ifName)
{
    struct HdiP2pGroupInfoStartedParam hdiP2pGroupInfoStartedParam = {0};
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventGroupInfoStarted == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (WpaFillP2pGroupInfoStartedParam(groupStartedParam, &hdiP2pGroupInfoStartedParam) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: hdiP2pGroupStartedParam is NULL or groupStartedParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventGroupInfoStarted(node->callbackObj, &hdiP2pGroupInfoStartedParam, ifName);
    }
    HdiP2pGroupInfoStartedParamFree(&hdiP2pGroupInfoStartedParam, false);
    return ret;
}

int32_t ProcessEventP2pGroupRemoved(struct HdfWpaRemoteNode *node,
    struct P2pGroupRemovedParam *groupRemovedParam, const char *ifName)
{
    struct HdiP2pGroupRemovedParam hdiP2pGroupRemovedParam = {0};
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventGroupRemoved == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (WpaFillP2pGroupRemovedParam(groupRemovedParam, &hdiP2pGroupRemovedParam) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: hdiP2pGroupRemovedParam is NULL or groupRemovedParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventGroupRemoved(node->callbackObj, &hdiP2pGroupRemovedParam, ifName);
    }
    HdiP2pGroupRemovedParamFree(&hdiP2pGroupRemovedParam, false);
    return ret;
}

int32_t ProcessEventP2pProvisionDiscoveryCompleted(struct HdfWpaRemoteNode *node,
    struct P2pProvisionDiscoveryCompletedParam *provisionDiscoveryCompletedParam, const char *ifName)
{
    struct HdiP2pProvisionDiscoveryCompletedParam hdiP2pProvisionDiscoveryCompletedParam = {0};
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventProvisionDiscoveryCompleted == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (WpaFillP2pProvisionDiscoveryCompletedParam(provisionDiscoveryCompletedParam,
        &hdiP2pProvisionDiscoveryCompletedParam) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Param is NULL or provisionDiscoveryCompletedParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventProvisionDiscoveryCompleted(node->callbackObj,
            &hdiP2pProvisionDiscoveryCompletedParam, ifName);
    }
    HdiP2pProvisionDiscoveryCompletedParamFree(&hdiP2pProvisionDiscoveryCompletedParam, false);
    return ret;
}

int32_t ProcessEventP2pFindStopped(struct HdfWpaRemoteNode *node,
     const char *ifName)
{
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = node->callbackObj->OnEventFindStopped(node->callbackObj, ifName);
    return ret;
}

int32_t ProcessEventP2pServDiscReq(struct HdfWpaRemoteNode *node,
    struct P2pServDiscReqInfoParam *servDiscReqInfo, const char *ifName)
{
    struct HdiP2pServDiscReqInfoParam hdiP2pServDiscReqInfo = {0};
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventServDiscReq == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (WpaFillP2pServDiscReqParam(servDiscReqInfo, &hdiP2pServDiscReqInfo) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: hdiP2pServDiscReqInfo is NULL or servDiscReqInfo fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventServDiscReq(node->callbackObj, &hdiP2pServDiscReqInfo, ifName);
    }
    HdiP2pServDiscReqInfoParamFree(&hdiP2pServDiscReqInfo, false);
    return ret;
}

int32_t ProcessEventP2pServDiscResp(struct HdfWpaRemoteNode *node,
    struct P2pServDiscRespParam *servDiscRespParam, const char *ifName)
{
    struct HdiP2pServDiscRespParam hdiP2pServDiscRespParam = {0};
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventServDiscResp == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (WpaFillP2pServDiscRespParam(servDiscRespParam, &hdiP2pServDiscRespParam) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: hdiP2pServDiscRespParam is NULL or servDiscRespParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventServDiscResp(node->callbackObj, &hdiP2pServDiscRespParam, ifName);
    }
    HdiP2pServDiscRespParamFree(&hdiP2pServDiscRespParam, false);
    return ret;
}

int32_t ProcessEventP2pStaConnectState(struct HdfWpaRemoteNode *node,
    struct P2pStaConnectStateParam *staConnectStateParam, const char *ifName)
{
    struct HdiP2pStaConnectStateParam hdiP2pStaConnectStateParam = {0};
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventStaConnectState == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (WpaFillP2pStaConnectStateParam(staConnectStateParam, &hdiP2pStaConnectStateParam) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: hdiP2pStaConnectStateParam is NULL or staConnectStateParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventStaConnectState(node->callbackObj, &hdiP2pStaConnectStateParam, ifName);
    }
    HdiP2pStaConnectStateParamFree(&hdiP2pStaConnectStateParam, false);
    return ret;
}

int32_t ProcessEventP2pIfaceCreated(struct HdfWpaRemoteNode *node, struct P2pIfaceCreatedParam *ifaceCreatedParam,
    const char *ifName)
{
    struct HdiP2pIfaceCreatedParam hdiP2pIfaceCreatedParam = {0};
    int32_t ret = HDF_FAILURE;
    if (node == NULL || node->callbackObj == NULL || node->callbackObj->OnEventIfaceCreated == NULL) {
        HDF_LOGE("%{public}s: hdf wlan remote node or callbackObj is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (WpaFillP2pIfaceCreatedParam(ifaceCreatedParam, &hdiP2pIfaceCreatedParam) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: hdiP2pIfaceCreatedParam is NULL or ifaceCreatedParam fialed!", __func__);
    } else {
        ret = node->callbackObj->OnEventIfaceCreated(node->callbackObj, &hdiP2pIfaceCreatedParam, ifName);
    }
    HdiP2pIfaceCreatedParamFree(&hdiP2pIfaceCreatedParam, false);
    return ret;
}
