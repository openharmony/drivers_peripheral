/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <stdlib.h>

#include "hdf_log.h"
#include "sbuf_common_adapter.h"
#include "securec.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int32_t WifiEapolPacketSend(const char *ifName, const uint8_t *srcAddr,
    const uint8_t *dstAddr, uint8_t *buf, uint32_t length)
{
    (void)srcAddr;
    (void)dstAddr;
    int32_t ret;
    struct HdfSBuf *data = NULL;

    if (ifName == NULL || buf == NULL) {
        HDF_LOGE("%s: Input param is null", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    data = HdfSbufObtainDefaultSize();
    if (data == NULL) {
        HDF_LOGE("%s: Init HdfSBuf failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    bool isSerializeFailed = false;
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteString(data, ifName);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, buf, length);
    if (isSerializeFailed) {
        HDF_LOGE("%s: Serialize failed!", __FUNCTION__);
        ret = RET_CODE_FAILURE;
    } else {
        ret = SendCmdSync(WIFI_WPA_CMD_SEND_EAPOL, data, NULL);
    }
    HdfSbufRecycle(data);
    return ret;
}

#define DEFAULT_EAPOL_PACKAGE_SIZE 800

int32_t WifiEapolPacketReceive(const char *ifName, WifiRxEapol *rxEapol)
{
    int32_t ret;
    WifiRxEapol eapol = {0};
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *respData = NULL;

    if (ifName == NULL || rxEapol == NULL) {
        HDF_LOGE("%s: Input param is null", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    data = HdfSbufObtainDefaultSize();
    respData = HdfSbufObtain(DEFAULT_EAPOL_PACKAGE_SIZE);
    do {
        if (data == NULL || respData == NULL) {
            HDF_LOGE("%s: Init HdfSBuf failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        if (!HdfSbufWriteString(data, ifName)) {
            HDF_LOGE("%s: Serialize failed!", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        ret = SendCmdSync(WIFI_WPA_CMD_RECEIVE_EAPOL, data, respData);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%s: WifiEapolPacketReceive failed ret = %d", __FUNCTION__, ret);
            break;
        }
        if (!HdfSbufReadBuffer(respData, (const void **)(&(eapol.buf)), &(eapol.len))) {
            ret = RET_CODE_FAILURE;
            HDF_LOGE("%s: WifiEapolPacketReceive HdfSbufReadBuffer failed", __FUNCTION__);
            break;
        }
        rxEapol->buf = NULL;
        rxEapol->len = 0;
        if (eapol.len != 0) {
            rxEapol->buf = malloc(eapol.len);
            if (rxEapol->buf == NULL) {
                HDF_LOGE("%s: rxEapol->buf is null", __FUNCTION__);
                ret = RET_CODE_FAILURE;
                break;
            }
            if (memcpy_s(rxEapol->buf, eapol.len, eapol.buf, eapol.len) != EOK) {
                HDF_LOGE("%s: memcpy failed", __FUNCTION__);
            }
            rxEapol->len = eapol.len;
        }
    } while (0);
    HdfSbufRecycle(respData);
    HdfSbufRecycle(data);
    return ret;
}

int32_t WifiEapolEnable(const char *ifName)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;

    if (ifName == NULL) {
        HDF_LOGE("%s: Input param is null", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    data = HdfSbufObtainDefaultSize();
    if (data == NULL) {
        HDF_LOGE("%s: HdfSbufObtainDefaultSize fail", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    if (HdfSbufWriteString(data, ifName)) {
        ret = SendCmdSync(WIFI_WPA_CMD_ENALBE_EAPOL, data, NULL);
    } else {
        HDF_LOGE("%s: Serialize failed!", __FUNCTION__);
        ret = RET_CODE_FAILURE;
    }
    HdfSbufRecycle(data);

    return ret;
}

int32_t WifiEapolDisable(const char *ifName)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;

    if (ifName == NULL) {
        return RET_CODE_INVALID_PARAM;
    }
    data = HdfSbufObtainDefaultSize();
    if (data == NULL) {
        return RET_CODE_FAILURE;
    }
    if (HdfSbufWriteString(data, ifName)) {
        ret = SendCmdSync(WIFI_WPA_CMD_DISABLE_EAPOL, data, NULL);
    } else {
        HDF_LOGE("%s: Serialize failed!", __FUNCTION__);
        ret = RET_CODE_FAILURE;
    }
    HdfSbufRecycle(data);
    return ret;
}

int32_t WifiCmdSetAp(const char *ifName, WifiApSetting *apsettings)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;

    if (ifName == NULL || apsettings == NULL) {
        HDF_LOGE("%s: Input param is null", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    data = HdfSbufObtainDefaultSize();
    if (data == NULL) {
        HDF_LOGE("%s: HdfSbufObtainDefaultSize fail", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    bool isSerializeFailed = false;
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteString(data, ifName);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteInt32(data, apsettings->freqParams.mode);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteInt32(data, apsettings->freqParams.freq);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteInt32(data, apsettings->freqParams.channel);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteInt32(data, apsettings->freqParams.htEnabled);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteInt32(data, apsettings->freqParams.secChannelOffset);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteInt32(data, apsettings->freqParams.vhtEnabled);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteInt32(data, apsettings->freqParams.centerFreq1);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteInt32(data, apsettings->freqParams.centerFreq2);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteInt32(data, apsettings->freqParams.bandwidth);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteUint8(data, apsettings->freqParams.band);

    isSerializeFailed = isSerializeFailed || !HdfSbufWriteInt32(data, apsettings->beaconInterval);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteInt32(data, apsettings->dtimPeriod);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteUint8(data, apsettings->hiddenSsid);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteUint8(data, apsettings->authType);
    isSerializeFailed =
        isSerializeFailed || !HdfSbufWriteBuffer(data, apsettings->beaconData.head, apsettings->beaconData.headLen);
    isSerializeFailed =
        isSerializeFailed || !HdfSbufWriteBuffer(data, apsettings->beaconData.tail, apsettings->beaconData.tailLen);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, apsettings->ssid, apsettings->ssidLen);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, apsettings->meshSsid, apsettings->meshSsidLen);
    if (isSerializeFailed) {
        HDF_LOGE("%s: Serialize failed!", __FUNCTION__);
        ret = RET_CODE_FAILURE;
    } else {
        ret = SendCmdSync(WIFI_WPA_CMD_SET_AP, data, NULL);
    }
    HdfSbufRecycle(data);
    return ret;
}

int32_t WifiCmdChangeBeacon(const char *ifName, WifiApSetting *apsettings)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;

    if (ifName == NULL || apsettings == NULL) {
        HDF_LOGE("%s: Input param is null", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    data = HdfSbufObtainDefaultSize();
    if (data == NULL) {
        HDF_LOGE("%s: HdfSbufObtainDefaultSize fail", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    bool isSerializeFailed = false;
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteString(data, ifName);
    isSerializeFailed =
        isSerializeFailed || !HdfSbufWriteBuffer(data, apsettings->beaconData.head, apsettings->beaconData.headLen);
    isSerializeFailed =
        isSerializeFailed || !HdfSbufWriteBuffer(data, apsettings->beaconData.tail, apsettings->beaconData.tailLen);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, apsettings->ssid, apsettings->ssidLen);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, apsettings->meshSsid, apsettings->meshSsidLen);
    if (isSerializeFailed) {
        HDF_LOGE("%s: Serialize failed!", __FUNCTION__);
        ret = RET_CODE_FAILURE;
    } else {
        ret = SendCmdSync(WIFI_WPA_CMD_CHANGE_BEACON, data, NULL);
    }
    HdfSbufRecycle(data);
    return ret;
}

int32_t WifiCmdSendMlme(const char *ifName, WifiMlmeData *mlme)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;

    if (ifName == NULL || mlme == NULL) {
        return RET_CODE_INVALID_PARAM;
    }
    data = HdfSbufObtainDefaultSize();
    if (data == NULL) {
        return RET_CODE_FAILURE;
    }
    bool isSerializeFailed = false;
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteString(data, ifName);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, mlme, sizeof(WifiMlmeData));
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, mlme->data, mlme->dataLen);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, mlme->cookie, sizeof(*mlme->cookie));
    if (isSerializeFailed) {
        HDF_LOGE("%s: Serialize failed!", __FUNCTION__);
        ret = RET_CODE_FAILURE;
    } else {
        ret = SendCmdSync(WIFI_WPA_CMD_SEND_MLME, data, NULL);
    }
    HdfSbufRecycle(data);
    return ret;
}

static int32_t WifiCmdOperKey(const char *ifName, uint32_t cmd, WifiKeyExt *keyExt)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;

    if (ifName == NULL || keyExt == NULL) {
        HDF_LOGE("%s: Input param is null", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    data = HdfSbufObtainDefaultSize();
    if (data == NULL) {
        HDF_LOGE("%s: HdfSbufObtainDefaultSize fail", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    bool isSerializeFailed = false;
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteString(data, ifName);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteInt32(data, keyExt->type);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteUint32(data, keyExt->keyIdx);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteUint32(data, keyExt->cipher);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteUint8(data, keyExt->def);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteUint8(data, keyExt->defMgmt);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteUint8(data, keyExt->defaultTypes);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteUint8(data, keyExt->resv);
    if (keyExt->addr == NULL) {
        isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, keyExt->addr, 0);
    } else {
        isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, keyExt->addr, ETH_ADDR_LEN);
    }
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, keyExt->key, keyExt->keyLen);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, keyExt->seq, keyExt->seqLen);
    if (isSerializeFailed) {
        HDF_LOGE("%s: Serialize failed!", __FUNCTION__);
        ret = RET_CODE_FAILURE;
    } else {
        ret = SendCmdSync(cmd, data, NULL);
    }
    HdfSbufRecycle(data);
    return ret;
}

int32_t WifiCmdDelKey(const char *ifName, WifiKeyExt *keyExt)
{
    return WifiCmdOperKey(ifName, WIFI_WPA_CMD_DEL_KEY, keyExt);
}

int32_t WifiCmdNewKey(const char *ifName, WifiKeyExt *keyExt)
{
    return WifiCmdOperKey(ifName, WIFI_WPA_CMD_NEW_KEY, keyExt);
}

int32_t WifiCmdSetKey(const char *ifName, WifiKeyExt *keyExt)
{
    return WifiCmdOperKey(ifName, WIFI_WPA_CMD_SET_KEY, keyExt);
}

int32_t WifiCmdSetMode(const char *ifName, WifiSetMode *setMode)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;

    if (ifName == NULL || setMode == NULL) {
        HDF_LOGE("%s: Input param is null", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    data = HdfSbufObtainDefaultSize();
    if (data == NULL) {
        HDF_LOGE("%s: HdfSbufObtainDefaultSize fail", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    bool isSerializeFailed = false;
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteString(data, ifName);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, setMode, sizeof(*setMode));
    if (isSerializeFailed) {
        HDF_LOGE("%s: Serialize failed!", __FUNCTION__);
        ret = RET_CODE_FAILURE;
    } else {
        ret = SendCmdSync(WIFI_WPA_CMD_SET_MODE, data, NULL);
    }
    HdfSbufRecycle(data);
    HDF_LOGD("%s: WifiCmdSetMode finished! ret=%d", __FUNCTION__, ret);
    return ret;
}

int32_t WifiCmdGetOwnMac(const char *ifName, char *buf, uint32_t len)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;

    if (ifName == NULL || buf == NULL) {
        HDF_LOGE("%s: Input param is null", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    data = HdfSbufObtainDefaultSize();
    reply = HdfSbufObtainDefaultSize();
    do {
        if (data == NULL || reply == NULL) {
            HDF_LOGE("%s: At least one param is null", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        if (HdfSbufWriteString(data, ifName)) {
            ret = SendCmdSync(WIFI_WPA_CMD_GET_ADDR, data, reply);
        } else {
            HDF_LOGE("%s: Serialize failed!", __FUNCTION__);
            ret = RET_CODE_FAILURE;
        }
        if (ret != RET_CODE_SUCCESS) {
            ret = RET_CODE_FAILURE;
            break;
        }
        uint32_t replayDataSize = 0;
        const uint8_t *replayData = 0;
        if (!HdfSbufReadBuffer(reply, (const void **)(&replayData), &replayDataSize) ||
            replayDataSize != ETH_ADDR_LEN) {
            HDF_LOGE("%s: fail or data size mismatch", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        if (memcpy_s(buf, len, replayData, replayDataSize) != EOK) {
            HDF_LOGE("%s: memcpy failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
        }
    } while (0);
    HdfSbufRecycle(reply);
    HdfSbufRecycle(data);
    return ret;
}

int32_t WifiCmdGetHwFeature(const char *ifName, WifiHwFeatureData *hwFeatureData)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;

    if (ifName == NULL || hwFeatureData == NULL) {
        HDF_LOGE("%s: Input param is null", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    data = HdfSbufObtainDefaultSize();
    reply = HdfSbufObtain(sizeof(WifiHwFeatureData) + sizeof(uint64_t));
    do {
        if (data == NULL || reply == NULL) {
            HDF_LOGE("%s: At least one param is null", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        if (HdfSbufWriteString(data, ifName)) {
            ret = SendCmdSync(WIFI_WPA_CMD_GET_HW_FEATURE, data, reply);
        } else {
            HDF_LOGE("%s: HdfSbufWriteString failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
        }
        if (ret != RET_CODE_SUCCESS) {
            ret = RET_CODE_FAILURE;
            break;
        }
        const WifiHwFeatureData *respFeaturenData = NULL;
        uint32_t dataSize = 0;
        if (!HdfSbufReadBuffer(reply, (const void **)(&respFeaturenData), &dataSize) ||
            dataSize != sizeof(WifiHwFeatureData)) {
            HDF_LOGE("%s: HdfSbufReadBuffer failed or unexpect dataSize", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        if (memcpy_s(hwFeatureData, sizeof(WifiHwFeatureData), respFeaturenData, dataSize) != EOK) {
            HDF_LOGE("%s: memcpy failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
        }
    } while (0);
    HdfSbufRecycle(reply);
    HdfSbufRecycle(data);
    return ret;
}

int32_t WifiCmdDisconnet(const char *ifName, int32_t reasonCode)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;

    if (ifName == NULL) {
        HDF_LOGE("%s: Input param is null", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    data = HdfSbufObtainDefaultSize();
    if (data == NULL) {
        HDF_LOGE("%s: HdfSbufObtainDefaultSize fail", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    bool isSerializeFailed = false;
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteString(data, ifName);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteUint16(data, reasonCode);
    if (isSerializeFailed) {
        HDF_LOGE("%s: Serialize failed!", __FUNCTION__);
        ret = RET_CODE_FAILURE;
    } else {
        ret = SendCmdSync(WIFI_WPA_CMD_DISCONNECT, data, NULL);
    }
    HdfSbufRecycle(data);
    return ret;
}

int32_t WifiCmdAssoc(const char *ifName, WifiAssociateParams *assocParams)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;

    if (ifName == NULL || assocParams == NULL) {
        HDF_LOGE("%s: Input param is null!", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    data = HdfSbufObtainDefaultSize();
    if (data == NULL) {
        HDF_LOGE("%s: HdfSbufObtainDefaultSize fail!", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    bool isSerializeFailed = false;
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteString(data, ifName);
    if (assocParams->bssid == NULL) {
        isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, assocParams->bssid, 0);
    } else {
        isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, assocParams->bssid, ETH_ADDR_LEN);
    }
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, assocParams->ssid, assocParams->ssidLen);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, assocParams->ie, assocParams->ieLen);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, assocParams->key, assocParams->keyLen);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteUint8(data, assocParams->authType);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteUint8(data, assocParams->privacy);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteUint8(data, assocParams->keyIdx);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteUint8(data, assocParams->mfp);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteUint32(data, assocParams->freq);
    isSerializeFailed =
        isSerializeFailed || !HdfSbufWriteBuffer(data, assocParams->crypto, sizeof(assocParams->crypto[0]));
    if (isSerializeFailed) {
        HDF_LOGE("%s: Serialize failed!", __FUNCTION__);
        ret = RET_CODE_FAILURE;
    } else {
        ret = SendCmdSync(WIFI_WPA_CMD_ASSOC, data, NULL);
    }
    HdfSbufRecycle(data);
    return ret;
}

int32_t WifiCmdSetNetdev(const char *ifName, WifiSetNewDev *info)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;

    if (ifName == NULL || info == NULL) {
        HDF_LOGE("%s: Input param is null!", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    data = HdfSbufObtainDefaultSize();
    if (data == NULL) {
        HDF_LOGE("%s: HdfSbufObtainDefaultSize fail!", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    bool isSerializeFailed = false;
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteString(data, ifName);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, info, sizeof(WifiSetNewDev));
    if (isSerializeFailed) {
        HDF_LOGE("%s: Serialize failed!", __FUNCTION__);
        ret = RET_CODE_FAILURE;
    } else {
        ret = SendCmdSync(WIFI_WPA_CMD_SET_NETDEV, data, NULL);
    }
    HdfSbufRecycle(data);
    return ret;
}

int32_t WifiCmdStaRemove(const char *ifName, const uint8_t *addr, uint32_t addrLen)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;

    if (ifName == NULL || addr == NULL) {
        return RET_CODE_INVALID_PARAM;
    }
    data = HdfSbufObtainDefaultSize();
    if (data == NULL) {
        return RET_CODE_FAILURE;
    }
    bool isSerializeFailed = false;
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteString(data, ifName);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, addr, addrLen);
    if (isSerializeFailed) {
        HDF_LOGE("%s: Serialize failed!", __FUNCTION__);
        ret = RET_CODE_FAILURE;
    } else {
        ret = SendCmdSync(WIFI_WPA_CMD_STA_REMOVE, data, NULL);
    }
    HdfSbufRecycle(data);
    return ret;
}

int32_t WifiCmdSendAction(const char *ifName, WifiActionData *actionData)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;

    if (ifName == NULL || actionData == NULL) {
        HDF_LOGE("%s: input parameter invalid!", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    data = HdfSbufObtainDefaultSize();
    if (data == NULL) {
        HDF_LOGE("%s: Init HdfSBuf failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    bool isSerializeFailed = false;
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteString(data, ifName);

    isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, actionData->bssid, ETH_ADDR_LEN);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, actionData->dst, ETH_ADDR_LEN);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, actionData->src, ETH_ADDR_LEN);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, actionData->data, actionData->dataLen);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteUint32(data, actionData->freq);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteUint32(data, actionData->wait);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteInt32(data, actionData->noCck);
    if (isSerializeFailed) {
        HDF_LOGE("%s: Serialize failed!", __FUNCTION__);
        ret = RET_CODE_FAILURE;
    } else {
        ret = SendCmdSync(WIFI_WPA_CMD_SEND_ACTION, data, NULL);
    }
    HdfSbufRecycle(data);
    return ret;
}

int32_t WifiCmdSetClient(uint32_t clientNum)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;

    data = HdfSbufObtainDefaultSize();
    if (data == NULL) {
        HDF_LOGE("%s: Init HdfSBuf failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, clientNum)) {
        HDF_LOGE("%s: sbuf write failed!", __FUNCTION__);
        ret = RET_CODE_FAILURE;
    } else {
        ret = SendCmdSync(WIFI_CLIENT_CMD_SET_CLIENT, data, NULL);
    }
    HdfSbufRecycle(data);
    return ret;
}

int32_t WifiCmdProbeReqReport(const char *ifName, const int32_t *report)
{
    if (ifName == NULL || report == NULL) {
        HDF_LOGE("%s: input parameter invalid!", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    struct HdfSBuf *data = HdfSbufObtainDefaultSize();
    if (data == NULL) {
        HDF_LOGE("%s: Init HdfSBuf failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    bool isSerializeFailed = false;
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteString(data, ifName);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteInt32(data, *report);
    int32_t ret;
    if (isSerializeFailed) {
        HDF_LOGE("Serialize failed.");
        ret = RET_CODE_FAILURE;
    } else {
        ret = SendCmdSync(WIFI_WPA_CMD_PROBE_REQ_REPORT, data, NULL);
    }
    HdfSbufRecycle(data);
    return ret;
}

int32_t WifiCmdRemainOnChannel(const char *ifName, const WifiOnChannel *onChannel)
{
    if (ifName == NULL || onChannel == NULL) {
        HDF_LOGE("%s: input parameter invalid!", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    struct HdfSBuf *data = HdfSbufObtainDefaultSize();
    if (data == NULL) {
        HDF_LOGE("%s: Init HdfSBuf failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    bool isSerializeFailed = false;
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteString(data, ifName);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteUint32(data, onChannel->freq);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteUint32(data, onChannel->duration);
    int32_t ret;
    if (isSerializeFailed) {
        HDF_LOGE("Serialize failed.");
        ret = RET_CODE_FAILURE;
    } else {
        ret = SendCmdSync(WIFI_WPA_CMD_REMAIN_ON_CHANNEL, data, NULL);
        HdfSbufRecycle(data);
        return ret;
    }
    HdfSbufRecycle(data);
    return ret;
}

int32_t WifiCmdCancelRemainOnChannel(const char *ifName)
{
    if (ifName == NULL) {
        HDF_LOGE("%s: input parameter invalid!", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    struct HdfSBuf *data = HdfSbufObtainDefaultSize();
    if (data == NULL) {
        HDF_LOGE("%s: Init HdfSBuf failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    bool isSerializeFailed = false;
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteString(data, ifName);
    int32_t ret;
    if (isSerializeFailed) {
        HDF_LOGE("Serialize failed.");
        ret = RET_CODE_FAILURE;
    } else {
        ret = SendCmdSync(WIFI_WPA_CMD_CANCEL_REMAIN_ON_CHANNEL, data, NULL);
        HdfSbufRecycle(data);
        return ret;
    }
    HdfSbufRecycle(data);
    return ret;
}

int32_t WifiCmdAddIf(const char *ifName, const WifiIfAdd *ifAdd)
{
    if (ifName == NULL || ifAdd == NULL) {
        HDF_LOGE("%s: input parameter invalid!", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    struct HdfSBuf *data = HdfSbufObtainDefaultSize();
    if (data == NULL) {
        HDF_LOGE("%s: Init HdfSBuf failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    bool isSerializeFailed = false;
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteString(data, ifName);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, ifAdd, sizeof(WifiIfAdd));
    int32_t ret;
    if (isSerializeFailed) {
        HDF_LOGE("%s: Serialize failed!", __FUNCTION__);
        ret = RET_CODE_FAILURE;
    } else {
        ret = SendCmdSync(WIFI_WPA_CMD_ADD_IF, data, NULL);
    }
    HdfSbufRecycle(data);
    return ret;
}

int32_t WifiCmdRemoveIf(const char *ifName, const WifiIfRemove *ifRemove)
{
    if (ifName == NULL || ifRemove == NULL) {
        HDF_LOGE("%s: input parameter invalid!", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    struct HdfSBuf *data = HdfSbufObtainDefaultSize();
    if (data == NULL) {
        HDF_LOGE("%s: Init HdfSBuf failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    bool isSerializeFailed = false;
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteString(data, ifName);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, ifRemove, sizeof(WifiIfRemove));
    int32_t ret;
    if (isSerializeFailed) {
        HDF_LOGE("%s: Serialize failed!", __FUNCTION__);
        ret = RET_CODE_FAILURE;
    } else {
        ret = SendCmdSync(WIFI_WPA_CMD_REMOVE_IF, data, NULL);
    }
    HdfSbufRecycle(data);
    return ret;
}

int32_t WifiCmdSetApWpsP2pIe(const char *ifName, const WifiAppIe *appIe)
{
    if (ifName == NULL || appIe == NULL) {
        HDF_LOGE("%s: input parameter invalid!", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    struct HdfSBuf *data = HdfSbufObtainDefaultSize();
    if (data == NULL) {
        HDF_LOGE("%s: Init HdfSBuf failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    bool isSerializeFailed = false;
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteString(data, ifName);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteUint32(data, appIe->ieLen);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteUint8(data, appIe->appIeType);
    if (appIe->ie == NULL) {
        isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, appIe->ie, 0);
    } else {
        isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, appIe->ie, appIe->ieLen);
    }
    int32_t ret;
    if (isSerializeFailed) {
        HDF_LOGE("%s: Serialize failed!", __FUNCTION__);
        ret = RET_CODE_FAILURE;
    } else {
        ret = SendCmdSync(WIFI_WPA_CMD_SET_AP_WPS_P2P_IE, data, NULL);
    }
    HdfSbufRecycle(data);
    return ret;
}

int32_t WifiCmdGetDrvFlags(const char *ifName, WifiGetDrvFlags *params)
{
    int32_t ret;

    if (ifName == NULL || params == NULL) {
        HDF_LOGE("%s: input parameter invalid!", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    struct HdfSBuf *data = HdfSbufObtainDefaultSize();
    struct HdfSBuf *reply = HdfSbufObtainDefaultSize();
    do {
        if (data == NULL || reply == NULL) {
            HDF_LOGE("%s: Init HdfSBuf failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }

        if (!HdfSbufWriteString(data, ifName)) {
            HDF_LOGE("%s: HdfSbufWriteString failed!", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        ret = SendCmdSync(WIFI_WPA_CMD_GET_DRIVER_FLAGS, data, reply);
        if (ret != RET_CODE_SUCCESS) {
            ret = RET_CODE_FAILURE;
            break;
        }
        if (!HdfSbufReadUint64(reply, &(params->drvFlags))) {
            ret = RET_CODE_FAILURE;
            break;
        }
    } while (0);
    HdfSbufRecycle(reply);
    HdfSbufRecycle(data);
    return ret;
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
