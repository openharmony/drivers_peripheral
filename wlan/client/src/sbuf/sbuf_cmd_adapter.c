/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#define DRIVER_SERVICE_NAME "hdfwifi"
static struct HdfDevEventlistener g_wifiDevEventListener;
static bool g_isHasRegisterListener = false;
#define PNO_SCAN_INFO_MAXSIZE 1500

static int32_t ParserNetworkInfo(struct HdfSBuf *reply, struct NetworkInfoResult *result)
{
    uint32_t i;
    const char *ifName = NULL;
    uint8_t *mode = NULL;
    uint32_t replayDataSize;

    if (!HdfSbufReadUint32(reply, &result->nums)) {
        HDF_LOGE("%s: get networkNum failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    if (result->nums > MAX_IFACE_NUM) {
        result->nums = MAX_IFACE_NUM;
    }
    for (i = 0; i < result->nums; i++) {
        ifName = HdfSbufReadString(reply);
        if (ifName == NULL) {
            HDF_LOGE("%s: get ifName failed", __FUNCTION__);
            return RET_CODE_FAILURE;
        }
        if (!HdfSbufReadBuffer(reply, (const void **)&mode, &replayDataSize) || mode == NULL ||
            replayDataSize != WIFI_IFTYPE_MAX) {
            HDF_LOGE("%s: get mode failed", __FUNCTION__);
            return RET_CODE_FAILURE;
        }
        if (strncpy_s(result->infos[i].name, IFNAMSIZ, ifName, strlen(ifName)) != EOK) {
            HDF_LOGE("%s: memcpy_s name failed", __FUNCTION__);
            return RET_CODE_FAILURE;
        }
        if (memcpy_s(result->infos[i].supportMode, WIFI_IFTYPE_MAX, mode, replayDataSize) != EOK) {
            HDF_LOGE("%s: memcpy_s supportMode failed", __FUNCTION__);
            return RET_CODE_FAILURE;
        }
    }
    return RET_CODE_SUCCESS;
}

static int32_t ParserDeviceMacAddr(struct HdfSBuf *reply, uint8_t *mac, uint8_t len)
{
    uint8_t isEfuseSavedMac;
    uint32_t replayDataSize = 0;
    const uint8_t *replayData = 0;

    if (!HdfSbufReadUint8(reply, &isEfuseSavedMac)) {
        HDF_LOGE("%s: HdfSbufReadUint8 failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    if (!isEfuseSavedMac) {
        HDF_LOGE("%s: not support to get device mac addr", __FUNCTION__);
        return RET_CODE_NOT_SUPPORT;
    }
    if (!HdfSbufReadBuffer(reply, (const void **)(&replayData), &replayDataSize) || replayDataSize != len) {
        HDF_LOGE("%s: HdfSbufReadBuffer failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    if (memcpy_s(mac, len, replayData, replayDataSize) != EOK) {
        HDF_LOGE("%s: memcpy failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    return RET_CODE_SUCCESS;
}

static int32_t ParserFreqInfo(struct HdfSBuf *reply, struct FreqInfoResult *result, uint32_t size)
{
    uint32_t replayDataSize = 0;
    const uint8_t *replayData = 0;

    if (result == NULL || result->freqs == NULL || result->txPower == NULL) {
        HDF_LOGE("%s:  Invalid input parameter", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }

    if (!HdfSbufReadUint32(reply, &result->nums)) {
        HDF_LOGE("%s: read num failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    if (result->nums > size) {
        HDF_LOGE("%s: num valid", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    if (!HdfSbufReadBuffer(reply, (const void **)(&replayData), &replayDataSize)) {
        HDF_LOGE("%s: read freqs failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    if (memcpy_s(result->freqs, size * sizeof(uint32_t), replayData, replayDataSize) != EOK) {
        HDF_LOGE("%s: memcpy failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    return RET_CODE_SUCCESS;
}

static int32_t ParserAssociatedStas(struct HdfSBuf *reply, struct AssocStaInfoResult *result)
{
    uint32_t replayDataSize = 0;
    const uint8_t *replayData = 0;

    if (!HdfSbufReadUint32(reply, &result->num)) {
        HDF_LOGE("%s: read num failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    if (result->num > MAX_ASSOC_STA_NUM) {
        HDF_LOGE("%s: num invalid", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    if (result->num != 0) {
        if (!HdfSbufReadBuffer(reply, (const void **)(&replayData), &replayDataSize) ||
            replayDataSize > sizeof(result->infos)) {
            HDF_LOGE("%s: read AssocStaInfo failed", __FUNCTION__);
            return RET_CODE_FAILURE;
        }
        if (memcpy_s(result->infos, sizeof(result->infos), replayData, replayDataSize) != EOK) {
            HDF_LOGE("%s: memcpy failed", __FUNCTION__);
            return RET_CODE_FAILURE;
        }
    }
    return RET_CODE_SUCCESS;
}

static int32_t HdfSbufObtainDefault(struct HdfSBuf **data, struct HdfSBuf **reply)
{
    *data = HdfSbufObtainDefaultSize();
    if (*data == NULL) {
        return RET_CODE_FAILURE;
    }
    *reply = HdfSbufObtainDefaultSize();
    if (*reply == NULL) {
        HdfSbufRecycle(*data);
        return RET_CODE_FAILURE;
    }
    return RET_CODE_SUCCESS;
}

static int32_t WifiMsgRegisterEventListener(struct HdfDevEventlistener *listener)
{
    struct HdfIoService *wifiService = GetWifiService();
    if (wifiService == NULL || listener == NULL) {
        HDF_LOGE("%s: At least one param is null", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    if (HdfDeviceRegisterEventListener(wifiService, listener) != RET_CODE_SUCCESS) {
        HDF_LOGE("%s: fail to register event listener, line: %d", __FUNCTION__, __LINE__);
        return RET_CODE_FAILURE;
    }
    g_isHasRegisterListener = true;
    return RET_CODE_SUCCESS;
}

static void WifiMsgUnregisterEventListener(struct HdfDevEventlistener *listener)
{
    struct HdfIoService *wifiService = GetWifiService();
    if (listener == NULL) {
        return;
    }
    if (HdfDeviceUnregisterEventListener(wifiService, listener) != HDF_SUCCESS) {
        HDF_LOGE("%s: fail to unregister event listener, line: %d", __FUNCTION__, __LINE__);
    }
    g_isHasRegisterListener = false;
}

int32_t WifiDriverClientInit(void)
{
    int32_t ret;
    struct HdfIoService *wifiService = InitWifiService(DRIVER_SERVICE_NAME);
    if (wifiService == NULL) {
        HDF_LOGE("%s: fail to get remote service!", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    g_wifiDevEventListener.onReceive = OnWiFiEvents;
    if (g_isHasRegisterListener) {
        HDF_LOGI("%s:has register listener!", __FUNCTION__);
        return RET_CODE_SUCCESS;
    }
    ret = WifiMsgRegisterEventListener(&g_wifiDevEventListener);
    if (ret != RET_CODE_SUCCESS) {
        HDF_LOGE("%s: register event listener failed, line: %d", __FUNCTION__, __LINE__);
    }
    return ret;
}

void WifiDriverClientDeinit(void)
{
    struct HdfIoService *wifiService = GetWifiService();
    if (wifiService == NULL) {
        return;
    }
    WifiMsgUnregisterEventListener(&g_wifiDevEventListener);
    if (HdfIoserviceGetListenerCount(wifiService) != 0) {
        HDF_LOGE("%s: the current EventListener is not empty. cancel the listener registration first.",
            __FUNCTION__);
        return;
    }
    ReleaseWifiService();
}

int32_t GetUsableNetworkInfo(struct NetworkInfoResult *result)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;

    if (result == NULL) {
        HDF_LOGE("%s params is NULL", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    if (HdfSbufObtainDefault(&data, &reply) != RET_CODE_SUCCESS) {
        return RET_CODE_FAILURE;
    }
    ret = SendCmdSync(WIFI_HAL_CMD_GET_NETWORK_INFO, data, reply);
    if (ret == RET_CODE_SUCCESS) {
        ret = ParserNetworkInfo(reply, result);
    } else {
        ret = RET_CODE_FAILURE;
    }
    HdfSbufRecycle(data);
    HdfSbufRecycle(reply);
    return ret;
}

int32_t IsSupportCombo(uint8_t *isSupportCombo)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;

    if (isSupportCombo == NULL) {
        HDF_LOGE("%s params is NULL", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    if (HdfSbufObtainDefault(&data, &reply) != RET_CODE_SUCCESS) {
        return RET_CODE_FAILURE;
    }
    ret = SendCmdSync(WIFI_HAL_CMD_IS_SUPPORT_COMBO, data, reply);
    do {
        if (ret != RET_CODE_SUCCESS) {
            break;
        }
        if (!HdfSbufReadUint8(reply, isSupportCombo)) {
            HDF_LOGE("%s: HdfSbufReadUint8 failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
        } else {
            ret = RET_CODE_SUCCESS;
        }
    } while (0);
    HdfSbufRecycle(data);
    HdfSbufRecycle(reply);
    return ret;
}

int32_t GetComboInfo(uint64_t *comboInfo, uint32_t size)
{
    int32_t ret;
    uint8_t isComboValid;
    uint32_t replayDataSize = 0;
    const uint8_t *replayData = 0;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;

    if (comboInfo == NULL) {
        HDF_LOGE("%s params is NULL", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    if (HdfSbufObtainDefault(&data, &reply) != RET_CODE_SUCCESS) {
        return RET_CODE_FAILURE;
    }
    ret = SendCmdSync(WIFI_HAL_CMD_GET_SUPPORT_COMBO, data, reply);
    do {
        if (ret != RET_CODE_SUCCESS) {
            ret = RET_CODE_FAILURE;
            break;
        }
        if (!HdfSbufReadUint8(reply, &isComboValid)) {
            HDF_LOGE("%s: read combo valid flag failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        if (!isComboValid) {
            HDF_LOGE("%s: not support combo mode", __FUNCTION__);
            ret = RET_CODE_NOT_SUPPORT;
            break;
        }
        if (!HdfSbufReadBuffer(reply, (const void **)(&replayData), &replayDataSize)) {
            HDF_LOGE("%s: HdfSbufReadBuffer failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        if (memcpy_s(comboInfo, size, replayData, replayDataSize) != EOK) {
            HDF_LOGE("%s: memcpy failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
    } while (0);
    HdfSbufRecycle(data);
    HdfSbufRecycle(reply);
    return ret;
}

int32_t SetMacAddr(const char *ifName, unsigned char *mac, uint8_t len)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;

    if (ifName == NULL || mac == NULL) {
        HDF_LOGE("%s params is NULL", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    if (HdfSbufObtainDefault(&data, &reply) != RET_CODE_SUCCESS) {
        return RET_CODE_FAILURE;
    }
    do {
        if (!HdfSbufWriteString(data, ifName)) {
            HDF_LOGE("%s: write ifName failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        if (!HdfSbufWriteBuffer(data, mac, len)) {
            HDF_LOGE("%s: write mac failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        ret = SendCmdSync(WIFI_HAL_CMD_SET_MAC_ADDR, data, reply);
    } while (0);
    HdfSbufRecycle(data);
    HdfSbufRecycle(reply);
    return ret;
}

int32_t GetDevMacAddr(const char *ifName, int32_t type, uint8_t *mac, uint8_t len)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;

    if (ifName == NULL || mac == NULL) {
        HDF_LOGE("%s params is NULL", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    if (HdfSbufObtainDefault(&data, &reply) != RET_CODE_SUCCESS) {
        return RET_CODE_FAILURE;
    }
    do {
        if (!HdfSbufWriteString(data, ifName)) {
            HDF_LOGE("%s: write ifName failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        if (!HdfSbufWriteInt32(data, type)) {
            HDF_LOGE("%s: write type failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        ret = SendCmdSync(WIFI_HAL_CMD_GET_DEV_MAC_ADDR, data, reply);
        if (ret != RET_CODE_SUCCESS) {
            ret = RET_CODE_FAILURE;
            break;
        }
        ret = ParserDeviceMacAddr(reply, mac, len);
    } while (0);
    HdfSbufRecycle(data);
    HdfSbufRecycle(reply);
    return ret;
}

int32_t GetValidFreqByBand(const char *ifName, int32_t band, struct FreqInfoResult *result, uint32_t size)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;

    if (ifName == NULL || result == NULL || band >= IEEE80211_NUM_BANDS) {
        HDF_LOGE("%s params is NULL", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    if (HdfSbufObtainDefault(&data, &reply) != RET_CODE_SUCCESS) {
        return RET_CODE_FAILURE;
    }
    do {
        if (!HdfSbufWriteString(data, ifName)) {
            HDF_LOGE("%s: write ifName failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        if (!HdfSbufWriteInt32(data, band)) {
            HDF_LOGE("%s: write band failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        ret = SendCmdSync(WIFI_HAL_CMD_GET_VALID_FREQ, data, reply);
        if (ret != RET_CODE_SUCCESS) {
            ret = RET_CODE_FAILURE;
            break;
        }
        ret = ParserFreqInfo(reply, result, size);
    } while (0);
    HdfSbufRecycle(data);
    HdfSbufRecycle(reply);
    return ret;
}

int32_t SetTxPower(const char *ifName, int32_t power)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;

    if (ifName == NULL) {
        HDF_LOGE("%s params is NULL", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    if (HdfSbufObtainDefault(&data, &reply) != RET_CODE_SUCCESS) {
        return RET_CODE_FAILURE;
    }
    do {
        if (!HdfSbufWriteString(data, ifName)) {
            HDF_LOGE("%s: write ifName failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        if (!HdfSbufWriteInt32(data, power)) {
            HDF_LOGE("%s: HdfSbufWriteInt32 failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        ret = SendCmdSync(WIFI_HAL_CMD_SET_TX_POWER, data, reply);
    } while (0);
    HdfSbufRecycle(data);
    HdfSbufRecycle(reply);
    return ret;
}

int32_t GetAssociatedStas(const char *ifName, struct AssocStaInfoResult *result)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;

    if (ifName == NULL || result == NULL) {
        HDF_LOGE("%s params is NULL", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    if (HdfSbufObtainDefault(&data, &reply) != RET_CODE_SUCCESS) {
        return RET_CODE_FAILURE;
    }
    do {
        if (!HdfSbufWriteString(data, ifName)) {
            HDF_LOGE("%s: write ifName failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        ret = SendCmdSync(WIFI_HAL_CMD_GET_ASSOC_STA, data, reply);
        if (ret != RET_CODE_SUCCESS) {
            ret = RET_CODE_FAILURE;
            break;
        }
        ret = ParserAssociatedStas(reply, result);
    } while (0);
    HdfSbufRecycle(data);
    HdfSbufRecycle(reply);
    return ret;
}

int32_t WifiSetCountryCode(const char *ifName, const char *code, uint32_t len)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;

    if (ifName == NULL || code == NULL) {
        HDF_LOGE("%s params is NULL", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    if (HdfSbufObtainDefault(&data, &reply) != RET_CODE_SUCCESS) {
        return RET_CODE_FAILURE;
    }
    do {
        if (!HdfSbufWriteString(data, ifName)) {
            HDF_LOGE("%s: write ifName failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        if (!HdfSbufWriteBuffer(data, code, len)) {
            HDF_LOGE("%s: write code failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        ret = SendCmdSync(WIFI_HAL_CMD_SET_COUNTRY_CODE, data, reply);
    } while (0);
    HdfSbufRecycle(data);
    HdfSbufRecycle(reply);
    return ret;
}

int32_t SetScanMacAddr(const char *ifName, uint8_t *scanMac, uint8_t len)
{
    int32_t ret;
    uint8_t isFuncValid;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;

    if (ifName == NULL || scanMac == NULL) {
        HDF_LOGE("%s params is NULL", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    if (HdfSbufObtainDefault(&data, &reply) != RET_CODE_SUCCESS) {
        return RET_CODE_FAILURE;
    }
    do {
        if (!HdfSbufWriteString(data, ifName)) {
            HDF_LOGE("%s: write ifName failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        if (!HdfSbufWriteBuffer(data, scanMac, len)) {
            HDF_LOGE("%s: write scan mac failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        ret = SendCmdSync(WIFI_HAL_CMD_SET_SCAN_MAC_ADDR, data, reply);
        if (ret != RET_CODE_SUCCESS) {
            break;
        }
        if (!HdfSbufReadUint8(reply, &isFuncValid)) {
            HDF_LOGE("%s: read valid flag failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        if (!isFuncValid) {
            HDF_LOGE("%s: not support to set scan mac addr", __FUNCTION__);
            ret = RET_CODE_NOT_SUPPORT;
            break;
        }
    } while (0);
    HdfSbufRecycle(data);
    HdfSbufRecycle(reply);
    return ret;
}

int32_t AcquireChipId(const char *ifName, uint8_t *chipId)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;

    if (ifName == NULL || chipId == NULL) {
        HDF_LOGE("%s params is NULL", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    if (HdfSbufObtainDefault(&data, &reply) != RET_CODE_SUCCESS) {
        return RET_CODE_FAILURE;
    }
    do {
        if (!HdfSbufWriteString(data, ifName)) {
            HDF_LOGE("%s: HdfSbufWriteString failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        ret = SendCmdSync(WIFI_HAL_CMD_GET_CHIPID, data, reply);
        if (ret != RET_CODE_SUCCESS) {
            break;
        }
        if (!HdfSbufReadUint8(reply, chipId)) {
            HDF_LOGE("%s:  HdfSbufReadUint8 failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
    } while (0);
    HdfSbufRecycle(data);
    HdfSbufRecycle(reply);
    return ret;
}

static int32_t GetIfNames(struct HdfSBuf *reply, char **ifNames, uint32_t *num)
{
    uint32_t i;
    uint32_t replayDataSize = 0;
    const char *replayData = NULL;

    if (!HdfSbufReadUint32(reply, num)) {
        HDF_LOGE("%s: HdfSbufReadUint32 failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    *ifNames = (char *)calloc(*num, IFNAMSIZ);
    if (*ifNames == NULL) {
        HDF_LOGE("%s: calloc failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }

    if (!HdfSbufReadBuffer(reply, (const void **)(&replayData), &replayDataSize) ||
        replayDataSize < (*num * IFNAMSIZ)) {
        HDF_LOGE("%s: HdfSbufReadBuffer failed", __FUNCTION__);
        free(*ifNames);
        *ifNames = NULL;
        return RET_CODE_FAILURE;
    }

    for (i = 0; i < *num; i++) {
        if (memcpy_s(*ifNames + i * IFNAMSIZ, IFNAMSIZ, replayData + i * IFNAMSIZ, replayDataSize) != EOK) {
            HDF_LOGE("%s: memcpy failed", __FUNCTION__);
            free(*ifNames);
            *ifNames = NULL;
            return RET_CODE_FAILURE;
        }
    }
    return RET_CODE_SUCCESS;
}

int32_t GetIfNamesByChipId(const uint8_t chipId, char **ifNames, uint32_t *num)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;

    if (ifNames == NULL || num == NULL) {
        HDF_LOGE("%s params is NULL", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    if (HdfSbufObtainDefault(&data, &reply) != RET_CODE_SUCCESS) {
        return RET_CODE_FAILURE;
    }
    do {
        if (!HdfSbufWriteUint8(data, chipId)) {
            HDF_LOGE("%s: HdfSbufWriteUint8 failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        ret = SendCmdSync(WIFI_HAL_CMD_GET_IFNAMES, data, reply);
        if (ret != RET_CODE_SUCCESS) {
            break;
        }
        ret = GetIfNames(reply, ifNames, num);
    } while (0);
    HdfSbufRecycle(data);
    HdfSbufRecycle(reply);
    return ret;
}

int32_t SetResetDriver(const uint8_t chipId, const char *ifName)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;

    if (HdfSbufObtainDefault(&data, &reply) != RET_CODE_SUCCESS) {
        return RET_CODE_FAILURE;
    }
    do {
        if (!HdfSbufWriteUint8(data, chipId)) {
            HDF_LOGE("%s: HdfSbufWriteUint8 failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        if (!HdfSbufWriteString(data, ifName)) {
            HDF_LOGE("%s: Serialize failed!", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        ret = SendCmdSync(WIFI_HAL_CMD_RESET_DRIVER, data, reply);
    } while (0);
    HdfSbufRecycle(data);
    HdfSbufRecycle(reply);
    return ret;
}

int32_t GetNetDeviceInfo(struct NetDeviceInfoResult *netDeviceInfoResult)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    uint32_t netdevNum = 0;
    uint32_t ifNameSize;
    uint32_t macSize;
    uint32_t i;
    const uint8_t *replayData = NULL;
    const char *ifName = NULL;

    if (netDeviceInfoResult == NULL) {
        HDF_LOGE("%s: params is NULL", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    if (HdfSbufObtainDefault(&data, &reply) != RET_CODE_SUCCESS) {
        return RET_CODE_FAILURE;
    }
    do {
        ret = SendCmdSync(WIFI_HAL_CMD_GET_NETDEV_INFO, data, reply);
        if (ret != RET_CODE_SUCCESS) {
            break;
        }
        if (!HdfSbufReadUint32(reply, &netdevNum)) {
            HDF_LOGE("%s: HdfSbufReadUint32 failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        for (i = 0; i < netdevNum; i++) {
            if (!HdfSbufReadUint32(reply, &(netDeviceInfoResult->deviceInfos[i].index)) ||
                !HdfSbufReadBuffer(reply, (const void **)(&ifName), &ifNameSize) ||
                !HdfSbufReadUint8(reply, &(netDeviceInfoResult->deviceInfos[i].iftype)) ||
                !HdfSbufReadBuffer(reply, (const void **)(&replayData), &macSize)) {
                HDF_LOGE("%s: read fail!", __FUNCTION__);
                ret = RET_CODE_FAILURE;
                break;
            }
            if (memcpy_s(netDeviceInfoResult->deviceInfos[i].ifName, ifNameSize, ifName, ifNameSize) != EOK) {
                HDF_LOGE("%s: memcpy failed", __FUNCTION__);
                ret = RET_CODE_FAILURE;
                break;
            }
            if (memcpy_s(netDeviceInfoResult->deviceInfos[i].mac, macSize, replayData, macSize) != EOK) {
                HDF_LOGE("%s: memcpy failed", __FUNCTION__);
                ret = RET_CODE_FAILURE;
                break;
            }
        }
    } while (0);
    HdfSbufRecycle(data);
    HdfSbufRecycle(reply);
    return ret;
}

int32_t GetCurrentPowerMode(const char *ifName, uint8_t *mode)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;

    if (HdfSbufObtainDefault(&data, &reply) != RET_CODE_SUCCESS) {
        HDF_LOGE("%s: HdfSbufObtainDefault fail", __FUNCTION__);
        return RET_CODE_FAILURE;
    }

    do {
        if (!HdfSbufWriteString(data, ifName)) {
            HDF_LOGE("%s: write ifName fail!", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        ret = SendCmdSync(WIFI_HAL_CMD_GET_POWER_MODE, data, reply);
        if (ret != RET_CODE_SUCCESS) {
            HDF_LOGE("%s: SendCmdSync fail!", __FUNCTION__);
            break;
        }
        if (!HdfSbufReadUint8(reply, mode)) {
            HDF_LOGE("%s: HdfSbufReadUint8 failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
    } while (0);

    HdfSbufRecycle(data);
    HdfSbufRecycle(reply);
    return ret;
}

int32_t SetPowerMode(const char *ifName, uint8_t mode)
{
    int32_t ret = RET_CODE_FAILURE;
    struct HdfSBuf *data = NULL;

    data = HdfSbufObtainDefaultSize();
    if (data == NULL) {
        HDF_LOGE("%s: HdfSbufObtainDefaultSize fail!", __FUNCTION__);
        return ret;
    }

    do {
        if (!HdfSbufWriteString(data, ifName)) {
            HDF_LOGE("%s: write ifName fail!", __FUNCTION__);
            break;
        }
        if (!HdfSbufWriteUint8(data, mode)) {
            HDF_LOGE("%s: write ifName fail!", __FUNCTION__);
            break;
        }
        ret = SendCmdSync(WIFI_HAL_CMD_SET_POWER_MODE, data, NULL);
    } while (0);

    HdfSbufRecycle(data);
    return ret;
}

int32_t WifiCmdScan(const char *ifName, WifiScan *scan)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;

    if (ifName == NULL || scan == NULL) {
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
    if (scan->bssid == NULL) {
        isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, scan->bssid, 0);
    } else {
        isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, scan->bssid, ETH_ADDR_LEN);
    }
    isSerializeFailed =
        isSerializeFailed || !HdfSbufWriteBuffer(data, scan->ssids, sizeof(scan->ssids[0]) * scan->numSsids);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteBuffer(data, scan->extraIes, scan->extraIesLen);
    isSerializeFailed =
        isSerializeFailed || !HdfSbufWriteBuffer(data, scan->freqs, sizeof(scan->freqs[0]) * scan->numFreqs);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteUint8(data, scan->prefixSsidScanFlag);
    isSerializeFailed = isSerializeFailed || !HdfSbufWriteUint8(data, scan->fastConnectFlag);
    if (isSerializeFailed) {
        HDF_LOGE("%s: Serialize failed!", __FUNCTION__);
        ret = RET_CODE_FAILURE;
    } else {
        ret = SendCmdSync(WIFI_WPA_CMD_SCAN, data, NULL);
    }
    HdfSbufRecycle(data);
    return ret;
}

int32_t StartChannelMeas(const char *ifName, const struct MeasParam *measParam)
{
    int32_t ret = RET_CODE_FAILURE;
    struct HdfSBuf *data = NULL;

    data = HdfSbufObtainDefaultSize();
    if (data == NULL) {
        HDF_LOGE("%s: HdfSbufObtainDefaultSize fail!", __FUNCTION__);
        return ret;
    }

    do {
        if (!HdfSbufWriteString(data, ifName)) {
            HDF_LOGE("%s: write ifName fail!", __FUNCTION__);
            break;
        }
        if (!HdfSbufWriteBuffer(data, measParam, sizeof(struct MeasParam))) {
            HDF_LOGE("%s: write paramBuf fail!", __FUNCTION__);
            break;
        }
        ret = SendCmdSync(WIFI_HAL_CMD_START_CHANNEL_MEAS, data, NULL);
    } while (0);

    HdfSbufRecycle(data);
    return ret;
}

int32_t SetProjectionScreenParam(const char *ifName, const ProjectionScreenParam *param)
{
    int32_t ret = RET_CODE_FAILURE;
    struct HdfSBuf *req = NULL;

    req = HdfSbufObtainDefaultSize();
    if (req == NULL) {
        HDF_LOGE("%{public}s: HdfSbufObtainDefaultSize fail!", __FUNCTION__);
        return ret;
    }

    do {
        if (!HdfSbufWriteString(req, ifName)) {
            HDF_LOGE("%{public}s: write ifName fail!", __FUNCTION__);
            break;
        }
        if (!HdfSbufWriteInt32(req, param->cmdId)) {
            HDF_LOGE("%{public}s: write cmd fail!", __FUNCTION__);
            break;
        }
        if (!HdfSbufWriteBuffer(req, param->buf, param->bufLen)) {
            HDF_LOGE("%{public}s: write buffer data fail!", __FUNCTION__);
            break;
        }
        ret = SendCmdSync(WIFI_HAL_CMD_CONFIG_PROJECTION_SCREEN, req, NULL);
        if (ret != RET_CODE_SUCCESS) {
            HDF_LOGE("%{public}s: SendCmdSync fail, ret = %{public}d!", __FUNCTION__, ret);
        }
    } while (0);

    HdfSbufRecycle(req);
    return ret;
}

int32_t SendCmdIoctl(const char *ifName, int32_t cmdId, const int8_t *paramBuf, uint32_t paramBufLen)
{
    int ret = RET_CODE_FAILURE;
    struct HdfSBuf *req = NULL;

    req = HdfSbufObtainDefaultSize();
    if (req == NULL) {
        HDF_LOGE("%{public}s: HdfSbufObtainDefaultSize fail!", __FUNCTION__);
        return ret;
    }

    do {
        if (!HdfSbufWriteString(req, ifName)) {
            HDF_LOGE("%{public}s: write ifName fail!", __FUNCTION__);
            break;
        }
        if (!HdfSbufWriteInt32(req, cmdId)) {
            HDF_LOGE("%{public}s: write cmd fail!", __FUNCTION__);
            break;
        }
        if (!HdfSbufWriteBuffer(req, paramBuf, paramBufLen)) {
            HDF_LOGE("%{public}s: write buffer data fail!", __FUNCTION__);
            break;
        }
        ret = SendCmdSync(WIFI_HAL_CMD_SET_CMD_IOCTL, req, NULL);
        if (ret != RET_CODE_SUCCESS) {
            HDF_LOGE("%{public}s: SendCmdSync fail, ret = %{public}d!", __FUNCTION__, ret);
        }
    } while (0);

    HdfSbufRecycle(req);
    return ret;
}

int32_t GetStationInfo(const char *ifName, StationInfo *info, const uint8_t *mac, uint32_t macLen)
{
    int32_t ret = RET_CODE_FAILURE;
    
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    const uint8_t *replayData = NULL;
    uint32_t size;

    if (HdfSbufObtainDefault(&data, &reply) != RET_CODE_SUCCESS) {
        return RET_CODE_FAILURE;
    }

    do {
        if (!HdfSbufWriteString(data, ifName)) {
            HDF_LOGE("%{public}s: write ifName fail!", __FUNCTION__);
            break;
        }
        if (!HdfSbufWriteBuffer(data, mac, macLen)) {
            HDF_LOGE("%{public}s: write mac address fail!", __FUNCTION__);
            break;
        }
        ret = SendCmdSync(WIFI_HAL_CMD_GET_STATION_INFO, data, reply);
        if (ret != RET_CODE_SUCCESS) {
            HDF_LOGE("%{public}s: SendCmdSync fail, ret = %{public}d!", __FUNCTION__, ret);
            break;
        }
        if (!HdfSbufReadBuffer(reply, (const void **)(&replayData), &size)) {
            HDF_LOGE("%{public}s: read station information fail!", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        if (memcpy_s(info, sizeof(StationInfo), replayData, size) != EOK) {
            HDF_LOGE("%{public}s: memcpy_s fail", __FUNCTION__);
            ret = RET_CODE_FAILURE;
        }
    } while (0);
    HdfSbufRecycle(data);
    HdfSbufRecycle(reply);
    return ret;
}

static int32_t SerializeSettingsToSbuf(struct HdfSBuf *req, const WifiPnoSettings *pnoSettings)
{
    if (!HdfSbufWriteInt32(req, pnoSettings->min2gRssi)) {
        HDF_LOGE("%{public}s: write min2gRssi fail!", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    if (!HdfSbufWriteInt32(req, pnoSettings->min5gRssi)) {
        HDF_LOGE("%{public}s: write min5gRssi fail!", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    if (!HdfSbufWriteInt32(req, pnoSettings->scanIntervalMs)) {
        HDF_LOGE("%{public}s: write scanIntervalMs fail!", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    if (!HdfSbufWriteInt32(req, pnoSettings->scanIterations)) {
        HDF_LOGE("%{public}s: write scanIterations fail!", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    if (!HdfSbufWriteUint32(req, pnoSettings->pnoNetworksLen)) {
        HDF_LOGE("%{public}s: write pnoNetworksLen fail!", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    for (uint32_t i = 0; i < pnoSettings->pnoNetworksLen; i++) {
        if (!HdfSbufWriteUint8(req, pnoSettings->pnoNetworks[i].isHidden)) {
            HDF_LOGE("%{public}s: write isHidden fail!", __FUNCTION__);
            return RET_CODE_FAILURE;
        }
        if (!HdfSbufWriteBuffer(req, pnoSettings->pnoNetworks[i].freqs,
            sizeof(int32_t) * (pnoSettings->pnoNetworks[i].freqsLen))) {
            HDF_LOGE("%{public}s: write freqs fail!", __FUNCTION__);
            return RET_CODE_FAILURE;
        }
        if (!HdfSbufWriteBuffer(req, pnoSettings->pnoNetworks[i].ssid.ssid,
            pnoSettings->pnoNetworks[i].ssid.ssidLen)) {
            HDF_LOGE("%{public}s: write ssid fail!", __FUNCTION__);
            return RET_CODE_FAILURE;
        }
    }
    return RET_CODE_SUCCESS;
}

int32_t WifiStartPnoScan(const char *ifName, const WifiPnoSettings *pnoSettings)
{
    int32_t ret = RET_CODE_FAILURE;
    struct HdfSBuf *req = NULL;

    if (ifName == NULL || pnoSettings == NULL) {
        HDF_LOGE("%s: Input param is null", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    req = HdfSbufObtain(PNO_SCAN_INFO_MAXSIZE);
    if (req == NULL) {
        HDF_LOGE("%s: HdfSbufObtainDefaultSize fail", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    do {
        if (!HdfSbufWriteString(req, ifName)) {
            HDF_LOGE("%{public}s: write ifName fail!", __FUNCTION__);
            break;
        }
        if (SerializeSettingsToSbuf(req, pnoSettings) != RET_CODE_SUCCESS) {
            HDF_LOGE("%{public}s:SerilizeSettingsToSbuf fail!", __FUNCTION__);
            break;
        }
        ret = SendCmdSync(WIFI_HAL_CMD_START_PNO_SCAN, req, NULL);
        if (ret != RET_CODE_SUCCESS) {
            HDF_LOGE("%{public}s: SendCmdSync fail, ret = %{public}d!", __FUNCTION__, ret);
        }
    } while (0);
    HdfSbufRecycle(req);
    return ret;
}

int32_t WifiStopPnoScan(const char *ifName)
{
    int32_t ret = RET_CODE_FAILURE;
    struct HdfSBuf *req = NULL;

    req = HdfSbufObtainDefaultSize();
    if (req == NULL) {
        HDF_LOGE("%{public}s: HdfSbufObtainDefaultSize fail!", __FUNCTION__);
        return ret;
    }

    do {
        if (!HdfSbufWriteString(req, ifName)) {
            HDF_LOGE("%{public}s: write ifName fail!", __FUNCTION__);
            break;
        }
        ret = SendCmdSync(WIFI_HAL_CMD_STOP_PNO_SCAN, req, NULL);
        if (ret != RET_CODE_SUCCESS) {
            HDF_LOGE("%{public}s: SendCmdSync fail, ret = %{public}d!", __FUNCTION__, ret);
        }
    } while (0);

    HdfSbufRecycle(req);
    return ret;
}

int32_t ClientGetApBandwidth(const char *ifName, uint8_t *bandwidth)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;

    if (HdfSbufObtainDefault(&data, &reply) != RET_CODE_SUCCESS) {
        HDF_LOGE("%s: HdfSbufObtainDefault fail", __FUNCTION__);
        return RET_CODE_FAILURE;
    }

    do {
        if (!HdfSbufWriteString(data, ifName)) {
            HDF_LOGE("%s: write ifName fail!", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        ret = SendCmdSync(WIFI_HAL_CMD_GET_AP_BANDWIDTH, data, reply);
        if (ret != RET_CODE_SUCCESS) {
            HDF_LOGE("%s: SendCmdSync fail, code=%d", __FUNCTION__, ret);
            break;
        }
        if (!HdfSbufReadUint8(reply, bandwidth)) {
            HDF_LOGE("%s: HdfSbufReadUint8 failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
    } while (0);

    HdfSbufRecycle(data);
    HdfSbufRecycle(reply);
    return ret;
}

int32_t WifiGetSignalPollInfo(const char *ifName, struct SignalResult *signalResult)
{
    int32_t ret = RET_CODE_FAILURE;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    const uint8_t *replayData = NULL;
    uint32_t size;

    if (HdfSbufObtainDefault(&data, &reply) != RET_CODE_SUCCESS) {
        return RET_CODE_FAILURE;
    }
    do {
        if (!HdfSbufWriteString(data, ifName)) {
            HDF_LOGE("%{public}s: write ifName fail!", __FUNCTION__);
            break;
        }
        ret = SendCmdSync(WIFI_HAL_CMD_GET_SIGNAL_INFO, data, reply);
        if (ret != RET_CODE_SUCCESS) {
            HDF_LOGE("%{public}s: SendCmdSync fail, ret = %{public}d!", __FUNCTION__, ret);
            break;
        }
        if (!HdfSbufReadBuffer(reply, (const void **)(&replayData), &size)) {
            HDF_LOGE("%{public}s: read signal information fail!", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        if (memcpy_s(signalResult, sizeof(struct SignalResult), replayData, size) != EOK) {
            HDF_LOGE("%{public}s: memcpy_s fail", __FUNCTION__);
            ret = RET_CODE_FAILURE;
        }
    } while (0);
    HdfSbufRecycle(data);
    HdfSbufRecycle(reply);
    return ret;
}

int32_t WifiSendActionFrame(const char *ifName, uint32_t freq, const uint8_t *frameData, uint32_t frameDataLen)
{
    (void)ifName;
    (void)freq;
    (void)frameData;
    (void)frameDataLen;
    return RET_CODE_NOT_SUPPORT;
}

int32_t WifiRegisterActionFrameReceiver(const char *ifName, const uint8_t *match, uint32_t matchLen)
{
    (void)ifName;
    (void)match;
    (void)matchLen;
    return RET_CODE_NOT_SUPPORT;
}

int32_t WifiSetPowerSaveMode(const char *ifName, int32_t frequency, int32_t mode)
{
    (void)ifName;
    (void)frequency;
    (void)mode;

    return RET_CODE_NOT_SUPPORT;
}

int32_t WifiSetDpiMarkRule(int32_t uid, int32_t protocol, int32_t enable)
{
    (void)uid;
    (void)protocol;
    (void)enable;

    return RET_CODE_NOT_SUPPORT;
}

int32_t WifiInstallWlanExtParam(const char *ifName, const InstallWlanParam *param)
{
    (void)ifName;
    (void)param;

    return RET_CODE_NOT_SUPPORT;
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
