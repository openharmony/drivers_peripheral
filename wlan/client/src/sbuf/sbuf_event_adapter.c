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

#include "../wifi_common_cmd.h"
#include "hdf_io_service.h"
#include "hdf_sbuf.h"
#include "hdf_log.h"
#include "securec.h"
#include "wifi_driver_client.h"
#include <osal_mem.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

WifiScanResults g_scanResults = { 0 };

static void WifiEventNewStaProcess(const char *ifName, uint32_t event, struct HdfSBuf *reqData)
{
    WifiNewStaInfo staInfo;
    uint32_t len = 0;

    if (!HdfSbufReadInt32(reqData, &staInfo.reassoc)) {
        HDF_LOGE("%s: fail to get reassoc", __FUNCTION__);
        return;
    }
    if (!HdfSbufReadBuffer(reqData, (const void **)(&staInfo.ie), &staInfo.ieLen)) {
        HDF_LOGE("%s: fail to get ie", __FUNCTION__);
        return;
    }
    if (!HdfSbufReadBuffer(reqData, (const void **)(&staInfo.macAddr), &len) || (len != ETH_ADDR_LEN)) {
        HDF_LOGE("%s: fail to get macAddr", __FUNCTION__);
        return;
    }
    WifiEventReport(ifName, event, &staInfo);
}

static void WifiEventDelStaProcess(const char *ifName, uint32_t event, struct HdfSBuf *reqData)
{
    uint8_t *addr = NULL;
    uint32_t len = 0;

    if ((!HdfSbufReadBuffer(reqData, (const void **)(&addr), &len)) || (len != ETH_ADDR_LEN)) {
        HDF_LOGE("%s: fail to get macAddr", __FUNCTION__);
        return;
    }
    WifiEventReport(ifName, event, addr);
}

static void WifiEventRxMgmtProcess(const char *ifName, uint32_t event, struct HdfSBuf *reqData)
{
    WifiRxMgmt rxMgmt;

    if (!HdfSbufReadInt32(reqData, &rxMgmt.freq)) {
        HDF_LOGE("%s: fail to get freq", __FUNCTION__);
        return;
    }
    if (!HdfSbufReadInt32(reqData, &rxMgmt.sigMbm)) {
        HDF_LOGE("%s: fail to get sigMbm", __FUNCTION__);
        return;
    }
    if (!HdfSbufReadBuffer(reqData, (const void **)(&rxMgmt.buf), &rxMgmt.len)) {
        HDF_LOGE("%s: fail to get buf", __FUNCTION__);
        return;
    }
    WifiEventReport(ifName, event, &rxMgmt);
}

static void WifiEventTxStatusProcess(const char *ifName, uint32_t event, struct HdfSBuf *reqData)
{
    WifiTxStatus txStatus;

    if (!HdfSbufReadUint8(reqData, &txStatus.ack)) {
        HDF_LOGE("%s: fail to get ack", __FUNCTION__);
        return;
    }
    if (!HdfSbufReadBuffer(reqData, (const void **)(&txStatus.buf), &txStatus.len)) {
        HDF_LOGE("%s: fail to get buf", __FUNCTION__);
        return;
    }
    WifiEventReport(ifName, event, &txStatus);
}

static void WifiEventScanDoneProcess(const char *ifName, uint32_t event, struct HdfSBuf *reqData)
{
    uint32_t status;

    if (!HdfSbufReadUint32(reqData, &status)) {
        HDF_LOGE("%s: fail to get status", __FUNCTION__);
        return;
    }
    if (g_scanResults.scanResult == NULL) {
        HDF_LOGE("%s: g_scanResults.scanResult is NULL", __FUNCTION__);
        return;
    }
    WifiEventReport(ifName, WIFI_EVENT_SCAN_RESULTS, &g_scanResults);
    HDF_LOGI("%s: g_scanResults.num = %u", __FUNCTION__, g_scanResults.num);
    FreeScanResults(&g_scanResults);
    WifiEventReport(ifName, event, &status);
}

static int32_t FillScanResult(WifiScanResult *dst, WifiScanResult *src)
{
    int32_t ret = RET_CODE_FAILURE;

    if (dst == NULL || src == NULL || src->bssid == NULL || src->ie == NULL || src->beaconIe == NULL ||
        src->ieLen == 0 || src->beaconIeLen == 0) {
        HDF_LOGE("%s: Invalid parameters", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    if (memcpy_s(dst, sizeof(WifiScanResult), src, sizeof(WifiScanResult)) != EOK) {
        return RET_CODE_FAILURE;
    }
    do {
        dst->bssid = OsalMemCalloc(ETH_ADDR_LEN);
        if (dst->bssid == NULL) {
            HDF_LOGE("%s: OsalMemCalloc bssid fail", __FUNCTION__);
            break;
        }
        if (memcpy_s(dst->bssid, ETH_ADDR_LEN, src->bssid, ETH_ADDR_LEN) != EOK) {
            HDF_LOGE("%s: memcpy_s bssid fail", __FUNCTION__);
            break;
        }
        dst->ie = OsalMemCalloc(src->ieLen);
        if (dst->ie == NULL) {
            HDF_LOGE("%s: OsalMemCalloc ie fail", __FUNCTION__);
            break;
        }
        if (memcpy_s(dst->ie, src->ieLen, src->ie, src->ieLen) != EOK) {
            HDF_LOGE("%s: memcpy_s ie fail", __FUNCTION__);
            break;
        }
        dst->beaconIe = OsalMemCalloc(src->beaconIeLen);
        if (dst->beaconIe == NULL) {
            HDF_LOGE("%s: OsalMemCalloc beaconIe fail", __FUNCTION__);
            break;
        }
        if (memcpy_s(dst->beaconIe, src->beaconIeLen, src->beaconIe, src->beaconIeLen) != EOK) {
            HDF_LOGE("%s: memcpy_s beaconIe fail", __FUNCTION__);
            break;
        }
        ret = RET_CODE_SUCCESS;
    } while (0);
    if (ret != RET_CODE_SUCCESS) {
        FreeScanResult(dst);
    }
    return ret;
}

static void WifiEventScanResultProcess(const char *ifName, uint32_t event, struct HdfSBuf *reqData)
{
    WifiScanResult scanResult = { 0 };
    uint32_t len = 0;

    if (g_scanResults.scanResult == NULL) {
        if (InitScanResults(&g_scanResults) != RET_CODE_SUCCESS) {
            HDF_LOGE("%s: InitScanResults failed",  __FUNCTION__);
            return;
        }
    }
    if (!HdfSbufReadUint16(reqData, &(scanResult.beaconInt))) {
        HDF_LOGE("%s: fail to get beaconInt", __FUNCTION__);
        return;
    }
    if (!HdfSbufReadUint16(reqData, &(scanResult.caps))) {
        HDF_LOGE("%s: fail to get caps", __FUNCTION__);
        return;
    }
    if (!HdfSbufReadInt32(reqData, &(scanResult.level))) {
        HDF_LOGE("%s: fail to get level", __FUNCTION__);
        return;
    }
    scanResult.level /= SIGNAL_LEVEL_CONFFICIENT;  /* mBm to dBm */
    if (!HdfSbufReadUint32(reqData, &(scanResult.freq))) {
        HDF_LOGE("%s: fail to get freq", __FUNCTION__);
        return;
    }
    if (!HdfSbufReadUint32(reqData, &(scanResult.flags))) {
        HDF_LOGE("%s: fail to get flags", __FUNCTION__);
        return;
    }
    if ((!HdfSbufReadBuffer(reqData, (const void **)(&(scanResult.bssid)), &len)) || len != ETH_ADDR_LEN) {
        HDF_LOGE("%s: fail to get bssid", __FUNCTION__);
        return;
    }
    if (!HdfSbufReadBuffer(reqData, (const void **)(&(scanResult.ie)), &(scanResult.ieLen))) {
        HDF_LOGE("%s: fail to get ie", __FUNCTION__);
        return;
    }
    if (!HdfSbufReadBuffer(reqData, (const void **)(&(scanResult.beaconIe)), &(scanResult.beaconIeLen))) {
        HDF_LOGE("%s: fail to get beaconIe", __FUNCTION__);
        return;
    }
    WifiEventReport(ifName, event, &scanResult);
    if (FillScanResult(&g_scanResults.scanResult[g_scanResults.num], &scanResult) != EOK) {
        HDF_LOGE("%s: fail to fill scan result", __FUNCTION__);
        return;
    }
    g_scanResults.num++;
    if (g_scanResults.num == g_scanResults.scanResultCapacity) {
        g_scanResults.scanResultCapacity += INIT_SCAN_RES_NUM;
        WifiScanResult *newScanResult = NULL;
        newScanResult = (WifiScanResult *)OsalMemCalloc(sizeof(WifiScanResult) * (g_scanResults.scanResultCapacity));
        if (newScanResult == NULL) {
            HDF_LOGE("%s: newscanResult is NULL",  __FUNCTION__);
            g_scanResults.num = 0;
            g_scanResults.scanResultCapacity -= INIT_SCAN_RES_NUM;
            return;
        }
        if (memcpy_s((void *)newScanResult, sizeof(WifiScanResult) * (g_scanResults.scanResultCapacity),
            (void *)g_scanResults.scanResult, sizeof(WifiScanResult) * (g_scanResults.num)) != RET_CODE_SUCCESS) {
            HDF_LOGE("%s: memcpy_s fail",  __FUNCTION__);
        }
        OsalMemFree(&g_scanResults.scanResult);
        g_scanResults.scanResult = newScanResult;
        newScanResult = NULL;
    }
}

static void WifiEventConnectResultProcess(const char *ifName, uint32_t event, struct HdfSBuf *reqData)
{
    WifiConnectResult result;
    uint32_t len = 0;

    if (!HdfSbufReadUint16(reqData, &(result.status))) {
        HDF_LOGE("%s: fail to get status", __FUNCTION__);
        return;
    }
    if (!HdfSbufReadUint16(reqData, &(result.freq))) {
        HDF_LOGE("%s: fail to get freq", __FUNCTION__);
        return;
    }
    if ((!HdfSbufReadBuffer(reqData, (const void **)(&(result.bssid)), &len)) || len != ETH_ADDR_LEN) {
        HDF_LOGE("%s: fail to get bssid", __FUNCTION__);
        return;
    }
    if (!HdfSbufReadBuffer(reqData, (const void **)(&(result.reqIe)), &(result.reqIeLen))) {
        HDF_LOGE("%s: fail to get reqIe", __FUNCTION__);
        return;
    }
    if (!HdfSbufReadBuffer(reqData, (const void **)(&(result.respIe)), &(result.respIeLen))) {
        HDF_LOGE("%s: fail to get respIe", __FUNCTION__);
        return;
    }
    WifiEventReport(ifName, event, &result);
}

static void WifiEventDisconnectProcess(const char *ifName, uint32_t event, struct HdfSBuf *reqData)
{
    WifiDisconnect result;

    if (!HdfSbufReadUint16(reqData, &(result.reason))) {
        HDF_LOGE("%s: fail to get reason", __FUNCTION__);
        return;
    }
    if (!HdfSbufReadBuffer(reqData, (const void **)(&(result.ie)), &(result.ieLen))) {
        HDF_LOGE("%s: fail to get bssid", __FUNCTION__);
        return;
    }
    WifiEventReport(ifName, event, &result);
}

static void WifiDriverEventEapolRecvProcess(const char *ifName, uint32_t event, struct HdfSBuf *reqData)
{
    WifiEventReport(ifName, event, reqData);
}

static void WifiEventResetDriverProcess(const char *ifName, int32_t event, struct HdfSBuf *reqData)
{
    unsigned char chipId;
    int resetStatus;

    if (!HdfSbufReadInt32(reqData, &resetStatus)) {
        HDF_LOGE("%s: fail to get resetStatus, line: %d", __FUNCTION__, __LINE__);
        return;
    }
    if (!HdfSbufReadUint8(reqData, &chipId)) {
        HDF_LOGE("%s: fail to get chipId, line: %d", __FUNCTION__, __LINE__);
        return;
    }
    WifiEventReport(ifName, event, &resetStatus);
}

static void WifiDriverEventRemainOnChannelProcess(const char *ifName, uint32_t event, struct HdfSBuf *reqData)
{
    WifiOnChannel result = {0};
    if (!HdfSbufReadUint32(reqData, &(result.freq))) {
        HDF_LOGE("%s failed to get frequency.", __FUNCTION__);
        return;
    }
    if (!HdfSbufReadUint32(reqData, &(result.duration))) {
        HDF_LOGE("%s failed to get duration.", __FUNCTION__);
        return;
    }
    WifiEventReport(ifName, event, &result);
}

static void WifiDriverEventCancelRemainOnChannelProcess(const char *ifName, uint32_t event, struct HdfSBuf *reqData)
{
    WifiOnChannel result = {0};
    if (!HdfSbufReadUint32(reqData, &(result.freq))) {
        HDF_LOGE("%s: fail to get freq", __FUNCTION__);
        return;
    }
    WifiEventReport(ifName, event, &result);
}

int OnWiFiEvents(struct HdfDevEventlistener *listener,
    struct HdfIoService *service, uint32_t eventId, struct HdfSBuf *data)
{
    (void)listener;
    (void)service;

    if (data == NULL) {
        HDF_LOGE("%s: params is NULL, line: %d", __FUNCTION__, __LINE__);
        return RET_CODE_FAILURE;
    }
    const char *ifName = HdfSbufReadString(data);
    if (ifName == NULL) {
        HDF_LOGE("%s fail to get ifName", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    HDF_LOGI("%s: WifiDriverEventProcess event=%u", __FUNCTION__, eventId);
    switch (eventId) {
        case WIFI_EVENT_NEW_STA:
            WifiEventNewStaProcess(ifName, eventId, data);
            break;
        case WIFI_EVENT_DEL_STA:
            WifiEventDelStaProcess(ifName, eventId, data);
            break;
        case WIFI_EVENT_RX_MGMT:
            WifiEventRxMgmtProcess(ifName, eventId, data);
            break;
        case WIFI_EVENT_TX_STATUS:
            WifiEventTxStatusProcess(ifName, eventId, data);
            break;
        case WIFI_EVENT_SCAN_DONE:
            WifiEventScanDoneProcess(ifName, eventId, data);
            break;
        case WIFI_EVENT_SCAN_RESULT:
            WifiEventScanResultProcess(ifName, eventId, data);
            break;
        case WIFI_EVENT_CONNECT_RESULT:
            WifiEventConnectResultProcess(ifName, eventId, data);
            break;
        case WIFI_EVENT_DISCONNECT:
            WifiEventDisconnectProcess(ifName, eventId, data);
            break;
        case WIFI_EVENT_EAPOL_RECV:
            WifiDriverEventEapolRecvProcess(ifName, eventId, data);
            break;
        case WIFI_EVENT_RESET_DRIVER:
            WifiEventResetDriverProcess(ifName, eventId, data);
            break;
        case WIFI_EVENT_REMAIN_ON_CHANNEL:
            WifiDriverEventRemainOnChannelProcess(ifName, eventId, data);
            break;
        case WIFI_EVENT_CANCEL_REMAIN_ON_CHANNEL:
            WifiDriverEventCancelRemainOnChannelProcess(ifName, eventId, data);
            break;
        default:
            break;
    }
    return RET_CODE_SUCCESS;
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
