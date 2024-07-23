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

#include <poll.h>
#include <sys/types.h>
#include <securec.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <linux/nl80211.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/handlers.h>
#include <osal_mem.h>

#include "hilog/log.h"
#include "../wifi_common_cmd.h"
#include "netlink_adapter.h"

#define OUI_QCA 0x001374

#define LISTEN_FD_NUMS 2
#define EVENT_SOCKET_INDEX 0
#define CTRL_SOCKET_INDEX 1
#define CTRL_SOCKET_WRITE_SIDE 0
#define CTRL_SOCKET_READ_SIDE 1

#define BUFSIZE 1024
#define POLLTIMEOUT 1000

static inline uint32_t BitLeftShift(uint8_t x)
{
    return 1U << x;
}

#define SCAN_QUAL_INVALID      BitLeftShift(0)
#define SCAN_NOISE_INVALID     BitLeftShift(1)
#define SCAN_LEVEL_INVALID     BitLeftShift(2)
#define SCAN_LEVEL_DBM         BitLeftShift(3)
#define SCAN_ASSOCIATED        BitLeftShift(5)

#define SUCCESS_STATUS 0
#define WLAN_ATTR_SCAN_COOKIE 7
#define WLAN_ATTR_SCAN_STATUS 8
#define WLAN_ATTR_SCAN_MAX 11
#define SCAN_STATUS_MAX 2
#define NL80211_SCAN_DONE 107

typedef struct {
    WifiScanResults *scanResults;
    const char *ifName;
} WifiScanResultArg;

static int g_familyId = 0;

static int NoSeqCheck(struct nl_msg *msg, void *arg)
{
    (void)msg;
    return NL_OK;
}

static void QcaWifiEventScanDoneProcess(const char *ifName, struct nlattr *data, size_t len)
{
    struct nlattr *attr[WLAN_ATTR_SCAN_MAX + 1];
    uint32_t status;

    if (nla_parse(attr, WLAN_ATTR_SCAN_MAX, data, len, NULL) ||
        attr[WLAN_ATTR_SCAN_STATUS] ||
        !attr[WLAN_ATTR_SCAN_COOKIE]) {
        return;
    }

    status = nla_get_u8(attr[WLAN_ATTR_SCAN_STATUS]);
    if (status >= SCAN_STATUS_MAX) {
        HILOG_ERROR(LOG_CORE, "%s: invalid status",  __FUNCTION__);
        return;
    }

    WifiEventReport(ifName, WIFI_EVENT_SCAN_DONE, &status);
}

static void WifiEventVendorProcess(const char *ifName, struct nlattr **attr)
{
    uint32_t vendorId;
    uint32_t subCmd;
    uint8_t *data = NULL;
    uint32_t len;

    if (attr[NL80211_ATTR_VENDOR_ID] == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: failed to get vendor id", __FUNCTION__);
        return;
    }
    if (attr[NL80211_ATTR_VENDOR_SUBCMD] == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: failed to get vendor subcmd", __FUNCTION__);
        return;
    }

    vendorId = nla_get_u32(attr[NL80211_ATTR_VENDOR_ID]);
    subCmd = nla_get_u32(attr[NL80211_ATTR_VENDOR_SUBCMD]);
    if (vendorId != OUI_QCA || subCmd != NL80211_SCAN_DONE) {
        HILOG_ERROR(LOG_CORE, "%s: unsupported vendor event", __FUNCTION__);
        return;
    }

    if (attr[NL80211_ATTR_VENDOR_DATA] == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: get vendor data fail", __FUNCTION__);
        return;
    }
    data = nla_data(attr[NL80211_ATTR_VENDOR_DATA]);
    len = (uint32_t)nla_len(attr[NL80211_ATTR_VENDOR_DATA]);

    QcaWifiEventScanDoneProcess(ifName, (struct nlattr *)data, len);
}

static int32_t GetNlaDataScanResult(struct nlattr *attr[], int len, WifiScanResult *scanResult)
{
    uint8_t *ie;
    uint8_t *beaconIe;
    uint8_t *bssid;

    (void)len;
    if (attr[NL80211_BSS_INFORMATION_ELEMENTS]) {
        ie = nla_data(attr[NL80211_BSS_INFORMATION_ELEMENTS]);
        scanResult->ieLen = (uint32_t)nla_len(attr[NL80211_BSS_INFORMATION_ELEMENTS]);
        if (ie != NULL && scanResult->ieLen != 0) {
            scanResult->ie = OsalMemCalloc(scanResult->ieLen);
            if (scanResult->ie == NULL || memcpy_s(scanResult->ie, scanResult->ieLen, ie, scanResult->ieLen) != EOK) {
                HILOG_ERROR(LOG_CORE, "%s: fill ie data fail", __FUNCTION__);
                return RET_CODE_FAILURE;
            }
        }
    }
    if (attr[NL80211_BSS_BEACON_IES]) {
        beaconIe = nla_data(attr[NL80211_BSS_INFORMATION_ELEMENTS]);
        scanResult->beaconIeLen = (uint32_t)nla_len(attr[NL80211_BSS_INFORMATION_ELEMENTS]);
        if (beaconIe != NULL && scanResult->beaconIeLen != 0) {
            scanResult->beaconIe = OsalMemCalloc(scanResult->beaconIeLen);
            if (scanResult->beaconIe == NULL ||
                memcpy_s(scanResult->beaconIe, scanResult->beaconIeLen, beaconIe, scanResult->beaconIeLen) != EOK) {
                HILOG_ERROR(LOG_CORE, "%s: fill beacon ie data fail", __FUNCTION__);
                return RET_CODE_FAILURE;
            }
        }
    }
    if (attr[NL80211_BSS_BSSID]) {
        bssid = nla_data(attr[NL80211_BSS_BSSID]);
        if (bssid != NULL) {
            scanResult->bssid = OsalMemCalloc(ETH_ADDR_LEN);
            if (scanResult->bssid == NULL || memcpy_s(scanResult->bssid, ETH_ADDR_LEN, bssid, ETH_ADDR_LEN) != EOK) {
                HILOG_ERROR(LOG_CORE, "%s: fill bssid fail", __FUNCTION__);
                return RET_CODE_FAILURE;
            }
        }
    }
    return RET_CODE_SUCCESS;
}

static int32_t DoGetScanResult(struct nlattr *attr[], int len, WifiScanResult *scanResult)
{
    if (GetNlaDataScanResult(attr, len, scanResult) != RET_CODE_SUCCESS) {
        return RET_CODE_FAILURE;
    }
    if (attr[NL80211_BSS_FREQUENCY]) {
        scanResult->freq = nla_get_u32(attr[NL80211_BSS_FREQUENCY]);
    }
    if (attr[NL80211_BSS_BEACON_INTERVAL]) {
        scanResult->beaconInt = nla_get_u16(attr[NL80211_BSS_BEACON_INTERVAL]);
    }
    if (attr[NL80211_BSS_CAPABILITY]) {
        scanResult->caps = nla_get_u16(attr[NL80211_BSS_CAPABILITY]);
    }
    if (attr[NL80211_BSS_SIGNAL_MBM]) {
         /* mBm to dBm */
        scanResult->level = (int32_t)nla_get_u32(attr[NL80211_BSS_SIGNAL_MBM]) / SIGNAL_LEVEL_CONFFICIENT;
        scanResult->flags |= SCAN_LEVEL_DBM | SCAN_QUAL_INVALID;
    } else if (attr[NL80211_BSS_SIGNAL_UNSPEC]) {
        scanResult->level = (int32_t)nla_get_u8(attr[NL80211_BSS_SIGNAL_UNSPEC]);
        scanResult->flags |= SCAN_QUAL_INVALID;
    } else {
        scanResult->flags |= SCAN_LEVEL_INVALID | SCAN_QUAL_INVALID;
    }
    if (attr[NL80211_BSS_TSF]) {
        scanResult->tsf = nla_get_u64(attr[NL80211_BSS_TSF]);
    }
    if (attr[NL80211_BSS_BEACON_TSF]) {
        uint64_t tsf = nla_get_u64(attr[NL80211_BSS_BEACON_TSF]);
        if (tsf > scanResult->tsf) {
            scanResult->tsf = tsf;
        }
    }
    if (attr[NL80211_BSS_SEEN_MS_AGO]) {
        scanResult->age = nla_get_u32(attr[NL80211_BSS_SEEN_MS_AGO]);
    }
    return RET_CODE_SUCCESS;
}

static int32_t WifiGetScanResultHandler(struct nl_msg *msg, void *arg)
{
    WifiScanResult *scanResult = NULL;
    WifiScanResults *scanResults = NULL;
    struct genlmsghdr *hdr = nlmsg_data(nlmsg_hdr(msg));
    WifiScanResultArg *handlerArg = (WifiScanResultArg *)arg;
    struct nlattr *attr[NL80211_ATTR_MAX + 1], *bssAttr[NL80211_BSS_MAX + 1];
    static struct nla_policy bssPolicy[NL80211_BSS_MAX + 1];
    memset_s(bssPolicy, sizeof(bssPolicy), 0, sizeof(bssPolicy));
    bssPolicy[NL80211_BSS_FREQUENCY].type = NLA_U32;
    bssPolicy[NL80211_BSS_TSF].type = NLA_U64;
    bssPolicy[NL80211_BSS_BEACON_INTERVAL].type = NLA_U16;
    bssPolicy[NL80211_BSS_CAPABILITY].type = NLA_U16;
    bssPolicy[NL80211_BSS_SIGNAL_MBM].type = NLA_U32;
    bssPolicy[NL80211_BSS_SIGNAL_UNSPEC].type = NLA_U8;
    bssPolicy[NL80211_BSS_STATUS].type = NLA_U32;
    bssPolicy[NL80211_BSS_SEEN_MS_AGO].type = NLA_U32;

    if (handlerArg == NULL || handlerArg->scanResults == NULL || handlerArg->ifName == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: Invalid param",  __FUNCTION__);
        return NL_SKIP;
    }
    scanResults = handlerArg->scanResults;
    scanResult = &scanResults->scanResult[scanResults->num];
    nla_parse(attr, NL80211_ATTR_MAX, genlmsg_attrdata(hdr, 0), genlmsg_attrlen(hdr, 0), NULL);
    if (!attr[NL80211_ATTR_BSS]) {
        HILOG_ERROR(LOG_CORE, "%s: bss info missing",  __FUNCTION__);
        return NL_SKIP;
    }
    if (nla_parse_nested(bssAttr, NL80211_BSS_MAX, attr[NL80211_ATTR_BSS], bssPolicy)) {
        HILOG_ERROR(LOG_CORE, "%s: failed to parse nested attributes",  __FUNCTION__);
        return NL_SKIP;
    }
    if (DoGetScanResult(bssAttr, NL80211_BSS_MAX + 1, scanResult) != RET_CODE_SUCCESS) {
        HILOG_ERROR(LOG_CORE, "%s: DoGetScanResult fail",  __FUNCTION__);
        FreeScanResult(scanResult);
        return NL_SKIP;
    }
    HILOG_DEBUG(LOG_CORE, "%{public}s, line:%{public}d num:%{public}u scanResultCapacity:%{public}u", __FUNCTION__,
        __LINE__, scanResults->num, scanResults->scanResultCapacity);
    scanResults->num++;
    if (scanResults->num == scanResults->scanResultCapacity) {
        scanResults->scanResultCapacity += INIT_SCAN_RES_NUM;
        WifiScanResult *newScanResult = NULL;
        newScanResult = (WifiScanResult *)OsalMemCalloc(sizeof(WifiScanResult) * (scanResults->scanResultCapacity));
        if (newScanResult == NULL) {
            HILOG_ERROR(LOG_CORE, "%{public}s: newscanResult is NULL",  __FUNCTION__);
            scanResults->scanResultCapacity -= INIT_SCAN_RES_NUM;
            scanResults->num = 0;
            return NL_SKIP;
        }
        if (memcpy_s((void *)newScanResult, sizeof(WifiScanResult) * (scanResults->scanResultCapacity),
            (void *)scanResults->scanResult, sizeof(WifiScanResult) * (scanResults->num)) != RET_CODE_SUCCESS) {
            HILOG_ERROR(LOG_CORE, "%{public}s: memcpy_s fail",  __FUNCTION__);
        }
        OsalMemFree(scanResults->scanResult);
        scanResults->scanResult = newScanResult;
        newScanResult = NULL;
    }
    return NL_SKIP;
}

static void WifiEventScanResultProcess(const char *ifName)
{
    HILOG_DEBUG(LOG_CORE, "hal enter %{public}s", __FUNCTION__);
    int32_t ret;
    WifiScanResults scanResults = {0};
    WifiScanResultArg arg;
    uint32_t ifaceId = if_nametoindex(ifName);
    struct nl_msg *msg = nlmsg_alloc();
    if (NULL == msg) {
        HILOG_ERROR(LOG_CORE, "%s: msg is NULL.",  __FUNCTION__);
        return;
    }
    if (InitScanResults(&scanResults) != RET_CODE_SUCCESS) {
        HILOG_ERROR(LOG_CORE, "%s: InitScanResults failed",  __FUNCTION__);
        return;
    }
    arg.scanResults = &scanResults;
    arg.ifName = ifName;
    genlmsg_put(msg, 0, 0, g_familyId, 0, NLM_F_DUMP, NL80211_CMD_GET_SCAN, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifaceId);
    ret = NetlinkSendCmdSync(msg, WifiGetScanResultHandler, (void *)&arg);
    if (ret != RET_CODE_SUCCESS) {
        HILOG_ERROR(LOG_CORE, "%s: send cmd failed",  __FUNCTION__);
    }
    WifiEventReport(ifName, WIFI_EVENT_SCAN_RESULTS, &scanResults);
    HILOG_INFO(LOG_CORE, "%s: scanResults.num = %u", __FUNCTION__, scanResults.num);
    FreeScanResults(&scanResults);
    nlmsg_free(msg);
    HILOG_DEBUG(LOG_CORE, "hal exit %{public}s", __FUNCTION__);
}

static void WifiEventScanAbortedProcess(const char *ifName)
{
    WifiScanResults scanResults = {0};

    if (ifName == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: ifName is NULL.",  __FUNCTION__);
        return;
    }
    WifiEventReport(ifName, WIFI_EVENT_SCAN_ABORTED, &scanResults);
}

static void DoProcessEvent(const char *ifName, int cmd, struct nlattr **attr)
{
    HILOG_DEBUG(LOG_CORE, "hal enter %{public}s cmd=%{public}d ifName=%{public}s", __FUNCTION__, cmd, ifName);
    switch (cmd) {
        case NL80211_CMD_VENDOR:
            HILOG_INFO(LOG_CORE, "receive cmd NL80211_CMD_VENDOR");
            WifiEventVendorProcess(ifName, attr);
            break;
        case NL80211_CMD_START_SCHED_SCAN:
            HILOG_INFO(LOG_CORE, "receive cmd NL80211_CMD_START_SCHED_SCAN");
            break;
        case NL80211_CMD_SCHED_SCAN_RESULTS:
            HILOG_INFO(LOG_CORE, "receive cmd NL80211_CMD_SCHED_SCAN_RESULTS");
            WifiEventScanResultProcess(ifName);
            break;
        case NL80211_CMD_SCHED_SCAN_STOPPED:
            HILOG_INFO(LOG_CORE, "receive cmd NL80211_CMD_SCHED_SCAN_STOPPED");
            break;
        case NL80211_CMD_NEW_SCAN_RESULTS:
            HILOG_INFO(LOG_CORE, "receive cmd NL80211_CMD_NEW_SCAN_RESULTS");
            WifiEventScanResultProcess(ifName);
            break;
        case NL80211_CMD_SCAN_ABORTED:
            HILOG_INFO(LOG_CORE, "receive cmd NL80211_CMD_SCAN_ABORTED");
            WifiEventScanAbortedProcess(ifName);
            break;
        case NL80211_CMD_TRIGGER_SCAN:
            HILOG_INFO(LOG_CORE, "receive cmd NL80211_CMD_TRIGGER_SCAN");
            break;
        case NL80211_CMD_FRAME_TX_STATUS:
            HILOG_INFO(LOG_CORE, "receive cmd NL80211_CMD_FRAME_TX_STATUS");
            WifiEventTxStatus(ifName, attr);
            break;
        default:
            HILOG_INFO(LOG_CORE, "not supported cmd");
            break;
    }
    HILOG_DEBUG(LOG_CORE, "hal exit %{public}s", __FUNCTION__);
}

static int32_t ProcessEvent(struct nl_msg *msg, void *arg)
{
    HILOG_DEBUG(LOG_CORE, "hal enter %{public}s", __FUNCTION__);
    struct genlmsghdr *hdr = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *attr[NL80211_ATTR_MAX + 1];
    struct NetworkInfoResult networkInfo;
    uint32_t ifidx = -1;
    uint32_t i;
    int ret;

    nla_parse(attr, NL80211_ATTR_MAX, genlmsg_attrdata(hdr, 0),
        genlmsg_attrlen(hdr, 0), NULL);

    if (attr[NL80211_ATTR_IFINDEX]) {
        ifidx = nla_get_u32(attr[NL80211_ATTR_IFINDEX]);
    }
    HILOG_INFO(LOG_CORE, "ifidx = %{public}d", ifidx);

    ret = GetUsableNetworkInfo(&networkInfo);
    if (ret != RET_CODE_SUCCESS) {
        HILOG_ERROR(LOG_CORE, "%s: get usable network information failed", __FUNCTION__);
        return NL_SKIP;
    }

    for (i = 0; i < networkInfo.nums; i++) {
        HILOG_DEBUG(LOG_CORE, "name=%{public}s index=%{public}d mode=%{public}s",
            networkInfo.infos[i].name, if_nametoindex(networkInfo.infos[i].name), networkInfo.infos[i].supportMode);
        if (ifidx == if_nametoindex(networkInfo.infos[i].name)) {
            DoProcessEvent(networkInfo.infos[i].name, hdr->cmd, attr);
            return NL_SKIP;
        }
    }
    HILOG_DEBUG(LOG_CORE, "hal exit %{public}s", __FUNCTION__);
    return NL_SKIP;
}

static struct nl_cb *CreateCb(void)
{
    struct nl_cb *cb;

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (cb == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: alloc cb failed", __FUNCTION__);
        return NULL;
    }

    nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, NoSeqCheck, NULL);
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, ProcessEvent, NULL);

    return cb;
}

static int HandleEvent(struct nl_sock *sock)
{
    HILOG_DEBUG(LOG_CORE, "hal enter %{public}s", __FUNCTION__);
    int ret;
    struct nl_cb *cb = CreateCb();
    if (cb == NULL) {
        HILOG_ERROR(LOG_CORE, "%{public}s: Create cb failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }

    ret = nl_recvmsgs(sock, cb);
    HILOG_INFO(LOG_CORE, "nl_recvmsgs ret:%{public}d, errno:%{public}d %{public}s", ret, errno, strerror(errno));
    nl_cb_put(cb);
    cb = NULL;
    HILOG_DEBUG(LOG_CORE, "hal exit %{public}s", __FUNCTION__);
    return ret;
}

static int32_t CtrlNoSeqCheck(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *hdr = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *attr[NL80211_ATTR_MAX + 1];

    nla_parse(attr, NL80211_ATTR_MAX, genlmsg_attrdata(hdr, 0),
        genlmsg_attrlen(hdr, 0), NULL);
    
    if (hdr->cmd != NL80211_CMD_FRAME) {
        return NL_OK;
    }
    if (attr[NL80211_ATTR_FRAME] == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: failed to get frame data", __FUNCTION__);
        return NL_OK;
    }

    WifiActionData actionData;
    actionData.data = nla_data(attr[NL80211_ATTR_FRAME]);
    actionData.dataLen = (uint32_t)nla_len(attr[NL80211_ATTR_FRAME]);
    HILOG_INFO(LOG_CORE, "%s: receive data len = %{public}d", __FUNCTION__, actionData.dataLen);
    WifiEventReport("p2p0", WIFI_EVENT_ACTION_RECEIVED, &actionData);
    return NL_OK;
}

static int32_t CtrlSocketErrorHandler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
    int32_t *ret = (int32_t *)arg;
    *ret = err->error;
    HILOG_ERROR(LOG_CORE, "%s: ctrl sock error ret = %{public}d", __FUNCTION__, *ret);
    return NL_SKIP;
}

static int32_t CtrlSocketFinishHandler(struct nl_msg *msg, void *arg)
{
    int32_t *ret = (int32_t *)arg;
    HILOG_ERROR(LOG_CORE, "%s: ctrl sock finish ret = %{public}d", __FUNCTION__, *ret);
    *ret = 0;
    return NL_SKIP;
}

static int32_t CtrlSocketAckHandler(struct nl_msg *msg, void *arg)
{
    int32_t *err = (int32_t *)arg;
    HILOG_ERROR(LOG_CORE, "%s: ctrl sock ack ret = %{public}d", __FUNCTION__, *err);
    *err = 0;
    return NL_STOP;
}

static int HandleCtrlEvent(struct nl_sock *sock)
{
    HILOG_INFO(LOG_CORE, "hal enter %{public}s", __FUNCTION__);
    int ret;
    struct nl_cb *cb;
    int error;

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (cb == NULL) {
        HILOG_ERROR(LOG_CORE, "%{public}s: alloc ctrl cb failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }

    nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, CtrlNoSeqCheck, NULL);
    nl_cb_err(cb, NL_CB_CUSTOM, CtrlSocketErrorHandler, &error);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, CtrlSocketFinishHandler, &error);
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, CtrlSocketAckHandler, &error);

    ret = nl_recvmsgs(sock, cb);
    HILOG_INFO(LOG_CORE, "nl_recvmsgs ret:%{public}d, errno:%{public}d %{public}s", ret, errno, strerror(errno));
    nl_cb_put(cb);
    cb = NULL;
    HILOG_INFO(LOG_CORE, "hal exit %{public}s", __FUNCTION__);
    return ret;
}

void *EventThread(void *para)
{
    HILOG_INFO(LOG_CORE, "hal enter %{public}s", __FUNCTION__);
    struct nl_sock *eventSock = NULL;
    struct nl_sock *ctrlSock = NULL;
    struct pollfd pollFds[LISTEN_FD_NUMS] = {0};
    struct WifiThreadParam *threadParam = NULL;
    int ret;
    enum ThreadStatus *status = NULL;

    if (para == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: para is null", __FUNCTION__);
        return NULL;
    } else {
        threadParam = (struct WifiThreadParam *)para;
        eventSock = threadParam->eventSock;
        ctrlSock = threadParam->ctrlSock;
        g_familyId = threadParam->familyId;
        status = threadParam->status;
        *status = THREAD_RUN;
    }

    pollFds[EVENT_SOCKET_INDEX].fd = nl_socket_get_fd(eventSock);
    pollFds[EVENT_SOCKET_INDEX].events = POLLIN | POLLERR;
    pollFds[CTRL_SOCKET_INDEX].fd = nl_socket_get_fd(ctrlSock);
    pollFds[CTRL_SOCKET_INDEX].events = POLLIN;

    while (*status == THREAD_RUN) {
        ret = TEMP_FAILURE_RETRY(poll(pollFds, LISTEN_FD_NUMS, POLLTIMEOUT));
        HILOG_DEBUG(LOG_CORE, "EventThread TEMP_FAILURE_RETRY ret:%{public}d status:%{public}d", ret, *status);
        if (ret < 0) {
            HILOG_ERROR(LOG_CORE, "%{public}s: fail poll", __FUNCTION__);
            break;
        } else if ((uint32_t)pollFds[EVENT_SOCKET_INDEX].revents & POLLERR) {
            HILOG_ERROR(LOG_CORE, "%{public}s: event socket get POLLERR event", __FUNCTION__);
            break;
        } else if ((uint32_t)pollFds[EVENT_SOCKET_INDEX].revents & POLLIN) {
            if (HandleEvent(eventSock) != RET_CODE_SUCCESS) {
                HILOG_ERROR(LOG_CORE, "EventThread HandleEvent break");
                break;
            }
        } else if ((uint32_t)pollFds[CTRL_SOCKET_INDEX].revents & POLLIN) {
            if (HandleCtrlEvent(ctrlSock) != RET_CODE_SUCCESS) {
                HILOG_ERROR(LOG_CORE, "EventThread HandleCtrlEvent break");
                break;
            }
        }
    }

    *status = THREAD_STOP;
    HILOG_INFO(LOG_CORE, "hal exit %{public}s", __FUNCTION__);
    return NULL;
}
