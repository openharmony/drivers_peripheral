/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <net/if.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <netlink-private/types.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/handlers.h>
#include <securec.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/if_arp.h>
#include <linux/netlink.h>
#include <linux/nl80211.h>
#include <linux/wireless.h>
#include <linux/version.h>

#include "../wifi_common_cmd.h"
#include "hilog/log.h"
#include "netlink_adapter.h"

#define VENDOR_ID 0x001A11

// vendor subcmd
#define WIFI_SUBCMD_SET_COUNTRY_CODE   0x100E
#define WIFI_SUBCMD_SET_RANDOM_MAC_OUI 0x100C

#define WAITFORMUTEX  100000
#define WAITFORTHREAD 100000
#define RETRIES       30

#define STR_WLAN0     "wlan0"
#define STR_WLAN1     "wlan1"
#define STR_P2P0      "p2p0"
#define STR_P2P0_X    "p2p0-"
#define NET_DEVICE_INFO_PATH "/sys/class/net"

#define PRIMARY_ID_POWER_MODE   0x8bfd
#define SECONDARY_ID_POWER_MODE 0x101
#define SET_POWER_MODE_SLEEP     "pow_mode sleep"
#define SET_POWER_MODE_INIT      "pow_mode init"
#define SET_POWER_MODE_THIRD     "pow_mode third"
#define GET_POWER_MODE           "get_pow_mode"

#define CMD_SET_CLOSE_GO_CAC      "SET_CLOSE_GO_CAC"
#define CMD_SET_CHANGE_GO_CHANNEL "CMD_SET_CHANGE_GO_CHANNEL"
#define CMD_SET_GO_DETECT_RADAR   "CMD_SET_GO_DETECT_RADAR"
#define CMD_SET_DYNAMIC_DBAC_MODE "SET_DYNAMIC_DBAC_MODE"
#define CMD_SET_P2P_SCENES        "CMD_SET_P2P_SCENES"
#define P2P_BUF_SIZE              64
#define MAX_PRIV_CMD_SIZE         4096
#define LOW_LITMIT_FREQ_2_4G      2400
#define HIGH_LIMIT_FREQ_2_4G      2500
#define LOW_LIMIT_FREQ_5G         5100
#define HIGH_LIMIT_FREQ_5G        5900

static inline uint32_t BIT(uint8_t x)
{
    return 1U << x;
}
#define STA_DRV_DATA_TX_MCS BIT(0)
#define STA_DRV_DATA_RX_MCS BIT(1)
#define STA_DRV_DATA_TX_VHT_MCS BIT(2)
#define STA_DRV_DATA_RX_VHT_MCS BIT(3)
#define STA_DRV_DATA_TX_VHT_NSS BIT(4)
#define STA_DRV_DATA_RX_VHT_NSS BIT(5)
#define STA_DRV_DATA_TX_SHORT_GI BIT(6)
#define STA_DRV_DATA_RX_SHORT_GI BIT(7)
#define STA_DRV_DATA_LAST_ACK_RSSI BIT(8)

#define WLAN_IFACE_LENGTH 4
#define P2P_IFACE_LENGTH 3
#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + ((c) > 255 ? 255 : (c)))
#endif

// vendor attr
enum AndrWifiAttr {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0))
    WIFI_ATTRIBUTE_INVALID,
#endif
    WIFI_ATTRIBUTE_NUM_FEATURE_SET,
    WIFI_ATTRIBUTE_FEATURE_SET,
    WIFI_ATTRIBUTE_RANDOM_MAC_OUI,
    WIFI_ATTRIBUTE_NODFS_SET,
    WIFI_ATTRIBUTE_COUNTRY
};

struct FamilyData {
    const char *group;
    int32_t id;
};

struct WifiHalInfo {
    struct nl_sock *cmdSock;
    struct nl_sock *eventSock;
    int32_t familyId;

    // thread controller info
    pthread_t thread;
    enum ThreadStatus status;
    pthread_mutex_t mutex;
};

typedef struct {
    void *buf;
    uint16_t length;
    uint16_t flags;
} DataPoint;

union HwprivReqData {
    char name[IFNAMSIZ];
    int32_t mode;
    DataPoint point;
};

typedef struct {
    char interfaceName[IFNAMSIZ];
    union HwprivReqData data;
} HwprivIoctlData;

typedef struct {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0))
    uint8_t *buf;
    uint32_t size;
    uint32_t len;
#else
    uint32_t size;
    uint32_t len;
    uint8_t *buf;
#endif
} WifiPrivCmd;

static struct WifiHalInfo g_wifiHalInfo = {0};

static struct nl_sock *OpenNetlinkSocket(void)
{
    struct nl_sock *sock = NULL;

    sock = nl_socket_alloc();
    if (sock == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: fail to alloc socket", __FUNCTION__);
        return NULL;
    }

    if (nl_connect(sock, NETLINK_GENERIC) != 0) {
        HILOG_ERROR(LOG_CORE, "%s: fail to connect socket", __FUNCTION__);
        nl_socket_free(sock);
        return NULL;
    }
    return sock;
}

static void CloseNetlinkSocket(struct nl_sock *sock)
{
    if (sock != NULL) {
        nl_socket_free(sock);
    }
}

static int32_t ConnectCmdSocket(void)
{
    g_wifiHalInfo.cmdSock = OpenNetlinkSocket();
    if (g_wifiHalInfo.cmdSock == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: fail to open cmd socket", __FUNCTION__);
        return RET_CODE_FAILURE;
    }

    nl_socket_disable_seq_check(g_wifiHalInfo.cmdSock);
    // send find familyId result to Controller
    g_wifiHalInfo.familyId = genl_ctrl_resolve(g_wifiHalInfo.cmdSock, NL80211_GENL_NAME);
    if (g_wifiHalInfo.familyId < 0) {
        HILOG_ERROR(LOG_CORE, "%s: fail to resolve family", __FUNCTION__);
        CloseNetlinkSocket(g_wifiHalInfo.cmdSock);
        g_wifiHalInfo.cmdSock = NULL;
        return RET_CODE_FAILURE;
    }
    HILOG_INFO(LOG_CORE, "%s: family id: %d", __FUNCTION__, g_wifiHalInfo.familyId);
    return RET_CODE_SUCCESS;
}

static void DisconnectCmdSocket(void)
{
    CloseNetlinkSocket(g_wifiHalInfo.cmdSock);
    g_wifiHalInfo.cmdSock = NULL;
}

static int32_t CmdSocketErrorHandler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
    int32_t *ret = (int32_t *)arg;

    *ret = err->error;
    return NL_SKIP;
}

static int32_t CmdSocketFinishHandler(struct nl_msg *msg, void *arg)
{
    int32_t *ret = (int32_t *)arg;

    *ret = 0;
    return NL_SKIP;
}

static int32_t CmdSocketAckHandler(struct nl_msg *msg, void *arg)
{
    int32_t *err = (int32_t *)arg;

    *err = 0;
    return NL_STOP;
}

static struct nl_cb *NetlinkSetCallback(const RespHandler handler, int32_t *error, void *data)
{
    struct nl_cb *cb = NULL;

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (cb == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: nl_cb_alloc failed", __FUNCTION__);
        return NULL;
    }
    nl_cb_err(cb, NL_CB_CUSTOM, CmdSocketErrorHandler, error);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, CmdSocketFinishHandler, error);
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, CmdSocketAckHandler, error);
    if (handler != NULL) {
        nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, handler, data);
    }
    return cb;
}

static int32_t PthreadMutexLock(void)
{
    int32_t rc;
    int32_t count = 0;

    while ((rc = pthread_mutex_trylock(&g_wifiHalInfo.mutex)) == EBUSY) {
        if (count < RETRIES) {
            HILOG_ERROR(LOG_CORE, "%s: pthread b trylock", __FUNCTION__);
            count++;
            usleep(WAITFORMUTEX);
        } else {
            HILOG_ERROR(LOG_CORE, "%s: pthread trylock timeout", __FUNCTION__);
            return RET_CODE_SUCCESS;
        }
    }
    return rc;
}

int32_t NetlinkSendCmdSync(struct nl_msg *msg, const RespHandler handler, void *data)
{
    int32_t rc;
    int32_t error;
    struct nl_cb *cb = NULL;

    if (g_wifiHalInfo.cmdSock == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: sock is null", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }

    if (PthreadMutexLock() != RET_CODE_SUCCESS) {
        HILOG_ERROR(LOG_CORE, "%s: pthread trylock failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }

    do {
        rc = nl_send_auto(g_wifiHalInfo.cmdSock, msg);
        if (rc < 0) {
            HILOG_ERROR(LOG_CORE, "%s: nl_send_auto failed", __FUNCTION__);
            break;
        }
        cb = NetlinkSetCallback(handler, &error, data);
        if (cb == NULL) {
            HILOG_ERROR(LOG_CORE, "%s: nl_cb_alloc failed", __FUNCTION__);
            rc = RET_CODE_FAILURE;
            break;
        }
        /* wait for reply */
        error = 1;
        while (error > 0) {
            rc = nl_recvmsgs(g_wifiHalInfo.cmdSock, cb);
            if (rc < 0) {
                HILOG_ERROR(LOG_CORE, "%s: nl_recvmsgs failed: rc = %d, errno = %d, (%s)", __FUNCTION__, rc, errno,
                    strerror(errno));
            }
        }
        if (error == -NLE_MSGTYPE_NOSUPPORT) {
            HILOG_ERROR(LOG_CORE, "%s: Netlink message type is not supported", __FUNCTION__);
            rc = RET_CODE_NOT_SUPPORT;
        }
        nl_cb_put(cb);
    } while (0);

    pthread_mutex_unlock(&g_wifiHalInfo.mutex);
    return rc;
}

static void ParseFamilyId(struct nlattr *attr, struct FamilyData *familyData)
{
    struct nlattr *tmp = NULL;
    void *data = NULL;
    int32_t len;
    int32_t i;

    nla_for_each_nested(tmp, attr, i) {
        struct nlattr *attrMcastGrp[CTRL_ATTR_MCAST_GRP_MAX + 1];
        data = nla_data(tmp);
        len = nla_len(tmp);
        nla_parse(attrMcastGrp, CTRL_ATTR_MCAST_GRP_MAX, data, len, NULL);
        data = nla_data(attrMcastGrp[CTRL_ATTR_MCAST_GRP_NAME]);
        len = nla_len(attrMcastGrp[CTRL_ATTR_MCAST_GRP_NAME]);
        if (attrMcastGrp[CTRL_ATTR_MCAST_GRP_NAME] && attrMcastGrp[CTRL_ATTR_MCAST_GRP_ID] &&
            strncmp((char *)data, familyData->group, len) == 0) {
            familyData->id = (int32_t)nla_get_u32(attrMcastGrp[CTRL_ATTR_MCAST_GRP_ID]);
        }
    }
}

static int32_t FamilyIdHandler(struct nl_msg *msg, void *arg)
{
    struct FamilyData *familyData = (struct FamilyData *)arg;
    struct genlmsghdr *hdr = NULL;
    struct nlattr *attr[CTRL_ATTR_MAX + 1];
    void *data = NULL;
    int32_t len;

    hdr = nlmsg_data(nlmsg_hdr(msg));
    if (hdr == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: get nlmsg header fail", __FUNCTION__);
        return NL_SKIP;
    }

    data = genlmsg_attrdata(hdr, 0);
    len = genlmsg_attrlen(hdr, 0);
    nla_parse(attr, CTRL_ATTR_MAX, data, len, NULL);
    if (!attr[CTRL_ATTR_MCAST_GROUPS]) {
        return NL_SKIP;
    }

    ParseFamilyId(attr[CTRL_ATTR_MCAST_GROUPS], familyData);

    return NL_SKIP;
}

static int32_t GetMulticastId(const char *family, const char *group)
{
    struct nl_msg *msg = NULL;
    int32_t ret;
    static struct FamilyData familyData;
    int32_t familyId = genl_ctrl_resolve(g_wifiHalInfo.cmdSock, "nlctrl");

    familyData.group = group;
    familyData.id = -ENOENT;

    msg = nlmsg_alloc();
    if (msg == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: nlmsg_alloc failed", __FUNCTION__);
        return RET_CODE_NOMEM;
    }

    if (!genlmsg_put(msg, 0, 0, familyId, 0, 0, CTRL_CMD_GETFAMILY, 0) ||
        nla_put_string(msg, CTRL_ATTR_FAMILY_NAME, family)) {
        HILOG_ERROR(LOG_CORE, "%s: put msg failed", __FUNCTION__);
        nlmsg_free(msg);
        return RET_CODE_FAILURE;
    }

    ret = NetlinkSendCmdSync(msg, FamilyIdHandler, &familyData);
    if (ret == 0) {
        ret = familyData.id;
    }
    nlmsg_free(msg);
    return ret;
}

static int32_t NlsockAddMembership(struct nl_sock *sock, const char *group)
{
    int32_t id;
    int32_t ret;

    id = GetMulticastId(NL80211_GENL_NAME, group);
    if (id < 0) {
        HILOG_ERROR(LOG_CORE, "%s: get multicast id failed", __FUNCTION__);
        return id;
    }

    ret = nl_socket_add_membership(sock, id);
    if (ret < 0) {
        HILOG_ERROR(LOG_CORE, "%s: Could not add multicast membership for %d: %d (%s)", __FUNCTION__, id, ret,
            strerror(-ret));
        return RET_CODE_FAILURE;
    }

    return RET_CODE_SUCCESS;
}

static int32_t ConnectEventSocket(void)
{
    int32_t ret;

    g_wifiHalInfo.eventSock = OpenNetlinkSocket();
    if (g_wifiHalInfo.eventSock == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: fail to open event socket", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    do {
        ret = NlsockAddMembership(g_wifiHalInfo.eventSock, NL80211_MULTICAST_GROUP_SCAN);
        if (ret != RET_CODE_SUCCESS) {
            HILOG_ERROR(LOG_CORE, "%s: nlsock add membership for scan event failed.", __FUNCTION__);
            break;
        }
        ret = NlsockAddMembership(g_wifiHalInfo.eventSock, NL80211_MULTICAST_GROUP_MLME);
        if (ret != RET_CODE_SUCCESS) {
            HILOG_ERROR(LOG_CORE, "%s: nlsock add membership for mlme failed.", __FUNCTION__);
            break;
        }
        ret = NlsockAddMembership(g_wifiHalInfo.eventSock, NL80211_MULTICAST_GROUP_REG);
        if (ret != RET_CODE_SUCCESS) {
            HILOG_ERROR(LOG_CORE, "%s: nlsock add membership for regulatory failed.", __FUNCTION__);
            break;
        }
        ret = NlsockAddMembership(g_wifiHalInfo.eventSock, NL80211_MULTICAST_GROUP_VENDOR);
        if (ret != RET_CODE_SUCCESS) {
            HILOG_ERROR(LOG_CORE, "%s: nlsock add membership for vendor failed.", __FUNCTION__);
            break;
        }
        return RET_CODE_SUCCESS;
    } while (0);
    CloseNetlinkSocket(g_wifiHalInfo.eventSock);
    g_wifiHalInfo.eventSock = NULL;
    return ret;
}

void DisconnectEventSocket(void)
{
    CloseNetlinkSocket(g_wifiHalInfo.eventSock);
    g_wifiHalInfo.eventSock = NULL;
}

static int32_t WifiMsgRegisterEventListener(void)
{
    int32_t rc;
    int32_t count = 0;
    struct WifiThreadParam threadParam;

    threadParam.eventSock = g_wifiHalInfo.eventSock;
    threadParam.familyId = g_wifiHalInfo.familyId;
    threadParam.status = &g_wifiHalInfo.status;

    g_wifiHalInfo.status = THREAD_STARTING;
    rc = pthread_create(&(g_wifiHalInfo.thread), NULL, EventThread, &threadParam);
    if (rc != 0) {
        HILOG_ERROR(LOG_CORE, "%s: failed create event thread", __FUNCTION__);
        g_wifiHalInfo.status = THREAD_STOP;
        return RET_CODE_FAILURE;
    }

    // waiting for thread start running
    while (g_wifiHalInfo.status != THREAD_RUN) {
        HILOG_INFO(LOG_CORE, "%s: waiting for thread start running.", __FUNCTION__);
        if (count < RETRIES) {
            count++;
            usleep(WAITFORTHREAD);
        } else {
            HILOG_ERROR(LOG_CORE, "%s: warit for thread running timeout", __FUNCTION__);
            if (g_wifiHalInfo.status != THREAD_STOP) {
                g_wifiHalInfo.status = THREAD_STOP;
                pthread_join(g_wifiHalInfo.thread, NULL);
            }
            return RET_CODE_FAILURE;
        }
    }

    return RET_CODE_SUCCESS;
}

static void WifiMsgUnregisterEventListener(void)
{
    g_wifiHalInfo.status = THREAD_STOPPING;
    pthread_join(g_wifiHalInfo.thread, NULL);
}

int32_t WifiDriverClientInit(void)
{
    if (g_wifiHalInfo.cmdSock != NULL) {
        HILOG_ERROR(LOG_CORE, "%s: already create cmd socket", __FUNCTION__);
        return RET_CODE_FAILURE;
    }

    if (pthread_mutex_init(&g_wifiHalInfo.mutex, NULL) != RET_CODE_SUCCESS) {
        HILOG_ERROR(LOG_CORE, "%s: init mutex failed.", __FUNCTION__);
        return RET_CODE_FAILURE;
    }

    if (ConnectCmdSocket() != RET_CODE_SUCCESS) {
        HILOG_ERROR(LOG_CORE, "%s: connect cmd socket failed.", __FUNCTION__);
        goto err_cmd;
    }

    if (ConnectEventSocket() != RET_CODE_SUCCESS) {
        HILOG_ERROR(LOG_CORE, "%s: connect event socket failed", __FUNCTION__);
        goto err_event;
    }

    if (WifiMsgRegisterEventListener() != RET_CODE_SUCCESS) {
        HILOG_ERROR(LOG_CORE, "%s: WifiMsgRegisterEventListener failed", __FUNCTION__);
        goto err_reg;
    }

    return RET_CODE_SUCCESS;
err_reg:
    DisconnectEventSocket();
err_event:
    DisconnectCmdSocket();
err_cmd:
    pthread_mutex_destroy(&g_wifiHalInfo.mutex);
    return RET_CODE_FAILURE;
}

void WifiDriverClientDeinit(void)
{
    WifiMsgUnregisterEventListener();

    if (g_wifiHalInfo.cmdSock == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: cmd socket not inited", __FUNCTION__);
    } else {
        DisconnectCmdSocket();
    }

    if (g_wifiHalInfo.eventSock == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: event socket not inited", __FUNCTION__);
    } else {
        DisconnectEventSocket();
    }

    pthread_mutex_destroy(&g_wifiHalInfo.mutex);
}

static int32_t ParserIsSupportCombo(struct nl_msg *msg, void *arg)
{
    struct nlattr *attr[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *hdr = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *nlComb = NULL;
    struct nlattr *attrComb[NUM_NL80211_IFACE_COMB];
    uint8_t *isSupportCombo = (uint8_t *)arg;
    int32_t ret, i;
    static struct nla_policy ifaceCombPolicy[NUM_NL80211_IFACE_COMB];
    ifaceCombPolicy[NL80211_IFACE_COMB_LIMITS].type = NLA_NESTED;
    ifaceCombPolicy[NL80211_IFACE_COMB_MAXNUM].type = NLA_U32;
    ifaceCombPolicy[NL80211_IFACE_COMB_NUM_CHANNELS].type = NLA_U32;

    // parse all enum nl80211_attrs type
    ret = nla_parse(attr, NL80211_ATTR_MAX, genlmsg_attrdata(hdr, 0), genlmsg_attrlen(hdr, 0), NULL);
    if (ret != 0) {
        HILOG_ERROR(LOG_CORE, "%s: nla_parse tb failed", __FUNCTION__);
        return NL_SKIP;
    }

    if (attr[NL80211_ATTR_INTERFACE_COMBINATIONS] != NULL) {
        nla_for_each_nested(nlComb, attr[NL80211_ATTR_INTERFACE_COMBINATIONS], i)
        {
            // parse all enum nl80211_if_combination_attrs type
            ret = nla_parse_nested(attrComb, MAX_NL80211_IFACE_COMB, nlComb, ifaceCombPolicy);
            if (ret != 0) {
                HILOG_ERROR(LOG_CORE, "%s: nla_parse_nested nlComb failed", __FUNCTION__);
                return NL_SKIP;
            }
            if (!attrComb[NL80211_IFACE_COMB_LIMITS] || !attrComb[NL80211_IFACE_COMB_MAXNUM] ||
                !attrComb[NL80211_IFACE_COMB_NUM_CHANNELS]) {
                *isSupportCombo = 0;
            } else {
                *isSupportCombo = 1;
            }
        }
    }
    HILOG_INFO(LOG_CORE, "%s: isSupportCombo is %hhu", __FUNCTION__, *isSupportCombo);
    return NL_SKIP;
}

static int32_t ParserSupportComboInfo(struct nl_msg *msg, void *arg)
{
    (void)arg;
    struct nlattr *attr[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *hdr = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *nlComb = NULL, *nlLimit = NULL, *nlMode = NULL;
    struct nlattr *attrComb[NUM_NL80211_IFACE_COMB];
    struct nlattr *attrLimit[NUM_NL80211_IFACE_LIMIT];
    int32_t ret, i, j, k, type;
    static struct nla_policy ifaceCombPolicy[NUM_NL80211_IFACE_COMB];
    ifaceCombPolicy[NL80211_IFACE_COMB_LIMITS].type = NLA_NESTED;
    ifaceCombPolicy[NL80211_IFACE_COMB_MAXNUM].type = NLA_U32;
    ifaceCombPolicy[NL80211_IFACE_COMB_NUM_CHANNELS].type = NLA_U32;

    static struct nla_policy ifaceLimitPolicy[NUM_NL80211_IFACE_LIMIT];
    ifaceLimitPolicy[NL80211_IFACE_LIMIT_MAX].type = NLA_U32;
    ifaceLimitPolicy[NL80211_IFACE_LIMIT_TYPES].type = NLA_NESTED;

    ret = nla_parse(attr, NL80211_ATTR_MAX, genlmsg_attrdata(hdr, 0), genlmsg_attrlen(hdr, 0), NULL);
    if (ret != 0) {
        HILOG_ERROR(LOG_CORE, "%s: nla_parse tb failed", __FUNCTION__);
        return NL_SKIP;
    }

    if (attr[NL80211_ATTR_INTERFACE_COMBINATIONS] != NULL) {
        // get each ieee80211_iface_combination
        nla_for_each_nested(nlComb, attr[NL80211_ATTR_INTERFACE_COMBINATIONS], i)
        {
            ret = nla_parse_nested(attrComb, MAX_NL80211_IFACE_COMB, nlComb, ifaceCombPolicy);
            if (ret != 0) {
                HILOG_ERROR(LOG_CORE, "%s: nla_parse_nested nlComb failed", __FUNCTION__);
                return NL_SKIP;
            }
            if (!attrComb[NL80211_IFACE_COMB_LIMITS] || !attrComb[NL80211_IFACE_COMB_MAXNUM] ||
                !attrComb[NL80211_IFACE_COMB_NUM_CHANNELS]) {
                return RET_CODE_NOT_SUPPORT;
            }
            // parse each ieee80211_iface_limit
            nla_for_each_nested(nlLimit, attrComb[NL80211_IFACE_COMB_LIMITS], j)
            {
                ret = nla_parse_nested(attrLimit, MAX_NL80211_IFACE_LIMIT, nlLimit, ifaceLimitPolicy);
                if (ret || !attrLimit[NL80211_IFACE_LIMIT_TYPES])
                    return RET_CODE_NOT_SUPPORT; /* broken combination */
                // parse each ieee80211_iface_limit's types
                nla_for_each_nested(nlMode, attrLimit[NL80211_IFACE_LIMIT_TYPES], k)
                {
                    type = nla_type(nlMode);
                    if (type > WIFI_IFTYPE_UNSPECIFIED && type < WIFI_IFTYPE_MAX) {
                        HILOG_INFO(LOG_CORE, "%s: mode: %d", __FUNCTION__, type);
                    }
                }
                HILOG_INFO(LOG_CORE, "%s: has parse a attrLimit", __FUNCTION__);
            }
        }
    }
    return NL_SKIP;
}

static struct nlattr *GetWiphyBands(struct genlmsghdr *hdr)
{
    struct nlattr *attrMsg[NL80211_ATTR_MAX + 1];
    void *data = genlmsg_attrdata(hdr, 0);
    int32_t len = genlmsg_attrlen(hdr, 0);
    nla_parse(attrMsg, NL80211_ATTR_MAX, data, len, NULL);
    if (!attrMsg[NL80211_ATTR_WIPHY_BANDS]) {
        HILOG_ERROR(LOG_CORE, "%s: no wiphy bands", __FUNCTION__);
    }
    return attrMsg[NL80211_ATTR_WIPHY_BANDS];
}

static void GetCenterFreq(struct nlattr *bands, struct FreqInfoResult *result)
{
    struct nlattr *attrFreq[NL80211_FREQUENCY_ATTR_MAX + 1];
    struct nlattr *nlFreq = NULL;
    void *data = NULL;
    int32_t len;
    int32_t i;
    uint32_t freq;
    static struct nla_policy freqPolicy[NL80211_FREQUENCY_ATTR_MAX + 1];
    freqPolicy[NL80211_FREQUENCY_ATTR_FREQ].type = NLA_U32;
    freqPolicy[NL80211_FREQUENCY_ATTR_MAX_TX_POWER].type = NLA_U32;

    // get each ieee80211_channel
    nla_for_each_nested(nlFreq, bands, i)
    {
        data = nla_data(nlFreq);
        len = nla_len(nlFreq);
        nla_parse(attrFreq, NL80211_FREQUENCY_ATTR_MAX, data, len, freqPolicy);
        // get center freq
        if (attrFreq[NL80211_FREQUENCY_ATTR_FREQ] == NULL) {
            continue;
        }
        freq = nla_get_u32(attrFreq[NL80211_FREQUENCY_ATTR_FREQ]);
        switch (result->band) {
            case NL80211_BAND_2GHZ:
                if (attrFreq[NL80211_FREQUENCY_ATTR_MAX_TX_POWER]) {
                    if (freq > LOW_LITMIT_FREQ_2_4G && freq < HIGH_LIMIT_FREQ_2_4G) {
                        result->freqs[result->nums] = freq;
                        result->txPower[result->nums] = nla_get_u32(attrFreq[NL80211_FREQUENCY_ATTR_MAX_TX_POWER]);
                        result->nums++;
                    }
                }
                break;
            case NL80211_BAND_5GHZ:
                if (freq > LOW_LIMIT_FREQ_5G && freq < HIGH_LIMIT_FREQ_5G) {
                    result->freqs[result->nums] = freq;
                    result->nums++;
                }
                break;
            default:
                break;
        }
    }
}

static int32_t ParserValidFreq(struct nl_msg *msg, void *arg)
{
    struct FreqInfoResult *result = (struct FreqInfoResult *)arg;
    struct genlmsghdr *hdr = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *attrWiphyBands = NULL;
    struct nlattr *attrBand[NL80211_BAND_ATTR_MAX + 1];
    struct nlattr *nlBand = NULL;
    int32_t i;
    void *data = NULL;
    int32_t len;

    attrWiphyBands = GetWiphyBands(hdr);
    if (attrWiphyBands == NULL) {
        return NL_SKIP;
    }

    // get each ieee80211_supported_band
    nla_for_each_nested(nlBand, attrWiphyBands, i)
    {
        data = nla_data(nlBand);
        len = nla_len(nlBand);
        nla_parse(attrBand, NL80211_BAND_ATTR_MAX, data, len, NULL);
        if (attrBand[NL80211_BAND_ATTR_FREQS] == NULL)
            continue;
        GetCenterFreq(attrBand[NL80211_BAND_ATTR_FREQS], result);
    }
    return NL_SKIP;
}

static bool IsWifiIface(const char *name)
{
    if (strncmp(name, "wlan", WLAN_IFACE_LENGTH) != 0 && strncmp(name, "p2p", P2P_IFACE_LENGTH) != 0) {
        /* not a wifi interface; ignore it */
        return false;
    } else {
        return true;
    }
}

static int32_t GetAllIfaceInfo(struct NetworkInfoResult *infoResult)
{
    struct dirent *de;
    DIR *dir = opendir(NET_DEVICE_INFO_PATH);
    if (dir == NULL) {
        return RET_CODE_FAILURE;
    }
    infoResult->nums = 0;
    while ((de = readdir(dir))) {
        if (de->d_name[0] == '.') {
            continue;
        }
        if (IsWifiIface(de->d_name)) {
            if (strncpy_s(infoResult->infos[infoResult->nums].name, IFNAMSIZ, de->d_name, sizeof(de->d_name)) != EOK) {
                HILOG_ERROR(LOG_CORE, "%s: strncpy_s infoResult->infos failed", __FUNCTION__);
                closedir(dir);
                return RET_CODE_FAILURE;
            }
            infoResult->nums++;
        }
    }
    closedir(dir);
    if (infoResult->nums == 0) {
        return RET_CODE_NOT_AVAILABLE;
    }
    return RET_CODE_SUCCESS;
}

int32_t GetUsableNetworkInfo(struct NetworkInfoResult *result)
{
    int32_t ret;
    uint32_t i;

    ret = GetAllIfaceInfo(result);
    if (ret != RET_CODE_SUCCESS) {
        HILOG_ERROR(LOG_CORE, "%s: GetAllIfaceInfo failed", __FUNCTION__);
        return ret;
    }

    HILOG_INFO(LOG_CORE, "%s: wifi iface num %d", __FUNCTION__, result->nums);
    for (i = 0; i < result->nums; ++i) {
        ret = memset_s(result->infos[i].supportMode, sizeof(result->infos[i].supportMode), 0,
            sizeof(result->infos[i].supportMode));
        if (ret != EOK) {
            HILOG_ERROR(LOG_CORE, "%s: memset_s esult->infos failed", __FUNCTION__);
            return RET_CODE_FAILURE;
        }
        if (strncmp(result->infos[i].name, STR_WLAN0, strlen(STR_WLAN0)) == 0) {
            result->infos[i].supportMode[WIFI_IFTYPE_STATION] = 1;
            result->infos[i].supportMode[WIFI_IFTYPE_AP] = 1;
        } else if (strncmp(result->infos[i].name, STR_WLAN1, strlen(STR_WLAN1)) == 0) {
            result->infos[i].supportMode[WIFI_IFTYPE_STATION] = 1;
        } else if (strncmp(result->infos[i].name, STR_P2P0, strlen(STR_P2P0)) == 0) {
            result->infos[i].supportMode[WIFI_IFTYPE_P2P_DEVICE] = 1;
        } else if (strncmp(result->infos[i].name, STR_P2P0_X, strlen(STR_P2P0_X)) == 0) {
            result->infos[i].supportMode[WIFI_IFTYPE_P2P_CLIENT] = 1;
            result->infos[i].supportMode[WIFI_IFTYPE_P2P_GO] = 1;
        }
    }
    return RET_CODE_SUCCESS;
}

int32_t IsSupportCombo(uint8_t *isSupportCombo)
{
    uint32_t ifaceId;
    struct nl_msg *msg = NULL;
    struct NetworkInfoResult networkInfo;
    int32_t ret;

    ret = GetUsableNetworkInfo(&networkInfo);
    if (ret != RET_CODE_SUCCESS) {
        HILOG_ERROR(LOG_CORE, "%s: get network info failed", __FUNCTION__);
        return ret;
    }

    ifaceId = if_nametoindex(networkInfo.infos[0].name);
    if (ifaceId == 0) {
        HILOG_ERROR(LOG_CORE, "%s: get iface id(%u) failed", __FUNCTION__, ifaceId);
        return RET_CODE_FAILURE;
    }

    msg = nlmsg_alloc();
    if (msg == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: nlmsg alloc failed", __FUNCTION__);
        return RET_CODE_NOMEM;
    }

    genlmsg_put(msg, 0, 0, g_wifiHalInfo.familyId, 0, NLM_F_DUMP, NL80211_CMD_GET_WIPHY, 0);
    nla_put_flag(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifaceId);
    ret = NetlinkSendCmdSync(msg, ParserIsSupportCombo, isSupportCombo);
    if (ret != RET_CODE_SUCCESS) {
        HILOG_ERROR(LOG_CORE, "%s: send cmd failed", __FUNCTION__);
    }
    nlmsg_free(msg);
    return ret;
}

int32_t GetComboInfo(uint64_t *comboInfo, uint32_t size)
{
    (void)size;
    uint32_t ifaceId;
    struct nl_msg *msg = NULL;
    struct NetworkInfoResult networkInfo;
    int32_t ret;

    ret = GetUsableNetworkInfo(&networkInfo);
    if (ret != RET_CODE_SUCCESS) {
        HILOG_ERROR(LOG_CORE, "%s: get network info failed", __FUNCTION__);
        return ret;
    }

    ifaceId = if_nametoindex(networkInfo.infos[0].name);
    if (ifaceId == 0) {
        HILOG_ERROR(LOG_CORE, "%s: get iface id(%d) failed", __FUNCTION__, ifaceId);
        return RET_CODE_FAILURE;
    }

    msg = nlmsg_alloc();
    if (msg == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: nlmsg alloc failed", __FUNCTION__);
        return RET_CODE_NOMEM;
    }
    genlmsg_put(msg, 0, 0, g_wifiHalInfo.familyId, 0, NLM_F_DUMP, NL80211_CMD_GET_WIPHY, 0);
    nla_put_flag(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifaceId);
    ret = NetlinkSendCmdSync(msg, ParserSupportComboInfo, comboInfo);
    if (ret != RET_CODE_SUCCESS) {
        HILOG_ERROR(LOG_CORE, "%s: send cmd failed", __FUNCTION__);
    }
    nlmsg_free(msg);
    return ret;
}

int32_t SetMacAddr(const char *ifName, unsigned char *mac, uint8_t len)
{
    int32_t fd;
    int32_t ret;
    struct ifreq req;

    if (memset_s(&req, sizeof(req), 0, sizeof(req)) != EOK) {
        HILOG_ERROR(LOG_CORE, "%s: memset_s req failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    fd = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        HILOG_ERROR(LOG_CORE, "%s: open socket failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    if (strncpy_s(req.ifr_name, IFNAMSIZ, ifName, strlen(ifName)) != EOK) {
        HILOG_ERROR(LOG_CORE, "%s: strncpy_s fail", __FUNCTION__);
        close(fd);
        return RET_CODE_FAILURE;
    }
    req.ifr_addr.sa_family = ARPHRD_ETHER;
    if (memcpy_s(req.ifr_hwaddr.sa_data, len, mac, len) != EOK) {
        HILOG_ERROR(LOG_CORE, "%s: memcpy_s req.ifr_hwaddr.sa_data failed", __FUNCTION__);
        close(fd);
        return RET_CODE_FAILURE;
    }
    ret = ioctl(fd, SIOCSIFHWADDR, &req);
    if (ret != RET_CODE_SUCCESS) {
        HILOG_ERROR(LOG_CORE, "%s: ioctl failed, errno = %d, (%s)", __FUNCTION__, errno, strerror(errno));
        if (errno == EPERM) {
            ret = RET_CODE_NOT_SUPPORT;
        } else if (errno == EBUSY) {
            ret = RET_CODE_DEVICE_BUSY;
        } else {
            ret = RET_CODE_FAILURE;
        }
    }
    close(fd);
    return ret;
}

static int32_t ParserChipId(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *hdr = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *attr[NL80211_ATTR_MAX + 1];
    uint8_t *chipId = (uint8_t *)arg;
    uint8_t *getChipId = NULL;
    int32_t ret;

    ret = nla_parse(attr, NL80211_ATTR_MAX, genlmsg_attrdata(hdr, 0), genlmsg_attrlen(hdr, 0), NULL);
    if (ret != 0) {
        HILOG_ERROR(LOG_CORE, "%s: nla_parse failed", __FUNCTION__);
        return NL_SKIP;
    }

    if (attr[NL80211_ATTR_MAX]) {
        getChipId = nla_data(attr[NL80211_ATTR_MAX]);
        *chipId = *getChipId;
    }

    return NL_SKIP;
}

int32_t GetDevMacAddr(const char *ifName, int32_t type, uint8_t *mac, uint8_t len)
{
    (void)type;
    int32_t fd, ret;
    struct ifreq req;

    if (memset_s(&req, sizeof(req), 0, sizeof(req)) != EOK) {
        HILOG_ERROR(LOG_CORE, "%s: memset_s req failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        HILOG_ERROR(LOG_CORE, "%s: open socket failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    req.ifr_addr.sa_family = AF_INET;
    strncpy_s(req.ifr_name, IFNAMSIZ, ifName, strlen(ifName));
    ret = ioctl(fd, SIOCGIFHWADDR, &req);
    if (ret != 0) {
        HILOG_ERROR(LOG_CORE, "%s: ioctl failed, errno = %d, (%s)", __FUNCTION__, errno, strerror(errno));
        close(fd);
        return RET_CODE_FAILURE;
    }
    if (memcpy_s(mac, len, (unsigned char *)req.ifr_hwaddr.sa_data, len) != EOK) {
        HILOG_ERROR(LOG_CORE, "%s: memcpy_s mac failed", __FUNCTION__);
        ret = RET_CODE_FAILURE;
    }
    close(fd);
    return ret;
}

int32_t GetValidFreqByBand(const char *ifName, int32_t band, struct FreqInfoResult *result, uint32_t size)
{
    uint32_t ifaceId;
    struct nl_msg *msg = NULL;
    int32_t ret;

    if (result == NULL || result->freqs == NULL || result->txPower == NULL) {
        HILOG_ERROR(LOG_CORE, "%s:  Invalid input parameter", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }

    if (band >= IEEE80211_NUM_BANDS) {
        HILOG_ERROR(LOG_CORE, "%s:  Invalid input parameter, band = %d", __FUNCTION__, band);
        return RET_CODE_INVALID_PARAM;
    }

    ifaceId = if_nametoindex(ifName);
    if (ifaceId == 0) {
        HILOG_ERROR(LOG_CORE, "%s: get iface id(%d) failed", __FUNCTION__, ifaceId);
        return RET_CODE_INVALID_PARAM;
    }

    msg = nlmsg_alloc();
    if (msg == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: nlmsg alloc failed", __FUNCTION__);
        return RET_CODE_NOMEM;
    }

    genlmsg_put(msg, 0, 0, g_wifiHalInfo.familyId, 0, NLM_F_DUMP, NL80211_CMD_GET_WIPHY, 0);
    nla_put_flag(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifaceId);
    ret = memset_s(result->freqs, size * sizeof(uint32_t), 0, size * sizeof(uint32_t));
    if (ret != EOK) {
        HILOG_ERROR(LOG_CORE, "%s: memset_s result->freqs  failed", __FUNCTION__);
        nlmsg_free(msg);
        return RET_CODE_FAILURE;
    }
    result->nums = 0;
    result->band = band;
    ret = NetlinkSendCmdSync(msg, ParserValidFreq, result);
    if (ret != RET_CODE_SUCCESS) {
        HILOG_ERROR(LOG_CORE, "%s: send cmd failed", __FUNCTION__);
    }
    nlmsg_free(msg);
    return ret;
}

int32_t SetTxPower(const char *ifName, int32_t power)
{
    uint32_t ifaceId;
    struct nl_msg *msg = NULL;
    int32_t ret;

    ifaceId = if_nametoindex(ifName);
    if (ifaceId == 0) {
        HILOG_ERROR(LOG_CORE, "%s: get iface id(%d) failed", __FUNCTION__, ifaceId);
        return RET_CODE_INVALID_PARAM;
    }

    msg = nlmsg_alloc();
    if (msg == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: nlmsg alloc failed", __FUNCTION__);
        return RET_CODE_NOMEM;
    }

    genlmsg_put(msg, 0, 0, g_wifiHalInfo.familyId, 0, 0, NL80211_CMD_SET_WIPHY, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifaceId);
    nla_put_u32(msg, NL80211_ATTR_WIPHY_TX_POWER_SETTING, NL80211_TX_POWER_LIMITED);
    nla_put_u32(msg, NL80211_ATTR_WIPHY_TX_POWER_LEVEL, 100 * power);
    ret = NetlinkSendCmdSync(msg, NULL, NULL);
    if (ret != RET_CODE_SUCCESS) {
        HILOG_ERROR(LOG_CORE, "%s: send cmd failed", __FUNCTION__);
    } else {
        HILOG_INFO(LOG_CORE, "%s: send end success", __FUNCTION__);
    }
    nlmsg_free(msg);
    return ret;
}

int32_t GetAssociatedStas(const char *ifName, struct AssocStaInfoResult *result)
{
    (void)ifName;
    if (memset_s(result, sizeof(struct AssocStaInfoResult), 0, sizeof(struct AssocStaInfoResult)) != EOK) {
        HILOG_ERROR(LOG_CORE, "%s: memset_s result failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    return RET_CODE_SUCCESS;
}

int32_t WifiSetCountryCode(const char *ifName, const char *code, uint32_t len)
{
    uint32_t ifaceId = if_nametoindex(ifName);
    struct nl_msg *msg = NULL;
    struct nlattr *data = NULL;
    int32_t ret;

    if (ifaceId == 0) {
        HILOG_ERROR(LOG_CORE, "%s: if_nametoindex failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }

    msg = nlmsg_alloc();
    if (msg == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: nlmsg alloc failed", __FUNCTION__);
        return RET_CODE_NOMEM;
    }

    genlmsg_put(msg, 0, 0, g_wifiHalInfo.familyId, 0, 0, NL80211_CMD_VENDOR, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifaceId);
    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, VENDOR_ID);
    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD, WIFI_SUBCMD_SET_COUNTRY_CODE);
    data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    if (data == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: nla_nest_start failed", __FUNCTION__);
        nlmsg_free(msg);
        return RET_CODE_FAILURE;
    }
    nla_put(msg, WIFI_ATTRIBUTE_COUNTRY, len, code);
    nla_nest_end(msg, data);

    ret = NetlinkSendCmdSync(msg, NULL, NULL);
    if (ret != RET_CODE_SUCCESS) {
        HILOG_ERROR(LOG_CORE, "%s: send cmd failed", __FUNCTION__);
    }
    nlmsg_free(msg);
    return ret;
}

int32_t SetScanMacAddr(const char *ifName, uint8_t *scanMac, uint8_t len)
{
    int32_t ret;
    uint32_t ifaceId = if_nametoindex(ifName);
    struct nl_msg *msg = nlmsg_alloc();
    struct nlattr *data = NULL;

    if (msg == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: nlmsg alloc failed", __FUNCTION__);
        return RET_CODE_NOMEM;
    }
    if (ifaceId == 0) {
        HILOG_ERROR(LOG_CORE, "%s: if_nametoindex failed", __FUNCTION__);
        nlmsg_free(msg);
        return RET_CODE_FAILURE;
    }
    genlmsg_put(msg, 0, 0, g_wifiHalInfo.familyId, 0, 0, NL80211_CMD_VENDOR, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifaceId);
    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, VENDOR_ID);
    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD, WIFI_SUBCMD_SET_RANDOM_MAC_OUI);
    data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    if (data == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: nla_nest_start failed", __FUNCTION__);
        nlmsg_free(msg);
        return RET_CODE_FAILURE;
    }
    nla_put(msg, WIFI_ATTRIBUTE_RANDOM_MAC_OUI, len, scanMac);
    nla_nest_end(msg, data);
    ret = NetlinkSendCmdSync(msg, NULL, NULL);
    if (ret != RET_CODE_SUCCESS) {
        HILOG_ERROR(LOG_CORE, "%s: send cmd failed", __FUNCTION__);
    }
    nlmsg_free(msg);
    return ret;
}

int32_t AcquireChipId(const char *ifName, uint8_t *chipId)
{
    struct nl_msg *msg = NULL;
    uint32_t ifaceId;
    int32_t ret;

    if (ifName == NULL || chipId == NULL) {
        HILOG_ERROR(LOG_CORE, "%s params is NULL", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }

    ifaceId = if_nametoindex(ifName);
    if (ifaceId == 0) {
        HILOG_ERROR(LOG_CORE, "%s: if_nametoindex failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }

    msg = nlmsg_alloc();
    if (msg == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: nlmsg alloc failed", __FUNCTION__);
        return RET_CODE_NOMEM;
    }

    genlmsg_put(msg, 0, 0, g_wifiHalInfo.familyId, 0, NLM_F_DUMP, NL80211_CMD_GET_WIPHY, 0);
    nla_put_flag(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifaceId);

    ret = NetlinkSendCmdSync(msg, ParserChipId, chipId);
    if (ret != RET_CODE_SUCCESS) {
        HILOG_ERROR(LOG_CORE, "%s: NetlinkSendCmdSync failed.", __FUNCTION__);
    }
    nlmsg_free(msg);
    return ret;
}

int32_t GetIfNamesByChipId(const uint8_t chipId, char **ifNames, uint32_t *num)
{
    if (ifNames == NULL || num == NULL) {
        HILOG_ERROR(LOG_CORE, "%s params is NULL", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }

    if (chipId >= MAX_WLAN_DEVICE) {
        HILOG_ERROR(LOG_CORE, "%s: chipId = %d", __FUNCTION__, chipId);
        return RET_CODE_INVALID_PARAM;
    }
    *num = 1;
    *ifNames = (char *)calloc(*num, IFNAMSIZ);
    if (*ifNames == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: calloc failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    if (memcpy_s(*ifNames, IFNAMSIZ, "wlan0", IFNAMSIZ) != EOK) {
        HILOG_ERROR(LOG_CORE, "%s: memcpy failed", __FUNCTION__);
        free(*ifNames);
        *ifNames = NULL;
        return RET_CODE_FAILURE;
    }
    return RET_CODE_SUCCESS;
}

int32_t SetResetDriver(const uint8_t chipId, const char *ifName)
{
    (void)chipId;
    (void)ifName;
    return RET_CODE_SUCCESS;
}

static int32_t NetDeviceInfoHandler(struct nl_msg *msg, void *arg)
{
    struct NetDeviceInfo *info = (struct NetDeviceInfo *)arg;
    struct nlattr *attr[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *hdr = NULL;
    void *data = NULL;
    int32_t len;

    hdr = nlmsg_data(nlmsg_hdr(msg));
    if (hdr == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: get nlmsg header fail", __FUNCTION__);
        return NL_SKIP;
    }
    data = genlmsg_attrdata(hdr, 0);
    len = genlmsg_attrlen(hdr, 0);
    nla_parse(attr, NL80211_ATTR_MAX, data, len, NULL);
    if (attr[NL80211_ATTR_IFTYPE]) {
        info->iftype = nla_get_u32(attr[NL80211_ATTR_IFTYPE]);
        HILOG_ERROR(LOG_CORE, "%s: %s iftype is %hhu", __FUNCTION__, info->ifName, info->iftype);
    }
    if (attr[NL80211_ATTR_MAC]) {
        if (memcpy_s(info->mac, ETH_ADDR_LEN, nla_data(attr[NL80211_ATTR_MAC]), ETH_ADDR_LEN) != EOK) {
            HILOG_ERROR(LOG_CORE, "%s: memcpy_s mac address fail", __FUNCTION__);
        }
    }

    return NL_SKIP;
}

static int32_t GetIftypeAndMac(struct NetDeviceInfo *info)
{
    struct nl_msg *msg = nlmsg_alloc();
    int32_t ret;

    if (msg == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: nlmsg_alloc failed.", __FUNCTION__);
        return RET_CODE_FAILURE;
    }

    genlmsg_put(msg, 0, 0, g_wifiHalInfo.familyId, 0, 0, NL80211_CMD_GET_INTERFACE, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(info->ifName));

    ret = NetlinkSendCmdSync(msg, NetDeviceInfoHandler, info);
    if (ret != RET_CODE_SUCCESS) {
        HILOG_ERROR(LOG_CORE, "%s: NetlinkSendCmdSync failed.", __FUNCTION__);
    }
    nlmsg_free(msg);
    return ret;
}

int32_t GetNetDeviceInfo(struct NetDeviceInfoResult *netDeviceInfoResult)
{
    struct NetworkInfoResult networkInfo;
    uint32_t i;
    int32_t ret;

    ret = GetUsableNetworkInfo(&networkInfo);
    if (ret != RET_CODE_SUCCESS) {
        HILOG_ERROR(LOG_CORE, "%s: get network info failed", __FUNCTION__);
        return ret;
    }

    for (i = 0; i < networkInfo.nums && i < MAX_NETDEVICE_COUNT; i++) {
        if (memset_s(&netDeviceInfoResult->deviceInfos[i], sizeof(struct NetDeviceInfo), 0,
            sizeof(struct NetDeviceInfo)) != EOK) {
            HILOG_ERROR(LOG_CORE, "%s: memset_s fail", __FUNCTION__);
            return RET_CODE_FAILURE;
        }
        netDeviceInfoResult->deviceInfos[i].index = i + 1;
        if (strncpy_s(netDeviceInfoResult->deviceInfos[i].ifName, IFNAMSIZ,
            networkInfo.infos[i].name, IFNAMSIZ) != EOK) {
            HILOG_ERROR(LOG_CORE, "%s: strncpy_s fail", __FUNCTION__);
            return RET_CODE_FAILURE;
        }
        ret = GetIftypeAndMac(&netDeviceInfoResult->deviceInfos[i]);
        if (ret != RET_CODE_SUCCESS) {
            HILOG_ERROR(LOG_CORE, "%s: get iftype and mac failed", __FUNCTION__);
            return ret;
        }
    }

    return RET_CODE_SUCCESS;
}

static int32_t CmdScanPutMsg(struct nl_msg *msg, const WifiScan *scan)
{
    struct nlattr *nest = NULL;
    int32_t i;

    if (scan->ssids) {
        nest = nla_nest_start(msg, NL80211_ATTR_SCAN_SSIDS);
        if (nest == NULL) {
            HILOG_ERROR(LOG_CORE, "%s: nla_nest_start failed", __FUNCTION__);
            return RET_CODE_FAILURE;
        }
        for (i = 0; i < scan->numSsids; i++) {
            nla_put(msg, i + 1, scan->ssids->ssidLen, scan->ssids->ssid);
        }
        nla_nest_end(msg, nest);
    }

    if (scan->freqs) {
        nest = nla_nest_start(msg, NL80211_ATTR_SCAN_FREQUENCIES);
        if (nest == NULL) {
            HILOG_ERROR(LOG_CORE, "%s: nla_nest_start failed", __FUNCTION__);
            return RET_CODE_FAILURE;
        }
        for (i = 0; i < scan->numFreqs; i++) {
            nla_put_u32(msg, i + 1, scan->freqs[i]);
        }
        nla_nest_end(msg, nest);
    }

    if (scan->extraIes) {
        nla_put(msg, NL80211_ATTR_IE, scan->extraIesLen, scan->extraIes);
    }

    if (scan->bssid) {
        nla_put(msg, NL80211_ATTR_MAC, ETH_ADDR_LEN, scan->bssid);
    }

    return RET_CODE_SUCCESS;
}

int32_t WifiCmdScan(const char *ifName, WifiScan *scan)
{
    uint32_t ifaceId = if_nametoindex(ifName);
    struct nl_msg *msg = NULL;
    int32_t ret;

    if (ifaceId == 0) {
        HILOG_ERROR(LOG_CORE, "%s: if_nametoindex failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }

    msg = nlmsg_alloc();
    if (msg == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: nlmsg alloc failed", __FUNCTION__);
        return RET_CODE_NOMEM;
    }

    genlmsg_put(msg, 0, 0, g_wifiHalInfo.familyId, 0, 0, NL80211_CMD_TRIGGER_SCAN, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifaceId);
    do {
        ret = CmdScanPutMsg(msg, scan);
        if (ret != RET_CODE_SUCCESS) {
            HILOG_ERROR(LOG_CORE, "%s: put msg failed", __FUNCTION__);
            break;
        }
        ret = NetlinkSendCmdSync(msg, NULL, NULL);
        if (ret != RET_CODE_SUCCESS) {
            HILOG_ERROR(LOG_CORE, "%s: send cmd failed", __FUNCTION__);
        }
    } while (0);
    nlmsg_free(msg);
    return ret;
}

static int32_t ParsePowerMode(const char *buf, uint16_t len, uint8_t *mode)
{
    char *key[WIFI_POWER_MODE_NUM] = {"sleep\n", "third\n", "init\n"};
    char *str = "pow_mode = ";
    if (buf == NULL || mode == NULL) {
        return RET_CODE_INVALID_PARAM;
    }
    char *pos = strstr(buf, str);
    if (pos == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: no power mode", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    pos += strlen(str);
    if (!strncmp(pos, key[WIFI_POWER_MODE_SLEEPING], strlen(key[WIFI_POWER_MODE_SLEEPING]))) {
        *mode = WIFI_POWER_MODE_SLEEPING;
    } else if (!strncmp(pos, key[WIFI_POWER_MODE_GENERAL], strlen(key[WIFI_POWER_MODE_GENERAL]))) {
        *mode = WIFI_POWER_MODE_GENERAL;
    } else if (!strncmp(pos, key[WIFI_POWER_MODE_THROUGH_WALL], strlen(key[WIFI_POWER_MODE_THROUGH_WALL]))) {
        *mode = WIFI_POWER_MODE_THROUGH_WALL;
    } else {
        HILOG_ERROR(LOG_CORE, "%s: no invalid power mode", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    return RET_CODE_SUCCESS;
}

int32_t GetCurrentPowerMode(const char *ifName, uint8_t *mode)
{
    int32_t fd = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    int32_t ret;
    HwprivIoctlData ioctlData;

    (void)memset_s(&ioctlData, sizeof(ioctlData), 0, sizeof(ioctlData));
    if (fd < 0) {
        HILOG_ERROR(LOG_CORE, "%s: open socket failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    do {
        if (strcpy_s(ioctlData.interfaceName, IFNAMSIZ, ifName) != EOK) {
            HILOG_ERROR(LOG_CORE, "%s: strcpy_s failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        ioctlData.data.point.flags = SECONDARY_ID_POWER_MODE;
        ioctlData.data.point.length = strlen(GET_POWER_MODE) + 1;
        ioctlData.data.point.buf = calloc(ioctlData.data.point.length, sizeof(char));
        if (ioctlData.data.point.buf == NULL) {
            HILOG_ERROR(LOG_CORE, "%s: calloc failed", __FUNCTION__);
            ret = RET_CODE_NOMEM;
            break;
        }
        if (memcpy_s(ioctlData.data.point.buf, ioctlData.data.point.length,
            GET_POWER_MODE, strlen(GET_POWER_MODE)) != EOK) {
            HILOG_ERROR(LOG_CORE, "%s: memcpy_s failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        ret = ioctl(fd, PRIMARY_ID_POWER_MODE, &ioctlData);
        if (ret != RET_CODE_SUCCESS) {
            HILOG_ERROR(LOG_CORE, "%s: ioctl failed, errno = %d, (%s)", __FUNCTION__, errno, strerror(errno));
            if (errno == EOPNOTSUPP) {
                ret = RET_CODE_NOT_SUPPORT;
            } else {
                ret = RET_CODE_FAILURE;
            }
            break;
        }
        ret = ParsePowerMode(ioctlData.data.point.buf, ioctlData.data.point.length, mode);
        if (ret != RET_CODE_SUCCESS) {
            HILOG_ERROR(LOG_CORE, "%s: ParsePowerMode failed", __FUNCTION__);
            break;
        }
    } while (0);
    if (ioctlData.data.point.buf != NULL) {
        free(ioctlData.data.point.buf);
        ioctlData.data.point.buf = NULL;
    }
    close(fd);
    return ret;
}

static int32_t FillHwprivIoctlData(HwprivIoctlData *ioctlData, uint8_t mode)
{
    const char *strTable[WIFI_POWER_MODE_NUM] = {SET_POWER_MODE_SLEEP, SET_POWER_MODE_THIRD, SET_POWER_MODE_INIT};
    const char *modeStr = strTable[mode];

    ioctlData->data.point.length = strlen(strTable[mode]) + 1;
    ioctlData->data.point.buf = calloc(ioctlData->data.point.length, sizeof(char));
    if (ioctlData->data.point.buf == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: calloc failed", __FUNCTION__);
        return RET_CODE_NOMEM;
    }
    ioctlData->data.point.flags = SECONDARY_ID_POWER_MODE;
    if (strncpy_s(ioctlData->data.point.buf, ioctlData->data.point.length, modeStr, strlen(modeStr)) != EOK) {
        HILOG_ERROR(LOG_CORE, "%s: strncpy_s failed", __FUNCTION__);
        free(ioctlData->data.point.buf);
        ioctlData->data.point.buf = NULL;
        return RET_CODE_FAILURE;
    }

    return RET_CODE_SUCCESS;
}

int32_t SetPowerMode(const char *ifName, uint8_t mode)
{
    int32_t fd;
    int32_t ret;
    HwprivIoctlData ioctlData;

    (void)memset_s(&ioctlData, sizeof(ioctlData), 0, sizeof(ioctlData));
    fd = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        HILOG_ERROR(LOG_CORE, "%s: open socket failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }

    do {
        if (strcpy_s(ioctlData.interfaceName, IFNAMSIZ, ifName) != EOK) {
            HILOG_ERROR(LOG_CORE, "%s: strcpy_s failed", __FUNCTION__);
            ret = RET_CODE_FAILURE;
            break;
        }
        ret = FillHwprivIoctlData(&ioctlData, mode);
        if (ret != RET_CODE_SUCCESS) {
            break;
        }
        ret = ioctl(fd, PRIMARY_ID_POWER_MODE, &ioctlData);
        if (ret != RET_CODE_SUCCESS) {
            HILOG_ERROR(LOG_CORE, "%s: ioctl failed, errno = %d, (%s)", __FUNCTION__, errno, strerror(errno));
            if (errno == EOPNOTSUPP) {
                ret = RET_CODE_NOT_SUPPORT;
            } else {
                ret = RET_CODE_FAILURE;
            }
        }
    } while (0);

    if (ioctlData.data.point.buf != NULL) {
        free(ioctlData.data.point.buf);
        ioctlData.data.point.buf = NULL;
    }
    close(fd);
    return ret;
}

int32_t StartChannelMeas(const char *ifName, const struct MeasParam *measParam)
{
    (void)ifName;
    (void)measParam;
    return RET_CODE_NOT_SUPPORT;
}

int32_t GetChannelMeasResult(const char *ifName, struct MeasResult *measResult)
{
    (void)ifName;
    (void)measResult;
    return RET_CODE_NOT_SUPPORT;
}

static int32_t SendCommandToDriver(const char *cmd, uint32_t len, const char *ifName)
{
    struct ifreq ifr;
    WifiPrivCmd privCmd = {0};
    uint8_t buf[MAX_PRIV_CMD_SIZE] = {0};
    int32_t ret = RET_CODE_FAILURE;

    if (cmd == NULL) {
        HILOG_ERROR(LOG_CORE, "%{public}s: cmd is null", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    if (len > MAX_PRIV_CMD_SIZE) {
        HILOG_ERROR(LOG_CORE, "%{public}s: Size of command is too large", __FUNCTION__);
        return RET_CODE_INVALID_PARAM;
    }
    if (memset_s(&ifr, sizeof(ifr), 0, sizeof(ifr)) != EOK) {
        HILOG_ERROR(LOG_CORE, "%s: memset_s ifr failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    if (memcpy_s(buf, MAX_PRIV_CMD_SIZE, cmd, len) != EOK) {
        HILOG_ERROR(LOG_CORE, "%{public}s: memcpy_s error", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    privCmd.buf = buf;
    privCmd.size = sizeof(buf);
    privCmd.len = len;
    ifr.ifr_data = (void *)&privCmd;
    if (strcpy_s(ifr.ifr_name, IFNAMSIZ, ifName) != EOK) {
        HILOG_ERROR(LOG_CORE, "%s: strcpy_s error", __FUNCTION__);
        return RET_CODE_FAILURE;
    }
    int32_t sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        HILOG_ERROR(LOG_CORE, "%{public}s: socket failed, errno = %{public}d, (%{public}s)", __FUNCTION__, errno,
            strerror(errno));
        return ret;
    }
    do {
        ret = ioctl(sock, SIOCDEVPRIVATE + 1, &ifr);
        if (ret < 0) {
            HILOG_ERROR(LOG_CORE, "%{public}s: ioctl failed, errno = %{public}d, (%{public}s)", __FUNCTION__, errno,
                strerror(errno));
            ret = (errno == EOPNOTSUPP) ? RET_CODE_NOT_SUPPORT : RET_CODE_FAILURE;
            break;
        }
        (void)memset_s((void *)cmd, len, 0, len);
        if (memcpy_s((void *)cmd, len, privCmd.buf, len - 1) != EOK) {
            HILOG_ERROR(LOG_CORE, "%{public}s: memcpy_s error", __FUNCTION__);
            ret = RET_CODE_FAILURE;
        }
    } while (0);

    close(sock);
    return ret;
}

static int32_t DisableNextCacOnce(const char *ifName)
{
    char cmdBuf[P2P_BUF_SIZE] = {CMD_SET_CLOSE_GO_CAC};

    return SendCommandToDriver(cmdBuf, P2P_BUF_SIZE, ifName);
}

static int32_t SetGoChannel(const char *ifName, const int8_t *data, uint32_t len)
{
    int32_t ret = RET_CODE_FAILURE;
    char cmdBuf[P2P_BUF_SIZE] = {0};
    uint32_t cmdLen;

    cmdLen = strlen(CMD_SET_CHANGE_GO_CHANNEL);
    if ((cmdLen + len) >= P2P_BUF_SIZE) {
        HILOG_ERROR(LOG_CORE, "%{public}s: the length of input data is too large", __FUNCTION__);
        return ret;
    }
    ret = snprintf_s(cmdBuf, P2P_BUF_SIZE, P2P_BUF_SIZE - 1, "%s %d", CMD_SET_CHANGE_GO_CHANNEL, *data);
    if (ret < RET_CODE_SUCCESS) {
        HILOG_ERROR(LOG_CORE, "%{public}s: ifName: %{public}s, ret = %{public}d", __FUNCTION__, ifName, ret);
        return RET_CODE_FAILURE;
    }
    return SendCommandToDriver(cmdBuf, P2P_BUF_SIZE, ifName);
}

static int32_t SetGoDetectRadar(const char *ifName, const int8_t *data, uint32_t len)
{
    int32_t ret = RET_CODE_FAILURE;
    char cmdBuf[P2P_BUF_SIZE] = {0};
    uint32_t cmdLen;

    cmdLen = strlen(CMD_SET_GO_DETECT_RADAR);
    if ((cmdLen + len) >= P2P_BUF_SIZE) {
        HILOG_ERROR(LOG_CORE, "%{public}s: the length of input data is too large", __FUNCTION__);
        return ret;
    }
    ret = snprintf_s(cmdBuf, P2P_BUF_SIZE, P2P_BUF_SIZE - 1, "%s %d", CMD_SET_GO_DETECT_RADAR, *data);
    if (ret < RET_CODE_SUCCESS) {
        HILOG_ERROR(LOG_CORE, "%{public}s: ifName: %{public}s, ret = %{public}d", __FUNCTION__, ifName, ret);
        return RET_CODE_FAILURE;
    }
    return SendCommandToDriver(cmdBuf, P2P_BUF_SIZE, ifName);
}

static int32_t SetP2pScenes(const char *ifName, const int8_t *data, uint32_t len)
{
    int32_t ret = RET_CODE_FAILURE;
    char cmdBuf[P2P_BUF_SIZE] = {0};
    uint32_t cmdLen;

    cmdLen = strlen(CMD_SET_P2P_SCENES);
    if ((cmdLen + len) >= P2P_BUF_SIZE) {
        HILOG_ERROR(LOG_CORE, "%{public}s: the length of input data is too large", __FUNCTION__);
        return ret;
    }
    ret = snprintf_s(cmdBuf, P2P_BUF_SIZE, P2P_BUF_SIZE - 1, "%s %d", CMD_SET_P2P_SCENES, *data);
    if (ret < RET_CODE_SUCCESS) {
        HILOG_ERROR(LOG_CORE, "%{public}s: ifName: %{public}s, ret = %{public}d", __FUNCTION__, ifName, ret);
        return RET_CODE_FAILURE;
    }
    return SendCommandToDriver(cmdBuf, P2P_BUF_SIZE, ifName);
}

static int32_t SetDynamicDbacMode(const char *ifName, const int8_t *data, uint32_t len)
{
    int32_t ret = RET_CODE_FAILURE;
    char cmdBuf[P2P_BUF_SIZE] = {0};
    uint32_t cmdLen;

    cmdLen = strlen(CMD_SET_DYNAMIC_DBAC_MODE);
    if ((cmdLen + len) >= P2P_BUF_SIZE) {
        HILOG_ERROR(LOG_CORE, "%{public}s: the length of input data is too large", __FUNCTION__);
        return ret;
    }
    ret = snprintf_s(cmdBuf, P2P_BUF_SIZE, P2P_BUF_SIZE - 1, "%s %d", CMD_SET_DYNAMIC_DBAC_MODE, *data);
    if (ret < RET_CODE_SUCCESS) {
        HILOG_ERROR(LOG_CORE, "%{public}s: ifName: %{public}s, ret = %{public}d", __FUNCTION__, ifName, ret);
        return RET_CODE_FAILURE;
    }
    return SendCommandToDriver(cmdBuf, P2P_BUF_SIZE, ifName);
}

int32_t SetProjectionScreenParam(const char *ifName, const ProjScrnCmdParam *param)
{
    int32_t ret;

    if (strcmp(ifName, STR_WLAN0) != EOK) {
        HILOG_ERROR(LOG_CORE, "%{public}s: %{public}s is not supported", __FUNCTION__, ifName);
        return RET_CODE_NOT_SUPPORT;
    }
    switch (param->cmdId) {
        case CMD_CLOSE_GO_CAC:
            ret = DisableNextCacOnce(ifName);
            break;
        case CMD_SET_GO_CSA_CHANNEL:
            ret = SetGoChannel(ifName, param->buf, param->bufLen);
            break;
        case CMD_SET_GO_RADAR_DETECT:
            ret = SetGoDetectRadar(ifName, param->buf, param->bufLen);
            break;
        case CMD_ID_MCC_STA_P2P_QUOTA_TIME:
            ret = SetDynamicDbacMode(ifName, param->buf, param->bufLen);
            break;
        case CMD_ID_CTRL_ROAM_CHANNEL:
            ret = SetP2pScenes(ifName, param->buf, param->bufLen);
            break;
        default:
            HILOG_ERROR(LOG_CORE, "%{public}s: Invalid command id", __FUNCTION__);
            return RET_CODE_NOT_SUPPORT;
    }
    if (ret != RET_CODE_SUCCESS) {
        HILOG_ERROR(LOG_CORE, "%{public}s: Config projection screen fail, ret = %{public}d", __FUNCTION__, ret);
    }
    return ret;
}

int32_t SendCmdIoctl(const char *ifName, int32_t cmdId, const int8_t *paramBuf, uint32_t paramBufLen)
{
    (void)ifName;
    (void)cmdId;
    (void)paramBuf;
    (void)paramBufLen;
    return RET_CODE_NOT_SUPPORT;
}

static void ParseStaTxRate(struct nlattr **stats, uint32_t size, StationInfo *info)
{
    struct nlattr *rate[NL80211_RATE_INFO_MAX + 1];
    static struct nla_policy ratePolicy[NL80211_RATE_INFO_MAX + 1];

    if (size < NL80211_STA_INFO_MAX + 1) {
        HILOG_ERROR(LOG_CORE, "%{public}s: size of stats is not enough", __FUNCTION__);
        return;
    }
    ratePolicy[NL80211_RATE_INFO_BITRATE].type = NLA_U16;
    ratePolicy[NL80211_RATE_INFO_BITRATE32].type = NLA_U32;
    ratePolicy[NL80211_RATE_INFO_MCS].type = NLA_U8;
    ratePolicy[NL80211_RATE_INFO_VHT_MCS].type = NLA_U8;
    ratePolicy[NL80211_RATE_INFO_SHORT_GI].type = NLA_FLAG;
    ratePolicy[NL80211_RATE_INFO_VHT_NSS].type = NLA_U8;
    if (stats[NL80211_STA_INFO_TX_BITRATE] != NULL &&
        nla_parse_nested(rate, NL80211_RATE_INFO_MAX, stats[NL80211_STA_INFO_TX_BITRATE], ratePolicy) == 0) {
        if (rate[NL80211_RATE_INFO_BITRATE32] != NULL) {
            info->txRate = nla_get_u32(rate[NL80211_RATE_INFO_BITRATE32]);
        } else if (rate[NL80211_RATE_INFO_BITRATE] != NULL) {
            info->txRate = nla_get_u16(rate[NL80211_RATE_INFO_BITRATE]);
        }
        if (rate[NL80211_RATE_INFO_MCS] != NULL) {
            info->txMcs = nla_get_u8(rate[NL80211_RATE_INFO_MCS]);
            info->flags |= STA_DRV_DATA_TX_MCS;
        }
        if (rate[NL80211_RATE_INFO_VHT_MCS] != NULL) {
            info->txVhtmcs = nla_get_u8(rate[NL80211_RATE_INFO_VHT_MCS]);
            info->flags |= STA_DRV_DATA_TX_VHT_MCS;
        }
        if (rate[NL80211_RATE_INFO_SHORT_GI] != NULL) {
            info->flags |= STA_DRV_DATA_TX_SHORT_GI;
        }
        if (rate[NL80211_RATE_INFO_VHT_NSS] != NULL) {
            info->txVhtNss = nla_get_u8(rate[NL80211_RATE_INFO_VHT_NSS]);
            info->flags |= STA_DRV_DATA_TX_VHT_NSS;
        }
    }
}

static void ParseStaRxRate(struct nlattr **stats, uint32_t size, StationInfo *info)
{
    struct nlattr *rate[NL80211_RATE_INFO_MAX + 1];
    static struct nla_policy ratePolicy[NL80211_RATE_INFO_MAX + 1];

    if (size < NL80211_STA_INFO_MAX + 1) {
        HILOG_ERROR(LOG_CORE, "%{public}s: size of stats is not enough", __FUNCTION__);
        return;
    }
    ratePolicy[NL80211_RATE_INFO_BITRATE].type = NLA_U16;
    ratePolicy[NL80211_RATE_INFO_BITRATE32].type = NLA_U32;
    ratePolicy[NL80211_RATE_INFO_MCS].type = NLA_U8;
    ratePolicy[NL80211_RATE_INFO_VHT_MCS].type = NLA_U8;
    ratePolicy[NL80211_RATE_INFO_SHORT_GI].type = NLA_FLAG;
    ratePolicy[NL80211_RATE_INFO_VHT_NSS].type = NLA_U8;
    if (stats[NL80211_STA_INFO_RX_BITRATE] != NULL &&
        nla_parse_nested(rate, NL80211_RATE_INFO_MAX, stats[NL80211_STA_INFO_RX_BITRATE], ratePolicy) == 0) {
        if (rate[NL80211_RATE_INFO_BITRATE32] != NULL) {
            info->rxRate = nla_get_u32(rate[NL80211_RATE_INFO_BITRATE32]);
        } else if (rate[NL80211_RATE_INFO_BITRATE] != NULL) {
            info->rxRate = nla_get_u16(rate[NL80211_RATE_INFO_BITRATE]);
        }
        if (rate[NL80211_RATE_INFO_MCS] != NULL) {
            info->rxMcs = nla_get_u8(rate[NL80211_RATE_INFO_MCS]);
            info->flags |= STA_DRV_DATA_RX_MCS;
        }
        if (rate[NL80211_RATE_INFO_VHT_MCS] != NULL) {
            info->rxVhtmcs = nla_get_u8(rate[NL80211_RATE_INFO_VHT_MCS]);
            info->flags |= STA_DRV_DATA_RX_VHT_MCS;
        }
        if (rate[NL80211_RATE_INFO_SHORT_GI] != NULL) {
            info->flags |= STA_DRV_DATA_RX_SHORT_GI;
        }
        if (rate[NL80211_RATE_INFO_VHT_NSS] != NULL) {
            info->rxVhtNss = nla_get_u8(rate[NL80211_RATE_INFO_VHT_NSS]);
            info->flags |= STA_DRV_DATA_RX_VHT_NSS;
        }
    }
}

static void ParseStaInfo(struct nlattr **stats, uint32_t size, StationInfo *info)
{
    ParseStaTxRate(stats, size, info);
    ParseStaRxRate(stats, size, info);
}

static int32_t StationInfoHandler(struct nl_msg *msg, void *arg)
{
    StationInfo *info = (StationInfo *)arg;
    struct genlmsghdr *hdr = NULL;
    struct nlattr *attr[NL80211_ATTR_MAX + 1];
    struct nlattr *stats[NL80211_STA_INFO_MAX + 1];
    static struct nla_policy statsPolicy[NL80211_STA_INFO_MAX + 1];

    statsPolicy[NL80211_STA_INFO_INACTIVE_TIME].type = NLA_U32;
    statsPolicy[NL80211_STA_INFO_RX_BYTES].type = NLA_U32;
    statsPolicy[NL80211_STA_INFO_TX_BYTES].type = NLA_U32;
    statsPolicy[NL80211_STA_INFO_RX_PACKETS].type = NLA_U32;
    statsPolicy[NL80211_STA_INFO_TX_PACKETS].type = NLA_U32;
    statsPolicy[NL80211_STA_INFO_TX_FAILED].type = NLA_U32;
    statsPolicy[NL80211_STA_INFO_RX_BYTES64].type = NLA_U64;
    statsPolicy[NL80211_STA_INFO_TX_BYTES64].type = NLA_U64;
    statsPolicy[NL80211_STA_INFO_SIGNAL].type = NLA_U8;
    statsPolicy[NL80211_STA_INFO_ACK_SIGNAL].type = NLA_U8;
    statsPolicy[NL80211_STA_INFO_RX_DURATION].type = NLA_U64;

    hdr = nlmsg_data(nlmsg_hdr(msg));
    if (hdr == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: get nlmsg header fail", __FUNCTION__);
        return NL_SKIP;
    }

    nla_parse(attr, NL80211_ATTR_MAX, genlmsg_attrdata(hdr, 0), genlmsg_attrlen(hdr, 0), NULL);
    if (!attr[NL80211_ATTR_STA_INFO]) {
        HILOG_ERROR(LOG_CORE, "%s: sta stats missing!", __FUNCTION__);
        return NL_SKIP;
    }

    if (nla_parse_nested(stats, NL80211_STA_INFO_MAX, attr[NL80211_ATTR_STA_INFO], statsPolicy)) {
        HILOG_ERROR(LOG_CORE, "%s: failed to parse nested attributes!", __FUNCTION__);
        return NL_SKIP;
    }

    ParseStaInfo(stats, NL80211_STA_INFO_MAX + 1, info);
    return NL_SKIP;
}

int32_t GetStationInfo(const char *ifName, StationInfo *info, const uint8_t *mac, uint32_t macLen)
{
    uint32_t ifaceId = if_nametoindex(ifName);
    struct nl_msg *msg = NULL;
    int32_t ret = RET_CODE_FAILURE;

    if (ifaceId == 0) {
        HILOG_ERROR(LOG_CORE, "%s: if_nametoindex failed", __FUNCTION__);
        return RET_CODE_FAILURE;
    }

    msg = nlmsg_alloc();
    if (msg == NULL) {
        HILOG_ERROR(LOG_CORE, "%s: nlmsg alloc failed", __FUNCTION__);
        return RET_CODE_NOMEM;
    }
    do {
        if (!genlmsg_put(msg, 0, 0, g_wifiHalInfo.familyId, 0, 0, NL80211_CMD_GET_STATION, 0)) {
            HILOG_ERROR(LOG_CORE, "%s: genlmsg_put faile", __FUNCTION__);
            break;
        }
        if (nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifaceId) != RET_CODE_SUCCESS) {
            HILOG_ERROR(LOG_CORE, "%s: nla_put_u32 ifaceId faile", __FUNCTION__);
            break;
        }
        if (nla_put(msg, NL80211_ATTR_MAC, ETH_ADDR_LEN, mac) != RET_CODE_SUCCESS) {
            HILOG_ERROR(LOG_CORE, "%s: nla_put mac address faile", __FUNCTION__);
            break;
        }

        ret = NetlinkSendCmdSync(msg, StationInfoHandler, info);
        if (ret != RET_CODE_SUCCESS) {
            HILOG_ERROR(LOG_CORE, "%s: send cmd failed", __FUNCTION__);
        }
    } while (0);
    nlmsg_free(msg);
    return ret;
}