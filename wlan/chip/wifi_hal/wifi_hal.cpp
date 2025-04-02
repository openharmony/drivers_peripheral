/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
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

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <netpacket/packet.h>
#include <linux/filter.h>
#include <linux/pkt_sched.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/object-api.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/attr.h>
#include <netlink/handlers.h>
#include <netlink/msg.h>
#include <dirent.h>
#include <net/if.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <vector>
#include "wifi_hal.h"
#include "cpp_bindings.h"
#include "common.h"
#include <hdf_log.h>
#include "securec.h"
#include "gscan.h"
#include "wifi_ioctl.h"
#include "wifi_scan.h"
#include "v2_0/ichip_iface.h"

constexpr int32_t WIFI_HAL_CMD_SOCK_PORT = 644;
constexpr int32_t WIFI_HAL_EVENT_SOCK_PORT = 645;
constexpr int32_t MAX_VIRTUAL_IFACES = 5;
constexpr int32_t WIFI_HAL_EVENT_BUFFER_NOT_AVAILABLE = 105;
constexpr int32_t EVENT_BUF_SIZE = 2048;
constexpr int32_t POLL_DRIVER_DURATION_US = 100000;
constexpr int32_t POLL_DRIVER_MAX_TIME_MS = 10000;
constexpr int32_t SIZE_BATE = 256;
constexpr int32_t SIZE_1K = 1024;
constexpr int32_t NUM_4 = 4;
constexpr int32_t DEFAULT_OFFSET = 22;
constexpr int32_t CALLOC_MAX_VALUE = 10;
constexpr int32_t OFFSET_8 = 8;
constexpr int32_t OFFSET_16 = 16;
constexpr int32_t OFFSET_24 = 24;
constexpr int32_t MASK_CSMA = 0xFF;

static std::mutex g_callbackMutex;

static int WifiGetMulticastId(wifiHandle handle, const char *name, const char *group);
static int wifiAddMemberShip(wifiHandle handle, const char *group);
static WifiError WifiInitInterfaces(wifiHandle handle);
static int GetInterface(const char *name, InterfaceInfo *info);
static bool IsWifiInterface(const char *name);
static void WifiCleanupDynamicIfaces(wifiHandle handle);
static void InternalCleanedUpHandler(wifiHandle handle);
static int InternalPollinHandler(wifiHandle handle);
static WifiError WifiSetCountryCode(wifiInterfaceHandle handle, const char *country_code);
static WifiError WifiGetSignalInfo(wifiInterfaceHandle handle,
    OHOS::HDI::Wlan::Chip::V2_0::SignalPollResult& signalPollresult);
static WifiError RegisterIfaceCallBack(const char *ifaceName,
    WifiCallbackHandler OnCallbackEvent);
static WifiError VendorHalCreateIface(wifiHandle handle, const char* ifname,
    HalIfaceType ifaceType);
static WifiError VendorHalDeleteIface(wifiHandle handle, const char* ifname);
static void CheckWhetherAddIface(wifiHandle handle, const char* ifname);
WifiError IsSupportCoex(bool& isCoex);
static WifiError SendCmdToDriver(const char *ifaceName, int32_t commandId,
    const std::vector<int8_t>& paramData, std::vector<int8_t>& result);

typedef enum WifiAttr {
    HAL_INVALID                    = 0,
    HAL_FEATURE_SET_NUM            = 1,
    HAL_FEATURE_SET                = 2,
    HAL_PNO_RANDOM_MAC_OUI         = 3,
    HAL_NODFS_SET                  = 4,
    HAL_COUNTRY                    = 5,
    HAL_ND_OFFLOAD_VALUE           = 6,
    HAL_TCPACK_SUP_VALUE           = 7,
    HAL_LATENCY_MODE               = 8,
    HAL_RANDOM_MAC                 = 9,
    HAL_TX_POWER_SCENARIO          = 10,
    HAL_THERMAL_MITIGATION         = 11,
    HAL_THERMAL_COMPLETION_WINDOW  = 12,
    HAL_VOIP_MODE                  = 13,
    HAL_DTIM_MULTIPLIER            = 14,
    HAL_MAX
} WifiAttrT;

#define NET_FILE_PATH "/sys/class/net/wlan0"

#define NL80211_SCAN_CMD(cmd) ((cmd) == NL80211_CMD_NEW_SCAN_RESULTS || (cmd) == NL80211_CMD_SCHED_SCAN_RESULTS || \
                               (cmd) == NL80211_CMD_SCAN_ABORTED)

static const int RSV_MAX_SIZE = 3;

typedef struct {
    int index;
    int c0Rssi;
    int c1Rssi;
    int rsv[RSV_MAX_SIZE];
} RssiReportStru;

HalInfo *g_halInfo = nullptr;

static void WifiPreDeinitialize(void)
{
    HDF_LOGI("wifi_pre_uninitialize enter");
    if (g_halInfo->cmdSock != nullptr) {
        close(g_halInfo->cleanupSocks[0]);
        close(g_halInfo->cleanupSocks[1]);
        nl_socket_free(g_halInfo->cmdSock);
        nl_socket_free(g_halInfo->eventSock);
        g_halInfo->cmdSock = nullptr;
        g_halInfo->eventSock = nullptr;
    }
    pthread_mutex_destroy(&g_halInfo->cbLock);
    DestroyResponseLock();
    free(g_halInfo);
    g_halInfo = nullptr;
}

WifiError InitWifiVendorHalFuncTable(WifiHalFn *fn)
{
    if (fn == NULL) {
        return HAL_UNKNOWN;
    }
    fn->vendorHalInit = VendorHalInit;
    fn->waitDriverStart = WaitDriverStart;
    fn->vendorHalExit = VendorHalExit;
    fn->startHalLoop = StartHalLoop;
    fn->vendorHalGetIfaces = VendorHalGetIfaces;
    fn->vendorHalGetIfName = VendorHalGetIfName;
    fn->vendorHalGetChannelsInBand = VendorHalGetChannelsInBand;
    fn->vendorHalSetRestartHandler = VendorHalSetRestartHandler;
    fn->vendorHalCreateIface = VendorHalCreateIface;
    fn->vendorHalDeleteIface = VendorHalDeleteIface;
    fn->triggerVendorHalRestart = TriggerVendorHalRestart;
    fn->wifiSetCountryCode = WifiSetCountryCode;
    fn->getSignalPollInfo = WifiGetSignalInfo;
    fn->wifiStartScan = WifiStartScan;
    fn->registerIfaceCallBack = RegisterIfaceCallBack;
    fn->getScanResults = WifiGetScanInfo;
    fn->wifiStartPnoScan = WifiStartPnoScan;
    fn->wifiStopPnoScan = WifiStopPnoScan;
    fn->wifiGetSupportedFeatureSet = WifiGetSupportedFeatureSet;
    fn->getChipCaps = GetChipCaps;
    fn->isSupportCoex = IsSupportCoex;
    fn->sendCmdToDriver = SendCmdToDriver;
    return HAL_SUCCESS;
}

static void WifiSocketSetLocalPort(struct nl_sock *sock, uint32_t port)
{
    constexpr int32_t num = DEFAULT_OFFSET;
    uint32_t pid = static_cast<uint32_t>(getpid()) & 0x3FFFFF;
    nl_socket_set_local_port(sock, pid + (port << num));
}

static nl_sock* WifiCreateNlSocket(int port)
{
    struct nl_sock *sock = nl_socket_alloc();
    if (sock == nullptr) {
        HDF_LOGE("Could not create handle");
        return nullptr;
    }

    WifiSocketSetLocalPort(sock, port);

    if (nl_connect(sock, NETLINK_GENERIC)) {
        HDF_LOGE("Could not connect handle");
        nl_socket_free(sock);
        return nullptr;
    }
    return sock;
}

static int ReportEventCallback(int cmd, WifiEvent &event)
{
    std::unique_lock<std::mutex> lock(g_callbackMutex);
    if (NL80211_SCAN_CMD(cmd)) {
        if (g_halInfo->ifaceCallBack.onScanEvent != nullptr) {
            g_halInfo->ifaceCallBack.onScanEvent(cmd);
            return NL_OK;
        }
    }
    return NL_SKIP;
}

static int InternalNoSeqCheck(struct nl_msg *msg, void *arg)
{
    return NL_OK;
}

static int InternalValidMessageHandler(nl_msg *msg, void *arg)
{
    HalInfo *info = GetHalInfo((wifiHandle)arg);
    WifiEvent event(msg);
    int res = event.Parse();
    if (res < 0 || info == nullptr) {
        HDF_LOGE("Failed to Parse event: %{public}d", res);
        return NL_SKIP;
    }
    int cmd = event.GetCmd();
    uint32_t vendorId = 0;
    int subcmd = 0;
    if (cmd == NL80211_CMD_VENDOR) {
        vendorId = event.GetU32(NL80211_ATTR_VENDOR_ID);
        subcmd = static_cast<int>(event.GetU32(NL80211_ATTR_VENDOR_SUBCMD));
        HDF_LOGD("event receive %{public}d, vendorId = 0x%{public}0x, subcmd = 0x%{public}0x", cmd, vendorId, subcmd);
    }
    if (ReportEventCallback(cmd, event) == NL_OK) {
        return NL_OK;
    }
    pthread_mutex_lock(&info->cbLock);
    for (int i = 0; i < info->numEventCb; i++) {
        if (cmd == info->eventCb[i].nlCmd) {
            if (cmd == NL80211_CMD_VENDOR && ((vendorId != info->eventCb[i].vendorId) ||
                (subcmd != info->eventCb[i].vendorSubcmd))) {
                continue;
            }
            CbInfo *cbi = &(info->eventCb[i]);
            nl_recvmsg_msg_cb_t cbFunc = cbi->cbFunc;
            WifiCommand *wifiCommand = (WifiCommand *)cbi->cbArg;
            if (wifiCommand != nullptr) {
                wifiCommand->AddRef();
            }
            pthread_mutex_unlock(&info->cbLock);
            if (cbFunc) {
                (*cbFunc)(msg, cbi->cbArg);
            }
            if (wifiCommand != nullptr) {
                wifiCommand->ReleaseRef();
            }
            return NL_OK;
        }
    }
    pthread_mutex_unlock(&info->cbLock);
    return NL_OK;
}

static int wifiAddMemberShip(wifiHandle handle, const char *group)
{
    HalInfo *info = GetHalInfo(handle);
    int id = WifiGetMulticastId(handle, "nl80211", group);
    if (id < 0 || info == nullptr) {
        HDF_LOGE("Could not find group %{public}s", group);
        return id;
    }

    int ret = nl_socket_add_membership(info->eventSock, id);
    if (ret < 0) {
        HDF_LOGE("Could not add membership to group %{public}s", group);
    }

    return ret;
}

static WifiError GetInterfaceNum(int* n)
{
    int cnt = 0;
    DIR *d = opendir("/sys/class/net");
    if (d == nullptr) {
        return HAL_UNKNOWN;
    }
    struct dirent *de;
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.') {
            continue;
        }
        if (IsWifiInterface(de->d_name)) {
            cnt++;
        }
    }
    closedir(d);
    *n = cnt;
    return HAL_SUCCESS;
}
 
static void RelaseHalInfoSpace(HalInfo *info)
{
    if (info == nullptr || info->interfaces == nullptr || info->numInterfaces == 0) {
        return;
    }
    int i = 0;
    while (i < info->numInterfaces) {
        free(info->interfaces[i]);
        i++;
    }
    free(info->interfaces);
    info->interfaces = nullptr;
    info->numInterfaces = 0;
}

static WifiError WifiInitInterfacesSplitting(wifiHandle handle, HalInfo *info, DIR *d, int &i, int &n)
{
    struct dirent *de;
    while ((de = readdir(d)) && i < n) {
        if (de->d_name[0] == '.') {
            continue;
        }
        if (IsWifiInterface(de->d_name)) {
            InterfaceInfo *ifinfo = (InterfaceInfo *)malloc(sizeof(InterfaceInfo));
            if (ifinfo == nullptr) {
                return HAL_OUT_OF_MEMORY;
            }
            if (memset_s(ifinfo, sizeof(InterfaceInfo), 0, sizeof(InterfaceInfo)) != EOK ||
                GetInterface(de->d_name, ifinfo) != HAL_SUCCESS) {
                free(ifinfo);
                return HAL_OUT_OF_MEMORY;
            }
            ifinfo->isVirtual = false;
            ifinfo->handle = handle;
            info->interfaces[i] = ifinfo;
            i++;
        }
    }
    return HAL_SUCCESS;
}

static WifiError WifiInitInterfaces(wifiHandle handle)
{
    HalInfo *info = (HalInfo *)handle;
    int n = 0;
    WifiError ret = GetInterfaceNum(&n);
    if (ret == HAL_UNKNOWN) {
        return HAL_UNKNOWN;
    }
    if (n == 0) {
        return HAL_NOT_AVAILABLE;
    }

    DIR *d = opendir("/sys/class/net");
    if (d == nullptr) {
        return HAL_UNKNOWN;
    }
    n += MAX_VIRTUAL_IFACES;
    if (n > CALLOC_MAX_VALUE) {
        closedir(d);
        return HAL_OUT_OF_MEMORY;
    }
    info->interfaces = (InterfaceInfo **)calloc(n, sizeof(InterfaceInfo *) * n);
    if (!info->interfaces) {
        RelaseHalInfoSpace(info);
        closedir(d);
        return HAL_OUT_OF_MEMORY;
    }
    int i = 0;
    if (WifiInitInterfacesSplitting(handle, info, d, i, n) != HAL_SUCCESS) {
        RelaseHalInfoSpace(info);
        closedir(d);
        return HAL_OUT_OF_MEMORY;
    }
    closedir(d);
    info->numInterfaces = i;
    info->maxNumInterfaces = n;
    return HAL_SUCCESS;
}

class GetMulticastIdCommand : public WifiCommand {
public:
    GetMulticastIdCommand(wifiHandle handle, const char *name, const char *group)
        : WifiCommand("GetMulticastIdCommand", handle, 0)
    {
        mName = name;
        mGroup = group;
        mId = -1;
    }

    int GetId()
    {
        return mId;
    }

    int Create() override
    {
        int nlctrlFamily = genl_ctrl_resolve(mInfo->cmdSock, "nlctrl");
        int ret = mMsg.Create(nlctrlFamily, CTRL_CMD_GETFAMILY, 0, 0);
        if (ret < 0) {
            return ret;
        }
        ret = mMsg.PutString(CTRL_ATTR_FAMILY_NAME, mName);
        return ret;
    }

    int HandleResponse(WifiEvent& reply) override
    {
        struct nlattr **tb = reply.Attributes();
        struct nlattr *mcgrp = nullptr;
        int i;

        if (!tb[CTRL_ATTR_MCAST_GROUPS]) {
            HDF_LOGI("No multicast groups found");
            return NL_SKIP;
        }

        FOR_EACH_ATTR(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], i) {
            struct nlattr *tb2[CTRL_ATTR_MCAST_GRP_MAX + 1];
            nla_parse(tb2, CTRL_ATTR_MCAST_GRP_MAX, (nlattr *)nla_data(mcgrp),
                nla_len(mcgrp), NULL);
            if (!tb2[CTRL_ATTR_MCAST_GRP_NAME] || !tb2[CTRL_ATTR_MCAST_GRP_ID]) {
                continue;
            }
            char *grpName = (char *)nla_data(tb2[CTRL_ATTR_MCAST_GRP_NAME]);
            int grpNameLen = nla_len(tb2[CTRL_ATTR_MCAST_GRP_NAME]);
            if (strncmp(grpName, mGroup, grpNameLen) != 0) {
                continue;
            }
            mId = static_cast<int32_t>(nla_get_u32(tb2[CTRL_ATTR_MCAST_GRP_ID]));
            break;
        }
        return NL_SKIP;
    }

private:
    const char *mName;
    const char *mGroup;
    int mId;
};

static int WifiGetMulticastId(wifiHandle handle, const char *name, const char *group)
{
    GetMulticastIdCommand cmd(handle, name, group);
    auto lock = ReadLockData();
    int res = cmd.RequestResponse();
    if (res < 0) {
        return res;
    } else {
        return cmd.GetId();
    }
}

static bool IsWifiInterface(const char *name)
{
    constexpr int32_t NUM_3 = 3;
    constexpr int32_t NUM_5 = 5;
    if (strncmp(name, "wlan", NUM_4) != 0 && strncmp(name, "swlan", NUM_5) != 0 &&
        strncmp(name, "p2p", NUM_3) != 0 && strncmp(name, "aware", NUM_5) != 0 &&
        strncmp(name, "nan", NUM_3) != 0) {
        /* not a wifi interface; ignore it */
        return false;
    } else {
        return true;
    }
}

static int GetInterface(const char *name, InterfaceInfo *info)
{
    unsigned int size = 0;
    size = strlcpy(info->name, name, sizeof(info->name));
    if (size >= sizeof(info->name)) {
        return HAL_OUT_OF_MEMORY;
    }
    info->id = static_cast<int>(if_nametoindex(name));
    return HAL_SUCCESS;
}

wifiInterfaceHandle WifiGetWlanInterface(wifiHandle info, wifiInterfaceHandle *ifaceHandles, int numIfaceHandles)
{
    constexpr int32_t NUM_5 = 5;
    char buf[EVENT_BUF_SIZE];
    wifiInterfaceHandle wlan0Handle;
    WifiError res = VendorHalGetIfaces((wifiHandle)info, &numIfaceHandles, &ifaceHandles);
    if (res < 0) {
        return NULL;
    }
    for (int i = 0; i < numIfaceHandles; i++) {
        if (VendorHalGetIfName(ifaceHandles[i], buf, sizeof(buf)) == HAL_SUCCESS) {
            if (strncmp(buf, "wlan0", NUM_5) == 0) {
                HDF_LOGI("found interface %{public}s\n", buf);
                wlan0Handle = ifaceHandles[i];
                return wlan0Handle;
            }
        }
    }
    return NULL;
}

static void PreInitFail(bool needCloseSock, struct nl_sock *eventSock,
    struct nl_sock *cmdSock, bool needClearLock, bool needClearcb)
{
    if (needCloseSock) {
        close(g_halInfo->cleanupSocks[0]);
        close(g_halInfo->cleanupSocks[1]);
    }
    if (cmdSock != nullptr) {
        nl_socket_free(cmdSock);
    }
    if (eventSock != nullptr) {
        nl_socket_free(eventSock);
    }
    if (needClearLock) {
        pthread_mutex_destroy(&g_halInfo->cbLock);
        DestroyResponseLock();
    }
    if (needClearcb) {
        if (g_halInfo->eventCb != nullptr) {
            free(g_halInfo->eventCb);
            g_halInfo->eventCb = nullptr;
        }
        if (g_halInfo->cmd != nullptr) {
            free(g_halInfo->cmd);
            g_halInfo->cmd = nullptr;
        }
    }
    if (g_halInfo != nullptr) {
        free(g_halInfo);
        g_halInfo = nullptr;
    }
}

static bool SetHalInfo(struct nl_sock *eventSock, struct nl_sock *cmdSock)
{
    struct nl_cb *cb = nl_socket_get_cb(eventSock);
    if (cb == nullptr) {
        HDF_LOGE("Could not create handle");
        return false;
    }
    nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, InternalNoSeqCheck, g_halInfo);
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, InternalValidMessageHandler, g_halInfo);
    nl_cb_put(cb);
    g_halInfo->cmdSock = cmdSock;
    g_halInfo->eventSock = eventSock;
    g_halInfo->cleanUp = false;
    g_halInfo->inEventLoop = false;
    g_halInfo->eventCb = reinterpret_cast<CbInfo *>(malloc(sizeof(CbInfo) * DEFAULT_EVENT_CB_SIZE));
    if (g_halInfo->eventCb == nullptr) {
        return false;
    }
    g_halInfo->allocEventCb = DEFAULT_EVENT_CB_SIZE;
    g_halInfo->numEventCb = 0;
    g_halInfo->cmd = reinterpret_cast<CmdInfo *>(malloc(sizeof(CmdInfo) * DEFAULT_CMD_SIZE));
    if (g_halInfo->cmd == nullptr) {
        free(g_halInfo->eventCb);
        g_halInfo->eventCb = nullptr;
        return false;
    }
    g_halInfo->allocCmd = DEFAULT_CMD_SIZE;
    g_halInfo->numCmd = 0;
    g_halInfo->nl80211FamilyId = genl_ctrl_resolve(cmdSock, "nl80211");
    if (g_halInfo->nl80211FamilyId < 0) {
        HDF_LOGE("Could not resolve nl80211 familty id");
        free(g_halInfo->eventCb);
        g_halInfo->eventCb = nullptr;
        free(g_halInfo->cmd);
        g_halInfo->cmd = nullptr;
        return false;
    }
    return true;
}

static struct nl_sock *InitCmdSock()
{
    struct nl_sock *cmdSock = WifiCreateNlSocket(WIFI_HAL_CMD_SOCK_PORT);
    if (cmdSock == nullptr) {
        HDF_LOGE("cmd sock create failed");
        return nullptr;
    }
    if (nl_socket_set_buffer_size(cmdSock, (SIZE_BATE * SIZE_1K), 0) < 0) {
        HDF_LOGE("Could not set size for cmdSock: %{public}s", strerror(errno));
    }
    return cmdSock;
}

static struct nl_sock *InitEventSock()
{
    struct nl_sock *eventSock = WifiCreateNlSocket(WIFI_HAL_EVENT_SOCK_PORT);
    if (eventSock == nullptr) {
        HDF_LOGE("event sock create failed");
        return nullptr;
    }
    if (nl_socket_set_buffer_size(eventSock, (NUM_4 * SIZE_1K * SIZE_1K), 0) < 0) {
        HDF_LOGE("Could not set size for eventSock: %{public}s", strerror(errno));
    }
    return eventSock;
}

static bool InitHalInfo()
{
    g_halInfo = reinterpret_cast<HalInfo *>(malloc(sizeof(HalInfo)));
    if (g_halInfo == nullptr) {
        HDF_LOGE("Could not allocate HalInfo");
        return false;
    }
    if (memset_s(g_halInfo, sizeof(*g_halInfo), 0, sizeof(*g_halInfo)) != EOK) {
        HDF_LOGE("memset HalInfo failed");
        free(g_halInfo);
        g_halInfo = nullptr;
        return false;
    }
    return true;
}

static WifiError WifiPreInitialize(void)
{
    srand(getpid());
    wifiHandle handle;

    HDF_LOGI("WifiPreInitialize");
    if (g_halInfo != nullptr) {
        WifiPreDeinitialize();
    }
    if (!InitHalInfo()) {
        return HAL_UNKNOWN;
    }
    HDF_LOGI("Creating socket");
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_halInfo->cleanupSocks) == -1) {
        HDF_LOGE("Could not create cleanup sockets");
        PreInitFail(false, nullptr, nullptr, false, false);
        return HAL_UNKNOWN;
    }
    struct nl_sock *cmdSock = InitCmdSock();
    if (cmdSock == nullptr) {
        PreInitFail(true, nullptr, nullptr, false, false);
        return HAL_UNKNOWN;
    }
    struct nl_sock *eventSock = InitEventSock();
    if (eventSock == nullptr) {
        PreInitFail(true, nullptr, cmdSock, false, false);
        return HAL_UNKNOWN;
    }
    if (!SetHalInfo(eventSock, cmdSock)) {
        PreInitFail(true, eventSock, cmdSock, false, false);
        return HAL_UNKNOWN;
    }
    pthread_mutex_init(&g_halInfo->cbLock, nullptr);
    InitResponseLock();
    handle = (wifiHandle) g_halInfo;
    if (WifiInitInterfaces(handle) != HAL_SUCCESS) {
        HDF_LOGE("No wifi interface found");
        PreInitFail(true, eventSock, cmdSock, true, true);
        return HAL_NOT_AVAILABLE;
    }
    if ((wifiAddMemberShip(handle, "scan") < 0) || (wifiAddMemberShip(handle, "mlme")  < 0) ||
        (wifiAddMemberShip(handle, "regulatory") < 0) || (wifiAddMemberShip(handle, "vendor") < 0)) {
        HDF_LOGE("Add membership failed");
        PreInitFail(true, eventSock, cmdSock, true, true);
        return HAL_NOT_AVAILABLE;
    }
    HDF_LOGI("Initialized Wifi HAL Successfully; vendor cmd = %{public}d", NL80211_CMD_VENDOR);
    return HAL_SUCCESS;
}

WifiError VendorHalInit(wifiHandle *handle)
{
    WifiError result = HAL_SUCCESS;

    HDF_LOGI("WifiInitialize");
    if (g_halInfo == nullptr) {
        result = WifiPreInitialize();
        if (result != HAL_SUCCESS) {
            HDF_LOGE("WifiInitialize WifiPreInitialize failed");
            return result;
        } else {
            HDF_LOGE("WifiInitialize WifiPreInitialize succeeded");
        }
    }
    *handle = (wifiHandle) g_halInfo;
    return HAL_SUCCESS;
}


WifiError WaitDriverStart(void)
{
    // This function will Wait to make sure basic client netdev is created
    // Function times out after 10 seconds
#ifdef SUPPORT_EMULATOR
    return HAL_SUCCESS;
#endif
    int count = (POLL_DRIVER_MAX_TIME_MS * 1000) / POLL_DRIVER_DURATION_US;
    FILE *fd;

    do {
        if ((fd = fopen(NET_FILE_PATH, "r")) != nullptr) {
            fclose(fd);
            WifiPreInitialize();
            return HAL_SUCCESS;
        }
        usleep(POLL_DRIVER_DURATION_US);
    } while (--count > 0);

    HDF_LOGE("Timed out waiting on Driver ready ... ");
    return HAL_TIMED_OUT;
}

static std::vector<std::string> added_ifaces;

static void WifiCleanupDynamicIfaces(wifiHandle handle)
{
    unsigned int len = added_ifaces.size();
    HDF_LOGI("%{public}s: virtual iface size %{public}d\n", __FUNCTION__, len);
    while (len--) {
        VendorHalDeleteIface(handle, added_ifaces.front().c_str());
        HDF_LOGI("%{public}s: deleted virtual iface %{public}s\n",
            __FUNCTION__, added_ifaces.front().c_str());
    }
    added_ifaces.clear();
}

static void VendorHalExitSplitting(wifiHandle handle, HalInfo *info)
{
    /* calling internal modules or cleanup */
    pthread_mutex_lock(&info->cbLock);
    int badCommands = 0;
    HDF_LOGI("eventCb callbacks left: %{public}d ", info->numEventCb);
    for (int i = 0; i < info->numEventCb; i++) {
        HDF_LOGI("eventCb cleanup. index:%{public}d", i);
        CbInfo *cbi = &(info->eventCb[i]);
        if (!cbi) {
            HDF_LOGE("cbi null for index %{public}d", i);
            continue;
        }
        HDF_LOGI("eventCb cleanup. vendor cmd:%{public}d sub_cmd:%{public}d", cbi->vendorId, cbi->vendorSubcmd);
        WifiCommand *cmd = (WifiCommand *)cbi->cbArg;
        if (cmd != nullptr) {
            HDF_LOGI("Command left in eventCb");
        }
    }
    HDF_LOGI("Check bad commands: numCmd:%{public}d badCommands:%{public}d", info->numCmd, badCommands);
    while (info->numCmd > badCommands) {
        int numCmd = info->numCmd;
        CmdInfo *cmdi = &(info->cmd[badCommands]);
        WifiCommand *cmd = cmdi->cmd;
        if (cmd != nullptr) {
            HDF_LOGI("Cancelling command:%{public}s", cmd->GetType());
            pthread_mutex_unlock(&info->cbLock);
            cmd->Cancel();
            pthread_mutex_lock(&info->cbLock);
            if (numCmd == info->numCmd) {
                HDF_LOGI("Cancelling command:%{public}s did not work", (cmd ? cmd->GetType() : ""));
                badCommands++;
            }
            /* release reference added when command is saved */
            cmd->ReleaseRef();
        }
    }
    for (int i = 0; i < info->numEventCb; i++) {
        CbInfo *cbi = &(info->eventCb[i]);
        if (!cbi) {
            HDF_LOGE("cbi null for index %{public}d", i);
            continue;
        }
    }
    if (!GetGHalutilMode()) {
        WifiCleanupDynamicIfaces(handle);
    }
    pthread_mutex_unlock(&info->cbLock);
}

void VendorHalExit(wifiHandle handle, VendorHalExitHandler handler)
{
    if (!handle) {
        HDF_LOGE("Handle is null");
        return;
    }

    HalInfo *info = GetHalInfo(handle);
    int numIfaceHandles = 0;
    wifiInterfaceHandle *ifaceHandles = NULL;
    wifiInterfaceHandle wlan0Handle;

    info->CleanedUpHandler = handler;
    auto lock = WriteLock();
    wlan0Handle = WifiGetWlanInterface((wifiHandle) info, ifaceHandles, numIfaceHandles);
    if (wlan0Handle != NULL) {
        HDF_LOGE("Calling hal cleanup");
        if (!GetGHalutilMode()) {
            WifiCleanupDynamicIfaces(handle);
            HDF_LOGI("Cleaned dynamic virtual ifaces\n");
            HDF_LOGI("wifi_stop_hal success");
        }
    } else {
        HDF_LOGE("Not cleaning up hal as global_iface is NULL");
    }

    VendorHalExitSplitting(handle, info);

    info->cleanUp = true;

    if (TEMP_FAILURE_RETRY(write(info->cleanupSocks[0], "Exit", NUM_4)) < 1) {
        // As a fallback set the cleanup flag to TRUE
        HDF_LOGE("could not write to the cleanup socket");
    }
    HDF_LOGE("wifi_cleanUp done");
}

static void InternalCleanedUpHandler(wifiHandle handle)
{
    auto lock = WriteLock();
    HalInfo *info = GetHalInfo(handle);
    if (info == nullptr) {
        HDF_LOGE("InternalCleanedUpHandler: info is null");
        return;
    }
    VendorHalExitHandler cleanedUpHandler = info->CleanedUpHandler;
    HDF_LOGI("internal clean up");
    if (info->cmdSock != nullptr) {
        HDF_LOGI("cmdSock non null. clean up");
        close(info->cleanupSocks[0]);
        close(info->cleanupSocks[1]);
        nl_socket_free(info->cmdSock);
        nl_socket_free(info->eventSock);
        info->cmdSock = nullptr;
        info->eventSock = nullptr;
    }

    if (cleanedUpHandler) {
        HDF_LOGI("cleanup_handler cb");
        (*cleanedUpHandler)(handle);
    } else {
        HDF_LOGE("!! clean up handler is null!!");
    }
    DestroyResponseLock();
    pthread_mutex_destroy(&info->cbLock);
    free(info);
    g_halInfo = nullptr;
    HDF_LOGI("Internal cleanup completed");
}

static int InternalPollinHandler(wifiHandle handle)
{
    HalInfo *info = GetHalInfo(handle);
    if (info == nullptr) {
        HDF_LOGE("InternalPollinHandler: info is nullptr");
        return -1;
    }
    struct nl_cb *cb = nl_socket_get_cb(info->eventSock);
    int res = nl_recvmsgs(info->eventSock, cb);
    HDF_LOGD("nl_recvmsgs returned %{public}d", res);
    nl_cb_put(cb);
    return res;
}

void StartHalLoop(wifiHandle handle)
{
    constexpr int32_t NUM_2 = 2;
    HalInfo *info = GetHalInfo(handle);
    if (info == nullptr || info->eventSock == nullptr || info->inEventLoop) {
        return;
    } else {
        info->inEventLoop = true;
    }

    pollfd pfd[2];
    if (memset_s(&pfd[0], sizeof(pollfd) * NUM_2, 0, sizeof(pollfd) * NUM_2) != EOK) {
        return;
    }
    pfd[0].fd = nl_socket_get_fd(info->eventSock);
    pfd[0].events = POLLIN;
    pfd[1].fd = info->cleanupSocks[1];
    pfd[1].events = POLLIN;

    char buf[2048];
    do {
        int timeout = -1;                   /* Infinite timeout */
        pfd[0].revents = 0;
        pfd[1].revents = 0;
        int result = TEMP_FAILURE_RETRY(poll(pfd, NUM_2, timeout));
        if (result < 0) {
            HDF_LOGE("Error polling socket");
        } else if (static_cast<uint32_t>(pfd[0].revents) & POLLERR) {
            HDF_LOGE("POLL Error; error no = %{public}d (%{public}s)", errno, strerror(errno));
            ssize_t result2 = TEMP_FAILURE_RETRY(read(pfd[0].fd, buf, sizeof(buf)));
            HDF_LOGE("Read after POLL returned %zd, error no = %{public}d (%{public}s)", result2,
                errno, strerror(errno));
            if (errno == WIFI_HAL_EVENT_BUFFER_NOT_AVAILABLE) {
                HDF_LOGE("Exit, No buffer space");
                break;
            }
        } else if (static_cast<uint32_t>(pfd[0].revents) & POLLHUP) {
            HDF_LOGE("Remote side hung up");
            break;
        } else if ((static_cast<uint32_t>(pfd[0].revents) & (POLLIN)) && (!info->cleanUp)) {
            InternalPollinHandler(handle);
        } else if (static_cast<uint32_t>(pfd[1].revents) & POLLIN) {
            HDF_LOGI("Got a Signal to exit!!!");
        } else {
            HDF_LOGE("Unknown event - %{public}0x, %{public}0x", pfd[0].revents, pfd[1].revents);
        }
    } while (!info->cleanUp);

    InternalCleanedUpHandler(handle);
    HDF_LOGE("Exit %{public}s", __FUNCTION__);
}

class VirtualIfaceConfig : public WifiCommand {
    const char *mIfname;
    nl80211_iftype mType;
    uint32_t mwlan0Id;

public:
    VirtualIfaceConfig(wifiInterfaceHandle handle, const char* ifname, nl80211_iftype ifaceType, uint32_t wlan0Id)
        : WifiCommand("VirtualIfaceConfig", handle, 0), mIfname(ifname), mType(ifaceType), mwlan0Id(wlan0Id)
    {
        mIfname = ifname;
        mType = ifaceType;
        mwlan0Id = wlan0Id;
    }

    int CreateRequest(WifiRequest& request, const char* ifname,
        nl80211_iftype ifaceType, uint32_t wlan0Id)
    {
        HDF_LOGD("add ifname = %{public}s, ifaceType = %{public}d, wlan0Id = %{public}d",
            ifname, ifaceType, wlan0Id);

        int result = request.Create(NL80211_CMD_NEW_INTERFACE);
        if (result < 0) {
            HDF_LOGE("failed to create NL80211_CMD_NEW_INTERFACE; result = %{public}d", result);
            return result;
        }

        result = request.PutU32(NL80211_ATTR_IFINDEX, wlan0Id);
        if (result < 0) {
            HDF_LOGE("failed to put NL80211_ATTR_IFINDEX; result = %{public}d", result);
            return result;
        }

        result = request.PutString(NL80211_ATTR_IFNAME, ifname);
        if (result < 0) {
            HDF_LOGE("failed to put NL80211_ATTR_IFNAME = %{public}s; result = %{public}d", ifname, result);
            return result;
        }

        result = request.PutU32(NL80211_ATTR_IFTYPE, ifaceType);
        if (result < 0) {
            HDF_LOGE("failed to put NL80211_ATTR_IFTYPE = %{public}d; result = %{public}d", ifaceType, result);
            return result;
        }
        return HAL_SUCCESS;
    }

    int DeleteRequest(WifiRequest& request, const char* ifname)
    {
        HDF_LOGD("delete ifname = %{public}s\n", ifname);
        int result = request.Create(NL80211_CMD_DEL_INTERFACE);
        if (result < 0) {
            HDF_LOGE("failed to create NL80211_CMD_DEL_INTERFACE; result = %{public}d", result);
            return result;
        }
        result = request.PutU32(NL80211_ATTR_IFINDEX, if_nametoindex(ifname));
        if (result < 0) {
            HDF_LOGE("failed to put NL80211_ATTR_IFINDEX = %{public}d; result = %{public}d",
                if_nametoindex(ifname), result);
            return result;
        }
        result = request.PutString(NL80211_ATTR_IFNAME, ifname);
        if (result < 0) {
            HDF_LOGE("failed to put NL80211_ATTR_IFNAME = %{public}s; result = %{public}d", ifname, result);
            return result;
        }
        return HAL_SUCCESS;
    }

    int CreateIface()
    {
        HDF_LOGD("Creating virtual interface");
        WifiRequest request(FamilyId(), IfaceId());
        int result = CreateRequest(request, mIfname, mType, mwlan0Id);
        if (result != HAL_SUCCESS) {
            HDF_LOGE("failed to create virtual iface request; result = %{public}d\n", result);
            return result;
        }
        auto lock = ReadLockData();
        result = RequestResponse(request);
        if (result != HAL_SUCCESS) {
            HDF_LOGE("failed to Get the virtual iface create response; result = %{public}d\n", result);
            return result;
        }
        HDF_LOGD("Created virtual interface");
        return HAL_SUCCESS;
    }

    int DeleteIface()
    {
        HDF_LOGD("Deleting virtual interface");
        WifiRequest request(FamilyId(), IfaceId());
        int result = DeleteRequest(request, mIfname);
        if (result != HAL_SUCCESS) {
            HDF_LOGE("failed to create virtual iface delete request; result = %{public}d\n", result);
            return result;
        }
        auto lock = ReadLockData();
        result = RequestResponse(request);
        if (result != HAL_SUCCESS) {
            HDF_LOGE("failed to Get response of delete virtual interface; result = %{public}d\n", result);
            return result;
        }
        HDF_LOGD("Deleted virtual interface");
        return HAL_SUCCESS;
    }
protected:
    int HandleResponse(WifiEvent& reply) override
    {
        HDF_LOGD("Request complete!");
        /* Nothing to do on response! */
        return NL_SKIP;
    }
};

static WifiError WifiAddIfaceHalInfo(wifiHandle handle, const char* ifname, bool isVirtual)
{
    HalInfo *info = nullptr;
    int i = 0;

    info = (HalInfo *)handle;
    if (info == nullptr) {
        HDF_LOGE("Could not find info\n");
        return HAL_UNKNOWN;
    }

    HDF_LOGI("%{public}s: add InterfaceInfo for iface: %{public}s\n", __FUNCTION__, ifname);
    if (info->numInterfaces == MAX_VIRTUAL_IFACES) {
        HDF_LOGE("No space. MAX limit reached for virtual interfaces %{public}d\n", info->numInterfaces);
        return HAL_OUT_OF_MEMORY;
    }

    InterfaceInfo *ifinfo = (InterfaceInfo *)malloc(sizeof(InterfaceInfo));
    if (!ifinfo) {
        free(info->interfaces);
        info->numInterfaces = 0;
        return HAL_OUT_OF_MEMORY;
    }

    ifinfo->handle = handle;
    while (i < info->maxNumInterfaces) {
        if (info->interfaces[i] == nullptr) {
            if (GetInterface(ifname, ifinfo) != HAL_SUCCESS) {
                continue;
            }
            ifinfo->isVirtual = isVirtual;
            info->interfaces[i] = ifinfo;
            info->numInterfaces++;
            HDF_LOGI("%{public}s: Added iface: %{public}s at the index %{public}d\n", __FUNCTION__, ifname, i);
            break;
        }
        i++;
    }
    return HAL_SUCCESS;
}

static void CheckWhetherAddIface(wifiHandle handle, const char* ifname)
{
    HalInfo *info = (HalInfo *)handle;
    int i = 0;

    while (i < info->maxNumInterfaces) {
        if (info->interfaces[i] != nullptr &&
            strncmp(info->interfaces[i]->name,
            ifname, sizeof(info->interfaces[i]->name)) == 0) {
            HDF_LOGD("%{public}s is exists", ifname);
            return;
        }
        i++;
    }
    WifiAddIfaceHalInfo((wifiHandle)handle, ifname, false);
}

static WifiError VendorHalCreateIface(wifiHandle handle, const char* ifname, HalIfaceType ifaceType)
{
    int numIfaceHandles = 0;
    WifiError ret = HAL_SUCCESS;
    wifiInterfaceHandle *ifaceHandles = NULL;
    wifiInterfaceHandle wlan0Handle;
    nl80211_iftype type = NL80211_IFTYPE_UNSPECIFIED;
    uint32_t wlan0Id = if_nametoindex("wlan0");
    if (!handle || !wlan0Id) {
        HDF_LOGE("%{public}s: Error wifiHandle NULL or wlan0 not present\n", __FUNCTION__);
        return HAL_UNKNOWN;
    }
    /* Do not create interface if already exist. */
    if (if_nametoindex(ifname)) {
        HDF_LOGI("%{public}s: if_nametoindex(%{public}s) = %{public}d already exists, skip create \n",
            __FUNCTION__, ifname, if_nametoindex(ifname));
        CheckWhetherAddIface(handle, ifname);
        return HAL_SUCCESS;
    }
    HDF_LOGI("%{public}s: ifname name = %{public}s, type = %{public}u\n", __FUNCTION__, ifname,
        ifaceType);
    switch (ifaceType) {
        case HAL_TYPE_STA:
            type = NL80211_IFTYPE_STATION;
            break;
        case HAL_TYPE_AP:
            type = NL80211_IFTYPE_AP;
            break;
        case HAL_TYPE_P2P:
            type = NL80211_IFTYPE_P2P_DEVICE;
            break;
        case HAL_TYPE_NAN:
            type = NL80211_IFTYPE_NAN;
            break;
        default:
            HDF_LOGE("%{public}s: Wrong interface type %{public}u\n", __FUNCTION__, ifaceType);
            return HAL_UNKNOWN;
    }
    wlan0Handle = WifiGetWlanInterface((wifiHandle)handle, ifaceHandles, numIfaceHandles);
    VirtualIfaceConfig command(wlan0Handle, ifname, type, wlan0Id);
    ret = (WifiError)command.CreateIface();
    if (ret != HAL_SUCCESS) {
        HDF_LOGE("%{public}s: Iface add Error:%{public}d", __FUNCTION__, ret);
        return ret;
    }
    /* Update dynamic interface list*/
    added_ifaces.push_back(std::string(ifname));
    ret = WifiAddIfaceHalInfo((wifiHandle)handle, ifname, true);
    return ret;
}

static WifiError WifiClearIfaceHalInfo(wifiHandle handle, const char* ifname)
{
    HalInfo *info = (HalInfo *)handle;
    int i = 0;

    HDF_LOGI("%s: clear hal info for iface: %s\n", __FUNCTION__, ifname);
    while (i < info->maxNumInterfaces) {
        if ((info->interfaces[i] != nullptr) &&
            strncmp(info->interfaces[i]->name, ifname,
            sizeof(info->interfaces[i]->name)) == 0) {
            free(info->interfaces[i]);
            info->interfaces[i] = nullptr;
            info->numInterfaces--;
            HDF_LOGI("%s: Cleared the index = %d for iface: %s\n", __FUNCTION__, i, ifname);
            break;
        }
        i++;
    }
    if (i < info->numInterfaces) {
        for (int j = i; j < info->numInterfaces; j++) {
            info->interfaces[j] = info->interfaces[j + 1];
        }
        info->interfaces[info->numInterfaces] = nullptr;
    }
    return HAL_SUCCESS;
}

static WifiError VendorHalDeleteIface(wifiHandle handle, const char* ifname)
{
    int numIfaceHandles = 0;
    int i = 0;
    WifiError ret = HAL_SUCCESS;
    wifiInterfaceHandle *ifaceHandles = NULL;
    wifiInterfaceHandle wlan0Handle;
    HalInfo *info = (HalInfo *)handle;
    uint32_t wlan0Id = if_nametoindex("wlan0");
    if (!handle || !wlan0Id) {
        HDF_LOGE("%{public}s: Error wifiHandle NULL or wlan0 not present\n", __FUNCTION__);
        return HAL_UNKNOWN;
    }

    while (i < info->maxNumInterfaces) {
        if (info->interfaces[i] != nullptr &&
            strncmp(info->interfaces[i]->name,
            ifname, sizeof(info->interfaces[i]->name)) == 0) {
            if (!info->interfaces[i]->isVirtual) {
                HDF_LOGI("%{public}s: %{public}s is static iface, skip delete\n",
                    __FUNCTION__, ifname);
                    return HAL_SUCCESS;
            }
        }
        i++;
    }

    HDF_LOGD("%{public}s: iface name=%{public}s\n", __FUNCTION__, ifname);
    wlan0Handle = WifiGetWlanInterface((wifiHandle)handle, ifaceHandles, numIfaceHandles);
    VirtualIfaceConfig command(wlan0Handle, ifname, (nl80211_iftype)0, 0);
    ret = (WifiError)command.DeleteIface();
    if (ret != HAL_SUCCESS) {
        HDF_LOGE("%{public}s: Iface delete Error:%{public}d", __FUNCTION__, ret);
        return ret;
    }
    added_ifaces.erase(std::remove(added_ifaces.begin(), added_ifaces.end(), std::string(ifname)),
        added_ifaces.end());
    ret = WifiClearIfaceHalInfo((wifiHandle)handle, ifname);
    return ret;
}

WifiError VendorHalGetIfaces(wifiHandle handle, int *num, wifiInterfaceHandle **interfaces)
{
    if (!handle) {
        HDF_LOGE("Handle is null");
        return HAL_UNKNOWN;
    }

    HalInfo *info = (HalInfo *)handle;
    *interfaces = (wifiInterfaceHandle *)info->interfaces;
    *num = info->numInterfaces;

    return HAL_SUCCESS;
}

WifiError VendorHalGetIfName(wifiInterfaceHandle handle, char *name, size_t size)
{
    if (!handle) {
        HDF_LOGE("Handle is null");
        return HAL_UNKNOWN;
    }
    InterfaceInfo *info = (InterfaceInfo *)handle;
    if (strncpy_s(name, IFNAMSIZ, info->name, IFNAMSIZ) != EOK) {
        return HAL_UNKNOWN;
    }
    name[IFNAMSIZ - 1] = '\0';
    return HAL_SUCCESS;
}

class SetCountryCodeCommand : public WifiCommand {
public:
    SetCountryCodeCommand(wifiInterfaceHandle handle, const char *countryCode)
        : WifiCommand("SetCountryCodeCommand", handle, 0)
    {
        mCountryCode = countryCode;
    }
    int Create() override
    {
        int ret;

        ret = mMsg.Create(HAL_OUI, WIFI_SUBCMD_SET_COUNTRY_CODE);
        if (ret < 0) {
            HDF_LOGE("Can't create message to send to driver - %{public}d", ret);
            return ret;
        }
        nlattr *data = mMsg.AttrStart(NL80211_ATTR_VENDOR_DATA);
        ret = mMsg.PutString(HAL_COUNTRY, mCountryCode);
        if (ret < 0) {
            return ret;
        }
        mMsg.AttrEnd(data);
        return HAL_SUCCESS;
    }
private:
    const char *mCountryCode;
};

static WifiError WifiSetCountryCode(wifiInterfaceHandle handle, const char *country_code)
{
    if (!handle) {
        HDF_LOGE("Handle is null");
        return HAL_INVALID_ARGS;
    }
    auto lock = ReadLockData();
    SetCountryCodeCommand command(handle, country_code);
    return (WifiError) command.RequestResponse();
}

class GetAssociatedInfoCommand : public WifiCommand {
public:
    GetAssociatedInfoCommand(wifiInterfaceHandle handle, AssociatedInfo *info)
        : WifiCommand("GetAssociatedInfoCommand", handle, 0)
    {
        mAssocInfo = info;
    }
    int Create() override
    {
        int ret;

        ret = mMsg.Create(FamilyId(), NL80211_CMD_GET_SCAN, NLM_F_DUMP, 0);
        if (ret < 0) {
            HDF_LOGE("Can't create message to send to driver - %{public}d", ret);
            return ret;
        }
        ret = mMsg.PutU32(NL80211_ATTR_IFINDEX, IfaceId());
        if (ret < 0) {
            return ret;
        }
        return HAL_SUCCESS;
    }
protected:
    int HandleResponse(WifiEvent& reply) override
    {
        uint32_t status;
        struct nlattr **attr = reply.Attributes();
        struct nlattr *bss[NL80211_BSS_MAX + 1];
        struct nla_policy bssPolicy[NL80211_BSS_MAX + 1];
        bssPolicy[NL80211_BSS_BSSID].type = NLA_UNSPEC;
        bssPolicy[NL80211_BSS_FREQUENCY].type = NLA_U32;
        bssPolicy[NL80211_BSS_STATUS].type = NLA_U32;

        HDF_LOGD("In GetAssociatedInfoCommand::HandleResponse");
        if (!attr[NL80211_ATTR_BSS]) {
            HDF_LOGE("HandleResponse: BSS info missing!");
            return NL_SKIP;
        }
        if (nla_parse_nested(bss, NL80211_BSS_MAX, attr[NL80211_ATTR_BSS], bssPolicy) < 0 ||
            bss[NL80211_BSS_STATUS] == NULL) {
            HDF_LOGD("HandleResponse BSS attr or status missing!");
            return NL_SKIP;
        }
        status = nla_get_u32(bss[NL80211_BSS_STATUS]);
        if (status == BSS_STATUS_ASSOCIATED && bss[NL80211_BSS_FREQUENCY]) {
            mAssocInfo->associatedFreq = nla_get_u32(bss[NL80211_BSS_FREQUENCY]);
        }
        if (status == BSS_STATUS_ASSOCIATED && bss[NL80211_BSS_BSSID]) {
            if (memcpy_s(mAssocInfo->associatedBssid, ETH_ADDR_LEN,
                nla_data(bss[NL80211_BSS_BSSID]), ETH_ADDR_LEN) != EOK) {
                HDF_LOGE("HandleResponse: memcpy_s failed!");
                return NL_SKIP;
            }
        }
        return NL_SKIP;
    }
private:
    AssociatedInfo *mAssocInfo;
};

static int WifiGetAssociateInfo(wifiInterfaceHandle handle, AssociatedInfo *info)
{
    GetAssociatedInfoCommand command(handle, info);
    auto lock = ReadLockData();
    return (WifiError) command.RequestResponse();
}

class GetSignalInfoCommand : public WifiCommand {
public:
    GetSignalInfoCommand(wifiInterfaceHandle handle, AssociatedInfo assocInfo)
        : WifiCommand("GetSignalInfoCommand", handle, 0)
    {
        mAssocInfo = assocInfo;
        if (memset_s(&mSignalInfo, sizeof(mSignalInfo), 0, sizeof(mSignalInfo)) != EOK) {
            HDF_LOGE("memset mSignalInfo failed");
        }
    }
    int Create() override
    {
        int ret;

        ret = mMsg.Create(FamilyId(), NL80211_CMD_GET_STATION, 0, 0);
        if (ret < 0) {
            HDF_LOGE("Can't create message to send to driver - %{public}d", ret);
            return ret;
        }
        ret = mMsg.PutU32(NL80211_ATTR_IFINDEX, IfaceId());
        if (ret < 0) {
            return ret;
        }
        ret = mMsg.Put(NL80211_ATTR_MAC, mAssocInfo.associatedBssid, ETH_ADDR_LEN);
        if (ret < 0) {
            return ret;
        }
        mSignalInfo.associatedFreq = static_cast<int32_t>(mAssocInfo.associatedFreq);
        return HAL_SUCCESS;
    }
    OHOS::HDI::Wlan::Chip::V2_0::SignalPollResult &GetScanResultsInfo()
    {
        return mSignalInfo;
    }
protected:
    int HandleResponse(WifiEvent& reply) override
    {
        struct nlattr **attr = reply.Attributes();
        struct nlattr *stats[NL80211_STA_INFO_MAX + 1];
        struct nla_policy statsPolicy[NL80211_STA_INFO_MAX + 1];
        statsPolicy[NL80211_STA_INFO_SIGNAL].type = NLA_S8;
        statsPolicy[NL80211_STA_INFO_RX_BYTES].type = NLA_U32;
        statsPolicy[NL80211_STA_INFO_TX_BYTES].type = NLA_U32;
        statsPolicy[NL80211_STA_INFO_RX_PACKETS].type = NLA_U32;
        statsPolicy[NL80211_STA_INFO_TX_PACKETS].type = NLA_U32;
        statsPolicy[NL80211_STA_INFO_TX_FAILED].type = NLA_U32;
        statsPolicy[NL80211_STA_INFO_NOISE].type = NLA_S32;
        statsPolicy[NL80211_STA_INFO_SNR].type = NLA_S32;
        statsPolicy[NL80211_STA_INFO_CNAHLOAD].type = NLA_S32;
        statsPolicy[NL80211_STA_INFO_UL_DELAY].type = NLA_S32;
        statsPolicy[NL80211_STA_INFO_UL_DELAY_ARRAY].type = NLA_U16;
        statsPolicy[NL80211_STA_INFO_TX_TIME].type = NLA_U16;
        statsPolicy[NL80211_STA_INFO_BEACON_RSSI].type = NLA_S8;
        statsPolicy[NL80211_STA_INFO_CHLOAD_SELF].type = NLA_U16;
        statsPolicy[NL80211_STA_INFO_SIGNAL_DUAL].type = NLA_S8;
        statsPolicy[NL80211_STA_INFO_TX_PPDU_CNT].type = NLA_U32;
        statsPolicy[NL80211_STA_INFO_TX_PPDU_RETRY_CNT].type = NLA_U32;
        statsPolicy[NL80211_STA_INFO_PPDU_PER].type = NLA_U8;
        statsPolicy[NL80211_STA_INFO_TX_MCS].type = NLA_U8;
        statsPolicy[NL80211_STA_INFO_CWMIN].type = NLA_U8;
        statsPolicy[NL80211_STA_INFO_CWMAX].type = NLA_S8;
        statsPolicy[NL80211_STA_INFO_ULDELAY_CDF].type = NLA_U16;
        statsPolicy[NL80211_STA_INFO_TX_TIME_CDF].type = NLA_U16;

        if (!attr[NL80211_ATTR_STA_INFO]) {
            HDF_LOGE("HandleResponse: sta stats missing!");
            return NL_SKIP;
        }
        if (nla_parse_nested(stats, NL80211_STA_INFO_MAX, attr[NL80211_ATTR_STA_INFO], statsPolicy) < 0) {
            HDF_LOGE("HandleResponse: nla_parse_nested NL80211_ATTR_STA_INFO failed!");
            return NL_SKIP;
        }
        FillSignal(stats, NL80211_STA_INFO_MAX + 1);
        FillSignalExt(stats, NL80211_STA_INFO_MAX + 1);
        FillSignalAiWifi(stats, NL80211_STA_INFO_MAX + 1);
        FillSignalRate(stats, NL80211_STA_INFO_MAX + 1);
        return NL_SKIP;
    }
private:
    OHOS::HDI::Wlan::Chip::V2_0::SignalPollResult mSignalInfo;
    AssociatedInfo mAssocInfo;

    void FillSignal(struct nlattr **stats, uint32_t size)
    {
        if (size < NL80211_STA_INFO_MAX + 1) {
            HDF_LOGE("size of stats is not enough");
            return;
        }

        if (stats[NL80211_STA_INFO_SIGNAL] != nullptr) {
            mSignalInfo.currentRssi = nla_get_s8(stats[NL80211_STA_INFO_SIGNAL]);
        }
        if (stats[NL80211_STA_INFO_TX_BYTES] != nullptr) {
            mSignalInfo.currentTxBytes = (uint64_t)nla_get_u32(stats[NL80211_STA_INFO_TX_BYTES]);
        }
        if (stats[NL80211_STA_INFO_RX_BYTES] != nullptr) {
            mSignalInfo.currentRxBytes = (uint64_t)nla_get_u32(stats[NL80211_STA_INFO_RX_BYTES]);
        }
        if (stats[NL80211_STA_INFO_TX_PACKETS] != nullptr) {
            mSignalInfo.currentTxPackets = (int32_t)nla_get_u32(stats[NL80211_STA_INFO_TX_PACKETS]);
        }
        if (stats[NL80211_STA_INFO_RX_PACKETS] != nullptr) {
            mSignalInfo.currentRxPackets = (int32_t)nla_get_u32(stats[NL80211_STA_INFO_RX_PACKETS]);
        }
        if (stats[NL80211_STA_INFO_TX_FAILED] != nullptr) {
            mSignalInfo.currentTxFailed = (int32_t)nla_get_u32(stats[NL80211_STA_INFO_TX_FAILED]);
        }
    }

    void FillSignalExt(struct nlattr **stats, uint32_t size)
    {
        if (size < NL80211_STA_INFO_MAX + 1) {
            HDF_LOGE("size of stats is not enough");
            return;
        }

        if (stats[NL80211_STA_INFO_NOISE] != NULL) {
            mSignalInfo.currentNoise = nla_get_s32(stats[NL80211_STA_INFO_NOISE]);
        }
        if (stats[NL80211_STA_INFO_SNR] != NULL) {
            mSignalInfo.currentSnr = nla_get_s32(stats[NL80211_STA_INFO_SNR]);
        }
        if (stats[NL80211_STA_INFO_CNAHLOAD] != NULL) {
            mSignalInfo.currentChload = nla_get_s32(stats[NL80211_STA_INFO_CNAHLOAD]);
        }
        if (stats[NL80211_STA_INFO_UL_DELAY] != NULL) {
            mSignalInfo.currentUlDelay = nla_get_s32(stats[NL80211_STA_INFO_UL_DELAY]);
        }
        if (stats[NL80211_STA_INFO_UL_DELAY_ARRAY] != NULL) {
            uint16_t *ulDelayArray = (uint16_t *)nla_data(stats[NL80211_STA_INFO_UL_DELAY_ARRAY]);
            HDF_LOGD("mSignalInfo.ulDelayArray[0]=%{public}d ", ulDelayArray[0]);
        }
        if (stats[NL80211_STA_INFO_TX_TIME] != NULL) {
            uint16_t *txTime = (uint16_t *)nla_data(stats[NL80211_STA_INFO_TX_TIME]);
            HDF_LOGD("mSignalInfo.txTime[0]=%{public}d ", txTime[0]);
        }
        if (stats[NL80211_STA_INFO_CHLOAD_SELF] != NULL) {
            mSignalInfo.chloadSelf = nla_get_u16(stats[NL80211_STA_INFO_CHLOAD_SELF]);
        }
        if (stats[NL80211_STA_INFO_SIGNAL_DUAL] != NULL) {
            int8_t *rptRssi = (int8_t *)nla_data(stats[NL80211_STA_INFO_SIGNAL_DUAL]);
            mSignalInfo.c0Rssi = rptRssi[0];
            mSignalInfo.c1Rssi = rptRssi[1];
        }
        FillSignalAiWifi(stats, NL80211_STA_INFO_MAX + 1);
    }

    void FillSignalAiWifi(struct nlattr **stats, uint32_t size)
    {
        const int beaconRssiMaxLen = 10;
        if (size < NL80211_STA_INFO_MAX + 1) {
            HDF_LOGE("size of stats is not enough");
            return;
        }
        if (stats[NL80211_STA_INFO_BEACON_RSSI] != NULL) {
            int8_t *beaconRssi = (int8_t *)nla_data(stats[NL80211_STA_INFO_BEACON_RSSI]);
            int beaconRssiLen = (int32_t)(nla_len(stats[NL80211_STA_INFO_BEACON_RSSI]));
            std::vector<uint8_t> beaconRssiVec(beaconRssi, beaconRssi + beaconRssiLen);
            if (beaconRssiLen > 0 && beaconRssiLen <= beaconRssiMaxLen) {
                mSignalInfo.ext.insert(mSignalInfo.ext.end(), beaconRssiVec.begin(), beaconRssiVec.end());
            }
        }
        if (stats[NL80211_STA_INFO_TX_PPDU_CNT] != NULL) {
            uint32_t txPpduCnt = nla_get_u32(stats[NL80211_STA_INFO_TX_PPDU_CNT]);
            mSignalInfo.ext.push_back(static_cast<uint8_t>(txPpduCnt & MASK_CSMA));
            mSignalInfo.ext.push_back(static_cast<uint8_t>((txPpduCnt >> OFFSET_8) & MASK_CSMA));
            mSignalInfo.ext.push_back(static_cast<uint8_t>((txPpduCnt >> OFFSET_16) & MASK_CSMA));
            mSignalInfo.ext.push_back(static_cast<uint8_t>((txPpduCnt >> OFFSET_24) & MASK_CSMA));
        }
        if (stats[NL80211_STA_INFO_TX_PPDU_RETRY_CNT] != NULL) {
            uint32_t txPpduRetryCnt = nla_get_u32(stats[NL80211_STA_INFO_TX_PPDU_RETRY_CNT]);
            mSignalInfo.ext.push_back(static_cast<uint8_t>(txPpduRetryCnt & MASK_CSMA));
            mSignalInfo.ext.push_back(static_cast<uint8_t>((txPpduRetryCnt >> OFFSET_8) & MASK_CSMA));
            mSignalInfo.ext.push_back(static_cast<uint8_t>((txPpduRetryCnt >> OFFSET_16) & MASK_CSMA));
            mSignalInfo.ext.push_back(static_cast<uint8_t>((txPpduRetryCnt >> OFFSET_24) & MASK_CSMA));
        }
        if (stats[NL80211_STA_INFO_PPDU_PER] != NULL) {
            uint8_t ppduPer = nla_get_u8(stats[NL80211_STA_INFO_PPDU_PER]);
            mSignalInfo.ext.push_back(ppduPer);
        }
        if (stats[NL80211_STA_INFO_TX_MCS] != NULL) {
            uint8_t txMcs = nla_get_u8(stats[NL80211_STA_INFO_TX_MCS]);
            mSignalInfo.ext.push_back(txMcs);
        }
        FillSignalAiWifiEx(stats, size);
    }
    void FillSignalAiWifiEx(struct nlattr **stats, uint32_t size)
    {
        if (size < NL80211_STA_INFO_MAX + 1) {
            HDF_LOGE("size of stats is not enough");
            return;
        }
        if (stats[NL80211_STA_INFO_CWMIN] != NULL) {
            uint8_t cwMin = nla_get_u8(stats[NL80211_STA_INFO_CWMIN]);
            mSignalInfo.ext.push_back(cwMin);
        }
        if (stats[NL80211_STA_INFO_CWMAX] != NULL) {
            uint8_t cwMax = nla_get_u8(stats[NL80211_STA_INFO_CWMAX]);
            mSignalInfo.ext.push_back(cwMax);
        }
        if (stats[NL80211_STA_INFO_ULDELAY_CDF] != NULL) {
            uint8_t *uldelayCdf = (uint8_t *)nla_data(stats[NL80211_STA_INFO_ULDELAY_CDF]);
            int uldelayCdfLen = (int32_t)(nla_len(stats[NL80211_STA_INFO_ULDELAY_CDF]));
            for (int i = 0; i < uldelayCdfLen; ++i) {
                mSignalInfo.ext.push_back(static_cast<uint8_t>(uldelayCdf[i]));
            }
        }
        if (stats[NL80211_STA_INFO_TX_TIME_CDF] != NULL) {
            uint8_t *txtimeCdf = (uint8_t *)nla_data(stats[NL80211_STA_INFO_TX_TIME_CDF]);
            int txtimeCdfLen = (int32_t)(nla_len(stats[NL80211_STA_INFO_TX_TIME_CDF]));
            for (int i = 0; i < txtimeCdfLen; ++i) {
                mSignalInfo.ext.push_back(static_cast<uint8_t>(txtimeCdf[i]));
            }
        }
    }

    void FillSignalRate(struct nlattr **stats, uint32_t size)
    {
        struct nlattr *rate[NL80211_RATE_INFO_MAX + 1];
        struct nla_policy ratePolicy[NL80211_RATE_INFO_MAX + 1];
        ratePolicy[NL80211_RATE_INFO_BITRATE].type = NLA_U16;
        ratePolicy[NL80211_RATE_INFO_BITRATE32].type = NLA_U32;

        if (size < NL80211_STA_INFO_MAX + 1) {
            HDF_LOGE("FillSignalRate: size of stats is not enough");
            return;
        }
        if (stats[NL80211_STA_INFO_RX_BITRATE] != NULL &&
            nla_parse_nested(rate, NL80211_RATE_INFO_MAX, stats[NL80211_STA_INFO_RX_BITRATE], ratePolicy) == 0) {
            if (rate[NL80211_RATE_INFO_BITRATE32] != nullptr) {
                mSignalInfo.rxBitrate = (int32_t)nla_get_u32(rate[NL80211_RATE_INFO_BITRATE32]);
            } else if (rate[NL80211_RATE_INFO_BITRATE] != nullptr) {
                mSignalInfo.rxBitrate = nla_get_u16(rate[NL80211_RATE_INFO_BITRATE]);
            }
        }
        if (stats[NL80211_STA_INFO_TX_BITRATE] != NULL &&
            nla_parse_nested(rate, NL80211_RATE_INFO_MAX, stats[NL80211_STA_INFO_TX_BITRATE], ratePolicy) == 0) {
            if (rate[NL80211_RATE_INFO_BITRATE32] != nullptr) {
                mSignalInfo.txBitrate = (int32_t)nla_get_u32(rate[NL80211_RATE_INFO_BITRATE32]);
            } else if (rate[NL80211_RATE_INFO_BITRATE] != nullptr) {
                mSignalInfo.txBitrate = nla_get_u16(rate[NL80211_RATE_INFO_BITRATE]);
            }
        }
    }
};


static WifiError WifiGetSignalInfo(wifiInterfaceHandle handle,
    OHOS::HDI::Wlan::Chip::V2_0::SignalPollResult& signalPollresult)
{
    AssociatedInfo associatedInfo;

    if (!handle) {
        HDF_LOGE("Handle is null");
        return HAL_INVALID_ARGS;
    }
    (void)memset_s(&associatedInfo, sizeof(associatedInfo), 0, sizeof(associatedInfo));
    if (WifiGetAssociateInfo(handle, &associatedInfo) < 0) {
        return HAL_NONE;
    }
    GetSignalInfoCommand command(handle, associatedInfo);
    auto lock = ReadLockData();
    command.RequestResponse();
    signalPollresult = command.GetScanResultsInfo();
    return HAL_SUCCESS;
}

static WifiError RegisterIfaceCallBack(const char *ifaceName, WifiCallbackHandler OnCallbackEvent)
{
    std::unique_lock<std::mutex> lock(g_callbackMutex);
    if (ifaceName == nullptr) {
        HDF_LOGE(" ifaceName is null!");
        return HAL_NONE;
    }

    g_halInfo->ifaceCallBack = OnCallbackEvent;

    return HAL_SUCCESS;
}

WifiError IsSupportCoex(bool& isCoex)
{
    isCoex = false;
    return HAL_SUCCESS;
}

static WifiError SendCmdToDriver(const char *ifaceName, int32_t commandId,
    const std::vector<int8_t>& paramData, std::vector<int8_t>& result)
{
    return HAL_SUCCESS;
}
