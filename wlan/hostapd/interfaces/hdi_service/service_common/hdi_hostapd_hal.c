/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "hdi_hostapd_hal.h"

#include <errno.h>
#include <hdf_base.h>
#include <hdf_log.h>
#include <linux/wireless.h>
#include <malloc.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "common/wpa_ctrl.h"
#include "securec.h"

#ifdef OHOS_EUPDATER
#define CONFIG_ROOR_DIR "/tmp/service/el1/public/wifi"
#else
#define CONFIG_ROOR_DIR "/data/service/el1/public/wifi"
#endif // OHOS_EUPDATER

#define CONFIG_DENY_MAC_FILE_NAME "deny_mac.conf"
#define SLEEP_TIME_100_MS (100 * 1000)
#define CONFIG_PATH_DIR CONFIG_ROOR_DIR"/wpa_supplicant"
#define CTRL_LEN 128
#define IFACENAME_LEN 6
#define CFGNAME_LEN 30
#define MAX_RETRY_COUNT 20

#if (AP_NUM > 1)
#define WIFI_5G_CFG "hostapd_0.conf"
#define WIFI_2G_CFG "hostapd_1.conf"
#define HOSTAPD_5G_CFG CONFIG_ROOR_DIR"/wpa_supplicant/"WIFI_5G_CFG
#define HOSTAPD_2G_CFG CONFIG_ROOR_DIR"/wpa_supplicant/"WIFI_2G_CFG
#define HOSTAPD_5G_UDPPORT ""
#define HOSTAPD_2G_UDPPORT ""

WifiHostapdHalDeviceInfo g_hostapdHalDevInfo[] = {
    {AP_5G_MAIN_INSTANCE, NULL, WIFI_5G_CFG, HOSTAPD_5G_CFG, HOSTAPD_5G_UDPPORT},
    {AP_2G_MAIN_INSTANCE, NULL, WIFI_2G_CFG, HOSTAPD_2G_CFG, HOSTAPD_2G_UDPPORT},
};
#else
#define AP_IFNAME "wlan0"
#define AP_IFNAME_COEX "wlan1"
#define HOSTAPD_DEFAULT_CFG "hostapd.conf"
#define HOSTAPD_CTRL_GLOBAL_INTERFACE CONFIG_ROOR_DIR"/sockets/wpa/hostapd"
#define HOSTAPD_DEFAULT_CFG_PATH CONFIG_ROOR_DIR"/wpa_supplicant/"HOSTAPD_DEFAULT_CFG
#define HOSTAPD_DEFAULT_UDPPORT ""
#define AP_SET_CFG_DELAY 500000
#define SOFTAP_MAX_BUFFER_SIZE 4096
#define IFNAMSIZ 16
#define ADDITIONAL_SPACE_FOR_FORMATTING 3

WifiHostapdHalDeviceInfo g_hostapdHalDevInfo[] = {
    {AP_2G_MAIN_INSTANCE, NULL, HOSTAPD_DEFAULT_CFG, HOSTAPD_DEFAULT_CFG_PATH, HOSTAPD_DEFAULT_UDPPORT}
};
static char g_ctrlInterfacel[CTRL_LEN];
static char g_hostapdCfg[CTRL_LEN];
static char g_apIfaceName[IFACENAME_LEN];
static char g_apCfgName[CFGNAME_LEN];
static char g_hostapdPasswd[CTRL_LEN];
#endif

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

int InitCfg(const char *ifaceName)
{
    if (memcpy_s(g_apCfgName, CFGNAME_LEN, HOSTAPD_DEFAULT_CFG, sizeof(HOSTAPD_DEFAULT_CFG)) != EOK) {
        HDF_LOGE("memcpy cfg fail");
        return -1;
    }
    if (memcpy_s(g_apIfaceName, IFACENAME_LEN, ifaceName, strlen(ifaceName)) != EOK) {
        HDF_LOGE("memcpy ap name fail");
        return -1;
    }
    if (memcpy_s(g_hostapdCfg, CTRL_LEN, HOSTAPD_DEFAULT_CFG_PATH,
        sizeof(HOSTAPD_DEFAULT_CFG_PATH)) != EOK) {
        HDF_LOGE("memcpy hostapd fail");
        return -1;
    }
    if (memcpy_s(g_ctrlInterfacel, CTRL_LEN, HOSTAPD_CTRL_GLOBAL_INTERFACE,
        sizeof(HOSTAPD_CTRL_GLOBAL_INTERFACE)) != EOK) {
        HDF_LOGE("memcpy ctrl fail");
        return -1;
    }
    g_hostapdHalDevInfo[0].cfgName = g_apCfgName;
    g_hostapdHalDevInfo[0].config = g_hostapdCfg;
    return 0;
}

const WifiHostapdHalDeviceInfo *GetWifiCfg(int *len)
{
    *len = sizeof(g_hostapdHalDevInfo) / sizeof(WifiHostapdHalDeviceInfo);
    return g_hostapdHalDevInfo;
}

static void ReleaseHostapdCtrl(int id)
{
    if (g_hostapdHalDevInfo[id].hostapdHalDev == NULL) {
        return;
    }
    if (g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn != NULL) {
        wpa_ctrl_close(g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn);
        g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn = NULL;
    }
    if (g_hostapdHalDevInfo[id].hostapdHalDev->ctrlRecv != NULL) {
        wpa_ctrl_close(g_hostapdHalDevInfo[id].hostapdHalDev->ctrlRecv);
        g_hostapdHalDevInfo[id].hostapdHalDev->ctrlRecv = NULL;
    }
}

static int InitHostapdCtrl(const char *ctrlPath, int id)
{
    if (g_hostapdHalDevInfo[id].hostapdHalDev == NULL || ctrlPath == NULL) {
        HDF_LOGE("InitHostapdCtrl id %{public}d hostapdHalDev or ifname is null", id);
        return -1;
    }
    int flag = 0;
    do {
        g_hostapdHalDevInfo[id].hostapdHalDev->ctrlRecv = wpa_ctrl_open(ctrlPath);
        if (g_hostapdHalDevInfo[id].hostapdHalDev->ctrlRecv == NULL) {
            HDF_LOGE("open hostapd control interface ctrlRecv failed");
            break;
        }
        if (wpa_ctrl_attach(g_hostapdHalDevInfo[id].hostapdHalDev->ctrlRecv) != 0) {
            HDF_LOGE("attach hostapd monitor interface failed");
            break;
        }
        g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn = wpa_ctrl_open(ctrlPath);
        if (g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn == NULL) {
            HDF_LOGE("open hostapd control interface ctrlConn failed");
            break;
        }
        flag += 1;
    } while (0);
    if (!flag) {
        ReleaseHostapdCtrl(id);
        return -1;
    }
    return 0;
}

void GetDestPort(char *destPort, size_t len, int id)
{
    if (strcpy_s(destPort, len, g_hostapdHalDevInfo[id].udpPort) != EOK) {
        HDF_LOGE("failed to copy the destPort");
    }
}

static void GetCtrlInterface(char *ctrlPath, size_t len, int id)
{
    if (strcpy_s(ctrlPath, len, g_ctrlInterfacel) != EOK) {
        HDF_LOGE("failed to copy the ctrl_path");
    }
}

static int HostapdCliConnect(int id)
{
    if (g_hostapdHalDevInfo[id].hostapdHalDev == NULL) {
        HDF_LOGE("hostapdHalDev is NULL");
        return -1;
    }
    if (g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn != NULL) {
        HDF_LOGI("Hostapd already initialized");
        return 0;
    }
    int retryCount = MAX_RETRY_COUNT;
    char ctrlPath[BUFFER_SIZE_128] = {0};
    GetCtrlInterface(ctrlPath, sizeof(ctrlPath), id);
    HDF_LOGI("HostapdCliConnect Ifname is: %{public}s", ctrlPath);
    while (retryCount-- > 0) {
        if (InitHostapdCtrl(ctrlPath, id) == 0) {
            HDF_LOGI("Global hostapd interface connect successfully");
            break;
        } else {
            HDF_LOGD("Init hostapd ctrl failed");
        }
        usleep(SLEEP_TIME_100_MS);
    }
    if (retryCount <= 0) {
        HDF_LOGI("Retry init hostapd ctrl failed, retryCount: %{public}d", retryCount);
        return -1;
    }
    return 0;
}

static int HostapdCliClose(int id)
{
    if (g_hostapdHalDevInfo[id].hostapdHalDev == NULL) {
        return 0;
    }
    if (g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn != NULL) {
        wpa_ctrl_close(g_hostapdHalDevInfo[id].hostapdHalDev->ctrlRecv);
        g_hostapdHalDevInfo[id].hostapdHalDev->ctrlRecv = NULL;
        wpa_ctrl_close(g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn);
        g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn = NULL;
    }
    return 0;
}

static int WpaCtrlCommand(struct wpa_ctrl *ctrl, const char *cmd, char *buf, size_t bufSize)
{
    HDF_LOGI("enter WpaCtrlCommand");
    if (ctrl == NULL || cmd == NULL || buf == NULL || bufSize <= 0) {
        HDF_LOGE("Request parameters not correct");
        return -1;
    }
    size_t len = bufSize - 1;
    HDF_LOGD("wpa_ctrl_request -> cmd: %{private}s", cmd);
    int ret = wpa_ctrl_request(ctrl, cmd, strlen(cmd), buf, &len, NULL);
    if (ret == REQUEST_FAILED) {
        HDF_LOGE("[%{private}s] command timed out", cmd);
        return ret;
    } else if (ret < 0) {
        HDF_LOGE("[%{private}s] command failed", cmd);
        return -1;
    }
    if (len < bufSize) {
        buf[len] = '\0';
    } else {
        HDF_LOGE("len is invalid,current len is %{public}zu, bufSize is %{public}zu", len, bufSize);
        return -1;
    }
    if (memcmp(buf, "FAIL", FAIL_LENGTH) == 0) {
        HDF_LOGE("[%{private}s] request success, but result %{public}s", cmd, buf);
        return -1;
    }
    return 0;
}

void ReleaseHostapdDev(int id)
{
    if (g_hostapdHalDevInfo[id].hostapdHalDev != NULL) {
        HostapdCliClose(id);
        free(g_hostapdHalDevInfo[id].hostapdHalDev);
        g_hostapdHalDevInfo[id].hostapdHalDev = NULL;
    }
}

int GetIfaceState(const char *ifaceName)
{
    int state = 0;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        HDF_LOGE("GetIfaceState: create socket fail");
        return state;
    }

    struct ifreq ifr = {};
    (void)memset_s(&ifr, sizeof(ifr), 0, sizeof(ifr));
    if (strcpy_s(ifr.ifr_name, IFNAMSIZ, ifaceName) != EOK) {
        HDF_LOGE("GetIfaceState: strcpy_s fail");
        close(sock);
        return state;
    }
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        HDF_LOGE("GetIfaceState: can not get interface state: %{public}s", ifaceName);
        close(sock);
        return state;
    }
    state = ((ifr.ifr_flags & IFF_UP) > 0 ? 1 : 0);
    HDF_LOGD("GetIfaceState: current interface state: %{public}d", state);
    close(sock);
    return state;
}

static int InitHostapdHal(int id)
{
    if (g_hostapdHalDevInfo[id].hostapdHalDev == NULL) {
        HDF_LOGE("InitHostapdHal id %d hostapdHalDev is null", id);
        return -1;
    }
    if (HostapdCliConnect(id) != 0) {
        HDF_LOGE("InitHostapdHal id %d HostapdCliConnect fail", id);
        return -1;
    }
    return 0;
}

static int EnableAp(int id)
{
    char cmdAdd[BUFSIZE_CMD] = {0};
    char cmdEnable[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};
    if (sprintf_s(cmdAdd, sizeof(cmdAdd), "ADD %s config=%s wpa_passphrase=%s pass_length=%d",
        g_apIfaceName, g_hostapdCfg, g_hostapdPasswd, strlen(g_hostapdPasswd)) < 0) {
        HDF_LOGE("add config sprintf_s fail");
        return -1;
    }
    HDF_LOGD("cmdAdd is %{public}s", cmdAdd);
    if (WpaCtrlCommand(g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn, cmdAdd, buf, sizeof(buf)) < 0) {
        HDF_LOGE("add ap failed");
        return -1;
    }
    if (sprintf_s(cmdEnable, sizeof(cmdEnable), "IFNAME=%s ENABLE", g_apIfaceName) < 0) {
        HDF_LOGE("enableAp sprintf_s fail");
        return -1;
    }
    HDF_LOGD("enable ap cmd is %{public}s", cmdEnable);
    return WpaCtrlCommand(g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn, cmdEnable, buf, sizeof(buf));
}

static int DisableAp(int id)
{
    char cmd[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};
    if (sprintf_s(cmd, sizeof(cmd), "REMOVE %s", g_apIfaceName) < 0) {
        HDF_LOGE("remove ap sprintf_s fail");
        return -1;
    }
    HDF_LOGD("remove ap cmd is %{public}s", cmd);
    g_hostapdHalDevInfo[id].hostapdHalDev->execDisable = 1;
    return WpaCtrlCommand(g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf));
}

static int StopAp(int id)
{
    char buf[BUFSIZE_REQUEST_SMALL] = {0};
    return WpaCtrlCommand(g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn, "TERMINATE", buf, sizeof(buf));
}

static int SetApName(const char *name, int id)
{
    if (name == NULL) {
        HDF_LOGE("SetApName name is null");
        return -1;
    }
    char cmd[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};

    if (sprintf_s(cmd, sizeof(cmd), "SET ssid %s", name) < 0) {
        HDF_LOGE("SetApName sprintf_s fail");
        return -1;
    }
    return WpaCtrlCommand(g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf));
}

static int SetApRsnPairwise(const char *type, int id)
{
    if (type == NULL) {
        HDF_LOGE("SetApRsnPairwise type is null");
        return -1;
    }

    char cmd[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};

    if (sprintf_s(cmd, sizeof(cmd), "SET rsn_pairwise %s", type) < 0) {
        HDF_LOGE("SetApRsnPairwise sprintf_s fail");
        return -1;
    }
    return WpaCtrlCommand(g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf));
}

static int SetApWpaPairwise(const char *type, int id)
{
    if (type == NULL) {
        HDF_LOGE("SetApWpaPairwise type is null");
        return -1;
    }
    char cmd[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};

    if (sprintf_s(cmd, sizeof(cmd), "SET wpa_pairwise %s", type) < 0) {
        HDF_LOGE("SetApWpaPairwise sprintf_s fail");
        return -1;
    }
    return WpaCtrlCommand(g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf));
}

static int SetApWpaKeyMgmt(const char *type, int id)
{
    if (type == NULL) {
        HDF_LOGE("SetApWpaPairwise type is null");
        return -1;
    }
    char cmd[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};

    if (sprintf_s(cmd, sizeof(cmd), "SET wpa_key_mgmt %s", type) < 0) {
        HDF_LOGE("SetApWpaKeyMgmt sprintf_s fail");
        return -1;
    }
    return WpaCtrlCommand(g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf));
}

static int SetApWpaValue(int securityType, int id)
{
    int retval = -1;
    char cmd[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};

    switch (securityType) {
        case NONE: /* The authentication mode is NONE. */
            retval = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "SET wpa 0");
            break;
        case WPA_PSK: /* The authentication mode is WPA-PSK. */
            retval = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "SET wpa 1");
            break;
        case WPA2_PSK: /* The authentication mode is WPA2-PSK. */
            retval = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "SET wpa 2");
            break;
        default:
            HDF_LOGE("Unknown encryption type");
            return retval;
    }
    if (retval < 0) {
        HDF_LOGE("%{public}s snprintf_s failed, cmd is: %{public}s, type is: %{public}d", __func__, cmd, securityType);
        return -1;
    }

    retval = WpaCtrlCommand(g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf));
    if (retval == 0 && securityType != NONE) {
        /*
         * If the value of wpa is switched between 0, 1, and 2, the wpa_key_mgmt,
         * wpa_pairwise, and rsn_pairwise attributes must be set. Otherwise, the
         * enable or STA cannot be connected.
         */
        retval = SetApWpaKeyMgmt("WPA-PSK", id);
    }
    if (retval == 0 && securityType == WPA_PSK) {
        retval = SetApWpaPairwise("CCMP", id);
    }
    if (retval == 0 && securityType == WPA2_PSK) {
        retval = SetApRsnPairwise("CCMP", id);
    }
    if (retval != 0) {
        HDF_LOGE("%{public}s: hostapd failed to set securityType", __func__);
        return -1;
    }
    return retval;
}

static int SetApPasswd(const char *pass, int id)
{
    if (pass == NULL) {
        HDF_LOGE("SetApPasswd pass is null");
        return -1;
    }
    if (memset_s(g_hostapdPasswd, CTRL_LEN, 0, strlen(g_hostapdPasswd)) != 0) {
        HDF_LOGE("SetApPasswd memset_s is null");
        return -1;
    }
    if (memcpy_s(g_hostapdPasswd, CTRL_LEN, pass, strlen(pass)) != 0) {
        HDF_LOGE("SetApPasswd memcpy_s fail");
        return -1;
    }
    return 0;
}

static int SetApChannel(int channel, int id)
{
    char cmd[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};

    if (sprintf_s(cmd, sizeof(cmd), "SET channel %d", channel) < 0) {
        HDF_LOGE("SetApChannel sprintf_s fail");
        return -1;
    }
    return WpaCtrlCommand(g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf));
}

static int SetApWmm(int value, int id)
{
    char cmd[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};

    if (sprintf_s(cmd, sizeof(cmd), "SET wmm_enabled %d", value) < 0) {
        HDF_LOGE("SetApWmm sprintf_s fail");
        return -1;
    }
    return WpaCtrlCommand(g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf));
}

static int SetAp80211n(int value, int id)
{
    char cmd[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};

    if (sprintf_s(cmd, sizeof(cmd), "SET ieee80211n %d", value) < 0) {
        HDF_LOGE("SetAp80211n sprintf_s fail");
        return -1;
    }
    return WpaCtrlCommand(g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf));
}

static int SetApBand(int band, int id)
{
    char cmd[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};
    const char *hwMode = NULL;

    switch (band) {
        case AP_NONE_BAND:
            hwMode = "any"; /* Unknown frequency band */
            break;
        case AP_2GHZ_BAND:
            hwMode = "g";   /* BAND_2_4_GHZ */
            break;
        case AP_5GHZ_BAND:
            hwMode = "a";   /* BAND_5_GHZ */
            break;
        default:
            HDF_LOGE("Invalid band");
            return -1;
    }

    if (sprintf_s(cmd, sizeof(cmd), "SET hw_mode %s", hwMode) < 0) {
        HDF_LOGE("SetApBand sprintf_s fail");
        return -1;
    }
    return WpaCtrlCommand(g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf));
}

static int SendPrivateCmd(struct iwreq *wrq, struct iw_priv_args *privPtr, const char *fName,
    int bufLen, int sock, char dataBuf[])
{
    int ret;
    int cmd = 0;
    int subCmd = 0;

    if (wrq == NULL || privPtr == NULL || fName == NULL) {
        HDF_LOGE("SendPrivateCmd input parameter invalid");
        return -1;
    }
    /* Find the matching command from the privPtr array */
    int i;
    for (i = 0; i < wrq->u.data.length; i++) {
        if (strncmp(privPtr[i].name, fName, strlen(fName)) == 0) {
            cmd = (int)privPtr[i].cmd;
            break;
        }
    }
    /* No matching command found */
    if (i == wrq->u.data.length) {
        HDF_LOGE("fName: %{public}s - function not supported", fName);
        return -1;
    }
    /* Process sub-command for a private command */
    if (cmd < SIOCDEVPRIVATE) {
        int j;
        for (j = 0; j < i; j++) {
            if ((privPtr[j].set_args == privPtr[i].set_args) &&
                (privPtr[j].get_args == privPtr[i].get_args) &&
                (privPtr[j].name[0] == '\0')) {
                break;
            }
        }
        /* No valid sub-command found */
        if (j == i) {
            HDF_LOGE("fName: %{public}s - invalid private ioctl", fName);
            return -1;
        }
        /* Set the sub-command and update the main command */
        subCmd = cmd;
        cmd = (int)privPtr[j].cmd;
    }
    wrq->ifr_name[IFNAMSIZ - 1] = '\0';
    /* Set the data length and pointer based on bufLen and dataBuf */
    if ((bufLen == 0) && (*dataBuf != 0)) {
        wrq->u.data.length = strlen(dataBuf) + 1;
    } else {
        wrq->u.data.length = (uint16_t)bufLen;
    }
    wrq->u.data.pointer = dataBuf;
    wrq->u.data.flags = (uint16_t)subCmd;
    /* Perform the ioctl operation */
    ret = ioctl(sock, cmd, wrq);
    HDF_LOGD("the data length is:%hu, ret is %d", wrq->u.data.length, ret);
    return ret;
}

static int SetCommandHwHisi(const char *iface, const char *fName, unsigned int bufLen, char dataBuf[])
{
    char buf[SOFTAP_MAX_BUFFER_SIZE] = { 0 };
    struct iwreq wrq;
    int ret;

    if (iface == NULL || fName == NULL) {
        HDF_LOGE("SetCommandHwHisi: iface or fName is null.");
        return -1;
    }

    ret = strncpy_s(wrq.ifr_name, sizeof(wrq.ifr_name), g_apIfaceName, strlen(g_apIfaceName));
    if (ret != EOK) {
        HDF_LOGE("%{public}s strncpy_s wrq fail", __func__);
        return -1;
    }
    wrq.ifr_name[IFNAMSIZ - 1] = '\0';
    wrq.u.data.pointer = buf;
    wrq.u.data.length = sizeof(buf) / sizeof(struct iw_priv_args);
    wrq.u.data.flags = 0;
    HDF_LOGD("the interface name is: %{public}s", wrq.ifr_name);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        HDF_LOGE("Softap SetCommandHw - failed to open socket");
        return -1;
    }
    ret = ioctl(sock, SIOCGIWPRIV, &wrq);
    if (ret < 0) {
        HDF_LOGE("SIOCGIPRIV failed: %{public}d", ret);
        close(sock);
        return ret;
    }
    struct iw_priv_args *privPtr = (struct iw_priv_args *)wrq.u.data.pointer;
    ret = strncpy_s(wrq.ifr_name, sizeof(wrq.ifr_name), g_apIfaceName, strlen(g_apIfaceName));
    if (ret != EOK) {
        HDF_LOGE("%{public}s strncpy_s wrq fail", __func__);
        close(sock);
        return -1;
    }
    ret = SendPrivateCmd(&wrq, privPtr, fName, bufLen, sock, dataBuf);
    close(sock);
    return ret;
}

static int AddParam(unsigned int position, const char *cmd, const char *arg, char outDataBuf[], unsigned int outSize)
{
    if (cmd == NULL || arg == NULL) {
        HDF_LOGE("%{public}s cmd == NULL or arg == NULL", __func__);
        return -1;
    }
    /* ADDITIONAL_SPACE_FOR_FORMATTING 3: for "=" "," and terminator */
    if ((unsigned int)(position + strlen(cmd) + strlen(arg) + ADDITIONAL_SPACE_FOR_FORMATTING) >= outSize) {
        HDF_LOGE("%{public}s Command line is too big", __func__);
        return -1;
    }

    int ret = sprintf_s(&outDataBuf[position], outSize - position, "%s=%s,", cmd, arg);
    if (ret == -1) {
        HDF_LOGE("%{public}s sprintf_s cmd fail", __func__);
        return -1;
    }
    position += ret;
    return position;
}

static int SetApMaxConnHw(int maxConn, int channel)
{
    char dataBuf[SOFTAP_MAX_BUFFER_SIZE] = { 0 };
    if (memset_s(dataBuf, SOFTAP_MAX_BUFFER_SIZE, 0, SOFTAP_MAX_BUFFER_SIZE) != EOK) {
        HDF_LOGE("SetApMaxConnHw  memset_s fail");
        return -1;
    }
    int index = 0;
    if ((index = AddParam(index, "ASCII_CMD", "AP_CFG", dataBuf, SOFTAP_MAX_BUFFER_SIZE)) == -1) {
        HDF_LOGE("AddParam ASCII_CMD fail");
        return -1;
    }
    char chann[10] = {0};
    if (sprintf_s(chann, sizeof(chann), "%d", channel) == -1) {
        HDF_LOGE("AddParam CHANNEL sprintf_s failed");
        return -1;
    }
    if ((index = AddParam(index, "CHANNEL", chann, dataBuf, SOFTAP_MAX_BUFFER_SIZE)) == -1) {
        HDF_LOGE("AddParam CHANNEL fail");
        return -1;
    }
    char maxStaNum[10] = {0};
    if (sprintf_s(maxStaNum, sizeof(maxStaNum), "%d", maxConn) == -1) {
        HDF_LOGE("AddParam maxStaNum sprintf_s failed");
        return -1;
    }
    if ((index = AddParam(index, "MAX_SCB", maxStaNum, dataBuf, SOFTAP_MAX_BUFFER_SIZE)) == -1) {
        HDF_LOGE("AddParam MAX_SCB fail");
        return -1;
    }
    if ((unsigned int)(index + 4) >= sizeof(dataBuf)) { // 4 : for "END" and terminator
        HDF_LOGE("Command line is too big");
        return -1;
    }
    int ret = sprintf_s(&dataBuf[index], sizeof(dataBuf) - index, "END");
    if (ret == -1) {
        HDF_LOGE("sprintf_s fail.");
        return -1;
    }
    HDF_LOGD("the command is :%{public}s", dataBuf);

    ret = SetCommandHwHisi(AP_IFNAME, "AP_SET_CFG", SOFTAP_MAX_BUFFER_SIZE, dataBuf);
    if (ret) {
        HDF_LOGE("SetSoftapHw - failed: %{public}d", ret);
    } else {
        HDF_LOGI("SetSoftapHw - Ok");
        usleep(AP_SET_CFG_DELAY);
    }
    return 0;
}

static int SetApMaxConn(int maxConn, int id)
{
    char cmd[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};

    if (sprintf_s(cmd, sizeof(cmd), "SET max_num_sta %d", maxConn) < 0) {
        HDF_LOGE("SetApMaxConn sprintf_s fail");
        return -1;
    }
    return WpaCtrlCommand(g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf));
}

static int ModBlockList(const char *mac, int id)
{
    if (mac == NULL) {
        HDF_LOGD("ModBlockList mac is null");
        return -1;
    }
    char buf[BUFSIZE_REQUEST_SMALL] = {0};
    char cmd[BUFSIZE_CMD] = {0};
    char file[FILE_NAME_SIZE] = {0};
    if (snprintf_s(file, sizeof(file), sizeof(file) - 1, "%s/%s", CONFIG_PATH_DIR, CONFIG_DENY_MAC_FILE_NAME) < 0) {
        HDF_LOGE("ModBlockList sprintf_s file fail");
        return -1;
    }
    FILE *fp = fopen(file, "w");
    if (fp == NULL) {
        HDF_LOGE("ModBlockList fopen fail");
        return -1;
    }
    if (fprintf(fp, "%s\n", mac) < 0) {
        fclose(fp);
        HDF_LOGE("ModBlockList fprintf fail");
        return -1;
    }
    if (fclose(fp) != 0) {
        HDF_LOGE("ModBlockList fclose error");
        return -1;
    }
    if (sprintf_s(cmd, sizeof(cmd), "IFNAME=%s SET deny_mac_file %s/%s", g_apIfaceName,
        CONFIG_PATH_DIR, CONFIG_DENY_MAC_FILE_NAME) < 0) {
        HDF_LOGE("ModBlockList sprintf_s cmd fail");
        return -1;
    }
    return WpaCtrlCommand(g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf));
}

static int AddBlocklist(const char *mac, int id)
{
    if (mac == NULL) {
        HDF_LOGE("AddBlocklist mac is null");
        return -1;
    }
    char cmd[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};

    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s DENY_ACL ADD_MAC %s", g_apIfaceName, mac) < 0) {
        HDF_LOGE("AddBlocklist sprintf_s cmd fail");
        return -1;
    }
    if (WpaCtrlCommand(g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf)) != 0) {
        HDF_LOGE("AddBlocklist WpaCtrlCommand Failed");
        return -1;
    }
    if (strncasecmp(buf, "UNKNOWN COMMAND", UNKNOWN_COMMAND_LENGTH) == 0) {
        HDF_LOGE("AddBlocklist DENY_ACL command return %{public}s, use SET command", buf);
        /**
         * The hostapd of an earlier version does not support the DENY_ACL command and uses the configuration file.
         */
        return ModBlockList(mac, id);
    }
    return 0;
}

static int DelBlocklist(const char *mac, int id)
{
    if (mac == NULL) {
        HDF_LOGE("DelBlocklist mac is null");
        return -1;
    }
    char cmd[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};

    if (sprintf_s(cmd, sizeof(cmd), "IFNAME=%s DENY_ACL DEL_MAC %s", g_apIfaceName, mac) < 0) {
        HDF_LOGE("DelBlocklist sprintf_s DENY_ACL cmd fail");
        return -1;
    }
    if (WpaCtrlCommand(g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf)) != 0) {
        HDF_LOGE("DelBlocklist WpaCtrlCommand Failed");
        return -1;
    }
    if (strncasecmp(buf, "UNKNOWN COMMAND", UNKNOWN_COMMAND_LENGTH) == 0) {
        HDF_LOGD("DelBlocklist DENY_ACL command return %{public}s, use SET command", buf);
        if (sprintf_s(cmd, sizeof(cmd), "-%s", mac) < 0) {
            HDF_LOGE("DelBlocklist sprintf_s set cmd fail");
            return -1;
        }
        return ModBlockList(cmd, id);
    }
    return 0;
}

static int GetApStatus(StatusInfo *info, int id)
{
    if (info == NULL) {
        HDF_LOGD("GetApStatus info is null");
        return -1;
    }
    char *buf = (char *)calloc(BUFSIZE_RECV, sizeof(char));
    if (buf == NULL) {
        HDF_LOGE("GetApStatus buf calloc fail");
        return -1;
    }

    if (WpaCtrlCommand(g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn, "STATUS", buf, BUFSIZE_RECV) != 0) {
        HDF_LOGE("Status WpaCtrlCommand failed");
        free(buf);
        buf = NULL;
        return -1;
    }

    char *p = strstr(buf, "state=");
    if (p == NULL) {
        HDF_LOGD("Status not find state result!");
        free(buf);
        buf = NULL;
        return 0;
    }
    p += strlen("state=");  // skip state=
    unsigned pos = 0;
    while (pos < sizeof(info->state) - 1 && *p != '\0' && *p != '\n') {
        info->state[pos++] = *p;
        ++p;
    }
    info->state[pos] = 0;
    free(buf);
    buf = NULL;
    return 0;
}

static int ShowConnectedDevList(char *buf, int size, int id)
{
    if (buf == NULL) {
        HDF_LOGE("ShowConnectedDevList buf is null");
        return -1;
    }
    char cmd[BUFSIZE_CMD] = {0};
    char *reqBuf = (char *)calloc(BUFSIZE_REQUEST, sizeof(char));
    if (reqBuf == NULL) {
        HDF_LOGD("ShowConnectedDevList reqBuf calloc fail");
        return -1;
    }
    if (WpaCtrlCommand(g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn, "STA-FIRST",
        reqBuf, BUFSIZE_REQUEST) != 0) {
        HDF_LOGE("ShowConnectedDevList WpaCtrlCommand Failed");
        free(reqBuf);
        reqBuf = NULL;
        return -1;
    }
    do {
        char *pos = reqBuf;
        while (*pos != '\0' && *pos != '\n') { /* return station info, first line is mac address */
            pos++;
        }
        *pos = '\0';
        if (strcmp(reqBuf, "") != 0) {
            int bufLen = strlen(buf);
            int staLen = strlen(reqBuf);
            if (bufLen + staLen + 1 >= size) {
                free(reqBuf);
                reqBuf = NULL;
                return 0;
            }
            buf[bufLen++] = ',';
            for (int i = 0; i < staLen; ++i) {
                buf[bufLen + i] = reqBuf[i];
            }
            buf[bufLen + staLen] = '\0';
        }
        if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "STA-NEXT %s", reqBuf) < 0) {
            break;
        }
    } while (WpaCtrlCommand(g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn, cmd, reqBuf, BUFSIZE_REQUEST) == 0);
    free(reqBuf);
    reqBuf = NULL;
    return 0;
}

static int ReloadApConfigInfo(int id)
{
    char buf[BUFSIZE_REQUEST_SMALL] = {0};
    return WpaCtrlCommand(g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn, "RELOAD", buf, sizeof(buf));
}

static int DisConnectedDev(const char *mac, int id)
{
    if (mac == NULL) {
        HDF_LOGE("DisConnectedDev mac is null");
        return -1;
    }
    char cmd[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};

    if (sprintf_s(cmd, sizeof(cmd), "IFNAME=%s DISASSOCIATE %s", g_apIfaceName, mac) < 0) {
        HDF_LOGE("DisConnectedDev sprintf_s fail");
        return -1;
    }
    return WpaCtrlCommand(g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf));
}

static int SetCountryCode(const char *code, int id)
{
    if (code == NULL) {
        HDF_LOGE("SetCountryCode code is null");
        return -1;
    }
    char cmd[BUFSIZE_CMD] = {0};
    char buf[BUFSIZE_REQUEST_SMALL] = {0};

    if (sprintf_s(cmd, sizeof(cmd), "SET country_code %s", code) < 0) {
        HDF_LOGE("SetCountryCode sprintf_s fail");
        return -1;
    }
    return WpaCtrlCommand(g_hostapdHalDevInfo[id].hostapdHalDev->ctrlConn, cmd, buf, sizeof(buf));
}

WifiHostapdHalDevice *GetWifiHostapdDev(int id)
{
    pthread_mutex_lock(&g_mutex);
    HDF_LOGI("enter GetWifiHostapdDev");

    if (id < 0 || id >= AP_MAX_INSTANCE) {
        HDF_LOGE("Invalid id: %{public}d!", id);
        pthread_mutex_unlock(&g_mutex);
        return NULL;
    }

    if (g_hostapdHalDevInfo[id].hostapdHalDev != NULL) {
        pthread_mutex_unlock(&g_mutex);
        return g_hostapdHalDevInfo[id].hostapdHalDev;
    }

    g_hostapdHalDevInfo[id].hostapdHalDev = (WifiHostapdHalDevice *)calloc(1, sizeof(WifiHostapdHalDevice));
    if (g_hostapdHalDevInfo[id].hostapdHalDev == NULL) {
        HDF_LOGE("GetWifiHostapdDev hostapdHalDev calloc fail");
        pthread_mutex_unlock(&g_mutex);
        return NULL;
    }

    /* ************ Register hostapd_cli Interface ************************* */
    g_hostapdHalDevInfo[id].hostapdHalDev->stopAp = StopAp;
    g_hostapdHalDevInfo[id].hostapdHalDev->enableAp = EnableAp;
    g_hostapdHalDevInfo[id].hostapdHalDev->disableAp = DisableAp;
    g_hostapdHalDevInfo[id].hostapdHalDev->setApName = SetApName;
    g_hostapdHalDevInfo[id].hostapdHalDev->setApRsnPairwise = SetApRsnPairwise;
    g_hostapdHalDevInfo[id].hostapdHalDev->setApWpaPairwise = SetApWpaPairwise;
    g_hostapdHalDevInfo[id].hostapdHalDev->setApWpaKeyMgmt = SetApWpaKeyMgmt;
    g_hostapdHalDevInfo[id].hostapdHalDev->setApWpaValue = SetApWpaValue;
    g_hostapdHalDevInfo[id].hostapdHalDev->setApPasswd = SetApPasswd;
    g_hostapdHalDevInfo[id].hostapdHalDev->setApChannel = SetApChannel;
    g_hostapdHalDevInfo[id].hostapdHalDev->setApWmm = SetApWmm;
    g_hostapdHalDevInfo[id].hostapdHalDev->setAp80211n = SetAp80211n;
    g_hostapdHalDevInfo[id].hostapdHalDev->setApBand = SetApBand;
    g_hostapdHalDevInfo[id].hostapdHalDev->setApMaxConnHw = SetApMaxConnHw;
    g_hostapdHalDevInfo[id].hostapdHalDev->setApMaxConn = SetApMaxConn;
    g_hostapdHalDevInfo[id].hostapdHalDev->addBlocklist = AddBlocklist;
    g_hostapdHalDevInfo[id].hostapdHalDev->delBlocklist = DelBlocklist;
    g_hostapdHalDevInfo[id].hostapdHalDev->status = GetApStatus;
    g_hostapdHalDevInfo[id].hostapdHalDev->showConnectedDevList = ShowConnectedDevList;
    g_hostapdHalDevInfo[id].hostapdHalDev->reloadApConfigInfo = ReloadApConfigInfo;
    g_hostapdHalDevInfo[id].hostapdHalDev->disConnectedDev = DisConnectedDev;
    g_hostapdHalDevInfo[id].hostapdHalDev->setCountryCode = SetCountryCode;

    if (InitHostapdHal(id) != 0) {
        HDF_LOGE("InitHostapdHal return failed!!");
        free(g_hostapdHalDevInfo[id].hostapdHalDev);
        g_hostapdHalDevInfo[id].hostapdHalDev = NULL;
        pthread_mutex_unlock(&g_mutex);
        return NULL;
    }
    pthread_mutex_unlock(&g_mutex);
    return g_hostapdHalDevInfo[id].hostapdHalDev;
}
