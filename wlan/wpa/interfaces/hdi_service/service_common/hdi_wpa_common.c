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

#include "hdi_wpa_common.h"
#include <hdf_log.h>
#include <string.h>
#include "common/wpa_ctrl.h"
#include "hdi_wpa_hal.h"
#include "wpa_common_cmd.h"

#undef LOG_TAG
#define LOG_TAG "HdiHalWpaCommon"

#define HEX_TO_DEC_MOVING 4
#define DEC_MAX_SCOPE 10
#define WPA_CMD_RETURN_TIMEOUT (-2)

static pthread_mutex_t g_mutexSta = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_mutexP2p = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_mutexChba = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_mutexCommon = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_mutexWpa = PTHREAD_MUTEX_INITIALIZER;

int Hex2Dec(const char *str)
{
    if (str == NULL || strncasecmp(str, "0x", strlen("0x")) != 0) {
        return 0;
    }
    int result = 0;
    const char *tmp = str + strlen("0x");
    while (*tmp != '\0') {
        result <<= HEX_TO_DEC_MOVING;
        if (*tmp >= '0' && *tmp <= '9') {
            result += *tmp - '0';
        } else if (*tmp >= 'A' && *tmp <= 'F') {
            result += *tmp - 'A' + DEC_MAX_SCOPE;
        } else if (*tmp >= 'a' && *tmp <= 'f') {
            result += *tmp - 'a' + DEC_MAX_SCOPE;
        } else {
            result = 0;
            break;
        }
        ++tmp;
    }
    return result;
}

void TrimQuotationMark(char *str, char c)
{
    if (str == NULL) {
        return;
    }
    int len = strlen(str);
    if (len == 0) {
        return;
    }
    if (str[len - 1] == c) {
        str[len - 1] = '\0';
        --len;
    }
    if (str[0] == c) {
        for (int i = 0; i < len - 1; ++i) {
            str[i] = str[i + 1];
        }
        str[len - 1] = '\0';
    }
    return;
}

void ReleaseWpaCtrl(WpaCtrl *pCtrl)
{
    if (pCtrl == NULL) {
        return;
    }
    if (pCtrl->pSend != NULL) {
        wpa_ctrl_close(pCtrl->pSend);
        pCtrl->pSend = NULL;
    }
    if (pCtrl->pRecv != NULL) {
        wpa_ctrl_close(pCtrl->pRecv);
        pCtrl->pRecv = NULL;
    }
    return;
}

int InitWpaCtrl(WpaCtrl *pCtrl, const char *ifname)
{
    if (pCtrl == NULL || ifname == NULL) {
        return -1;
    }
    int flag = 0;
    do {
        pCtrl->pSend = wpa_ctrl_open(ifname);
        if (pCtrl->pSend == NULL) {
            HDF_LOGE("open wpa control send interface failed!");
            break;
        }
        flag += 1;
    } while (0);
    if (!flag) {
        ReleaseWpaCtrl(pCtrl);
        return -1;
    }
    return 0;
}

static int StaCliCmd(WpaCtrl *ctrl, const char *cmd, char *buf, size_t bufLen)
{
    pthread_mutex_lock(&g_mutexSta);

    HDF_LOGI("enter StaCliCmd");
    if (ctrl == NULL || ctrl->pSend == NULL || cmd == NULL || buf == NULL || bufLen == 0) {
        HDF_LOGE("StaCliCmd, invalid parameters!");
        pthread_mutex_unlock(&g_mutexSta);
        return -1;
    }
    size_t len = bufLen - 1;
    HDF_LOGD("wpa_ctrl_request -> cmd: %{private}s", cmd);
    int ret = wpa_ctrl_request(ctrl->pSend, cmd, strlen(cmd), buf, &len, NULL);
    if (ret == WPA_CMD_RETURN_TIMEOUT) {
        HDF_LOGE("[%{private}s] command timed out.", cmd);
        pthread_mutex_unlock(&g_mutexSta);
        return WPA_CMD_RETURN_TIMEOUT;
    } else if (ret < 0) {
        HDF_LOGE("[%{private}s] command failed.", cmd);
        pthread_mutex_unlock(&g_mutexSta);
        return -1;
    }
    buf[len] = '\0';
    HDF_LOGD("wpa_ctrl_request -> buf: %{private}s", buf);
    if (strncmp(buf, "FAIL\n", strlen("FAIL\n")) == 0 ||
        strncmp(buf, "UNKNOWN COMMAND\n", strlen("UNKNOWN COMMAND\n")) == 0) {
        HDF_LOGE("%{private}s request success, but response %{public}s", cmd, buf);
        pthread_mutex_unlock(&g_mutexSta);
        return -1;
    }
    pthread_mutex_unlock(&g_mutexSta);
    return 0;
}

static int P2pCliCmd(WpaCtrl *ctrl, const char *cmd, char *buf, size_t bufLen)
{
    pthread_mutex_lock(&g_mutexP2p);

    HDF_LOGI("enter P2pCliCmd");
    if (ctrl == NULL || ctrl->pSend == NULL || cmd == NULL || buf == NULL || bufLen == 0) {
        HDF_LOGE("P2pCliCmd, invalid parameters!");
        pthread_mutex_unlock(&g_mutexP2p);
        return -1;
    }
    size_t len = bufLen - 1;
    HDF_LOGD("wpa_ctrl_request -> cmd: %{private}s", cmd);
    int ret = wpa_ctrl_request(ctrl->pSend, cmd, strlen(cmd), buf, &len, NULL);
    if (ret == WPA_CMD_RETURN_TIMEOUT) {
        HDF_LOGE("[%{private}s] command timed out.", cmd);
        pthread_mutex_unlock(&g_mutexP2p);
        return WPA_CMD_RETURN_TIMEOUT;
    } else if (ret < 0) {
        HDF_LOGE("[%{private}s] command failed.", cmd);
        pthread_mutex_unlock(&g_mutexP2p);
        return -1;
    }
    buf[len] = '\0';
    HDF_LOGD("wpa_ctrl_request -> buf: %{private}s", buf);
    if (strncmp(buf, "FAIL\n", strlen("FAIL\n")) == 0 ||
        strncmp(buf, "UNKNOWN COMMAND\n", strlen("UNKNOWN COMMAND\n")) == 0) {
        HDF_LOGE("%{private}s request success, but response %{public}s", cmd, buf);
        pthread_mutex_unlock(&g_mutexP2p);
        return -1;
    }
    pthread_mutex_unlock(&g_mutexP2p);
    return 0;
}

static int ChbaCliCmd(WpaCtrl *ctrl, const char *cmd, char *buf, size_t bufLen)
{
    pthread_mutex_lock(&g_mutexChba);

    HDF_LOGI("enter ChbaCliCmd");
    if (ctrl == NULL || ctrl->pSend == NULL || cmd == NULL || buf == NULL || bufLen == 0) {
        HDF_LOGE("ChbaCliCmd, invalid parameters!");
        pthread_mutex_unlock(&g_mutexChba);
        return -1;
    }
    size_t len = bufLen - 1;
    HDF_LOGD("wpa_ctrl_request -> cmd: %{private}s", cmd);
    int ret = wpa_ctrl_request(ctrl->pSend, cmd, strlen(cmd), buf, &len, NULL);
    if (ret == WPA_CMD_RETURN_TIMEOUT) {
        HDF_LOGE("[%{private}s] command timed out.", cmd);
        pthread_mutex_unlock(&g_mutexChba);
        return WPA_CMD_RETURN_TIMEOUT;
    } else if (ret < 0) {
        HDF_LOGE("[%{private}s] command failed.", cmd);
        pthread_mutex_unlock(&g_mutexChba);
        return -1;
    }
    buf[len] = '\0';
    HDF_LOGD("wpa_ctrl_request -> buf: %{private}s", buf);
    if (strncmp(buf, "FAIL\n", strlen("FAIL\n")) == 0 ||
        strncmp(buf, "UNKNOWN COMMAND\n", strlen("UNKNOWN COMMAND\n")) == 0) {
        HDF_LOGE("%{private}s request success, but response %{public}s", cmd, buf);
        pthread_mutex_unlock(&g_mutexChba);
        return -1;
    }
    pthread_mutex_unlock(&g_mutexChba);
    return 0;
}

static int CommonCliCmd(WpaCtrl *ctrl, const char *cmd, char *buf, size_t bufLen)
{
    pthread_mutex_lock(&g_mutexCommon);

    HDF_LOGI("enter CommonCliCmd");
    if (ctrl == NULL || ctrl->pSend == NULL || cmd == NULL || buf == NULL || bufLen == 0) {
        HDF_LOGE("CommonCliCmd, invalid parameters!");
        pthread_mutex_unlock(&g_mutexCommon);
        return -1;
    }
    size_t len = bufLen - 1;
    HDF_LOGD("wpa_ctrl_request -> cmd: %{private}s", cmd);
    int ret = wpa_ctrl_request(ctrl->pSend, cmd, strlen(cmd), buf, &len, NULL);
    if (ret == WPA_CMD_RETURN_TIMEOUT) {
        HDF_LOGE("[%{private}s] command timed out.", cmd);
        pthread_mutex_unlock(&g_mutexCommon);
        return WPA_CMD_RETURN_TIMEOUT;
    } else if (ret < 0) {
        HDF_LOGE("[%{private}s] command failed.", cmd);
        pthread_mutex_unlock(&g_mutexCommon);
        return -1;
    }
    buf[len] = '\0';
    HDF_LOGD("wpa_ctrl_request -> buf: %{private}s", buf);
    if (strncmp(buf, "FAIL\n", strlen("FAIL\n")) == 0 ||
        strncmp(buf, "UNKNOWN COMMAND\n", strlen("UNKNOWN COMMAND\n")) == 0) {
        HDF_LOGE("%{private}s request success, but response %{public}s", cmd, buf);
        pthread_mutex_unlock(&g_mutexCommon);
        return -1;
    }
    pthread_mutex_unlock(&g_mutexCommon);
    return 0;
}


int WpaCliCmd(const char *cmd, char *buf, size_t bufLen)
{
    int ret = -1;
    HDF_LOGI("enter WpaCliCmd");
    if (cmd == NULL || buf == NULL || bufLen == 0) {
        HDF_LOGE("WpaCliCmd, invalid parameters!");
        return ret;
    }
    char *ifName = NULL;
    pthread_mutex_lock(&g_mutexWpa);
    if (strncmp(cmd, "IFNAME=", strlen("IFNAME=")) == 0) {
        ifName = (char *)cmd + strlen("IFNAME=");
    } else if (strncmp(cmd, "INTERFACE_ADD ", strlen("INTERFACE_ADD ")) == 0) {
        ifName = (char *)cmd + strlen("INTERFACE_ADD ");
    } else if (strncmp(cmd, "INTERFACE_REMOVE ", strlen("INTERFACE_REMOVE ")) == 0) {
        ifName = (char *)cmd + strlen("INTERFACE_REMOVE ");
    } else {
        ifName = "common";
    }

    if (strncmp(ifName, "wlan", strlen("wlan")) == 0) {
        ret = StaCliCmd(GetStaCtrl(), cmd, buf, bufLen);
    } else if (strncmp(ifName, "p2p", strlen("p2p")) == 0) {
        ret = P2pCliCmd(GetP2pCtrl(), cmd, buf, bufLen);
    } else if (strncmp(ifName, "chba", strlen("chba")) == 0) {
        ret = ChbaCliCmd(GetChbaCtrl(), cmd, buf, bufLen);
    } else if (strncmp(ifName, "common", strlen("common")) == 0) {
        ret = CommonCliCmd(GetCommonCtrl(), cmd, buf, bufLen);
    } else {
        HDF_LOGE("WpaCliCmd, ifName is unknow!");
    }
    if (ret == 0 && ifName != NULL &&
        strncmp(cmd, "INTERFACE_REMOVE ", strlen("INTERFACE_REMOVE ")) == 0) {
        int nameLen = strlen(ifName);
        ReleaseIfaceCtrl(ifName, nameLen);
    }
    pthread_mutex_unlock(&g_mutexWpa);
    return ret;
}

int IsSockRemoved(const char *ifName, int len)
{
    int ret = -1;
    if (len < IFNAME_LEN_MIN || len > IFNAME_LEN_MAX) {
        HDF_LOGE("ifname is invalid");
        return ret;
    }
    pthread_mutex_lock(&g_mutexWpa);
    if (strncmp(ifName, "wlan", strlen("wlan")) == 0) {
        if (GetStaCtrl() == NULL) {
            ret = 0;
        }
    } else if (strncmp(ifName, "p2p", strlen("p2p")) == 0) {
        if (GetP2pCtrl() == NULL) {
            ret = 0;
        }
    } else if (strncmp(ifName, "chba", strlen("chba")) == 0) {
        if (GetChbaCtrl() == NULL) {
            ret = 0;
        }
    }
    pthread_mutex_unlock(&g_mutexWpa);
    return ret;
}
