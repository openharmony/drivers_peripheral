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

int WpaCliCmd(const char *cmd, char *buf, size_t bufLen)
{
    HDF_LOGI("enter WpaCliCmd");
    if (cmd == NULL || buf == NULL || bufLen == 0) {
        HDF_LOGE("WpaCliCmd, invalid parameters!");
        return -1;
    }
    WpaCtrl *ctrl = NULL;
    char *ifName = NULL;
    if (strncmp(cmd, "IFNAME=", strlen("IFNAME=")) == 0) {
        ifName = (char *)cmd + strlen("IFNAME=");
    } else if (strncmp(cmd, "INTERFACE_ADD ", strlen("INTERFACE_ADD ")) == 0) {
        ifName = (char *)cmd + strlen("INTERFACE_ADD ");
    } else if (strncmp(cmd, "INTERFACE_REMOVE ", strlen("INTERFACE_REMOVE ")) == 0) {
        ifName = (char *)cmd + strlen("INTERFACE_REMOVE ");
    } else {
        ifName = "wlan0";
    }
 
    if (strncmp(ifName, "wlan", strlen("wlan")) == 0) {
        ctrl = GetStaCtrl();
    } else if (strncmp(ifName, "p2p", strlen("p2p")) == 0) {
        ctrl = GetP2pCtrl();
    } else if (strncmp(ifName, "chba", strlen("chba")) == 0) {
        ctrl = GetChbaCtrl();
    } else if (strncmp(ifName, "common", strlen("common")) == 0) {
        ctrl = GetCommonCtrl();
    }
    if (ctrl == NULL || ctrl->pSend == NULL) {
        HDF_LOGE("WpaCliCmd, ctrl/ctrl->pSend is NULL!");
        return -1;
    }
    size_t len = bufLen - 1;
    HDF_LOGD("wpa_ctrl_request -> cmd: %{private}s", cmd);
    int ret = wpa_ctrl_request(ctrl->pSend, cmd, strlen(cmd), buf, &len, NULL);
    if (ret == WPA_CMD_RETURN_TIMEOUT) {
        HDF_LOGE("[%{private}s] command timed out.", cmd);
        return WPA_CMD_RETURN_TIMEOUT;
    } else if (ret < 0) {
        HDF_LOGE("[%{private}s] command failed.", cmd);
        return -1;
    }
    buf[len] = '\0';
    HDF_LOGD("wpa_ctrl_request -> buf: %{private}s", buf);
    if (strncmp(buf, "FAIL\n", strlen("FAIL\n")) == 0 ||
        strncmp(buf, "UNKNOWN COMMAND\n", strlen("UNKNOWN COMMAND\n")) == 0) {
        HDF_LOGE("%{private}s request success, but response %{public}s", cmd, buf);
        return -1;
    }
    return 0;
}
