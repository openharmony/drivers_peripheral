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

#include "wpa_supplicant_hal.h"
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <hdf_log.h>
#include "hdi_wpa_common.h"
#include "securec.h"
#include "utils/common.h"
#include "wpa_hdi_util.h"

#undef LOG_TAG
#define LOG_TAG "HdiWpaStaHal"

#define FAIL_BUSY 2

#define COLUMN_INDEX_ZERO 0
#define COLUMN_INDEX_ONE 1
#define COLUMN_INDEX_TWO 2
#define COLUMN_INDEX_THREE 3
#define COLUMN_INDEX_FOUR 4
#define COLUMN_INDEX_FIVE 5

#define FAIL_PBC_OVERLAP_RETUEN 3
#define CMD_BUFFER_SIZE 1024
#define MAX_NAME_LEN 12
#define REPLY_BUF_LENGTH (4096 * 10)
#define REPLY_BUF_SMALL_LENGTH 64
#define CMD_FREQ_MAX_LEN 8
#define STA_NO_LEN 2
#define FREQ_MAX_SIZE 100
#define CMD_BUFFER_MIN_SIZE 15

const int WPA_QUOTATION_MARKS_FLAG_YES = 0;
const int WPA_QUOTATION_MARKS_FLAG_NO = 1;

const unsigned int HT_OPER_EID = 61;
const unsigned int VHT_OPER_EID = 192;
const unsigned int EXT_EXIST_EID = 255;
const unsigned int EXT_HE_OPER_EID = 36;
const unsigned int HE_OPER_BASIC_LEN = 6;
const unsigned int VHT_OPER_INFO_EXTST_MASK = 0x40;
const unsigned int GHZ_HE_INFO_EXIST_MASK_6 = 0x02;
const unsigned int GHZ_HE_WIDTH_MASK_6 = 0x03;
const unsigned int BSS_EXIST_MASK = 0x80;
const unsigned int VHT_OPER_INFO_BEGIN_INDEX = 6;
const unsigned int VHT_INFO_SIZE = 3;
const unsigned int HT_INFO_SIZE = 3;
const unsigned int UINT8_MASK = 0xFF;
const unsigned int UNSPECIFIED = -1;
const unsigned int MAX_INFO_ELEMS_SIZE = 256;
const unsigned int SUPP_RATES_SIZE = 8;
const unsigned int EXT_SUPP_RATES_SIZE = 4;
const unsigned int SUPPORTED_RATES_EID = 1;
const unsigned int ERP_EID = 42;
const unsigned int EXT_SUPPORTED_RATES_EID = 50;

const unsigned int BAND_5_GHZ = 2;
const unsigned int BAND_6_GHZ = 8;
const unsigned int CHAN_WIDTH_20MHZ = 0;
const unsigned int CHAN_WIDTH_40MHZ = 1;
const unsigned int CHAN_WIDTH_80MHZ = 2;
const unsigned int CHAN_WIDTH_160MHZ = 3;
const unsigned int CHAN_WIDTH_80MHZ_MHZ = 4;

WifiWpaStaInterface *g_wpaStaInterface = NULL;

static WpaSsidField g_wpaHalSsidFields[] = {
    {DEVICE_CONFIG_SSID, "ssid", WPA_QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_PSK, "psk", WPA_QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_KEYMGMT, "key_mgmt", WPA_QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_PRIORITY, "priority", WPA_QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_SCAN_SSID, "scan_ssid", WPA_QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_EAP, "eap", WPA_QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_IDENTITY, "identity", WPA_QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_PASSWORD, "password", WPA_QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_BSSID, "bssid", WPA_QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_AUTH_ALGORITHMS, "auth_alg", WPA_QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_WEP_KEY_IDX, "wep_tx_keyidx", WPA_QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_WEP_KEY_0, "wep_key0", WPA_QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_WEP_KEY_1, "wep_key1", WPA_QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_WEP_KEY_2, "wep_key2", WPA_QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_WEP_KEY_3, "wep_key3", WPA_QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_EAP_CLIENT_CERT, "client_cert", WPA_QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_EAP_PRIVATE_KEY, "private_key", WPA_QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_EAP_PHASE2METHOD, "phase2", WPA_QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_IEEE80211W, "ieee80211w", WPA_QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_ALLOW_PROTOCOLS, "proto", WPA_QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_GROUP_CIPHERS, "group", WPA_QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_PAIRWISE_CIPHERS, "pairwise", WPA_QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_SAE_PASSWD, "sae_password", WPA_QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_EAP_CA_CERT, "ca_cert", WPA_QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_EAP_CERT_PWD, "private_key_passwd", WPA_QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_WAPI_CA_CERT, "wapi_ca_cert", WPA_QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_WAPI_USER_CERT, "wapi_user_sel_cert", WPA_QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_WAPI_PSK_KEY_TYPE, "psk_key_type", WPA_QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_WAPI_PSK, "wapi_psk", WPA_QUOTATION_MARKS_FLAG_YES},
};

static int WpaCliCmdStatus(WifiWpaStaInterface *this, const char*ifName, struct WpaHalCmdStatus *pcmd)
{
    if (this == NULL || pcmd == NULL) {
        return -1;
    }
    char cmd[CMD_BUFFER_SIZE] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s STATUS", ifName == NULL ? this->ifname : ifName) < 0) {
        HDF_LOGE("snprintf error");
        return -1;
    }
    char buf[REPLY_BUF_LENGTH] = {0};
    if (WpaCliCmd(cmd, buf, REPLY_BUF_LENGTH) != 0) {
        return -1;
    }
    char *savedPtr = NULL;
    char *key = strtok_r(buf, "=", &savedPtr);
    while (key != NULL) {
        char *value = strtok_r(NULL, "\n", &savedPtr);
        if (strcmp(key, "bssid") == 0) {
            if (strcpy_s(pcmd->bssid, sizeof(pcmd->bssid), value) != EOK) {
                HDF_LOGE("%{public}s strcpy failed", __func__);
            }
        } else if (strcmp(key, "freq") == 0) {
            pcmd->freq = atoi(value);
        } else if (strcmp(key, "ssid") == 0) {
            if (strcpy_s(pcmd->ssid, sizeof(pcmd->ssid), value) != EOK) {
                HDF_LOGE("%{public}s strcpy failed", __func__);
            }
            printf_decode((u8 *)pcmd->ssid, sizeof(pcmd->ssid), pcmd->ssid);
        } else if (strcmp(key, "id") == 0) {
            pcmd->id = atoi(value);
        } else if (strcmp(key, "key_mgmt") == 0) {
            if (strcpy_s(pcmd->keyMgmt, sizeof(pcmd->keyMgmt), value) != EOK) {
                HDF_LOGE("%{public}s strcpy failed", __func__);
            }
        } else if (strcmp(key, "address") == 0) {
            if (strcpy_s(pcmd->address, sizeof(pcmd->address), value) != EOK) {
                HDF_LOGE("%{public}s strcpy failed", __func__);
            }
        }

        key = strtok_r(NULL, "=", &savedPtr);
    }
    if (strcmp(pcmd->address, "") == 0) {
        return -1;
    }
    if (strcmp(pcmd->bssid, "") == 0) {
        return 1;
    }
    return 0;
}

static int WpaCliCmdAddNetworks(WifiWpaStaInterface *this)
{
    if (this == NULL) {
        return -1;
    }
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    char cmd[CMD_BUFFER_SIZE] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s ADD_NETWORK", this->ifname) < 0) {
        HDF_LOGE("snprintf error");
        return -1;
    }
    if (WpaCliCmd(cmd, buf, sizeof(buf)) != 0) {
        return -1;
    }
    return atoi(buf);
}

static int WpaCliCmdReconnect(WifiWpaStaInterface *this)
{
    if (this == NULL) {
        return -1;
    }
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    char cmd[CMD_BUFFER_SIZE] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s RECONNECT", this->ifname) < 0) {
        HDF_LOGE("snprintf error");
        return -1;
    }
    return WpaCliCmd(cmd, buf, sizeof(buf));
}

static int WpaCliCmdReassociate(WifiWpaStaInterface *this)
{
    if (this == NULL) {
        return -1;
    }
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    char cmd[CMD_BUFFER_SIZE] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s REASSOCIATE", this->ifname) < 0) {
        HDF_LOGE("snprintf error");
        return -1;
    }
    return WpaCliCmd(cmd, buf, sizeof(buf));
}

static int WpaCliCmdDisconnect(WifiWpaStaInterface *this)
{
    if (this == NULL) {
        return -1;
    }
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    char cmd[CMD_BUFFER_SIZE] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s DISCONNECT", this->ifname) < 0) {
        HDF_LOGE("snprintf error");
        return -1;
    }
    return WpaCliCmd(cmd, buf, sizeof(buf));
}

static int WpaCliCmdSaveConfig(WifiWpaStaInterface *this)
{
    if (this == NULL) {
        return -1;
    }
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    char cmd[CMD_BUFFER_SIZE] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s SAVE_CONFIG", this->ifname) < 0) {
        HDF_LOGE("snprintf error");
        return -1;
    }
    return WpaCliCmd(cmd, buf, sizeof(buf));
}

static int WpaCliCmdSetNetwork(WifiWpaStaInterface *this, const struct WpaSetNetworkArgv *argv)
{
    if (this == NULL || argv == NULL) {
        return -1;
    }
    int pos = -1;
    for (unsigned i = 0; i < sizeof(g_wpaHalSsidFields) / sizeof(g_wpaHalSsidFields[0]); ++i) {
        if (g_wpaHalSsidFields[i].field == argv->param) {
            pos = i;
            break;
        }
    }
    if (pos < 0) {
        HDF_LOGE("%{public}s unsupported param: %{public}d", __func__, argv->param);
        return -1;
    }
    char cmd[CMD_BUFFER_SIZE] = {0};
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    int res;

    res = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s SET_NETWORK %d %s %s", this->ifname,
            argv->id, g_wpaHalSsidFields[pos].fieldName, argv->value);
    HDF_LOGI("%{public}s cmd= %{public}s", __func__, cmd);
    if (res < 0) {
        HDF_LOGE("%{public}s Internal error, set request message failed!", __func__);
        return -1;
    }
    return WpaCliCmd(cmd, buf, sizeof(buf));
}

static int WpaCliCmdEnableNetwork(WifiWpaStaInterface *this, int networkId)
{
    if (this == NULL) {
        return -1;
    }
    char cmd[CMD_BUFFER_SIZE] = {0};
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s ENABLE_NETWORK %d", this->ifname, networkId) < 0) {
        HDF_LOGE("snprintf err");
        return -1;
    }
    return WpaCliCmd(cmd, buf, sizeof(buf));
}

static int WpaCliCmdSelectNetwork(WifiWpaStaInterface *this, int networkId)
{
    if (this == NULL) {
        return -1;
    }
    char cmd[CMD_BUFFER_SIZE] = {0};
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s SELECT_NETWORK %d", this->ifname, networkId) < 0) {
        HDF_LOGE("snprintf err");
        return -1;
    }
    return WpaCliCmd(cmd, buf, sizeof(buf));
}

static int WpaCliCmdDisableNetwork(WifiWpaStaInterface *this, int networkId)
{
    if (this == NULL) {
        return -1;
    }
    char cmd[CMD_BUFFER_SIZE] = {0};
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s DISABLE_NETWORK %d", this->ifname, networkId) < 0) {
        HDF_LOGE("snprintf err");
        return -1;
    }
    return WpaCliCmd(cmd, buf, sizeof(buf));
}

static int WpaCliCmdRemoveNetwork(WifiWpaStaInterface *this, int networkId)
{
    if (this == NULL) {
        return -1;
    }
    char cmd[CMD_BUFFER_SIZE] = {0};
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    int res = 0;
    if (networkId == -1) {
        res = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s REMOVE_NETWORK all", this->ifname);
    } else if (networkId >= 0) {
        res = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s REMOVE_NETWORK %d", this->ifname, networkId);
    } else {
        return -1;
    }
    if (res < 0) {
        HDF_LOGE("snprintf err");
        return -1;
    }
    return WpaCliCmd(cmd, buf, sizeof(buf));
}

static int WpaCliCmdGetNetwork(
    WifiWpaStaInterface *this, const struct WpaGetNetworkArgv *argv, char *pcmd, unsigned size)
{
    if (this == NULL || argv == NULL || pcmd == NULL) {
        return -1;
    }
    char cmd[CMD_BUFFER_SIZE] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s GET_NETWORK %d %s", this->ifname, argv->id,
        argv->param) < 0) {
        HDF_LOGE("snprintf err");
        return -1;
    }
    char *buf = (char *)calloc(REPLY_BUF_LENGTH, sizeof(char));
    if (buf == NULL) {
        return -1;
    }
    if (WpaCliCmd(cmd, buf, REPLY_BUF_LENGTH) != 0) {
        free(buf);
        return -1;
    }
    if (strncpy_s(pcmd, size, buf, strlen(buf)) != EOK) {
        HDF_LOGE("copy set get_network result failed!");
        free(buf);
        return -1;
    }
    free(buf);
    return 0;
}

static int WpaCliCmdWpsPbc(WifiWpaStaInterface *this, const struct WpaWpsPbcArgv *wpspbc)
{
    if (this == NULL) {
        return -1;
    }
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    char cmd[CMD_BUFFER_SIZE] = {0};
    int pos = 0;
    int res = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s WPS_PBC", this->ifname);
    if (res < 0) {
        HDF_LOGE("snprintf err");
        return -1;
    }
    pos += res;
    if (wpspbc != NULL) {
        res = 0; /* reset res value */
        if (wpspbc->anyFlag == 1) {
            res = snprintf_s(cmd + pos, sizeof(cmd) - pos, sizeof(cmd) - pos - 1, " %s", "any");
        } else if (strlen(wpspbc->bssid) > 0) {
            res = snprintf_s(cmd + pos, sizeof(cmd) - pos, sizeof(cmd) - pos - 1, " %s", wpspbc->bssid);
        }
        if (res < 0) {
            HDF_LOGE("snprintf err");
            return -1;
        }
        pos += res;
        if (wpspbc->multiAp > 0) { /* The value of ap needs to be determined. The value is greater than 0. */
            res = snprintf_s(
                cmd + pos, sizeof(cmd) - pos, sizeof(cmd) - pos - 1, " multi_ap=%d", wpspbc->multiAp);
            if (res < 0) {
                HDF_LOGE("snprintf err");
                return -1;
            }
        }
    }
    if (WpaCliCmd(cmd, buf, sizeof(buf)) != 0) {
        HDF_LOGE("wps_pbc return failed!");
        return -1;
    }
    if (strncmp(buf, "FAIL-PBC-OVERLAP", strlen("FAIL-PBC-OVERLAP")) == 0) {
        HDF_LOGE("wps_pbc success, but result err: buf =%{public}s", buf);
        return FAIL_PBC_OVERLAP_RETUEN; /* Add a new enumerated value. */
    }
    return 0;
}

static int WpaCliCmdWpsPin(WifiWpaStaInterface *this, const struct WpaWpsPinArgv *wpspin, int *pincode)
{
    if (this == NULL || wpspin == NULL || pincode == NULL) {
        return -1;
    }
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    char cmd[CMD_BUFFER_SIZE] = {0};
    int pos = 0;
    int res = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s WPS_PIN", this->ifname);
    if (res < 0) {
        HDF_LOGE("snprintf err");
        return -1;
    }
    pos += res;
    if (strlen(wpspin->bssid) > 0) {
        res = snprintf_s(cmd + pos, sizeof(cmd) - pos, sizeof(cmd) - pos - 1, " %s", wpspin->bssid);
    } else {
        res = snprintf_s(cmd + pos, sizeof(cmd) - pos, sizeof(cmd) - pos - 1, " any");
    }
    if (res < 0) {
        HDF_LOGE("snprintf err");
        return -1;
    }
    pos += res;
    if (strlen(wpspin->pinCode) > 0) {
        res = snprintf_s(cmd + pos, sizeof(cmd) - pos, sizeof(cmd) - pos - 1, " %s", wpspin->pinCode);
        if (res < 0) {
            HDF_LOGE("snprintf err");
            return -1;
        }
    }
    if (WpaCliCmd(cmd, buf, sizeof(buf)) != 0) {
        HDF_LOGE("wps_pin return failed!");
        return -1;
    }
    *pincode = atoi(buf);
    return 0;
}

static int WpaCliCmdWpsCancel(WifiWpaStaInterface *this)
{
    if (this == NULL) {
        return -1;
    }
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    char cmd[CMD_BUFFER_SIZE] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s WPS_CANCEL", this->ifname) < 0) {
        HDF_LOGE("snprintf err");
        return -1;
    }
    return WpaCliCmd(cmd, buf, sizeof(buf));
}

static int WpaCliCmdPowerSave(WifiWpaStaInterface *this, int enable)
{
    if (this == NULL) {
        return -1;
    }
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    char cmd[CMD_BUFFER_SIZE] = {0};
    int ret;
    if (enable) {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s SET PS 1", this->ifname);
    } else {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s SET PS 0", this->ifname);
    }
    if (ret < 0) {
        HDF_LOGE("snprintf err");
        return -1;
    }
    return WpaCliCmd(cmd, buf, sizeof(buf));
}

static int WpaCliCmdSetRoamConfig(WifiWpaStaInterface *this, const char *bssid)
{
    if (this == NULL || bssid == NULL) {
        return -1;
    }
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    char cmd[CMD_BUFFER_SIZE] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s SET bssid %s", this->ifname, bssid) < 0) {
        HDF_LOGE("snprintf err");
        return -1;
    }
    return WpaCliCmd(cmd, buf, sizeof(buf));
}

static int WpaCliCmdSetCountryCode(WifiWpaStaInterface *this, const char *countryCode)
{
    if (this == NULL || countryCode == NULL) {
        return -1;
    }
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    char cmd[CMD_BUFFER_SIZE] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s DRIVER COUNTRY %s", this->ifname, countryCode) < 0) {
        HDF_LOGE("snprintf err");
        return -1;
    }
    return WpaCliCmd(cmd, buf, sizeof(buf));
}

static int WpaCliCmdGetCountryCode(WifiWpaStaInterface *this, char *countryCode, int codeSize)
{
    if (this == NULL || countryCode == NULL) {
        return -1;
    }
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    char cmd[CMD_BUFFER_SIZE] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s GET country", this->ifname) < 0) {
        HDF_LOGE("snprintf err");
        return -1;
    }
    if (WpaCliCmd(cmd, buf, sizeof(buf)) != 0) {
        HDF_LOGE("get countrycode failed");
        return -1;
    }
    if (strncpy_s(countryCode, codeSize, buf, strlen(buf)) != EOK) {
        HDF_LOGE("copy set country code failed!");
        return -1;
    }
    return 0;
}

static int WpaCliCmdGetConnectionCapabilities(WifiWpaStaInterface *this, struct ConnectionCapabilities *connectionCap)
{
    if (this == NULL || connectionCap == NULL) {
        return -1;
    }
    char buf[REPLY_BUF_LENGTH] = {0};
    char cmd[CMD_BUFFER_SIZE] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s GET_CONNECTION_CAPABILITY", this->ifname) < 0) {
        HDF_LOGE("snprintf err");
        return -1;
    }

    if (WpaCliCmd(cmd, buf, sizeof(buf)) != 0) {
        HDF_LOGE("WpaCliCmd GET_CONNECTION_CAPABILITY failed");
        return -1;
    }
    char *savedPtr = NULL;
    char *key = strtok_r(buf, "=", &savedPtr);
    while (key != NULL) {
        char *value = strtok_r(NULL, "\n", &savedPtr);
        if (strcmp(key, "technology") == 0) {
            connectionCap->technology = atoi(value);
        } else if (strcmp(key, "channelBandwidth") == 0) {
            connectionCap->channelBandwidth = atoi(value);
        }  else if (strcmp(key, "maxNumberTxSpatialStreams") == 0) {
            connectionCap->maxNumberTxSpatialStreams = atoi(value);
        }  else if (strcmp(key, "maxNumberRxSpatialStreams") == 0) {
            connectionCap->maxNumberRxSpatialStreams = atoi(value);
        }  else if (strcmp(key, "legacyMode") == 0) {
            connectionCap->legacyMode = atoi(value);
        }
        key = strtok_r(NULL, "=", &savedPtr);
    }
    HDF_LOGI("WpaCliCmdGetConnectionCapabilities technology =%d channelBandwidth = %d", connectionCap->technology,
        connectionCap->channelBandwidth);
    return 0;
}

static int WpaCliCmdGetRequirePmf(WifiWpaStaInterface *this, int *enable)
{
    if (this == NULL || enable == NULL) {
        return -1;
    }
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    char cmd[CMD_BUFFER_SIZE] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s GET_REQUIRE_PMF", this->ifname) < 0) {
        HDF_LOGE("snprintf err");
        return -1;
    }

    if (WpaCliCmd(cmd, buf, sizeof(buf)) != 0) {
        HDF_LOGE("WpaCliCmd GET_REQUIRE_PMF failed");
        return -1;
    }
    char *savedPtr = NULL;
    char *key = strtok_r(buf, "=", &savedPtr);
    while (key != NULL) {
        char *value = strtok_r(NULL, "\n", &savedPtr);
        if (strcmp(key, "require_pmf") == 0) {
            *enable = atoi(value);
        }
        key = strtok_r(NULL, "=", &savedPtr);
    }
    HDF_LOGI("WpaCliCmdGetRequirePmf enable =%d ", *enable);
    return 0;
}

static int WpaCliCmdWepKeyTxKeyIdx(WifiWpaStaInterface *this, int *keyIdx)
{
    if (this == NULL || keyIdx == NULL) {
        return -1;
    }
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    char cmd[CMD_BUFFER_SIZE] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s GET_WEP_KEY_IDX", this->ifname) < 0) {
        HDF_LOGE("snprintf err");
        return -1;
    }

    if (WpaCliCmd(cmd, buf, sizeof(buf)) != 0) {
        HDF_LOGE("WpaCliCmd GET_WEP_KEY_IDX failed");
        return -1;
    }
    char *savedPtr = NULL;
    char *key = strtok_r(buf, "=", &savedPtr);
    while (key != NULL) {
        char *value = strtok_r(NULL, "\n", &savedPtr);
        if (strcmp(key, "wep_tx_keyidx") == 0) {
            *keyIdx = atoi(value);
        }
        key = strtok_r(NULL, "=", &savedPtr);
    }
    HDF_LOGI("WpaCliCmdWepKeyTxKeyIdx keyIdx =%d ", *keyIdx);
    return 0;
}

static int WpaCliCmdWepKey(WifiWpaStaInterface *this, int keyIdx, unsigned char *wepKey, unsigned int *wepKeyLen)
{
    if (this == NULL || wepKey == NULL || wepKeyLen == NULL) {
        return -1;
    }
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    char cmd[CMD_BUFFER_SIZE] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s GET_WEP_KEY GET_WEP_KEY_IDX %d",
		this->ifname, keyIdx) < 0) {
        HDF_LOGE("snprintf err");
        return -1;
    }

    if (WpaCliCmd(cmd, buf, sizeof(buf)) != 0) {
        HDF_LOGE("WpaCliCmd WepKey failed");
        return -1;
    }
    char *savedPtr = NULL;
    char *key = strtok_r(buf, "=", &savedPtr);
    while (key != NULL) {
        char *value = strtok_r(NULL, "\n", &savedPtr);
        if (strcmp(key, "wep_key") == 0) {
            if (strncpy_s((char *)wepKey, strlen(value), value, strlen(value)) != 0) {
                HDF_LOGE("copy wep_key failed!");
                return -1;
            }
            *wepKeyLen = strlen(value);
        }
        key = strtok_r(NULL, "=", &savedPtr);
    }
    HDF_LOGI("WpaCliCmdWepKey wepKey =%s", wepKey);
    return 0;
}

static int WpaCliCmdGetPsk(WifiWpaStaInterface *this, unsigned char *psk, unsigned int *pskLen)
{
    if (this == NULL || psk == NULL || pskLen == NULL) {
        return -1;
    }
    char buf[REPLY_BUF_LENGTH] = {0};
    char cmd[CMD_BUFFER_SIZE] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s GET_PSK", this->ifname) < 0) {
        HDF_LOGE("snprintf err");
        return -1;
    }

    if (WpaCliCmd(cmd, buf, sizeof(buf)) != 0) {
        HDF_LOGE("WpaCliCmd GET_PSK failed");
        return -1;
    }
    char *savedPtr = NULL;
    char *key = strtok_r(buf, "=", &savedPtr);
    while (key != NULL) {
        char *value = strtok_r(NULL, "\n", &savedPtr);
        if (strcmp(key, "psk") == 0) {
            if (strncpy_s((char *)psk, strlen(value), value, strlen(value)) != 0) {
                HDF_LOGE("copy psk failed!");
                return -1;
            }
            *pskLen = strlen(value);
        }
        key = strtok_r(NULL, "=", &savedPtr);
    }
    HDF_LOGI("WpaCliCmdGetPsk psk =%s", psk);
    return 0;
}

static int WpaCliCmdGetPskPassphrase(WifiWpaStaInterface *this, char *psk, unsigned int pskLen)
{
    if (this == NULL || psk == NULL) {
        return -1;
    }
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    char cmd[CMD_BUFFER_SIZE] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s GET_PSK_PASSPHRASE", this->ifname) < 0) {
        HDF_LOGE("snprintf err");
        return -1;
    }

    if (WpaCliCmd(cmd, buf, sizeof(buf)) != 0) {
        HDF_LOGE("WpaCliCmd GET_PSK_PASSPHRASE failed");
        return -1;
    }
    char *savedPtr = NULL;
    char *key = strtok_r(buf, "=", &savedPtr);
    while (key != NULL) {
        char *value = strtok_r(NULL, "\n", &savedPtr);
        if (strcmp(key, "passphrase") == 0) {
            if (strncpy_s((char *)psk, (int)pskLen, value, strlen(value)) != 0) {
                HDF_LOGE("copy passphrase failed!");
                return -1;
            }
        }
        key = strtok_r(NULL, "=", &savedPtr);
    }
    HDF_LOGI("WpaCliCmdGetPskPassphrase psk = %s", psk);
    return 0;
}

static int WpaCliCmdGetScanSsid(WifiWpaStaInterface *this, int *scanSsid)
{
    if (this == NULL || scanSsid == NULL) {
        return -1;
    }
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    char cmd[CMD_BUFFER_SIZE] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s GET_SCAN_SSID", this->ifname) < 0) {
        HDF_LOGE("snprintf err");
        return -1;
    }

    if (WpaCliCmd(cmd, buf, sizeof(buf)) != 0) {
        HDF_LOGE("WpaCliCmd GET_SCAN_SSID failed");
        return -1;
    }
    char *savedPtr = NULL;
    char *key = strtok_r(buf, "=", &savedPtr);
    while (key != NULL) {
        char *value = strtok_r(NULL, "\n", &savedPtr);
        if (strcmp(key, "scan_ssid") == 0) {
            *scanSsid = atoi(value);
        }
        key = strtok_r(NULL, "=", &savedPtr);
    }
    HDF_LOGI("WpaCliCmdGetScanSsid scanSsid =%d ", *scanSsid);
    return 0;
}

static int WpaCliCmdSetAutoConnect(WifiWpaStaInterface *this, int enable)
{
    if (this == NULL) {
        return -1;
    }
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    char cmd[CMD_BUFFER_SIZE] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s STA_AUTOCONNECT %d", this->ifname, enable) < 0) {
        HDF_LOGE("snprintf err");
        return -1;
    }
    return WpaCliCmd(cmd, buf, sizeof(buf));
}

static int WpaCliCmdWpaBlockListClear(WifiWpaStaInterface *this)
{
    if (this == NULL) {
        return -1;
    }
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    char cmd[CMD_BUFFER_SIZE] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s BL%cCKLIST clear", this->ifname, 'A') < 0) {
        HDF_LOGE("snprintf err");
        return -1;
    }
    return WpaCliCmd(cmd, buf, sizeof(buf));
}

static void ListNetworkProcess(WifiNetworkInfo *pcmd, char *tmpBuf, int bufLeng)
{
    int start = 0; /* start pos */
    int end = 0;   /* end pos */
    int i = 0;
    while (end < bufLeng) {
        if (tmpBuf[end] != '\t') {
            ++end;
            continue;
        }
        tmpBuf[end] = '\0';
        if (i == COLUMN_INDEX_ZERO) {
            pcmd->id = atoi(tmpBuf);
        } else if (i == COLUMN_INDEX_ONE) {
            if (strcpy_s(pcmd->ssid, sizeof(pcmd->ssid), tmpBuf + start) != EOK) {
                break;
            }
            printf_decode((u8 *)pcmd->ssid, sizeof(pcmd->ssid), pcmd->ssid);
        } else if (i == COLUMN_INDEX_TWO) {
            if (strcpy_s(pcmd->bssid, sizeof(pcmd->bssid), tmpBuf + start) != EOK) {
                break;
            }
            start = end + 1;
            if (strcpy_s(pcmd->flags, sizeof(pcmd->flags), tmpBuf + start) != EOK) {
                break;
            }
            break;
        }
        ++i;
        end++;
        start = end;
    }
    return;
}

static int WpaCliCmdListNetworks(WifiWpaStaInterface *this, WifiNetworkInfo *pcmd, int *size)
{
    if (this == NULL || pcmd == NULL || size == NULL || *size <= 0) {
        return -1;
    }
    char cmd[CMD_BUFFER_SIZE] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s LIST_NETWORKS", this->ifname) < 0) {
        HDF_LOGE("snprintf err");
        return -1;
    }
    char *buf = (char *)calloc(REPLY_BUF_LENGTH, sizeof(char));
    if (buf == NULL) {
        return -1;
    }
    if (WpaCliCmd(cmd, buf, REPLY_BUF_LENGTH) != 0) {
        free(buf);
        return -1;
    }
    char *savedPtr = NULL;
    strtok_r(buf, "\n", &savedPtr); /* skip first line */
    char *token = strtok_r(NULL, "\n", &savedPtr);
    int j = 0;

    while (token != NULL) {
        if (j >= *size) {
            *size = j;
            HDF_LOGW("list_networks full!");
            free(buf);
            return 0;
        }
        int length = strlen(token);
        if (length <= 0) {
            break;
        }
        ListNetworkProcess(pcmd + j, token, length);
        token = strtok_r(NULL, "\n", &savedPtr);
        j++;
    }
    *size = j;
    if (*size <= 0) {
        HDF_LOGW("list_networks empty!");
    }
    free(buf);
    return 0;
}

static unsigned AssignCmdLen(WifiWpaStaInterface *this, const ScanSettings *settings)
{
    if (settings->scanStyle == SCAN_TYPE_PNO) {
        unsigned exceptedLen = strlen("IFNAME=") + strlen(this->ifname) + 1 + strlen("set pno x");
        if (settings->isStartPnoScan) {
            HDF_LOGI("AssignCmdLen, startPnoScan, freqSize=%{public}d", settings->freqSize);
            if (settings->freqSize > 0) {
                exceptedLen += strlen(" freq=") + (CMD_FREQ_MAX_LEN + 1) * settings->freqSize;
            }
        }
        return exceptedLen;
    }
    unsigned exceptedLen = strlen("IFNAME=") + strlen(this->ifname) + 1 + strlen("SCAN");
    HDF_LOGI("AssignCmdLen, startScan, freSize=%{public}d, hiddenSsidSize=%{public}d",
        settings->freqSize, settings->hiddenSsidSize);
    if (settings->freqSize > 0) {
        exceptedLen += strlen(" freq=") + (CMD_FREQ_MAX_LEN + 1) * settings->freqSize;
    }
    for (int i = 0; i < settings->hiddenSsidSize; ++i) {
        unsigned ssidLen = strlen(settings->hiddenSsid[i]);
        exceptedLen += strlen(" ssid ") + (ssidLen << 1);
    }
    return exceptedLen;
}

static int ConcatScanSetting(const ScanSettings *settings, char *buff, int len)
{
    if (settings == NULL || (settings->scanStyle == SCAN_TYPE_PNO && !settings->isStartPnoScan)) {
        return 0;
    }
    int pos = 0;
    int res;
    int i;
    if (settings->freqSize < 0 || settings->freqSize > FREQ_MAX_SIZE) {
        HDF_LOGE("invalid parameter");
        return 0;
    }
    for (i = 0; i < settings->freqSize; ++i) {
        if (i == 0) {
            res = snprintf_s(buff + pos, len - pos, len - pos - 1, "%s", " freq=");
            if (res < 0) {
                HDF_LOGE("snprintf error");
                return -1;
            }
            pos += res;
        }
        if (i != (settings->freqSize - 1)) {
            res = snprintf_s(buff + pos, len - pos, len - pos - 1, "%d,", settings->freqs[i]);
        } else {
            res = snprintf_s(buff + pos, len - pos, len - pos - 1, "%d;", settings->freqs[i]);
        }
        if (res < 0) {
            HDF_LOGE("snprintf error");
            return -1;
        }
        pos += res;
    }
    for (i = 0; (i < settings->hiddenSsidSize) && (settings->scanStyle != SCAN_TYPE_PNO); ++i) {
        res = snprintf_s(buff + pos, len - pos, len - pos - 1, " ssid ");
        if (res < 0) {
            HDF_LOGE("snprintf error");
            return -1;
        }
        pos += res;
        char *p = settings->hiddenSsid[i];
        while (*p) {
            res = snprintf_s(buff + pos, len - pos, len - pos - 1, "%02x", *p);
            if (res < 0) {
                HDF_LOGE("snprintf error");
                return -1;
            }
            pos += res;
            p++;
        }
    }
    return 0;
}

static int WpaCliCmdBssFlush(WifiWpaStaInterface *this)
{
    if (this == NULL) {
        return -1;
    }
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    char cmd[CMD_BUFFER_SIZE] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s BSS_FLUSH 0", this->ifname) < 0) {
        HDF_LOGE("snprintf err");
        return -1;
    }
    return WpaCliCmd(cmd, buf, sizeof(buf));
}

static int WpaCliCmdScan(WifiWpaStaInterface *this, const ScanSettings *settings)
{
    if (this == NULL) {
        HDF_LOGE("WpaCliCmdScan, this is NULL!");
        return -1;
    }

    /* Invalidate expired scan results */
    WpaCliCmdBssFlush(this);
    unsigned len = CMD_BUFFER_SIZE;
    unsigned expectedLen = 0;
    if (settings != NULL) {
        expectedLen = AssignCmdLen(this, settings);
    }
    if (expectedLen < CMD_BUFFER_MIN_SIZE || expectedLen > CMD_BUFFER_SIZE) {
        HDF_LOGE("invalid parameter");
        return -1;
    }
    if (expectedLen >= len) {
        len = expectedLen + 1;
    }
    char *pcmd = (char *)calloc(len, sizeof(char));
    if (pcmd == NULL) {
        HDF_LOGE("WpaCliCmdScan, pcmd is NULL!");
        return -1;
    }
    int pos = 0;
    int res = 0;
    if (settings != NULL) {
        if (settings->scanStyle == SCAN_TYPE_PNO && settings->isStartPnoScan) {
            res = snprintf_s(pcmd, len, len - 1, "IFNAME=%s SET PNO 1", this->ifname);
        } else if (settings->scanStyle == SCAN_TYPE_PNO && !settings->isStartPnoScan) {
            res = snprintf_s(pcmd, len, len - 1, "IFNAME=%s SET PNO 0", this->ifname);
        } else {
            res = snprintf_s(pcmd, len, len - 1, "IFNAME=%s SCAN", this->ifname);
        }
    }
    if (res < 0) {
        HDF_LOGE("WpaCliCmdScan, snprintf_s error!");
        free(pcmd);
        return -1;
    }
    pos += res;
    if (settings != NULL && ConcatScanSetting(settings, pcmd + pos, len - pos) < 0) {
        HDF_LOGE("ConcatScanSetting return failed!");
        free(pcmd);
        return -1;
    }
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    if (WpaCliCmd(pcmd, buf, sizeof(buf)) != 0) {
        free(pcmd);
        return -1;
    }
    free(pcmd);
    if (strncmp(buf, "FAIL-BUSY", strlen("FAIL-BUSY")) == 0) {
        HDF_LOGE("WpaCliCmdScan, WpaCliCmd return FAIL-BUSY!");
        return FAIL_BUSY;
    }
    return 0;
}

static int ConvertChanToFreqMhz(int channel, int band)
{
    int band24Ghz = 1;
    int channelTimes = 5;

    if (band == band24Ghz) {
        int bandFirstChNum24 = 1;
        int bandLastChNum24 = 14;
        int bandStartFreqMhz24 = 2412;
        int bandSpecial = 2484;
        int channelSpecial = 14;
        if (channel == channelSpecial) {
            return bandSpecial;
        } else if (channel >= bandFirstChNum24 && channel <= bandLastChNum24) {
            return ((channel - bandFirstChNum24) * channelTimes) + bandStartFreqMhz24;
        } else {
            return UNSPECIFIED;
        }
    }
    if (band == BAND_5_GHZ) {
        int bandFirstChMum5 = 32;
        int bandLastChMum5 = 173;
        int bandStartFreqMhz5 = 5160;
        if (channel >= bandFirstChMum5 && channel <= bandLastChMum5) {
            return ((channel - bandFirstChMum5) * channelTimes) + bandStartFreqMhz5;
        } else {
            return UNSPECIFIED;
        }
    }
    if (band == BAND_6_GHZ) {
        int bandFirstChMum6 = 1;
        int bandLastChMum6 = 233;
        int bandStartFreqMhz6 = 5955;
        int bandCla2Freq136ChMhz6 = 5935;
        int channelType = 2;
        if (channel >= bandFirstChMum6 && channel <= bandLastChMum6) {
            if (channel == channelType) {
                return bandCla2Freq136ChMhz6;
            }
            return ((channel - bandFirstChMum6) * channelTimes) + bandStartFreqMhz6;
        } else {
            return UNSPECIFIED;
        }
    }
    return UNSPECIFIED;
}

static int GetHeChanWidth(int heChannelWidth, int centerSegFreq0, int centerSegFreq1)
{
    int channelWidth = 2;
    int segFreqValue = 8;
    if (heChannelWidth == 0) {
        return CHAN_WIDTH_20MHZ;
    } else if (heChannelWidth == 1) {
        return CHAN_WIDTH_40MHZ;
    } else if (heChannelWidth == channelWidth) {
        return CHAN_WIDTH_80MHZ;
    } else if (abs(centerSegFreq1 - centerSegFreq0) == segFreqValue) {
        return CHAN_WIDTH_160MHZ;
    } else {
        return CHAN_WIDTH_80MHZ_MHZ;
    }
}

static int GetHeCentFreq(int centerSegFreq)
{
    if (centerSegFreq == 0) {
        return 0;
    }
    return ConvertChanToFreqMhz(centerSegFreq, BAND_6_GHZ);
}

static int GetHtChanWidth(int secondOffsetChannel)
{
    if (secondOffsetChannel != 0) {
        return CHAN_WIDTH_40MHZ;
    } else {
        return CHAN_WIDTH_20MHZ;
    }
}

static int GetHtCentFreq0(int primaryFrequency, int secondOffsetChannel)
{
    if (secondOffsetChannel != 0) {
        int freqValue = 10;
        int offsetChannle = 3;
        if (secondOffsetChannel == 1) {
            return primaryFrequency + freqValue;
        } else if (secondOffsetChannel == offsetChannle) {
            return primaryFrequency - freqValue;
        } else {
            HDF_LOGE("error on get centFreq0");
            return 0;
        }
    } else {
        return primaryFrequency;
    }
}

static int GetVhtChanWidth(int channelType, int centerFrequencyIndex1, int centerFrequencyIndex2)
{
    int freqValue = 8;
    if (channelType == 0) {
        return UNSPECIFIED;
    } else if (centerFrequencyIndex2 == 0) {
        return CHAN_WIDTH_80MHZ;
    } else if (abs(centerFrequencyIndex1 - centerFrequencyIndex2) == freqValue) {
        return CHAN_WIDTH_160MHZ;
    } else {
        return CHAN_WIDTH_80MHZ_MHZ;
    }
}

static int GetVhtCentFreq(int channelType, int centerFrequencyIndex)
{
    if (centerFrequencyIndex == 0 || channelType == 0) {
        return 0;
    } else {
        return ConvertChanToFreqMhz(centerFrequencyIndex, BAND_5_GHZ);
    }
}

static int HexStringToString(const char *str, char *out)
{
    unsigned len = strlen(str);
    if ((len & 1) != 0) {
        return -1;
    }
    const int hexShiftNum = 4;
    for (unsigned i = 0, j = 0; i + 1 < len; ++i) {
        int8_t high = IsValidHexCharAndConvert(str[i]);
        int8_t low = IsValidHexCharAndConvert(str[++i]);
        if (high < 0 || low < 0) {
            return -1;
        }
        char tmp = ((high << hexShiftNum) | (low & 0x0F));
        out[j] = tmp;
        ++j;
    }
    return 0;
}

static bool GetChanWidthCenterFreqVht(ScanInfo *pcmd, ScanInfoElem* infoElem)
{
    if ((pcmd == NULL) || (infoElem == NULL)) {
        HDF_LOGE("pcmd or infoElem is NULL.");
        return false;
    }
    if ((infoElem->content == NULL) || ((unsigned int)infoElem->size < VHT_INFO_SIZE)) {
        return false;
    }
    int channelType = infoElem->content[COLUMN_INDEX_ZERO] & UINT8_MASK;
    int centerFrequencyIndex1 = infoElem->content[COLUMN_INDEX_ONE] & UINT8_MASK;
    int centerFrequencyIndex2 = infoElem->content[COLUMN_INDEX_TWO] & UINT8_MASK;
    pcmd->isVhtInfoExist = 1;
    pcmd->channelWidth = GetVhtChanWidth(channelType, centerFrequencyIndex1, centerFrequencyIndex2);
    if ((unsigned int)pcmd->channelWidth == UNSPECIFIED) {
        return false;
    }
    pcmd->centerFrequency0 = GetVhtCentFreq(channelType, centerFrequencyIndex1);
    pcmd->centerFrequency1 = GetVhtCentFreq(channelType, centerFrequencyIndex2);
    return true;
}

static bool GetChanWidthCenterFreqHe(ScanInfo *pcmd, ScanInfoElem* infoElem)
{
    if ((pcmd == NULL) || (infoElem == NULL)) {
        HDF_LOGE("pcmd or iesNeedParse is NULL.");
        return false;
    }
    if ((infoElem->content == NULL) || ((unsigned int)infoElem->size < (HE_OPER_BASIC_LEN + 1))) {
        return false;
    }
    if (infoElem->content[0] != EXT_HE_OPER_EID) {
        return false;
    }
    char* content = infoElem->content + 1;
    bool isVhtInfoExist = (content[COLUMN_INDEX_ONE] & VHT_OPER_INFO_EXTST_MASK) != 0;
    bool is6GhzInfoExist = (content[COLUMN_INDEX_TWO] & GHZ_HE_INFO_EXIST_MASK_6) != 0;
    bool coHostedBssPresent = (content[COLUMN_INDEX_ONE] & BSS_EXIST_MASK) != 0;
    int expectedLen = HE_OPER_BASIC_LEN + (isVhtInfoExist ? COLUMN_INDEX_THREE : 0) +
        (coHostedBssPresent ? 1 : 0) + (is6GhzInfoExist ? COLUMN_INDEX_FIVE : 0);
    pcmd->isHeInfoExist = 1;
    if (infoElem->size < expectedLen) {
        return false;
    }
    if (is6GhzInfoExist) {
        int startIndx = VHT_OPER_INFO_BEGIN_INDEX + (isVhtInfoExist ? COLUMN_INDEX_THREE : 0) +
            (coHostedBssPresent ? 1 : 0);
        int heChannelWidth = content[startIndx + 1] & GHZ_HE_WIDTH_MASK_6;
        int centerSegFreq0 = content[startIndx + COLUMN_INDEX_TWO] & UINT8_MASK;
        int centerSegFreq1 = content[startIndx + COLUMN_INDEX_THREE] & UINT8_MASK;
        pcmd->channelWidth = GetHeChanWidth(heChannelWidth, centerSegFreq0, centerSegFreq1);
        pcmd->centerFrequency0 = GetHeCentFreq(centerSegFreq0);
        pcmd->centerFrequency1 = GetHeCentFreq(centerSegFreq1);
        return true;
    }
    if (isVhtInfoExist) {
        struct ScanInfoElem vhtInformation = {0};
        vhtInformation.id = VHT_OPER_EID;
        vhtInformation.size = VHT_INFO_SIZE;
        vhtInformation.content = content + VHT_OPER_INFO_BEGIN_INDEX;
        return GetChanWidthCenterFreqVht(pcmd, &vhtInformation);
    }
    return false;
}

static bool GetChanWidthCenterFreqHt(ScanInfo *pcmd, ScanInfoElem* infoElem)
{
    const int offsetBit = 0x3;
    if ((pcmd == NULL) || (infoElem == NULL)) {
        HDF_LOGE("pcmd or infoElem is NULL.");
        return false;
    }
    if ((infoElem->content == NULL) || ((unsigned int)infoElem->size < HT_INFO_SIZE)) {
        return false;
    }
    int secondOffsetChannel = infoElem->content[1] & offsetBit;
    pcmd->channelWidth = GetHtChanWidth(secondOffsetChannel);
    pcmd->centerFrequency0 = GetHtCentFreq0(pcmd->freq, secondOffsetChannel);
    pcmd->isHtInfoExist = 1;
    return true;
}

static bool GetChanMaxRates(ScanInfo *pcmd, ScanInfoElem* infoElem)
{
    if ((pcmd == NULL) || (infoElem == NULL)) {
        HDF_LOGE("pcmd or infoElem is NULL.");
        return false;
    }
    if ((infoElem->content == NULL) || ((unsigned int)infoElem->size < SUPP_RATES_SIZE)) {
        return false;
    }
    int maxIndex = infoElem->size - 1;
    int maxRates = infoElem->content[maxIndex] & UINT8_MASK;
    pcmd->maxRates = maxRates;
    return true;
}

static bool GetChanExtMaxRates(ScanInfo *pcmd, ScanInfoElem* infoElem)
{
    if ((pcmd == NULL) || (infoElem == NULL)) {
        HDF_LOGE("pcmd or infoElem is NULL.");
        return false;
    }
    if ((infoElem->content == NULL) || ((unsigned int)infoElem->size < EXT_SUPP_RATES_SIZE)) {
        return false;
    }
    int maxIndex = infoElem->size - 1;
    int maxRates = infoElem->content[maxIndex] & UINT8_MASK;
    pcmd->extMaxRates = maxRates;
    return true;
}

static void GetChanWidthCenterFreq(ScanInfo *pcmd, struct NeedParseIe* iesNeedParse)
{
    if ((pcmd == NULL) || (iesNeedParse == NULL)) {
        HDF_LOGE("pcmd or iesNeedParse is NULL.");
        return;
    }

    if ((iesNeedParse->ieExtern != NULL) && GetChanWidthCenterFreqHe(pcmd, iesNeedParse->ieExtern)) {
        return;
    }
    if ((iesNeedParse->ieVhtOper != NULL) && GetChanWidthCenterFreqVht(pcmd, iesNeedParse->ieVhtOper)) {
        return;
    }
    if ((iesNeedParse->ieHtOper != NULL) && GetChanWidthCenterFreqHt(pcmd, iesNeedParse->ieHtOper)) {
        return;
    }
    if ((iesNeedParse->ieMaxRate != NULL) && GetChanMaxRates(pcmd, iesNeedParse->ieMaxRate)) {
        HDF_LOGE("pcmd maxRates is %{public}d.", pcmd->maxRates);
        return;
    }
    if ((iesNeedParse->ieExtMaxRate != NULL) && GetChanExtMaxRates(pcmd, iesNeedParse->ieExtMaxRate)) {
        HDF_LOGE("pcmd extMaxRates is %{public}d.", pcmd->extMaxRates);
        return;
    }
    if (iesNeedParse->ieErp != NULL) {
        HDF_LOGE("pcmd isErpExist is true.");
        pcmd->isErpExist = 1;
        return;
    }
    HDF_LOGE("GetChanWidthCenterFreq fail.");
    return;
}

static void RecordIeNeedParse(unsigned int id, ScanInfoElem* ie, struct NeedParseIe* iesNeedParse)
{
    if (iesNeedParse == NULL) {
        return;
    }
    switch (id) {
        case EXT_EXIST_EID:
            iesNeedParse->ieExtern = ie;
            break;
        case VHT_OPER_EID:
            iesNeedParse->ieVhtOper = ie;
            break;
        case HT_OPER_EID:
            iesNeedParse->ieHtOper = ie;
            break;
        case SUPPORTED_RATES_EID:
            iesNeedParse->ieMaxRate = ie;
            break;
        case ERP_EID:
            iesNeedParse->ieErp = ie;
            break;
        case EXT_SUPPORTED_RATES_EID:
            iesNeedParse->ieExtMaxRate = ie;
            break;
        default:
            break;
    }
}

static void GetInfoElems(int length, int end, char *srcBuf, ScanInfo *pcmd)
{
    int len;
    int start = end + 1;
    int last = end + 1;
    int lenValue = 2;
    int lastLength = 3;
    int remainingLength = length - start;
    int infoElemsSize = 0;
    struct NeedParseIe iesNeedParse = {NULL};
    ScanInfoElem* infoElemsTemp = (ScanInfoElem *)calloc(MAX_INFO_ELEMS_SIZE, sizeof(ScanInfoElem));
    if (infoElemsTemp == NULL) {
        return;
    }
    while (remainingLength > 1 && start < length) {
        if (srcBuf[start] == '[') {
            ++start;
            infoElemsTemp[infoElemsSize].id = atoi(srcBuf + start);
        }
        if (srcBuf[start] != ' ') {
            ++start;
        }
        if (srcBuf[last] != ']') {
            ++last;
            continue;
        }
        len = last - start - 1;
        infoElemsTemp[infoElemsSize].size = len / lenValue;
        infoElemsTemp[infoElemsSize].content = (char *)calloc(len / lenValue + 1, sizeof(char));
        if (infoElemsTemp[infoElemsSize].content == NULL) {
            break;
        }
        ++start;
        srcBuf[last] = '\0';
        HexStringToString(srcBuf + start, infoElemsTemp[infoElemsSize].content);
        if ((length - last) > lastLength) { // make sure there is no useless character
            last = last + 1;
        }
        start = last;
        remainingLength = length - last;
        RecordIeNeedParse(infoElemsTemp[infoElemsSize].id, &infoElemsTemp[infoElemsSize], &iesNeedParse);
        ++infoElemsSize;
    }
    GetChanWidthCenterFreq(pcmd, &iesNeedParse);

    // clear old infoElems first
    if (pcmd->infoElems != NULL) {
        for (int i = 0; i < pcmd->ieSize; i++) {
            if (pcmd->infoElems[i].content != NULL) {
                free(pcmd->infoElems[i].content);
                pcmd->infoElems[i].content = NULL;
            }
        }
        free(pcmd->infoElems);
        pcmd->infoElems = NULL;
    }
    pcmd->infoElems = infoElemsTemp;
    pcmd->ieSize = infoElemsSize;
    return;
}

int DelScanInfoLine(ScanInfo *pcmd, char *srcBuf, int length)
{
    int columnIndex = 0;
    int start = 0;
    int end = 0;
    int fail = 0;
    while (end < length) {
        if (srcBuf[end] != '\t') {
            ++end;
            continue;
        }
        srcBuf[end] = '\0';
        if (columnIndex == COLUMN_INDEX_ZERO) {
            if (strcpy_s(pcmd->bssid, sizeof(pcmd->bssid), srcBuf + start) != EOK) {
                fail = 1;
                break;
            }
        } else if (columnIndex == COLUMN_INDEX_ONE) {
            pcmd->freq = atoi(srcBuf + start);
        } else if (columnIndex == COLUMN_INDEX_TWO) {
            pcmd->siglv = atoi(srcBuf + start);
        } else if (columnIndex == COLUMN_INDEX_THREE) {
            if (strcpy_s(pcmd->flags, sizeof(pcmd->flags), srcBuf + start) != EOK) {
                fail = 1;
                break;
            }
        } else if (columnIndex == COLUMN_INDEX_FOUR) {
            if (strcpy_s(pcmd->ssid, sizeof(pcmd->ssid), srcBuf + start) != EOK) {
                fail = 1;
                break;
            }
            printf_decode((u8 *)pcmd->ssid, sizeof(pcmd->ssid), pcmd->ssid);
            GetInfoElems(length, end, srcBuf, pcmd);
            start = length;
            break;
        }
        ++columnIndex;
        ++end;
        start = end;
    }
    if (fail == 0 && start < length) {
        if (strcpy_s(pcmd->flags, sizeof(pcmd->flags), srcBuf + start) != EOK) {
            fail = 1;
        }
    }
    return fail;
}

static int WpaCliCmdScanInfo(WifiWpaStaInterface *this, unsigned char *resultBuf,
    unsigned int *resultBufLen)
{
    HDF_LOGI("enter WpaCliCmdScanInfo2");
    if (this == NULL || resultBuf == NULL || resultBufLen == NULL) {
        return -1;
    }
    char cmd[CMD_BUFFER_SIZE] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s SCAN_RESULTS", this->ifname) < 0) {
        HDF_LOGE("snprintf err");
        return -1;
    }
    if (WpaCliCmd(cmd, (char*)resultBuf, REPLY_BUF_LENGTH) != 0) {
        HDF_LOGE("WpaCliCmd SCAN_RESULTS fail");
        return -1;
    }
    *resultBufLen = strlen((char*)resultBuf);
    HDF_LOGI("WpaCliCmdScanInfo2, resultBufLen = %{public}d", *resultBufLen);
    return 0;
}

static int WpaCliCmdGetSignalInfo(WifiWpaStaInterface *this, WpaSignalInfo *info)
{
    if (this == NULL || info == NULL) {
        return -1;
    }
    char cmd[CMD_BUFFER_SIZE] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s SIGNAL_POLL", this->ifname) < 0) {
        HDF_LOGE("snprintf err");
        return -1;
    }
    char *buf = (char *)calloc(REPLY_BUF_LENGTH, sizeof(char));
    if (buf == NULL) {
        return -1;
    }
    if (WpaCliCmd(cmd, buf, REPLY_BUF_LENGTH) != 0) {
        free(buf);
        return -1;
    }
    char *savedPtr = NULL;
    char *token = strtok_r(buf, "=", &savedPtr);
    while (token != NULL) {
        if (strcmp(token, "RSSI") == 0) {
            token = strtok_r(NULL, "\n", &savedPtr);
            info->signal = atoi(token);
        } else if (strcmp(token, "LINKSPEED") == 0) {
            token = strtok_r(NULL, "\n", &savedPtr);
            info->txrate = atoi(token);
        } else if (strcmp(token, "NOISE") == 0) {
            token = strtok_r(NULL, "\n", &savedPtr);
            info->noise = atoi(token);
        } else if (strcmp(token, "FREQUENCY") == 0) {
            token = strtok_r(NULL, "\n", &savedPtr);
            info->frequency = atoi(token);
        } else {
            strtok_r(NULL, "\n", &savedPtr);
        }
        token = strtok_r(NULL, "=", &savedPtr);
    }
    free(buf);
    return 0;
}

/* mode： 0 - enabled, 1 - disabled. */
static int WpaCliCmdWpaSetPowerMode(WifiWpaStaInterface *this, bool mode)
{
    HDF_LOGI("Enter WpaCliCmdWpaSetPowerMode, mode:%{public}d.", mode);
    if (this == NULL) {
        HDF_LOGE("WpaCliCmdWpaSetPowerMode, this is NULL.");
        return -1;
    }
    char cmd[CMD_BUFFER_SIZE] = {0};
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s DRIVER POWERMODE %d",
        this->ifname, mode) < 0) {
        HDF_LOGE("WpaCliCmdWpaSetPowerMode, snprintf_s err");
        return -1;
    }
    return WpaCliCmd(cmd, buf, sizeof(buf));
}

static int WpaCliCmdWpaSetSuspendMode(WifiWpaStaInterface *this, bool mode)
{
    HDF_LOGI("Enter WpaCliCmdWpaSetSuspendMode, mode:%{public}d.", mode);
    if (this == NULL) {
        HDF_LOGE("WpaCliCmdWpaSetSuspendMode, this is NULL.");
        return -1;
    }
    char cmd[CMD_BUFFER_SIZE] = {0};
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s DRIVER SETSUSPENDMODE %d",
        this->ifname, mode) < 0) {
        HDF_LOGE("WpaCliCmdWpaSetSuspendMode, snprintf_s err");
        return -1;
    }
    return WpaCliCmd(cmd, buf, sizeof(buf));
}

static int WpaCliCmdStaShellCmd(WifiWpaStaInterface *this, const char *params)
{
    if (this == NULL || params == NULL) {
        return -1;
    }
    char cmd[CMD_BUFFER_SIZE] = {0};
    char buf[REPLY_BUF_SMALL_LENGTH] = {0};
    if (snprintf_s(cmd, sizeof(cmd), sizeof(cmd) - 1, "IFNAME=%s STA_SHELL %s",
        this->ifname, params) < 0) {
        HDF_LOGE("WpaCliCmdStaShellCmd, snprintf_s err");
        return -1;
    }
    return WpaCliCmd(cmd, buf, sizeof(buf));
}

WifiWpaStaInterface *GetWifiStaInterface(const char *name)
{
    WifiWpaStaInterface *p = g_wpaStaInterface;
    char staNo[STA_NO_LEN + 1] = {0};
    while (p != NULL) {
        if (strcmp(p->ifname, name) == 0) {
            return p;
        }
        p = p->next;
    }
    p = (WifiWpaStaInterface *)calloc(1, sizeof(WifiWpaStaInterface));
    if (p == NULL) {
        return NULL;
    }
    strcpy_s(p->ifname, sizeof(p->ifname), name);
    if(strncpy_s(staNo, sizeof(staNo), name + strlen("wlan"), STA_NO_LEN) != EOK) {
        HDF_LOGE("GetWifiStaInterface, strncpy_s err");
        free(p);
        return NULL;
    }
    p->staNo =  atoi(staNo);
    p->wpaCliCmdStatus = WpaCliCmdStatus;
    p->wpaCliCmdAddNetworks = WpaCliCmdAddNetworks;
    p->wpaCliCmdReconnect = WpaCliCmdReconnect;
    p->wpaCliCmdReassociate = WpaCliCmdReassociate;
    p->wpaCliCmdDisconnect = WpaCliCmdDisconnect;
    p->wpaCliCmdSaveConfig = WpaCliCmdSaveConfig;
    p->wpaCliCmdSetNetwork = WpaCliCmdSetNetwork;
    p->wpaCliCmdEnableNetwork = WpaCliCmdEnableNetwork;
    p->wpaCliCmdSelectNetwork = WpaCliCmdSelectNetwork;
    p->wpaCliCmdDisableNetwork = WpaCliCmdDisableNetwork;
    p->wpaCliCmdRemoveNetwork = WpaCliCmdRemoveNetwork;
    p->wpaCliCmdGetNetwork = WpaCliCmdGetNetwork;
    p->wpaCliCmdWpsPbc = WpaCliCmdWpsPbc;
    p->wpaCliCmdWpsPin = WpaCliCmdWpsPin;
    p->wpaCliCmdWpsCancel = WpaCliCmdWpsCancel;
    p->wpaCliCmdPowerSave = WpaCliCmdPowerSave;
    p->wpaCliCmdSetRoamConfig = WpaCliCmdSetRoamConfig;
    p->wpaCliCmdSetCountryCode = WpaCliCmdSetCountryCode;
    p->wpaCliCmdGetCountryCode = WpaCliCmdGetCountryCode;
    p->wpaCliCmdSetAutoConnect = WpaCliCmdSetAutoConnect;
    p->wpaCliCmdWpaBlockListClear = WpaCliCmdWpaBlockListClear;
    p->wpaCliCmdListNetworks = WpaCliCmdListNetworks;
    p->wpaCliCmdScan = WpaCliCmdScan;
    p->wpaCliCmdScanInfo = WpaCliCmdScanInfo;
    p->wpaCliCmdGetSignalInfo = WpaCliCmdGetSignalInfo;
    p->wpaCliCmdWpaSetSuspendMode = WpaCliCmdWpaSetSuspendMode;
    p->wpaCliCmdWpaSetPowerMode = WpaCliCmdWpaSetPowerMode;
    p->wpaCliCmdGetScanSsid = WpaCliCmdGetScanSsid;
    p->wpaCliCmdGetPskPassphrase = WpaCliCmdGetPskPassphrase;
    p->wpaCliCmdGetPsk = WpaCliCmdGetPsk;
    p->wpaCliCmdWepKey = WpaCliCmdWepKey;
    p->wpaCliCmdWepKeyTxKeyIdx = WpaCliCmdWepKeyTxKeyIdx;
    p->wpaCliCmdGetRequirePmf = WpaCliCmdGetRequirePmf;
    p->wpaCliCmdGetConnectionCapabilities = WpaCliCmdGetConnectionCapabilities;
    p->wpaCliCmdStaShellCmd = WpaCliCmdStaShellCmd;
    p->next = g_wpaStaInterface;
    g_wpaStaInterface = p;

    return p;
}

void ReleaseWifiStaInterface(int staNo)
{
    char name[MAX_NAME_LEN] = {0};
    if (snprintf_s(name, sizeof(name), sizeof(name) - 1, "wlan%d", staNo) < 0) {
        HDF_LOGE("snprintf error");
        return;
    }
    WifiWpaStaInterface *p = g_wpaStaInterface;
    WifiWpaStaInterface *prev = NULL;
    while (p != NULL) {
        if (strcmp(p->ifname, name) == 0) {
            break;
        }
        prev = p;
        p = p->next;
    }
    if (p == NULL) {
        return;
    }
    if (prev == NULL) {
        g_wpaStaInterface = p->next;
    } else {
        prev->next = p->next;
    }
    free(p);
    return;
}

WifiWpaStaInterface *TraversalWifiStaInterface(void)
{
    return g_wpaStaInterface;
}

int GetStaInterfaceNo(const char *ifName)
{
    WifiWpaStaInterface *p = g_wpaStaInterface;
    while (p != NULL) {
        if (strcmp(p->ifname, ifName) == 0) {
            return p->staNo;
        }
        p = p->next;
    }
    return -1;
}
