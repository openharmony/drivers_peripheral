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

#include <string>
#include "wifi_hal.h"
#include "wifi_ioctl.h"
#include <securec.h>
#include <osal_mem.h>
#include <hdf_log.h>

static const std::string POWER_MODE_SLEEP = "sleep";
static const std::string POWER_MODE_THIRD = "third";
static const std::string POWER_MODE_INIT = "init";

static int32_t SendCommandToDriverByInterfaceName(int32_t sock, char *cmd, const char *interfaceName)
{
    struct ifreq ifr;
    int32_t ret = -1;
    WifiPrivCmd privCmd;

    if (cmd == nullptr || interfaceName == nullptr) {
        HDF_LOGE("SendCommandToDriver: cmd is null or interfaceName is null.");
        return HAL_INVALID_ARGS;
    }
    (void)memset_s(&ifr, sizeof(ifr), 0, sizeof(ifr));
    (void)memset_s(&privCmd, sizeof(privCmd), 0, sizeof(privCmd));
#if (defined(LINUX_VERSION_CODE) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0))
    privCmd.buf = static_cast<unsigned char *>(OsalMemCalloc(MAX_PRIV_CMD_SIZE));
    if (privCmd.buf == nullptr) {
        HDF_LOGE("%{public}s :OsalMemCalloc fail", __func__);
        return HAL_NONE;
    }
#endif
    do {
        if (memcpy_s(privCmd.buf, MAX_PRIV_CMD_SIZE, cmd, MAX_CMD_LEN) != EOK) {
            HDF_LOGE("memcpy_s privCmd fail");
            break;
        }
        privCmd.size = MAX_PRIV_CMD_SIZE;
        privCmd.len = MAX_CMD_LEN;
        ifr.ifr_data = reinterpret_cast<char *>(&privCmd);
        if (strcpy_s(ifr.ifr_name, IFNAMSIZ, interfaceName) != EOK) {
            HDF_LOGE("strcpy_s ifr fail");
            break;
        }
        ret = ioctl(sock, SIOCDEVPRIVATE + 1, &ifr);
        if (ret < 0) {
            HDF_LOGE("ioctl %{public}s fail, errno = %{public}d: %{public}s", cmd, errno, strerror(errno));
            if (errno == EOPNOTSUPP) {
                ret = HAL_NOT_SUPPORTED;
            } else {
                ret = HAL_NONE;
            }
        }
        (void)memset_s(cmd, MAX_CMD_LEN, 0, MAX_CMD_LEN);
        if (memcpy_s(cmd, MAX_CMD_LEN, privCmd.buf, MAX_CMD_LEN - 1) != EOK) {
            HDF_LOGE("%{public}s :memcpy_s cmd fail", __func__);
            ret = HAL_NONE;
            break;
        }
    } while (0);
#if (defined(LINUX_VERSION_CODE) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0))
    OsalMemFree(privCmd.buf);
#endif
    return ret;
}

static int SendCmdIoctl(const char *ifName, char *cmdBuf)
{
    int ret = -1;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        HDF_LOGE("%s :socket error", __func__);
        return ret;
    }

    ret = SendCommandToDriverByInterfaceName(sock, cmdBuf, ifName);
    HDF_LOGI("%s : ret: %d", __func__, ret);
    close(sock);
    return ret;
}

WifiError GetPowerMode(const char *ifName, int *mode)
{
    return HAL_SUCCESS;
}

WifiError SetPowerMode(const char *ifName, int mode)
{
    return HAL_SUCCESS;
}

WifiError SetTxPower(const char *ifName, int mode)
{
    return HAL_SUCCESS;
}

WifiError EnablePowerMode(const char *ifName, int mode)
{
    return HAL_SUCCESS;
}

uint32_t WifiGetSupportedFeatureSet(const char *ifName)
{
    uint32_t ret = 0;
    char cmdBuf[MAX_CMD_LEN] = { 0 };
    size_t cmdLen = strlen(CMD_GET_WIFI_PRIV_FEATURE_CAPABILITY);

    if (ifName == nullptr) {
        HDF_LOGE("WifiGetSupportedFeatureSet iface is null.");
        return ret;
    }
    if (memcpy_s(cmdBuf, MAX_CMD_LEN, CMD_GET_WIFI_PRIV_FEATURE_CAPABILITY, cmdLen) != EOK) {
        HDF_LOGE("%{public}s :memcpy_s cmdBuf fail", __FUNCTION__);
        return ret;
    }
    if (SendCmdIoctl(ifName, cmdBuf) == 0) {
        ret = *(reinterpret_cast<uint32_t *>(cmdBuf));
    } else {
        HDF_LOGI("WifiGetSupportedFeatureSet failed");
    }
    return ret;
}

uint32_t GetChipCaps(const char *ifName)
{
    uint32_t ret = 0;
    char cmdBuf[MAX_CMD_LEN] = { 0 };
    size_t cmdLen = strlen(CMD_WIFI_CATEGORY);

    if (ifName == nullptr) {
        HDF_LOGE("HisiGetWifiCategory ifName is null.");
        return ret;
    }
    if (memcpy_s(cmdBuf, MAX_CMD_LEN, CMD_WIFI_CATEGORY, cmdLen) != EOK) {
        HDF_LOGE("%{public}s :memcpy_s cmdBuf fail", __FUNCTION__);
        return ret;
    }
    if (SendCmdIoctl(ifName, cmdBuf) == 0) {
        if (strncmp(cmdBuf, CMD_WIFI_CATEGORY, cmdLen) != 0) {
            ret = *(reinterpret_cast<uint8_t *>(cmdBuf));
        }
    } else {
        HDF_LOGI("GetChipCaps failed");
    }
    return ret;
}

