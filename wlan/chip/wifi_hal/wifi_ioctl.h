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

#ifndef WIFI_IOCTL_H
#define WIFI_IOCTL_H

#include <net/if.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <netlink-private/types.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/handlers.h>
#include <linux/version.h>
#include <securec.h>
#include <cstdio>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define PRIMARY_ID_POWER_MODE   0x8bfd
#define SECONDARY_ID_POWER_MODE 0x101
#define SET_POWER_MODE_SLEEP     "pow_mode sleep"
#define SET_POWER_MODE_INIT      "pow_mode init"
#define SET_POWER_MODE_THIRD     "pow_mode third"
#define GET_POWER_MODE           "get_pow_mode"
#define CMD_SET_STA_PM_ON        "SET_STA_PM_ON"
#define CMD_WIFI_CATEGORY "CMD_WIFI_CATEGORY"
#define CMD_GET_WIFI_PRIV_FEATURE_CAPABILITY "GET_WIFI_PRIV_FEATURE_CAPABILITY"
#define WIFI_POWER_MODE_SLEEPING 0
#define WIFI_POWER_MODE_GENERAL 1
#define WIFI_POWER_MODE_THROUGH_WALL 2
#define WIFI_POWER_MODE_NUM 3
#define MAX_CMD_LEN 64
#define MAX_PRIV_CMD_SIZE 4096
#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + ((c) > 255 ? 255 : (c)))
#endif

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
#if (defined(LINUX_VERSION_CODE) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0))
    uint8_t *buf;
    uint32_t size;
    uint32_t len;
#else
    uint32_t size;
    uint32_t len;
    uint8_t *buf;
#endif
} WifiPrivCmd;

WifiError GetPowerMode(const char *ifName, int *mode);
WifiError SetPowerMode(const char *ifName, int mode);
WifiError EnablePowerMode(const char *ifName, int mode);
uint32_t GetChipCaps(const char *ifName);
uint32_t WifiGetSupportedFeatureSet(const char *ifName);
WifiError SetTxPower(const char *ifName, int mode);

#endif
