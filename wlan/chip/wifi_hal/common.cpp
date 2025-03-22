
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

#include <cstdint>
#include <fcntl.h>
#include <sys/socket.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <linux/rtnetlink.h>
#include <netpacket/packet.h>
#include <linux/filter.h>
#include <linux/errqueue.h>

#include <linux/pkt_sched.h>
#include <netlink/object-api.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/handlers.h>

#include "wifi_hal.h"
#include "common.h"
#include "cpp_bindings.h"
#include "securec.h"

#define MAX_CMD_SIZE 64

/* test mode flag for halutil only */
bool g_halutilMode = false;
static std::shared_mutex g_rwMutex;

std::shared_lock<std::shared_mutex> ReadLockData()
{
    return std::shared_lock<std::shared_mutex>{g_rwMutex};
}

std::unique_lock<std::shared_mutex> WriteLock()
{
    return std::unique_lock<std::shared_mutex>{g_rwMutex};
}
InterfaceInfo *GetIfaceInfo(wifiInterfaceHandle handle)
{
    return (InterfaceInfo *)handle;
}

wifiHandle GetWifiHandle(wifiInterfaceHandle handle)
{
    InterfaceInfo *info = GetIfaceInfo(handle);
    if (info != nullptr) {
        return GetIfaceInfo(handle)->handle;
    }
    return nullptr;
}

HalInfo *GetHalInfo(wifiHandle handle)
{
    return (HalInfo *)handle;
}

HalInfo *GetHalInfo(wifiInterfaceHandle handle)
{
    return GetHalInfo(GetWifiHandle(handle));
}

wifiHandle GetWifiHandle(HalInfo *info)
{
    return (wifiHandle)info;
}

wifiInterfaceHandle GetIfaceHandle(InterfaceInfo *info)
{
    return (wifiInterfaceHandle)info;
}

WifiError WifiRegisterHandler(wifiHandle handle, int cmd, nl_recvmsg_msg_cb_t func, void *arg)
{
    HalInfo *info = (HalInfo *)handle;
    pthread_mutex_lock(&info->cbLock);
    WifiError result = HAL_OUT_OF_MEMORY;

    if (info->numEventCb < info->allocEventCb) {
        info->eventCb[info->numEventCb].nlCmd  = cmd;
        info->eventCb[info->numEventCb].vendorId  = 0;
        info->eventCb[info->numEventCb].vendorSubcmd  = 0;
        info->eventCb[info->numEventCb].cbFunc = func;
        info->eventCb[info->numEventCb].cbArg  = arg;
        HDF_LOGD("Successfully added event handler %{public}p:%{public}p for command %{public}d at %{public}d",
            arg, func, cmd, info->numEventCb);
        info->numEventCb++;
        result = HAL_SUCCESS;
    }

    pthread_mutex_unlock(&info->cbLock);
    return result;
}

WifiError WifiRegisterVendorHandler(wifiHandle handle,
    uint32_t id, int subcmd, nl_recvmsg_msg_cb_t func, void *arg)
{
    HalInfo *info = (HalInfo *)handle;
    pthread_mutex_lock(&info->cbLock);
    WifiError result = HAL_OUT_OF_MEMORY;
    if (info->numEventCb < info->allocEventCb) {
        int i = 0;
        bool isUpdate = false;
        for (i = 0; i < info->numEventCb; i++) {
            if ((info->eventCb[i].nlCmd == NL80211_CMD_VENDOR) &&
                (info->eventCb[i].vendorId == id) &&
                (info->eventCb[i].vendorSubcmd == subcmd)) {
                isUpdate = true;
                break;
            }
        }
        if (isUpdate) {
            info->eventCb[i].cbFunc = func;
            info->eventCb[i].cbArg = arg;
        } else {
            info->eventCb[info->numEventCb].nlCmd  = NL80211_CMD_VENDOR;
            info->eventCb[info->numEventCb].vendorId  = id;
            info->eventCb[info->numEventCb].vendorSubcmd  = subcmd;
            info->eventCb[info->numEventCb].cbFunc = func;
            info->eventCb[info->numEventCb].cbArg  = arg;
            info->numEventCb++;
        }
        HDF_LOGI("%{public}s ""event handler for vendor 0x%{public}0x and subcmd 0x%{public}0x at %{public}d",
            isUpdate ? "Updated" : "Added", id, subcmd, info->numEventCb);
        result = HAL_SUCCESS;
    }

    pthread_mutex_unlock(&info->cbLock);
    return result;
}

void WifiUnregisterHandler(wifiHandle handle, int cmd)
{
    HalInfo *info = (HalInfo *)handle;

    if (cmd == NL80211_CMD_VENDOR) {
        HDF_LOGE("Must use WifiUnregisterVendorHandler to remove vendor handlers");
        return;
    }

    pthread_mutex_lock(&info->cbLock);

    for (int i = 0; i < info->numEventCb; i++) {
        if (info->eventCb[i].nlCmd == cmd) {
            HDF_LOGD("Successfully removed event handler for cmd = 0x%{public}0x from %{public}d",
                     cmd, i);

            if (memmove_s(&info->eventCb[i], (info->numEventCb - i) * sizeof(CbInfo), &info->eventCb[i + 1],
                (info->numEventCb - i - 1) * sizeof(CbInfo)) != EOK) {
                break;
            }
            info->numEventCb--;
            break;
        }
    }

    pthread_mutex_unlock(&info->cbLock);
}

void WifiUnregisterVendorHandlerWithoutLock(wifiHandle handle, uint32_t id, int subcmd)
{
    HalInfo *info = (HalInfo *)handle;

    for (int i = 0; i < info->numEventCb; i++) {
        if (info->eventCb[i].nlCmd == NL80211_CMD_VENDOR &&
            info->eventCb[i].vendorId == id &&
            info->eventCb[i].vendorSubcmd == subcmd) {
            HDF_LOGI("Successfully removed event handler for vendor 0x%{public}0x,"
                "subcmd 0x%{public}0x from %{public}d", id, subcmd, i);
            if (memmove_s(&info->eventCb[i], (info->numEventCb - i) * sizeof(CbInfo), &info->eventCb[i + 1],
                (info->numEventCb - i - 1) * sizeof(CbInfo)) != EOK) {
                break;
            }
            break;
        }
    }
}

void WifiUnregisterVendorHandler(wifiHandle handle, uint32_t id, int subcmd)
{
    HalInfo *info = (HalInfo *)handle;

    pthread_mutex_lock(&info->cbLock);
    WifiUnregisterVendorHandlerWithoutLock(handle, id, subcmd);
    pthread_mutex_unlock(&info->cbLock);
}


WifiError WifiRegisterCmd(wifiHandle handle, int id, WifiCommand *cmd)
{
    HalInfo *info = (HalInfo *)handle;

    HDF_LOGD("registering command %{public}d", id);

    WifiError result = HAL_OUT_OF_MEMORY;
    if (info == nullptr) {
        HDF_LOGE("wifi info is null");
        return result;
    }
    if (info->numCmd < info->allocCmd) {
        info->cmd[info->numCmd].id   = id;
        info->cmd[info->numCmd].cmd  = cmd;
        HDF_LOGD("Successfully added command %{public}d: at %{public}d", id, info->numCmd);
        info->numCmd++;
        result = HAL_SUCCESS;
    } else {
        HDF_LOGE("Failed to add command %{public}d: at %{public}d, reached MAX limit %{public}d",
            id, info->numCmd, info->allocCmd);
    }

    return result;
}

WifiCommand *WifiUnregisterCmd(wifiHandle handle, int id)
{
    HalInfo *info = (HalInfo *)handle;

    HDF_LOGD("un-registering command %{public}d", id);

    WifiCommand *cmd = nullptr;

    if (info->numCmd > MAX_CMD_SIZE) {
        HDF_LOGE("invilid cmd size");
        return cmd;
    }
    for (int i = 0; i < info->numCmd; i++) {
        if (info->cmd[i].id == id) {
            cmd = info->cmd[i].cmd;
            if (memmove_s(&info->cmd[i], (info->numCmd - i) * sizeof(CmdInfo), &info->cmd[i + 1],
                (info->numCmd - i - 1) * sizeof(CmdInfo)) != EOK) {
                break;
            }
            info->numCmd--;
            HDF_LOGD("Successfully removed command %{public}d: from %{public}d", id, i);
            break;
        }
    }

    if (!cmd) {
        HDF_LOGI("Failed to remove command %{public}d", id);
    }

    return cmd;
}

void WifiUnregisterCmd(wifiHandle handle, WifiCommand *cmd)
{
    HalInfo *info = (HalInfo *)handle;

    for (int i = 0; i < info->numCmd; i++) {
        if (info->cmd[i].cmd == cmd) {
            int id = info->cmd[i].id;
            if (memmove_s(&info->cmd[i], (info->numCmd - i) * sizeof(CmdInfo), &info->cmd[i + 1],
                (info->numCmd - i - 1) * sizeof(CmdInfo)) != EOK) {
                break;
            }
            info->numCmd--;
            HDF_LOGD("Successfully removed command %{public}d: from %{public}d", id, i);
            break;
        }
    }
}

void SetHautilMode(bool halutilMode)
{
    g_halutilMode = halutilMode;
}
bool GetGHalutilMode()
{
    return g_halutilMode;
}
