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
#include <unistd.h>
#include "sync.h"
#include "wifi_hal.h"
#include "common.h"
#include "cpp_bindings.h"
#include <sys/stat.h>

#define ARRAYSIZE(a)    (unsigned char)(sizeof(a) / sizeof((a)[0]))

#define HAL_VERSION "DEFAULT vendor HAL"

typedef enum {
    LOGGER_ATTRIBUTE_INVALID            = 0,
    LOGGER_ATTRIBUTE_DRIVER_VER         = 1,
    LOGGER_ATTRIBUTE_FW_VER         = 2,
    LOGGER_ATTRIBUTE_RING_ID            = 3,
    LOGGER_ATTRIBUTE_RING_NAME          = 4,
    LOGGER_ATTRIBUTE_RING_FLAGS         = 5,
    LOGGER_ATTRIBUTE_LOG_LEVEL          = 6,
    LOGGER_ATTRIBUTE_LOG_TIME_INTVAL        = 7,
    LOGGER_ATTRIBUTE_LOG_MIN_DATA_SIZE      = 8,
    LOGGER_ATTRIBUTE_FW_DUMP_LEN        = 9,
    LOGGER_ATTRIBUTE_FW_DUMP_DATA       = 10,
    LOGGER_ATTRIBUTE_FW_ERR_CODE        = 11,
    LOGGER_ATTRIBUTE_RING_DATA           = 12,
    LOGGER_ATTRIBUTE_RING_STATUS        = 13,
    LOGGER_ATTRIBUTE_RING_NUM           = 14,
    LOGGER_ATTRIBUTE_DRIVER_DUMP_LEN        = 15,
    LOGGER_ATTRIBUTE_DRIVER_DUMP_DATA       = 16,
    LOGGER_ATTRIBUTE_PKT_FATE_NUM       = 17,
    LOGGER_ATTRIBUTE_PKT_FATE_DATA      = 18,
    LOGGER_ATTRIBUTE_HANG_REASON        = 19,
    /* Add new attributes just above this */
    LOGGER_ATTRIBUTE_MAX
} LOGGER_ATTRIBUTE;

constexpr int32_t HAL_RESTART_ID = 2;

class SetRestartHandler : public WifiCommand {
    VendorHalRestartHandler mHandler;
    char *mBuff;
public:
    SetRestartHandler(wifiHandle handle, int id, VendorHalRestartHandler handler)
        : WifiCommand("SetRestartHandler", handle, id), mHandler(handler), mBuff(nullptr)
    { }
    int Start()
    {
        HDF_LOGI("Start Restart Handler");
        RegisterVendorHandler(BRCM_OUI, BRCM_VENDOR_EVENT_HANGED);
        return HAL_SUCCESS;
    }
    int Cancel() override
    {
        HDF_LOGI("Clear Restart Handler");

        /* unregister alert handler */
        UnregisterVendorHandler(BRCM_OUI, BRCM_VENDOR_EVENT_HANGED);
        WifiUnregisterCmd(WifiHandle(), Id());
        HDF_LOGI("Success to clear restarthandler");
        return HAL_SUCCESS;
    }

    int HandleResponse(WifiEvent& reply) override
    {
        /* Nothing to do on response! */
        return NL_OK;
    }

    int HandleEvent(WifiEvent& event) override
    {
        nlattr *vendorData = event.GetAttribute(NL80211_ATTR_VENDOR_DATA);
        int len = event.GetVendorDataLen();
        int eventId = event.GetVendorSubcmd();
        HDF_LOGI("Got event: %d", eventId);

        if (vendorData == nullptr || len == 0) {
            HDF_LOGE("No Debug data found");
            return NL_SKIP;
        }
        if (eventId == BRCM_VENDOR_EVENT_HANGED) {
            for (NlIterator it(vendorData); it.HasNext(); it.Next()) {
                if (it.GetType() == LOGGER_ATTRIBUTE_HANG_REASON) {
                    mBuff = (char *)it.GetData();
                } else {
                    HDF_LOGI("Ignoring invalid attribute type = %d, size = %d",
                        it.GetType(), it.GetLen());
                }
            }

            if (*mHandler.onVendorHalRestart) {
                (*mHandler.onVendorHalRestart)(mBuff);
                HDF_LOGI("Hang event received.");
            } else {
                HDF_LOGI("No Restart handler registered");
            }
        }
        return NL_OK;
    }
};

class SubSystemRestart : public WifiCommand {
public:
    explicit SubSystemRestart(wifiInterfaceHandle iface)
        : WifiCommand("SubSystemRestart", iface, 0)
    { }

    int CreateRequest(WifiRequest& request)
    {
        int result = request.Create(HAL_OUI, WIFI_SUBCMD_TRIGGER_SSR);
        if (result < 0) {
            return result;
        }

        nlattr *data = request.AttrStart(NL80211_ATTR_VENDOR_DATA);

        request.AttrEnd(data);
        return HAL_SUCCESS;
    }

    int Create() override
    {
        WifiRequest request(FamilyId(), IfaceId());

        int result = CreateRequest(request);
        if (result < 0) {
            HDF_LOGE("Failed to create ssr request result = %d\n", result);
            return result;
        }

        result = RequestResponse(request);
        if (result != HAL_SUCCESS) {
            HDF_LOGE("Failed to register ssr response; result = %d\n", result);
        }
        return result;
    }

protected:
    int HandleResponse(WifiEvent& reply) override
    {
        /* Nothing to do on response! */
        return NL_OK;
    }

    int HandleEvent(WifiEvent& event) override
    {
        /* NO events to handle here! */
        return NL_SKIP;
    }
};

WifiError VendorHalSetRestartHandler(wifiHandle handle, VendorHalRestartHandler handler)
{
    HalInfo *info = nullptr;

    info = (HalInfo *)handle;
    if (info == nullptr) {
        HDF_LOGE("Could not find hal info\n");
        return HAL_UNKNOWN;
    }

    SetRestartHandler *cmd = new SetRestartHandler(handle, HAL_RESTART_ID, handler);
    NULL_CHECK_RETURN(cmd, "memory allocation failure", HAL_OUT_OF_MEMORY);
    WifiError result = WifiRegisterCmd(handle, HAL_RESTART_ID, cmd);
    if (result != HAL_SUCCESS) {
        cmd->ReleaseRef();
        return result;
    }

    result = (WifiError)cmd->Start();
    if (result != HAL_SUCCESS) {
        WifiUnregisterCmd(handle, HAL_RESTART_ID);
        cmd->ReleaseRef();
        return result;
    }

    /* Cache the handler to use it for trigger subsystem restart */
    HDF_LOGI("Register SSR handler");
    info->restartHandler = handler;
    return result;
}

WifiError TriggerVendorHalRestart(wifiHandle handle)
{
    WifiError result = HAL_SUCCESS;
    HalInfo *info = nullptr;
    char errorStr[20];
    SubSystemRestart *cmd = nullptr;
    wifiInterfaceHandle *ifaceHandles = nullptr;
    wifiInterfaceHandle wlan0Handle;
    int numIfaceHandles = 0;

    info = (HalInfo *)handle;
    if (handle == NULL || info == nullptr) {
        HDF_LOGE("Could not find hal info\n");
        result = HAL_UNKNOWN;
        goto exit;
    }

    HDF_LOGI("Trigger subsystem restart\n");

    wlan0Handle = WifiGetWlanInterface((wifiHandle)handle, ifaceHandles, numIfaceHandles);

    cmd = new SubSystemRestart(wlan0Handle);
    NULL_CHECK_RETURN(cmd, "memory allocation failure", HAL_OUT_OF_MEMORY);

    result = (WifiError)cmd->Create();
    if (result != HAL_SUCCESS) {
        cmd->ReleaseRef();
        if (strncpy_s(errorStr, sizeof(errorStr), "HAL_UNKNOWN", sizeof("HAL_UNKNOWN")) != EOK) {
            return result;
        }
        HDF_LOGE("Failed to create SSR");
        return result;
    }

    if (strncpy_s(errorStr, sizeof(errorStr), "HAL_SUCCESS", sizeof("HAL_SUCCESS")) != EOK) {
        goto exit;
    }

exit:
    if (cmd != nullptr) {
        cmd->ReleaseRef();
    }
    if (info->restartHandler.onVendorHalRestart) {
        HDF_LOGI("Trigger ssr handler registered handler");
        (info->restartHandler.onVendorHalRestart)(errorStr);
    } else {
        HDF_LOGI("No trigger ssr handler registered");
    }
    return result;
}