/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "ddk_uevent_handle.h"

#include <linux/netlink.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "ddk_pnp_listener_mgr.h"
#include "hdf_base.h"
#include "hdf_log.h"
#include "securec.h"
#include "usbfn_uevent_handle.h"
#include "usbd_wrapper.h"

#define UEVENT_MSG_LEN          2048
#define UEVENT_SOCKET_GROUPS    0xffffffff
#define UEVENT_SOCKET_BUFF_SIZE (64 * 1024)
#define TIMEVAL_SECOND          0
#define TIMEVAL_USECOND         (100 * 1000)

#define HDF_LOG_TAG usbfn_uevent

char *g_gadgetEventPath = "invalid_path";

struct UsbFnUeventInfo {
    const char *devPath;
    const char *subSystem;
    const char *usbState;
    const char *dualRoleMode;
};

static void UsbFnDispatchUevent(const struct UsbFnUeventInfo *info)
{
    bool isGadgetConnect = strcmp(info->devPath, g_gadgetEventPath) == 0;
    isGadgetConnect = (isGadgetConnect && strcmp(info->usbState, "CONNECTED") == 0);
    if (isGadgetConnect) {
        DdkListenerMgrNotifyAll(NULL, USB_PNP_DRIVER_GADGET_ADD);
        return;
    }

    bool isGadgetDisconnect = strcmp(info->devPath, g_gadgetEventPath) == 0;
    isGadgetDisconnect = (isGadgetDisconnect && strcmp(info->usbState, "DISCONNECTED") == 0);
    if (isGadgetDisconnect) {
        DdkListenerMgrNotifyAll(NULL, USB_PNP_DRIVER_GADGET_REMOVE);
        return;
    }

    bool isPort2Device = strcmp(info->subSystem, "dual_role_usb") == 0;
    isPort2Device = (isPort2Device && strcmp(info->dualRoleMode, "ufp") == 0);
    if (isPort2Device) {
        DdkListenerMgrNotifyAll(NULL, USB_PNP_DRIVER_PORT_DEVICE);
        return;
    }

    bool isPort2Host = strcmp(info->subSystem, "dual_role_usb") == 0;
    isPort2Host = (isPort2Host && strcmp(info->dualRoleMode, "dfp") == 0);
    if (isPort2Host) {
        DdkListenerMgrNotifyAll(NULL, USB_PNP_DRIVER_PORT_HOST);
        return;
    }
}

void UsbFnHandleUevent(const char msg[], ssize_t rcvLen)
{
    struct UsbFnUeventInfo info = {
        .devPath = "",
        .subSystem = "",
        .usbState = "",
        .dualRoleMode = "",
    };

    const char *msgTmp = msg;
    while (*msgTmp && (msgTmp - msg < rcvLen)) {
        if (strncmp(msgTmp, "DEVPATH=", strlen("DEVPATH=")) == 0) {
            msgTmp += strlen("DEVPATH=");
            info.devPath = msgTmp;
        } else if (strncmp(msgTmp, "SUBSYSTEM=", strlen("SUBSYSTEM=")) == 0 &&
            strlen(info.subSystem) == 0) { // some uevent has more than one SUBSYSTEM property
            msgTmp += strlen("SUBSYSTEM=");
            info.subSystem = msgTmp;
        } else if (strncmp(msgTmp, "USB_STATE=", strlen("USB_STATE=")) == 0) {
            msgTmp += strlen("USB_STATE=");
            info.usbState = msgTmp;
        } else if (strncmp(msgTmp, "DUAL_ROLE_MODE=", strlen("DUAL_ROLE_MODE=")) == 0) {
            msgTmp += strlen("DUAL_ROLE_MODE=");
            info.dualRoleMode = msgTmp;
        }
        msgTmp += strlen(msgTmp) + 1; // 1 is a skip character '\0'
    }

    UsbFnDispatchUevent(&info);
    return;
}

int32_t UsbFnUeventInit(const char *gadgetEventPath)
{
    if (gadgetEventPath == NULL) {
        HDF_LOGE("%{public}s invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    g_gadgetEventPath = (char *)gadgetEventPath;
    return HDF_SUCCESS;
}