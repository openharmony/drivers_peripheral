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

#include "usb_accessory_uevent_handle.h"
#include "hdf_base.h"
#include "hdf_log.h"
#include "usbd_wrapper.h"
#include "ddk_pnp_listener_mgr.h"

#define HDF_LOG_TAG usb_accessory_uevent

char *g_usbAccessoryUeventPath = "invalid_path";

struct UsbAccessoryUeventInfo {
    const char *devPath;
    const char *subSystem;
    const char *accessory;
    const char *devName;
};

static void UsbAccessoryDispatchUevent(const struct UsbAccessoryUeventInfo *info)
{
    HDF_LOGD("%{public}s: devPath: %{public}s, accessory: %{public}s", __func__, info->devPath, info->accessory);
    if (strcmp(info->devPath, g_usbAccessoryUeventPath) != 0) {
        return;
    }
    if (strcmp(info->accessory, "START") == 0) {
        DdkListenerMgrNotifyAll(NULL, USB_ACCESSORY_START);
    } else if (strcmp(info->accessory, "SEND") == 0) {
        DdkListenerMgrNotifyAll(NULL, USB_ACCESSORY_SEND);
    }
}

void UsbAccessoryUeventHandle(const char msg[], ssize_t rcvLen)
{
    HDF_LOGD("%{public}s: msg: %{public}s, len: %{public}zd", __func__, msg, rcvLen);
    char fullMsg[rcvLen + 1];
    for (int i = 0; i < rcvLen; i++) {
        if (msg[i] == '\0') {
            fullMsg[i] = ' ';
        } else {
            fullMsg[i] = msg[i];
        }
    }
    fullMsg[rcvLen] = '\0';
    HDF_LOGD("%{public}s:Full message: %{public}s", __func__, fullMsg);

    struct UsbAccessoryUeventInfo info = {
        .devPath = "",
        .subSystem = "",
        .accessory = "",
        .devName = ""
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
        } else if (strncmp(msgTmp, "ACCESSORY=", strlen("ACCESSORY=")) == 0) {
            msgTmp += strlen("ACCESSORY=");
            info.accessory = msgTmp;
        } else if (strncmp(msgTmp, "DEVNAME=", strlen("DEVNAME=")) == 0) {
            msgTmp += strlen("DEVNAME=");
            info.devName = msgTmp;
        }
        msgTmp += strlen(msgTmp) + 1; // 1 is a skip character '\0'
    }

    UsbAccessoryDispatchUevent(&info);
}

int32_t UsbAccessoryUeventInit(const char *ueventPath)
{
    if (ueventPath == NULL) {
        HDF_LOGE("%{public}s invalid param", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGD("%{public}s: enter, ueventPath: %{public}s", __func__, ueventPath);

    g_usbAccessoryUeventPath = (char *)ueventPath;
    return HDF_SUCCESS;
}
