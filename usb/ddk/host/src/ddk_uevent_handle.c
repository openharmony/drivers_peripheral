/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "ddk_device_manager.h"
#include "ddk_pnp_listener_mgr.h"
#include "hdf_base.h"
#include "hdf_log.h"
#include "securec.h"
#include "usbfn_uevent_handle.h"

#define UEVENT_MSG_LEN          2048
#define UEVENT_SOCKET_GROUPS    0xffffffff
#define UEVENT_SOCKET_BUFF_SIZE (64 * 1024)
#define TIMEVAL_SECOND          0
#define TIMEVAL_USECOND         (100 * 1000)

#define HDF_LOG_TAG usb_ddk_uevent

struct DdkUeventInfo {
    const char *action;
    const char *devPath;
    const char *subSystem;
    const char *devType;
    const char *devNum;
    const char *busNum;
};

static int DdkUeventOpen(int *fd)
{
    struct sockaddr_nl addr;
    if (memset_s(&addr, sizeof(addr), 0, sizeof(addr)) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: addr memset_s failed!", __func__);
        return HDF_FAILURE;
    }
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = (uint32_t)getpid();
    addr.nl_groups = UEVENT_SOCKET_GROUPS;

    int socketfd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
    if (socketfd < 0) {
        HDF_LOGE("%{public}s: socketfd failed! ret = %d", __func__, socketfd);
        return HDF_FAILURE;
    }

    int buffSize = UEVENT_SOCKET_BUFF_SIZE;
    if (setsockopt(socketfd, SOL_SOCKET, SO_RCVBUF, &buffSize, sizeof(buffSize)) != 0) {
        HDF_LOGE("%{public}s: setsockopt failed!", __func__);
        return HDF_FAILURE;
    }
    if (bind(socketfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        HDF_LOGE("%{public}s: bind socketfd failed!", __func__);
        close(socketfd);
        return HDF_FAILURE;
    }
    *fd = socketfd;
    return HDF_SUCCESS;
}

static int32_t DdkUeventAddDevice(const char *devPath)
{
    char *pos = strrchr(devPath, '/');
    if (pos == NULL) {
        HDF_LOGE("%{public}s: no / in devpath:%{public}s", __func__, devPath);
        return HDF_ERR_INVALID_PARAM;
    }

    const struct UsbPnpNotifyMatchInfoTable *device = DdkDevMgrCreateDevice(pos + 1); // 1 skip '/'
    if (device == NULL) {
        HDF_LOGE("%{public}s: create device failed:%{public}s", __func__, devPath);
        return HDF_FAILURE;
    }
    DdkListenerMgrNotifyAll(device, USB_PNP_NOTIFY_ADD_DEVICE);
    return HDF_SUCCESS;
}

static int32_t DdkUeventRemoveDevice(const char *busNum, const char *devNum)
{
    struct UsbPnpNotifyMatchInfoTable dev;
    int32_t ret = DdkDevMgrRemoveDevice(strtol(busNum, NULL, 10), strtol(devNum, NULL, 10), &dev); // 10 means decimal
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: remove device failed, busNum:%{public}s, devNum:%{public}s", __func__, busNum, devNum);
        return HDF_FAILURE;
    }
    DdkListenerMgrNotifyAll(&dev, USB_PNP_NOTIFY_REMOVE_DEVICE);
    return HDF_SUCCESS;
}

static void DdkDispatchUevent(const struct DdkUeventInfo *info)
{
    if (strcmp(info->subSystem, "usb") != 0) {
        return;
    }

    int32_t ret = HDF_SUCCESS;
    if (strcmp(info->action, "bind") == 0 && strcmp(info->devType, "usb_device") == 0) {
        ret = DdkUeventAddDevice(info->devPath);
    } else if (strcmp(info->action, "remove") == 0 && strcmp(info->devType, "usb_device") == 0) {
        ret = DdkUeventRemoveDevice(info->busNum, info->devNum);
    }

    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: action:%{public}s, ret:%{public}d", __func__, info->action, ret);
    }
}

static void DdkHandleUevent(const char msg[], ssize_t rcvLen)
{
    (void)rcvLen;
    struct DdkUeventInfo info = {
        .action = "",
        .subSystem = "",
        .busNum = "",
        .devNum = "",
        .devPath = "",
        .devType = "",
    };

    const char *msgTmp = msg;
    while (*msgTmp != '\0') {
        if (strncmp(msgTmp, "ACTION=", strlen("ACTION=")) == 0) {
            msgTmp += strlen("ACTION=");
            info.action = msgTmp;
        } else if (strncmp(msgTmp, "DEVPATH=", strlen("DEVPATH=")) == 0) {
            msgTmp += strlen("DEVPATH=");
            info.devPath = msgTmp;
        } else if (strncmp(msgTmp, "SUBSYSTEM=", strlen("SUBSYSTEM=")) == 0 &&
            strlen(info.subSystem) == 0) { // some uevent has more than one SUBSYSTEM property
            msgTmp += strlen("SUBSYSTEM=");
            info.subSystem = msgTmp;
        } else if (strncmp(msgTmp, "DEVTYPE=", strlen("DEVTYPE=")) == 0 &&
            strlen(info.devType) == 0) { // some uevent has more than one DEVTYPE property
            msgTmp += strlen("DEVTYPE=");
            info.devType = msgTmp;
        } else if (strncmp(msgTmp, "BUSNUM=", strlen("BUSNUM=")) == 0) {
            msgTmp += strlen("BUSNUM=");
            info.busNum = msgTmp;
        } else if (strncmp(msgTmp, "DEVNUM=", strlen("DEVNUM=")) == 0) {
            msgTmp += strlen("DEVNUM=");
            info.devNum = msgTmp;
        }
        msgTmp += strlen(msgTmp) + 1; // 1 is a skip character '\0'
    }

    DdkDispatchUevent(&info);
    return;
}

void *DdkUeventMain(void *param)
{
    (void)param;
    int fd = -1;
    if (DdkUeventOpen(&fd) != HDF_SUCCESS) {
        return NULL;
    }

    int32_t ret;
    ssize_t rcvLen = 0;
    fd_set fds;
    char msg[UEVENT_MSG_LEN];
    struct timeval tv;
    do {
        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        tv.tv_sec = TIMEVAL_SECOND;
        tv.tv_usec = TIMEVAL_USECOND;
        ret = select(fd + 1, &fds, NULL, NULL, &tv);
        if (ret < 0) {
            continue;
        }
        if (!(ret > 0 && FD_ISSET(fd, &fds))) {
            continue;
        }

        (void)memset_s(msg, UEVENT_MSG_LEN, 0, UEVENT_MSG_LEN);
        do {
            if ((rcvLen = recv(fd, msg, UEVENT_MSG_LEN, 0)) < 0) {
                HDF_LOGE("recv failed");
                return NULL;
            }
            if (rcvLen == (ssize_t)UEVENT_MSG_LEN) {
                continue;
            }
            DdkHandleUevent(msg, rcvLen);
            UsbFnHandleUevent(msg, rcvLen);
        } while (rcvLen > 0);
    } while (true);
}