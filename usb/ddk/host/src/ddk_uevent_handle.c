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
#include <poll.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "ddk_device_manager.h"
#include "ddk_pnp_listener_mgr.h"
#include "ddk_uevent_queue.h"
#include "hdf_base.h"
#include "hdf_io_service_if.h"
#include "hdf_log.h"
#include "osal_time.h"
#include "securec.h"
#include "usbfn_uevent_handle.h"
#include "usbd_wrapper.h"
#include "usb_accessory_uevent_handle.h"

#define HDF_LOG_TAG usb_ddk_uevent

#ifdef USB_EVENT_NOTIFY_LINUX_NATIVE_MODE
#define UEVENT_MSG_LEN          2048
#define UEVENT_SOCKET_GROUPS    0xffffffff
#define UEVENT_SOCKET_BUFF_SIZE (64 * 1024)
#define TIMEVAL_SECOND          0
#define TIMEVAL_USECOND         (100 * 1000)
#define UEVENT_POLL_WAIT_TIME   100
#define MAX_ERR_TIMES           10

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
        HDF_LOGE("%{public}s: socketfd failed! ret = %{public}d", __func__, socketfd);
        return HDF_FAILURE;
    }

    int buffSize = UEVENT_SOCKET_BUFF_SIZE;
    if (setsockopt(socketfd, SOL_SOCKET, SO_RCVBUF, &buffSize, sizeof(buffSize)) != 0) {
        HDF_LOGE("%{public}s: setsockopt failed!", __func__);
        close(socketfd);
        return HDF_FAILURE;
    }

    const int32_t on = 1; // turn on passcred
    if (setsockopt(socketfd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) != 0) {
        HDF_LOGE("setsockopt failed!");
        close(socketfd);
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

    DdkUeventAddTask(&info);
    return;
}

static ssize_t DdkReadUeventMsg(int sockFd, char *buffer, size_t length)
{
    struct iovec iov;
    iov.iov_base = buffer;
    iov.iov_len = length;

    struct sockaddr_nl addr;
    (void)memset_s(&addr, sizeof(addr), 0, sizeof(addr));

    struct msghdr msghdr = {0};
    msghdr.msg_name = &addr;
    msghdr.msg_namelen = sizeof(addr);
    msghdr.msg_iov = &iov;
    msghdr.msg_iovlen = 1;

    char credMsg[CMSG_SPACE(sizeof(struct ucred))] = {0};
    msghdr.msg_control = credMsg;
    msghdr.msg_controllen = sizeof(credMsg);

    ssize_t len = recvmsg(sockFd, &msghdr, 0);
    if (len <= 0) {
        return HDF_FAILURE;
    }

    struct cmsghdr *hdr = CMSG_FIRSTHDR(&msghdr);
    if (hdr == NULL || hdr->cmsg_type != SCM_CREDENTIALS) {
        HDF_LOGE("Unexpected control message, ignored");
        *buffer = '\0';
        return HDF_FAILURE;
    }

    return len;
}

void *DdkUeventMain(void *param)
{
    (void)param;
    int errorTimes = 0;
    int socketfd = -1;
    if (DdkUeventOpen(&socketfd) != HDF_SUCCESS) {
        HDF_LOGE("DdkUeventOpen failed");
        return NULL;
    }

    ssize_t rcvLen = 0;
    char msg[UEVENT_MSG_LEN];

    struct pollfd fd;
    fd.fd = socketfd;
    fd.events = POLLIN | POLLERR;
    fd.revents = 0;
    do {
        if (poll(&fd, 1, -1) <= 0) {
            HDF_LOGE("usb event poll fail %{public}d", errno);
            OsalMSleep(UEVENT_POLL_WAIT_TIME);
            continue;
        }

        if (((uint32_t)fd.revents & POLLIN) == POLLIN) {
            errorTimes = 0;
            (void)memset_s(&msg, sizeof(msg), 0, sizeof(msg));
            rcvLen = DdkReadUeventMsg(socketfd, msg, UEVENT_MSG_LEN);
            if (rcvLen <= 0) {
                continue;
            }
            DdkHandleUevent(msg, rcvLen);
            UsbFnHandleUevent(msg, rcvLen);
            UsbAccessoryUeventHandle(msg, rcvLen);
        } else if (((uint32_t)fd.revents & POLLERR) == POLLERR) {
            if (errorTimes < MAX_ERR_TIMES) {
                ++errorTimes;
            } else {
                OsalMSleep(UEVENT_POLL_WAIT_TIME);
            }
            HDF_LOGE("usb event poll error");
        }
    } while (true);

    close(socketfd);
    return NULL;
}

int32_t DdkUeventInit(const char *gadgetEventPath)
{
    DdkUeventStartDispatchThread();
    return UsbFnUeventInit(gadgetEventPath);
}
#else  // USB_EVENT_NOTIFY_LINUX_NATIVE_MODE
static int32_t DdkUeventCallBack(void *priv, uint32_t id, struct HdfSBuf *data)
{
    if (id == USB_PNP_NOTIFY_REPORT_INTERFACE) {
        return HDF_SUCCESS;
    }

    if (data == NULL) {
        HDF_LOGE("%{public}s: HdfIoServiceBind failed.", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct UsbPnpNotifyMatchInfoTable *info = NULL;
    if (id == USB_PNP_NOTIFY_ADD_DEVICE || id == USB_PNP_NOTIFY_REMOVE_DEVICE) {
        uint32_t infoSize;
        bool flag = HdfSbufReadBuffer(data, (const void **)(&info), &infoSize);
        if (!flag || info == NULL) {
            HDF_LOGE("%{public}s: HdfSbufReadBuffer failed, flag=%{public}d", __func__, flag);
            return HDF_ERR_INVALID_PARAM;
        }
    }

    HDF_LOGI("%{public}s: cmd is: %{public}u.", __func__, id);
    DdkListenerMgrNotifyAll(info, id);
    return HDF_SUCCESS;
}

int32_t DdkUeventInit(const char *gadgetEventPath)
{
    (void)gadgetEventPath;
    struct HdfIoService *usbPnpSrv = HdfIoServiceBind(USB_PNP_NOTIFY_SERVICE_NAME);
    if (usbPnpSrv == NULL) {
        HDF_LOGE("%{public}s: HdfIoServiceBind failed.", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    static struct HdfDevEventlistener usbPnpListener = {.callBack = DdkUeventCallBack};
    int32_t ret = HdfDeviceRegisterEventListener(usbPnpSrv, &usbPnpListener);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: HdfDeviceRegisterEventListener failed ret=%{public}d", __func__, ret);
    }
    return ret;
}
#endif // USB_EVENT_NOTIFY_LINUX_NATIVE_MODE
