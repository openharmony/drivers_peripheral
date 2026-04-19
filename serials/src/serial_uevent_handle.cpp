/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "serial_uevent_handle.h"
#include <linux/netlink.h>
#include <cstring>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "hdf_base.h"
#include "hdf_io_service_if.h"
#include "hdf_log.h"
#include "osal_time.h"
#include "securec.h"

#undef LOG_TAG
#define LOG_TAG "SERIAL_IMPL"
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002519

namespace OHOS {
namespace HDI {
namespace Serials {
namespace V1_0 {
SerialUeventHandle::SerialUeventHandle(SerialUeventQueue* queue) : queue_(queue) {}

SerialUeventHandle::~SerialUeventHandle()
{
    Stop();
}

int32_t SerialUeventHandle::Init()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (running_) {
        HDF_LOGI("%{public}s: already running", __func__);
        return HDF_SUCCESS;
    }

    if (pipe(pipeFd_) < 0) {
        HDF_LOGE("%{public}s: create pipe failed, errno=%{public}d", __func__, errno);
        return HDF_FAILURE;
    }

    running_ = true;
    thread_ = std::thread(&SerialUeventHandle::SerialUeventMain, this);
    return HDF_SUCCESS;
}

void SerialUeventHandle::ClosePipeFd()
{
    if (pipeFd_[ARRAY_INDEX_0] >= 0) {
        close(pipeFd_[ARRAY_INDEX_0]);
        pipeFd_[ARRAY_INDEX_0] = INVALID_FD;
    }
    if (pipeFd_[ARRAY_INDEX_1] >= 0) {
        close(pipeFd_[ARRAY_INDEX_1]);
        pipeFd_[ARRAY_INDEX_1] = INVALID_FD;
    }
}

void SerialUeventHandle::Stop()
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!running_) {
            return;
        }
        running_ = false;
    }

    if (pipeFd_[ARRAY_INDEX_1] >= 0) {
        char ch = 'x';
        write(pipeFd_[ARRAY_INDEX_1], &ch, sizeof(ch));
    }

    if (thread_.joinable()) {
        thread_.join();
    }

    ClosePipeFd();

    if (socketFd_ >= 0) {
        fdsan_close_with_tag(socketFd_, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
        socketFd_ = INVALID_FD;
    }
}

int SerialUeventHandle::SerialUeventOpen(int *fd)
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
        HDF_LOGE("%{public}s: socketfd failed! ret=%{public}d, errno:%{public}d", __func__, socketfd, errno);
        return HDF_FAILURE;
    }
    fdsan_exchange_owner_tag(socketfd, 0, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));

    int buffSize = UEVENT_SOCKET_BUFF_SIZE;
    if (setsockopt(socketfd, SOL_SOCKET, SO_RCVBUF, &buffSize, sizeof(buffSize)) != 0) {
        HDF_LOGE("%{public}s: setsockopt failed! %{public}d", __func__, errno);
        fdsan_close_with_tag(socketfd, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
        return HDF_FAILURE;
    }

    const int32_t on = 1;
    if (setsockopt(socketfd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) != 0) {
        HDF_LOGE("setsockopt failed! %{public}d", errno);
        fdsan_close_with_tag(socketfd, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
        return HDF_FAILURE;
    }

    if (bind(socketfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        HDF_LOGE("%{public}s: bind socketfd failed! %{public}d", __func__, errno);
        fdsan_close_with_tag(socketfd, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
        return HDF_FAILURE;
    }
    *fd = socketfd;
    return HDF_SUCCESS;
}

void SerialUeventHandle::SerialHandleUevent(const char msg[], ssize_t rcvLen)
{
    (void)rcvLen;
    SerialUeventInfo info;

    const char *msgTmp = msg;
    while (*msgTmp != '\0') {
        if (strncmp(msgTmp, "ACTION=", strlen("ACTION=")) == 0) {
            msgTmp += strlen("ACTION=");
            info.action = msgTmp;
        } else if (strncmp(msgTmp, "DEVNAME=", strlen("DEVNAME=")) == 0) {
            msgTmp += strlen("DEVNAME=");
            info.devName = msgTmp;
        } else if (strncmp(msgTmp, "SUBSYSTEM=", strlen("SUBSYSTEM=")) == 0 && info.subSystem.empty()) {
            msgTmp += strlen("SUBSYSTEM=");
            info.subSystem = msgTmp;
        } else if (strncmp(msgTmp, "DEVTYPE=", strlen("DEVTYPE=")) == 0 && info.devType.empty()) {
            msgTmp += strlen("DEVTYPE=");
            info.devType = msgTmp;
        } else if (strncmp(msgTmp, "BUSNUM=", strlen("BUSNUM=")) == 0) {
            msgTmp += strlen("BUSNUM=");
            info.busNum = msgTmp;
        } else if (strncmp(msgTmp, "DEVNUM=", strlen("DEVNUM=")) == 0) {
            msgTmp += strlen("DEVNUM=");
            info.devNum = msgTmp;
        }
        msgTmp += strlen(msgTmp) + 1;
    }

    if (queue_ != nullptr) {
        queue_->AddTask(info);
    }
}

ssize_t SerialUeventHandle::SerialReadUeventMsg(int sockFd, char *buffer, size_t length)
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

bool SerialUeventHandle::InitUeventSocket()
{
    int errorTimes = 0;
    while (SerialUeventOpen(&socketFd_) != HDF_SUCCESS) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!running_) {
                return false;
            }
        }
        errorTimes++;
        if (errorTimes > MAX_UEVENT_BIND_RETRY_TIMES) {
            HDF_LOGE("SerialUeventOpen failed");
            return false;
        }
        OsalMSleep(UEVENT_POLL_WAIT_TIME);
    }
    return true;
}

void SerialUeventHandle::ProcessEventLoop(struct pollfd fds[], char msg[], ssize_t &rcvLen, int &errorTimes)
{
    while (running_) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!running_) {
                return;
            }
        }

        int ret = poll(fds, PIPE_FD_LEN, -1);
        if (ret < 0) {
            HDF_LOGE("poll failed, errno=%{public}d", errno);
            if (errno == EINTR) {
                continue;
            }
            return;
        }

        if ((fds[ARRAY_INDEX_1].revents & POLLIN) != 0) {
            char buf[16];
            read(fds[ARRAY_INDEX_1].fd, buf, sizeof(buf));
            return;
        }

        if ((fds[ARRAY_INDEX_0].revents & POLLERR) != 0) {
            if (errorTimes < MAX_ERR_TIMES) {
                ++errorTimes;
            } else {
                OsalMSleep(UEVENT_POLL_WAIT_TIME);
            }
            HDF_LOGE("uevent poll error, fd.revents=%{public}hd", fds[ARRAY_INDEX_0].revents);
            continue;
        }

        if ((fds[ARRAY_INDEX_0].revents & POLLIN) != 0) {
            errorTimes = 0;
            (void)memset_s(msg, UEVENT_MSG_LEN, 0, UEVENT_MSG_LEN);
            rcvLen = SerialReadUeventMsg(socketFd_, msg, UEVENT_MSG_LEN);
            if (rcvLen > 0) {
                SerialHandleUevent(msg, rcvLen);
            }
        }
    }
}

void SerialUeventHandle::SerialUeventMain()
{
    if (!InitUeventSocket()) {
        return;
    }

    ssize_t rcvLen = 0;
    char msg[UEVENT_MSG_LEN];

    struct pollfd fds[PIPE_FD_LEN];
    fds[ARRAY_INDEX_0].fd = socketFd_;
    fds[ARRAY_INDEX_0].events = POLLIN | POLLERR;
    fds[ARRAY_INDEX_0].revents = 0;
    fds[ARRAY_INDEX_1].fd = pipeFd_[ARRAY_INDEX_0];
    fds[ARRAY_INDEX_1].events = POLLIN;
    fds[ARRAY_INDEX_1].revents = 0;
    int errorTimes = 0;

    ProcessEventLoop(fds, msg, rcvLen, errorTimes);

    if (socketFd_ >= 0) {
        fdsan_close_with_tag(socketFd_, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
        socketFd_ = INVALID_FD;
    }
}

} // V1_0
} // Serials
} // HDI
} // OHOS