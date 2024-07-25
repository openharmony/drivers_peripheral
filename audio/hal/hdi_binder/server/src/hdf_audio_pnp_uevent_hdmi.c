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

#include "hdf_audio_pnp_uevent_hdmi.h"
#include <asm/types.h>
#include <pthread.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>
#include "audio_uhdf_log.h"
#include "hdf_audio_pnp_server.h"
#include "hdf_base.h"
#include "hdf_io_service.h"
#include "osal_time.h"
#include "securec.h"

#define HDF_LOG_TAG HDF_AUDIO_HAL_HOST

#define RECV_BUFFER_SIZE       2048
#define FILE_BUFFER_SIZE       7
#define UEVENT_STATE           "STATE"
#define UEVENT_HDMI_STATE      "HDMI="
#define UEVENT_HDMI_STATE_PLUG "HDMI=1"
#define UEVENT_HDMI_STATE_REMV "HDMI=0"

#define HDMI_STATUS_FILE_PATH "/sys/class/extcon/extcon2/state"

#define UEVENT_SOCKET_GROUPS    0xffffffff

#define MAXEVENTS 1
#define TIMEOUT   (-1)

#define AUDIO_HDMI_CARD_NAME "hdf_audio_codec_hdmi_dev0"

static int32_t AudioHdmiPnpUeventStatus(const char *statusStr, bool isPnp)
{
    if (statusStr == NULL) {
        AUDIO_FUNC_LOGE("error statusStr is null");
        return HDF_ERR_INVALID_PARAM;
    }

    struct AudioEvent audioEvent;
    if (strncmp(statusStr, UEVENT_HDMI_STATE_PLUG, strlen(UEVENT_HDMI_STATE_PLUG)) == 0) {
        audioEvent.eventType = AUDIO_DEVICE_ADD;
        if (AudioUhdfLoadDriver(AUDIO_HDMI_CARD_NAME) != HDF_SUCCESS) {
            AUDIO_FUNC_LOGW("AudioUhdfLoadDriver Failed");
        }
        AUDIO_FUNC_LOGI("An HDMI device is plugged in");
    } else if (strncmp(statusStr, UEVENT_HDMI_STATE_REMV, strlen(UEVENT_HDMI_STATE_REMV)) == 0) {
        audioEvent.eventType = AUDIO_DEVICE_REMOVE;
        if (AudioUhdfUnloadDriver(AUDIO_HDMI_CARD_NAME) != HDF_SUCCESS) {
            AUDIO_FUNC_LOGW("AudioUhdfUnloadDriver Failed");
        }
        AUDIO_FUNC_LOGI("The HDMI device is removed");
    } else {
        AUDIO_FUNC_LOGE("error HDMI status unknown! statusStr = %{public}s", statusStr);
        return HDF_FAILURE;
    }

    audioEvent.deviceType = AUDIO_HDMI_DEVICE;
    if (isPnp) {
        return AudioPnpUpdateInfoOnly(audioEvent);
    }

    return HDF_SUCCESS;
}

static int32_t AudioPnpUeventParse(const char *str)
{
    if (str == NULL) {
        AUDIO_FUNC_LOGE("error device is null");
        return HDF_FAILURE;
    }

    while (*str != '\0') {
        if (strncmp(str, UEVENT_STATE, strlen(UEVENT_STATE)) == 0) {
            const char *temp = str + strlen(UEVENT_STATE) + 1; // 1 is a skip character '='
            if (strncmp(temp, UEVENT_HDMI_STATE, strlen(UEVENT_HDMI_STATE)) == 0) {
                return AudioHdmiPnpUeventStatus(temp, true);
            }
        }
        str += strlen(str) + 1; // 1 is a skip character '\0'
    }

    return HDF_SUCCESS;
}

static int32_t AudioHdmiOpenEventPoll(int32_t *sockFd, int *fdEpoll)
{
    if (sockFd == NULL || fdEpoll == NULL) {
        AUDIO_FUNC_LOGE("sockFd or fdEpoll is null");
        return HDF_FAILURE;
    }
    struct sockaddr_nl snl;
    struct epoll_event epollUdev;
    int32_t buffSize = RECV_BUFFER_SIZE;

    snl.nl_family = AF_NETLINK;
    snl.nl_groups = UEVENT_SOCKET_GROUPS;

    *fdEpoll = epoll_create1(EPOLL_CLOEXEC);
    if (*fdEpoll < 0) {
        AUDIO_FUNC_LOGE("error creating epoll fd: %{public}m");
        return HDF_FAILURE;
    }

    OsalMSleep(30); // Wait 30ms to resolve the conflict with the pnp uevent "address already in use"
    *sockFd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
    if (*sockFd < 0) {
        AUDIO_FUNC_LOGE("new socket failed, %{public}d", errno);
        close(*fdEpoll);
        return HDF_FAILURE;
    }

    if (setsockopt(*sockFd, SOL_SOCKET, SO_RCVBUF, &buffSize, sizeof(buffSize)) != 0) {
        AUDIO_FUNC_LOGE("setsockopt failed %{public}m");
        close(*fdEpoll);
        close(*sockFd);
        return HDF_FAILURE;
    }

    if (bind(*sockFd, (struct sockaddr *)&snl, sizeof(struct sockaddr_nl)) < 0) {
        AUDIO_FUNC_LOGE("bind failed: %{public}m");
        close(*fdEpoll);
        close(*sockFd);
        return HDF_FAILURE;
    }

    (void)memset_s(&epollUdev, sizeof(struct epoll_event), 0, sizeof(struct epoll_event));
    epollUdev.events = EPOLLIN;
    epollUdev.data.fd = *sockFd;
    if (epoll_ctl(*fdEpoll, EPOLL_CTL_ADD, *sockFd, &epollUdev) < 0) {
        AUDIO_FUNC_LOGE("fail to add fd to epoll: %{public}m");
        close(*fdEpoll);
        close(*sockFd);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t InitializeHdmiStateInternal(void)
{
    char buffer[FILE_BUFFER_SIZE] = {0};

    FILE *pFile = fopen(HDMI_STATUS_FILE_PATH, "r");
    if (pFile == NULL) {
        AUDIO_FUNC_LOGE("open hdmi status file failed!");
        return HDF_FAILURE;
    }

    size_t length = fread(buffer, 1, FILE_BUFFER_SIZE, pFile);
    if (length != FILE_BUFFER_SIZE) {
        (void)fclose(pFile);
        AUDIO_FUNC_LOGE("fread hdmi status file failed!%{public}zu", length);
        return HDF_FAILURE;
    }

    (void)fclose(pFile);
    return AudioHdmiPnpUeventStatus(buffer, false);
}

static bool g_hdmiPnpThreadRunning = false;
static void AudioHdmiPnpUeventStart(void *useless)
{
    (void)useless;

    int fdEpoll = -1;
    int32_t sockFd = -1;

    AUDIO_FUNC_LOGI("audio hdmi uevent start!");
    if (InitializeHdmiStateInternal() != HDF_SUCCESS) {
        AUDIO_FUNC_LOGW("booting check hdmi audio device statu failed!");
    }

    if (AudioHdmiOpenEventPoll(&sockFd, &fdEpoll) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("fail to open event poll");
        return;
    }

    while (g_hdmiPnpThreadRunning) {
        struct epoll_event ev;
        char buf[RECV_BUFFER_SIZE];

        if (epoll_wait(fdEpoll, &ev, MAXEVENTS, TIMEOUT) < 0) {
            AUDIO_FUNC_LOGW("error receiving uevent message: %{public}m");
            continue;
        }

        (void)memset_s(buf, RECV_BUFFER_SIZE, 0, RECV_BUFFER_SIZE);

        (void)recv(sockFd, buf, RECV_BUFFER_SIZE, 0);

        if (AudioPnpUeventParse(buf) != HDF_SUCCESS) {
            AUDIO_FUNC_LOGE("AudioPnpUeventParse failed");
        }
    }
    close(fdEpoll);
    close(sockFd);

    return;
}

int32_t AudioHdmiPnpUeventStartThread(void)
{
    const char *threadName = "pnp_hdmi";
    g_hdmiPnpThreadRunning = true;

    AUDIO_FUNC_LOGI("create audio hdmi pnp uevent thread");
    FfrtTaskAttr attr;
    FfrtAttrInitFunc()(&attr);
    FfrtAttrSetQosFunc()(&attr, FFRT_QOS_DEFAULT);
    FfrtAttrSetNameFunc()(&attr, threadName);
    FfrtSubmitBaseFunc()(FfrtCreateFunctionWrapper(AudioHdmiPnpUeventStart, NULL, NULL), NULL, NULL, &attr);

    return HDF_SUCCESS;
}

void AudioHdmiPnpUeventStopThread(void)
{
    AUDIO_FUNC_LOGI("audio hdmi pnp uevent thread exit");
    g_hdmiPnpThreadRunning = false;
}
