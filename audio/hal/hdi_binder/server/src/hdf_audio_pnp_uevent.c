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

#include "hdf_audio_pnp_uevent.h"
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include "hdf_audio_pnp_server.h"
#include "hdf_base.h"
#include "securec.h"
#include "audio_uhdf_log.h"

#define UEVENT_ACTION           "ACTION="
#define UEVENT_NAME             "NAME="
#define UEVENT_STATE            "STATE="
#define UEVENT_DEVTYPE          "DEVTYPE="
#define UEVENT_SUBSYSTEM        "SUBSYSTEM="
#define UEVENT_SWITCH_NAME      "SWITCH_NAME="
#define UEVENT_SWITCH_STATE     "SWITCH_STATE="
#define UEVENT_ACTION_ADD       "add"
#define UEVENT_ACTION_REMOVE    "remove"
#define UEVENT_ACTION_CHANGE    "change"
#define UEVENT_TYPE_EXTCON      "extcon3"
#define UEVENT_NAME_HEADSET     "headset"
#define UEVENT_STATE_ANALOG_HS0 "MICROPHONE=0"
#define UEVENT_STATE_ANALOG_HS1 "MICROPHONE=1"
#define UEVENT_SUBSYSTEM_SWITCH "switch"
#define UEVENT_SWITCH_NAME_H2W  "h2w"
#define UEVENT_HDI_NAME         "HID_NAME="
#define UEVENT_USB_AUDIO        "USB Audio"
#define UEVENT_USB_HEADSET      "HEADSET"

#define UEVENT_SOCKET_BUFF_SIZE (64 * 1024)
#define UEVENT_SOCKET_GROUPS    0xffffffff
#define UEVENT_MSG_LEN          2048

#define TIMEVAL_SECOND  0
#define TIMEVAL_USECOND (100 * 1000)

#define HDF_LOG_TAG HDF_AUDIO_HAL_HOST

struct AudioPnpUevent {
    const char *action;
    const char *name;
    const char *state;
    const char *devType;
    const char *subSystem;
    const char *switchName;
    const char *switchState;
    const char *hidName;
};

static int32_t AudioAnalogHeadsetDeviceCheck(struct AudioPnpUevent *audioPnpUevent)
{
    struct AudioEvent audioEvent;
    static int32_t h2wTypeLast = HDF_AUDIO_HEADSET;
    if (audioPnpUevent == NULL) {
        AUDIO_FUNC_LOGE("audioPnpUevent is null!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (strncmp(audioPnpUevent->subSystem, UEVENT_SUBSYSTEM_SWITCH, strlen(UEVENT_SUBSYSTEM_SWITCH)) == 0) {
        if (strncmp(audioPnpUevent->switchName, UEVENT_SWITCH_NAME_H2W, strlen(UEVENT_SWITCH_NAME_H2W)) != 0) {
            AUDIO_FUNC_LOGE("the switch name of 'h2w' not found!");
            return HDF_FAILURE;
        }
        if (audioPnpUevent->switchState[0] == '0') {
            audioEvent.eventType = HDF_AUDIO_DEVICE_REMOVE;
            audioEvent.deviceType = h2wTypeLast;
        } else if (audioPnpUevent->switchState[0] == '1') {
            audioEvent.eventType = HDF_AUDIO_DEVICE_ADD;
            audioEvent.deviceType = HDF_AUDIO_HEADSET;
        } else {
            audioEvent.eventType = HDF_AUDIO_DEVICE_ADD;
            audioEvent.deviceType = HDF_AUDIO_HEADPHONE;
        }
        h2wTypeLast = audioEvent.deviceType;
    } else {
        if (strncmp(audioPnpUevent->action, UEVENT_ACTION_CHANGE, strlen(UEVENT_ACTION_CHANGE)) != 0) {
            return HDF_FAILURE;
        }
        if (strstr(audioPnpUevent->name, UEVENT_NAME_HEADSET) == NULL) {
            return HDF_FAILURE;
        }
        if (strncmp(audioPnpUevent->devType, UEVENT_TYPE_EXTCON, strlen(UEVENT_TYPE_EXTCON)) != 0) {
            return HDF_FAILURE;
        }
        if (strstr(audioPnpUevent->state, UEVENT_STATE_ANALOG_HS0) != NULL) {
            audioEvent.eventType = HDF_AUDIO_DEVICE_REMOVE;
        } else if (strstr(audioPnpUevent->state, UEVENT_STATE_ANALOG_HS1) != NULL) {
            audioEvent.eventType = HDF_AUDIO_DEVICE_ADD;
        } else {
            return HDF_FAILURE;
        }
        audioEvent.deviceType = HDF_AUDIO_HEADSET;
    }
    return AudioPnpUpdateInfoOnly(audioEvent);
}

static int32_t AudioDigitalHeadsetDeviceCheck(struct AudioPnpUevent *audioPnpUevent)
{
    struct AudioEvent audioEvent;
    if (audioPnpUevent == NULL) {
        AUDIO_FUNC_LOGE("audioPnpUevent is null!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (audioPnpUevent->action == NULL || audioPnpUevent->hidName == NULL) {
        AUDIO_FUNC_LOGE("action or hidName is null!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (strcmp(audioPnpUevent->action, UEVENT_ACTION_ADD) == 0 &&
        ((strstr(audioPnpUevent->hidName, UEVENT_USB_AUDIO) != NULL) ||
        (strstr(audioPnpUevent->hidName, UEVENT_USB_HEADSET) != NULL))) {
        AUDIO_FUNC_LOGI("USB Audio(%{public}s) add", audioPnpUevent->hidName);
        audioEvent.eventType = HDF_AUDIO_DEVICE_ADD;
        audioEvent.deviceType = HDF_AUDIO_USB_HEADSET;
        (void)AudioPnpUpdateAndSend(audioEvent);
        return HDF_SUCCESS;
    }

    if (strcmp(audioPnpUevent->action, UEVENT_ACTION_REMOVE) == 0 &&
        ((strstr(audioPnpUevent->hidName, UEVENT_USB_AUDIO) != NULL) ||
        (strstr(audioPnpUevent->hidName, UEVENT_USB_HEADSET) != NULL))) {
        AUDIO_FUNC_LOGI("USB Audio(%{public}s) remove", audioPnpUevent->hidName);
        audioEvent.eventType = HDF_AUDIO_DEVICE_REMOVE;
        audioEvent.deviceType = HDF_AUDIO_USB_HEADSET;
        (void)AudioPnpUpdateAndSend(audioEvent);
        return HDF_SUCCESS;
    }

    return HDF_SUCCESS;
}

static int32_t AudioPnpUeventParse(const char *msg, const int32_t strLength)
{
    errno_t ret;
    if (msg == NULL || strLength < 0 || strLength > UEVENT_MSG_LEN) {
        AUDIO_FUNC_LOGE("msg is null or strLength error!");
        return HDF_ERR_INVALID_PARAM;
    }
    char eventMsg[UEVENT_MSG_LEN] = {0};
    (void)memset_s(eventMsg, UEVENT_MSG_LEN, 0, UEVENT_MSG_LEN);
    ret = memcpy_s(eventMsg, UEVENT_MSG_LEN, msg, strLength);
    if (ret != EOK) {
        AUDIO_FUNC_LOGE("msg copy fail! ret = %{public}d", ret);
        return HDF_FAILURE;
    }

    struct AudioPnpUevent audioPnpUevent = {"", "", "", "", "", "", "", ""};
    char *msgTmp = eventMsg;
    while (*msgTmp != 0) {
        if (strncmp(msgTmp, UEVENT_ACTION, strlen(UEVENT_ACTION)) == 0) {
            msgTmp += strlen(UEVENT_ACTION);
            audioPnpUevent.action = msgTmp;
        } else if (strncmp(msgTmp, UEVENT_NAME, strlen(UEVENT_NAME)) == 0) {
            msgTmp += strlen(UEVENT_NAME);
            audioPnpUevent.name = msgTmp;
        } else if (strncmp(msgTmp, UEVENT_STATE, strlen(UEVENT_STATE)) == 0) {
            msgTmp += strlen(UEVENT_STATE);
            audioPnpUevent.state = msgTmp;
        } else if (strncmp(msgTmp, UEVENT_DEVTYPE, strlen(UEVENT_DEVTYPE)) == 0) {
            msgTmp += strlen(UEVENT_DEVTYPE);
            audioPnpUevent.devType = msgTmp;
        } else if (strncmp(msgTmp, UEVENT_SUBSYSTEM, strlen(UEVENT_SUBSYSTEM)) == 0) {
            msgTmp += strlen(UEVENT_SUBSYSTEM);
            audioPnpUevent.subSystem = msgTmp;
        } else if (strncmp(msgTmp, UEVENT_SWITCH_NAME, strlen(UEVENT_SWITCH_NAME)) == 0) {
            msgTmp += strlen(UEVENT_SWITCH_NAME);
            audioPnpUevent.switchName = msgTmp;
        } else if (strncmp(msgTmp, UEVENT_SWITCH_STATE, strlen(UEVENT_SWITCH_STATE)) == 0) {
            msgTmp += strlen(UEVENT_SWITCH_STATE);
            audioPnpUevent.switchState = msgTmp;
        } else if (strncmp(msgTmp, UEVENT_HDI_NAME, strlen(UEVENT_HDI_NAME)) == 0) {
            msgTmp += strlen(UEVENT_HDI_NAME);
            audioPnpUevent.hidName = msgTmp;
        }
        msgTmp += strlen(msgTmp) + 1; // 1 is a skip character '\0'
    }

    (void)AudioAnalogHeadsetDeviceCheck(&audioPnpUevent);
    (void)AudioDigitalHeadsetDeviceCheck(&audioPnpUevent);
    return HDF_SUCCESS;
}

static int AudioPnpUeventOpen(int *fd)
{
    int socketfd;
    struct sockaddr_nl addr;
    int buffSize = UEVENT_SOCKET_BUFF_SIZE;

    if (memset_s(&addr, sizeof(addr), 0, sizeof(addr)) != EOK) {
        AUDIO_FUNC_LOGE("addr memset_s failed!");
        return HDF_FAILURE;
    }
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = (sa_family_t)getpid();
    addr.nl_groups = UEVENT_SOCKET_GROUPS;

    socketfd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
    if (socketfd < 0) {
        AUDIO_FUNC_LOGE("socketfd failed! ret = %{public}d", socketfd);
        return HDF_FAILURE;
    }

    if (setsockopt(socketfd, SOL_SOCKET, SO_RCVBUF, &buffSize, sizeof(buffSize)) != 0) {
        AUDIO_FUNC_LOGE("setsockopt failed!");
        return HDF_FAILURE;
    }
    if (bind(socketfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        AUDIO_FUNC_LOGE("bind socketfd failed!");
        close(socketfd);
        return HDF_FAILURE;
    }
    *fd = socketfd;
    return HDF_SUCCESS;
}

static void *AudioPnpUeventStart(void *useless)
{
    (void)useless;
    int ret;
    ssize_t rcvlen;
    int socketfd = 0;
    fd_set fds;
    char msg[UEVENT_MSG_LEN];
    struct timeval tv;

    AUDIO_FUNC_LOGI("audio uevent start.");
    if (AudioPnpUeventOpen(&socketfd) != HDF_SUCCESS) {
        return NULL;
    }

    do {
        FD_ZERO(&fds);
        FD_SET(socketfd, &fds);
        tv.tv_sec = TIMEVAL_SECOND;
        tv.tv_usec = TIMEVAL_USECOND;
        ret = select(socketfd + 1, &fds, NULL, NULL, &tv);
        if (ret < 0) {
            continue;
        }
        if (!(ret > 0 && FD_ISSET(socketfd, &fds))) {
            continue;
        }

        (void)memset_s(msg, UEVENT_MSG_LEN, 0, UEVENT_MSG_LEN);
        do {
            if ((rcvlen = recv(socketfd, msg, UEVENT_MSG_LEN, 0)) < 0) {
                return NULL;
            }
            if (rcvlen == UEVENT_MSG_LEN) {
                continue;
            }
            AudioPnpUeventParse(msg, (int32_t)rcvlen);
        } while (rcvlen > 0);
    } while (true);
}

int32_t AudioPnpUeventStartThread(void)
{
    pthread_t thread;
    pthread_attr_t tidsAttr;
    const char *threadName = "pnp_uevent";

    AUDIO_FUNC_LOGI("create audio uevent thread.");
    pthread_attr_init(&tidsAttr);
    pthread_attr_setdetachstate(&tidsAttr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&thread, &tidsAttr, AudioPnpUeventStart, NULL) != 0) {
        AUDIO_FUNC_LOGE("create AudioPnpUeventStart thread failed!");
        return HDF_FAILURE;
    }

    if (pthread_setname_np(thread, threadName) != 0) {
        AUDIO_FUNC_LOGE("AudioPnpUeventStartThread setname failed!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}
