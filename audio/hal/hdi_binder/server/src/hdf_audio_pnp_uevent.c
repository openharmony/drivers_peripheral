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
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include "hdf_audio_pnp_server.h"
#include "hdf_base.h"
#include "hdf_log.h"
#include "securec.h"

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
#define UEVENT_TYPE_PORT        "typec_port"
#define UEVENT_TYPE_EXTCON      "extcon3"
#define UEVENT_NAME_DIGITAL_KEY "USB-C HEADSET"
#define UEVENT_NAME_HEADSET     "headset"
#define UEVENT_USB_HOST         "USB-HOST=0"
#define UEVENT_ANALOG_KEY       "HEADPHONE=0"
#define UEVENT_STATE_ANALOG_HS0 "MICROPHONE=0"
#define UEVENT_STATE_ANALOG_HS1 "MICROPHONE=1"
#define UEVENT_SUBSYSTEM_SWITCH "switch"
#define UEVENT_SWITCH_NAME_H2W  "h2w"

#define UEVENT_SOCKET_BUFF_SIZE (64 * 1024)
#define UEVENT_SOCKET_GROUPS    0xffffffff
#define UEVENT_MSG_LEN          2048

#define TIMEVAL_SECOND  0
#define TIMEVAL_USECOND (100 * 1000)

#define AUDIO_PNP_STATE_INIT 0
#define AUDIO_PNP_STATE_ON   1
#define AUDIO_PNP_STATE_OFF  (-1)

#define HDF_LOG_TAG HDF_AUDIO_HAL_HOST

struct AudioPnpUevent {
    const char *action;
    const char *name;
    const char *state;
    const char *devType;
    const char *subSystem;
    const char *switchName;
    const char *switchState;
};

struct AudioUsbPnpTag {
    bool audioPnpState;
    int32_t audioPnpAnalogState;
    int32_t audioPnpDigitalState;
};

static int32_t AudioUsbDeviceStateCheck(struct AudioPnpUevent *audioPnpUevent, struct AudioUsbPnpTag *pnpTag)
{
    if (audioPnpUevent == NULL || pnpTag == NULL) {
        HDF_LOGE("%{public}s: audioPnpUevent or pnpTag is null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (strncmp(audioPnpUevent->action, UEVENT_ACTION_ADD, strlen(UEVENT_ACTION_ADD)) == 0) {
        pnpTag->audioPnpState = true;
    } else if (strncmp(audioPnpUevent->action, UEVENT_ACTION_REMOVE, strlen(UEVENT_ACTION_REMOVE)) == 0) {
        pnpTag->audioPnpState = false;
    }

    return HDF_SUCCESS;
}

static int32_t AudioUsbDigitalDeviceCheck(struct AudioPnpUevent *audioPnpUevent, struct AudioUsbPnpTag *pnpTag)
{
    struct AudioEvent audioEvent;
    if (audioPnpUevent == NULL || pnpTag == NULL) {
        HDF_LOGE("%{public}s: audioPnpUevent or pnpTag is null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (strstr(audioPnpUevent->name, UEVENT_NAME_DIGITAL_KEY) != NULL) {
        if (pnpTag->audioPnpState) {
            pnpTag->audioPnpDigitalState = AUDIO_PNP_STATE_OFF;
            HDF_LOGI("%{public}s: USB-C DIGITAL HEADSET Online.", __func__);
            audioEvent.eventType = HDF_AUDIO_DEVICE_ADD;
            audioEvent.deviceType = HDF_AUDIO_USBA_HEADPHONE;
            AudioPnpUpdateAndSend(audioEvent);
        } else {
            pnpTag->audioPnpDigitalState = AUDIO_PNP_STATE_OFF;
            HDF_LOGI("%{public}s: USB-C DIGITAL HEADSET Offline.", __func__);
            audioEvent.eventType = HDF_AUDIO_DEVICE_REMOVE;
            audioEvent.deviceType = HDF_AUDIO_USBA_HEADPHONE;
            AudioPnpUpdateAndSend(audioEvent);
        }
    }

    return HDF_SUCCESS;
}

static int32_t AudioUsbAnalogDeviceCheck(struct AudioPnpUevent *audioPnpUevent, struct AudioUsbPnpTag *pnpTag)
{
    struct AudioEvent audioEvent;
    if (audioPnpUevent == NULL || pnpTag == NULL) {
        HDF_LOGE("%{public}s: audioPnpUevent or pnpTag is null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (strncmp(audioPnpUevent->devType, UEVENT_TYPE_PORT, strlen(UEVENT_TYPE_PORT)) == 0) {
        pnpTag->audioPnpAnalogState = AUDIO_PNP_STATE_ON;
    }
    if (strstr(audioPnpUevent->state, UEVENT_USB_HOST) != NULL && pnpTag->audioPnpAnalogState ==
        AUDIO_PNP_STATE_ON && pnpTag->audioPnpDigitalState != AUDIO_PNP_STATE_OFF) {
        if (strstr(audioPnpUevent->state, UEVENT_ANALOG_KEY) != NULL) {
            pnpTag->audioPnpAnalogState = AUDIO_PNP_STATE_INIT;
            HDF_LOGI("%{public}s: USB-C ANALOG HEADSET Online.", __func__);
            audioEvent.eventType = HDF_AUDIO_DEVICE_ADD;
            audioEvent.deviceType = HDF_AUDIO_USB_HEADPHONE;
            AudioPnpUpdateAndSend(audioEvent);
        } else if (strstr(audioPnpUevent->state, UEVENT_ANALOG_KEY) != NULL) {
            pnpTag->audioPnpAnalogState = AUDIO_PNP_STATE_INIT;
            HDF_LOGI("%{public}s: USB-C ANALOG HEADSET Offline.", __func__);
            audioEvent.eventType = HDF_AUDIO_DEVICE_REMOVE;
            audioEvent.deviceType = HDF_AUDIO_USB_HEADPHONE;
            AudioPnpUpdateAndSend(audioEvent);
        }
        pnpTag->audioPnpDigitalState = AUDIO_PNP_STATE_INIT;
    }

    return HDF_SUCCESS;
}

static int32_t AudioPnpUeventCompare(struct AudioPnpUevent *audioPnpUevent)
{
    static struct AudioUsbPnpTag audioUsbPnpTag = {
        .audioPnpState = false,
        .audioPnpAnalogState = AUDIO_PNP_STATE_INIT,
        .audioPnpDigitalState = AUDIO_PNP_STATE_INIT,
    };
    if (AudioUsbDeviceStateCheck(audioPnpUevent, &audioUsbPnpTag) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: usb status add/remove fail!", __func__);
        return HDF_FAILURE;
    }
    if (AudioUsbDigitalDeviceCheck(audioPnpUevent, &audioUsbPnpTag) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: usb digital headset/phone check fail!", __func__);
        return HDF_FAILURE;
    }
    if (AudioUsbAnalogDeviceCheck(audioPnpUevent, &audioUsbPnpTag) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: usb analog headset/phone check fail!", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t AudioAnalogHeadsetDeviceCheck(struct AudioPnpUevent *audioPnpUevent)
{
    struct AudioEvent audioEvent;
    static int32_t h2wTypeLast = HDF_AUDIO_HEADSET;
    if (audioPnpUevent == NULL) {
        HDF_LOGE("%{public}s: audioPnpUevent is null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (strncmp(audioPnpUevent->subSystem, UEVENT_SUBSYSTEM_SWITCH, strlen(UEVENT_SUBSYSTEM_SWITCH)) == 0) {
        if (strncmp(audioPnpUevent->switchName, UEVENT_SWITCH_NAME_H2W, strlen(UEVENT_SWITCH_NAME_H2W)) != 0) {
            HDF_LOGE("%{public}s: the switch name of 'h2w' not found!", __func__);
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
            HDF_LOGE("%{public}s: don't surpport headset type, name = %{public}s!", __func__, audioPnpUevent->name);
            return HDF_FAILURE;
        }
        if (strncmp(audioPnpUevent->devType, UEVENT_TYPE_EXTCON, strlen(UEVENT_TYPE_EXTCON)) != 0) {
            HDF_LOGE("%{public}s: don't surpport devType = %{public}s!", __func__, audioPnpUevent->devType);
            return HDF_FAILURE;
        }
        if (strstr(audioPnpUevent->state, UEVENT_STATE_ANALOG_HS0) != NULL) {
            audioEvent.eventType = HDF_AUDIO_DEVICE_REMOVE;
        } else if (strstr(audioPnpUevent->state, UEVENT_STATE_ANALOG_HS1) != NULL) {
            audioEvent.eventType = HDF_AUDIO_DEVICE_ADD;
        } else {
            HDF_LOGE("%{public}s: don't surpport type, state = %{public}s!", __func__, audioPnpUevent->state);
            return HDF_FAILURE;
        }
        audioEvent.deviceType = HDF_AUDIO_HEADSET;
    }
    return AudioPnpUpdateInfoOnly(audioEvent);
}

static int32_t AudioPnpUeventParse(const char *msg, const int32_t strLength)
{
    errno_t ret;
    if (msg == NULL || strLength < 0 || strLength > UEVENT_MSG_LEN) {
        HDF_LOGE("%{public}s: msg is null or strLength error!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    char eventMsg[UEVENT_MSG_LEN] = {0};
    (void)memset_s(eventMsg, UEVENT_MSG_LEN, 0, UEVENT_MSG_LEN);
    ret = memcpy_s(eventMsg, UEVENT_MSG_LEN, msg, strLength);
    if (ret != EOK) {
        HDF_LOGE("%{public}s: msg copy fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    struct AudioPnpUevent audioPnpUevent = {
        .action = "",
        .name = "",
        .state = "",
        .devType = "",
        .subSystem = "",
        .switchName = "",
        .switchState = ""
    };
    char *msgTmp = eventMsg;
    while (*msgTmp) {
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
        }
        msgTmp += strlen(msgTmp) + 1; // 1 is a skip character '\0'
    }
    (void)AudioAnalogHeadsetDeviceCheck(&audioPnpUevent);
    return AudioPnpUeventCompare(&audioPnpUevent);
}

static int AudioPnpUeventOpen(int *fd)
{
    int socketfd;
    struct sockaddr_nl addr;
    int buffSize = UEVENT_SOCKET_BUFF_SIZE;

    if (memset_s(&addr, sizeof(addr), 0, sizeof(addr)) != EOK) {
        HDF_LOGE("%{public}s: addr memset_s failed!", __func__);
        return HDF_FAILURE;
    }
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = UEVENT_SOCKET_GROUPS;

    socketfd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
    if (socketfd < 0) {
        HDF_LOGE("%{public}s: socketfd failed! ret = %{public}d", __func__, socketfd);
        return HDF_FAILURE;
    }

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

static void *AudioPnpUeventStart(void *useless)
{
    (void)useless;
    int ret;
    int rcvlen;
    int socketfd = 0;
    fd_set fds;
    char msg[UEVENT_MSG_LEN];
    struct timeval tv;

    HDF_LOGI("%{public}s: audio uevent start.", __func__);
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
            AudioPnpUeventParse(msg, rcvlen);
        } while (rcvlen > 0);
    } while (1);
}

int32_t AudioPnpUeventStartThread(void)
{
    pthread_t thread;
    pthread_attr_t tidsAttr;

    HDF_LOGI("%{public}s: create audio uevent thread.", __func__);
    pthread_attr_init(&tidsAttr);
    pthread_attr_setdetachstate(&tidsAttr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&thread, &tidsAttr, AudioPnpUeventStart, NULL)) {
        HDF_LOGE("%{public}s: create AudioPnpUeventStart thread failed!", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}
