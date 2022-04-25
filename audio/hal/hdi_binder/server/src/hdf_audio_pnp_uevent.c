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

#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "securec.h"
#include "hdf_log.h"
#include "hdf_base.h"
#include "audio_events.h"
#include "hdf_audio_pnp_server.h"
#include "hdf_audio_pnp_uevent.h"

#define UEVENT_ACTION       "ACTION="
#define UEVENT_NAME         "NAME="
#define UEVENT_STATE        "STATE="
#define UEVENT_DEVTYPE      "DEVTYPE="
#define UEVENT_ADD          "add"
#define UEVENT_REMOVE       "remove"
#define UEVENT_TYPE_PORT    "typec_port"
#define UEVENT_DIGITAL_KEY  "USB-C HEADSET"
#define UEVENT_USB_HOST     "USB-HOST=0"
#define UEVENT_ANALOG_KEY   "HEADPHONE=0"

#define AUDIO_HDI_SERVICE_NAME  "audio_hdi_usb_service"
#define AUDIO_TOKEN_SERVER_NAME "ohos.hdi.audio_service"
#define AUDIO_PNP_SEND_USB_CMD  8

#define UEVENT_SOCKET_BUFF_SIZE (64 * 1024)
#define UEVENT_SOCKET_GROUPS    0xffffffff
#define UEVENT_MSG_LEN          2048

#define TIMEVAL_SECOND  0
#define TIMEVAL_USECOND (100 * 1000)

#define AUDIO_PNP_INFO_LEN_MAX 256

#define AUDIO_PNP_STATE_INIT  0
#define AUDIO_PNP_STATE_ON    1
#define AUDIO_PNP_STATE_OFF (-1)

#define HDF_LOG_TAG HDF_AUDIO_HAL_HOST

struct AudioPnpUevent {
    const char *action;
    const char *name;
    const char *state;
    const char *devType;
};

struct AudioUsbPnpTag {
    bool audioPnpState;
    int32_t audioPnpAnalogState;
    int32_t audioPnpDigitalState;
};

static int32_t AudioPnpUpdateAndSend(struct AudioEvent audioEvent)
{
    int32_t ret;
    char pnpInfo[AUDIO_PNP_INFO_LEN_MAX] = {0};

    ret = snprintf_s(pnpInfo, AUDIO_PNP_INFO_LEN_MAX, AUDIO_PNP_INFO_LEN_MAX - 1,
                     "EVENT_TYPE=0x%x;DEVICE_TYPE=0x%x", audioEvent.eventType, audioEvent.deviceType);
    if (ret < 0) {
        HDF_LOGE("%{public}s: snprintf_s fail!", __func__);
        return HDF_FAILURE;
    }

    ret = AudioPnpUpdateInfo(pnpInfo);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: update info fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    ret = AudioPnpStatusSend(AUDIO_HDI_SERVICE_NAME, AUDIO_TOKEN_SERVER_NAME, pnpInfo, AUDIO_PNP_SEND_USB_CMD);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: send info fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}
static int32_t AudioUsbDeviceStateCheck(struct AudioPnpUevent *audioPnpUevent, struct AudioUsbPnpTag *pnpTag)
{
    if (audioPnpUevent == NULL || pnpTag == NULL) {
        HDF_LOGE("%{public}s: audioPnpUevent or pnpTag is null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (strncmp(audioPnpUevent->action, UEVENT_ADD, strlen(UEVENT_ADD)) == 0) {
        pnpTag->audioPnpState = true;
    } else if (strncmp(audioPnpUevent->action, UEVENT_REMOVE, strlen(UEVENT_REMOVE)) == 0) {
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

    if (strstr(audioPnpUevent->name, UEVENT_DIGITAL_KEY) != NULL) {
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

static int32_t AudioPnpUeventParse(const char *msg, const int32_t strLength)
{
    if (msg == NULL || strLength < 0 || strLength > UEVENT_MSG_LEN) {
        HDF_LOGE("%{public}s: msg is null or strLength error!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    char eventMsg[UEVENT_MSG_LEN] = {0};
    (void)memset_s(eventMsg, UEVENT_MSG_LEN, 0, UEVENT_MSG_LEN);
    errno_t ret = memcpy_s(eventMsg, UEVENT_MSG_LEN, msg, strLength);
    if (ret != EOK) {
        HDF_LOGE("%{public}s: msg copy fail! ret = %{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    struct AudioPnpUevent audioPnpUevent = {
        .action = "",
        .name = "",
        .state = "",
        .devType = "",
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
        }
        msgTmp += strlen(msgTmp) + 1; // 1 is a skip character '\0'
    }

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
    if (bind(socketfd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
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
