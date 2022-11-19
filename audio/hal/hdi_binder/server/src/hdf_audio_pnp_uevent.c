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
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>

#include <linux/netlink.h>

#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "audio_uhdf_log.h"
#include "hdf_audio_pnp_server.h"
#include "hdf_base.h"
#include "osal_time.h"
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

#define UEVENT_POLL_WAIT_TIME 100

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
    static uint32_t h2wTypeLast = HDF_AUDIO_HEADSET;
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
        } else if ((audioPnpUevent->switchState[0] == '1') || (audioPnpUevent->switchState[0] == '2')) { // 1-2: headset
            audioEvent.eventType = HDF_AUDIO_DEVICE_ADD;
            audioEvent.deviceType = HDF_AUDIO_HEADSET;
        } else {
            audioEvent.eventType = HDF_AUDIO_DEVICE_ADD;
            audioEvent.deviceType = HDF_AUDIO_DEVICE_UNKOWN;
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

    AUDIO_FUNC_LOGI("audio analog [%{public}s][%{public}s]",
        audioEvent.deviceType == HDF_AUDIO_HEADSET ? "headset" : "headphone",
        audioEvent.eventType == HDF_AUDIO_DEVICE_ADD ? "add" : "removed");

    return AudioPnpUpdateInfoOnly(audioEvent);
}

static int32_t AudioDigitalHeadsetDeviceCheck(struct AudioPnpUevent *audioPnpUevent)
{
    struct AudioEvent audioEvent;

    if (audioPnpUevent == NULL) {
        AUDIO_FUNC_LOGE("audioPnpUevent is null");
        return HDF_ERR_INVALID_PARAM;
    }

    if (audioPnpUevent->action == NULL || audioPnpUevent->hidName == NULL) {
        AUDIO_FUNC_LOGE("action or hidName is null");
        return HDF_ERR_INVALID_PARAM;
    }

    if ((strstr(audioPnpUevent->hidName, UEVENT_USB_AUDIO) == NULL) &&
        (strstr(audioPnpUevent->hidName, UEVENT_USB_HEADSET) == NULL)) {
        return HDF_FAILURE;
    }

    if (strcmp(audioPnpUevent->action, UEVENT_ACTION_ADD) == 0) {
        audioEvent.eventType = HDF_AUDIO_DEVICE_ADD;
    } else if (strcmp(audioPnpUevent->action, UEVENT_ACTION_REMOVE) == 0) {
        audioEvent.eventType = HDF_AUDIO_DEVICE_REMOVE;
    } else {
        return HDF_FAILURE;
    }
    audioEvent.deviceType = HDF_AUDIO_USB_HEADSET;
    AUDIO_FUNC_LOGI("audio usb [%{public}s][%{public}s]", audioPnpUevent->hidName,
        audioEvent.eventType == HDF_AUDIO_DEVICE_ADD ? "add" : "removed");

    return AudioPnpUpdateAndSend(audioEvent);
}

static bool AudioPnpUeventParse(const char *msg, const ssize_t strLength)
{
    struct AudioPnpUevent audioPnpUevent = {"", "", "", "", "", "", "", ""};

    if (strncmp(msg, "libudev", strlen("libudev")) == 0) {
        return false;
    }

    for (const char *msgTmp = msg; msgTmp < (msg + strLength);) {
        if (*msgTmp == '\0') {
            msgTmp++;
            continue;
        }

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
        msgTmp += strlen(msgTmp) + 1;
    }

    if (AudioAnalogHeadsetDeviceCheck(&audioPnpUevent) == HDF_SUCCESS) {
        return true;
    }
    if (AudioDigitalHeadsetDeviceCheck(&audioPnpUevent) == HDF_SUCCESS) {
        return true;
    }

    return false;
}

static int AudioPnpUeventOpen(int *fd)
{
    int socketFd = -1;
    int buffSize = UEVENT_SOCKET_BUFF_SIZE;
    const int32_t on = 1; // turn on passcred
    struct sockaddr_nl addr;

    if (memset_s(&addr, sizeof(addr), 0, sizeof(addr)) != EOK) {
        AUDIO_FUNC_LOGE("addr memset_s failed!");
        return HDF_FAILURE;
    }
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = (sa_family_t)getpid();
    addr.nl_groups = UEVENT_SOCKET_GROUPS;

    socketFd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
    if (socketFd < 0) {
        AUDIO_FUNC_LOGE("socketFd failed! ret = %{public}d", socketFd);
        return HDF_FAILURE;
    }

    if (setsockopt(socketFd, SOL_SOCKET, SO_RCVBUF, &buffSize, sizeof(buffSize)) != 0) {
        AUDIO_FUNC_LOGE("setsockopt failed!");
        close(socketFd);
        return HDF_FAILURE;
    }

    if (setsockopt(socketFd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) != 0) {
        AUDIO_FUNC_LOGE("setsockopt failed!");
        close(socketFd);
        return HDF_FAILURE;
    }

    if (bind(socketFd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        AUDIO_FUNC_LOGE("bind socketFd failed!");
        close(socketFd);
        return HDF_FAILURE;
    }

    *fd = socketFd;

    return HDF_SUCCESS;
}

static ssize_t AudioPnpReadUeventMsg(int sockFd, char *buffer, size_t length)
{
    char credMsg[CMSG_SPACE(sizeof(struct ucred))] = {0};
    struct iovec iov;
    struct sockaddr_nl addr;
    struct msghdr msghdr = {0};

    (void)memset_s(&addr, sizeof(addr), 0, sizeof(addr));

    iov.iov_base = buffer;
    iov.iov_len = length;

    msghdr.msg_name = &addr;
    msghdr.msg_namelen = sizeof(addr);
    msghdr.msg_iov = &iov;
    msghdr.msg_iovlen = 1;
    msghdr.msg_control = credMsg;
    msghdr.msg_controllen = sizeof(credMsg);

    ssize_t len = recvmsg(sockFd, &msghdr, 0);
    if (len <= 0) {
        return HDF_FAILURE;
    }

    struct cmsghdr *hdr = CMSG_FIRSTHDR(&msghdr);
    if (hdr == NULL || hdr->cmsg_type != SCM_CREDENTIALS) {
        AUDIO_FUNC_LOGW("Unexpected control message, ignored");
        *buffer = '\0';
        return HDF_FAILURE;
    }

    return len;
}

static bool g_pnpThreadRunning = false;
static void *AudioPnpUeventStart(void *useless)
{
    (void)useless;
    ssize_t rcvLen;
    int socketFd = -1;
    struct pollfd fd;
    char msg[UEVENT_MSG_LEN + 1] = {0};

    AUDIO_FUNC_LOGI("audio uevent start");
    if (AudioPnpUeventOpen(&socketFd) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("open audio pnp socket failed!");
        return NULL;
    }

    fd.fd = socketFd;
    fd.events = POLLIN | POLLERR;
    fd.revents = 0;

    while (g_pnpThreadRunning) {
        if (poll(&fd, 1, -1) <= 0) {
            AUDIO_FUNC_LOGE("audio event poll fail %{public}d", errno);
            OsalMSleep(UEVENT_POLL_WAIT_TIME);
            continue;
        }

        if (((uint32_t)fd.revents & POLLIN) == POLLIN) {
            (void)memset_s(&msg, sizeof(msg), 0, sizeof(msg));
            rcvLen = AudioPnpReadUeventMsg(socketFd, msg, UEVENT_MSG_LEN);
            if (rcvLen <= 0) {
                continue;
            }

            if (!AudioPnpUeventParse(msg, rcvLen)) {
                continue;
            }
        } else if (((uint32_t)fd.revents & POLLERR) == POLLERR) {
            AUDIO_FUNC_LOGE("audio event poll error");
        }
    }

    close(socketFd);
    return NULL;
}

int32_t AudioPnpUeventStartThread(void)
{
    pthread_t thread;
    pthread_attr_t tidsAttr;

    const char *threadName = "pnp_uevent";
    g_pnpThreadRunning = true;

    AUDIO_FUNC_LOGI("create audio uevent thread");
    pthread_attr_init(&tidsAttr);
    pthread_attr_setdetachstate(&tidsAttr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&thread, &tidsAttr, AudioPnpUeventStart, NULL) != 0) {
        AUDIO_FUNC_LOGE("create audio pnp uevent thread failed");
        return HDF_FAILURE;
    }

    if (pthread_setname_np(thread, threadName) != 0) {
        AUDIO_FUNC_LOGE("AudioPnpUeventStartThread setname failed");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

void AudioPnpUeventStopThread(void)
{
    AUDIO_FUNC_LOGI("audio pnp uevent thread exit");
    g_pnpThreadRunning = false;
}

#define USB_DEV_NAME_LEN_MAX    64
#define USB_DES_LEN_MAX         4096
#define DEV_BUS_USB_DIR         "/dev/bus/usb"
#define USB_IF_DESC_LEN         9
#define USB_IF_CLASS_OFFSET     5
#define USB_IF_SUBCLASS_OFFSET  6
#define USB_AUDIO_DESC_TYPE     0x4
#define USB_AUDIO_CLASS         1
#define USB_AUDIO_SUBCLASS_CNTL 1
#define AUDIO_DEVICE_ONLINE     1

struct UsbDevice {
    int8_t devName[USB_DEV_NAME_LEN_MAX];
    uint8_t desc[USB_DES_LEN_MAX];
    size_t descLen;
};

static inline bool IsBadName(const char *name)
{
    if (*name == '\0') {
        AUDIO_FUNC_LOGE("name is null");
        return true;
    }

    while (*name != '\0') {
        if (isdigit(*name++) == 0) {
            return true;
        }
    }
    return false;
}

static int32_t CheckUsbDesc(struct UsbDevice *usbDevice)
{
    for (size_t len = 0; len < usbDevice->descLen;) {
        size_t descLen = usbDevice->desc[len];
        if (descLen == 0) {
            return HDF_ERR_INVALID_PARAM;
        }

        if (descLen < USB_IF_DESC_LEN) {
            len += descLen;
            continue;
        }

        int32_t descType = usbDevice->desc[len + 1];
        if (descType != USB_AUDIO_DESC_TYPE) {
            len += descLen;
            continue;
        }

        int32_t usbClass = usbDevice->desc[len + USB_IF_CLASS_OFFSET];
        int32_t subClass = usbDevice->desc[len + USB_IF_SUBCLASS_OFFSET];
        if (usbClass == USB_AUDIO_CLASS && subClass == USB_AUDIO_SUBCLASS_CNTL) {
            AUDIO_FUNC_LOGI(
                "descType %{public}d, usbClass %{public}d, subClass %{public}d", descType, usbClass, subClass);
            return AUDIO_DEVICE_ONLINE;
        }
        len += descLen;
    }
    return HDF_SUCCESS;
}

static int32_t ReadAndScanUsbDev(char *devPath)
{
    int fd = -1;
    struct UsbDevice usbDevice;
    ssize_t len;
    errno_t error;
    char realpathRes[PATH_MAX + 1] = {'\0'};

    if (realpath(devPath, realpathRes) == NULL) {
        AUDIO_FUNC_LOGE("audio realpath fail");
        return HDF_FAILURE;
    }

    fd = open(realpathRes, O_RDONLY);
    if (fd < 0) {
        AUDIO_FUNC_LOGE("audio realpath open fail");
        return HDF_FAILURE;
    }

    len = read(fd, usbDevice.desc, sizeof(usbDevice.desc));
    if (len < 0) {
        AUDIO_FUNC_LOGE("audio realpath read fail");
        return HDF_FAILURE;
    }

    error = strncpy_s((char *)usbDevice.devName, sizeof(usbDevice.devName), realpathRes, sizeof(usbDevice.devName) - 1);
    if (error != EOK) {
        AUDIO_FUNC_LOGE("audio realpath strncpy fail");
        return HDF_FAILURE;
    }

    usbDevice.descLen = (size_t)len;
    return CheckUsbDesc(&usbDevice);
}

static int32_t ScanUsbBusSubDir(char *subDir)
{
    int32_t ret = 0;
    int32_t len;
    DIR *devDir;
    struct dirent *dirEnt = NULL;
    char devName[USB_DEV_NAME_LEN_MAX] = {0};

    devDir = opendir(subDir);
    if (devDir == NULL) {
        AUDIO_FUNC_LOGE("audio open sub dir fail");
        return HDF_ERR_INVALID_PARAM;
    }

    while (((dirEnt = readdir(devDir)) != NULL) && (ret == 0)) {
        if (IsBadName(dirEnt->d_name)) {
            continue;
        }

        len = snprintf_s(devName, USB_DEV_NAME_LEN_MAX, (USB_DEV_NAME_LEN_MAX - 1), "%s%s", subDir, dirEnt->d_name);
        if (len < 0) {
            closedir(devDir);
            AUDIO_FUNC_LOGE("audio snprintf sub dir fail");
            return HDF_FAILURE;
        }

        ret = ReadAndScanUsbDev(devName);
        if (ret > 0) {
            closedir(devDir);
            AUDIO_FUNC_LOGE("audio ReadAndScanUsbDev fail");
            return ret;
        }
    }

    closedir(devDir);
    return ret;
}

static int32_t DetectAudioUsbDeviceState(void)
{
    int32_t ret = 0;
    int32_t len;
    DIR *busDir = NULL;
    struct dirent *dirEnt = NULL;
    char subDir[USB_DEV_NAME_LEN_MAX] = {0};

    busDir = opendir(DEV_BUS_USB_DIR);
    if (busDir == NULL) {
        AUDIO_FUNC_LOGE("audio open bus dir fail");
        return HDF_ERR_INVALID_PARAM;
    }

    while (((dirEnt = readdir(busDir)) != NULL) && (ret == 0)) {
        if (IsBadName(dirEnt->d_name)) {
            continue;
        }

        len = snprintf_s(subDir, USB_DEV_NAME_LEN_MAX, USB_DEV_NAME_LEN_MAX - 1, DEV_BUS_USB_DIR "/%s", dirEnt->d_name);
        if (len < 0) {
            closedir(busDir);
            AUDIO_FUNC_LOGE("audio snprintf bus dir fail");
            return HDF_FAILURE;
        }

        ret = ScanUsbBusSubDir(subDir);
        if (ret > 0) {
            break;
        }
    }

    closedir(busDir);
    return ret;
}

#define SWITCH_STATE_PATH    "/sys/class/switch/h2w/state"
#define STATE_PATH_ITEM_SIZE 1

static int32_t DetectAnalogHeadsetState(void)
{
    int8_t state = 0;
    FILE *fp = fopen(SWITCH_STATE_PATH, "r");
    if (fp == NULL) {
        AUDIO_FUNC_LOGE("audio open switch state node fail");
        return HDF_ERR_INVALID_PARAM;
    }

    size_t ret = fread(&state, STATE_PATH_ITEM_SIZE, STATE_PATH_ITEM_SIZE, fp);
    if (ret == 0) {
        fclose(fp);
        AUDIO_FUNC_LOGE("audio read switch state node fail");
        return HDF_FAILURE;
    }

    (void)fclose(fp);
    AUDIO_FUNC_LOGI("audio switch state = %{public}c", state);
    return (state != '0') ? AUDIO_DEVICE_ONLINE : 0;
}

bool DetectAudioUsbDevice(void)
{
    return (DetectAudioUsbDeviceState() > 0);
}

bool DetectAudioAnalogHeadsetDevice(void)
{
    return (DetectAnalogHeadsetState() > 0);
}
