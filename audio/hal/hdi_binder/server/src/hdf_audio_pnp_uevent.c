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
#include "hdf_device_object.h"
#include "osal_time.h"
#include "securec.h"

#define HDF_LOG_TAG HDF_AUDIO_HOST

#define UEVENT_ACTION           "ACTION="
#define UEVENT_NAME             "NAME="
#define UEVENT_STATE            "STATE="
#define UEVENT_DEV_NAME         "DEVNAME="
#define UEVENT_DEVTYPE          "DEVTYPE="
#define UEVENT_SUBSYSTEM        "SUBSYSTEM="
#define UEVENT_SWITCH_NAME      "SWITCH_NAME="
#define UEVENT_SWITCH_STATE     "SWITCH_STATE="
#define UEVENT_ID_MODEL         "ID_MODEL="
#define UEVENT_HDI_NAME         "HID_NAME="
#define UEVENT_ACTION_ADD       "add"
#define UEVENT_ACTION_REMOVE    "remove"
#define UEVENT_ACTION_CHANGE    "change"
#define UEVENT_TYPE_EXTCON      "extcon3"
#define UEVENT_NAME_HEADSET     "headset"
#define UEVENT_STATE_ANALOG_HS0 "MICROPHONE=0"
#define UEVENT_STATE_ANALOG_HS1 "MICROPHONE=1"
#define UEVENT_SUBSYSTEM_SWITCH "switch"
#define UEVENT_SWITCH_NAME_H2W  "h2w"
#define UEVENT_USB_AUDIO        "USB Audio"
#define UEVENT_USB_HEADSET      "HEADSET"
#define UEVENT_SUBSYSTEM_USB        "usb"
#define UEVENT_SUBSYSTEM_USB_DEVICE "usb_device"

#define UEVENT_SOCKET_BUFF_SIZE (64 * 1024)
#define UEVENT_SOCKET_GROUPS    0xffffffff
#define UEVENT_MSG_LEN          2048
#define AUDIO_EVENT_INFO_LEN_MAX 256
#define UEVENT_POLL_WAIT_TIME 100
#define AUDIO_UEVENT_USB_DEVICE_COUNT 10

#define USB_DEV_NAME_LEN_MAX    64
#define USB_DES_LEN_MAX         4096
#define DEV_BUS_USB_DIR         "/dev/bus/usb"
#define BUS_USB_DIR             "bus/usb"
#define USB_IF_DESC_LEN         9
#define USB_IF_CLASS_OFFSET     5
#define USB_IF_SUBCLASS_OFFSET  6
#define USB_AUDIO_DESC_TYPE     0x4
#define USB_AUDIO_CLASS         1
#define USB_AUDIO_SUBCLASS_CTRL 1
#define AUDIO_DEVICE_ONLINE     1
#define AUDIO_DEVICE_WAIT_ONLINE 20
#define AUDIO_DEVICE_WAIT_TRY_TIME 10
#define AUDIO_DEVICE_WAIT_USB_ONLINE 1000
#define AUDIO_DEVICE_WAIT_USB_HEADSET_ONLINE 150
#define UEVENT_ARR_SIZE 9
#define MOVE_NUM 16

#define REMOVE_AUDIO_DEVICE '0'
#define ADD_DEVICE_HEADSET '1'
#define ADD_DEVICE_HEADSET_WITHOUT_MIC '2'
#define ADD_DEVICE_ADAPTER '4'

struct UsbDevice {
    int8_t devName[USB_DEV_NAME_LEN_MAX];
    uint8_t desc[USB_DES_LEN_MAX];
    size_t descLen;
};

struct AudioPnpUevent {
    const char *action;
    const char *name;
    const char *state;
    const char *devType;
    const char *subSystem;
    const char *switchName;
    const char *switchState;
    const char *hidName;
    const char *devName;
};

struct AudioEvent g_audioPnpDeviceState = {
    .eventType = AUDIO_EVENT_UNKNOWN,
    .deviceType = AUDIO_DEVICE_UNKNOWN,
};

static bool IsUpdatePnpDeviceState(struct AudioEvent *pnpDeviceEvent)
{
    if (pnpDeviceEvent->eventType == g_audioPnpDeviceState.eventType &&
        pnpDeviceEvent->deviceType == g_audioPnpDeviceState.deviceType) {
        return false;
    }
    return true;
}

static void UpdatePnpDeviceState(struct AudioEvent *pnpDeviceEvent)
{
    g_audioPnpDeviceState.eventType = pnpDeviceEvent->eventType;
    g_audioPnpDeviceState.deviceType = pnpDeviceEvent->deviceType;
}

static int32_t CheckUsbDesc(struct UsbDevice *usbDevice)
{
    if (usbDevice->descLen > USB_DES_LEN_MAX) {
        AUDIO_FUNC_LOGE("usbDevice->descLen is more than USB_DES_LEN_MAX");
        return HDF_ERR_INVALID_PARAM;
    }
    for (size_t len = 0; len < usbDevice->descLen;) {
        size_t descLen = usbDevice->desc[len];
        if (descLen == 0) {
            AUDIO_FUNC_LOGE("descLen is 0");
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

        /* According to the 1.0 and 2.0 usb standard protocols, the audio field corresponding to the interface
         * description type is: offset=1 interface descriptor type is 4; offset=5 interface class,audio is 1; offset=6
         * interface subclass,audio control is 1 */
        int32_t usbClass = usbDevice->desc[len + USB_IF_CLASS_OFFSET];
        int32_t subClass = usbDevice->desc[len + USB_IF_SUBCLASS_OFFSET];
        if (usbClass == USB_AUDIO_CLASS && subClass == USB_AUDIO_SUBCLASS_CTRL) {
            AUDIO_FUNC_LOGI(
                "descType %{public}d, usbClass %{public}d, subClass %{public}d", descType, usbClass, subClass);
            return AUDIO_DEVICE_ONLINE;
        }
        len += descLen;
    }
    return HDF_SUCCESS;
}

static int32_t ReadAndScanUsbDev(const char *devPath)
{
    FILE *fp = NULL;
    struct UsbDevice usbDevice;
    size_t len;
    errno_t error;
    uint32_t tryTime = 0;
    char realpathRes[PATH_MAX + 1] = {'\0'};

    if (devPath == NULL) {
        AUDIO_FUNC_LOGE("audio devPath null");
        return HDF_FAILURE;
    }

    while (tryTime < AUDIO_DEVICE_WAIT_TRY_TIME) {
        if (realpath(devPath, realpathRes) != NULL) {
            break;
        }

        tryTime++;
        AUDIO_FUNC_LOGW("audio try[%{public}d] realpath fail[%{public}d]", tryTime, errno);
        OsalMSleep(AUDIO_DEVICE_WAIT_ONLINE);
    }

    fp = fopen(realpathRes, "r");
    if (fp == NULL) {
        AUDIO_FUNC_LOGE("audio realpath open fail[%{public}d]", errno);
        return HDF_FAILURE;
    }

    len = fread(usbDevice.desc, 1, sizeof(usbDevice.desc) - 1, fp);
    if (len == 0) {
        AUDIO_FUNC_LOGE("audio realpath read fail");
        (void)fclose(fp);
        return HDF_FAILURE;
    }
    (void)fclose(fp);

    error = strncpy_s((char *)usbDevice.devName, sizeof(usbDevice.devName), realpathRes, sizeof(usbDevice.devName) - 1);
    if (error != EOK) {
        AUDIO_FUNC_LOGE("audio realpath strncpy fail");
        return HDF_FAILURE;
    }

    usbDevice.descLen = len;
    return CheckUsbDesc(&usbDevice);
}

#define SWITCH_STATE_PATH    "/sys/class/switch/h2w/state"
#define STATE_PATH_ITEM_SIZE 1

static int32_t DetectAnalogHeadsetState(struct AudioEvent *audioEvent)
{
    int8_t state = 0;
    FILE *fp = fopen(SWITCH_STATE_PATH, "r");
    if (fp == NULL) {
        AUDIO_FUNC_LOGE("audio open switch state node fail, %{public}d", errno);
        return HDF_ERR_INVALID_PARAM;
    }

    size_t ret = fread(&state, STATE_PATH_ITEM_SIZE, STATE_PATH_ITEM_SIZE, fp);
    if (ret == 0) {
        (void)fclose(fp);
        AUDIO_FUNC_LOGE("audio read switch state node fail, %{public}d", errno);
        return HDF_FAILURE;
    }

    AUDIO_FUNC_LOGI("audio switch state = %{public}c", state);
    if (state == '0') {
        audioEvent->eventType = AUDIO_DEVICE_REMOVE;
        audioEvent->deviceType = AUDIO_HEADSET;
    } else {
        audioEvent->eventType = AUDIO_DEVICE_ADD;
        audioEvent->deviceType = AUDIO_HEADSET;
    }

    (void)fclose(fp);
    return HDF_SUCCESS;
}

struct AudioDevBusUsbDevice {
    bool isUsed;
    int8_t devName[USB_DEV_NAME_LEN_MAX];
};

struct AudioDevBusUsbDevice g_audioUsbDeviceList[AUDIO_UEVENT_USB_DEVICE_COUNT] = {0};

static bool FindAudioUsbDevice(const char *devName)
{
    if (strlen(devName) > USB_DEV_NAME_LEN_MAX - 1) {
        AUDIO_FUNC_LOGE("find usb audio device name exceed max len");
        return false;
    }

    for (uint32_t i = 0; i < AUDIO_UEVENT_USB_DEVICE_COUNT; i++) {
        if (g_audioUsbDeviceList[i].isUsed &&
            (strncmp((char *)g_audioUsbDeviceList[i].devName, devName, strlen(devName)) == EOK)) {
            return true;
        }
    }
    return false;
}
static bool AddAudioUsbDevice(const char *devName)
{
    if (strlen(devName) > USB_DEV_NAME_LEN_MAX - 1) {
        AUDIO_FUNC_LOGE("add usb audio device name exceed max len");
        return false;
    }

    if (FindAudioUsbDevice(devName)) {
        AUDIO_FUNC_LOGI("find usb audio device name[%{public}s]", devName);
        return true;
    }

    for (uint32_t i = 0; i < AUDIO_UEVENT_USB_DEVICE_COUNT; i++) {
        if (g_audioUsbDeviceList[i].isUsed) {
            continue;
        }
        if (strncpy_s((char *)g_audioUsbDeviceList[i].devName, USB_DEV_NAME_LEN_MAX, devName, strlen(devName)) != EOK) {
            AUDIO_FUNC_LOGE("add usb audio device name fail");
            return false;
        }
        g_audioUsbDeviceList[i].isUsed = true;
        return true;
    }
    AUDIO_FUNC_LOGE("add usb audio device name fail");
    return false;
}

static bool DeleteAudioUsbDevice(const char *devName)
{
    if (strlen(devName) > USB_DEV_NAME_LEN_MAX - 1) {
        AUDIO_FUNC_LOGE("delete usb audio device name exceed max len");
        return false;
    }

    for (uint32_t i = 0; i < AUDIO_UEVENT_USB_DEVICE_COUNT; i++) {
        if (g_audioUsbDeviceList[i].isUsed &&
            strncmp((char *)g_audioUsbDeviceList[i].devName, devName, strlen(devName)) == EOK) {
            g_audioUsbDeviceList[i].isUsed = false;
            AUDIO_FUNC_LOGI("delete usb audio device name[%{public}s]", devName);
            return true;
        }
    }

    return false;
}

static bool CheckAudioUsbDevice(const char *devName)
{
    int32_t state = 0;
    int32_t len;
    char subDir[USB_DEV_NAME_LEN_MAX] = {0};

    if (*devName == '\0') {
        return false;
    }
    len = snprintf_s(subDir, USB_DEV_NAME_LEN_MAX, USB_DEV_NAME_LEN_MAX - 1, "/dev/" "%s", devName);
    if (len < 0) {
        AUDIO_FUNC_LOGE("audio snprintf dev dir fail");
        return false;
    }

    AUDIO_FUNC_LOGI("usb device name[%{public}s]", devName);
    state = ReadAndScanUsbDev(subDir);
    if ((state == AUDIO_DEVICE_ONLINE) && AddAudioUsbDevice(devName)) {
        return true;
    }
    return false;
}

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

static int32_t ScanUsbBusSubDir(const char *subDir)
{
    int32_t len;
    DIR *devDir = NULL;
    struct dirent *dirEnt = NULL;

    char devName[USB_DEV_NAME_LEN_MAX] = {0};

    devDir = opendir(subDir);
    if (devDir == NULL) {
        AUDIO_FUNC_LOGE("open usb sub dir failed");
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t state = HDF_SUCCESS;
    while (((dirEnt = readdir(devDir)) != NULL) && (state == HDF_SUCCESS)) {
        if (IsBadName(dirEnt->d_name)) {
            continue;
        }

        len = snprintf_s(devName, USB_DEV_NAME_LEN_MAX, USB_DEV_NAME_LEN_MAX - 1, "%s/%s", subDir, dirEnt->d_name);
        if (len < 0) {
            AUDIO_FUNC_LOGE("audio snprintf dev dir fail");
            state = HDF_FAILURE;
            break;
        }

        AUDIO_FUNC_LOGD("audio usb dir[%{public}s]", devName);
        state = ReadAndScanUsbDev(devName);
        if (state == AUDIO_DEVICE_ONLINE) {
            char *subDevName = devName + strlen("/dev/");
            AUDIO_FUNC_LOGI("audio sub dev dir=[%{public}s]", subDevName);
            if (AddAudioUsbDevice(subDevName)) {
                AUDIO_FUNC_LOGI("audio add usb audio device success");
                break;
            }
        }
    }

    closedir(devDir);
    return state;
}

static int32_t DetectUsbHeadsetState(struct AudioEvent *audioEvent)
{
    int32_t len;
    DIR *busDir = NULL;
    struct dirent *dirEnt = NULL;

    char subDir[USB_DEV_NAME_LEN_MAX] = {0};

    busDir = opendir(DEV_BUS_USB_DIR);
    if (busDir == NULL) {
        AUDIO_FUNC_LOGE("open usb dir failed");
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t state = HDF_SUCCESS;
    while (((dirEnt = readdir(busDir)) != NULL) && (state == HDF_SUCCESS)) {
        if (IsBadName(dirEnt->d_name)) {
            continue;
        }

        len = snprintf_s(subDir, USB_DEV_NAME_LEN_MAX, USB_DEV_NAME_LEN_MAX - 1, DEV_BUS_USB_DIR "/%s", dirEnt->d_name);
        if (len < 0) {
            AUDIO_FUNC_LOGE("audio snprintf dev dir fail");
            break;
        }

        state = ScanUsbBusSubDir(subDir);
        if (state == AUDIO_DEVICE_ONLINE) {
            audioEvent->eventType = AUDIO_DEVICE_ADD;
            audioEvent->deviceType = AUDIO_USB_HEADSET;
            closedir(busDir);
            return HDF_SUCCESS;
        }
    }

    closedir(busDir);
    return HDF_FAILURE;
}

static int32_t AudioUsbHeadsetDetectDevice(struct AudioPnpUevent *audioPnpUevent)
{
    struct AudioEvent audioEvent = {0};

    if (audioPnpUevent == NULL) {
        AUDIO_FUNC_LOGE("audioPnpUevent is null");
        return HDF_ERR_INVALID_PARAM;
    }

    if (audioPnpUevent->action == NULL || audioPnpUevent->devName == NULL || audioPnpUevent->subSystem == NULL ||
        audioPnpUevent->devType == NULL) {
        AUDIO_FUNC_LOGE("audioPnpUevent element is null");
        return HDF_ERR_INVALID_PARAM;
    }

    if ((strcmp(audioPnpUevent->subSystem, UEVENT_SUBSYSTEM_USB) != 0) ||
        (strcmp(audioPnpUevent->devType, UEVENT_SUBSYSTEM_USB_DEVICE) != 0) ||
        (strstr(audioPnpUevent->devName, BUS_USB_DIR) == NULL)) {
        return HDF_ERR_INVALID_PARAM;
    }

    if (strcmp(audioPnpUevent->action, UEVENT_ACTION_ADD) == 0) {
        if (!CheckAudioUsbDevice(audioPnpUevent->devName)) {
            AUDIO_FUNC_LOGW("check audio usb device not exist, not add");
            return HDF_ERR_INVALID_PARAM;
        }
        audioEvent.eventType = AUDIO_DEVICE_ADD;
    } else if (strcmp(audioPnpUevent->action, UEVENT_ACTION_REMOVE) == 0) {
        if (!DeleteAudioUsbDevice(audioPnpUevent->devName)) {
            AUDIO_FUNC_LOGW("check audio usb device[%{public}s] not exist, not delete", audioPnpUevent->devName);
            return HDF_ERR_INVALID_PARAM;
        }
        audioEvent.eventType = AUDIO_DEVICE_REMOVE;
    } else {
        return HDF_FAILURE;
    }

    audioEvent.deviceType = AUDIO_USB_HEADSET;
    AUDIO_FUNC_LOGI("audio usb headset [%{public}s]", audioEvent.eventType == AUDIO_DEVICE_ADD ? "add" : "removed");

    if (!IsUpdatePnpDeviceState(&audioEvent)) {
        AUDIO_FUNC_LOGI("audio usb device[%{public}u] state[%{public}u] not need flush !", audioEvent.deviceType,
            audioEvent.eventType);
        return HDF_SUCCESS;
    }
    UpdatePnpDeviceState(&audioEvent);

    return AudioPnpUpdateInfoOnly(audioEvent);
}

static int32_t SetAudioEventValue(struct AudioEvent *audioEvent, struct AudioPnpUevent *audioPnpUevent)
{
    if (strncmp(audioPnpUevent->subSystem, UEVENT_SUBSYSTEM_SWITCH, strlen(UEVENT_SUBSYSTEM_SWITCH)) == 0) {
        static uint32_t h2wTypeLast = AUDIO_HEADSET;
        if (strncmp(audioPnpUevent->switchName, UEVENT_SWITCH_NAME_H2W, strlen(UEVENT_SWITCH_NAME_H2W)) != 0) {
            AUDIO_FUNC_LOGE("the switch name of 'h2w' not found!");
            return HDF_FAILURE;
        }
        switch (audioPnpUevent->switchState[0]) {
            case REMOVE_AUDIO_DEVICE:
                audioEvent->eventType = AUDIO_DEVICE_REMOVE;
                audioEvent->deviceType = h2wTypeLast;
                break;
            case ADD_DEVICE_HEADSET:
            case ADD_DEVICE_HEADSET_WITHOUT_MIC:
                audioEvent->eventType = AUDIO_DEVICE_ADD;
                audioEvent->deviceType = AUDIO_HEADSET;
                break;
            case ADD_DEVICE_ADAPTER:
                audioEvent->eventType = AUDIO_DEVICE_ADD;
                audioEvent->deviceType = AUDIO_ADAPTER_DEVICE;
                break;
            default:
                audioEvent->eventType = AUDIO_DEVICE_ADD;
                audioEvent->deviceType = AUDIO_DEVICE_UNKNOWN;
                break;
        }
        h2wTypeLast = audioEvent->deviceType;
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
            audioEvent->eventType = AUDIO_DEVICE_REMOVE;
        } else if (strstr(audioPnpUevent->state, UEVENT_STATE_ANALOG_HS1) != NULL) {
            audioEvent->eventType = AUDIO_DEVICE_ADD;
        } else {
            return HDF_FAILURE;
        }
        audioEvent->deviceType = AUDIO_HEADSET;
    }
    return HDF_SUCCESS;
}

static int32_t AudioAnalogHeadsetDetectDevice(struct AudioPnpUevent *audioPnpUevent)
{
    struct AudioEvent audioEvent;
    if (audioPnpUevent == NULL) {
        AUDIO_FUNC_LOGE("audioPnpUevent is null!");
        return HDF_ERR_INVALID_PARAM;
    }
    if (SetAudioEventValue(&audioEvent, audioPnpUevent) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    AUDIO_FUNC_LOGI("audio analog [%{public}s][%{public}s]",
        audioEvent.deviceType == AUDIO_HEADSET ? "headset" : "headphone",
        audioEvent.eventType == AUDIO_DEVICE_ADD ? "add" : "removed");

    if (!IsUpdatePnpDeviceState(&audioEvent)) {
        AUDIO_FUNC_LOGI("audio analog device[%{public}u] state[%{public}u] not need flush !", audioEvent.deviceType,
            audioEvent.eventType);
        return HDF_SUCCESS;
    }
    UpdatePnpDeviceState(&audioEvent);
    return AudioPnpUpdateInfoOnly(audioEvent);
}

static bool AudioPnpUeventParse(const char *msg, const ssize_t strLength)
{
    struct AudioPnpUevent audioPnpUevent = {"", "", "", "", "", "", "", "", ""};

    if (strncmp(msg, "libudev", strlen("libudev")) == 0) {
        return false;
    }

    if (strLength > UEVENT_MSG_LEN + 1) {
        AUDIO_FUNC_LOGE("strLength > UEVENT_MSG_LEN + 1");
        return false;
    }
    for (const char *msgTmp = msg; msgTmp < (msg + strLength);) {
        if (*msgTmp == '\0') {
            msgTmp++;
            continue;
        }
        const char *arrStrTmp[UEVENT_ARR_SIZE] = {
            UEVENT_ACTION, UEVENT_DEV_NAME, UEVENT_NAME, UEVENT_STATE, UEVENT_DEVTYPE,
            UEVENT_SUBSYSTEM, UEVENT_SWITCH_NAME, UEVENT_SWITCH_STATE, UEVENT_HDI_NAME
        };
        const char **arrVarTmp[UEVENT_ARR_SIZE] = {
            &audioPnpUevent.action, &audioPnpUevent.devName, &audioPnpUevent.name,
            &audioPnpUevent.state, &audioPnpUevent.devType, &audioPnpUevent.subSystem,
            &audioPnpUevent.switchName, &audioPnpUevent.switchState, &audioPnpUevent.hidName
        };
        for (int i = 0; i < UEVENT_ARR_SIZE; i++) {
            if (strncmp(msgTmp, arrStrTmp[i], strlen(arrStrTmp[i])) == 0) {
                msgTmp += strlen(arrStrTmp[i]);
                *arrVarTmp[i] = msgTmp;
                break;
            }
        }
        msgTmp += strlen(msgTmp) + 1;
    }

    if (AudioAnalogHeadsetDetectDevice(&audioPnpUevent) == HDF_SUCCESS) {
        return true;
    }
    if (AudioUsbHeadsetDetectDevice(&audioPnpUevent) == HDF_SUCCESS) {
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
    addr.nl_pid = ((uint32_t)gettid() << MOVE_NUM) | (uint32_t)getpid();
    addr.nl_groups = UEVENT_SOCKET_GROUPS;

    socketFd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
    if (socketFd < 0) {
        AUDIO_FUNC_LOGE("socket failed, %{public}d", errno);
        return HDF_FAILURE;
    }

    if (setsockopt(socketFd, SOL_SOCKET, SO_RCVBUF, &buffSize, sizeof(buffSize)) != 0) {
        AUDIO_FUNC_LOGE("setsockopt SO_RCVBUF failed, %{public}d", errno);
        close(socketFd);
        return HDF_FAILURE;
    }

    if (setsockopt(socketFd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) != 0) {
        AUDIO_FUNC_LOGE("setsockopt SO_PASSCRED failed, %{public}d", errno);
        close(socketFd);
        return HDF_FAILURE;
    }

    if (bind(socketFd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        AUDIO_FUNC_LOGE("bind socket failed, %{public}d", errno);
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

static void UpdateDeviceState(struct AudioEvent audioEvent, struct HdfDeviceObject *device)
{
    char pnpInfo[AUDIO_EVENT_INFO_LEN_MAX] = {0};
    int32_t ret;
    if (!IsUpdatePnpDeviceState(&audioEvent)) {
        AUDIO_FUNC_LOGI("audio first pnp device[%{public}u] state[%{public}u] not need flush !", audioEvent.deviceType,
            audioEvent.eventType);
        return;
    }
    ret = snprintf_s(pnpInfo, AUDIO_EVENT_INFO_LEN_MAX, AUDIO_EVENT_INFO_LEN_MAX - 1, "EVENT_TYPE=%u;DEVICE_TYPE=%u",
        audioEvent.eventType, audioEvent.deviceType);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("snprintf_s fail!");
        return;
    }

    UpdatePnpDeviceState(&audioEvent);
    if (HdfDeviceObjectSetServInfo(device, pnpInfo) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("set audio event status info failed!");
    }
    return;
}

#ifdef AUDIO_DOUBLE_PNP_DETECT
static struct AudioEvent g_usbHeadset = {0};
static void* UpdateUsbHeadset(void *arg)
{
    OsalMSleep(AUDIO_DEVICE_WAIT_USB_HEADSET_ONLINE);
    char pnpInfo[AUDIO_EVENT_INFO_LEN_MAX] = {0};
    int32_t ret;
    if (!IsUpdatePnpDeviceState(&g_usbHeadset)) {
        AUDIO_FUNC_LOGI("audio first pnp device[%{public}u] state[%{public}u] not need flush !",
            g_usbHeadset.deviceType, g_usbHeadset.eventType);
        return NULL;
    }
    ret = snprintf_s(pnpInfo, AUDIO_EVENT_INFO_LEN_MAX, AUDIO_EVENT_INFO_LEN_MAX - 1, "EVENT_TYPE=%u;DEVICE_TYPE=%u",
        g_usbHeadset.eventType, g_usbHeadset.deviceType);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("snprintf_s fail!");
        return NULL;
    }

    UpdatePnpDeviceState(&g_usbHeadset);
    struct HdfDeviceObject *device = (struct HdfDeviceObject *)arg;
    if (HdfDeviceObjectSetServInfo(device, pnpInfo) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("set audio event status info failed!");
    }
    if (HdfDeviceObjectUpdate(device) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("update audio status info failed!");
        return NULL;
    }
    return NULL;
}
#endif

void DetectAudioDevice(struct HdfDeviceObject *device)
{
    int32_t ret;
    struct AudioEvent audioEvent = {0};

    OsalMSleep(AUDIO_DEVICE_WAIT_USB_ONLINE); // Wait until the usb node is successfully created
    ret = DetectAnalogHeadsetState(&audioEvent);
    if ((ret == HDF_SUCCESS) && (audioEvent.eventType == AUDIO_DEVICE_ADD)) {
        AUDIO_FUNC_LOGI("audio detect analog headset");
        UpdateDeviceState(audioEvent, device);
#ifndef AUDIO_DOUBLE_PNP_DETECT
        return;
#endif
    }
#ifdef AUDIO_DOUBLE_PNP_DETECT
    ret = DetectUsbHeadsetState(&g_usbHeadset);
    if ((ret == HDF_SUCCESS) && (g_usbHeadset.eventType == AUDIO_DEVICE_ADD)) {
        AUDIO_FUNC_LOGI("audio detect usb headset");
        pthread_t thread;
        pthread_attr_t tidsAttr;
        const char *threadName = "update_usb_headset";
        pthread_attr_init(&tidsAttr);
        pthread_attr_setdetachstate(&tidsAttr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&thread, &tidsAttr, UpdateUsbHeadset, device) != 0) {
            AUDIO_FUNC_LOGE("create audio update usb headset thread failed");
            return;
        }

        if (pthread_setname_np(thread, threadName) != 0) {
            AUDIO_FUNC_LOGE("setname failed");
            return;
        }
    }
#else
    audioEvent.eventType = AUDIO_EVENT_UNKNOWN;
    audioEvent.deviceType = AUDIO_DEVICE_UNKNOWN;
    ret = DetectUsbHeadsetState(&audioEvent);
    if ((ret == HDF_SUCCESS) && (audioEvent.eventType == AUDIO_DEVICE_ADD)) {
        AUDIO_FUNC_LOGI("audio detect usb headset");
        UpdateDeviceState(audioEvent, device);
    }
#endif
    return;
}

static bool g_pnpThreadRunning = false;
static void AudioPnpUeventStart(void *useless)
{
    (void)useless;
    ssize_t rcvLen;
    int socketFd = -1;
    struct pollfd fd;
    char msg[UEVENT_MSG_LEN + 1] = {0};

    AUDIO_FUNC_LOGI("audio uevent start");
    if (AudioPnpUeventOpen(&socketFd) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("open audio pnp socket failed!");
        return;
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
    return;
}

int32_t AudioUsbPnpUeventStartThread(void)
{
    const char *threadName = "pnp_usb";
    g_pnpThreadRunning = true;

    AUDIO_FUNC_LOGI("create audio usb uevent thread");
    FfrtTaskAttr attr;
    FfrtAttrInitFunc()(&attr);
    FfrtAttrSetQosFunc()(&attr, FFRT_QOS_DEFAULT);
    FfrtAttrSetNameFunc()(&attr, threadName);
    FfrtSubmitBaseFunc()(FfrtCreateFunctionWrapper(AudioPnpUeventStart, NULL, NULL), NULL, NULL, &attr);

    return HDF_SUCCESS;
}

void AudioUsbPnpUeventStopThread(void)
{
    AUDIO_FUNC_LOGI("audio pnp uevent thread exit");
    g_pnpThreadRunning = false;
}
