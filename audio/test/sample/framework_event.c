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

#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include "securec.h"
#include "hdf_base.h"
#include "hdf_io_service_if.h"
#include "hdf_service_status.h"
#include "servmgr_hdi.h"
#include "servstat_listener_hdi.h"
#include "audio_events.h"
#include "hdf_audio_events.h"

#define AUDIO_FUNC_LOGE(fmt, arg...) do { \
        printf("%s: [%s]: [%d]:[ERROR]:" fmt"\n", __FILE__, __func__, __LINE__, ##arg); \
    } while (0)

static int32_t AudioServiceDeviceVal(enum AudioDeviceType deviceType)
{
    switch (deviceType) {
        case HDF_AUDIO_PRIMARY_DEVICE: // primary Service
            printf("*****************: Primary service valid.\n");
            return HDF_SUCCESS;
        case HDF_AUDIO_USB_DEVICE: // Usb Service
            printf("*****************: USB service valid.\n");
            return HDF_SUCCESS;
        case HDF_AUDIO_A2DP_DEVICE: // A2dp Service
            return HDF_ERR_NOT_SUPPORT;
        default:
            return HDF_FAILURE;
    }
}

static int32_t AudioServiceDeviceInVal(enum AudioDeviceType deviceType)
{
    switch (deviceType) {
        case HDF_AUDIO_PRIMARY_DEVICE: // primary Service
            printf("*****************: Primary service Invalid.\n");
            return HDF_SUCCESS;
        case HDF_AUDIO_USB_DEVICE: // Usb Service
            printf("*****************: USB service Invalid.\n");
            return HDF_SUCCESS;
        case HDF_AUDIO_A2DP_DEVICE: // A2dp Service
            return HDF_ERR_NOT_SUPPORT;
        default:
            return HDF_FAILURE;
    }
}

static int32_t AudioServiceMsgParse(struct AudioEvent *svcMsg)
{
    if (svcMsg == NULL) {
        return HDF_FAILURE;
    }

    switch (svcMsg->eventType) {
        case HDF_AUDIO_EVENT_UNKOWN:
            return HDF_FAILURE;
        case HDF_AUDIO_SERVICE_VALID:
            return AudioServiceDeviceVal(svcMsg->deviceType);
        case HDF_AUDIO_SERVICE_INVALID:
            return AudioServiceDeviceInVal(svcMsg->deviceType);
        default:
            return HDF_FAILURE;
    }
}

static int AudioGetServiceStatus(const struct ServiceStatus *svcStatus)
{
    if (svcStatus == NULL) {
        return HDF_FAILURE;
    }

    struct AudioEvent serviceMsg = {
        .eventType = HDF_AUDIO_EVENT_UNKOWN,
        .deviceType = HDF_AUDIO_DEVICE_UNKOWN,
    };
    char strTemp[AUDIO_PNP_MSG_LEN_MAX] = {0};
    if (memcpy_s(strTemp, AUDIO_PNP_MSG_LEN_MAX, (char *)svcStatus->info, strlen((char *)svcStatus->info))) {
        return HDF_FAILURE;
    }
    if ((AudioPnpMsgReadValue(strTemp, "EVENT_SERVICE_TYPE", &(serviceMsg.eventType)) != HDF_SUCCESS) ||
        (AudioPnpMsgReadValue(strTemp, "DEVICE_TYPE", &(serviceMsg.deviceType)) != HDF_SUCCESS)) {
        return HDF_FAILURE;
    }
    if (AudioServiceMsgParse(&serviceMsg) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t AudioLoadDeviceSucc(enum AudioDeviceType deviceType)
{
    switch (deviceType) {
        case HDF_AUDIO_PRIMARY_DEVICE: // primary load
            printf("*****************: Primary load success.\n");
            return HDF_SUCCESS;
        case HDF_AUDIO_USB_DEVICE: // Usb load
            printf("*****************: USB load success.\n");
            return HDF_SUCCESS;
        case HDF_AUDIO_A2DP_DEVICE: // A2dp load
            return HDF_ERR_NOT_SUPPORT;
        default:
            return HDF_FAILURE;
    }
}

static int32_t AudioLoadDeviceFail(enum AudioDeviceType deviceType)
{
    switch (deviceType) {
        case HDF_AUDIO_PRIMARY_DEVICE: // primary load
            printf("*****************: Primary load fail.\n");
            return HDF_SUCCESS;
        case HDF_AUDIO_USB_DEVICE: // Usb load
            printf("*****************: USB load fail.\n");
            return HDF_SUCCESS;
        case HDF_AUDIO_A2DP_DEVICE: // A2dp load
            return HDF_ERR_NOT_SUPPORT;
        default:
            return HDF_FAILURE;
    }
}

static int32_t AudioUnLoadDevice(enum AudioDeviceType deviceType)
{
    switch (deviceType) {
        case HDF_AUDIO_PRIMARY_DEVICE: // primary load
            printf("*****************: Primary unload.\n");
            return HDF_SUCCESS;
        case HDF_AUDIO_USB_DEVICE: // Usb load
            printf("*****************: USB unload.\n");
            return HDF_SUCCESS;
        case HDF_AUDIO_A2DP_DEVICE: // A2dp load
            return HDF_ERR_NOT_SUPPORT;
        default:
            return HDF_FAILURE;
    }
}

static int32_t AudioLoadMsgParse(struct AudioEvent *loadMsg)
{
    if (loadMsg == NULL) {
        return HDF_FAILURE;
    }

    switch (loadMsg->eventType) {
        case HDF_AUDIO_LOAD_SUCCESS:
            return AudioLoadDeviceSucc(loadMsg->deviceType);
        case HDF_AUDIO_LOAD_FAILURE:
            return AudioLoadDeviceFail(loadMsg->deviceType);
        case HDF_AUDIO_UNLOAD:
            return AudioUnLoadDevice(loadMsg->deviceType);
        default:
            return HDF_FAILURE;
    }
}

static int AudioGetLoadStatus(struct ServiceStatus *svcStatus)
{
    if (svcStatus == NULL) {
        return HDF_FAILURE;
    }

    struct AudioEvent loadMsg = {
        .eventType = HDF_AUDIO_EVENT_UNKOWN,
        .deviceType = HDF_AUDIO_DEVICE_UNKOWN,
    };
    char strTemp[AUDIO_PNP_MSG_LEN_MAX] = {0};
    if (memcpy_s(strTemp, AUDIO_PNP_MSG_LEN_MAX, (char *)svcStatus->info, strlen((char *)svcStatus->info))) {
        return HDF_FAILURE;
    }
    if ((AudioPnpMsgReadValue(strTemp, "EVENT_LOAD_TYPE", &(loadMsg.eventType)) != HDF_SUCCESS) ||
        (AudioPnpMsgReadValue(strTemp, "DEVICE_TYPE", &(loadMsg.deviceType)) != HDF_SUCCESS)) {
        return HDF_FAILURE;
    }
    if (AudioLoadMsgParse(&loadMsg) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t AudioPnpDeviceAdd(enum AudioDeviceType deviceType)
{
    switch (deviceType) {
        case HDF_AUDIO_USB_HEADPHONE: // USB Audio Add
        case HDF_AUDIO_USBA_HEADPHONE:
            printf("*****************: USB Audio earphone microphone add.\n");
            return HDF_SUCCESS;
        case HDF_AUDIO_USB_HEADSET:
        case HDF_AUDIO_USBA_HEADSET:
            printf("*****************: USB Audio earphone mic&speaker add.\n");
            return HDF_SUCCESS;
        case HDF_AUDIO_A2DP_DEVICE: // A2dp Add
            return HDF_ERR_NOT_SUPPORT;
        default:
            return HDF_FAILURE;
    }
}

static int32_t AudioPnpDeviceRemove(enum AudioDeviceType deviceType)
{
    switch (deviceType) {
        case HDF_AUDIO_USB_HEADPHONE: // USB Audio Remove
        case HDF_AUDIO_USBA_HEADPHONE:
            printf("*****************: USB Audio earphone microphone remove.\n");
            return HDF_SUCCESS;
        case HDF_AUDIO_USB_HEADSET:
        case HDF_AUDIO_USBA_HEADSET:
            printf("*****************: USB Audio earphone mic&speaker remove.\n");
            return HDF_SUCCESS;
        case HDF_AUDIO_A2DP_DEVICE: // A2dp Remove
            return HDF_ERR_NOT_SUPPORT;
        default:
            return HDF_FAILURE;
    }
}


static int32_t AudioPnpMsgParse(struct AudioEvent *pnpMsg)
{
    if (pnpMsg == NULL) {
        return HDF_FAILURE;
    }

    switch (pnpMsg->eventType) {
        case HDF_AUDIO_EVENT_UNKOWN:
            return HDF_FAILURE;
        case HDF_AUDIO_DEVICE_ADD:
            return AudioPnpDeviceAdd(pnpMsg->deviceType);
        case HDF_AUDIO_DEVICE_REMOVE:
            return AudioPnpDeviceRemove(pnpMsg->deviceType);
        default:
            return HDF_FAILURE;
    }
}

static int AudioGetUsbPnpStatus(struct ServiceStatus *svcStatus)
{
    if (svcStatus == NULL) {
        return HDF_FAILURE;
    }

    struct AudioEvent pnpMsg = {
        .eventType = HDF_AUDIO_EVENT_UNKOWN,
        .deviceType = HDF_AUDIO_DEVICE_UNKOWN,
    };
    char strTemp[AUDIO_PNP_MSG_LEN_MAX] = {0};
    if (memcpy_s(strTemp, AUDIO_PNP_MSG_LEN_MAX, (char *)svcStatus->info, strlen((char *)svcStatus->info))) {
        return HDF_FAILURE;
    }
    if ((AudioPnpMsgReadValue(strTemp, "EVENT_TYPE", &(pnpMsg.eventType)) != HDF_SUCCESS) ||
        (AudioPnpMsgReadValue(strTemp, "DEVICE_TYPE", &(pnpMsg.deviceType)) != HDF_SUCCESS)) {
        return HDF_FAILURE;
    }
    if (AudioPnpMsgParse(&pnpMsg) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static void AudioUsbPnpOnSvcStatusReceived(struct ServiceStatusListener *listener, struct ServiceStatus *svcStatus)
{
    if (listener == NULL || svcStatus == NULL) {
        AUDIO_FUNC_LOGE("listener or svcStatus is NULL!");
        return;
    }

    printf("\n===============================================================================\n"
           "@@@@@ serviceName: %s\n"
           "@@@@@ deviceClass: %d\n"
           "@@@@@ status     : %d\n"
           "@@@@@ info       : %s"
           "\n===============================================================================\n",
           svcStatus->serviceName, svcStatus->deviceClass, svcStatus->status, svcStatus->info);

    (void)AudioGetUsbPnpStatus(svcStatus);
    (void)AudioGetLoadStatus(svcStatus);
    (void)AudioGetServiceStatus(svcStatus);
}

static struct HDIServiceManager *g_servmgr = NULL;
static struct ServiceStatusListener *g_listener = NULL;
static bool g_listenerState = false;

static void StopListenerBySig(int32_t sig)
{
    printf("%s: Signal = %d\n", __func__, sig);
    if (g_servmgr == NULL || g_listener == NULL) {
        AUDIO_FUNC_LOGE("g_servmgr or g_listener is null!\n");
        return;
    }

    int32_t ret = g_servmgr->UnregisterServiceStatusListener(g_servmgr, g_listener);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("UnregisterServiceStatusListener fail! ret = %d.\n", ret);
        return;
    }
    HdiServiceStatusListenerFree(g_listener);
    HDIServiceManagerRelease(g_servmgr);
    g_listenerState = false;
    g_servmgr = NULL;
    return;
}

int main(void)
{
    printf("%s: system audio listener start \n", __func__);
    g_servmgr = HDIServiceManagerGet();
    if (g_servmgr == NULL) {
        AUDIO_FUNC_LOGE("HDIServiceManagerGet failed.\n");
        return HDF_FAILURE;
    }
    g_listener = HdiServiceStatusListenerNewInstance();
    if (g_listener == NULL) {
        AUDIO_FUNC_LOGE("HdiServiceStatusListenerNewInstance failed.\n");
        HDIServiceManagerRelease(g_servmgr);
        g_servmgr = NULL;
        return HDF_FAILURE;
    }
    g_listener->callback = AudioUsbPnpOnSvcStatusReceived;
    int32_t status = g_servmgr->RegisterServiceStatusListener(g_servmgr, g_listener, DEVICE_CLASS_AUDIO);
    if (status != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("RegisterServiceStatusListener fail! ret = %d.\n", status);
        HDIServiceManagerRelease(g_servmgr);
        g_servmgr = NULL;
        HdiServiceStatusListenerFree(g_listener);
        return HDF_FAILURE;
    }
    g_listenerState = true;
    (void)signal(SIGINT, StopListenerBySig);
    (void)signal(SIGTERM, StopListenerBySig);
    while (g_listenerState) {
        sleep(1); // Wait for 1 second
    }

    return HDF_SUCCESS;
}
