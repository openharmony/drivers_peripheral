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

#include "hdf_audio_pnp_server.h"
#include "audio_uhdf_log.h"
#include "hdf_audio_input_event.h"
#include "hdf_audio_pnp_uevent.h"
#include "hdf_audio_pnp_uevent_hdmi.h"
#include "hdf_audio_server.h"
#include "hdf_device_desc.h"
#include "hdf_device_object.h"
#include "hdf_io_service_if.h"
#include "hdf_sbuf.h"
#include "hdf_service_status.h"
#include "securec.h"
#include "servmgr_hdi.h"

#define HDF_LOG_TAG             HDF_AUDIO_HOST
#define AUDIO_HDI_SERVICE_NAME  "audio_hdi_usb_service"
#define AUDIO_TOKEN_SERVER_NAME "ohos.hdi.audio_service"
#define AUDIO_PNP_INFO_LEN_MAX  256
#define AUDIO_CONTROL           "hdf_audio_control"
#define AUDIO_UNLOAD_DRIVER_ID  4

static struct HdfDeviceObject *g_audioPnpDevice = NULL;

int32_t AudioPnpStatusSend(const char *serverName, const char *tokenServerName, const char *pnpInfo, const int cmd)
{
    if (serverName == NULL || tokenServerName == NULL || pnpInfo == NULL) {
        AUDIO_FUNC_LOGE("serverName is null!");
        return HDF_ERR_INVALID_PARAM;
    }

    struct HDIServiceManager *servmgr = HDIServiceManagerGet();
    if (servmgr == NULL) {
        AUDIO_FUNC_LOGE("get all service failed!");
        return HDF_FAILURE;
    }

    struct HdfRemoteService *hdiAudioService = servmgr->GetService(servmgr, serverName);
    HDIServiceManagerRelease(servmgr);
    if (hdiAudioService == NULL || hdiAudioService->dispatcher == NULL) {
        AUDIO_FUNC_LOGE("get %{public}s not exist!", serverName);
        return HDF_FAILURE;
    }

    if (!HdfRemoteServiceSetInterfaceDesc(hdiAudioService, tokenServerName)) {
        AUDIO_FUNC_LOGE("SetInterfaceDesc %{public}s failed! ", tokenServerName);
        HdfRemoteServiceRecycle(hdiAudioService);
        return HDF_FAILURE;
    }

    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC);
    if (data == NULL) {
        AUDIO_FUNC_LOGE("sbuf data malloc failed!");
        return HDF_FAILURE;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(hdiAudioService, data)) {
        AUDIO_FUNC_LOGE("write token failed!");
        HdfSbufRecycle(data);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteString(data, pnpInfo)) {
        HdfSbufRecycle(data);
        AUDIO_FUNC_LOGE("sbuf write failed!");
        return HDF_FAILURE;
    }

    int ret = hdiAudioService->dispatcher->Dispatch(hdiAudioService, cmd, data, NULL);
    HdfSbufRecycle(data);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("%{public}s cmd(%{public}d) dispatch failed! ret = %{public}d", serverName, cmd, ret);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioPnpUpdateInfo(const char *statusInfo)
{
    if (g_audioPnpDevice == NULL) {
        AUDIO_FUNC_LOGE("g_audioPnpDevice is null!");
        return HDF_ERR_INVALID_PARAM;
    }
    if (statusInfo == NULL) {
        AUDIO_FUNC_LOGE("statusInfo is null!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (HdfDeviceObjectSetServInfo(g_audioPnpDevice, statusInfo) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("set audio new status info failed!");
        return HDF_FAILURE;
    }
    if (HdfDeviceObjectUpdate(g_audioPnpDevice) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("update audio status info failed!");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioPnpUpdateInfoOnly(struct AudioEvent audioEvent)
{
    int32_t ret;
    char pnpInfo[AUDIO_PNP_INFO_LEN_MAX] = {0};

    ret = snprintf_s(pnpInfo, AUDIO_PNP_INFO_LEN_MAX, AUDIO_PNP_INFO_LEN_MAX - 1, "EVENT_TYPE=%u;DEVICE_TYPE=%u",
        audioEvent.eventType, audioEvent.deviceType);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("snprintf_s failed!");
        return HDF_FAILURE;
    }

    ret = AudioPnpUpdateInfo(pnpInfo);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Update info failed: ret = %{public}d", ret);
        return HDF_FAILURE;
    }
    AUDIO_FUNC_LOGD("Audio uevent:%{public}s", pnpInfo);

    return HDF_SUCCESS;
}

int32_t AudioPnpUpdateAndSend(struct AudioEvent audioEvent)
{
    int32_t ret;
    char pnpInfo[AUDIO_PNP_INFO_LEN_MAX] = {0};

    ret = snprintf_s(pnpInfo, AUDIO_PNP_INFO_LEN_MAX, AUDIO_PNP_INFO_LEN_MAX - 1, "EVENT_TYPE=%u;DEVICE_TYPE=%u",
        audioEvent.eventType, audioEvent.deviceType);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("snprintf_s fail!");
        return HDF_FAILURE;
    }

    ret = AudioPnpUpdateInfo(pnpInfo);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("update info fail! ret = %{public}d", ret);
        return HDF_FAILURE;
    }

    ret = AudioPnpStatusSend(AUDIO_HDI_SERVICE_NAME, AUDIO_TOKEN_SERVER_NAME, pnpInfo, AUDIO_HDI_PNP_DEV_STATUS);
    if (ret != HDF_SUCCESS) {
        return HDF_FAILURE;
    }
    AUDIO_FUNC_LOGD("Audio uevent:%{public}s", pnpInfo);

    return HDF_SUCCESS;
}

static int32_t HdfAudioPnpBind(struct HdfDeviceObject *device)
{
    AUDIO_FUNC_LOGI("enter.");
    if (device == NULL) {
        AUDIO_FUNC_LOGE("device is null!");
        return HDF_ERR_INVALID_PARAM;
    }
    AUDIO_FUNC_LOGI("end.");

    return HDF_SUCCESS;
}

static int32_t HdfAudioPnpInit(struct HdfDeviceObject *device)
{
    AUDIO_FUNC_LOGI("enter.");
    if (device == NULL) {
        AUDIO_FUNC_LOGE("device is null!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfDeviceSetClass(device, DEVICE_CLASS_AUDIO)) {
        AUDIO_FUNC_LOGE("set audio class failed!");
        return HDF_FAILURE;
    }
    g_audioPnpDevice = device;
    AudioUsbPnpUeventStartThread();
    AudioHeadsetPnpInputStartThread();
    AudioHdmiPnpUeventStartThread();

    AUDIO_FUNC_LOGI("end.");
    return HDF_SUCCESS;
}

static void HdfAudioPnpRelease(struct HdfDeviceObject *device)
{
    AUDIO_FUNC_LOGI("enter.");
    if (device == NULL) {
        AUDIO_FUNC_LOGE("device is null!");
        return;
    }

    AudioUsbPnpUeventStopThread();
    AudioHeadsetPnpInputEndThread();
    AudioHdmiPnpUeventStopThread();
    device->service = NULL;

    AUDIO_FUNC_LOGI("end.");
    return;
}

int32_t AudioUhdfUnloadDriver(const char *driverName)
{
    struct HdfSBuf *sBuf = NULL;
    struct HdfIoService *service = NULL;

    if (driverName == NULL) {
        AUDIO_FUNC_LOGE("param is NULL!");
        return HDF_ERR_INVALID_PARAM;
    }

    service = HdfIoServiceBind(AUDIO_CONTROL);
    if (service == NULL || service->dispatcher == NULL || service->dispatcher->Dispatch == NULL) {
        AUDIO_FUNC_LOGE("Bind service failed!");
        return HDF_FAILURE;
    }

    sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == NULL) {
        HdfIoServiceRecycle(service);
        AUDIO_FUNC_LOGE("sbuf data malloc failed!");
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteString(sBuf, driverName)) {
        HdfSbufRecycle(sBuf);
        HdfIoServiceRecycle(service);
        AUDIO_FUNC_LOGE("driverName Write Fail!");
        return HDF_FAILURE;
    }

    int32_t ret = service->dispatcher->Dispatch(&service->object, AUDIO_UNLOAD_DRIVER_ID, sBuf, NULL);
    if (ret != HDF_SUCCESS) {
        HdfSbufRecycle(sBuf);
        HdfIoServiceRecycle(service);
        AUDIO_FUNC_LOGE("Unload HDMI Driver dispatch error");
        return HDF_FAILURE;
    }

    HdfSbufRecycle(sBuf);
    HdfIoServiceRecycle(service);
    return HDF_SUCCESS;
}

int32_t AudioUhdfLoadDriver(const char *driverName)
{
    struct HdfIoService *serv = NULL;

    if (driverName == NULL) {
        AUDIO_FUNC_LOGE("param is NULL!");
        return HDF_ERR_INVALID_PARAM;
    }

    serv = HdfIoServiceBind(driverName);
    if (serv == NULL) {
        AUDIO_FUNC_LOGE("error HdfIoServiceBind %{public}s", driverName);
        return HDF_FAILURE;
    }

    HdfIoServiceRecycle(serv);
    return HDF_SUCCESS;
}

struct HdfDriverEntry g_hdiAudioPnpEntry = {
    .moduleVersion = 1,
    .moduleName = "hdi_audio_pnp_server",
    .Bind = HdfAudioPnpBind,
    .Init = HdfAudioPnpInit,
    .Release = HdfAudioPnpRelease,
};

HDF_INIT(g_hdiAudioPnpEntry);
