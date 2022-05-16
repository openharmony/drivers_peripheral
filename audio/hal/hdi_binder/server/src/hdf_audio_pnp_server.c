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
#include "hdf_audio_input_event.h"
#include "hdf_audio_pnp_uevent.h"
#include "hdf_device_desc.h"
#include "hdf_io_service_if.h"
#include "hdf_log.h"
#include "hdf_sbuf.h"
#include "hdf_service_status.h"
#include "servmgr_hdi.h"

#define HDF_LOG_TAG             HDF_AUDIO_HAL_HOST
#define AUDIO_HDI_SERVICE_NAME  "audio_hdi_usb_service"
#define AUDIO_TOKEN_SERVER_NAME "ohos.hdi.audio_service"
#define AUDIO_PNP_SEND_USB_CMD  8
#define AUDIO_PNP_INFO_LEN_MAX  256

static struct HdfDeviceObject *g_audioPnpDevice = NULL;

int32_t AudioPnpStatusSend(const char *serverName,
    const char *tokenServerName, const char *pnpInfo, const int cmd)
{
    if (serverName == NULL || tokenServerName == NULL || pnpInfo == NULL) {
        HDF_LOGE("%{public}s: serverName is null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct HDIServiceManager *servmgr = HDIServiceManagerGet();
    if (servmgr == NULL) {
        HDF_LOGE("%{public}s: get all service failed!", __func__);
        return HDF_FAILURE;
    }
    struct HdfRemoteService *hdiAudioService = servmgr->GetService(servmgr, serverName);
    HDIServiceManagerRelease(servmgr);
    if (hdiAudioService == NULL || hdiAudioService->dispatcher == NULL) {
        HDF_LOGE("%{public}s: get %{public}s failed!", __func__, serverName);
        return HDF_FAILURE;
    }
    if (!HdfRemoteServiceSetInterfaceDesc(hdiAudioService, tokenServerName)) {
        HDF_LOGE("%{public}s: SetInterfaceDesc %{public}s failed! ", __func__, tokenServerName);
        HdfRemoteServiceRecycle(hdiAudioService);
        return HDF_FAILURE;
    }
    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC);
    if (data == NULL) {
        HDF_LOGE("%{public}s: sbuf data malloc failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(hdiAudioService, data)) {
        HDF_LOGE("%{public}s: write token failed!", __func__);
        HdfSbufRecycle(data);
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(data, pnpInfo)) {
        HdfSbufRecycle(data);
        HDF_LOGE("%{public}s: sbuf write failed!", __func__);
        return HDF_FAILURE;
    }
    int ret = hdiAudioService->dispatcher->Dispatch(hdiAudioService, cmd, data, NULL);
    HdfSbufRecycle(data);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: %{public}s cmd(%{public}d) dispatch failed! ret = %{public}d",
            __func__, serverName, cmd, ret);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioPnpUpdateInfo(const char *statusInfo)
{
    if (g_audioPnpDevice == NULL) {
        HDF_LOGE("%{public}s: g_audioPnpDevice is null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (statusInfo == NULL) {
        HDF_LOGE("%{public}s: statusInfo is null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (HdfDeviceObjectSetServInfo(g_audioPnpDevice, statusInfo) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: set audio new status info failed!", __func__);
        return HDF_FAILURE;
    }
    if (HdfDeviceObjectUpdate(g_audioPnpDevice) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: update audio status info failed!", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioPnpUpdateInfoOnly(struct AudioEvent audioEvent)
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
    HDF_LOGD("%{public}s: %{public}s", __func__, pnpInfo);

    return HDF_SUCCESS;
}

int32_t AudioPnpUpdateAndSend(struct AudioEvent audioEvent)
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
    HDF_LOGD("%{public}s: %{public}s", __func__, pnpInfo);

    return HDF_SUCCESS;
}

static int32_t HdfAudioPnpBind(struct HdfDeviceObject *device)
{
    HDF_LOGI("%{public}s: enter.", __func__);
    if (device == NULL) {
        HDF_LOGE("%{public}s: device is null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    HDF_LOGI("%{public}s: end.", __func__);

    return HDF_SUCCESS;
}

static int32_t HdfAudioPnpInit(struct HdfDeviceObject *device)
{
    HDF_LOGI("%{public}s: enter.", __func__);
    if (device == NULL) {
        HDF_LOGE("%{public}s: device is null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfDeviceSetClass(device, DEVICE_CLASS_AUDIO)) {
        HDF_LOGE("%{public}s: set audio class failed!", __func__);
        return HDF_FAILURE;
    }
    g_audioPnpDevice = device;
    AudioPnpUeventStartThread();
    AudioPnpInputStartThread();

    HDF_LOGI("%{public}s: end.", __func__);
    return HDF_SUCCESS;
}

static void HdfAudioPnpRelease(struct HdfDeviceObject *device)
{
    HDF_LOGI("%{public}s: enter.", __func__);
    if (device == NULL) {
        HDF_LOGE("%{public}s: device is null!", __func__);
        return;
    }
    AudioPnpInputEndThread();
    device->service = NULL;
    HDF_LOGI("%{public}s: end.", __func__);
    return;
}

struct HdfDriverEntry g_hdiAudioPnpEntry = {
    .moduleVersion = 1,
    .moduleName = "hdi_audio_pnp_server",
    .Bind = HdfAudioPnpBind,
    .Init = HdfAudioPnpInit,
    .Release = HdfAudioPnpRelease,
};

HDF_INIT(g_hdiAudioPnpEntry);
