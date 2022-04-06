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

#include "hdf_device_desc.h"
#include "hdf_io_service_if.h"
#include "hdf_log.h"
#include "hdf_sbuf.h"
#include "hdf_service_status.h"
#include "servmgr_hdi.h"

#define HDF_LOG_TAG HDF_AUDIO_HAL_HOST

static struct HdfDeviceObject *g_audioPnpDevice = NULL;

static int32_t AudioPnpDataTransfer(const char *serverName, const int cmd,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int ret;

    if (serverName == NULL || data == NULL || reply == NULL) {
        HDF_LOGE("%{public}s: serverName || data || reply is null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct HDIServiceManager *servmgr = HDIServiceManagerGet();
    if (servmgr == NULL) {
        HDF_LOGE("%{public}s: get all service failed!", __func__);
        return HDF_FAILURE;
    }
    struct HdfRemoteService *hdiAudioService = servmgr->GetService(servmgr, serverName);
    HDIServiceManagerRelease(servmgr);
    if (hdiAudioService == NULL) {
        HDF_LOGE("%{public}s: get %{public}s failed!", __func__, serverName);
        return HDF_FAILURE;
    }
    if (hdiAudioService->dispatcher == NULL) {
        HDF_LOGE("%{public}s: get %{public}s dispatcher failed!", __func__, serverName);
        return HDF_FAILURE;
    }
    ret = hdiAudioService->dispatcher->Dispatch(hdiAudioService, cmd, data, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGD("%{public}s: %{public}s dispatch failed! ret = %{public}d", __func__, serverName, ret);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioPnpStatusSend(const char *serverName, const char *pnpInfo, const int cmd)
{
    if (serverName == NULL || pnpInfo == NULL) {
        HDF_LOGE("%{public}s: serverName is null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC); // user
    if (data == NULL) {
        HDF_LOGE("%{public}s: sbuf data malloc failed!", __func__);
        return HDF_FAILURE;
    }
    struct HdfSBuf *reply = HdfSbufTypedObtain(SBUF_IPC); // user
    if (reply == NULL) {
        HdfSbufRecycle(data);
        HDF_LOGE("%{public}s: sbuf reply malloc failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(data, pnpInfo)) {
        HdfSbufRecycle(data);
        HdfSbufRecycle(reply);
        HDF_LOGE("%{public}s: sbuf write failed!", __func__);
        return HDF_FAILURE;
    }
    if (AudioPnpDataTransfer(serverName, cmd, data, reply) != HDF_SUCCESS) {
        HdfSbufRecycle(data);
        HdfSbufRecycle(reply);
        return HDF_FAILURE;
    }
    HdfSbufRecycle(data);
    HdfSbufRecycle(reply);
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

static int32_t AudioPnpSvrDispatch(struct HdfDeviceIoClient *ioClient, int cmd,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (ioClient == NULL || data == NULL || reply == NULL) {
        HDF_LOGE("%{public}s: ioClient || data || reply is null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    const char *pnpInfo = HdfSbufReadString(data);
    switch (cmd) {
        case 0 : // send pnp status to audio system service
            if (AudioPnpUpdateInfo(pnpInfo) != HDF_SUCCESS) {
                return HDF_FAILURE;
            }
            break;
        case 1 : // send pnp status to usb service
            if (AudioPnpStatusSend("audio_hdi_usb_service", pnpInfo, 8) != HDF_SUCCESS) { // 8 is usb service cmd
                return HDF_FAILURE;
            }
            break;
        default :
            HDF_LOGD("%{public}s: default cmd = %{public}d", __func__, cmd);
            break;
    }

    return HDF_SUCCESS;
}

static int32_t HdfAudioPnpBind(struct HdfDeviceObject *device)
{
    HDF_LOGI("%{public}s: enter.", __func__);
    if (device == NULL) {
        HDF_LOGE("%{public}s: device is null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    static struct IDeviceIoService audioPnpService = {
        .Dispatch = AudioPnpSvrDispatch,
    };
    device->service = &audioPnpService;

    HDF_LOGI("%{public}s: end.", __func__);
    return HDF_SUCCESS;
}

static int32_t HdfAudioPnpInit(struct HdfDeviceObject *device)
{
    const char *pnpInfo = "1;2;2;3;255"; // audio pnp initial state

    HDF_LOGI("%{public}s: enter.", __func__);
    if (device == NULL) {
        HDF_LOGE("%{public}s: device is null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfDeviceSetClass(device, DEVICE_CLASS_AUDIO)) {
        HDF_LOGE("%{public}s: set audio class failed!", __func__);
        return HDF_FAILURE;
    }
    if (HdfDeviceObjectSetServInfo(device, pnpInfo) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: set audio initial status info failed!", __func__);
        return HDF_FAILURE;
    }
    g_audioPnpDevice = device;

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
    device->service = NULL;
    HDF_LOGI("%{public}s: end.", __func__);
    return;
}

struct HdfDriverEntry g_hdiAudioPnpEntry = {
    .moduleVersion = 1,
    .moduleName = "HDF_AUDIO_PNP",
    .Bind = HdfAudioPnpBind,
    .Init = HdfAudioPnpInit,
    .Release = HdfAudioPnpRelease,
};

HDF_INIT(g_hdiAudioPnpEntry);
