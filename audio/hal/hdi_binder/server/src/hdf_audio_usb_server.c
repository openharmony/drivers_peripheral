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
#include "audio_adapter_info_common.h"
#include "audio_hal_log.h"
#include "hdf_audio_server_common.h"
#include "pnp_message_report.h"

#define HDF_LOG_TAG HDF_AUDIO_HAL_HOST

void AudioHdiUsbServerRelease(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGD("%{public}s: enter!", __func__);
    LOG_FUN_INFO();
    /* g_renderAndCaptureManage release */
    AdaptersServerManageInfomationRecycle();
    ReleaseAudioManagerObjectComm(GetAudioManagerFuncs());

    if (deviceObject == NULL) {
        HDF_LOGE("%{public}s: deviceObject is null!", __func__);
        return;
    }
    deviceObject->service = NULL;
    HDF_LOGD("%{public}s: end!", __func__);
    return;
}

int AudioHdiUsbServerBind(struct HdfDeviceObject *deviceObject)
{
    LOG_FUN_INFO();
    HDF_LOGD("%{public}s: enter!", __func__);
    if (deviceObject == NULL) {
        HDF_LOGE("%{public}s: deviceObject is null!", __func__);
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    static struct IDeviceIoService hdiService = {
        .Dispatch = HdiServiceDispatch,
        .Open = NULL,
        .Release = NULL,
    };
    AudioHdiSetLoadServerFlag(AUDIO_SERVER_USB);
    int32_t ret = HdiServiceGetFuncs();
    if (ret != AUDIO_HAL_SUCCESS) {
        HDF_LOGE("HdiServiceGetFuncs fail");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = HdfDeviceObjectSetInterfaceDesc(deviceObject, "ohos.hdi.audio_service");
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("failed to set interface desc");
        return ret;
    }
    deviceObject->service = &hdiService;
    HDF_LOGD("%{public}s: end!", __func__);
    return AUDIO_HAL_SUCCESS;
}

int AudioHdiUsbServerInit(struct HdfDeviceObject *deviceObject)
{
    HDF_LOGD("%{public}s: enter!", __func__);
    LOG_FUN_INFO();
    if (deviceObject == NULL) {
        HDF_LOGE("%{public}s: deviceObject is null!", __func__);
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }

    char strTemp[PNP_REPORT_MSG_LEN_MAX] = {0}; // "1;2;2;1;255"
    (void)sprintf_s(strTemp, sizeof(strTemp), "%d;%d;%d;%d;%d",
        EVENT_REPORT, SERVICE_STATUS, SERVICE_INIT, AUDIO_SERVER_USB, PNP_REPORT_RESERVED);
    uint8_t* strMsgReport = (uint8_t*)strTemp;
    int32_t ret = HdiServiceDynamicInitSet(strMsgReport, deviceObject);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: HdiServiceDynamicInitSet is fail!", __func__);
    }
    HDF_LOGD("%{public}s: end!", __func__);
    return AUDIO_HAL_SUCCESS;
}

struct HdfDriverEntry g_hdiAudioUSBServerEntry = {
    .moduleVersion = 1,
    .moduleName = "hdi_audio_usb_server",
    .Bind = AudioHdiUsbServerBind,
    .Init = AudioHdiUsbServerInit,
    .Release = AudioHdiUsbServerRelease,
};

HDF_INIT(g_hdiAudioUSBServerEntry);
