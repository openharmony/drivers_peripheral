/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#include "audio_dsp_base.h"
#include "audio_core.h"
#include "audio_dsp_if.h"
#include "osal_io.h"
#include "audio_driver_log.h"

#define HDF_LOG_TAG dsp_adapter

struct DspData g_dspData = {
    .DspInit = DspDeviceInit,
    .Read = DspDeviceReadReg,
    .Write = DspDeviceWriteReg,
    .decode = DspDecodeAudioStream,
    .encode = DspEncodeAudioStream,
    .Equalizer = DspEqualizerActive,
};

struct AudioDaiOps g_dspLinkDeviceOps = {
    .Startup = DspLinkStartup,
    .HwParams = DspLinkHwParams,
};

struct DaiData g_dspDaiData = {
    .DaiInit = DspLinkDeviceInit,
    .ops = &g_dspLinkDeviceOps,
};

static int32_t DspDriverBind(struct HdfDeviceObject *device)
{
    if (device == NULL) {
        AUDIO_DRIVER_LOG_ERR("device is NULL.");
        return HDF_ERR_INVALID_OBJECT;
    }

    struct AudioHost *audioHost = AudioHostCreateAndBind(device);
    if (audioHost == NULL) {
        AUDIO_DRIVER_LOG_ERR("audioHost create failed!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t DspDriverInit(struct HdfDeviceObject *device)
{
    if (device == NULL) {
        AUDIO_DRIVER_LOG_ERR("device is NULL.");
        return HDF_ERR_INVALID_OBJECT;
    }

    int32_t ret = DspGetServiceName(device, &g_dspData.drvDspName);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    ret = DspGetDaiName(device, &g_dspDaiData.drvDaiName);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    ret = AudioRegisterDsp(device, &g_dspData, &g_dspDaiData);
    if (ret !=  HDF_SUCCESS) {
        return ret;
    }
    return HDF_SUCCESS;
}


static void DspDriverRelease(struct HdfDeviceObject *device)
{
    if (device == NULL) {
        AUDIO_DRIVER_LOG_ERR("device is NULL");
        return;
    }

    struct DspHost *dspHost = (struct DspHost *)device->service;
    if (dspHost == NULL) {
        AUDIO_DRIVER_LOG_ERR("DspHost is NULL");
        return;
    }

    OsalIoUnmap((void *)((uintptr_t)(void*)&dspHost->priv));
    OsalMemFree(dspHost);
}

/* HdfDriverEntry definitions */
struct HdfDriverEntry g_dspDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "DSP",
    .Bind = DspDriverBind,
    .Init = DspDriverInit,
    .Release = DspDriverRelease,
};
HDF_INIT(g_dspDriverEntry);
