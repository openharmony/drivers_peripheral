/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#include "vibrator_linear_driver.h"
#include <securec.h>
#include "device_resource_if.h"
#include "gpio_if.h"
#include "hdf_base.h"
#include "hdf_device_desc.h"
#include "osal_mem.h"
#include "vibrator_driver.h"
#include "vibrator_parser.h"
#include "vibrator_driver_type.h"

#define HDF_LOG_TAG    khdf_vibrator_driver

struct VibratorLinearDriverData *g_linearVibratorData = NULL;
static struct VibratorLinearDriverData *GetLinearVibratorData(void)
{
    return g_linearVibratorData;
}

static int32_t StartLinearVibrator(void)
{
    int32_t ret;
    struct VibratorLinearDriverData *drvData = GetLinearVibratorData();
    CHECK_VIBRATOR_NULL_PTR_RETURN_VALUE(drvData, HDF_FAILURE);

    if (drvData->linearCfgData->vibratorBus.busType != VIBRATOR_BUS_GPIO) {
        HDF_LOGE("%s: vibrator bus type not gpio", __func__);
        return HDF_FAILURE;
    }

    ret = GpioWrite(drvData->linearCfgData->vibratorBus.GpioNum, GPIO_VAL_HIGH);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: pull gpio%d to %d level failed", __func__,
            drvData->linearCfgData->vibratorBus.GpioNum, GPIO_VAL_HIGH);
        return ret;
    }
    return HDF_SUCCESS;
}

static int32_t StartEffectLinearVibrator(uint32_t effectType)
{
    (void)effectType;
    HDF_LOGE("%s: vibrator set built-in effect no support!", __func__);
    return HDF_SUCCESS;
}

static int32_t StopLinearVibrator(void)
{
    int32_t ret;
    struct VibratorLinearDriverData *drvData = GetLinearVibratorData();
    CHECK_VIBRATOR_NULL_PTR_RETURN_VALUE(drvData, HDF_FAILURE);

    if (drvData->linearCfgData->vibratorBus.busType != VIBRATOR_BUS_GPIO) {
        HDF_LOGE("%s: vibrator bus type not gpio", __func__);
        return HDF_FAILURE;
    }

    ret = GpioWrite(drvData->linearCfgData->vibratorBus.GpioNum, GPIO_VAL_LOW);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: pull gpio%d to %d level failed", __func__,
            drvData->linearCfgData->vibratorBus.GpioNum, GPIO_VAL_LOW);
        return ret;
    }
    return HDF_SUCCESS;
}

static int32_t DispatchLinearVibrator(struct HdfDeviceIoClient *client,
    int32_t cmd, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    (void)client;
    (void)cmd;
    (void)data;
    (void)reply;

    return HDF_SUCCESS;
}

static int32_t BindLinearVibratorDriver(struct HdfDeviceObject *device)
{
    struct VibratorLinearDriverData *drvData = NULL;

    CHECK_VIBRATOR_NULL_PTR_RETURN_VALUE(device, HDF_FAILURE);

    drvData = (struct VibratorLinearDriverData *)OsalMemCalloc(sizeof(*drvData));
    CHECK_VIBRATOR_NULL_PTR_RETURN_VALUE(drvData, HDF_ERR_MALLOC_FAIL);

    drvData->ioService.Dispatch = DispatchLinearVibrator;
    drvData->device = device;
    device->service = &drvData->ioService;
    g_linearVibratorData = drvData;

    return HDF_SUCCESS;
}

static int32_t InitLinearVibratorDriver(struct HdfDeviceObject *device)
{
    static struct VibratorOps ops;
    struct VibratorLinearDriverData *drvData = NULL;

    CHECK_VIBRATOR_NULL_PTR_RETURN_VALUE(device, HDF_FAILURE);

    drvData = (struct VibratorLinearDriverData *)device->service;
    CHECK_VIBRATOR_NULL_PTR_RETURN_VALUE(drvData, HDF_FAILURE);

    ops.Start = StartLinearVibrator;
    ops.StartEffect = StartEffectLinearVibrator;
    ops.Stop = StopLinearVibrator;
    ops.SetParameter = NULL;

    if (RegisterVibratorOps(&ops) != HDF_SUCCESS) {
        HDF_LOGE("%s: register vibrator ops fail", __func__);
        return HDF_FAILURE;
    }

    drvData->linearCfgData = (struct VibratorCfgData *)OsalMemCalloc(sizeof(*drvData->linearCfgData));
    CHECK_VIBRATOR_NULL_PTR_RETURN_VALUE(drvData->linearCfgData, HDF_ERR_MALLOC_FAIL);

    if (GetVibratorBaseConfigData(device->property, drvData->linearCfgData) != HDF_SUCCESS) {
        HDF_LOGE("%s: parser vibrator cfg fail", __func__);
        return HDF_FAILURE;
    }

    if (RegisterVibratorInfo(&drvData->linearCfgData->vibratorInfo) != HDF_SUCCESS) {
        HDF_LOGE("%s: register vibrator info fail", __func__);
        return HDF_FAILURE;
    }

    if (GpioSetDir(drvData->linearCfgData->vibratorBus.GpioNum, GPIO_DIR_OUT) != HDF_SUCCESS) {
        HDF_LOGE("%s: set vibrator gpio fail", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static void ReleaseLinearVibratorDriver(struct HdfDeviceObject *device)
{
    struct VibratorLinearDriverData *drvData = NULL;

    if (device == NULL) {
        HDF_LOGE("%s: Device is null", __func__);
        return;
    }
    drvData = (struct VibratorLinearDriverData *)device->service;
    if (drvData == NULL) {
        HDF_LOGE("%s: DrvData pointer is null", __func__);
        return;
    }

    OsalMemFree(drvData->linearCfgData);
    OsalMemFree(drvData);
    g_linearVibratorData = NULL;
}

struct HdfDriverEntry g_linearVibratorDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "HDF_LINEAR_VIBRATOR",
    .Bind = BindLinearVibratorDriver,
    .Init = InitLinearVibratorDriver,
    .Release = ReleaseLinearVibratorDriver,
};

HDF_INIT(g_linearVibratorDriverEntry);
