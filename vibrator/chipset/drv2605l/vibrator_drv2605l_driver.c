/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#include "vibrator_drv2605l_driver.h"
#include <securec.h>
#include "device_resource_if.h"
#include "hdf_base.h"
#include "hdf_log.h"
#include "i2c_if.h"
#include "hdf_workqueue.h"
#include "osal_mutex.h"
#include "osal_mem.h"
#include "vibrator_driver.h"
#include "vibrator_parser.h"
#include "vibrator_driver_type.h"

#define HDF_LOG_TAG    hdf_drv2605l_driver

struct Drv2605lDriverData *g_drv2605lDrvData = NULL;

static struct Drv2605lDriverData *GetDrv2605lDrvData(void)
{
    return g_drv2605lDrvData;
}

static int32_t GetDrv2605lI2cHandle(struct VibratorI2cCfg *busCfg)
{
    CHECK_VIBRATOR_NULL_PTR_RETURN_VALUE(busCfg, HDF_ERR_INVALID_PARAM);

    busCfg->handle = I2cOpen(busCfg->busNum);
    if (busCfg->handle == NULL) {
        HDF_LOGE("%s: drv2605l i2c Handle invalid", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static void ReleaseDrv2605lBusHandle(struct VibratorI2cCfg *busCfg)
{
    if (busCfg == NULL) {
        HDF_LOGE("%s: drv2605l i2c config invalid", __func__);
        return;
    }

    if (busCfg->handle != NULL) {
        I2cClose(busCfg->handle);
        busCfg->handle = NULL;
    }
}

int32_t ReadDrv2605l(struct VibratorI2cCfg *busCfg, uint16_t regAddr, uint8_t *data, uint16_t dataLen)
{
    int32_t index = 0;
    unsigned char regBuf[I2C_REG_BUF_LEN] = {0};
    struct I2cMsg msg[I2C_READ_MSG_NUM];

    CHECK_VIBRATOR_NULL_PTR_RETURN_VALUE(busCfg, HDF_FAILURE);
    CHECK_VIBRATOR_NULL_PTR_RETURN_VALUE(data, HDF_FAILURE);
    CHECK_VIBRATOR_NULL_PTR_RETURN_VALUE(busCfg->handle, HDF_FAILURE);

    msg[I2C_READ_MSG_ADDR_IDX].addr = busCfg->devAddr;
    msg[I2C_READ_MSG_ADDR_IDX].flags = 0;
    msg[I2C_READ_MSG_ADDR_IDX].len = busCfg->regWidth;
    msg[I2C_READ_MSG_ADDR_IDX].buf = regBuf;

    if (busCfg->regWidth == DRV2605L_ADDR_WIDTH_1_BYTE) {
        regBuf[index++] = regAddr & I2C_BYTE_MASK;
    } else if (busCfg->regWidth == DRV2605L_ADDR_WIDTH_2_BYTE) {
        regBuf[index++] = (regAddr >> I2C_BYTE_OFFSET) & I2C_BYTE_MASK;
        regBuf[index++] = regAddr & I2C_BYTE_MASK;
    } else {
        HDF_LOGE("%s: i2c regWidth[%u] failed", __func__, busCfg->regWidth);
        return HDF_FAILURE;
    }

    msg[I2C_READ_MSG_VALUE_IDX].addr = busCfg->devAddr;
    msg[I2C_READ_MSG_VALUE_IDX].flags = I2C_FLAG_READ;
    msg[I2C_READ_MSG_VALUE_IDX].len = dataLen;
    msg[I2C_READ_MSG_VALUE_IDX].buf = data;

    if (I2cTransfer(busCfg->handle, msg, I2C_READ_MSG_NUM) != I2C_READ_MSG_NUM) {
        HDF_LOGE("%s: i2c[%u] read failed", __func__, busCfg->busNum);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t WriteDrv2605l(struct VibratorI2cCfg *busCfg, uint8_t *writeData, uint16_t dataLen)
{
    struct I2cMsg msg[I2C_WRITE_MSG_NUM];
    CHECK_VIBRATOR_NULL_PTR_RETURN_VALUE(busCfg, HDF_FAILURE);
    CHECK_VIBRATOR_NULL_PTR_RETURN_VALUE(writeData, HDF_FAILURE);
    CHECK_VIBRATOR_NULL_PTR_RETURN_VALUE(busCfg->handle, HDF_FAILURE);

    msg[0].addr = busCfg->devAddr;
    msg[0].flags = 0;
    msg[0].len = dataLen;
    msg[0].buf = writeData;

    if (I2cTransfer(busCfg->handle, msg, I2C_WRITE_MSG_NUM) != I2C_WRITE_MSG_NUM) {
        HDF_LOGE("%s: i2c[%u] write failed", __func__, busCfg->busNum);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t DetectDrv2605lDevice(struct Drv2605lDriverData *drvData)
{
    uint8_t value;
    uint16_t chipIdReg;
    uint16_t chipIdValue;
    int32_t ret;

    chipIdReg = drvData->drv2605lCfgData->vibratorAttr.chipIdReg;
    chipIdValue = drvData->drv2605lCfgData->vibratorAttr.chipIdValue;

    ret = GetDrv2605lI2cHandle(&drvData->drv2605lCfgData->vibratorBus.i2cCfg);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: get drv2605l bus handle failed", __func__);
        ReleaseDrv2605lBusHandle(&drvData->drv2605lCfgData->vibratorBus.i2cCfg);
        return HDF_FAILURE;
    }

    ret = ReadDrv2605l(&drvData->drv2605lCfgData->vibratorBus.i2cCfg, chipIdReg, &value, sizeof(value));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: i2c read chip id failed", __func__);
        ReleaseDrv2605lBusHandle(&drvData->drv2605lCfgData->vibratorBus.i2cCfg);
        return HDF_FAILURE;
    }

    if (value != chipIdValue) {
        HDF_LOGE("%s: drv2605l chip detect failed", __func__);
        ReleaseDrv2605lBusHandle(&drvData->drv2605lCfgData->vibratorBus.i2cCfg);
        return HDF_FAILURE;
    }

    HDF_LOGD("%s: drv2605l detect chip success", __func__);
    return HDF_SUCCESS;
}

static int32_t InitDrv2605lChip(struct VibratorCfgData *drv2605lCfgData)
{
    uint8_t value[DRV2605L_VALUE_BUTT];

    value[DRV2605L_ADDR_INDEX] = (uint8_t)DRV2605_REG_CONTROL3;
    value[DRV2605L_VALUE_INDEX] = (uint8_t)DRV2605_MODE_OPEN_LOOP;
    if (WriteDrv2605l(&drv2605lCfgData->vibratorBus.i2cCfg, value, sizeof(value)) != HDF_SUCCESS) {
        HDF_LOGE("%s: i2c addr [%0X] write failed", __func__, value[DRV2605L_ADDR_INDEX]);
        return HDF_FAILURE;
    }

    value[DRV2605L_ADDR_INDEX] = (uint8_t)DRV2605_REG_FEEDBACK;
    value[DRV2605L_VALUE_INDEX] = (uint8_t)DRV2605_MODE_LRA;
    if (WriteDrv2605l(&drv2605lCfgData->vibratorBus.i2cCfg, value, sizeof(value)) != HDF_SUCCESS) {
        HDF_LOGE("%s: i2c addr [%0X] write failed", __func__, value[DRV2605L_ADDR_INDEX]);
        return HDF_FAILURE;
    }

    value[DRV2605L_ADDR_INDEX] = (uint8_t)DRV2605_REG_RTPIN;
    value[DRV2605L_VALUE_INDEX] = (uint8_t)&drv2605lCfgData->vibratorAttr.defaultIntensity;
    if (WriteDrv2605l(&drv2605lCfgData->vibratorBus.i2cCfg, value, sizeof(value)) != HDF_SUCCESS) {
        HDF_LOGE("%s: i2c addr [%0X] write failed", __func__, value[DRV2605L_ADDR_INDEX]);
        return HDF_FAILURE;
    }

    value[DRV2605L_ADDR_INDEX] = (uint8_t)DRV2605_REG_LRARESON;
    value[DRV2605L_VALUE_INDEX] = (uint8_t)&drv2605lCfgData->vibratorAttr.defaultFrequency;
    if (WriteDrv2605l(&drv2605lCfgData->vibratorBus.i2cCfg, value, sizeof(value)) != HDF_SUCCESS) {
        HDF_LOGE("%s: i2c addr [%0X] write failed", __func__, value[DRV2605L_ADDR_INDEX]);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t SetModulationParameter(uint16_t intensity, int16_t frequency)
{
    uint8_t value[DRV2605L_VALUE_BUTT];
    struct Drv2605lDriverData *drvData = NULL;
    drvData = GetDrv2605lDrvData();

    CHECK_VIBRATOR_NULL_PTR_RETURN_VALUE(drvData, HDF_FAILURE);

    if (intensity != 0) {
        value[DRV2605L_ADDR_INDEX] = (uint8_t)DRV2605_REG_RTPIN;
        value[DRV2605L_VALUE_INDEX] = (uint8_t)INTENSITY_MAPPING_VALUE(intensity);
        if (WriteDrv2605l(&drvData->drv2605lCfgData->vibratorBus.i2cCfg, value, sizeof(value)) != HDF_SUCCESS) {
            HDF_LOGE("%s: i2c addr [%0X] write failed", __func__, value[DRV2605L_ADDR_INDEX]);
            return HDF_FAILURE;
        }
    } else {
        HDF_LOGD("%s: the setting of intensity 0 is not supported and \
            will be set as the system default intensity", __func__);
    }

    if (frequency != 0) {
        value[DRV2605L_ADDR_INDEX] = (uint8_t)DRV2605_REG_LRARESON;
        value[DRV2605L_VALUE_INDEX] = (uint8_t)FREQUENCY_MAPPING_VALUE(frequency);
        if (WriteDrv2605l(&drvData->drv2605lCfgData->vibratorBus.i2cCfg, value, sizeof(value)) != HDF_SUCCESS) {
            HDF_LOGE("%s: i2c addr [%0X] write failed", __func__, value[DRV2605L_ADDR_INDEX]);
            return HDF_FAILURE;
        }
    } else {
        HDF_LOGD("%s: the setting of frequency 0 is not supported and \
            will be set as the system default frequency", __func__);
    }

    return HDF_SUCCESS;
}

static int32_t StartModulationParameter()
{
    uint8_t value[DRV2605L_VALUE_BUTT];
    struct Drv2605lDriverData *drvData = NULL;
    drvData = GetDrv2605lDrvData();

    CHECK_VIBRATOR_NULL_PTR_RETURN_VALUE(drvData, HDF_FAILURE);

    value[DRV2605L_ADDR_INDEX] = (uint8_t)DRV2605_REG_MODE;
    value[DRV2605L_VALUE_INDEX] = (uint8_t)DRV2605_MODE_REALTIME;
    if (WriteDrv2605l(&drvData->drv2605lCfgData->vibratorBus.i2cCfg, value, sizeof(value)) != HDF_SUCCESS) {
        HDF_LOGE("%s: i2c addr [%0X] write failed", __func__, value[DRV2605L_ADDR_INDEX]);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t StopModulationParameter()
{
    uint8_t value[DRV2605L_VALUE_BUTT];
    struct Drv2605lDriverData *drvData = NULL;
    drvData = GetDrv2605lDrvData();

    CHECK_VIBRATOR_NULL_PTR_RETURN_VALUE(drvData, HDF_FAILURE);
    CHECK_VIBRATOR_NULL_PTR_RETURN_VALUE(drvData->drv2605lCfgData, HDF_FAILURE);

    value[DRV2605L_ADDR_INDEX] = (uint8_t)DRV2605_REG_MODE;
    value[DRV2605L_VALUE_INDEX] = (uint8_t)DRV2605_MODE_STANDBY;
    if (WriteDrv2605l(&drvData->drv2605lCfgData->vibratorBus.i2cCfg, value, sizeof(value)) != HDF_SUCCESS) {
        HDF_LOGE("%s: i2c addr [%0X] write failed", __func__, value[DRV2605L_ADDR_INDEX]);
        return HDF_FAILURE;
    }

    value[DRV2605L_ADDR_INDEX] = (uint8_t)DRV2605_REG_RTPIN;
    value[DRV2605L_VALUE_INDEX] = (uint8_t)&drvData->drv2605lCfgData->vibratorAttr.defaultIntensity;
    if (WriteDrv2605l(&drvData->drv2605lCfgData->vibratorBus.i2cCfg, value, sizeof(value)) != HDF_SUCCESS) {
        HDF_LOGE("%s: i2c addr [%0X] write failed", __func__, value[DRV2605L_ADDR_INDEX]);
        return HDF_FAILURE;
    }

    value[DRV2605L_ADDR_INDEX] = (uint8_t)DRV2605_REG_LRARESON;
    value[DRV2605L_VALUE_INDEX] = (uint8_t)&drvData->drv2605lCfgData->vibratorAttr.defaultFrequency;
    if (WriteDrv2605l(&drvData->drv2605lCfgData->vibratorBus.i2cCfg, value, sizeof(value)) != HDF_SUCCESS) {
        HDF_LOGE("%s: i2c addr [%0X] write failed", __func__, value[DRV2605L_ADDR_INDEX]);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t DispatchDrv2605l(struct HdfDeviceIoClient *client,
    int32_t cmd, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    (void)client;
    (void)cmd;
    (void)data;
    (void)reply;
    return HDF_SUCCESS;
}

int32_t BindDrv2605lDriver(struct HdfDeviceObject *device)
{
    struct Drv2605lDriverData *drvData = NULL;

    CHECK_VIBRATOR_NULL_PTR_RETURN_VALUE(device, HDF_FAILURE);

    drvData = (struct Drv2605lDriverData *)OsalMemCalloc(sizeof(*drvData));
    CHECK_VIBRATOR_NULL_PTR_RETURN_VALUE(drvData, HDF_ERR_MALLOC_FAIL);

    drvData->ioService.Dispatch = DispatchDrv2605l;
    drvData->device = device;
    device->service = &drvData->ioService;
    g_drv2605lDrvData = drvData;
    return HDF_SUCCESS;
}

int32_t InitDrv2605lDriver(struct HdfDeviceObject *device)
{
    static struct VibratorOps ops;
    struct Drv2605lDriverData *drvData = NULL;

    CHECK_VIBRATOR_NULL_PTR_RETURN_VALUE(device, HDF_FAILURE);
    drvData = (struct Drv2605lDriverData *)device->service;
    CHECK_VIBRATOR_NULL_PTR_RETURN_VALUE(drvData, HDF_FAILURE);

    ops.SetParameter = SetModulationParameter;
    ops.Start = StartModulationParameter;
    ops.Stop = StopModulationParameter;
    ops.StartEffect = NULL;

    drvData->drv2605lCfgData = (struct VibratorCfgData *)OsalMemCalloc(sizeof(*drvData->drv2605lCfgData));
    CHECK_VIBRATOR_NULL_PTR_RETURN_VALUE(drvData->drv2605lCfgData, HDF_ERR_MALLOC_FAIL);

    if (GetVibratorBaseConfigData(device->property, drvData->drv2605lCfgData) != HDF_SUCCESS) {
        HDF_LOGE("%s: get vibrator base config fail", __func__);
        return HDF_FAILURE;
    }

    if (DetectDrv2605lDevice(drvData) != HDF_SUCCESS) {
        HDF_LOGE("%s: drv2605l detect chip fail", __func__);
        return HDF_FAILURE;
    }

    if (InitDrv2605lChip(drvData->drv2605lCfgData) != HDF_SUCCESS) {
        HDF_LOGE("%s: init 2605l chip fail", __func__);
        return HDF_FAILURE;
    }

    if (RegisterVibratorInfo(&drvData->drv2605lCfgData->vibratorInfo) != HDF_SUCCESS) {
        HDF_LOGE("%s: register vibrator info fail", __func__);
        return HDF_FAILURE;
    }

    if (RegisterVibratorOps(&ops) != HDF_SUCCESS) {
        HDF_LOGE("%s: register vibrator ops fail", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

void ReleaseDrv2605lDriver(struct HdfDeviceObject *device)
{
    struct Drv2605lDriverData *drvData = NULL;

    if (device == NULL) {
        HDF_LOGE("%s: device is null", __func__);
        return;
    }

    drvData = (struct Drv2605lDriverData *)device->service;
    if (drvData == NULL) {
        HDF_LOGE("%s: drvData is null", __func__);
        return;
    }
    ReleaseDrv2605lBusHandle(&drvData->drv2605lCfgData->vibratorBus.i2cCfg);
    OsalMemFree(drvData->drv2605lCfgData);
    OsalMemFree(drvData);
    g_drv2605lDrvData = NULL;
}

struct HdfDriverEntry g_drv2605lDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "HDF_DRV2605L_VIBRATOR",
    .Bind = BindDrv2605lDriver,
    .Init = InitDrv2605lDriver,
    .Release = ReleaseDrv2605lDriver,
};

HDF_INIT(g_drv2605lDriverEntry);