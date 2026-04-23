/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#include "accel_sc7a20.h"
#include <securec.h>
#include "osal_mem.h"
#include "osal_time.h"
#include "sensor_accel_driver.h"
#include "sensor_config_controller.h"
#include "sensor_device_manager.h"

#define HDF_LOG_TAG    khdf_sensor_accel_driver
#define SC7A20_RANGE    (16384 * 2)
#define SC7A20_PRECISION    12
#define SC7A20_BOUNDARY    (0x1 << (SC7A20_PRECISION - 1))
#define SC7A20_GRAVITY_STEP    (SC7A20_RANGE / SC7A20_BOUNDARY)
#define SC7A20_MASK    0x7fff
#define SC7A20_ACCEL_OUTPUT_16BIT    16
#define SC7A20_ACCEL_OUTPUT_MSB      8

static struct Sc7a20DrvData *g_sc7a20DrvData = NULL;

static struct Sc7a20DrvData *Sc7a20GetDrvData(void)
{
    return g_sc7a20DrvData;
}

static int SensorConvertData(char highByte, char lowByte)
{
    int32_t result;

    result = ((uint32_t)highByte << (SC7A20_PRECISION - SC7A20_ACCEL_OUTPUT_MSB)) |
        ((uint32_t)lowByte >> (SC7A20_ACCEL_OUTPUT_16BIT - SC7A20_PRECISION));

    if (result < SC7A20_BOUNDARY) {
        result = result * SC7A20_GRAVITY_STEP;
    } else {
        result = ~(((~result & (SC7A20_MASK >> (SC7A20_ACCEL_OUTPUT_16BIT - SC7A20_PRECISION))) + 1) *
            SC7A20_GRAVITY_STEP) + 1;
    }

    return result;
}

static int32_t ReadSc7a20RawData(struct SensorCfgData *data, struct AccelData *rawData, uint64_t *timestamp)
{
    uint8_t status = 0;
    uint8_t reg[ACCEL_AXIS_BUTT];
    OsalTimespec time;
    int32_t x;
    int32_t y;
    int32_t z;

    (void)memset_s(&time, sizeof(time), 0, sizeof(time));
    (void)memset_s(reg, sizeof(reg), 0, sizeof(reg));

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);

    if (OsalGetTime(&time) != HDF_SUCCESS) {
        HDF_LOGE("%s: Get time failed", __func__);
        return HDF_FAILURE;
    }
    *timestamp = time.sec * SENSOR_SECOND_CONVERT_NANOSECOND + time.usec * SENSOR_CONVERT_UNIT; /* unit nanosecond */

    int32_t ret = ReadSensor(&data->busCfg, SC7A20_STATUS_ADDR, &status, sizeof(uint8_t));
    status &= 0x08;
    if (!status) {
        HDF_LOGE("%s: data status [%u] ret [%d]", __func__, status, ret);
        return HDF_FAILURE;
    }

    ret = ReadSensor(&data->busCfg, SC7A20_ACCEL_X_LSB_ADDR, &reg[ACCEL_X_AXIS_LSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    ret = ReadSensor(&data->busCfg, SC7A20_ACCEL_X_MSB_ADDR, &reg[ACCEL_X_AXIS_MSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    ret = ReadSensor(&data->busCfg, SC7A20_ACCEL_Y_LSB_ADDR, &reg[ACCEL_Y_AXIS_LSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    ret = ReadSensor(&data->busCfg, SC7A20_ACCEL_Y_MSB_ADDR, &reg[ACCEL_Y_AXIS_MSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    ret = ReadSensor(&data->busCfg, SC7A20_ACCEL_Z_LSB_ADDR, &reg[ACCEL_Z_AXIS_LSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    ret = ReadSensor(&data->busCfg, SC7A20_ACCEL_Z_MSB_ADDR, &reg[ACCEL_Z_AXIS_MSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    x = SensorConvertData(reg[ACCEL_X_AXIS_MSB], reg[ACCEL_X_AXIS_LSB]);
    y = SensorConvertData(reg[ACCEL_Y_AXIS_MSB], reg[ACCEL_Y_AXIS_LSB]);
    z = SensorConvertData(reg[ACCEL_Z_AXIS_MSB], reg[ACCEL_Z_AXIS_LSB]);
    rawData->x = x;
    rawData->y = y;
    rawData->z = z;

    return HDF_SUCCESS;
}

static int32_t ReadSc7a20Data(struct SensorCfgData *cfg, struct SensorReportEvent *event)
{
    int32_t ret;
    struct AccelData rawData = { 0, 0, 0 };
    static int32_t tmp[ACCEL_AXIS_NUM];

    CHECK_NULL_PTR_RETURN_VALUE(cfg, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(event, HDF_ERR_INVALID_PARAM);

    ret = ReadSc7a20RawData(cfg, &rawData, &event->timestamp);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: SC7A20 read raw data failed", __func__);
        return HDF_FAILURE;
    }

    event->sensorId = SENSOR_TAG_ACCELEROMETER;
    event->option = 0;
    event->mode = SENSOR_WORK_MODE_REALTIME;

    rawData.x = rawData.x * SC7A20_ACC_SENSITIVITY_2G;
    rawData.y = rawData.y * SC7A20_ACC_SENSITIVITY_2G;
    rawData.z = rawData.z * SC7A20_ACC_SENSITIVITY_2G;

    tmp[ACCEL_X_AXIS] = (rawData.x * SENSOR_CONVERT_UNIT) / SENSOR_CONVERT_UNIT;
    tmp[ACCEL_Y_AXIS] = (rawData.y * SENSOR_CONVERT_UNIT) / SENSOR_CONVERT_UNIT;
    tmp[ACCEL_Z_AXIS] = (rawData.z * SENSOR_CONVERT_UNIT) / SENSOR_CONVERT_UNIT;

    ret = SensorRawDataToRemapData(cfg->direction, tmp, sizeof(tmp) / sizeof(tmp[0]));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: SC7A20 convert raw data failed", __func__);
        return HDF_FAILURE;
    }

    event->dataLen = sizeof(tmp);
    event->data = (uint8_t *)&tmp;

    return ret;
}

static int32_t InitSc7a20(struct SensorCfgData *data)
{
    int32_t ret;

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);
    ret = SetSensorRegCfgArray(&data->busCfg, data->regCfgGroup[SENSOR_INIT_GROUP]);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: SC7A20 sensor init config failed", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t DispatchSc7a20(struct HdfDeviceIoClient *client,
    int cmd, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    (void)client;
    (void)cmd;
    (void)data;
    (void)reply;

    return HDF_SUCCESS;
}

static int32_t Sc7a20BindDriver(struct HdfDeviceObject *device)
{
    CHECK_NULL_PTR_RETURN_VALUE(device, HDF_ERR_INVALID_PARAM);

    struct Sc7a20DrvData *drvData = (struct Sc7a20DrvData *)OsalMemCalloc(sizeof(*drvData));
    if (drvData == NULL) {
        HDF_LOGE("%s: Malloc SC7A20 drv data fail", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    drvData->ioService.Dispatch = DispatchSc7a20;
    drvData->device = device;
    device->service = &drvData->ioService;
    g_sc7a20DrvData = drvData;

    return HDF_SUCCESS;
}

static int32_t Sc7a20InitDriver(struct HdfDeviceObject *device)
{
    int32_t ret;
    struct AccelOpsCall ops;

    CHECK_NULL_PTR_RETURN_VALUE(device, HDF_ERR_INVALID_PARAM);
    struct Sc7a20DrvData *drvData = (struct Sc7a20DrvData *)device->service;
    CHECK_NULL_PTR_RETURN_VALUE(drvData, HDF_ERR_INVALID_PARAM);

    drvData->sensorCfg = AccelCreateCfgData(device->property);
    if (drvData->sensorCfg == NULL || drvData->sensorCfg->root == NULL) {
        HDF_LOGD("%s: Creating accelcfg failed because detection failed", __func__);
        return HDF_ERR_NOT_SUPPORT;
    }

    ops.Init = NULL;
    ops.ReadData = ReadSc7a20Data;
    ret = AccelRegisterChipOps(&ops);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Register SC7A20 accel failed", __func__);
        return HDF_FAILURE;
    }

    ret = InitSc7a20(drvData->sensorCfg);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Init SC7A20 accel failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static void Sc7a20ReleaseDriver(struct HdfDeviceObject *device)
{
    CHECK_NULL_PTR_RETURN(device);

    struct Sc7a20DrvData *drvData = (struct Sc7a20DrvData *)device->service;
    CHECK_NULL_PTR_RETURN(drvData);

    if (drvData->sensorCfg != NULL) {
        AccelReleaseCfgData(drvData->sensorCfg);
        drvData->sensorCfg = NULL;
    }
    OsalMemFree(drvData);
}

struct HdfDriverEntry g_accelSc7a20DevEntry = {
    .moduleVersion = 1,
    .moduleName = "HDF_SENSOR_ACCEL_SC7A20",
    .Bind = Sc7a20BindDriver,
    .Init = Sc7a20InitDriver,
    .Release = Sc7a20ReleaseDriver,
};

HDF_INIT(g_accelSc7a20DevEntry);
