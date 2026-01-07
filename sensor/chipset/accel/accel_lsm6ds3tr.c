
/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#include "accel_lsm6ds3tr.h"
#include <securec.h>
#include "osal_mem.h"
#include "osal_time.h"
#include "sensor_accel_driver.h"
#include "sensor_config_controller.h"
#include "sensor_device_manager.h"

#define HDF_LOG_TAG    hdf_sensor_accel

static struct LSM6DS3TRDrvData *g_lsm6ds3trDrvData = NULL;

static struct LSM6DS3TRDrvData *LSM6DS3TRGetDrvData(void)
{
    return g_lsm6ds3trDrvData;
}

static int32_t ReadLSM6DS3TRRawData(struct SensorCfgData *data, struct AccelData *rawData, uint64_t *timestamp)
{
    uint8_t reg[ACCEL_AXIS_BUTT];
    OsalTimespec time;
    int32_t ret = 0;

    (void)memset_s(&time, sizeof(time), 0, sizeof(time));
    (void)memset_s(reg, sizeof(reg), 0, sizeof(reg));

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);

    if (OsalGetTime(&time) != HDF_SUCCESS) {
        HDF_LOGE("%s: Get time failed", __func__);
        return HDF_FAILURE;
    }
    *timestamp = time.sec * SENSOR_SECOND_CONVERT_NANOSECOND + time.usec * SENSOR_CONVERT_UNIT; /* unit nanosecond */
    ret = ReadSensor(&data->busCfg, LSM6DS3TR_ACCEL_X_LSB_ADDR, &reg[ACCEL_X_AXIS_LSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    ret = ReadSensor(&data->busCfg, LSM6DS3TR_ACCEL_X_MSB_ADDR, &reg[ACCEL_X_AXIS_MSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    ret = ReadSensor(&data->busCfg, LSM6DS3TR_ACCEL_Y_LSB_ADDR, &reg[ACCEL_Y_AXIS_LSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    ret = ReadSensor(&data->busCfg, LSM6DS3TR_ACCEL_Y_MSB_ADDR, &reg[ACCEL_Y_AXIS_MSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    ret = ReadSensor(&data->busCfg, LSM6DS3TR_ACCEL_Z_LSB_ADDR, &reg[ACCEL_Z_AXIS_LSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    ret = ReadSensor(&data->busCfg, LSM6DS3TR_ACCEL_Z_MSB_ADDR, &reg[ACCEL_Z_AXIS_MSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    rawData->x = (int16_t)(SENSOR_DATA_SHIFT_LEFT(reg[ACCEL_X_AXIS_MSB], SENSOR_DATA_WIDTH_8_BIT) |
        reg[ACCEL_X_AXIS_LSB]);
    rawData->y = (int16_t)(SENSOR_DATA_SHIFT_LEFT(reg[ACCEL_Y_AXIS_MSB], SENSOR_DATA_WIDTH_8_BIT) |
        reg[ACCEL_Y_AXIS_LSB]);
    rawData->z = (int16_t)(SENSOR_DATA_SHIFT_LEFT(reg[ACCEL_Z_AXIS_MSB], SENSOR_DATA_WIDTH_8_BIT) |
        reg[ACCEL_Z_AXIS_LSB]);
    return HDF_SUCCESS;
}

int32_t ReadLSM6DS3TRData(struct SensorCfgData *cfg, struct SensorReportEvent *event)
{
    int32_t ret;
    struct AccelData rawData = { 0, 0, 0 };
    static int32_t tmp[ACCEL_AXIS_NUM];

    CHECK_NULL_PTR_RETURN_VALUE(cfg, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(event, HDF_ERR_INVALID_PARAM);

    ret = ReadLSM6DS3TRRawData(cfg, &rawData, &event->timestamp);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: LSM6DS3TR read raw data failed", __func__);
        return HDF_FAILURE;
    }

    event->sensorId = SENSOR_TAG_ACCELEROMETER;
    event->option = 0;
    event->mode = SENSOR_WORK_MODE_REALTIME;

    tmp[ACCEL_X_AXIS] = rawData.x * LSM6DS3TR_ACC_SENSITIVITY_2G ;
    tmp[ACCEL_Y_AXIS] = rawData.y * LSM6DS3TR_ACC_SENSITIVITY_2G ;
    tmp[ACCEL_Z_AXIS] = rawData.z * LSM6DS3TR_ACC_SENSITIVITY_2G ;
    ret = SensorRawDataToRemapData(cfg->direction, tmp, sizeof(tmp) / sizeof(tmp[0]));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: LSM6DS3TR convert raw data failed", __func__);
        return HDF_FAILURE;
    }

    event->dataLen = sizeof(tmp);
    event->data = (uint8_t *)&tmp;

    return ret;
}

static int32_t InitLSM6DS3TR(struct SensorCfgData *data)
{
    uint8_t value[2];
    int ret;
    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);
    ret = SetSensorRegCfgArray(&data->busCfg, data->regCfgGroup[SENSOR_INIT_GROUP]);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: LSM6DS3TR sensor init config failed", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t DispatchLSM6DS3TR(struct HdfDeviceIoClient *client,
    int cmd, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    (void)client;
    (void)cmd;
    (void)data;
    (void)reply;

    return HDF_SUCCESS;
}

int32_t LSM6DS3TRBindDriver(struct HdfDeviceObject *device)
{
    CHECK_NULL_PTR_RETURN_VALUE(device, HDF_ERR_INVALID_PARAM);

    struct LSM6DS3TRDrvData *drvData = (struct LSM6DS3TRDrvData *)OsalMemCalloc(sizeof(*drvData));
    if (drvData == NULL) {
        HDF_LOGE("%s: Malloc LSM6DS3TR drv data fail", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    drvData->ioService.Dispatch = DispatchLSM6DS3TR;
    drvData->device = device;
    device->service = &drvData->ioService;

    return HDF_SUCCESS;
}

int32_t LSM6DS3TRInitDriver(struct HdfDeviceObject *device)
{
    int32_t ret;
    struct AccelOpsCall ops;
    CHECK_NULL_PTR_RETURN_VALUE(device, HDF_ERR_INVALID_PARAM);
    struct LSM6DS3TRDrvData *drvData = (struct LSM6DS3TRDrvData *)device->service;
    CHECK_NULL_PTR_RETURN_VALUE(drvData, HDF_ERR_INVALID_PARAM);

    drvData->sensorCfg = AccelCreateCfgData(device->property);
    HDF_LOGE("%s: cainiaocl_sensor:drvData->sensorCfg = %p", __func__, drvData->sensorCfg);
    if (drvData->sensorCfg == NULL || drvData->sensorCfg->root == NULL) {
        HDF_LOGD("%s: Creating LSM6DS3TR accelcfg failed because detection failed", __func__);
        return HDF_ERR_NOT_SUPPORT;
    }

    ops.Init = NULL;
    ops.ReadData = ReadLSM6DS3TRData;
    ret = AccelRegisterChipOps(&ops);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Register LSM6DS3TR accel failed", __func__);
        return HDF_FAILURE;
    }

    ret = InitLSM6DS3TR(drvData->sensorCfg);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Init LSM6DS3TR accel failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

void LSM6DS3TRReleaseDriver(struct HdfDeviceObject *device)
{
    CHECK_NULL_PTR_RETURN(device);

    struct LSM6DS3TRDrvData *drvData = (struct LSM6DS3TRDrvData *)device->service;
    CHECK_NULL_PTR_RETURN(drvData);

    if (drvData->sensorCfg != NULL) {
        AccelReleaseCfgData(drvData->sensorCfg);
        drvData->sensorCfg = NULL;
    }
    OsalMemFree(drvData);
}

struct HdfDriverEntry g_accelLSM6DS3TRDevEntry = {
    .moduleVersion = 1,
    .moduleName = "HDF_SENSOR_ACCEL_LSM6DS3TR",
    .Bind = LSM6DS3TRBindDriver,
    .Init = LSM6DS3TRInitDriver,
    .Release = LSM6DS3TRReleaseDriver,
};

HDF_INIT(g_accelLSM6DS3TRDevEntry);
