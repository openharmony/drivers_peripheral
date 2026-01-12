/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#include "gyro_lsm6ds3tr.h"
#include <securec.h>
#include "osal_mem.h"
#include "osal_time.h"
#include "sensor_gyro_driver.h"
#include "sensor_config_controller.h"
#include "sensor_device_manager.h"

#define HDF_LOG_TAG khdf_sensor_gyro_driver

static struct Gyro_Lsm6ds3trDrvData *g_lsm6ds3trDrvData = NULL;

static int32_t ReadLsm6ds3trGyroRawData(struct SensorCfgData *data, struct GyroData *rawData, uint64_t *timestamp)
{
    uint8_t status = 0;
    uint8_t reg[GYRO_AXIS_BUTT];
    OsalTimespec time;

    (void)memset_s(&time, sizeof(time), 0, sizeof(time));
    (void)memset_s(reg, sizeof(reg), 0, sizeof(reg));

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);
    if (OsalGetTime(&time) != HDF_SUCCESS) {
        HDF_LOGE("%s: Get time failed", __func__);
        return HDF_FAILURE;
    }
    *timestamp = time.sec * SENSOR_SECOND_CONVERT_NANOSECOND + time.usec * SENSOR_CONVERT_UNIT; /* unit nanosecond */
    int32_t ret = ReadSensor(&data->busCfg, LSM6DS3TR_STATUS_ADDR, &status, sizeof(uint8_t));

    ret = ReadSensor(&data->busCfg, LSM6DS3TR_GYRO_X_LSB_ADDR, &reg[GYRO_X_AXIS_LSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    ret = ReadSensor(&data->busCfg, LSM6DS3TR_GYRO_X_MSB_ADDR, &reg[GYRO_X_AXIS_MSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    ret = ReadSensor(&data->busCfg, LSM6DS3TR_GYRO_Y_LSB_ADDR, &reg[GYRO_Y_AXIS_LSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");
    ret = ReadSensor(&data->busCfg, LSM6DS3TR_GYRO_Y_MSB_ADDR, &reg[GYRO_Y_AXIS_MSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    ret = ReadSensor(&data->busCfg, LSM6DS3TR_GYRO_Z_LSB_ADDR, &reg[GYRO_Z_AXIS_LSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    ret = ReadSensor(&data->busCfg, LSM6DS3TR_GYRO_Z_MSB_ADDR, &reg[GYRO_Z_AXIS_MSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    rawData->x = (int16_t)(SENSOR_DATA_SHIFT_LEFT(reg[GYRO_X_AXIS_MSB], SENSOR_DATA_WIDTH_8_BIT) |
        reg[GYRO_X_AXIS_LSB]);
    rawData->y = (int16_t)(SENSOR_DATA_SHIFT_LEFT(reg[GYRO_Y_AXIS_MSB], SENSOR_DATA_WIDTH_8_BIT) |
        reg[GYRO_Y_AXIS_LSB]);
    rawData->z = (int16_t)(SENSOR_DATA_SHIFT_LEFT(reg[GYRO_Z_AXIS_MSB], SENSOR_DATA_WIDTH_8_BIT) |
        reg[GYRO_Z_AXIS_LSB]);
    return ret;
}

static int32_t ReadLsm6ds3trGyroData(struct SensorCfgData *data)
{
    int32_t ret;
    struct GyroData rawData = { 0, 0, 0 };
    int32_t tmp[GYRO_AXIS_NUM];
    struct SensorReportEvent event;

    (void)memset_s(&event, sizeof(event), 0, sizeof(event));

    ret = ReadLsm6ds3trGyroRawData(data, &rawData, &event.timestamp);
    if (ret != HDF_SUCCESS) {
        return HDF_FAILURE;
    }

    event.sensorId = SENSOR_TAG_GYROSCOPE;
    event.option = 0;
    event.mode = SENSOR_WORK_MODE_REALTIME;

    tmp[GYRO_X_AXIS] = (rawData.x * LSM6DS3TR_GYRO_RANGE_245DPS);
    tmp[GYRO_Y_AXIS] = (rawData.y * LSM6DS3TR_GYRO_RANGE_245DPS);
    tmp[GYRO_Z_AXIS] = (rawData.z * LSM6DS3TR_GYRO_RANGE_245DPS);
    ret = SensorRawDataToRemapData(data->direction, tmp, sizeof(tmp) / sizeof(tmp[0]));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: LSM6DS3TR convert raw data failed", __func__);
        return HDF_FAILURE;
    }

    event.dataLen = sizeof(tmp);
    event.data = (uint8_t *)&tmp;
    ret = ReportSensorEvent(&event);
    return ret;
}
static int32_t InitLsm6ds3tr(struct SensorCfgData *data)
{
    int32_t ret;

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);
    ret = SetSensorRegCfgArray(&data->busCfg, data->regCfgGroup[SENSOR_INIT_GROUP]);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: LSM6DS3TR sensor init config failed", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t DispatchLsm6ds3tr(struct HdfDeviceIoClient *client,
    int cmd, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    (void)client;
    (void)cmd;
    (void)data;
    (void)reply;

    return HDF_SUCCESS;
}

static int32_t GyroLsm6ds3trBindDriver(struct HdfDeviceObject *device)
{
    HDF_LOGI("%s: into GyroLsm6ds3trBindDriver", __func__);
    CHECK_NULL_PTR_RETURN_VALUE(device, HDF_ERR_INVALID_PARAM);

    struct Gyro_Lsm6ds3trDrvData *drvData = (struct Gyro_Lsm6ds3trDrvData *)OsalMemCalloc(sizeof(*drvData));
    if (drvData == NULL) {
        HDF_LOGE("%s: Malloc LSM6DS3TR drv data fail", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    drvData->ioService.Dispatch = DispatchLsm6ds3tr;
    drvData->device = device;
    device->service = &drvData->ioService;
    g_lsm6ds3trDrvData = drvData;

    return HDF_SUCCESS;
}

static int32_t GyroLsm6ds3trInitDriver(struct HdfDeviceObject *device)
{
    HDF_LOGI("%s: into GyroLsm6ds3trInitDriver", __func__);
    int32_t ret;
    struct GyroOpsCall ops;

    CHECK_NULL_PTR_RETURN_VALUE(device, HDF_ERR_INVALID_PARAM);
    struct Gyro_Lsm6ds3trDrvData *drvData = (struct Gyro_Lsm6ds3trDrvData *)device->service;
    CHECK_NULL_PTR_RETURN_VALUE(drvData, HDF_ERR_INVALID_PARAM);

    drvData->sensorCfg = GyroCreateCfgData(device->property);
    if (drvData->sensorCfg == NULL || drvData->sensorCfg->root == NULL) {
        HDF_LOGD("%s: Creating LSM6DS3TR gyrocfg failed because detection failed", __func__);
        return HDF_ERR_NOT_SUPPORT;
    }

    ops.Init = NULL;
    ops.ReadData = ReadLsm6ds3trGyroData;
    ret = GyroRegisterChipOps(&ops);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Register LSM6DS3TR gyro failed", __func__);
        return HDF_FAILURE;
    }

    ret = InitLsm6ds3tr(drvData->sensorCfg);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Init LSM6DS3TR gyro failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static void GyroLsm6ds3trReleaseDriver(struct HdfDeviceObject *device)
{
    CHECK_NULL_PTR_RETURN(device);

    struct Gyro_Lsm6ds3trDrvData *drvData = (struct Gyro_Lsm6ds3trDrvData *)device->service;
    CHECK_NULL_PTR_RETURN(drvData);

    if (drvData->sensorCfg != NULL) {
        GyroReleaseCfgData(drvData->sensorCfg);
        drvData->sensorCfg = NULL;
    }

    OsalMemFree(drvData);
}

struct HdfDriverEntry g_gyroLsm6ds3trDevEntry = {
    .moduleVersion = 1,
    .moduleName = "HDF_SENSOR_GYRO_LSM6DS3TR",
    .Bind = GyroLsm6ds3trBindDriver,
    .Init = GyroLsm6ds3trInitDriver,
    .Release = GyroLsm6ds3trReleaseDriver,
};

HDF_INIT(g_gyroLsm6ds3trDevEntry);
