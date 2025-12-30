/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#include "gyro_mic6200.h"
#include <securec.h>
#include "osal_mem.h"
#include "osal_time.h"
#include "sensor_gyro_driver.h"
#include "sensor_config_controller.h"
#include "sensor_device_manager.h"

#define HDF_LOG_TAG    khdf_sensor_gyro_driver
#define SHIFT_8BIT 8

static struct Mic6200DrvData *g_mic6200DrvData = NULL;

static struct Mic6200DrvData *Mic6200GetDrvData(void)
{
    return g_mic6200DrvData;
}

static int32_t ReadMic6200GyroRawData(struct SensorCfgData *data, struct GyroData *rawData, uint64_t *timestamp)
{
    uint8_t reg[GYRO_AXIS_BUTT];
    OsalTimespec time;
    int16_t x;
    int16_t y;
    int16_t z;

    (void)memset_s(&time, sizeof(time), 0, sizeof(time));
    (void)memset_s(reg, sizeof(reg), 0, sizeof(reg));

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);

    if (OsalGetTime(&time) != HDF_SUCCESS) {
        HDF_LOGE("%s: Get time failed", __func__);
        return HDF_FAILURE;
    }
    *timestamp = time.sec * SENSOR_SECOND_CONVERT_NANOSECOND + time.usec * SENSOR_CONVERT_UNIT; /* unit nanosecond */
    int32_t ret = ReadSensor(&data->busCfg, MIC6200_GYRO_X_LSB_ADDR, &reg[GYRO_X_AXIS_LSB], sizeof(reg));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: read data failed, ret [%d]", __func__, ret);
        return HDF_FAILURE;
    }
    x = reg[GYRO_X_AXIS_LSB] | (reg[GYRO_X_AXIS_MSB] << SHIFT_8BIT);
    y = reg[GYRO_Y_AXIS_LSB] | (reg[GYRO_Y_AXIS_MSB] << SHIFT_8BIT);
    z = reg[GYRO_Z_AXIS_LSB] | (reg[GYRO_Z_AXIS_MSB] << SHIFT_8BIT);
    rawData->x = (int32_t)x;
    rawData->y = (int32_t)y;
    rawData->z = (int32_t)z;

    return ret;
}

static int32_t ReadMic6200GyroData(struct SensorCfgData *data)
{
    int32_t ret;
    struct GyroData rawData = { 0, 0, 0 };
    struct SensorReportEvent event;
    int32_t *tmp = (int32_t *)OsalMemCalloc(sizeof(int32_t) * GYRO_AXIS_NUM);
	if (tmp == NULL) {
        return HDF_ERR_MALLOC_FAIL;
	}
    (void)memset_s(&event, sizeof(event), 0, sizeof(event));

    ret = ReadMic6200GyroRawData(data, &rawData, &event.timestamp);
    if (ret != HDF_SUCCESS) {
        return HDF_FAILURE;
    }

    event.sensorId = SENSOR_TAG_GYROSCOPE;
    event.option = 0;
    event.mode = SENSOR_WORK_MODE_REALTIME;

    // Convert raw data to degrees per second using MIC6200 resolution
    tmp[GYRO_X_AXIS] = (rawData.x * MIC6200_GYRO_SENSITIVITY_2000DPS_NUM) / MIC6200_GYRO_SENSITIVITY_2000DPS_DEN;
    tmp[GYRO_Y_AXIS] = (rawData.y * MIC6200_GYRO_SENSITIVITY_2000DPS_NUM) / MIC6200_GYRO_SENSITIVITY_2000DPS_DEN;
    tmp[GYRO_Z_AXIS] = (rawData.z * MIC6200_GYRO_SENSITIVITY_2000DPS_NUM) / MIC6200_GYRO_SENSITIVITY_2000DPS_DEN;

    ret = SensorRawDataToRemapData(data->direction, tmp, sizeof(tmp) / sizeof(tmp[0]));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: MIC6200 convert raw data failed", __func__);
        return HDF_FAILURE;
    }

    event.dataLen = sizeof(int32_t) * GYRO_AXIS_NUM;
    event.data = (uint8_t *)tmp;
    ret = ReportSensorEvent(&event);
    return ret;
}

static int32_t VerifyMic6200Id(struct SensorCfgData *data)
{
    int32_t ret;
    uint8_t chipId = 0;

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);
    
    // Read chip ID from register 0x00
    ret = ReadSensor(&data->busCfg, MIC6200_CHIP_ID_ADDR, &chipId, sizeof(uint8_t));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: read chip id failed", __func__);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: MIC6200 chip id read: 0x%02x, expected: 0x%02x", __func__, chipId, MIC6200_CHIP_ID_VALUE);

    // Verify chip ID
    if (chipId != MIC6200_CHIP_ID_VALUE) {
        HDF_LOGE("%s: chip id mismatch, read: 0x%02x, expected: 0x%02x", __func__, chipId, MIC6200_CHIP_ID_VALUE);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: MIC6200 chip id verified", __func__);
    return HDF_SUCCESS;
}

static int32_t InitMic6200(struct SensorCfgData *data)
{
    int32_t ret;
    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);
    
    HDF_LOGI("%s: Initializing MIC6200 gyroscope sensor", __func__);
    
    // Verify chip ID first
    ret = VerifyMic6200Id(data);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: MIC6200 chip verification failed", __func__);
        return HDF_FAILURE;
    }
    
    // Initialize sensor with configuration from HCS file
    ret = SetSensorRegCfgArray(&data->busCfg, data->regCfgGroup[SENSOR_INIT_GROUP]);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: MIC6200 sensor init config failed", __func__);
        return HDF_FAILURE;
    }
    
    return HDF_SUCCESS;
}

static int32_t DispatchMIC6200(struct HdfDeviceIoClient *client,
    int cmd, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    (void)client;
    (void)cmd;
    (void)data;
    (void)reply;

    return HDF_SUCCESS;
}

static int32_t Mic6200BindDriver(struct HdfDeviceObject *device)
{
    CHECK_NULL_PTR_RETURN_VALUE(device, HDF_ERR_INVALID_PARAM);

    struct Mic6200DrvData *drvData = (struct Mic6200DrvData *)OsalMemCalloc(sizeof(*drvData));
    if (drvData == NULL) {
        HDF_LOGE("%s: Malloc MIC6200 drv data fail", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    drvData->ioService.Dispatch = DispatchMIC6200;
    drvData->device = device;
    device->service = &drvData->ioService;
    g_mic6200DrvData = drvData;

    return HDF_SUCCESS;
}

static int32_t Mic6200InitDriver(struct HdfDeviceObject *device)
{
    int32_t ret;
    struct GyroOpsCall ops;

    CHECK_NULL_PTR_RETURN_VALUE(device, HDF_ERR_INVALID_PARAM);
    struct Mic6200DrvData *drvData = (struct Mic6200DrvData *)device->service;
    CHECK_NULL_PTR_RETURN_VALUE(drvData, HDF_ERR_INVALID_PARAM);

    drvData->sensorCfg = GyroCreateCfgData(device->property);
    if (drvData->sensorCfg == NULL || drvData->sensorCfg->root == NULL) {
        HDF_LOGD("%s: Creating gyrocfg failed because detection failed", __func__);
        return HDF_ERR_NOT_SUPPORT;
    }

    ops.Init = NULL;
    ops.ReadData = ReadMic6200GyroData;
    ret = GyroRegisterChipOps(&ops);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Register MIC6200 gyro failed", __func__);
        return HDF_FAILURE;
    }

    ret = InitMic6200(drvData->sensorCfg);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Init MIC6200 gyro failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static void Mic6200ReleaseDriver(struct HdfDeviceObject *device)
{
    CHECK_NULL_PTR_RETURN(device);

    struct Mic6200DrvData *drvData = (struct Mic6200DrvData *)device->service;
    CHECK_NULL_PTR_RETURN(drvData);

    if (drvData->sensorCfg != NULL) {
        GyroReleaseCfgData(drvData->sensorCfg);
        drvData->sensorCfg = NULL;
    }
    OsalMemFree(drvData);
}

struct HdfDriverEntry g_gyroMic6200DevEntry = {
    .moduleVersion = 1,
    .moduleName = "HDF_SENSOR_GYRO_MIC6200",
    .Bind = Mic6200BindDriver,
    .Init = Mic6200InitDriver,
    .Release = Mic6200ReleaseDriver,
};

HDF_INIT(g_gyroMic6200DevEntry);