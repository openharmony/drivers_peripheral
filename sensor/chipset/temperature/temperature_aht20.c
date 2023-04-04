/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#include "temperature_aht20.h"
#include <securec.h>
#include "osal_mem.h"
#include "osal_time.h"
#include "sensor_config_controller.h"
#include "sensor_device_manager.h"
#include "sensor_temperature_driver.h"

#define HDF_LOG_TAG    hdf_sensor_temperature_driver

static struct Aht20DrvData *g_aht20DrvData = NULL;

static struct Aht20DrvData *Aht20GetDrvData(void)
{
    return g_aht20DrvData;
}

static int32_t ReadAht20RawData(struct SensorCfgData *data, struct TemperatureData *rawData, uint64_t *timestamp)
{
    OsalTimespec time;
    int32_t count;
    int32_t ret = HDF_SUCCESS;
    uint8_t value[AHT20_TEMP_DATA_BUF_LEN];
    uint64_t tempValue;
    uint8_t measureCmdValue[] = {AHT20_TEMP_MEASURE_ADDR, AHT20_TEMP_MEASURE_ARG0, AHT20_TEMP_MEASURE_ARG1};

    (void)memset_s(&time, sizeof(time), 0, sizeof(time));

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);

    if (OsalGetTime(&time) != HDF_SUCCESS) {
        HDF_LOGE("%s: Get time failed", __func__);
        return HDF_FAILURE;
    }

    *timestamp = time.sec * SENSOR_SECOND_CONVERT_NANOSECOND + time.usec * SENSOR_CONVERT_UNIT; /* unit nanosecond */

    ret = WriteSensor(&data->busCfg, measureCmdValue, sizeof(measureCmdValue));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "write data");

    OsalMDelay(AHT20_TEMP_DELAY_MS);

    ret = ReadSensor(&data->busCfg, AHT20_TEMP_STATUS_ADDR, value, sizeof(value));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    for (count = 0; AHT20_TEMP_IS_BUSY(value[AHT20_TEMP_VALUE_IDX_ZERO]) && (count < AHT20_TEMP_RETRY_TIMES); count++) {
        OsalMDelay(AHT20_TEMP_DELAY_MS);
        ret = ReadSensor(&data->busCfg, AHT20_TEMP_STATUS_ADDR, value, sizeof(value));
        CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");
    }

    if (count >= AHT20_TEMP_RETRY_TIMES) {
        HDF_LOGE("%s:line %d aht20 device status busy!", __func__, __LINE__);
        return HDF_FAILURE;
    }

    tempValue = value[AHT20_TEMP_VALUE_IDX_THREE] & AHT20_TEMP_MASK;
    tempValue = (tempValue << AHT20_TEMP_SHFIT_BITS) | value[AHT20_TEMP_VALUE_IDX_FOUR];
    tempValue = (tempValue << AHT20_TEMP_SHFIT_BITS) | value[AHT20_TEMP_VALUE_IDX_FIVE];

    rawData->temperature = ((tempValue * AHT20_TEMP_SLOPE) / AHT20_TEMP_RESOLUTION) - AHT20_TEMP_CONSATNT;

    return HDF_SUCCESS;
}

static int32_t ReadAht20Data(struct SensorCfgData *data)
{
    int32_t ret;
    static int32_t temperature;
    struct TemperatureData rawData = { 0 };
    OsalTimespec time;
    struct SensorReportEvent event;

    (void)memset_s(&time, sizeof(time), 0, sizeof(time));
    (void)memset_s(&event, sizeof(event), 0, sizeof(event));

    if (OsalGetTime(&time) != HDF_SUCCESS) {
        HDF_LOGE("%s: Get time failed", __func__);
        return HDF_FAILURE;
    }

    event.timestamp = time.sec * SENSOR_SECOND_CONVERT_NANOSECOND + time.usec * SENSOR_CONVERT_UNIT;

    ret = ReadAht20RawData(data, &rawData, &event.timestamp);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: AHT20 read raw data failed", __func__);
        return HDF_FAILURE;
    }

    temperature = rawData.temperature;

    event.sensorId = SENSOR_TAG_TEMPERATURE;
    event.mode = SENSOR_WORK_MODE_REALTIME;
    event.dataLen = sizeof(temperature);
    event.data = (uint8_t *)&temperature;
    ret = ReportSensorEvent(&event);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: report data failed", __func__);
    }

    return ret;
}

static int32_t InitAht20(struct SensorCfgData *data)
{
    int32_t ret;
    uint8_t value[AHT20_TEMP_DATA_BUF_LEN];
    uint8_t resetCmd = AHT20_TEMP_RESET_ADDR;
    uint8_t calibrationCmd[] = {AHT20_TEMP_CALIBRATION_ADDR, AHT20_TEMP_CALIBRATION_ARG0, AHT20_TEMP_CALIBRATION_ARG1};

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);
    ret = SetSensorRegCfgArray(&data->busCfg, data->regCfgGroup[SENSOR_INIT_GROUP]);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: sensor init config failed", __func__);
        return HDF_FAILURE;
    }

    ret = ReadSensor(&data->busCfg, AHT20_TEMP_STATUS_ADDR, value, sizeof(value));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    if (AHT20_TEMP_IS_BUSY(value[AHT20_TEMP_VALUE_IDX_ZERO]) || !AHT20_TEMP_IS_CALI(value[AHT20_TEMP_VALUE_IDX_ZERO])) {
        ret = WriteSensor(&data->busCfg, &resetCmd, sizeof(resetCmd));
        CHECK_PARSER_RESULT_RETURN_VALUE(ret, "write data");

        OsalMDelay(AHT20_TEMP_STARTUP_MS);

        ret = WriteSensor(&data->busCfg, calibrationCmd, sizeof(calibrationCmd));
        CHECK_PARSER_RESULT_RETURN_VALUE(ret, "write data");

        OsalMDelay(AHT20_TEMP_CALIBRATION_MS);
    }

    return HDF_SUCCESS;
}

static int32_t DispatchAht20(struct HdfDeviceIoClient *client,
    int cmd, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    (void)client;
    (void)cmd;
    (void)data;
    (void)reply;

    return HDF_SUCCESS;
}

static int32_t Aht20BindDriver(struct HdfDeviceObject *device)
{
    CHECK_NULL_PTR_RETURN_VALUE(device, HDF_ERR_INVALID_PARAM);

    struct Aht20DrvData *drvData = (struct Aht20DrvData *)OsalMemCalloc(sizeof(*drvData));
    if (drvData == NULL) {
        HDF_LOGE("%s: malloc drv data fail", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    drvData->ioService.Dispatch = DispatchAht20;
    drvData->device = device;
    device->service = &drvData->ioService;
    g_aht20DrvData = drvData;

    return HDF_SUCCESS;
}

static int32_t Aht20InitDriver(struct HdfDeviceObject *device)
{
    int32_t ret;
    struct TemperatureOpsCall ops;

    CHECK_NULL_PTR_RETURN_VALUE(device, HDF_ERR_INVALID_PARAM);
    struct Aht20DrvData *drvData = (struct Aht20DrvData *)device->service;
    CHECK_NULL_PTR_RETURN_VALUE(drvData, HDF_ERR_INVALID_PARAM);

    drvData->sensorCfg = TemperatureCreateCfgData(device->property);
    if (drvData->sensorCfg == NULL || drvData->sensorCfg->root == NULL) {
        HDF_LOGE("%s: Creating temperature cfg failed because detection failed", __func__);
        return HDF_ERR_NOT_SUPPORT;
    }

    ops.Init = NULL;
    ops.ReadData = ReadAht20Data;
    ret = TemperatureRegisterChipOps(&ops);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Register temperature failed", __func__);
        return HDF_FAILURE;
    }

    ret = InitAht20(drvData->sensorCfg);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Init AHT20 temperature sensor failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static void Aht20ReleaseDriver(struct HdfDeviceObject *device)
{
    CHECK_NULL_PTR_RETURN(device);

    struct Aht20DrvData *drvData = (struct Aht20DrvData *)device->service;
    CHECK_NULL_PTR_RETURN(drvData);

    if (drvData->sensorCfg != NULL) {
        TemperatureReleaseCfgData(drvData->sensorCfg);
        drvData->sensorCfg = NULL;
    }
    OsalMemFree(drvData);
}

struct HdfDriverEntry g_temperatureAht20DevEntry = {
    .moduleVersion = 1,
    .moduleName = "HDF_SENSOR_TEMPERATURE_AHT20",
    .Bind = Aht20BindDriver,
    .Init = Aht20InitDriver,
    .Release = Aht20ReleaseDriver,
};

HDF_INIT(g_temperatureAht20DevEntry);
