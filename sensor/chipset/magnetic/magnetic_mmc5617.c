/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#include "magnetic_mmc5617.h"
#include <securec.h>
#include "osal_mem.h"
#include "osal_time.h"
#include "sensor_config_controller.h"
#include "sensor_device_manager.h"
#include "sensor_magnetic_driver.h"

#define HDF_LOG_TAG    hdf_sensor_magnetic

#define MAX_RETRY_ATTEMPTS 5

static struct Mmc5617DrvData *g_mmc5617DrvData = NULL;

struct Mmc5617DrvData *Mmc5617GetDrvData(void)
{
    return g_mmc5617DrvData;
}

static int32_t ReadMmc5617RawData(struct SensorCfgData *data, struct MagneticData *rawData, uint64_t *timestamp)
{
    uint8_t drdy = 0;
    uint8_t reg[MAGNETIC_AXIS_BUTT];
    OsalTimespec time;
    int32_t ret;
    int32_t retry = 0;

    (void)memset_s(&time, sizeof(time), 0, sizeof(time));
    (void)memset_s(reg, sizeof(reg), 0, sizeof(reg));

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);

    if (OsalGetTime(&time) != HDF_SUCCESS) {
        HDF_LOGE("%s: Get time failed", __func__);
        return HDF_FAILURE;
    }
    *timestamp = time.sec * SENSOR_SECOND_CONVERT_NANOSECOND + time.usec * SENSOR_CONVERT_UNIT; /* unit nanosecond */

    while (!(drdy & 0x01) && retry < MAX_RETRY_ATTEMPTS) {
        ReadSensor(&data->busCfg, MMC5617_STATUS_ADDR, &drdy, sizeof(uint8_t));
        retry++;
        OsalSleep(1);
    }

    ret = ReadSensor(&data->busCfg, MMC5617_MAGNETIC_X_MSB_ADDR, &reg[MAGNETIC_X_AXIS_MSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    ret = ReadSensor(&data->busCfg, MMC5617_MAGNETIC_X_LSB_ADDR, &reg[MAGNETIC_X_AXIS_LSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    ret = ReadSensor(&data->busCfg, MMC5617_MAGNETIC_Y_MSB_ADDR, &reg[MAGNETIC_Y_AXIS_MSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    ret = ReadSensor(&data->busCfg, MMC5617_MAGNETIC_Y_LSB_ADDR, &reg[MAGNETIC_Y_AXIS_LSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    ret = ReadSensor(&data->busCfg, MMC5617_MAGNETIC_Z_MSB_ADDR, &reg[MAGNETIC_Z_AXIS_MSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    ret = ReadSensor(&data->busCfg, MMC5617_MAGNETIC_Z_LSB_ADDR, &reg[MAGNETIC_Z_AXIS_LSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    rawData->x = (int16_t)(SENSOR_DATA_SHIFT_LEFT(reg[MAGNETIC_X_AXIS_MSB], SENSOR_DATA_WIDTH_8_BIT) |
        reg[MAGNETIC_X_AXIS_LSB]);
    rawData->y = (int16_t)(SENSOR_DATA_SHIFT_LEFT(reg[MAGNETIC_Y_AXIS_MSB], SENSOR_DATA_WIDTH_8_BIT) |
        reg[MAGNETIC_Y_AXIS_LSB]);
    rawData->z = (int16_t)(SENSOR_DATA_SHIFT_LEFT(reg[MAGNETIC_Z_AXIS_MSB], SENSOR_DATA_WIDTH_8_BIT) |
        reg[MAGNETIC_Z_AXIS_LSB]);

    return HDF_SUCCESS;
}

int32_t ReadMmc5617Data(struct SensorCfgData *data)
{
    struct MagneticData rawData = { 0, 0, 0 };
    struct SensorReportEvent event;
    int8_t sign[MAGNETIC_AXIS_NUM] = {1, -1, -1};
    int32_t *tmp = (int32_t *)OsalMemCalloc(sizeof(int32_t) * MAGNETIC_AXIS_NUM);
    if (tmp == NULL) {
        return HDF_ERR_MALLOC_FAIL;
    }
    (void)memset_s(&event, sizeof(event), 0, sizeof(event));
    (void)memset_s(tmp, sizeof(tmp), 0, sizeof(tmp));

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);

    int32_t ret = ReadMmc5617RawData(data, &rawData, &event.timestamp);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: MMC5617 read raw data failed", __func__);
        return HDF_FAILURE;
    }

    event.sensorId = SENSOR_TAG_MAGNETIC_FIELD;
    event.option = 0;
    event.mode = SENSOR_WORK_MODE_REALTIME;

    tmp[MAGNETIC_X_AXIS] = (rawData.x * sign[MAGNETIC_X_AXIS] - MMC5617_16BIT_OFFSET);
    tmp[MAGNETIC_Y_AXIS] = (rawData.y * sign[MAGNETIC_Y_AXIS] - MMC5617_16BIT_OFFSET);
    tmp[MAGNETIC_Z_AXIS] = (rawData.z * sign[MAGNETIC_Z_AXIS] - MMC5617_16BIT_OFFSET);

    ret = SensorRawDataToRemapData(data->direction, tmp, sizeof(tmp) / sizeof(tmp[0]));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: MMC5617 convert raw data failed", __func__);
        return HDF_FAILURE;
    }

    event.dataLen = sizeof(int32_t) * MAGNETIC_AXIS_NUM;
    event.data = (uint8_t *)tmp;
    ret = ReportSensorEvent(&event);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: MMC5617 report data failed", __func__);
    }

    return ret;
}

static int32_t InitMmc5617(struct SensorCfgData *data)
{
    int32_t ret;

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);

    ret = SetSensorRegCfgArray(&data->busCfg, data->regCfgGroup[SENSOR_INIT_GROUP]);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: MMC5617 sensor init config failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t DispatchMmc5617(struct HdfDeviceIoClient *client,
    int cmd, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    (void)client;
    (void)cmd;
    (void)data;
    (void)reply;

    return HDF_SUCCESS;
}

int32_t Mmc5617BindDriver(struct HdfDeviceObject *device)
{
    CHECK_NULL_PTR_RETURN_VALUE(device, HDF_ERR_INVALID_PARAM);

    struct Mmc5617DrvData *drvData = (struct Mmc5617DrvData *)OsalMemCalloc(sizeof(*drvData));
    if (drvData == NULL) {
        HDF_LOGE("%s: Malloc Mmc5617 drv data fail", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    drvData->ioService.Dispatch = DispatchMmc5617;
    drvData->device = device;
    device->service = &drvData->ioService;
    g_mmc5617DrvData = drvData;

    return HDF_SUCCESS;
}

int32_t Mmc5617InitDriver(struct HdfDeviceObject *device)
{
    int32_t ret;
    struct MagneticOpsCall ops;

    CHECK_NULL_PTR_RETURN_VALUE(device, HDF_ERR_INVALID_PARAM);
    struct Mmc5617DrvData *drvData = (struct Mmc5617DrvData *)device->service;
    CHECK_NULL_PTR_RETURN_VALUE(drvData, HDF_ERR_INVALID_PARAM);

    drvData->sensorCfg = MagneticCreateCfgData(device->property);
    if (drvData->sensorCfg == NULL || drvData->sensorCfg->root == NULL) {
        HDF_LOGD("%s: Creating magneticcfg failed because detection failed", __func__);
        return HDF_ERR_NOT_SUPPORT;
    }

    ops.Init = NULL;
    ops.ReadData = ReadMmc5617Data;
    ret = MagneticRegisterChipOps(&ops);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Register MMC5617 magnetic failed", __func__);
        return HDF_FAILURE;
    }

    ret = InitMmc5617(drvData->sensorCfg);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Init MMC5617 magnetic failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

void Mmc5617ReleaseDriver(struct HdfDeviceObject *device)
{
    CHECK_NULL_PTR_RETURN(device);

    struct Mmc5617DrvData *drvData = (struct Mmc5617DrvData *)device->service;
    CHECK_NULL_PTR_RETURN(drvData);

    if (drvData->sensorCfg != NULL) {
        MagneticReleaseCfgData(drvData->sensorCfg);
        drvData->sensorCfg = NULL;
    }
    OsalMemFree(drvData);
}

struct HdfDriverEntry g_magneticMmc5617DevEntry = {
    .moduleVersion = 1,
    .moduleName = "HDF_SENSOR_MAGNETIC_MMC5617",
    .Bind = Mmc5617BindDriver,
    .Init = Mmc5617InitDriver,
    .Release = Mmc5617ReleaseDriver,
};

HDF_INIT(g_magneticMmc5617DevEntry);
