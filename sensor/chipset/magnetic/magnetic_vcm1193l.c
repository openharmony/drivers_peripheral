/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#include "magnetic_vcm1193l.h"
#include <securec.h>
#include "osal_mem.h"
#include "osal_time.h"
#include "sensor_config_controller.h"
#include "sensor_device_manager.h"
#include "sensor_magnetic_driver.h"

#define HDF_LOG_TAG khdf_sensor_magnetic_driver

static struct Vcm1193lDrvData *g_vcm1193lDrvData = NULL;

static int32_t ReadVcm1193lRawData(struct SensorCfgData *data, struct MagneticData *rawData, uint64_t *timestamp)
{
    uint8_t reg[MAGNETIC_AXIS_BUTT];
    OsalTimespec time;

    (void)memset_s(&time, sizeof(time), 0, sizeof(time));
    (void)memset_s(reg, sizeof(reg), 0, sizeof(reg));

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);

    if (OsalGetTime(&time) != HDF_SUCCESS) {
        HDF_LOGE("%s: Get time failed", __func__);
        return HDF_FAILURE;
    }
    *timestamp = time.sec * SENSOR_SECOND_CONVERT_NANOSECOND + time.usec * SENSOR_CONVERT_UNIT; /* unit nanosecond */
    int32_t ret = -1;

    ret = ReadSensor(&data->busCfg, VCM1193L_MAGNETIC_X_MSB_ADDR, &reg[MAGNETIC_X_AXIS_MSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    ret = ReadSensor(&data->busCfg, VCM1193L_MAGNETIC_X_LSB_ADDR, &reg[MAGNETIC_X_AXIS_LSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    ret = ReadSensor(&data->busCfg, VCM1193L_MAGNETIC_Y_MSB_ADDR, &reg[MAGNETIC_Y_AXIS_MSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    ret = ReadSensor(&data->busCfg, VCM1193L_MAGNETIC_Y_LSB_ADDR, &reg[MAGNETIC_Y_AXIS_LSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    ret = ReadSensor(&data->busCfg, VCM1193L_MAGNETIC_Z_MSB_ADDR, &reg[MAGNETIC_Z_AXIS_MSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    ret = ReadSensor(&data->busCfg, VCM1193L_MAGNETIC_Z_LSB_ADDR, &reg[MAGNETIC_Z_AXIS_LSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    rawData->x = (int16_t)(SENSOR_DATA_SHIFT_LEFT(reg[MAGNETIC_X_AXIS_MSB], SENSOR_DATA_WIDTH_8_BIT) |
        reg[MAGNETIC_X_AXIS_LSB]);
    rawData->y = (int16_t)(SENSOR_DATA_SHIFT_LEFT(reg[MAGNETIC_Y_AXIS_MSB], SENSOR_DATA_WIDTH_8_BIT) |
        reg[MAGNETIC_Y_AXIS_LSB]);
    rawData->z = (int16_t)(SENSOR_DATA_SHIFT_LEFT(reg[MAGNETIC_Z_AXIS_MSB], SENSOR_DATA_WIDTH_8_BIT) |
        reg[MAGNETIC_Z_AXIS_LSB]);

    return HDF_SUCCESS;
}

static int32_t ReadVcm1193lData(struct SensorCfgData *data)
{
    struct MagneticData rawData = { 0, 0, 0 };
    int32_t tmp[MAGNETIC_AXIS_NUM];
    struct SensorReportEvent event;

    (void)memset_s(&event, sizeof(event), 0, sizeof(event));
    (void)memset_s(tmp, sizeof(tmp), 0, sizeof(tmp));

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);

    int32_t ret = ReadVcm1193lRawData(data, &rawData, &event.timestamp);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Vcm1193l read raw data failed", __func__);
        return HDF_FAILURE;
    }

    event.sensorId = SENSOR_TAG_MAGNETIC_FIELD;
    event.option = 0;
    event.mode = SENSOR_WORK_MODE_REALTIME;

    tmp[MAGNETIC_X_AXIS] = rawData.x / VCM1193L_MAGNETIC_SENSITIVITY_8G * VCM1193L_MAGNETIC_UT_TO_NT;
    tmp[MAGNETIC_Y_AXIS] = rawData.y / VCM1193L_MAGNETIC_SENSITIVITY_8G * VCM1193L_MAGNETIC_UT_TO_NT;
    tmp[MAGNETIC_Z_AXIS] = rawData.z / VCM1193L_MAGNETIC_SENSITIVITY_8G * VCM1193L_MAGNETIC_UT_TO_NT; /* nT */

    ret = SensorRawDataToRemapData(data->direction, tmp, sizeof(tmp) / sizeof(tmp[0]));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Vcm1193l convert raw data failed", __func__);
        return HDF_FAILURE;
    }

    event.dataLen = sizeof(tmp);
    event.data = (uint8_t *)&tmp;
    ret = ReportSensorEvent(&event);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Vcm1193l report data failed", __func__);
    }

    return ret;
}

static int32_t InitVcm1193l(struct SensorCfgData *data)
{
    int32_t ret;

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);

    ret = SetSensorRegCfgArray(&data->busCfg, data->regCfgGroup[SENSOR_INIT_GROUP]);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Vcm1193l sensor init config failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t DispatchVcm1193l(struct HdfDeviceIoClient *client,
    int cmd, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    (void)client;
    (void)cmd;
    (void)data;
    (void)reply;

    return HDF_SUCCESS;
}

static int32_t Vcm1193lBindDriver(struct HdfDeviceObject *device)
{
    CHECK_NULL_PTR_RETURN_VALUE(device, HDF_ERR_INVALID_PARAM);

    struct Vcm1193lDrvData *drvData = (struct Vcm1193lDrvData *)OsalMemCalloc(sizeof(*drvData));
    if (drvData == NULL) {
        HDF_LOGE("%s: Malloc Vcm1193l drv data fail", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    drvData->ioService.Dispatch = DispatchVcm1193l;
    drvData->device = device;
    device->service = &drvData->ioService;
    g_vcm1193lDrvData = drvData;

    return HDF_SUCCESS;
}

static int32_t Vcm1193lInitDriver(struct HdfDeviceObject *device)
{
    int32_t ret;
    struct MagneticOpsCall ops;

    CHECK_NULL_PTR_RETURN_VALUE(device, HDF_ERR_INVALID_PARAM);
    struct Vcm1193lDrvData *drvData = (struct Vcm1193lDrvData *)device->service;
    CHECK_NULL_PTR_RETURN_VALUE(drvData, HDF_ERR_INVALID_PARAM);

    drvData->sensorCfg = MagneticCreateCfgData(device->property);
    if (drvData->sensorCfg == NULL || drvData->sensorCfg->root == NULL) {
        HDF_LOGD("%s: Creating magneticcfg failed because detection failed", __func__);
        return HDF_ERR_NOT_SUPPORT;
    }

    ops.Init = NULL;
    ops.ReadData = ReadVcm1193lData;
    ret = MagneticRegisterChipOps(&ops);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Register vcm1193l magnetic failed", __func__);
        return HDF_FAILURE;
    }

    ret = InitVcm1193l(drvData->sensorCfg);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Init vcm1193l magnetic failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static void Vcm1193lReleaseDriver(struct HdfDeviceObject *device)
{
    CHECK_NULL_PTR_RETURN(device);

    struct Vcm1193lDrvData *drvData = (struct Vcm1193lDrvData *)device->service;
    CHECK_NULL_PTR_RETURN(drvData);

    if (drvData->sensorCfg != NULL) {
        MagneticReleaseCfgData(drvData->sensorCfg);
        drvData->sensorCfg = NULL;
    }
    OsalMemFree(drvData);
}

struct HdfDriverEntry g_magneticVcm1193lDevEntry = {
    .moduleVersion = 1,
    .moduleName = "HDF_SENSOR_MAGNETIC_VCM1193L",
    .Bind = Vcm1193lBindDriver,
    .Init = Vcm1193lInitDriver,
    .Release = Vcm1193lReleaseDriver,
};

HDF_INIT(g_magneticVcm1193lDevEntry);
