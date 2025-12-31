/*
 * Copyright (c) 2021-2022 xu
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#include "proximity_mn7991x.h"
#include <securec.h>
#include "osal_mem.h"
#include "osal_time.h"
#include "sensor_config_controller.h"
#include "sensor_device_manager.h"
#include "sensor_proximity_driver.h"

#define HDF_LOG_TAG    khdf_sensor_proximity_driver

#define PROXIMITY_STATE_FAR    5
#define PROXIMITY_STATE_NEAR   0

#define PROXIMITY_REG_NUM    3

static struct Mn7991xDrvData *g_mn7991xDrvData = NULL;

static int32_t ReadMn7991xData(struct SensorCfgData *data)
{
    int32_t ret;
    struct ProximityData rawData = { 5 };
    uint8_t reg_value[10];
    struct SensorReportEvent event;
    OsalTimespec time;
    int32_t *tmp = (int32_t *)OsalMemCalloc(sizeof(int32_t));
    if (tmp == NULL) {
        return HDF_ERR_MALLOC_FAIL;
    }
    (void)memset_s(&event, sizeof(event), 0, sizeof(event));
    ret = ReadSensor(&data->busCfg, MN7991X_PROX_RAW_DATA_REG_L, reg_value, sizeof(reg_value));
    if (ret < 0) {
        HDF_LOGI("%s: light read data error!  1 ret = %d.", __func__, ret);
    }
    rawData.stateFlag = reg_value[PROXIMITY_REG_NUM];
    (void)memset_s(&time, sizeof(time), 0, sizeof(time));
    if (OsalGetTime(&time) != HDF_SUCCESS) {
        HDF_LOGE("%s: Get time failed", __func__);
        return HDF_FAILURE;
    }
    event.timestamp = time.sec * SENSOR_SECOND_CONVERT_NANOSECOND + time.usec * SENSOR_CONVERT_UNIT;
    event.sensorId = SENSOR_TAG_PROXIMITY;
    event.option = 0;
    event.mode = SENSOR_WORK_MODE_ON_CHANGE;

    if (rawData.stateFlag <= MN7991X_PROXIMITY_THRESHOLD) {
        *tmp = PROXIMITY_STATE_FAR;
    } else {
        *tmp = PROXIMITY_STATE_NEAR;
    }

    event.dataLen = sizeof(*tmp);
    event.data = (uint8_t *)tmp;
    ret = ReportSensorEvent(&event);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Mn7991x report data failed", __func__);
    }

    return ret;
}

static int32_t InitMn7991x(struct SensorCfgData *data)
{
    int32_t ret;

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);
    ret = SetSensorRegCfgArray(&data->busCfg, data->regCfgGroup[SENSOR_INIT_GROUP]);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Mn7991x sensor init config failed", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t DispatchMn7991x(struct HdfDeviceIoClient *client,
    int cmd, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    (void)client;
    (void)cmd;
    (void)data;
    (void)reply;

    return HDF_SUCCESS;
}

static int32_t Mn7991xBindDriver(struct HdfDeviceObject *device)
{
    CHECK_NULL_PTR_RETURN_VALUE(device, HDF_ERR_INVALID_PARAM);
    HDF_LOGI("%s: entry", __func__);

    struct Mn7991xDrvData *drvData = (struct Mn7991xDrvData *)OsalMemCalloc(sizeof(*drvData));
    if (drvData == NULL) {
        HDF_LOGE("%s: Malloc Mn7991x drv data fail", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    drvData->ioService.Dispatch = DispatchMn7991x;
    drvData->device = device;
    device->service = &drvData->ioService;
    g_mn7991xDrvData = drvData;

    return HDF_SUCCESS;
}

static int32_t Mn7991xInitDriver(struct HdfDeviceObject *device)
{
    int32_t ret;
    struct ProximityOpsCall ops;
    HDF_LOGI("%s: entry", __func__);

    CHECK_NULL_PTR_RETURN_VALUE(device, HDF_ERR_INVALID_PARAM);
    struct Mn7991xDrvData *drvData = (struct Mn7991xDrvData *)device->service;
    CHECK_NULL_PTR_RETURN_VALUE(drvData, HDF_ERR_INVALID_PARAM);

    drvData->sensorCfg = ProximityCreateCfgData(device->property);
    if (drvData->sensorCfg == NULL || drvData->sensorCfg->root == NULL) {
        HDF_LOGD("%s: Creating proximitycfg failed because detection failed", __func__);
        return HDF_ERR_NOT_SUPPORT;
    }

    ops.Init = NULL;
    ops.ReadData = ReadMn7991xData;
    ret = ProximityRegisterChipOps(&ops);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Register Mn7991x proximity failed", __func__);
        return HDF_FAILURE;
    }

    ret = InitMn7991x(drvData->sensorCfg);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Init Mn7991x proximity failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}


static void Mn7991xReleaseDriver(struct HdfDeviceObject *device)
{
    CHECK_NULL_PTR_RETURN(device);
    HDF_LOGI("%s: entry", __func__);
    struct Mn7991xDrvData *drvData = (struct Mn7991xDrvData *)device->service;
    CHECK_NULL_PTR_RETURN(drvData);

    if (drvData->sensorCfg != NULL) {
        ProximityReleaseCfgData(drvData->sensorCfg);
        drvData->sensorCfg = NULL;
    }
    OsalMemFree(drvData);
}

struct HdfDriverEntry g_proximityMn7991xDevEntry = {
    .moduleVersion = 1,
    .moduleName = "HDF_SENSOR_PROXIMITY_MN7991X",
    .Bind = Mn7991xBindDriver,
    .Init = Mn7991xInitDriver,
    .Release = Mn7991xReleaseDriver,
};

HDF_INIT(g_proximityMn7991xDevEntry);