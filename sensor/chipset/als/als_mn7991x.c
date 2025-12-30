/*
 * Copyright (c) 2023 Nanjing Xiaoxiongpai Intelligent Technology Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#include "als_mn7991x.h"
#include <securec.h>
#include "osal_mem.h"
#include "osal_time.h"
#include "sensor_als_driver.h"
#include "sensor_config_controller.h"
#include "sensor_device_manager.h"

#define HDF_LOG_TAG    hdf_sensor_als

#define SHIFT_8BIT 8
#define REG_BYTE_OFFSET_0    0
#define REG_BYTE_OFFSET_1    1
#define REG_BYTE_OFFSET_2    2
#define REG_BYTE_OFFSET_3    3

static struct Mn7991xDrvData *g_mn7991xDrvData = NULL;

static int32_t ReadMn7991xData(struct SensorCfgData *data, struct SensorReportEvent *event)
{
    int32_t ret;
    OsalTimespec time;
    uint8_t reg_value[4];
    uint16_t als = 0;
    uint16_t ir = 0;
    struct AlsReportData *reportData = NULL;

    reportData = (struct AlsReportData *)OsalMemCalloc(sizeof(struct AlsReportData));
    if (reportData == NULL) {
        HDF_LOGE("%s: Malloc Mn7991x reportData fail", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    ret = ReadSensor(&data->busCfg, DEVREG_IR_DATAL, reg_value, sizeof(reg_value));
    if (ret < 0) {
        HDF_LOGE("%s: light read data error!  1 ret = %d.", __func__, ret);
        return HDF_FAILURE;
    }

    ir = ((reg_value[REG_BYTE_OFFSET_1] << SHIFT_8BIT) | (reg_value[REG_BYTE_OFFSET_0]));
    als = ((reg_value[REG_BYTE_OFFSET_3] << SHIFT_8BIT) | (reg_value[REG_BYTE_OFFSET_2]));

    (void)memset_s(&time, sizeof(time), 0, sizeof(time));
    if (OsalGetTime(&time) != HDF_SUCCESS) {
        HDF_LOGE("%s: Get time failed", __func__);
        return HDF_FAILURE;
    }
    event->timestamp = time.sec * SENSOR_SECOND_CONVERT_NANOSECOND + time.usec * SENSOR_CONVERT_UNIT;
    event->sensorId = SENSOR_TAG_AMBIENT_LIGHT;
    event->option = 0;
    event->mode = SENSOR_WORK_MODE_REALTIME;

    reportData->als = als * SENSOR_CONVERT_UNIT;
    event->dataLen = sizeof(*reportData);
    event->data = (uint8_t *)reportData;

    return ret;
}


static int32_t InitMn7991x(struct SensorCfgData *data)
{
    int32_t ret;

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);
    ret = SetSensorRegCfgArray(&data->busCfg, data->regCfgGroup[SENSOR_INIT_GROUP]);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: MN7991X sensor init config failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t DispatchMNX(struct HdfDeviceIoClient *client,
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

    struct Mn7991xDrvData *drvData = (struct Mn7991xDrvData *)OsalMemCalloc(sizeof(*drvData));
    if (drvData == NULL) {
        HDF_LOGE("%s: Malloc Mn7991x drv data fail", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    drvData->ioService.Dispatch = DispatchMNX;
    drvData->device = device;
    device->service = &drvData->ioService;
    g_mn7991xDrvData = drvData;

    return HDF_SUCCESS;
}

static int32_t Mn7991xInitDriver(struct HdfDeviceObject *device)
{
    int32_t ret;
    struct AlsOpsCall ops;

    CHECK_NULL_PTR_RETURN_VALUE(device, HDF_ERR_INVALID_PARAM);
    struct Mn7991xDrvData *drvData = (struct Mn7991xDrvData *)device->service;
    CHECK_NULL_PTR_RETURN_VALUE(drvData, HDF_ERR_INVALID_PARAM);

    drvData->sensorCfg = AlsCreateCfgData(device->property);
    if (drvData->sensorCfg == NULL || drvData->sensorCfg->root == NULL) {
        HDF_LOGD("%s: Creating alscfg failed because detection failed", __func__);
        return HDF_ERR_NOT_SUPPORT;
    }

    ops.Init = NULL;
    ops.ReadData = ReadMn7991xData;
    ret = AlsRegisterChipOps(&ops);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Register MN7991X als failed", __func__);
        return HDF_FAILURE;
    }

    ret = InitMn7991x(drvData->sensorCfg);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Init MN7991X als failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static void Mn7991xReleaseDriver(struct HdfDeviceObject *device)
{
    CHECK_NULL_PTR_RETURN(device);

    struct Mn7991xDrvData *drvData = (struct Mn7991xDrvData *)device->service;
    CHECK_NULL_PTR_RETURN(drvData);

    if (drvData->sensorCfg != NULL) {
        AlsReleaseCfgData(drvData->sensorCfg);
        drvData->sensorCfg = NULL;
    }
    OsalMemFree(drvData);
}

struct HdfDriverEntry g_alsMn7991xDevEntry = {
    .moduleVersion = 1,
    .moduleName = "HDF_SENSOR_ALS_MN7991X",
    .Bind = Mn7991xBindDriver,
    .Init = Mn7991xInitDriver,
    .Release = Mn7991xReleaseDriver,
};

HDF_INIT(g_alsMn7991xDevEntry);
