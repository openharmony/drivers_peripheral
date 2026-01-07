/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#include "proximity_stk33562.h"
#include <securec.h>
#include "osal_mem.h"
#include "osal_time.h"
#include "sensor_config_controller.h"
#include "sensor_device_manager.h"
#include "sensor_proximity_driver.h"

#define HDF_LOG_TAG khdf_sensor_proximity_driver

#define PROXIMITY_STATE_FAR    5
#define PROXIMITY_STATE_NEAR   0

static struct Stk33562DrvData *g_stk33562DrvData = NULL;

static int32_t ReadStk33562RawData(struct SensorCfgData *data, struct ProximityData *rawData, uint64_t *timestamp)
{
    OsalTimespec time;

    (void)memset_s(&time, sizeof(time), 0, sizeof(time));
    int32_t ret = -1;
    uint8_t reg[STK33562_PROX_ADDR_NUM];

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);

    if (OsalGetTime(&time) != HDF_SUCCESS) {
        HDF_LOGE("%s: Get time failed", __func__);
        return HDF_FAILURE;
    }
    *timestamp = time.sec * SENSOR_SECOND_CONVERT_NANOSECOND + time.usec * SENSOR_CONVERT_UNIT; /* unit nanosecond */

    ret = ReadSensor(&data->busCfg, STK33562_PROX_MSB_ADDR, &reg[STK33562_PROX_ADDR_MSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");
    ret = ReadSensor(&data->busCfg, STK33562_PROX_LSB_ADDR, &reg[STK33562_PROX_ADDR_LSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");
    rawData->stateFlag = (int16_t)(SENSOR_DATA_SHIFT_LEFT(reg[STK33562_PROX_ADDR_MSB], SENSOR_DATA_WIDTH_8_BIT) |
        reg[STK33562_PROX_ADDR_LSB]);
    return ret;
}

static int32_t ReadStk33562Data(struct SensorCfgData *data)
{
    int32_t ret;
    int32_t tmp;
    struct ProximityData rawData = { 5 };
    struct SensorReportEvent event;

    (void)memset_s(&event, sizeof(event), 0, sizeof(event));

    ret = ReadStk33562RawData(data, &rawData, &event.timestamp);
    if (ret != HDF_SUCCESS) {
        return HDF_FAILURE;
    }

    event.sensorId = SENSOR_TAG_PROXIMITY;
    event.option = 0;
    event.mode = SENSOR_WORK_MODE_ON_CHANGE;
    if (rawData.stateFlag <= STK33562_PROX_THRESH_FAR) {
        tmp = PROXIMITY_STATE_FAR;
    } else if (rawData.stateFlag >= STK33562_PROX_THRESH_NEAR) {
        tmp = PROXIMITY_STATE_NEAR;
    }

    event.dataLen = sizeof(tmp);
    event.data = (uint8_t *)&tmp;
    ret = ReportSensorEvent(&event);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: STK33562 report data failed", __func__);
    }

    return ret;
}

static int32_t InitStk33562(struct SensorCfgData *data)
{
    int32_t ret;

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);
    ret = SetSensorRegCfgArray(&data->busCfg, data->regCfgGroup[SENSOR_INIT_GROUP]);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: STK33562 sensor init config failed", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
static int32_t DispatchStk33562(struct HdfDeviceIoClient *client,
    int cmd, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    (void)client;
    (void)cmd;
    (void)data;
    (void)reply;

    return HDF_SUCCESS;
}

static int32_t Stk33562BindDriver(struct HdfDeviceObject *device)
{
    CHECK_NULL_PTR_RETURN_VALUE(device, HDF_ERR_INVALID_PARAM);

    struct Stk33562DrvData *drvData = (struct Stk33562DrvData *)OsalMemCalloc(sizeof(*drvData));
    if (drvData == NULL) {
        HDF_LOGE("%s: Malloc STK33562 drv data fail", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    drvData->ioService.Dispatch = DispatchStk33562;
    drvData->device = device;
    device->service = &drvData->ioService;
    g_stk33562DrvData = drvData;

    return HDF_SUCCESS;
}

static int32_t Stk33562InitDriver(struct HdfDeviceObject *device)
{
    int32_t ret = -1;
    struct ProximityOpsCall ops;

    CHECK_NULL_PTR_RETURN_VALUE(device, HDF_ERR_INVALID_PARAM);
    struct Stk33562DrvData *drvData = (struct Stk33562DrvData *)device->service;
    CHECK_NULL_PTR_RETURN_VALUE(drvData, HDF_ERR_INVALID_PARAM);

    drvData->sensorCfg = ProximityCreateCfgData(device->property);
    if (drvData->sensorCfg == NULL || drvData->sensorCfg->root == NULL) {
        HDF_LOGD("%s: Creating proximitycfg failed because detection failed", __func__);
        return HDF_ERR_NOT_SUPPORT;
    }

    ops.Init = NULL;
    ops.ReadData = ReadStk33562Data;
    ret = ProximityRegisterChipOps(&ops);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Register STK33562 proximity failed", __func__);
        return HDF_FAILURE;
    }

    ret = InitStk33562(drvData->sensorCfg);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Init STK33562 proximity failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static void Stk33562ReleaseDriver(struct HdfDeviceObject *device)
{
    CHECK_NULL_PTR_RETURN(device);

    struct Stk33562DrvData *drvData = (struct Stk33562DrvData *)device->service;
    CHECK_NULL_PTR_RETURN(drvData);

    if (drvData->sensorCfg != NULL) {
        ProximityReleaseCfgData(drvData->sensorCfg);
        drvData->sensorCfg = NULL;
    }
    OsalMemFree(drvData);
}

struct HdfDriverEntry g_proximityStk33562DevEntry = {
    .moduleVersion = 1,
    .moduleName = "HDF_SENSOR_PROXIMITY_STK33562",
    .Bind = Stk33562BindDriver,
    .Init = Stk33562InitDriver,
    .Release = Stk33562ReleaseDriver,
};

HDF_INIT(g_proximityStk33562DevEntry);
