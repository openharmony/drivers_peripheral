/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#include "als_stk33562.h"
#include <securec.h>
#include "osal_mem.h"
#include "osal_time.h"
#include "sensor_als_driver.h"
#include "sensor_config_controller.h"
#include "sensor_device_manager.h"

static struct Stk33562DrvData *g_stk33562DrvData = NULL;

static struct TimeRegAddrValueMap g_timeMap[EXTENDED_ALS_TIME_GROUP_INDEX_MAX] = {
    { EXTENDED_ALS_TIME_GROUP_ATTR_VALUE_0, STK33562_TIME_25MSEC },
    { EXTENDED_ALS_TIME_GROUP_ATTR_VALUE_1, STK33562_TIME_50MSEC },
    { EXTENDED_ALS_TIME_GROUP_ATTR_VALUE_2, STK33562_TIME_100MSEC },
    { EXTENDED_ALS_TIME_GROUP_ATTR_VALUE_3, STK33562_TIME_200MSEC },
    { EXTENDED_ALS_TIME_GROUP_ATTR_VALUE_4, STK33562_TIME_400MSEC },
    { EXTENDED_ALS_TIME_GROUP_ATTR_VALUE_5, STK33562_TIME_800MSEC },
    { EXTENDED_ALS_TIME_GROUP_ATTR_VALUE_6, STK33562_TIME_1600MSEC },
};

static struct GainRegAddrValueMap g_gainMap[EXTENDED_ALS_GAIN_GROUP_INDEX_MAX] = {
    { EXTENDED_ALS_GAIN_GROUP_ATTR_VALUE_0, STK33562_GAIN_1X },
    { EXTENDED_ALS_GAIN_GROUP_ATTR_VALUE_1, STK33562_GAIN_4X },
    { EXTENDED_ALS_GAIN_GROUP_ATTR_VALUE_2, STK33562_GAIN_16X },
    { EXTENDED_ALS_GAIN_GROUP_ATTR_VALUE_3, STK33562_GAIN_64X },
};

/* 放大100000倍后的Lux/LSB映射表（所有系数四舍五入） */
static AlsLuxLsbMap g_stk33562LuxLsbMap[] = {
    /* time 25ms */
    { STK33562_TIME_25MSEC, STK33562_GAIN_1X, 25000 },
    { STK33562_TIME_25MSEC, STK33562_GAIN_4X, 6250 },
    { STK33562_TIME_25MSEC, STK33562_GAIN_16X, 1562 },
    { STK33562_TIME_25MSEC, STK33562_GAIN_64X, 388 },
    /* time 50ms */
    { STK33562_TIME_50MSEC, STK33562_GAIN_1X, 12500 },
    { STK33562_TIME_50MSEC, STK33562_GAIN_4X, 3125 },
    { STK33562_TIME_50MSEC, STK33562_GAIN_16X, 781 },
    { STK33562_TIME_50MSEC, STK33562_GAIN_64X, 194 },

    /* time 100ms */
    { STK33562_TIME_100MSEC, STK33562_GAIN_1X, 6250 },
    { STK33562_TIME_100MSEC, STK33562_GAIN_4X, 1548 },
    { STK33562_TIME_100MSEC, STK33562_GAIN_16X, 386 },
    { STK33562_TIME_100MSEC, STK33562_GAIN_64X, 97 },

    /* time 200ms */
    { STK33562_TIME_200MSEC, STK33562_GAIN_1X, 3125 },
    { STK33562_TIME_200MSEC, STK33562_GAIN_4X, 774 },
    { STK33562_TIME_200MSEC, STK33562_GAIN_16X, 193 },
    { STK33562_TIME_200MSEC, STK33562_GAIN_64X, 49 },

    /* time 400ms */
    { STK33562_TIME_400MSEC, STK33562_GAIN_1X, 1562 },
    { STK33562_TIME_400MSEC, STK33562_GAIN_4X, 387 },
    { STK33562_TIME_400MSEC, STK33562_GAIN_16X, 96 },
    { STK33562_TIME_400MSEC, STK33562_GAIN_64X, 24 },

    /* time 800ms */
    { STK33562_TIME_800MSEC, STK33562_GAIN_1X, 781 },
    { STK33562_TIME_800MSEC, STK33562_GAIN_4X, 193 },
    { STK33562_TIME_800MSEC, STK33562_GAIN_16X, 48 },
    { STK33562_TIME_800MSEC, STK33562_GAIN_64X, 12 },

    /* time 1600ms */
    { STK33562_TIME_1600MSEC, STK33562_GAIN_1X, 391 },
    { STK33562_TIME_1600MSEC, STK33562_GAIN_4X, 97 },
    { STK33562_TIME_1600MSEC, STK33562_GAIN_16X, 24 },
    { STK33562_TIME_1600MSEC, STK33562_GAIN_64X, 7 },
};

static uint8_t g_stk33562LuxLsbMapSize = sizeof(g_stk33562LuxLsbMap) / sizeof(g_stk33562LuxLsbMap[0]);

/* this function is used to get the Lux/LSB by time and gain */
static uint32_t GetLuxLsbByTimeGain(uint32_t time, uint32_t gain, const AlsLuxLsbMap *map, const uint8_t mapSize)
{
    uint8_t i;
    for (i = 0; i < mapSize; i++) {
        if (map[i].time == time && map[i].gain == gain) {
            return map[i].luxLsb;
        }
    }
    HDF_LOGE("%s: No matching Lux/LSB (time=%d, gain=%d)", __func__, time, gain);
    return -1;
}
static int32_t CalLux(struct SensorCfgData *CfgData, struct AlsReportData *reportData, uint32_t *rawData)
{
    int32_t ret;
    uint32_t time;
    uint32_t gain;
    uint8_t regValue;
    uint32_t index = 1;
    uint32_t luxTemp;
    uint8_t itemNum;
    uint32_t luxLsb;
    struct SensorRegCfgGroupNode *groupNode = NULL;
    int32_t timeIndex = EXTENDED_ALS_TIME_GROUP_INDEX_2;
    int32_t gainIndex = EXTENDED_ALS_GAIN_GROUP_INDEX_0;

    if (rawData[ALS_STK33562_DATA] <= 0) {
        HDF_LOGE("%s: Als Data is NULL!", __func__);
        return HDF_FAILURE;
    }

    luxTemp = rawData[ALS_STK33562_DATA];
    groupNode = CfgData->extendedRegCfgGroup[EXTENDED_ALS_TIME_GROUP];
    itemNum = groupNode->itemNum;
    if (itemNum > EXTENDED_ALS_TIME_GROUP_INDEX_MAX) {
        HDF_LOGE("%s: ItemNum out of range", __func__);
        return HDF_FAILURE;
    }

    ret = ReadSensorRegCfgArray(&CfgData->busCfg, groupNode, timeIndex, &regValue, sizeof(regValue));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Failed to read sensor register array", __func__);
        return HDF_FAILURE;
    }
    regValue &= groupNode->regCfgItem->mask;
    time = GetTimeByRegValue(regValue, g_timeMap, itemNum);

    regValue = 0;
    groupNode = CfgData->extendedRegCfgGroup[EXTENDED_ALS_GAIN_GROUP];
    itemNum = groupNode->itemNum;

    ret = ReadSensorRegCfgArray(&CfgData->busCfg, groupNode, gainIndex, &regValue, sizeof(regValue));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Failed to read sensor register array ", __func__);
        return HDF_FAILURE;
    }
    regValue &= groupNode->regCfgItem->mask;
    gain = GetGainByRegValue(regValue, g_gainMap, itemNum);

    luxLsb = GetLuxLsbByTimeGain(time, gain, g_stk33562LuxLsbMap, g_stk33562LuxLsbMapSize);
    if (luxLsb < 0) {
        reportData->als = 0;
        return HDF_FAILURE;
    }

    /* unit of reportData->als is Mxl. gain needs to be reduced by 10000 to get the correct Lux value */
    reportData->als = (uint32_t)(luxTemp * luxLsb / STK33562_ALS_LUX_LSB_SCALE * STK33562_ALS_MXL_SCALE);
    return HDF_SUCCESS;
}

static int32_t RawDataConvert(struct SensorCfgData *CfgData, struct AlsReportData *reportData, uint32_t *rawData)
{
    int ret;

    ret = CalLux(CfgData, reportData, rawData);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Failed to calculate sensor brightness", __func__);
        return HDF_FAILURE;
    }

    reportData->als = (reportData->als > 0) ? reportData->als : 0;
    return HDF_SUCCESS;
}

static int32_t ReadStk33562RawData(struct SensorCfgData *data, struct Stk33562AlsData *rawData, uint64_t *timestamp)
{
    uint8_t status = 0;
    uint8_t reg[ALS_STK33562_BUF];
    OsalTimespec time;

    (void)memset_s(&time, sizeof(time), 0, sizeof(time));
    (void)memset_s(reg, sizeof(reg), 0, sizeof(reg));

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);

    if (OsalGetTime(&time) != HDF_SUCCESS) {
        HDF_LOGE("%s: Get time failed", __func__);
        return HDF_FAILURE;
    }
    *timestamp = time.sec * SENSOR_SECOND_CONVERT_NANOSECOND + time.usec * SENSOR_CONVERT_UNIT; /* unit nanosecond */
    int32_t ret;

    ret = ReadSensor(&data->busCfg, STK33562_ALS_D_LSB_ADDR, &reg[ALS_STK33562_D_LSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    ret = ReadSensor(&data->busCfg, STK33562_ALS_D_MSB_ADDR, &reg[ALS_STK33562_D_MSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    ret = ReadSensor(&data->busCfg, STK33562_ALS_C_LSB_ADDR, &reg[ALS_STK33562_C_LSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    ret = ReadSensor(&data->busCfg, STK33562_ALS_C_MSB_ADDR, &reg[ALS_STK33562_C_MSB], sizeof(uint8_t));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    rawData->als = (uint16_t)(SENSOR_DATA_SHIFT_LEFT(reg[ALS_STK33562_D_MSB], SENSOR_DATA_WIDTH_8_BIT) |
        reg[ALS_STK33562_D_LSB]);
    rawData->clear = (uint16_t)(SENSOR_DATA_SHIFT_LEFT(reg[ALS_STK33562_C_MSB], SENSOR_DATA_WIDTH_8_BIT) |
        reg[ALS_STK33562_C_LSB]);

    return HDF_SUCCESS;
}

static int32_t ReadStk33562Data(struct SensorCfgData *data, struct SensorReportEvent *event)
{
    int32_t ret;
    struct Stk33562AlsData rawData = { 0, 0 };
    int32_t tmp[ALS_STK33562_NUM];
    static struct AlsReportData reportData = { 0, 0 };

    ret = ReadStk33562RawData(data, &rawData, &event->timestamp);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: STK33562 read raw data failed", __func__);
        return HDF_FAILURE;
    }

    event->sensorId = SENSOR_TAG_AMBIENT_LIGHT;
    event->option = 0;
    event->mode = SENSOR_WORK_MODE_REALTIME;

    tmp[ALS_STK33562_DATA] = rawData.als;
    tmp[ALS_STK33562_CLEAR] = rawData.clear;

    ret = RawDataConvert(data, &reportData, tmp);
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "RawDataConvert");
    event->dataLen = sizeof(reportData.als);
    event->data = (uint8_t *)&reportData.als;

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
        HDF_LOGE("%s: Malloc Stk33562 drv data fail", __func__);
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
    int32_t ret;
    struct AlsOpsCall ops;

    CHECK_NULL_PTR_RETURN_VALUE(device, HDF_ERR_INVALID_PARAM);
    struct Stk33562DrvData *drvData = (struct Stk33562DrvData *)device->service;
    CHECK_NULL_PTR_RETURN_VALUE(drvData, HDF_ERR_INVALID_PARAM);

    drvData->sensorCfg = AlsCreateCfgData(device->property);
    if (drvData->sensorCfg == NULL || drvData->sensorCfg->root == NULL) {
        HDF_LOGD("%s: Creating alscfg failed because detection failed", __func__);
        return HDF_ERR_NOT_SUPPORT;
    }

    ops.Init = NULL;
    ops.ReadData = ReadStk33562Data;
    ret = AlsRegisterChipOps(&ops);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Register Stk33562 als failed", __func__);
        return HDF_FAILURE;
    }

    ret = InitStk33562(drvData->sensorCfg);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Init Stk33562 als failed", __func__);
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
        AlsReleaseCfgData(drvData->sensorCfg);
        drvData->sensorCfg = NULL;
    }
    OsalMemFree(drvData);
}

struct HdfDriverEntry g_alsStk33562DevEntry = {
    .moduleVersion = 1,
    .moduleName = "HDF_SENSOR_ALS_STK33562",
    .Bind = Stk33562BindDriver,
    .Init = Stk33562InitDriver,
    .Release = Stk33562ReleaseDriver,
};

HDF_INIT(g_alsStk33562DevEntry);
