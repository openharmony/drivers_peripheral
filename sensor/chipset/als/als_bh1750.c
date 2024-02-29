/*
 * Copyright (c) 2023 Nanjing Xiaoxiongpai Intelligent Technology Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#include "als_bh1750.h"
#include <securec.h>
#include "osal_mem.h"
#include "osal_time.h"
#include "sensor_als_driver.h"
#include "sensor_config_controller.h"
#include "sensor_device_manager.h"

#define HDF_LOG_TAG    hdf_sensor_als

static struct Bh1750DrvData *g_bh1750DrvData = NULL;

static struct Bh1750DrvData *Bh1750GetDrvData(void)
{
    return g_bh1750DrvData;
}

static int32_t ReadBh1750RawData(struct SensorCfgData *data, struct BH1750AlsData *rawData, uint64_t *timestamp)
{
    uint8_t reg[BH1750_TEMP_DATA_BUF_LEN] = { 0 };
    OsalTimespec time;
    int32_t ret = HDF_SUCCESS;
    uint8_t measureCmdValue[] = {BH1750_CONTINUOUS_H_RES_MODE};
    uint16_t tempValue;

    (void)memset_s(&time, sizeof(time), 0, sizeof(time));

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);

    if (OsalGetTime(&time) != HDF_SUCCESS) {
        HDF_LOGE("%s: Get time failed", __func__);
        return HDF_FAILURE;
    }
    *timestamp = time.sec * SENSOR_SECOND_CONVERT_NANOSECOND + time.usec * SENSOR_CONVERT_UNIT; /* unit nanosecond */

    ret = WriteSensor(&data->busCfg, measureCmdValue, sizeof(measureCmdValue));
    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "write data");

    OsalMDelay(BH1750_READ_VALUE_DELAY);

    ret = ReadSensor(&data->busCfg, NULL, reg, sizeof(reg));

    tempValue = reg[BH1750_TEMP_VALUE_IDX_ZERO];
    tempValue <<= SENSOR_DATA_WIDTH_8_BIT;
    tempValue |= reg[BH1750_TEMP_VALUE_IDX_ONE];

    CHECK_PARSER_RESULT_RETURN_VALUE(ret, "read data");

    rawData->als = (tempValue * BH1750_TEMP_CONSATNT_1) / BH1750_TEMP_CONSATNT_2;

    return HDF_SUCCESS;
}

static int32_t ReadBh1750Data(struct SensorCfgData *data)
{
    int32_t ret;
    static int32_t als;
    struct BH1750AlsData rawData = { 0 };
    struct SensorReportEvent event;

    (void)memset_s(&event, sizeof(event), 0, sizeof(event));
    ret = ReadBh1750RawData(data, &rawData, &event.timestamp);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: BH1750 read raw data failed", __func__);
        return HDF_FAILURE;
    }
    als = rawData.als;
    event.sensorId = SENSOR_TAG_AMBIENT_LIGHT;
    event.option = 0;
    event.mode = SENSOR_WORK_MODE_REALTIME;

    event.dataLen = sizeof(als);
    event.data = (uint8_t *)&als;

    ret = ReportSensorEvent(&event);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: BH1750 report data failed", __func__);
    }
    return ret;
}

static int32_t InitBh1750(struct SensorCfgData *data)
{
    int32_t ret;

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);
    ret = SetSensorRegCfgArray(&data->busCfg, data->regCfgGroup[SENSOR_INIT_GROUP]);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: BH1750 sensor init config failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t DispatchBH1750(struct HdfDeviceIoClient *client,
    int cmd, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    (void)client;
    (void)cmd;
    (void)data;
    (void)reply;

    return HDF_SUCCESS;
}

static int32_t Bh1750BindDriver(struct HdfDeviceObject *device)
{
    CHECK_NULL_PTR_RETURN_VALUE(device, HDF_ERR_INVALID_PARAM);

    struct Bh1750DrvData *drvData = (struct Bh1750DrvData *)OsalMemCalloc(sizeof(*drvData));
    if (drvData == NULL) {
        HDF_LOGE("%s: Malloc Bh1750 drv data fail", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    drvData->ioService.Dispatch = DispatchBH1750;
    drvData->device = device;
    device->service = &drvData->ioService;
    g_bh1750DrvData = drvData;

    return HDF_SUCCESS;
}

static int32_t Bh1750InitDriver(struct HdfDeviceObject *device)
{
    int32_t ret;
    struct AlsOpsCall ops;

    CHECK_NULL_PTR_RETURN_VALUE(device, HDF_ERR_INVALID_PARAM);
    struct Bh1750DrvData *drvData = (struct Bh1750DrvData *)device->service;
    CHECK_NULL_PTR_RETURN_VALUE(drvData, HDF_ERR_INVALID_PARAM);

    drvData->sensorCfg = AlsCreateCfgData(device->property);
    if (drvData->sensorCfg == NULL || drvData->sensorCfg->root == NULL) {
        HDF_LOGD("%s: Creating alscfg failed because detection failed", __func__);
        return HDF_ERR_NOT_SUPPORT;
    }

    ops.Init = NULL;
    ops.ReadData = ReadBh1750Data;
    ret = AlsRegisterChipOps(&ops);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Register BH1750 als failed", __func__);
        return HDF_FAILURE;
    }

    ret = InitBh1750(drvData->sensorCfg);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Init BH1750 als failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static void Bh1750ReleaseDriver(struct HdfDeviceObject *device)
{
    CHECK_NULL_PTR_RETURN(device);

    struct Bh1750DrvData *drvData = (struct Bh1750DrvData *)device->service;
    CHECK_NULL_PTR_RETURN(drvData);

    if (drvData->sensorCfg != NULL) {
        AlsReleaseCfgData(drvData->sensorCfg);
        drvData->sensorCfg = NULL;
    }
    OsalMemFree(drvData);
}

struct HdfDriverEntry g_alsBh1750DevEntry = {
    .moduleVersion = 1,
    .moduleName = "HDF_SENSOR_ALS_BH1750",
    .Bind = Bh1750BindDriver,
    .Init = Bh1750InitDriver,
    .Release = Bh1750ReleaseDriver,
};

HDF_INIT(g_alsBh1750DevEntry);
