/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 *
 * HDF is dual licensed: you can use it either under the terms of
 * the GPL, or the BSD license, at your option.
 * See the LICENSE file in the root of this repository for complete details.
 */

#include "accel_mic6200.h"
#include <securec.h>
#include "osal_mem.h"
#include "osal_time.h"
#include "sensor_accel_driver.h"
#include "sensor_config_controller.h"
#include "sensor_device_manager.h"

#define HDF_LOG_TAG    khdf_sensor_accel_driver
#define MIC6200_RANGE    16384
#define MIC6200_PRECISION    16
#define MIC6200_BOUNDARY    (0x1 << (MIC6200_PRECISION - 1))
#define MIC6200_GRAVITY_STEP    (MIC6200_RANGE / MIC6200_BOUNDARY)
#define MIC6200_MASK    0xffff
#define MIC6200_ACCEL_OUTPUT_16BIT    16
#define MIC6200_ACCEL_MSB      8

// MIC6200 Register Definitions
#define MIC6200_PAGE_SEL_ADDR        0xFF
#define MIC6200_PWR_MGMT_ADDR        0x40
#define MIC6200_CTRL_REG1_ADDR       0x41
#define MIC6200_CTRL_REG2_ADDR       0x42
#define MIC6200_CTRL_REG3_ADDR       0x43
#define MIC6200_CTRL_REG4_ADDR       0x44
#define MIC6200_CTRL_REG5_ADDR       0x45
#define MIC6200_CTRL_REG6_ADDR       0x46
#define MIC6200_CTRL_REG7_ADDR       0x47
#define MIC6200_CTRL_REG8_ADDR       0x48
#define MIC6200_FIFO_CTRL_ADDR       0x20
#define MIC6200_INT_CTRL_ADDR        0x16

// MIC6200 Register Values
#define MIC6200_PWR_ENABLE           0x33
#define MIC6200_PWR_DISABLE          0x11
#define MIC6200_ODR_125HZ_RANGE_8G   0x06
#define MIC6200_DISABLE_FIFO         0x00
#define MIC6200_DISABLE_INTERRUPTS   0x00

#define SHIFT_8BIT 8
#define MIC6200_REG_BYTE_OFFSET_0    0
#define MIC6200_REG_BYTE_OFFSET_1    1
#define MIC6200_REG_BYTE_OFFSET_2    2
#define MIC6200_REG_BYTE_OFFSET_3    3
#define MIC6200_REG_BYTE_OFFSET_4    4
#define MIC6200_REG_BYTE_OFFSET_5    5

static struct Mic6200DrvData *g_mic6200DrvData = NULL;

static struct Mic6200DrvData *Mic6200GetDrvData(void)
{
    return g_mic6200DrvData;
}

static int SensorConvertData(char highByte, char lowByte)
{
    int16_t result;

    result = ((uint16_t)highByte << MIC6200_ACCEL_MSB) | (uint8_t)lowByte;

    return (int)result;
}

static int32_t ReadMic6200RawData(struct SensorCfgData *data, struct AccelData *rawData, uint64_t *timestamp)
{
    uint8_t reg[ACCEL_AXIS_BUTT]; // 2 bytes per axis
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

    // Read 6 bytes starting from 0x0E (acceleration data registers)
    int32_t ret = ReadSensor(&data->busCfg, MIC6200_ACCEL_X_LSB_ADDR, reg, sizeof(reg));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: read data failed, ret [%d]", __func__, ret);
        return HDF_FAILURE;
    }

    x = reg[MIC6200_REG_BYTE_OFFSET_0] | (reg[MIC6200_REG_BYTE_OFFSET_1] << SHIFT_8BIT);
    y = reg[MIC6200_REG_BYTE_OFFSET_2] | (reg[MIC6200_REG_BYTE_OFFSET_3] << SHIFT_8BIT);
    z = reg[MIC6200_REG_BYTE_OFFSET_4] | (reg[MIC6200_REG_BYTE_OFFSET_5] << SHIFT_8BIT);
    rawData->x = (int32_t)x;
    rawData->y = (int32_t)y;
    rawData->z = (int32_t)z;

    return HDF_SUCCESS;
}

static int32_t ReadMic6200Data(struct SensorCfgData *cfg, struct SensorReportEvent *event)
{
    int32_t ret;
    struct AccelData rawData = { 0, 0, 0 };
    static int32_t tmp[ACCEL_AXIS_NUM];
    static uint32_t readCount = 0;

    CHECK_NULL_PTR_RETURN_VALUE(cfg, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(event, HDF_ERR_INVALID_PARAM);

    ret = ReadMic6200RawData(cfg, &rawData, &event->timestamp);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: MIC6200 read raw data failed", __func__);
        return HDF_FAILURE;
    }

    event->sensorId = SENSOR_TAG_ACCELEROMETER;
    event->option = 0;
    event->mode = SENSOR_WORK_MODE_REALTIME;

    rawData.x = (rawData.x * MIC6200_ACC_SENSITIVITY_8G_NUM) / MIC6200_ACC_SENSITIVITY_8G_DEN;
    rawData.y = (rawData.y * MIC6200_ACC_SENSITIVITY_8G_NUM) / MIC6200_ACC_SENSITIVITY_8G_DEN;
    rawData.z = (rawData.z * MIC6200_ACC_SENSITIVITY_8G_NUM) / MIC6200_ACC_SENSITIVITY_8G_DEN;

    tmp[ACCEL_X_AXIS] = (rawData.x * SENSOR_CONVERT_UNIT) / SENSOR_CONVERT_UNIT;
    tmp[ACCEL_Y_AXIS] = (rawData.y * SENSOR_CONVERT_UNIT) / SENSOR_CONVERT_UNIT;
    tmp[ACCEL_Z_AXIS] = (rawData.z * SENSOR_CONVERT_UNIT) / SENSOR_CONVERT_UNIT;

    ret = SensorRawDataToRemapData(cfg->direction, tmp, sizeof(tmp) / sizeof(tmp[0]));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: MIC6200 convert raw data failed", __func__);
        return HDF_FAILURE;
    }

    event->dataLen = sizeof(tmp);
    event->data = (uint8_t *)&tmp;

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

static int32_t Mic6200WriteRegister(struct SensorBusCfg *busCfg, uint8_t regAddr, uint8_t regValue)
{
    uint8_t writeData[2] = {regAddr, regValue};
    return WriteSensor(busCfg, writeData, sizeof(writeData));
}

static int32_t InitMic6200(struct SensorCfgData *data)
{
    int32_t ret;
    HDF_LOGE("%s: %d", __func__, __LINE__);
    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);
    ret = SetSensorRegCfgArray(&data->busCfg, data->regCfgGroup[SENSOR_INIT_GROUP]);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Mic6200 sensor init config failed", __func__);
        return HDF_FAILURE;
    }
    HDF_LOGI("%s: Initializing MIC6200 sensor: name=%s, sensorId=%d, vendorName=%s",
             __func__, data->sensorInfo.sensorName, data->sensorInfo.sensorId,
             data->sensorInfo.vendorName);
    // Verify chip ID first
    ret = VerifyMic6200Id(data);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: MIC6200 chip verification failed", __func__);
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
    struct AccelOpsCall ops;

    CHECK_NULL_PTR_RETURN_VALUE(device, HDF_ERR_INVALID_PARAM);
    struct Mic6200DrvData *drvData = (struct Mic6200DrvData *)device->service;
    CHECK_NULL_PTR_RETURN_VALUE(drvData, HDF_ERR_INVALID_PARAM);

    drvData->sensorCfg = AccelCreateCfgData(device->property);
    if (drvData->sensorCfg == NULL || drvData->sensorCfg->root == NULL) {
        HDF_LOGD("%s: Creating accelcfg failed because detection failed", __func__);
        return HDF_ERR_NOT_SUPPORT;
    }

    ops.Init = NULL;
    ops.ReadData = ReadMic6200Data;
    ret = AccelRegisterChipOps(&ops);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Register MIC6200 accel failed", __func__);
        return HDF_FAILURE;
    }

    ret = InitMic6200(drvData->sensorCfg);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Init MIC6200 accel failed", __func__);
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
        AccelReleaseCfgData(drvData->sensorCfg);
        drvData->sensorCfg = NULL;
    }
    OsalMemFree(drvData);
}

struct HdfDriverEntry g_accelMic6200DevEntry = {
    .moduleVersion = 1,
    .moduleName = "HDF_SENSOR_ACCEL_MIC6200",
    .Bind = Mic6200BindDriver,
    .Init = Mic6200InitDriver,
    .Release = Mic6200ReleaseDriver,
};

HDF_INIT(g_accelMic6200DevEntry);