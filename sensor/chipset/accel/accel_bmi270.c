/**
* Copyright (c) 2024 Bosch Sensortec GmbH. All rights reserved.
*
* accel_bmi270.c as part of the * /chipsets subdirectory
* is dual licensed: you can use it either under the terms of
* the GPL, or the BSD license, at your option.
* See the LICENSE file in the root of this repository for complete details.
*/

#include "accel_bmi270.h"
#include <securec.h>
#include "osal_mem.h"
#include "osal_time.h"
#include "sensor_accel_driver.h"
#include "sensor_config_controller.h"
#include "sensor_device_manager.h"

#define HDF_LOG_TAG    khdf_sensor_accel_driver
static struct Bmi270DrvData *g_bmi270DrvData = NULL;
//328 bytes
static uint8_t g_regw_buffer[512];

/* IO config for int-pin and I2C-pin */
#define SENSOR_I2C6_DATA_REG_ADDR 0x114f004c
#define SENSOR_I2C6_CLK_REG_ADDR  0x114f0048
#define SENSOR_I2C_REG_CFG        0x403

static uint8_t bmi270_cfg_buffer[] = {
    0xc8, 0x2e, 0x00, 0x2e, 0x80, 0x2e, 0x1a, 0x00, 0xc8, 0x2e, 0x00, 0x2e,
    0xc8, 0x2e, 0x00, 0x2e, 0xc8, 0x2e, 0x00, 0x2e, 0xc8, 0x2e, 0x00, 0x2e,
    0xc8, 0x2e, 0x00, 0x2e, 0xc8, 0x2e, 0x00, 0x2e, 0x90, 0x32, 0x21, 0x2e,
    0x59, 0xf5, 0x10, 0x30, 0x21, 0x2e, 0x6a, 0xf5, 0x1a, 0x24, 0x22, 0x00,
    0x80, 0x2e, 0x3b, 0x00, 0xc8, 0x2e, 0x44, 0x47, 0x22, 0x00, 0x37, 0x00,
    0xa4, 0x00, 0xff, 0x0f, 0xd1, 0x00, 0x07, 0xad, 0x80, 0x2e, 0x00, 0xc1,
    0x80, 0x2e, 0x00, 0xc1, 0x80, 0x2e, 0x00, 0xc1, 0x80, 0x2e, 0x00, 0xc1,
    0x80, 0x2e, 0x00, 0xc1, 0x80, 0x2e, 0x00, 0xc1, 0x80, 0x2e, 0x00, 0xc1,
    0x80, 0x2e, 0x00, 0xc1, 0x80, 0x2e, 0x00, 0xc1, 0x80, 0x2e, 0x00, 0xc1,
    0x80, 0x2e, 0x00, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x24,
    0xfc, 0xf5, 0x80, 0x30, 0x40, 0x42, 0x50, 0x50, 0x00, 0x30, 0x12, 0x24,
    0xeb, 0x00, 0x03, 0x30, 0x00, 0x2e, 0xc1, 0x86, 0x5a, 0x0e, 0xfb, 0x2f,
    0x21, 0x2e, 0xfc, 0xf5, 0x13, 0x24, 0x63, 0xf5, 0xe0, 0x3c, 0x48, 0x00,
    0x22, 0x30, 0xf7, 0x80, 0xc2, 0x42, 0xe1, 0x7f, 0x3a, 0x25, 0xfc, 0x86,
    0xf0, 0x7f, 0x41, 0x33, 0x98, 0x2e, 0xc2, 0xc4, 0xd6, 0x6f, 0xf1, 0x30,
    0xf1, 0x08, 0xc4, 0x6f, 0x11, 0x24, 0xff, 0x03, 0x12, 0x24, 0x00, 0xfc,
    0x61, 0x09, 0xa2, 0x08, 0x36, 0xbe, 0x2a, 0xb9, 0x13, 0x24, 0x38, 0x00,
    0x64, 0xbb, 0xd1, 0xbe, 0x94, 0x0a, 0x71, 0x08, 0xd5, 0x42, 0x21, 0xbd,
    0x91, 0xbc, 0xd2, 0x42, 0xc1, 0x42, 0x00, 0xb2, 0xfe, 0x82, 0x05, 0x2f,
    0x50, 0x30, 0x21, 0x2e, 0x21, 0xf2, 0x00, 0x2e, 0x00, 0x2e, 0xd0, 0x2e,
    0xf0, 0x6f, 0x02, 0x30, 0x02, 0x42, 0x20, 0x26, 0xe0, 0x6f, 0x02, 0x31,
    0x03, 0x40, 0x9a, 0x0a, 0x02, 0x42, 0xf0, 0x37, 0x05, 0x2e, 0x5e, 0xf7,
    0x10, 0x08, 0x12, 0x24, 0x1e, 0xf2, 0x80, 0x42, 0x83, 0x84, 0xf1, 0x7f,
    0x0a, 0x25, 0x13, 0x30, 0x83, 0x42, 0x3b, 0x82, 0xf0, 0x6f, 0x00, 0x2e,
    0x00, 0x2e, 0xd0, 0x2e, 0x12, 0x40, 0x52, 0x42, 0x00, 0x2e, 0x12, 0x40,
    0x52, 0x42, 0x3e, 0x84, 0x00, 0x40, 0x40, 0x42, 0x7e, 0x82, 0xe1, 0x7f,
    0xf2, 0x7f, 0x98, 0x2e, 0x6a, 0xd6, 0x21, 0x30, 0x23, 0x2e, 0x61, 0xf5,
    0xeb, 0x2c, 0xe1, 0x6f
};
//328 bytes

static struct Bmi270DrvData *Bmi270GetDrvData(void)
{
    return g_bmi270DrvData;
}

/// @brief basic register write function
/// @param data       Sensor configuration data structre pointer
/// @param rega       register address
/// @param buffer     value to write
/// @param len        write len
/// @return           HDF_SUCCESS if success, failed any error
static int32_t AccBmi270HalRegWrite(struct SensorCfgData *data, uint16_t rega, uint8_t* buffer, uint32_t len)
{
    int32_t rc = HDF_SUCCESS;
    uint32_t idx = 0;
    (void)memset_s(g_regw_buffer, sizeof(g_regw_buffer), 0, sizeof(g_regw_buffer));

    g_regw_buffer[0] = (rega & 0xFF);
    do {
        g_regw_buffer[idx + 1] = buffer[idx];
        idx ++;
    } while (idx < len);
    
    rc = WriteSensor(&data->busCfg, g_regw_buffer, (len + 1));
    OsalUDelay(BMI270_LP_MODE_WRITE_DELAY_IN_US);

    if (rc != HDF_SUCCESS) {
        HDF_LOGE("%s: [BMI270] w reg:%d err", __func__, rega);
    }

    return rc;
}

/// @brief basic register read function
/// @param data      Sensor configuration data structre pointer
/// @param rega      register address to read
/// @param buffer    read data buffer
/// @param len       read len
/// @return          HDF_SUCCESS if success, failed any error
static int32_t AccBmi270HalRegRead(struct SensorCfgData *data, uint16_t rega, uint8_t* buffer, uint32_t len)
{
    int32_t rc = HDF_SUCCESS;
    rc = ReadSensor(&data->busCfg, rega, buffer, len);
  
    OsalUDelay(BMI270_NORMAL_MODE_WRITE_DELAY_IN_US);
    if (rc != HDF_SUCCESS) {
        HDF_LOGE("%s: [BMI270] r reg:%d err", __func__, rega);
    }

    return rc;
}

static int32_t AccReadBmi270RawData(struct SensorCfgData *data, struct AccelData *rawData, int64_t *timestamp)
{
    OsalTimespec time;
    uint8_t status = 0;
    uint8_t regv[ACCEL_AXIS_BUTT] = {0};
    int32_t ret = HDF_SUCCESS;

    (void)memset_s(&time, sizeof(time), 0, sizeof(time));
    (void)memset_s(regv, sizeof(regv), 0, sizeof(regv));

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);

    if (OsalGetTime(&time) != HDF_SUCCESS) {
        HDF_LOGE("%s: Get time failed", __func__);
        return HDF_FAILURE;
    }
    *timestamp = time.sec * SENSOR_SECOND_CONVERT_NANOSECOND + time.usec * SENSOR_CONVERT_UNIT; /* unit nanosecond */

    ret = AccBmi270HalRegRead(data, BMI270_ACCEL_REGA_STATUS, &status, sizeof(uint8_t));
    /* any new data? */
    if (!(status & BMI270_ACCEL_DATA_READY_MASK) || (ret != HDF_SUCCESS)) {
        HDF_LOGI("%s: data status [%hhu] ret [%d]", __func__, status, ret);
        return HDF_FAILURE;
    }

    ret = AccBmi270HalRegRead(data, BMI270_ACCEL_REGA_X_LSB_ADDR, regv, BMI270_ACC_DATA_FRAME_SIZE);

    rawData->x = (int16_t)(SENSOR_DATA_SHIFT_LEFT(regv[ACCEL_X_AXIS_MSB], SENSOR_DATA_WIDTH_8_BIT) |
        regv[ACCEL_X_AXIS_LSB]);
    rawData->y = (int16_t)(SENSOR_DATA_SHIFT_LEFT(regv[ACCEL_Y_AXIS_MSB], SENSOR_DATA_WIDTH_8_BIT) |
        regv[ACCEL_Y_AXIS_LSB]);
    rawData->z = (int16_t)(SENSOR_DATA_SHIFT_LEFT(regv[ACCEL_Z_AXIS_MSB], SENSOR_DATA_WIDTH_8_BIT) |
        regv[ACCEL_Z_AXIS_LSB]);

    return ret;
}

static int32_t AccReadBmi270Data(struct SensorCfgData *cfg, struct SensorReportEvent *event)
{
    int32_t ret;
    struct AccelData rawData = { 0, 0, 0 };
    static int32_t tmp[ACCEL_AXIS_NUM];

    CHECK_NULL_PTR_RETURN_VALUE(cfg, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(event, HDF_ERR_INVALID_PARAM);

    ret = AccReadBmi270RawData(cfg, &rawData, (int64_t *)&event->timestamp);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: BMI270 read raw data failed", __func__);
        return HDF_FAILURE;
    }
    event->sensorId = SENSOR_TAG_ACCELEROMETER;
    event->option = 0;
    event->mode = SENSOR_WORK_MODE_REALTIME;

    rawData.x = rawData.x * BMI270_ACC_SENSITIVITY_2G;
    rawData.y = rawData.y * BMI270_ACC_SENSITIVITY_2G;
    rawData.z = rawData.z * BMI270_ACC_SENSITIVITY_2G;

    tmp[ACCEL_X_AXIS] = (rawData.x * SENSOR_CONVERT_UNIT) / SENSOR_CONVERT_UNIT;
    tmp[ACCEL_Y_AXIS] = (rawData.y * SENSOR_CONVERT_UNIT) / SENSOR_CONVERT_UNIT;
    tmp[ACCEL_Z_AXIS] = (rawData.z * SENSOR_CONVERT_UNIT) / SENSOR_CONVERT_UNIT;


    ret = SensorRawDataToRemapData(cfg->direction, tmp, sizeof(tmp) / sizeof(tmp[0]));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: BMI270 convert raw data failed", __func__);
        return HDF_FAILURE;
    }

    event->dataLen = sizeof(tmp);
    event->data = (uint8_t *)&tmp;

    return ret;
}

// success
static int32_t Bmi270IMUSwReset(struct SensorCfgData* data)
{
    uint8_t regv = BMI26X_REGV_CMD_SOFT_RESET;
    int32_t rc = AccBmi270HalRegWrite(data, BMI26X_REGA_USR_CMD, &regv, BMI270_ONE_BYTE);
    OsalMDelay(BMI270_RESET_DELAY_IN_MS);

    return rc;
}

static bool Bmi270HalIMUInited(struct SensorCfgData *data)
{
    bool rc = false;
    uint8_t regv = 0;

    rc = AccBmi270HalRegRead(data, BMI270_REGA_INTERNAL_STATUS, &regv, BMI270_ONE_BYTE);
    if (BST_GET_VAL_BIT(regv, 0)) {
        HDF_LOGI("[BMI270] %s, IMU inited", __LINE__);
        rc = true;
    }

    return rc;
}

static int32_t Bmi270CfgAccPwr(struct SensorCfgData *data, bool en)
{
    uint8_t regv = 0;
    int32_t rc = HDF_SUCCESS;
    rc = AccBmi270HalRegRead(data, BMI270_REGA_PWR_CTRL, &regv, BMI270_ONE_BYTE);

    if (en) {
        regv = BST_SET_VAL_BIT(regv, BMI270_ACC_POWER_BIT_POS_IN_PWR_CTRL_REG);
    } else {
        regv = BST_CLR_VAL_BIT(regv, BMI270_ACC_POWER_BIT_POS_IN_PWR_CTRL_REG);
    }

    rc = AccBmi270HalRegWrite(data, BMI270_REGA_PWR_CTRL, &regv, BMI270_ONE_BYTE);

    return rc;
}

// @load configuration
static int32_t Bmi270LoadCfg(struct SensorCfgData *data, uint8_t* cfg_data_buffer,
    uint32_t cfg_size, uint32_t in_burst_write_size)
{
    int32_t rc = HDF_SUCCESS;
    uint8_t regv = 0;
    /* Variable to update the configuration file index */
    uint16_t index = 0;
    /* Array to store address */
    uint8_t addr_array[2] = {0};
    uint32_t size_bw = in_burst_write_size; //burst write size in byte

    /* Disable loading of the configuration */
    rc = AccBmi270HalRegWrite(data, BMI26X_REGA_USR_TITAN_CTRL, &regv, BMI270_ONE_BYTE);

    for (index = 0; index < cfg_size; index += size_bw) {
        //1. len
        if (index + in_burst_write_size > cfg_size) {
            size_bw = cfg_size - index;
        }

        // index low in word
        addr_array[0] = (uint8_t)((index / 2) & 0x0F);
        // ndex high in word
        addr_array[1] = (uint8_t)((index / 2) >> 4);
        rc = AccBmi270HalRegWrite(data, BMI26X_REGA_USR_CONF_STREAM_IDX_LSB, addr_array, BMI270_TWO_BYTE);

        //2. data
        rc = AccBmi270HalRegWrite(data, BMI26X_REGA_USR_CONF_STREAM_IN,
                                  cfg_data_buffer + index, size_bw);
    }

    return rc;
}

static int32_t Bmi270HalLoadCfg(struct SensorCfgData *data)
{
    int32_t rc = HDF_SUCCESS;
    uint8_t regv = 0;
    uint8_t try_num_to_check_cfg = 0;
    bool cfg_is_avaiblabe = Bmi270HalIMUInited(data);
    if (cfg_is_avaiblabe) {
        return HDF_SUCCESS;
    }

    rc = Bmi270IMUSwReset(data);
    if (rc != HDF_SUCCESS) {
        return rc;
    }

    //disable advance power saving
    rc = AccBmi270HalRegWrite(data, BMI270_REGA_PWR_CFG, &regv, BMI270_ONE_BYTE);

    // load configuration now
    rc = Bmi270LoadCfg(data, bmi270_cfg_buffer,
                       HDF_ARRAY_SIZE(bmi270_cfg_buffer),
                       HDF_ARRAY_SIZE(bmi270_cfg_buffer));

    regv = 0x01;
    rc = AccBmi270HalRegWrite(data, BMI26X_REGA_USR_TITAN_CTRL, &regv, BMI270_ONE_BYTE);

    cfg_is_avaiblabe = false;
    rc = HDF_DEV_ERR_DEV_INIT_FAIL;
    do {
        OsalMDelay(BMI270_LOAD_RAM_PATCH_DELAY_IN_MS);
        cfg_is_avaiblabe = Bmi270HalIMUInited(data);
        try_num_to_check_cfg ++;
        if (cfg_is_avaiblabe) {
            rc = HDF_SUCCESS;
            break;
        }
    } while ((try_num_to_check_cfg < BMI26X_CHECK_CONFIGURE_STATUS_TIMES) &&
            (!cfg_is_avaiblabe));

    return rc;
}

static int32_t Bmi270GetWhoAmI(struct SensorCfgData *data)
{
    uint8_t regv = 0;
    int32_t rc = HDF_SUCCESS;

    rc = AccBmi270HalRegRead(data, 0x00, &regv, BMI270_ONE_BYTE);
    if (rc != HDF_SUCCESS) {
        HDF_LOGE("%s: [BMI270] WARN!!, NO Sensor", __func__);
        return HDF_FAILURE;
    }

    if (regv != BMI26X_REGV_WHOAMI) {
        rc = HDF_DEV_ERR_NO_DEVICE;
    }

    return rc;
}

static int32_t InitBmi270(struct SensorCfgData *data)
{
    int32_t ret = HDF_SUCCESS;
    uint8_t regv = 0x00;

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);
    ret = SetSensorRegCfgArray(&data->busCfg, data->regCfgGroup[SENSOR_INIT_GROUP]);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: BMI270 sensor init config failed", __func__);
        return HDF_FAILURE;
    }

    ret = Bmi270CfgAccPwr(data, true);
    //defualt odr:100hz
    // range:+/- 2G
    regv = 0;
    ret = AccBmi270HalRegWrite(data, BMI26X_REGA_ACC_RANGE, &regv, BMI270_ONE_BYTE);

    return ret;
}

static int32_t DispatchBmi270(struct HdfDeviceIoClient *client,
    int cmd, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    (void)client;
    (void)cmd;
    (void)data;
    (void)reply;

    return HDF_SUCCESS;
}

static int32_t Bmi270BindDriver(struct HdfDeviceObject *device)
{
    CHECK_NULL_PTR_RETURN_VALUE(device, HDF_ERR_INVALID_PARAM);

    struct Bmi270DrvData *drvData = (struct Bmi270DrvData *)OsalMemCalloc(sizeof(*drvData));
    if (drvData == NULL) {
        HDF_LOGE("%s: Malloc Bmi270 drv data fail", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    drvData->ioService.Dispatch = DispatchBmi270;
    drvData->device = device;
    device->service = &drvData->ioService;
    g_bmi270DrvData = drvData;

    return HDF_SUCCESS;
}

static int32_t Bmi270InitDriver(struct HdfDeviceObject *device)
{
    int32_t ret;
    struct AccelOpsCall ops;

    CHECK_NULL_PTR_RETURN_VALUE(device, HDF_ERR_INVALID_PARAM);
    struct Bmi270DrvData *drvData = (struct Bmi270DrvData *)device->service;
    CHECK_NULL_PTR_RETURN_VALUE(drvData, HDF_ERR_INVALID_PARAM);

    drvData->sensorCfg = AccelCreateCfgData(device->property);
    if (drvData->sensorCfg == NULL || drvData->sensorCfg->root == NULL) {
        HDF_LOGD("%s: Creating accelcfg failed because detection failed", __func__);
        return HDF_ERR_NOT_SUPPORT;
    }

    ops.Init = NULL;
    ops.ReadData = AccReadBmi270Data;
    ret = AccelRegisterChipOps(&ops);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Register BMI270 accel failed", __func__);
        return HDF_FAILURE;
    }

    // check whoami
    ret = Bmi270GetWhoAmI(drvData->sensorCfg);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    do {
        ret = Bmi270HalLoadCfg(drvData->sensorCfg);
    } while (0);

    // init hw
    ret = InitBmi270(drvData->sensorCfg);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Init BMI270 accel failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static void Bmi270ReleaseDriver(struct HdfDeviceObject *device)
{
    CHECK_NULL_PTR_RETURN(device);

    struct Bmi270DrvData *drvData = (struct Bmi270DrvData *)device->service;
    CHECK_NULL_PTR_RETURN(drvData);

    if (drvData->sensorCfg != NULL) {
        AccelReleaseCfgData(drvData->sensorCfg);
        drvData->sensorCfg = NULL;
    }
    OsalMemFree(drvData);
}

struct HdfDriverEntry g_accelBmi270DevEntry = {
    .moduleVersion = 1,
    .moduleName = "HDF_SENSOR_ACCEL_BMI270",
    .Bind = Bmi270BindDriver,
    .Init = Bmi270InitDriver,
    .Release = Bmi270ReleaseDriver,
};

HDF_INIT(g_accelBmi270DevEntry);
