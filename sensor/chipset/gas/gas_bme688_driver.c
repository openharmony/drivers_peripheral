/**
* Copyright (c) 2024 Bosch Sensortec GmbH. All rights reserved.
*
* gas_bme688_driver.c as part of the * /chipsets subdirectory
* is dual licensed: you can use it either under the terms of
* the GPL, or the BSD license, at your option.
* See the LICENSE file in the root of this repository for complete details.
*/

#include "gas_bme688_driver.h"
#include "osal_mem.h"
#include "osal_time.h"
#include "sensor_config_controller.h"
#include "sensor_device_manager.h"
#include "sensor_gas_driver.h"
#include <securec.h>

#define HDF_LOG_TAG hdf_sensor_gas

/* This internal API is used to calculate the temperature in integer */
static int16_t BmeHalCalcTemperature(struct SensorCfgData *data, uint32_t tempAdc);

/* This internal API is used to calculate the pressure value in integer */
static uint32_t BmeHalCalcPressure(struct SensorCfgData *data, uint32_t presAdc);

/* This internal API is used to calculate the humidity value in integer */
static uint32_t BmeHalCalcHumidity(struct SensorCfgData *data, uint16_t humADC);

/* This internal API is used to calculate the gas resistance high value in integer */
static uint32_t BmeHalCalcGasResistanceHigh(uint16_t gasResAdc, uint8_t gasRange);

/* This internal API is used to calculate the gas resistance low value in integer */
static uint32_t BmeHalCalcGasResistanceLow(struct SensorCfgData *data,
                                           uint16_t gasResAdc, uint8_t gasRange);

/* This internal API is used to calculate the heater resistance value using integer */
static uint8_t BmeHalCalcResHeat(struct SensorCfgData *data, uint16_t temp);

/* This internal API is used to set gas wait and resistance heat config using integer*/
static int32_t BmeHalSetConfig(struct SensorCfgData *data,
                               struct bme688HeatrConf *conf, uint8_t opMode, uint8_t *nbConv);

/* This internal API is used to calculate the gas wait */
static uint8_t BmeHalCalcGasWait(uint16_t dur);

/* This internal API is used to read a single data of the sensor */
static int32_t BmeHalReadFieldData(struct SensorCfgData *data, uint8_t index,
                                   struct GasFieldData *fieldData);

/* This internal API is used to get operation mode */
static int32_t Bme688GetOpMode(struct SensorCfgData *data, uint8_t *opMode);

/* This internal API is used to set operation mode */
static int32_t Bme688SetOpMode(struct SensorCfgData *data, const uint8_t opMode);

/* This internal API is used to get measurement duration */
static uint32_t Bme688GetMeasDur(struct SensorCfgData *data, const uint8_t opMode,
                                 struct GasCfg *gascfg);

/* This internal API is used to set configuration */
static int32_t Bme688SetConfig(struct SensorCfgData *data, struct GasCfg *gascfg);

/* This internal API is used to set heatr configuration */
static int32_t Bme688SetHeatrConfig(struct SensorCfgData *data, struct bme688HeatrConf *conf,
                                    uint8_t opMode);

/* This internal API is used to limit the max value of a parameter */
static int32_t BmeHalBoundaryCheck(struct SensorCfgData *data, uint8_t *value, uint8_t max);

/* This internal API is used to read the sensor data */
static int32_t Bme688GetData(struct SensorCfgData *data, struct GasFieldData *fieldData,
                             uint8_t opMode);

static struct Bme688DrvData *g_bme688DrvData = NULL;
static struct Bme688CalibData g_calibData;
static int16_t reTemp = 0;
static uint32_t reData[4] = {0};
static struct Bme688Status g_bme688State;

static struct Bme688DrvData *Bme688GetDrvData(void)
{
    return g_bme688DrvData;
}

/// @brief basic register write one byte function
/// @param data       Sensor configuration data structre pointer
/// @param rega       register address
/// @param buffer     value to write
/// @return           HDF_SUCCESS if success, failed any error
static int32_t BmeHalRegWriteOneByte(struct SensorCfgData *data, uint8_t rega, uint8_t buffer)
{
    int32_t rc = HDF_SUCCESS;
    int32_t index = 0;
    uint8_t g_regw_buffer[20];
    uint8_t len = 1;
    (void)memset_s(g_regw_buffer, sizeof(g_regw_buffer), 0, sizeof(g_regw_buffer));

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);

    g_regw_buffer[0] = (rega & 0xFF);
    do {
        g_regw_buffer[index + 1] = buffer;
        index++;
    } while (index < len);

    rc = WriteSensor(&data->busCfg, g_regw_buffer, (len + 1));
    OsalUDelay(BME688_DELAY_10);

    if (rc != HDF_SUCCESS) {
        HDF_LOGE("%s: [BME688] w reg:%d err", __func__, rega);
    }

    return rc;
}

/// @brief basic register write multiply byte function
/// @param data       Sensor configuration data structre pointer
/// @param rega       register address
/// @param buffer     value to write
/// @param len        write len
/// @return           HDF_SUCCESS if success, failed any error
static int32_t BmeHalRegWriteMulByte(struct SensorCfgData *data, uint8_t *rega, uint8_t *buffer, uint32_t len)
{
    int32_t rc = HDF_SUCCESS;
    int32_t index = 0;

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);

    do {
        rc = BmeHalRegWriteOneByte(data, rega[index], buffer[index]);
        index++;
    } while (index < len);

    return rc;
}

/// @brief basic register read function
/// @param data      Sensor configuration data structre pointer
/// @param rega      register address to read
/// @param buffer    read data buffer
/// @param len       read len
/// @return          HDF_SUCCESS if success, failed any error
static int32_t BmeHalRegRead(struct SensorCfgData *data, uint16_t rega, uint8_t *buffer, uint32_t len)
{
    int32_t rc = HDF_SUCCESS;

    rc = ReadSensor(&data->busCfg, rega, buffer, len);
    if (rc != HDF_SUCCESS) {
        HDF_LOGE("%s: [BME688] r reg:%d err", __func__, rega);
    }
    OsalUDelay(BME688_DELAY_4);

    return rc;
}

static int32_t Bme688HalReadSensorRawData(struct SensorCfgData *data, struct GasData *rawData)
{
    struct GasFieldData fieldData = { 0 };
    uint8_t opMode = 0;
    int32_t ret = HDF_SUCCESS;

    ret = Bme688GetOpMode(data, &opMode);
    if ((opMode & BME68X_MODE_MSK) == BME68X_SLEEP_MODE) {
        ret = Bme688GetData(data, &fieldData, BME68X_FORCED_MODE);

        g_bme688State.workState = BME688_WORK_MODE_SUSPEND;

        rawData->gasResitance = fieldData.gas_resistance;
        rawData->heatSource = BME688_HEATR_TEMP;
        rawData->temperature = fieldData.temperature;
        rawData->humidity = fieldData.humidity;
        rawData->pressure = fieldData.pressure;

        reData[RESISTANCE] = fieldData.gas_resistance;
        reData[TEMPERATURE] = BME688_HEATR_TEMP;
        reTemp = fieldData.temperature;
        reData[HUMIDITY] = fieldData.humidity;
        reData[PRESSURE] = fieldData.pressure;
    } else if ((opMode & BME68X_MODE_MSK) == BME68X_FORCED_MODE) {
        rawData->gasResitance = reData[RESISTANCE];
        rawData->heatSource = reData[TEMPERATURE];
        rawData->temperature = reTemp;
        rawData->humidity = reData[HUMIDITY];
        rawData->pressure = reData[PRESSURE];
    } else {
        HDF_LOGE("%s: opMode ERROR!", __func__);
        return HDF_FAILURE;
    }

    return ret;
}

/// @brief basic register write function
/// @param data       Sensor configuration data structre pointer
/// @param rega       register address
/// @param buffer     value to write
/// @param len        write len
/// @return           HDF_SUCCESS if success, failed any error
static int32_t ReadBme688RawData(struct SensorCfgData *data, struct GasData *rawData, int64_t *timestamp)
{
    OsalTimespec time;
    uint8_t regv[GAS_PART_SUM] = {0};
    int32_t ret = HDF_SUCCESS;
    struct GasFieldData fieldData = { 0 };
    struct GasCfg conf;
    struct bme688HeatrConf heatConf;
    (void)memset_s(&time, sizeof(time), 0, sizeof(time));
    (void)memset_s(regv, sizeof(regv), 0, sizeof(regv));

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);

    if (OsalGetTime(&time) != HDF_SUCCESS) {
        HDF_LOGE("%s: Get time failed", __func__);
        return HDF_FAILURE;
    }
    *timestamp = time.sec * SENSOR_SECOND_CONVERT_NANOSECOND + time.usec * SENSOR_CONVERT_UNIT; /* unit nanosecond */

    if (g_bme688State.workState == BME688_WORK_MODE_SUSPEND) {
        if (g_bme688State.inited != BME68X_ENABLE) {
            conf.humOs = BME68X_OS_16X;
            conf.tempOs = BME68X_OS_2X;
            conf.presOs = BME68X_OS_1X;
            conf.filter = BME68X_FILTER_OFF;
            conf.odr = BME68X_ODR_NONE;

            ret = Bme688SetConfig(data, &conf);
            if (ret != HDF_SUCCESS) {
                HDF_LOGE("%s: bme688 sensor set oversample config failed", __func__);
                return HDF_FAILURE;
            }

            heatConf.enable = BME68X_ENABLE;
            heatConf.heatr_temp = BME688_HEATR_TEMP;
            heatConf.heatr_dur = BME688_HEATR_DUR;

            ret = Bme688SetHeatrConfig(data, &heatConf, BME68X_FORCED_MODE);
            g_bme688State.inited = BME68X_ENABLE;
        }

        ret = Bme688SetOpMode(data, BME68X_FORCED_MODE);
        g_bme688State.workState = BME688_WORK_MODE_IDLE;
    }
    
    if (g_bme688State.workState == BME688_WORK_MODE_IDLE) {
        ret = Bme688HalReadSensorRawData(data, rawData);
    }

    return ret;
}

/* read bme688 sensor data */
static int32_t ReadBme688Data(struct SensorCfgData *cfg, struct SensorReportEvent *event)
{
    int32_t ret;
    struct GasData rawData = {0};
    static int16_t tmp[GAS_DEP_PART_SUM];

    CHECK_NULL_PTR_RETURN_VALUE(cfg, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(event, HDF_ERR_INVALID_PARAM);

    ret = ReadBme688RawData(cfg, &rawData, (int64_t *)&event->timestamp);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: bme688 read raw data failed", __func__);
        return HDF_FAILURE;
    }
    event->sensorId = SENSOR_TAG_GAS;
    event->option = 0;
    event->mode = SENSOR_WORK_MODE_REALTIME;

    HDF_LOGI("%s rawData->gasResitance = %d", __func__, rawData.gasResitance);
    HDF_LOGI("%s rawData->heatSource = %d", __func__, rawData.heatSource);
    HDF_LOGI("%s rawData->temperature = %d", __func__, rawData.temperature);
    HDF_LOGI("%s rawData->humidity = %d", __func__, rawData.humidity);
    HDF_LOGI("%s rawData->pressure = %d", __func__, rawData.pressure);

    tmp[GAS_PART_GASRES] = rawData.gasResitance;
    tmp[GAS_PART_HEAT] = rawData.heatSource;
    tmp[GAS_PART_TEMP] = rawData.temperature;
    tmp[GAS_PART_HUMI] = rawData.humidity;
    tmp[GAS_PART_PRE] = rawData.pressure;

    event->dataLen = sizeof(tmp);
    event->data = (uint8_t *)&tmp;

    return ret;
}

/* This internal API is used to soft reset sensor */
static int32_t Bme688SoftReset(struct SensorCfgData *data)
{
    int32_t rc;
    uint8_t regv = BME68X_SOFT_RESET_CMD;

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);

    rc = BmeHalRegWriteOneByte(data, BME68X_REG_SOFT_RESET, regv);
    if (rc != HDF_SUCCESS) {
        HDF_LOGE("%s: bme688 write command register failed", __func__);
        return HDF_FAILURE;
    }
    // delay 5ms after reset
    OsalMDelay(BME688_DELAY_5);

    return rc;
}

/* This internal API is used to validate chip id */
static int32_t Bme688ValChipId(struct SensorCfgData *data)
{
    uint8_t regv = 0;
    int32_t rc = HDF_SUCCESS;

    rc = BmeHalRegRead(data, BME68X_REG_CHIP_ID, &regv, 1);
    if (rc != HDF_SUCCESS) {
        HDF_LOGE("%s: [BME688] WARN!!, NO Sensor", __func__);
        return HDF_FAILURE;
    }

    HDF_LOGI("%s: rc = %d, WHO_AMI: 0x%x", __func__, rc, regv);

    if (regv != BME68X_CHIP_ID) {
        rc = HDF_DEV_ERR_NO_DEVICE;
    }

    return rc;
}

/* This internal API is used to read variant id */
static int32_t Bme688ReadVariantId(struct SensorCfgData *data)
{
    uint8_t regv = 0;
    int32_t rc = HDF_SUCCESS;

    rc = BmeHalRegRead(data, BME68X_REG_VARIANT_ID, &regv, 1);
    if (rc != HDF_SUCCESS) {
        HDF_LOGE("%s: [BME688] read variant id failed", __func__);
        return HDF_FAILURE;
    }
    HDF_LOGI("%s: rc = %d, regv = 0x%x", __func__, rc, regv);
    g_bme688State.variantId = regv;
    return rc;
}

/* function calculate the coeff from register to local before sensor data calibration */
static void Bme688GetCofParam(struct Bme688CalibData *myCalibData, uint8_t* coeff_array)
{
    /* Temperature related coefficients */
    myCalibData->par_t1 =
        (uint16_t)(BME68X_CONCAT_BYTES(coeff_array[BME68X_IDX_T1_MSB], coeff_array[BME68X_IDX_T1_LSB]));
    myCalibData->par_t2 =
        (int16_t)(BME68X_CONCAT_BYTES(coeff_array[BME68X_IDX_T2_MSB], coeff_array[BME68X_IDX_T2_LSB]));
    myCalibData->par_t3 =
        (int8_t)(coeff_array[BME68X_IDX_T3]);

    /* Pressure related coefficients */
    myCalibData->par_p1 =
        (uint16_t)(BME68X_CONCAT_BYTES(coeff_array[BME68X_IDX_P1_MSB], coeff_array[BME68X_IDX_P1_LSB]));
    myCalibData->par_p2 =
        (int16_t)(BME68X_CONCAT_BYTES(coeff_array[BME68X_IDX_P2_MSB], coeff_array[BME68X_IDX_P2_LSB]));
    myCalibData->par_p3 = (int8_t)coeff_array[BME68X_IDX_P3];
    myCalibData->par_p4 =
        (int16_t)(BME68X_CONCAT_BYTES(coeff_array[BME68X_IDX_P4_MSB], coeff_array[BME68X_IDX_P4_LSB]));
    myCalibData->par_p5 =
        (int16_t)(BME68X_CONCAT_BYTES(coeff_array[BME68X_IDX_P5_MSB], coeff_array[BME68X_IDX_P5_LSB]));
    myCalibData->par_p6 = (int8_t)(coeff_array[BME68X_IDX_P6]);
    myCalibData->par_p7 = (int8_t)(coeff_array[BME68X_IDX_P7]);
    myCalibData->par_p8 =
        (int16_t)(BME68X_CONCAT_BYTES(coeff_array[BME68X_IDX_P8_MSB], coeff_array[BME68X_IDX_P8_LSB]));
    myCalibData->par_p9 =
        (int16_t)(BME68X_CONCAT_BYTES(coeff_array[BME68X_IDX_P9_MSB], coeff_array[BME68X_IDX_P9_LSB]));
    myCalibData->par_p10 = (uint8_t)(coeff_array[BME68X_IDX_P10]);

     /* Humidity related coefficients */
    myCalibData->par_h1 =
        (uint16_t)(((uint16_t)coeff_array[BME68X_IDX_H1_MSB] << 4) |
                    (coeff_array[BME68X_IDX_H1_LSB] & BME68X_BIT_H1_DATA_MSK));
    myCalibData->par_h2 =
        (uint16_t)(((uint16_t)coeff_array[BME68X_IDX_H2_MSB] << 4) | ((coeff_array[BME68X_IDX_H2_LSB]) >> 4));
    myCalibData->par_h3 = (int8_t)coeff_array[BME68X_IDX_H3];
    myCalibData->par_h4 = (int8_t)coeff_array[BME68X_IDX_H4];
    myCalibData->par_h5 = (int8_t)coeff_array[BME68X_IDX_H5];
    myCalibData->par_h6 = (uint8_t)coeff_array[BME68X_IDX_H6];
    myCalibData->par_h7 = (int8_t)coeff_array[BME68X_IDX_H7];

    /* Gas heater related coefficients */
    myCalibData->par_gh1 = (int8_t)coeff_array[BME68X_IDX_GH1];
    myCalibData->par_gh2 =
        (int16_t)(BME68X_CONCAT_BYTES(coeff_array[BME68X_IDX_GH2_MSB], coeff_array[BME68X_IDX_GH2_LSB]));
    myCalibData->par_gh3 = (int8_t)coeff_array[BME68X_IDX_GH3];

    /* Other coefficients */
    myCalibData->res_heat_range = ((coeff_array[BME68X_IDX_RES_HEAT_RANGE] & BME68X_RHRANGE_MSK) / 16);
    myCalibData->res_heat_val = (int8_t)coeff_array[BME68X_IDX_RES_HEAT_VAL];
    myCalibData->range_sw_err = ((int8_t)(coeff_array[BME68X_IDX_RANGE_SW_ERR] & BME68X_RSERROR_MSK)) / 16;
}

/* This internal API is used to get calibration data */
static int32_t Bme688GetCalibData(struct SensorCfgData *data,
                                  struct Bme688CalibData *calibData)
{
    int32_t rc = HDF_SUCCESS;
    uint8_t coeff_array[BME68X_LEN_COEFF_ALL] = {0};

    rc = BmeHalRegRead(data, BME68X_REG_COEFF1, coeff_array, BME68X_LEN_COEFF1);
    if (rc != HDF_SUCCESS) {
        HDF_LOGE("%s: [BME688] read data from BME68X_REG_COEFF1 failed", __func__);
        return HDF_FAILURE;
    }

    rc = BmeHalRegRead(data, BME68X_REG_COEFF2, &coeff_array[BME68X_LEN_COEFF1], BME68X_LEN_COEFF2);
    if (rc != HDF_SUCCESS) {
        HDF_LOGE("%s: [BME688] read data from BME68X_REG_COEFF2 failed", __func__);
        return HDF_FAILURE;
    }

    rc = BmeHalRegRead(data, BME68X_REG_COEFF3, &coeff_array[BME68X_LEN_COEFF1 + BME68X_LEN_COEFF2], BME68X_LEN_COEFF3);
    if (rc != HDF_SUCCESS) {
        HDF_LOGE("%s: [BME688] read data from BME68X_REG_COEFF3 failed", __func__);
        return HDF_FAILURE;
    }

    Bme688GetCofParam(calibData, coeff_array);

    return rc;
}

static int32_t Bme688GetOpMode(struct SensorCfgData *data, uint8_t *opMode)
{
    int32_t rc = HDF_SUCCESS;
    uint8_t mode;

    CHECK_NULL_PTR_RETURN_VALUE(opMode, HDF_ERR_INVALID_PARAM);

    rc = BmeHalRegRead(data, BME68X_REG_CTRL_MEAS, &mode, 1);
    *opMode = mode & BME68X_MODE_MSK;

    return rc;
}

static int32_t Bme688SetOpMode(struct SensorCfgData *data, const uint8_t opMode)
{
    int32_t rc;
    uint8_t tmpPowMode;
    uint8_t powMode = 0;
    uint8_t regAddr = BME68X_REG_CTRL_MEAS;

    do {
        rc = BmeHalRegRead(data, regAddr, &tmpPowMode, 1);
        if (rc != HDF_SUCCESS) {
            HDF_LOGE("%s: [BME688] get power mode failed", __func__);
        }
        powMode = tmpPowMode & BME68X_MODE_MSK;
        if (powMode != BME68X_SLEEP_MODE) {
            tmpPowMode &= ~BME68X_MODE_MSK;
            rc = BmeHalRegWriteOneByte(data, regAddr, tmpPowMode);
            OsalMDelay(BME688_DELAY_10);
        }
    } while (powMode != BME68X_SLEEP_MODE && rc == HDF_SUCCESS);

    if (opMode != BME68X_SLEEP_MODE && rc == HDF_SUCCESS) {
        tmpPowMode = (tmpPowMode & ~BME68X_MODE_MSK) | (opMode & BME68X_MODE_MSK);
        rc = BmeHalRegWriteOneByte(data, regAddr, tmpPowMode);
    }

    return rc;
}

static int16_t BmeHalCalcTemperature(struct SensorCfgData *data, uint32_t tempAdc)
{
    int64_t var1;
    int64_t var2;
    int64_t var3;
    int16_t calcTemp;

    var1 = ((int32_t)tempAdc >> 3) - ((int32_t)g_calibData.par_t1 << 1);
    var2 = (var1 * (int32_t)g_calibData.par_t2) >> 11;
    var3 = ((var1 >> 1) * (var1 >> 1)) >> 12;
    var3 = ((var3) * ((int32_t)g_calibData.par_t3 << 4)) >> 14;
    g_calibData.t_fine = (int32_t)(var2 + var3);
    calcTemp = (int16_t)(((g_calibData.t_fine * 5) + 128) >> 8);

    /*measurement unit : degrees centigrade*/
    return calcTemp / 100;
}

static uint32_t BmeHalCalcPressure(struct SensorCfgData *data, uint32_t presAdc)
{
    int32_t var1;
    int32_t var2;
    int32_t var3;
    int32_t pressureComp;

    const int32_t pres_ovf_check = BME_INT32_C(0x40000000);

    /*lint -save -e701 -e702 -e713 */
    var1 = (((int32_t)g_calibData.t_fine) >> 1) - 64000;
    var2 = ((((var1 >> 2) * (var1 >> 2)) >> 11) * (int32_t)g_calibData.par_p6) >> 2;
    var2 = var2 + ((var1 * (int32_t)g_calibData.par_p5) << 1);
    var2 = (var2 >> 2) + ((int32_t)g_calibData.par_p4 << 16);
    var1 = (((((var1 >> 2) * (var1 >> 2)) >> 13) * ((int32_t)g_calibData.par_p3 << 5)) >> 3) +
           (((int32_t)g_calibData.par_p2 * var1) >> 1);
    var1 = var1 >> 18;
    var1 = ((32768 + var1) * (int32_t)g_calibData.par_p1) >> 15;
    pressureComp = 1048576 - presAdc;
    pressureComp = (int32_t)((pressureComp - (var2 >> 12)) * ((uint32_t)3125));
    if (pressureComp >= pres_ovf_check) {
        pressureComp = ((pressureComp / var1) << 1);
    } else {
        pressureComp = ((pressureComp << 1) / var1);
    }

    var1 = ((int32_t)g_calibData.par_p9 * (int32_t)(((pressureComp >> 3) * (pressureComp >> 3)) >> 13)) >> 12;
    var2 = ((int32_t)(pressureComp >> 2) * (int32_t)g_calibData.par_p8) >> 13;
    var3 = ((int32_t)(pressureComp >> 8) * (int32_t)(pressureComp >> 8) * (int32_t)(pressureComp >> 8) *
            (int32_t)g_calibData.par_p10) >> 17;
    pressureComp = (int32_t)(pressureComp) + ((var1 + var2 + var3 + ((int32_t)g_calibData.par_p7 << 7)) >> 4);

    /*lint -restore */
    /*measurement unit : kPa*/
    return (uint32_t)pressureComp / 100;
}

static uint32_t BmeHalCalcHumidity(struct SensorCfgData *data, uint16_t humADC)
{
    int32_t var1;
    int32_t var2;
    int32_t var3;
    int32_t var4;
    int32_t var5;
    int32_t var6;
    int32_t tempScaled;
    int32_t calcHum;

    /*lint -save -e702 -e704 */
    tempScaled = (((int32_t)g_calibData.t_fine * 5) + 128) >> 8;
    var1 = (int32_t)(humADC - ((int32_t)((int32_t)g_calibData.par_h1 * 16))) -
           (((tempScaled * (int32_t)g_calibData.par_h3) / ((int32_t)100)) >> 1);
    var2 =
        ((int32_t)g_calibData.par_h2 *
        (((tempScaled * (int32_t)g_calibData.par_h4) / ((int32_t)100)) +
        (((tempScaled * ((tempScaled * (int32_t)g_calibData.par_h5) / ((int32_t)100))) >> 6) / ((int32_t)100)) +
        (int32_t)(1 << 14))) >> 10;
    var3 = var1 * var2;
    var4 = (int32_t)g_calibData.par_h6 << 7;
    var4 = ((var4) + ((tempScaled * (int32_t)g_calibData.par_h7) / ((int32_t)100))) >> 4;
    var5 = ((var3 >> 14) * (var3 >> 14)) >> 10;
    var6 = (var4 * var5) >> 1;

    calcHum = (((var3 + var6) >> 10) * ((int32_t)1000)) >> 12;
    
    /* Cap at 100%rH */
    if (calcHum > BME688_MAX_HUM) {
        calcHum = BME688_MAX_HUM;
    } else if (calcHum < 0) {
        calcHum = 0;
    }

    /*lint -restore */
    /*measurement unit : Integer*/
    return (uint32_t)calcHum / 1000;
}

static uint32_t BmeHalCalcGasResistanceHigh(uint16_t gasResAdc, uint8_t gasRange)
{
    uint32_t calc_gas_res;
    uint32_t var1 = BME_UINT32_C(262144) >> gasRange;
    int32_t var2 = (int32_t)gasResAdc - BME_INT32_C(512);

    var2 *= BME_INT32_C(3);
    var2 = BME_INT32_C(4096) + var2;

    /* multiplying 10000 then dividing then multiplying by 100 instead of multiplying by 1000000 to prevent overflow */
    calc_gas_res = (BME_UINT32_C(10000) * var1) / (uint32_t)var2;
    calc_gas_res = calc_gas_res * 100;

    return calc_gas_res;
}

static uint32_t BmeHalCalcGasResistanceLow(struct SensorCfgData *data,
                                           uint16_t gasResAdc, uint8_t gasRange)
{
    int64_t var1;
    uint64_t var2;
    int64_t var3;
    uint32_t calc_gas_res;
    uint32_t lookup_table1[16] = {
        BME_UINT32_C(2147483647), BME_UINT32_C(2147483647), BME_UINT32_C(2147483647),
        BME_UINT32_C(2147483647), BME_UINT32_C(2147483647), BME_UINT32_C(2126008810),
        BME_UINT32_C(2147483647), BME_UINT32_C(2130303777), BME_UINT32_C(2147483647),
        BME_UINT32_C(2147483647), BME_UINT32_C(2143188679), BME_UINT32_C(2136746228),
        BME_UINT32_C(2147483647), BME_UINT32_C(2126008810), BME_UINT32_C(2147483647),
        BME_UINT32_C(2147483647)
    };
    uint32_t lookup_table2[16] = {
        BME_UINT32_C(4096000000), BME_UINT32_C(2048000000), BME_UINT32_C(1024000000),
        BME_UINT32_C(512000000), BME_UINT32_C(255744255), BME_UINT32_C(127110228),
        BME_UINT32_C(64000000), BME_UINT32_C(32258064), BME_UINT32_C(16016016),
        BME_UINT32_C(8000000), BME_UINT32_C(4000000), BME_UINT32_C(2000000),
        BME_UINT32_C(1000000), BME_UINT32_C(500000), BME_UINT32_C(250000),
        BME_UINT32_C(125000)
    };

    /*lint -save -e704 */
    var1 = (int64_t)((1340 +
             (5 * (int64_t)g_calibData.range_sw_err)) * ((int64_t)lookup_table1[gasRange])) >> 16;
    var2 = (((int64_t)((int64_t)gasResAdc << 15) - (int64_t)(16777216)) + var1);
    var3 = (((int64_t)lookup_table2[gasRange] * (int64_t)var1) >> 9);
    calc_gas_res = (uint32_t)((var3 + ((int64_t)var2 >> 1)) / (int64_t)var2);

    /*lint -restore */
    return calc_gas_res;
}

static uint8_t BmeHalCalcResHeat(struct SensorCfgData *data, uint16_t temp)
{
    uint8_t heatr_res;
    int32_t var1;
    int32_t var2;
    int32_t var3;
    int32_t var4;
    int32_t var5;
    int32_t heatr_res_x100;
    
    /* Cap temperature */
    if (temp > BME688_MAX_TEMP) {
        temp = BME688_MAX_TEMP;
    }

    var1 = (((int32_t)BME688_AMB_TEMP * g_calibData.par_gh3) / 1000) * 256;
    var2 = (g_calibData.par_gh1 + 784) *
                (((((g_calibData.par_gh2 + 154009) * temp * 5) / 100) + 3276800) / 10);
    var3 = var1 + (var2 / 2);
    var4 = (var3 / (g_calibData.res_heat_range + 4));
    var5 = (131 * g_calibData.res_heat_val) + 65536;
    heatr_res_x100 = (int32_t)(((var4 / var5) - 250) * 34);
    heatr_res = (uint8_t)((heatr_res_x100 + 50) / 100);

    return heatr_res;
}

static uint8_t BmeHalCalcGasWait(uint16_t dur)
{
    uint8_t factor = 0;
    uint8_t durVal;

    if (dur > 0xfc0) {
        durVal = 0xff;
    } else {
        while (dur > 0x3f) {
            dur /= 4;
            factor++;
        }
        durVal = (uint8_t)(dur + (factor * 64));
    }

    return durVal;
}

static uint32_t Bme688GetMeasDur(struct SensorCfgData *data, const uint8_t opMode, struct GasCfg *gascfg)
{
    int32_t ret = HDF_SUCCESS;
    uint32_t meas_dur = 0; /* Calculate in us */
    uint32_t meas_cycles;
    uint8_t os_to_meas_cycles[6] = { 0, 1, 2, 4, 8, 16 };

    CHECK_NULL_PTR_RETURN_VALUE(gascfg, HDF_ERR_INVALID_PARAM);

    ret = BmeHalBoundaryCheck(data, &gascfg->tempOs, BME68X_OS_16X);
    ret = BmeHalBoundaryCheck(data, &gascfg->presOs, BME68X_OS_16X);
    ret = BmeHalBoundaryCheck(data, &gascfg->humOs, BME68X_OS_16X);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: [BME688] boundary check failed", __func__);
    }

    meas_cycles = os_to_meas_cycles[gascfg->tempOs];
    meas_cycles += os_to_meas_cycles[gascfg->presOs];
    meas_cycles += os_to_meas_cycles[gascfg->humOs];

    /* TPH measurement duration */
    meas_dur = meas_cycles * BME_UINT32_C(1963);
    meas_dur += BME_UINT32_C(477 * 4); /* TPH switching duration */
    meas_dur += BME_UINT32_C(477 * 5); /* Gas measurement duration */

    if (opMode != BME68X_PARALLEL_MODE) {
        meas_dur += BME_UINT32_C(1000); /* Wake up duration of 1ms */
    }

    return meas_dur;
}


static int32_t BmeHalSetConfig(struct SensorCfgData *data, struct bme688HeatrConf *conf,
                               uint8_t opMode, uint8_t *nbConv)
{
    int32_t rc = HDF_SUCCESS;
    uint8_t writeLen = 0;
    uint8_t rh_reg_addr[10] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    uint8_t rh_reg_data[10] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    uint8_t gw_reg_addr[10] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    uint8_t gw_reg_data[10] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    
    switch (opMode) {
        case BME68X_FORCED_MODE:
            rh_reg_addr[0] = BME68X_REG_RES_HEAT0;
            rh_reg_data[0] = BmeHalCalcResHeat(data, conf->heatr_temp);
            gw_reg_addr[0] = BME68X_REG_GAS_WAIT0;
            gw_reg_data[0] = BmeHalCalcGasWait(conf->heatr_dur);
            (*nbConv) = 0;
            writeLen = 1;
            break;
        default:
            rc = HDF_ERR_INVALID_PARAM;
    }

    rc = BmeHalRegWriteOneByte(data, rh_reg_addr[0], rh_reg_data[0]);

    rc = BmeHalRegWriteOneByte(data, gw_reg_addr[0], gw_reg_data[0]);

    return rc;
}

static int32_t Bme688SetHeatrConfig(struct SensorCfgData *data, struct bme688HeatrConf *conf, uint8_t opMode)
{
    int32_t rc;
    uint8_t nb_conv = 0;
    uint8_t hctrl, run_gas = 0;
    uint8_t ctrl_gas_data[2];
    uint8_t ctrl_gas_addr[2] = { BME68X_REG_CTRL_GAS_0, BME68X_REG_CTRL_GAS_1 };

    CHECK_NULL_PTR_RETURN_VALUE(conf, HDF_ERR_INVALID_PARAM);

    rc = Bme688SetOpMode(data, BME68X_SLEEP_MODE);
    
    rc = BmeHalSetConfig(data, conf, opMode, &nb_conv);

    rc = BmeHalRegRead(data, BME68X_REG_CTRL_GAS_0, ctrl_gas_data, 2);

    if (conf->enable == BME68X_ENABLE) {
        hctrl = BME68X_ENABLE_HEATER;
        if (g_bme688State.variantId == BME68X_VARIANT_GAS_HIGH) {
            run_gas = BME68X_ENABLE_GAS_MEAS_H;
        } else {
            run_gas = BME68X_ENABLE_GAS_MEAS_L;
        }
    } else {
        hctrl = BME68X_DISABLE_HEATER;
        run_gas = BME68X_DISABLE_GAS_MEAS;
    }

    ctrl_gas_data[0] = BME68X_SET_BITS(ctrl_gas_data[0], BME68X_HCTRL, hctrl);
    ctrl_gas_data[1] = BME68X_SET_BITS_POS_0(ctrl_gas_data[1], BME68X_NBCONV, nb_conv);
    ctrl_gas_data[1] = BME68X_SET_BITS(ctrl_gas_data[1], BME68X_RUN_GAS, run_gas);

    rc = BmeHalRegWriteMulByte(data, ctrl_gas_addr, ctrl_gas_data, 2);

    return rc;
}

static int32_t BmeHalBoundaryCheck(struct SensorCfgData *data, uint8_t *value, uint8_t max)
{
    int32_t rc = HDF_SUCCESS;

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);
    if (value != NULL) {
        if (*value > max) {
            *value = max;
        }
    } else {
        rc = HDF_ERR_INVALID_PARAM;
    }

    return rc;
}

static int32_t Bme688SetConfig(struct SensorCfgData *data, struct GasCfg *gascfg)
{
    int32_t rc = HDF_SUCCESS;
    uint8_t odr20 = 0, odr3 = 1;
    uint8_t currentOpMode;

    CHECK_NULL_PTR_RETURN_VALUE(gascfg, HDF_ERR_INVALID_PARAM);

    uint8_t regArray[BME68X_LEN_CONFIG] = {0x71, 0x72, 0x73, 0x74, 0x75};
    uint8_t dataArray[BME68X_LEN_CONFIG] = {0};

    rc = Bme688GetOpMode(data, &currentOpMode);
    if (rc != HDF_SUCCESS) {
        HDF_LOGE("%s: bme688 get operation mode failed", __func__);
    }

    rc = Bme688SetOpMode(data, BME68X_SLEEP_MODE);
    if (rc != HDF_SUCCESS) {
        HDF_LOGE("%s: bme688 set sleep mode failed", __func__);
    }

    rc = BmeHalRegRead(data, regArray[0], dataArray, BME68X_LEN_CONFIG);
    if (rc != HDF_SUCCESS) {
        HDF_LOGE("%s, line : %d, bme688 read data array failed", __func__, __LINE__);
    }

    rc = BmeHalBoundaryCheck(data, &gascfg->filter, BME68X_FILTER_SIZE_127);
    rc = BmeHalBoundaryCheck(data, &gascfg->tempOs, BME68X_OS_16X);
    rc = BmeHalBoundaryCheck(data, &gascfg->presOs, BME68X_OS_16X);
    rc = BmeHalBoundaryCheck(data, &gascfg->humOs, BME68X_OS_16X);
    rc = BmeHalBoundaryCheck(data, &gascfg->odr, BME68X_ODR_NONE);
    if (rc != HDF_SUCCESS) {
        HDF_LOGE("%s: bme688 boundary check failed", __func__);
    }

    dataArray[4] = BME68X_SET_BITS(dataArray[4], BME68X_FILTER, gascfg->filter);
    dataArray[3] = BME68X_SET_BITS(dataArray[3], BME68X_OST, gascfg->tempOs);
    dataArray[3] = BME68X_SET_BITS(dataArray[3], BME68X_OSP, gascfg->presOs);
    dataArray[1] = BME68X_SET_BITS_POS_0(dataArray[1], BME68X_OSH, gascfg->humOs);
    if (gascfg->odr != BME68X_ODR_NONE) {
        odr20 = gascfg->odr;
        odr3 = 0;
    }

    dataArray[4] = BME68X_SET_BITS(dataArray[4], BME68X_ODR20, odr20);
    dataArray[0] = BME68X_SET_BITS(dataArray[0], BME68X_ODR3, odr3);

    rc = BmeHalRegWriteMulByte(data, regArray, dataArray, BME68X_LEN_CONFIG);
    if (rc != HDF_SUCCESS) {
        HDF_LOGE("%s: bme688 write config failed", __func__);
    }

    if (currentOpMode != BME68X_SLEEP_MODE) {
        rc = Bme688SetOpMode(data, currentOpMode);
    }

    return rc;
}

static int32_t BmeHalReadFieldData(struct SensorCfgData *data,
                                   uint8_t index, struct GasFieldData *fieldData)
{
    uint8_t gas_range_l, gas_range_h, buff[BME68X_LEN_FIELD] = {0};
    uint32_t adc_temp, adc_pres, tries = BME688_TRY_TIMES, rc = HDF_SUCCESS;
    uint16_t adc_gas_res_low, adc_gas_res_high, adc_hum;
    CHECK_NULL_PTR_RETURN_VALUE(fieldData, HDF_ERR_INVALID_PARAM);

    while ((tries) && (rc == HDF_SUCCESS)) {
        rc = BmeHalRegRead(data, (uint8_t)(BME68X_REG_FIELD0 + index * BME68X_LEN_FIELD_OFFSET),
                           buff, (uint16_t)BME68X_LEN_FIELD);
        if (rc != HDF_SUCCESS) {
            HDF_LOGE("%s: bme688 read data failed", __func__);
        }
        fieldData->status = buff[0] & BME68X_NEW_DATA_MSK;
        fieldData->gas_index = buff[0] & BME68X_GAS_INDEX_MSK;
        fieldData->meas_index = buff[1];
        /* read the raw data from the sensor */
        adc_pres = (uint32_t)(((uint32_t)buff[2] * 4096) | ((uint32_t)buff[3] * 16) | ((uint32_t)buff[4] / 16));
        adc_temp = (uint32_t)(((uint32_t)buff[5] * 4096) | ((uint32_t)buff[6] * 16) | ((uint32_t)buff[7] / 16));
        adc_hum = (uint16_t)(((uint32_t)buff[8] * 256) | (uint32_t)buff[9]);
        adc_gas_res_low = (uint16_t)((((uint32_t)buff[13]) * 4) | (((uint32_t)buff[14]) / 64));
        adc_gas_res_high = (uint16_t)((((uint32_t)buff[15]) * 4) | (((uint32_t)buff[16]) / 64));
        gas_range_l = buff[14] & BME68X_GAS_RANGE_MSK;
        gas_range_h = buff[16] & BME68X_GAS_RANGE_MSK;

        if (g_bme688State.variantId == BME68X_VARIANT_GAS_HIGH) {
            fieldData->status |= buff[16] & BME68X_GASM_VALID_MSK;
            fieldData->status |= buff[16] & BME68X_HEAT_STAB_MSK;
        } else {
            fieldData->status |= buff[14] & BME68X_GASM_VALID_MSK;
            fieldData->status |= buff[14] & BME68X_HEAT_STAB_MSK;
        }

        if (fieldData->status & BME68X_NEW_DATA_MSK) {
            rc = BmeHalRegRead(data, BME68X_REG_RES_HEAT0 + fieldData->gas_index, &fieldData->res_heat, 1);
            rc |= BmeHalRegRead(data, BME68X_REG_IDAC_HEAT0 + fieldData->gas_index, &fieldData->idac, 1);
            rc |= BmeHalRegRead(data, BME68X_REG_GAS_WAIT0 + fieldData->gas_index, &fieldData->gas_wait, 1);
            if (rc != HDF_SUCCESS) {
                HDF_LOGE("%s: bme688 read data failed", __func__);
            }
            fieldData->temperature = BmeHalCalcTemperature(data, adc_temp);
            fieldData->pressure = BmeHalCalcPressure(data, adc_pres);
            fieldData->humidity = BmeHalCalcHumidity(data, adc_hum);
            if (g_bme688State.variantId == BME68X_VARIANT_GAS_HIGH) {
                fieldData->gas_resistance = BmeHalCalcGasResistanceHigh(adc_gas_res_high, gas_range_h);
            } else {
                fieldData->gas_resistance = BmeHalCalcGasResistanceLow(data, adc_gas_res_low, gas_range_l);
            }
            break;
        }
        OsalMDelay(BME688_DELAY_10);
        tries--;
    }
    return rc;
}

static int32_t Bme688GetData(struct SensorCfgData *data, struct GasFieldData *fieldData, uint8_t opMode)
{
    int32_t ret;

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(fieldData, HDF_ERR_INVALID_PARAM);

    if (opMode == BME68X_FORCED_MODE) {
        ret = BmeHalReadFieldData(data, 0, fieldData);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%s: bme688 read field data failed", __func__);
            return HDF_FAILURE;
        }
    } else {
        HDF_LOGE("%s: sensor status error.", __func__);
        return HDF_FAILURE;
    }

    return ret;
}

static int32_t InitBme688(struct SensorCfgData *data)
{
    int32_t ret = HDF_SUCCESS;

    CHECK_NULL_PTR_RETURN_VALUE(data, HDF_ERR_INVALID_PARAM);
    ret = SetSensorRegCfgArray(&data->busCfg, data->regCfgGroup[SENSOR_INIT_GROUP]);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: bme688 sensor init config failed", __func__);
        return HDF_FAILURE;
    }

    ret = Bme688ReadVariantId(data);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: bme688 sensor read variant id failed", __func__);
        return HDF_FAILURE;
    }

    g_bme688State.workState = BME688_WORK_MODE_SUSPEND;
    g_bme688State.inited = BME68X_DISABLE;

    return ret;
}

static int32_t DispatchBme688(struct HdfDeviceIoClient *client, int cmd, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    (void)client;
    (void)cmd;
    (void)data;
    (void)reply;

    return HDF_SUCCESS;
}

static int32_t Bme688BindDriver(struct HdfDeviceObject *device)
{
    OsalUDelay(BME688_DELAY_50);
    CHECK_NULL_PTR_RETURN_VALUE(device, HDF_ERR_INVALID_PARAM);

    struct Bme688DrvData *drvData = (struct Bme688DrvData *)OsalMemCalloc(sizeof(*drvData));
    if (drvData == NULL) {
        HDF_LOGE("%s: Malloc Bme688 drv data fail", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    drvData->ioService.Dispatch = DispatchBme688;
    drvData->device = device;
    device->service = &drvData->ioService;
    g_bme688DrvData = drvData;

    return HDF_SUCCESS;
}

static int32_t Bme688InitDriver(struct HdfDeviceObject *device)
{
    int32_t ret;
    struct GasOpsCall ops;
    CHECK_NULL_PTR_RETURN_VALUE(device, HDF_ERR_INVALID_PARAM);
    struct Bme688DrvData *drvData = (struct Bme688DrvData *)device->service;
    CHECK_NULL_PTR_RETURN_VALUE(drvData, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(device->property, HDF_ERR_INVALID_PARAM);

    drvData->sensorCfg = GasCreateCfgData(device->property);
    if (drvData->sensorCfg == NULL || drvData->sensorCfg->root == NULL) {
        HDF_LOGD("%s: Creating gascfg failed because detection failed", __func__);
        return HDF_ERR_NOT_SUPPORT;
    }

    ops.Init = NULL;
    ops.ReadData = ReadBme688Data;
    ret = GasRegisterChipOps(&ops);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Register bme688 gas failed", __func__);
        return HDF_FAILURE;
    }

    ret = Bme688SoftReset(drvData->sensorCfg);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: bme688 dump data failed!", __func__);
    }

    // validate chip id
    ret = Bme688ValChipId(drvData->sensorCfg);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    ret = Bme688GetCalibData(drvData->sensorCfg, &g_calibData);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: get calibration data in init process failed", __func__);
        return HDF_FAILURE;
    }

    ret = InitBme688(drvData->sensorCfg);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%s: Init bme688 gas failed", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static void Bme688ReleaseDriver(struct HdfDeviceObject *device)
{
    CHECK_NULL_PTR_RETURN(device);

    struct Bme688DrvData *drvData = (struct Bme688DrvData *)device->service;
    CHECK_NULL_PTR_RETURN(drvData);

    if (drvData->sensorCfg != NULL) {
        GasReleaseCfgData(drvData->sensorCfg);
        drvData->sensorCfg = NULL;
    }

    OsalMemFree(drvData);
}

struct HdfDriverEntry g_gasBme688DevEntry = {
    .moduleVersion  = 1,
    .moduleName     = "HDF_SENSOR_GAS_BME688",
    .Bind           = Bme688BindDriver,
    .Init           = Bme688InitDriver,
    .Release        = Bme688ReleaseDriver,
};

HDF_INIT(g_gasBme688DevEntry);
