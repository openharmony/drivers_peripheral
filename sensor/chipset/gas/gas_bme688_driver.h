/**
* Copyright (c) 2024 Bosch Sensortec GmbH. All rights reserved.
*
* gas_bmr688_driver.h as part of the * /chipsets subdirectory
* is dual licensed: you can use it either under the terms of
* the GPL, or the BSD license, at your option.
* See the LICENSE file in the root of this repository for complete details.
*/

#ifndef BME688_H
#define BME688_H

#include "sensor_gas_driver.h"
#include "sensor_config_parser.h"

#define BME688_AMB_TEMP                (int8_t)25       /*ambient temperature*/
#define BME688_HEATR_TEMP              300              /*heating temperature*/
#define BME688_HEATR_DUR               100              /*heating duration*/

#if !defined(BME_UINT32_C)
#define BME_UINT32_C(val) val ## U
#endif

#if !defined(BME_INT32_C)
#define BME_INT32_C(val) val ## L
#endif

#define BME68X_CHIP_ID                 0x61     /* BME68X unique chip identifier */

#define BME68X_REG_CTRL_MEAS           0x74     /* CTRL_MEAS address */
#define BME68X_REG_COEFF1              0x8a     /* Register for 1st group of coefficients */
#define BME68X_REG_COEFF2              0xe1     /* Register for 2nd group of coefficients */
#define BME68X_REG_COEFF3              0x00     /* Register for 3rd group of coefficients */
#define BME68X_REG_CHIP_ID             0xd0     /* Chip ID address */
#define BME68X_REG_SOFT_RESET          0xe0     /* Soft reset address */
#define BME68X_REG_VARIANT_ID          0xF0     /* Variant ID Register */
#define BME68X_REG_FIELD0              0x1d     /* 0th Field address*/
#define BME68X_REG_RES_HEAT0           0x5a     /* 0th Res heat address */
#define BME68X_REG_IDAC_HEAT0          0x50     /* 0th Current DAC address*/
#define BME68X_REG_GAS_WAIT0           0x64     /* 0th Gas wait address */
#define BME68X_REG_CTRL_GAS_0          0x70     /* CTRL_GAS_0 address */
#define BME68X_REG_CTRL_GAS_1          0x71     /* CTRL_GAS_1 address */
#define BME68X_SOFT_RESET_CMD          0xb6     /* Soft reset command */

#define BME68X_LEN_COEFF_ALL           42       /* Length for all coefficients */
#define BME68X_LEN_COEFF1              23       /* Length for 1st group of coefficients */
#define BME68X_LEN_COEFF2              14       /* Length for 2nd group of coefficients */
#define BME68X_LEN_COEFF3              5        /* Length for 3rd group of coefficients */
#define BME68X_LEN_CONFIG              5        /* Length of the configuration register */
#define BME68X_LEN_FIELD               17       /* Length of the field */
#define BME68X_LEN_FIELD_OFFSET        17       /* Length between two fields */

#define BME68X_MODE_MSK                0x03     /* Mask for operation mode */

#define BME68X_GASM_VALID_MSK          0x20     /* Mask for gas measurement valid */
#define BME68X_GAS_INDEX_MSK           0x0f     /* Mask for gas index */
#define BME68X_GAS_RANGE_MSK           0x0f     /* Mask for gas range */
#define BME68X_GASM_VALID_MSK          0x20     /* Mask for gas measurement valid */
#define BME68X_HEAT_STAB_MSK           0x10     /* Mask for heater stability */
#define BME68X_NEW_DATA_MSK            0x80     /* Mask for new data */
#define BME68X_BIT_H1_DATA_MSK         0x0f     /* Mask for the H1 calibration coefficient */
#define BME68X_RHRANGE_MSK             0x30     /* Mask for res heat range */
#define BME68X_RSERROR_MSK             0xf0     /* Mask for range switching error */

#define BME68X_FILTER_MSK              0X1c     /* Mask for IIR filter */
#define BME68X_OST_MSK                 0Xe0     /* Mask for temperature oversampling */
#define BME68X_OSP_MSK                 0X1c     /* Mask for pressure oversampling */
#define BME68X_OSH_MSK                 0X07     /* Mask for humidity oversampling */
#define BME68X_ODR20_MSK               0xe0     /* Mask for ODR[2:0] */
#define BME68X_ODR3_MSK                0x80     /* Mask for ODR[3] */
#define BME68X_HCTRL_MSK               0x08     /* Mask for heater control */
#define BME68X_NBCONV_MSK              0X0f     /* Mask for number of conversions */
#define BME68X_RUN_GAS_MSK             0x30     /* Mask for run gas */
#define BME688_NEW_DATA_READY          0x80     /* Mask for new data */

#define BME68X_SLEEP_MODE              0        /* Sleep operation mode */
#define BME68X_FORCED_MODE             1        /* Forced operation mode */
#define BME68X_PARALLEL_MODE           2        /* Parallel operation mode */

#define BME68X_VARIANT_GAS_HIGH        0x01     /* High Gas variant */

#define BME68X_IDX_T1_LSB              31       /* Coefficient T1 LSB position */
#define BME68X_IDX_T1_MSB              32       /* Coefficient T1 MSB position */
#define BME68X_IDX_T2_LSB              0        /* Coefficient T2 LSB position */
#define BME68X_IDX_T2_MSB              1        /* Coefficient T2 MSB position */
#define BME68X_IDX_T3                  2        /* Coefficient T3 position */
#define BME68X_IDX_P1_LSB              4        /* Coefficient P1 LSB position */
#define BME68X_IDX_P1_MSB              5        /* Coefficient P1 MSB position */
#define BME68X_IDX_P2_LSB              6        /* Coefficient P2 LSB position */
#define BME68X_IDX_P2_MSB              7        /* Coefficient P2 MSB position */
#define BME68X_IDX_P3                  8        /* Coefficient P3 position */
#define BME68X_IDX_P4_LSB              10       /* Coefficient P4 LSB position */
#define BME68X_IDX_P4_MSB              11       /* Coefficient P4 MSB position */
#define BME68X_IDX_P5_LSB              12       /* Coefficient P5 LSB position */
#define BME68X_IDX_P5_MSB              13       /* Coefficient P5 MSB position */
#define BME68X_IDX_P7                  14       /* Coefficient P7 position */
#define BME68X_IDX_P6                  15       /* Coefficient P6 position */
#define BME68X_IDX_P8_LSB              18       /* Coefficient P8 LSB position */
#define BME68X_IDX_P8_MSB              19       /* Coefficient P8 MSB position */
#define BME68X_IDX_P9_LSB              20       /* Coefficient P9 LSB position */
#define BME68X_IDX_P9_MSB              21       /* Coefficient P9 MSB position */
#define BME68X_IDX_P10                 22       /* Coefficient P10 position */
#define BME68X_IDX_H2_MSB              23       /* Coefficient H2 MSB position */
#define BME68X_IDX_H2_LSB              24       /* Coefficient H2 LSB position */
#define BME68X_IDX_H1_LSB              24       /* Coefficient H1 LSB position */
#define BME68X_IDX_H1_MSB              25       /* Coefficient H1 MSB position */
#define BME68X_IDX_H3                  26       /* Coefficient H3 position */
#define BME68X_IDX_H4                  27       /* Coefficient H4 position */
#define BME68X_IDX_H5                  28       /* Coefficient H5 position */
#define BME68X_IDX_H6                  29       /* Coefficient H6 position */
#define BME68X_IDX_H7                  30       /* Coefficient H7 position */
#define BME68X_IDX_T1_LSB              31       /* Coefficient T1 LSB position */
#define BME68X_IDX_T1_MSB              32       /* Coefficient T1 MSB position */
#define BME68X_IDX_GH2_LSB             33       /* Coefficient GH2 LSB position */
#define BME68X_IDX_GH2_MSB             34       /* Coefficient GH2 MSB position */
#define BME68X_IDX_GH1                 35       /* Coefficient GH1 position */
#define BME68X_IDX_GH3                 36       /* Coefficient GH3 position */
#define BME68X_IDX_RES_HEAT_VAL        37       /* Coefficient res heat value position */
#define BME68X_IDX_RES_HEAT_RANGE      39       /* Coefficient res heat range position */
#define BME68X_IDX_RANGE_SW_ERR        41       /* Coefficient range switching error position */

#define BME68X_FILTER_SIZE_127         7        /* Filter coefficient of 128 */

#define BME68X_OS_1X                   1        /* Perform 1 measurement */
#define BME68X_OS_2X                   2        /* Perform 2 measurements */
#define BME68X_OS_4X                   3        /* Perform 4 measurements */
#define BME68X_OS_8X                   4        /* Perform 8 measurements */
#define BME68X_OS_16X                  5        /* Perform 16 measurements */
#define BME68X_ODR_NONE                8        /* No standby time */

#define BME68X_FILTER_OFF              0        /* Switch off the filter */

#define BME68X_ENABLE                  0x01     /* Enable */
#define BME68X_DISABLE                 0x00     /* Disable */
#define BME68X_DISABLE_HEATER          0x01     /* Disable heater */
#define BME68X_ENABLE_GAS_MEAS_L       0x01     /* Enable gas measurement low */
#define BME68X_ENABLE_GAS_MEAS_H       0x02     /* Enable gas measurement high */
#define BME68X_DISABLE_GAS_MEAS        0x00     /* Disable gas measurement */
#define BME68X_ENABLE_HEATER           0x00     /* Enable heater */

#define BME68X_HCTRL_POS               3        /* Heater control bit position */
#define BME68X_RUN_GAS_POS             4        /* Run gas bit position */
#define BME68X_FILTER_POS              2        /* Filter bit position */
#define BME68X_OST_POS                 5        /* Temperature oversampling bit position */
#define BME68X_OSP_POS                 2        /* Pressure oversampling bit position */
#define BME68X_ODR3_POS                7        /* ODR[3] bit position */
#define BME68X_ODR20_POS               5        /* ODR[2:0] bit position */

#define BME688_WORK_MODE_SUSPEND       1        /* Suspend mode */
#define BME688_WORK_MODE_IDLE          2        /* idle mode */

#define BME688_DELAY_4                 4        /*delay time about 4 */
#define BME688_DELAY_5                 5        /*delay time about 5 */
#define BME688_DELAY_10                10       /*delay time about 10 */
#define BME688_DELAY_50                50       /*delay time about 50 */

#define BME688_MAX_HUM                 100000   /* max humidity  */
#define BME688_MAX_TEMP                400      /* max temperature  */

#define BME68X_LEN_INTERLEAVE_BUFF     20       /* Length of the interleaved buffer */

#define BME688_TRY_TIMES               5        /* try to read field data times*/

/* Macro to combine two 8 bit data's to form a 16 bit data */
#define BME68X_CONCAT_BYTES(msb, lsb)          ((uint16_t)((msb) << 8) | (uint16_t)(lsb))

/* Macro to set bits */
#define BME68X_SET_BITS(reg_data, bitname, data) \
    (((reg_data) & ~(bitname##_MSK)) | \
    (((data) << bitname##_POS) & bitname##_MSK))

/* Macro to set bits starting from position 0 */
#define BME68X_SET_BITS_POS_0(reg_data, bitname, data) \
    (((reg_data) & ~(bitname##_MSK)) | ((data) & bitname##_MSK))

struct Bme688CalibData {
    /*! Calibration coefficient for the humidity sensor */
    uint16_t par_h1;

    /*! Calibration coefficient for the humidity sensor */
    uint16_t par_h2;

    /*! Calibration coefficient for the humidity sensor */
    int8_t par_h3;

    /*! Calibration coefficient for the humidity sensor */
    int8_t par_h4;

    /*! Calibration coefficient for the humidity sensor */
    int8_t par_h5;

    /*! Calibration coefficient for the humidity sensor */
    uint8_t par_h6;

    /*! Calibration coefficient for the humidity sensor */
    int8_t par_h7;

    /*! Calibration coefficient for the gas sensor */
    int8_t par_gh1;

    /*! Calibration coefficient for the gas sensor */
    int16_t par_gh2;

    /*! Calibration coefficient for the gas sensor */
    int8_t par_gh3;

    /*! Calibration coefficient for the temperature sensor */
    uint16_t par_t1;

    /*! Calibration coefficient for the temperature sensor */
    int16_t par_t2;

    /*! Calibration coefficient for the temperature sensor */
    int8_t par_t3;

    /*! Calibration coefficient for the pressure sensor */
    uint16_t par_p1;

    /*! Calibration coefficient for the pressure sensor */
    int16_t par_p2;

    /*! Calibration coefficient for the pressure sensor */
    int8_t par_p3;

    /*! Calibration coefficient for the pressure sensor */
    int16_t par_p4;

    /*! Calibration coefficient for the pressure sensor */
    int16_t par_p5;

    /*! Calibration coefficient for the pressure sensor */
    int8_t par_p6;

    /*! Calibration coefficient for the pressure sensor */
    int8_t par_p7;

    /*! Calibration coefficient for the pressure sensor */
    int16_t par_p8;

    /*! Calibration coefficient for the pressure sensor */
    int16_t par_p9;

    /*! Calibration coefficient for the pressure sensor */
    uint8_t par_p10;

    /*! Variable to store the intermediate temperature coefficient */
    int32_t t_fine;

    /*! Heater resistance range coefficient */
    uint8_t res_heat_range;

    /*! Heater resistance value coefficient */
    int8_t res_heat_val;

    /*! Gas resistance range switching error coefficient */
    int8_t range_sw_err;
};

struct bme688HeatrConf {
    /*! Enable gas measurement. Refer @ref en_dis */
    uint8_t enable;

    /*! Store the heater temperature for forced mode degree Celsius */
    uint16_t heatr_temp;

    /*! Store the heating duration for forced mode in milliseconds */
    uint16_t heatr_dur;

    /*! Store the heater temperature profile in degree Celsius */
    uint16_t *heatr_temp_prof;

    /*! Store the heating duration profile in milliseconds */
    uint16_t *heatr_dur_prof;

    /*! Variable to store the length of the heating profile */
    uint8_t profile_len;

    /*!
     * Variable to store heating duration for parallel mode
     * in milliseconds
     */
    uint16_t shared_heatr_dur;
};

struct Bme688GasRawData {
    uint32_t adc_temp;
    uint32_t adc_pres;
    uint16_t adc_hum;
    uint16_t adc_gas_res_low;
    uint16_t adc_gas_res_high;
    uint8_t gas_range_l;
    uint8_t gas_range_h;
};

struct Bme688Status {
    int8_t variantId;
    int8_t workState;
    int8_t inited;
};

struct Bme688DrvData {
    struct IDeviceIoService ioService;
    struct HdfDeviceObject *device;
    struct SensorCfgData *sensorCfg;
};

enum Bme688FieldData {
    RESISTANCE = 0,
    TEMPERATURE = 1,
    HUMIDITY = 2,
    PRESSURE = 3
};

#endif /* BME688_H */

